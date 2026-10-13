//! Reverse proxy and load balancer module.
//!
//! Supports multiple load-balancing strategies (round-robin, least-connections,
//! weighted) with active health checking, passive failure ejection, and
//! fail-open selection when every backend is unhealthy.
//!
//! Bodies stream in both directions over a pooled hyper client: request
//! bodies are forwarded as they arrive and upstream responses are relayed
//! frame by frame (SSE, long polls, large downloads, gRPC trailers).
//! HTTP/1.1 upgrades (WebSocket) are tunnelled after the upstream answers
//! `101`, and `application/grpc` requests go upstream over h2c.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use hyper::body::{Body, Bytes, Frame, SizeHint};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::upgrade::OnUpgrade;
use hyper::{Request, Response, StatusCode};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::{TokioExecutor, TokioIo};
use reqwest::Client;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use intellaro_http_router::config::HeaderManipulation;

use crate::config::{BackendServer, HealthCheckConfig, UpstreamConfig};
use crate::server::{full, stream, BoxBody, BoxError};

/// Pooled upstream client (plain or TLS by URI scheme); request bodies
/// are streamed `BoxBody`s.
type UpstreamClient = HyperClient<HttpsConnector<HttpConnector>, BoxBody>;

/// Upstream TCP connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default time allowed for an upstream to produce response headers when
/// the route sets no `timeouts.read`. Body streaming is not bounded, so
/// SSE and long downloads are unaffected.
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-request forwarding options.
#[derive(Debug)]
pub struct ForwardOptions {
    pub client_addr: SocketAddr,
    /// Scheme the client used ("http"/"https"); sets X-Forwarded-Proto
    /// when the header is not already present (chained-proxy safe).
    pub scheme: &'static str,
    /// Replacement path (+query) after rule-level strip/rewrite.
    pub path_override: Option<String>,
    /// Rule-level request header manipulation.
    pub headers: Option<HeaderManipulation>,
    /// Time allowed for the upstream to produce response headers
    /// (route `timeouts.read`); `None` = [`DEFAULT_READ_TIMEOUT`].
    pub read_timeout: Option<Duration>,
    /// The client connection's upgrade handle, taken from the inbound
    /// request. Consumed when the upstream switches protocols.
    pub upgrade: Option<OnUpgrade>,
}

impl Default for ForwardOptions {
    fn default() -> Self {
        Self {
            client_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            scheme: "http",
            path_override: None,
            headers: None,
            read_timeout: None,
            upgrade: None,
        }
    }
}

/// Consecutive transport/5xx failures before a backend is passively ejected.
const PASSIVE_MAX_FAILS: u32 = 3;

/// How long a passively ejected backend stays out of rotation.
const PASSIVE_EJECT: Duration = Duration::from_secs(10);

/// Milliseconds since process start (monotonic, atomically storable).
fn now_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Health state of a backend server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
}

/// Runtime state for a single backend server.
#[derive(Debug)]
pub struct BackendState {
    pub server: BackendServer,
    /// Active health-check verdict.
    pub status: RwLock<HealthStatus>,
    pub active_connections: AtomicUsize,
    /// Consecutive passive failures (transport errors / 5xx).
    consecutive_fails: AtomicU32,
    /// Monotonic ms until which this backend is passively ejected.
    down_until_ms: AtomicU64,
}

impl BackendState {
    fn new(server: BackendServer) -> Self {
        Self {
            server,
            status: RwLock::new(HealthStatus::Healthy),
            active_connections: AtomicUsize::new(0),
            consecutive_fails: AtomicU32::new(0),
            down_until_ms: AtomicU64::new(0),
        }
    }

    /// Record a passive failure; eject after `PASSIVE_MAX_FAILS` in a row.
    pub fn record_failure(&self) {
        let fails = self.consecutive_fails.fetch_add(1, Ordering::Relaxed) + 1;
        if fails >= PASSIVE_MAX_FAILS {
            self.consecutive_fails.store(0, Ordering::Relaxed);
            self.down_until_ms
                .store(now_ms() + PASSIVE_EJECT.as_millis() as u64, Ordering::Relaxed);
            metrics::counter!("backend_passive_ejections_total",
                "backend" => self.server.address.clone())
            .increment(1);
            warn!(
                backend = %self.server.address,
                eject_secs = PASSIVE_EJECT.as_secs(),
                "Backend passively ejected after consecutive failures"
            );
        }
    }

    /// Record a passive success (resets the failure streak).
    pub fn record_success(&self) {
        self.consecutive_fails.store(0, Ordering::Relaxed);
    }

    /// Whether this backend is currently in rotation.
    fn is_available(&self) -> bool {
        if now_ms() < self.down_until_ms.load(Ordering::Relaxed) {
            return false;
        }
        self.status
            .try_read()
            .map(|s| *s == HealthStatus::Healthy)
            .unwrap_or(true)
    }
}

/// Runtime state for an upstream group.
pub struct UpstreamState {
    pub name: String,
    pub backends: Vec<Arc<BackendState>>,
    pub strategy: String,
    pub round_robin_index: AtomicUsize,
    pub health_check: Option<HealthCheckConfig>,
}

/// The proxy engine manages all upstream groups and performs request forwarding.
pub struct ProxyEngine {
    upstreams: DashMap<String, Arc<UpstreamState>>,
    /// HTTP/1.1 (and upgrade-capable) upstream client.
    http_client: UpstreamClient,
    /// HTTP/2 prior-knowledge (h2c) client for gRPC.
    h2c_client: UpstreamClient,
    /// Client for active health probes.
    health_client: Client,
    /// Cancels this engine's health-check loops when the engine is
    /// replaced by a config reload.
    hc_stop: tokio::sync::watch::Sender<bool>,
}

impl Drop for ProxyEngine {
    fn drop(&mut self) {
        let _ = self.hc_stop.send(true);
    }
}

impl ProxyEngine {
    /// Create a new proxy engine from upstream configuration.
    pub fn new(upstream_configs: &[UpstreamConfig]) -> Self {
        let upstreams = DashMap::new();

        for config in upstream_configs {
            let backends: Vec<Arc<BackendState>> = config
                .servers
                .iter()
                .map(|server| Arc::new(BackendState::new(server.clone())))
                .collect();

            let state = Arc::new(UpstreamState {
                name: config.name.clone(),
                backends,
                strategy: config.load_balancing.clone(),
                round_robin_index: AtomicUsize::new(0),
                health_check: config.health_check.clone(),
            });

            upstreams.insert(config.name.clone(), state);
        }

        let mut http = HttpConnector::new();
        http.set_connect_timeout(Some(CONNECT_TIMEOUT));
        http.set_nodelay(true);
        http.enforce_http(false);
        let connector = https_connector(http);

        let http_client = HyperClient::builder(TokioExecutor::new())
            .pool_max_idle_per_host(100)
            .pool_idle_timeout(Duration::from_secs(90))
            .build(connector.clone());
        let h2c_client = HyperClient::builder(TokioExecutor::new())
            .http2_only(true)
            .pool_idle_timeout(Duration::from_secs(90))
            .build(connector);

        let health_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .expect("Failed to build health-check client");

        info!(
            upstream_count = upstream_configs.len(),
            "Proxy engine initialized"
        );

        let (hc_stop, _) = tokio::sync::watch::channel(false);

        Self {
            upstreams,
            http_client,
            h2c_client,
            health_client,
            hc_stop,
        }
    }

    /// Forward a request to an appropriate upstream backend.
    ///
    /// `req` carries method/uri/headers; the body is passed separately so
    /// callers choose between streaming it once or replaying a buffer.
    pub async fn forward<B>(
        &self,
        req: &Request<B>,
        body: BoxBody,
        opts: &mut ForwardOptions,
    ) -> Result<Response<BoxBody>, ProxyError> {
        let upstream_name = self.resolve_upstream(req);

        let upstream = self
            .upstreams
            .get(&upstream_name)
            .ok_or_else(|| ProxyError::NoUpstream(upstream_name.clone()))?;

        let backend = self.select_backend(&upstream)?;

        metrics::counter!("proxy_requests_total", "upstream" => upstream_name.clone()).increment(1);

        // The guard keeps the backend's connection count raised until the
        // response body (or upgraded tunnel) finishes, so least-connections
        // sees long-lived streams.
        let guard = ConnGuard::new(backend.clone());
        let result = self
            .send_upstream(req, &backend.server.address, body, opts, Some(guard))
            .await;

        match &result {
            Ok(resp) if resp.status().is_server_error() => backend.record_failure(),
            Ok(_) => backend.record_success(),
            Err(_) => backend.record_failure(),
        }

        result
    }

    /// Forward a request to a specific backend address (used by the routing
    /// engine, which does its own health accounting).
    pub async fn forward_to<B>(
        &self,
        req: &Request<B>,
        backend_address: &str,
        body: BoxBody,
        opts: &mut ForwardOptions,
    ) -> Result<Response<BoxBody>, ProxyError> {
        metrics::counter!("proxy_requests_total", "backend" => backend_address.to_string())
            .increment(1);
        self.send_upstream(req, backend_address, body, opts, None).await
    }

    /// Perform the upstream exchange: stream the request body up, relay the
    /// response body down, or tunnel the connection after a `101`.
    async fn send_upstream<B>(
        &self,
        req: &Request<B>,
        backend_address: &str,
        body: BoxBody,
        opts: &mut ForwardOptions,
        guard: Option<ConnGuard>,
    ) -> Result<Response<BoxBody>, ProxyError> {
        let path = opts.path_override.as_deref().unwrap_or_else(|| {
            req.uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/")
        });
        let (backend_scheme, backend_authority) = backend_origin(backend_address);
        let uri: hyper::Uri = format!("{backend_scheme}://{backend_authority}{path}")
            .parse()
            .map_err(|err: hyper::http::uri::InvalidUri| ProxyError::BackendError(err.to_string()))?;

        let grpc = is_grpc(req.headers());
        let upgrade = upgrade_protocol(req);

        let mut headers = build_upstream_headers(req, opts);
        if grpc {
            // gRPC requires `te: trailers` end to end (RFC 9113 §8.2.2).
            headers.insert(header::TE, HeaderValue::from_static("trailers"));
            // :authority comes from the URI on h2; a Host header is not sent.
            headers.remove(header::HOST);
        }
        if let Some(proto) = &upgrade {
            headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
            headers.insert(header::UPGRADE, proto.clone());
        }

        let mut upstream_req = Request::builder()
            .method(req.method().clone())
            .uri(uri)
            .body(body)
            .map_err(|err| ProxyError::BackendError(err.to_string()))?;
        *upstream_req.headers_mut() = headers;

        let client = if grpc { &self.h2c_client } else { &self.http_client };
        let read_timeout = opts.read_timeout.unwrap_or(DEFAULT_READ_TIMEOUT);
        let mut resp = tokio::time::timeout(read_timeout, client.request(upstream_req))
            .await
            .map_err(|_| ProxyError::Timeout(read_timeout))?
            .map_err(|err| ProxyError::BackendError(error_chain(&err)))?;

        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            let client_upgrade = match (&upgrade, opts.upgrade.take()) {
                (Some(_), Some(on_upgrade)) => on_upgrade,
                _ => {
                    return Err(ProxyError::BackendError(
                        "upstream switched protocols without an upgrade request".into(),
                    ))
                }
            };
            let upstream_upgrade = hyper::upgrade::on(&mut resp);
            tokio::spawn(tunnel(
                client_upgrade,
                upstream_upgrade,
                backend_address.to_string(),
                guard,
            ));

            // Relay the 101 verbatim: Connection/Upgrade and the
            // protocol's handshake headers (Sec-WebSocket-Accept, …).
            let mut out = Response::new(full(Bytes::new()));
            *out.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            *out.headers_mut() = resp.headers().clone();
            return Ok(out);
        }

        let (mut parts, body) = resp.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        let body = match guard {
            Some(guard) => stream(Tracked { inner: stream(body), _guard: guard }),
            None => stream(body),
        };
        Ok(Response::from_parts(parts, body))
    }

    /// Resolve which upstream group should handle this request.
    pub fn resolve_upstream<B>(&self, req: &Request<B>) -> String {
        // Default strategy: use Host (or the h2 :authority) or fall back to
        // the first upstream.
        if let Some(host) = request_host(req) {
            if self.upstreams.contains_key(host) {
                return host.to_string();
            }
        }

        // Fall back to the first registered upstream.
        self.upstreams
            .iter()
            .next()
            .map(|entry| entry.key().clone())
            .unwrap_or_default()
    }

    /// Select a backend from an upstream using the configured strategy.
    ///
    /// Fail-open: when every backend is unhealthy, selection proceeds over
    /// the full set rather than refusing traffic (WSLProxy parity).
    fn select_backend(
        &self,
        upstream: &UpstreamState,
    ) -> Result<Arc<BackendState>, ProxyError> {
        if upstream.backends.is_empty() {
            return Err(ProxyError::NoHealthyBackend(upstream.name.clone()));
        }

        let mut candidates: Vec<Arc<BackendState>> = upstream
            .backends
            .iter()
            .filter(|b| b.is_available())
            .cloned()
            .collect();

        if candidates.is_empty() {
            warn!(
                upstream = %upstream.name,
                "All backends unhealthy — failing open across full set"
            );
            metrics::counter!("proxy_fail_open_total", "upstream" => upstream.name.clone())
                .increment(1);
            candidates = upstream.backends.to_vec();
        }

        match upstream.strategy.as_str() {
            "least_connections" => {
                let selected = candidates
                    .iter()
                    .min_by_key(|b| b.active_connections.load(Ordering::Relaxed))
                    .unwrap();
                Ok(selected.clone())
            }
            "weighted" => {
                // Weighted round-robin: expand entries by weight, then round-robin.
                let total_weight: u32 = candidates.iter().map(|b| b.server.weight).sum();
                if total_weight == 0 {
                    return Err(ProxyError::NoHealthyBackend(upstream.name.clone()));
                }
                let index = upstream
                    .round_robin_index
                    .fetch_add(1, Ordering::Relaxed)
                    % total_weight as usize;

                let mut cumulative: u32 = 0;
                for backend in &candidates {
                    cumulative += backend.server.weight;
                    if index < cumulative as usize {
                        return Ok(backend.clone());
                    }
                }

                Ok(candidates.last().unwrap().clone())
            }
            // round_robin and anything unknown
            _ => {
                let index = upstream
                    .round_robin_index
                    .fetch_add(1, Ordering::Relaxed)
                    % candidates.len();
                Ok(candidates[index].clone())
            }
        }
    }

    /// Start background health checks for all upstreams.
    pub fn start_health_checks(self: &Arc<Self>) {
        for entry in self.upstreams.iter() {
            let upstream = entry.value().clone();

            if let Some(ref hc_config) = upstream.health_check {
                let client = self.health_client.clone();
                let interval = Duration::from_secs(hc_config.interval_secs.max(1));
                let path = hc_config.path.clone();
                let threshold = hc_config.unhealthy_threshold;
                let stop_rx = self.hc_stop.subscribe();

                info!(
                    upstream = %upstream.name,
                    interval_secs = interval.as_secs(),
                    path = %path,
                    "Active health checks started"
                );

                tokio::spawn(async move {
                    health_check_loop(upstream, client, interval, path, threshold, stop_rx).await;
                });
            }
        }
    }
}

/// Continuous health check loop for one upstream group.
async fn health_check_loop(
    upstream: Arc<UpstreamState>,
    client: Client,
    interval: Duration,
    path: String,
    unhealthy_threshold: u32,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
) {
    let mut failure_counts: Vec<u32> = vec![0; upstream.backends.len()];

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = stop_rx.changed() => {
                info!(upstream = %upstream.name, "Health check loop stopped");
                return;
            }
        }

        for (i, backend) in upstream.backends.iter().enumerate() {
            let (scheme, authority) = backend_origin(&backend.server.address);
            let url = format!("{scheme}://{authority}{path}");

            let is_healthy = matches!(
                client.get(&url).send().await,
                Ok(resp) if resp.status().is_success()
            );

            if is_healthy {
                failure_counts[i] = 0;
                let mut status = backend.status.write().await;
                if *status == HealthStatus::Unhealthy {
                    info!(
                        backend = %backend.server.address,
                        upstream = %upstream.name,
                        "Backend recovered"
                    );
                }
                *status = HealthStatus::Healthy;
            } else {
                failure_counts[i] += 1;
                if failure_counts[i] >= unhealthy_threshold {
                    let mut status = backend.status.write().await;
                    if *status == HealthStatus::Healthy {
                        warn!(
                            backend = %backend.server.address,
                            upstream = %upstream.name,
                            failures = failure_counts[i],
                            "Backend marked unhealthy"
                        );
                    }
                    *status = HealthStatus::Unhealthy;
                }
            }
        }
    }
}

/// Split a backend address into (scheme, authority). Addresses are
/// `host:port` (plain HTTP) or `https://host:port` (TLS to the backend,
/// certificate verified, SNI = host).
pub fn backend_origin(address: &str) -> (&'static str, &str) {
    if let Some(rest) = address.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = address.strip_prefix("http://") {
        ("http", rest)
    } else {
        ("http", address)
    }
}

/// HTTP + HTTPS connector. Backend certificates are verified against the
/// system trust store (internal CAs installed on the host work), falling
/// back to the bundled Mozilla roots when the system store is unavailable.
fn https_connector(http: HttpConnector) -> HttpsConnector<HttpConnector> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let builder = match hyper_rustls::HttpsConnectorBuilder::new().with_native_roots() {
        Ok(builder) => builder,
        Err(err) => {
            warn!(%err, "System trust store unavailable — using bundled web PKI roots");
            hyper_rustls::HttpsConnectorBuilder::new().with_webpki_roots()
        }
    };
    builder
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http)
}

/// Hop-by-hop headers that must not be forwarded (RFC 9110 §7.6.1).
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Remove hop-by-hop headers, including any named in `Connection`.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();
    for name in listed {
        headers.remove(name);
    }
    let hop: Vec<HeaderName> = headers
        .keys()
        .filter(|name| is_hop_by_hop(name.as_str()))
        .cloned()
        .collect();
    for name in hop {
        headers.remove(name);
    }
}

/// The client's Host: the `Host` header (HTTP/1.1) or the URI authority
/// (HTTP/2 `:authority`).
pub fn request_host<B>(req: &Request<B>) -> Option<&str> {
    req.headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| req.uri().authority().map(|a| a.as_str()))
}

/// Whether this is a gRPC call (must go upstream over HTTP/2).
fn is_grpc(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/grpc"))
}

/// The protocol an HTTP/1.1 client asks to upgrade to (`Connection:
/// upgrade` + `Upgrade: <proto>`), e.g. `websocket`.
fn upgrade_protocol<B>(req: &Request<B>) -> Option<HeaderValue> {
    let wants_upgrade = req
        .headers()
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
    if !wants_upgrade {
        return None;
    }
    req.headers().get(header::UPGRADE).cloned()
}

/// Build the header set sent upstream: end-to-end headers with the client's
/// Host preserved, plus the standard forwarding headers (`X-Forwarded-For`,
/// `X-Forwarded-Host`, `X-Forwarded-Proto`) and WSLProxy-parity
/// `X-Origin-IP`.
fn build_upstream_headers<B>(req: &Request<B>, opts: &ForwardOptions) -> HeaderMap {
    let headers = req.headers();
    let mut map = headers.clone();
    strip_hop_by_hop(&mut map);

    // HTTP/2 clients carry the host in :authority; give HTTP/1.1 upstreams
    // an explicit Host so virtual hosting behind the proxy keeps working.
    let host = request_host(req).map(str::to_owned);
    if let Some(host) = &host {
        if let Ok(val) = HeaderValue::from_str(host) {
            map.insert(header::HOST, val.clone());
            map.insert("x-forwarded-host", val);
        }
    }

    let client_ip = opts.client_addr.ip().to_string();

    let xff = match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        Some(existing) => format!("{existing}, {client_ip}"),
        None => client_ip.clone(),
    };
    if let Ok(val) = HeaderValue::from_str(&xff) {
        map.insert("x-forwarded-for", val);
    }
    if let Ok(val) = HeaderValue::from_str(&client_ip) {
        map.insert("x-origin-ip", val);
    }

    // Preserve an inbound X-Forwarded-Proto (chained proxies know the
    // original scheme); otherwise stamp the scheme this listener saw.
    if !map.contains_key("x-forwarded-proto") {
        map.insert("x-forwarded-proto", HeaderValue::from_static(opts.scheme));
    }

    // Rule-level request header manipulation.
    if let Some(hm) = &opts.headers {
        for (name, value) in &hm.request_set {
            if let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                map.insert(n, v);
            }
        }
        for name in &hm.request_remove {
            if let Ok(n) = HeaderName::from_bytes(name.as_bytes()) {
                map.remove(n);
            }
        }
    }

    map
}

/// Render an error with its source chain (hyper-util wraps the useful
/// cause, e.g. "connection refused", a level down).
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        source = cause.source();
    }
    out
}

/// Splice an upgraded client connection to the upgraded upstream
/// connection until either side closes.
async fn tunnel(
    client: OnUpgrade,
    upstream: OnUpgrade,
    backend: String,
    _guard: Option<ConnGuard>,
) {
    let (client, upstream) = match tokio::try_join!(client, upstream) {
        Ok(pair) => pair,
        Err(err) => {
            warn!(%backend, %err, "Upgrade handshake failed");
            return;
        }
    };
    let mut client = TokioIo::new(client);
    let mut upstream = TokioIo::new(upstream);

    metrics::gauge!("proxy_upgraded_connections").increment(1.0);
    match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        Ok((up, down)) => debug!(%backend, bytes_up = up, bytes_down = down, "Tunnel closed"),
        Err(err) => debug!(%backend, %err, "Tunnel closed with error"),
    }
    metrics::gauge!("proxy_upgraded_connections").decrement(1.0);
}

/// Holds a backend's active-connection slot until dropped.
pub struct ConnGuard(Arc<BackendState>);

impl ConnGuard {
    fn new(backend: Arc<BackendState>) -> Self {
        backend.active_connections.fetch_add(1, Ordering::Relaxed);
        Self(backend)
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A response body that releases its backend's connection slot when the
/// stream ends or the client goes away.
struct Tracked {
    inner: BoxBody,
    _guard: ConnGuard,
}

impl Body for Tracked {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        std::pin::Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Proxy-related errors.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("No upstream configured for: {0}")]
    NoUpstream(String),

    #[error("No healthy backend in upstream: {0}")]
    NoHealthyBackend(String),

    #[error("Backend communication error: {0}")]
    BackendError(String),

    #[error("Upstream did not respond within {0:?}")]
    Timeout(Duration),
}

impl std::fmt::Display for ProxyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProxyEngine({} upstreams)", self.upstreams.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_with(strategy: &str, addresses: &[(&str, u32)]) -> ProxyEngine {
        ProxyEngine::new(&[UpstreamConfig {
            name: "test".to_string(),
            servers: addresses
                .iter()
                .map(|(addr, weight)| BackendServer {
                    address: addr.to_string(),
                    weight: *weight,
                })
                .collect(),
            load_balancing: strategy.to_string(),
            health_check: None,
            circuit_breaker: None,
            retry: None,
            transform: None,
        }])
    }

    #[tokio::test]
    async fn round_robin_cycles_backends() {
        let engine = engine_with("round_robin", &[("a:1", 1), ("b:1", 1)]);
        let upstream = engine.upstreams.get("test").unwrap().clone();

        let first = engine.select_backend(&upstream).unwrap().server.address.clone();
        let second = engine.select_backend(&upstream).unwrap().server.address.clone();
        let third = engine.select_backend(&upstream).unwrap().server.address.clone();

        assert_ne!(first, second);
        assert_eq!(first, third);
    }

    #[tokio::test]
    async fn weighted_respects_weights() {
        let engine = engine_with("weighted", &[("heavy:1", 3), ("light:1", 1)]);
        let upstream = engine.upstreams.get("test").unwrap().clone();

        let mut heavy = 0;
        for _ in 0..40 {
            let backend = engine.select_backend(&upstream).unwrap();
            if backend.server.address == "heavy:1" {
                heavy += 1;
            }
        }
        assert_eq!(heavy, 30, "3:1 weights over 40 picks");
    }

    #[tokio::test]
    async fn passive_ejection_and_fail_open() {
        let engine = engine_with("round_robin", &[("a:1", 1)]);
        let upstream = engine.upstreams.get("test").unwrap().clone();
        let backend = upstream.backends[0].clone();

        for _ in 0..PASSIVE_MAX_FAILS {
            backend.record_failure();
        }
        assert!(!backend.is_available(), "ejected after consecutive failures");

        // Fail-open: selection still succeeds with every backend down.
        let selected = engine.select_backend(&upstream).unwrap();
        assert_eq!(selected.server.address, "a:1");
    }

    #[test]
    fn upstream_headers_strip_hop_by_hop_and_add_forwarding() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("host", "example.com".parse().unwrap());
        headers.insert("connection", "keep-alive".parse().unwrap());
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        headers.insert("x-custom", "yes".parse().unwrap());
        headers.insert("x-forwarded-for", "198.51.100.7".parse().unwrap());

        headers.insert("connection", "keep-alive, x-drop-me".parse().unwrap());
        headers.insert("x-drop-me", "1".parse().unwrap());
        let mut req = Request::new(());
        *req.headers_mut() = headers;

        let opts = ForwardOptions {
            client_addr: "203.0.113.9:55555".parse().unwrap(),
            scheme: "https",
            ..Default::default()
        };
        let out = build_upstream_headers(&req, &opts);

        assert!(out.get("connection").is_none());
        assert!(out.get("transfer-encoding").is_none());
        assert!(out.get("x-drop-me").is_none(), "Connection-listed header stripped");
        assert_eq!(out.get("host").unwrap(), "example.com", "Host preserved");
        assert_eq!(out.get("x-custom").unwrap(), "yes");
        assert_eq!(out.get("x-forwarded-host").unwrap(), "example.com");
        assert_eq!(out.get("x-origin-ip").unwrap(), "203.0.113.9");
        assert_eq!(
            out.get("x-forwarded-for").unwrap(),
            "198.51.100.7, 203.0.113.9"
        );
        assert_eq!(out.get("x-forwarded-proto").unwrap(), "https");
    }
}
