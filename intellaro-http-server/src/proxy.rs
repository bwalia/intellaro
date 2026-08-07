//! Reverse proxy and load balancer module.
//!
//! Supports multiple load-balancing strategies (round-robin, least-connections,
//! weighted) with active health checking, passive failure ejection, and
//! fail-open selection when every backend is unhealthy.
//!
//! Phase-0 data plane is store-and-forward: request and response bodies are
//! fully buffered. The streaming hyper-conn rewrite is a Phase 1 milestone
//! (see docs/parity-matrix.md).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use hyper::body::Bytes;
use hyper::Request;
use hyper::Response;
use reqwest::Client;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::{BackendServer, HealthCheckConfig, UpstreamConfig};
use crate::server::BoxBody;

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
    http_client: Client,
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

        let http_client = Client::builder()
            .pool_max_idle_per_host(100)
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to build HTTP client");

        info!(
            upstream_count = upstream_configs.len(),
            "Proxy engine initialized"
        );

        let (hc_stop, _) = tokio::sync::watch::channel(false);

        Self {
            upstreams,
            http_client,
            hc_stop,
        }
    }

    /// Forward a request to an appropriate upstream backend.
    ///
    /// `req` carries method/uri/headers; the (already buffered) body is
    /// passed separately so retries can reuse it.
    pub async fn forward<B>(
        &self,
        req: &Request<B>,
        body: Bytes,
        client_addr: SocketAddr,
    ) -> Result<Response<BoxBody>, ProxyError> {
        let upstream_name = self.resolve_upstream(req);

        let upstream = self
            .upstreams
            .get(&upstream_name)
            .ok_or_else(|| ProxyError::NoUpstream(upstream_name.clone()))?;

        let backend = self.select_backend(&upstream)?;

        metrics::counter!("proxy_requests_total", "upstream" => upstream_name.clone()).increment(1);

        backend.active_connections.fetch_add(1, Ordering::Relaxed);
        let result = self
            .send_upstream(req, &backend.server.address, body, client_addr)
            .await;
        backend.active_connections.fetch_sub(1, Ordering::Relaxed);

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
        body: Bytes,
        client_addr: SocketAddr,
    ) -> Result<Response<BoxBody>, ProxyError> {
        metrics::counter!("proxy_requests_total", "backend" => backend_address.to_string())
            .increment(1);
        self.send_upstream(req, backend_address, body, client_addr).await
    }

    /// Perform the actual upstream exchange (buffered, via reqwest).
    async fn send_upstream<B>(
        &self,
        req: &Request<B>,
        backend_address: &str,
        body: Bytes,
        client_addr: SocketAddr,
    ) -> Result<Response<BoxBody>, ProxyError> {
        let target_url = format!(
            "http://{}{}",
            backend_address,
            req.uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/")
        );

        let result = self
            .http_client
            .request(req.method().clone(), &target_url)
            .headers(build_upstream_headers(req.headers(), client_addr))
            .body(body)
            .send()
            .await;

        match result {
            Ok(resp) => {
                let status = resp.status();
                let headers = resp.headers().clone();
                let body_bytes = resp
                    .bytes()
                    .await
                    .map_err(|err| ProxyError::BackendError(err.to_string()))?;

                let mut builder = Response::builder().status(status);
                for (key, value) in headers.iter() {
                    if !is_hop_by_hop(key.as_str()) {
                        builder = builder.header(key, value);
                    }
                }

                builder
                    .body(BoxBody::new(body_bytes))
                    .map_err(|err| ProxyError::BackendError(err.to_string()))
            }
            Err(err) => Err(ProxyError::BackendError(err.to_string())),
        }
    }

    /// Resolve which upstream group should handle this request.
    pub fn resolve_upstream<B>(&self, req: &Request<B>) -> String {
        // Default strategy: use Host header or fall back to first upstream.
        if let Some(host) = req.headers().get("host").and_then(|h| h.to_str().ok()) {
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
                let client = self.http_client.clone();
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
            let url = format!("http://{}{}", backend.server.address, path);

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

/// Build the header set sent upstream: end-to-end headers only, plus the
/// standard forwarding headers (`X-Forwarded-For`, `X-Forwarded-Host`) and
/// WSLProxy-parity `X-Origin-IP`.
fn build_upstream_headers(
    headers: &hyper::HeaderMap,
    client_addr: SocketAddr,
) -> reqwest::header::HeaderMap {
    let mut map = reqwest::header::HeaderMap::new();

    for (key, value) in headers.iter() {
        let name = key.as_str();
        // reqwest derives Host from the target URL; the original host is
        // forwarded as X-Forwarded-Host below.
        if is_hop_by_hop(name) || name.eq_ignore_ascii_case("host") {
            continue;
        }
        if let (Ok(name), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            map.append(name, val);
        }
    }

    let client_ip = client_addr.ip().to_string();

    let xff = match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        Some(existing) => format!("{existing}, {client_ip}"),
        None => client_ip.clone(),
    };
    if let Ok(val) = reqwest::header::HeaderValue::from_str(&xff) {
        map.insert("x-forwarded-for", val);
    }
    if let Ok(val) = reqwest::header::HeaderValue::from_str(&client_ip) {
        map.insert("x-origin-ip", val);
    }
    if let Some(host) = headers.get("host").and_then(|v| v.to_str().ok()) {
        if let Ok(val) = reqwest::header::HeaderValue::from_str(host) {
            map.insert("x-forwarded-host", val);
        }
    }

    map
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

        let out = build_upstream_headers(&headers, "203.0.113.9:55555".parse().unwrap());

        assert!(out.get("connection").is_none());
        assert!(out.get("transfer-encoding").is_none());
        assert!(out.get("host").is_none());
        assert_eq!(out.get("x-custom").unwrap(), "yes");
        assert_eq!(out.get("x-forwarded-host").unwrap(), "example.com");
        assert_eq!(out.get("x-origin-ip").unwrap(), "203.0.113.9");
        assert_eq!(
            out.get("x-forwarded-for").unwrap(),
            "198.51.100.7, 203.0.113.9"
        );
    }
}
