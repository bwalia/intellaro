//! HTTP server setup and event-driven worker engine.
//!
//! Manages listener binding, TLS termination, connection acceptance,
//! and request dispatching across an async worker pool.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use intellaro_http_router::config::HeaderManipulation;
use intellaro_http_router::engine::RoutingError;
use intellaro_http_router::matcher::RequestInfo;
use intellaro_http_router::{RouteOutcome, RoutingEngine, RuleAction};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::cache::CacheLayer;
use crate::circuit_breaker::{self, CircuitBreakerRegistry};
use crate::config::{
    lookup_host_policy, AcmeConfig, ConfigManager, FallbackConfig, HostPolicy, ListenerConfig, StaticRootConfig,
};
use crate::logging;
use crate::proxy::ProxyEngine;
use crate::security::SecurityEngine;
use crate::tls::CertStore;
use tokio_rustls::TlsAcceptor;

/// Time allowed for a client to complete the TLS handshake.
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How often static TLS certificates are re-read from disk.
const CERT_RELOAD_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

/// Boxed error type carried by streaming bodies.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Body type used throughout the data plane: either a fully-buffered
/// payload (generated pages, cache hits) or a streamed upstream/client body.
pub type BoxBody = http_body_util::combinators::UnsyncBoxBody<Bytes, BoxError>;

/// Wrap a complete payload as a `BoxBody`.
pub fn full(bytes: impl Into<Bytes>) -> BoxBody {
    http_body_util::Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// Box a streamed body (client request or upstream response).
pub fn stream<B>(body: B) -> BoxBody
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    body.map_err(Into::into).boxed_unsync()
}

/// Maximum buffered request body size when a body must be replayable
/// (retry-enabled upstreams). Everything else streams.
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Largest response body buffered for the cache; larger (or unknown-length
/// bodies that grow past it) stream through uncached.
const MAX_CACHEABLE_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Shared application state accessible from all request handlers.
pub struct AppState {
    pub config_manager: ConfigManager,
    pub proxy_engine: Arc<ProxyEngine>,
    pub cache_layer: CacheLayer,
    pub security_engine: SecurityEngine,
    pub static_roots: Vec<StaticRootConfig>,
    pub routing_engine: Option<RoutingEngine>,
    pub circuit_breakers: CircuitBreakerRegistry,
    pub fallback: FallbackConfig,
    pub host_policies: Vec<HostPolicy>,
}

/// Start the HTTP server with all configured listeners.
///
/// Each listener runs in its own task, accepting connections and
/// dispatching them to the shared worker pool.
pub async fn run(
    config_manager: ConfigManager,
    mut shutdown_rx: watch::Receiver<bool>,
    routing_engine: Option<RoutingEngine>,
    ready: Option<Arc<AtomicBool>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = config_manager.get().await;

    let state = build_app_state(config_manager.clone(), &config, routing_engine);

    // Data-plane state is distributed to listeners via a watch channel so a
    // config reload swaps in a fresh AppState without dropping connections.
    // Listener sockets themselves are fixed for the process lifetime —
    // changing bind addresses still requires a restart.
    let (state_tx, state_rx) = watch::channel(state);

    // One certificate store per HTTPS listener. A bad certificate at
    // startup is fatal; later reload failures keep the last good one.
    let mut tls_stores: Vec<(SocketAddr, Arc<CertStore>)> = Vec::new();
    for listener in &config.listeners {
        if let Some(tls) = &listener.tls {
            let store = CertStore::new();
            store
                .set_static(tls)
                .map_err(|err| format!("listener {}: {err}", listener.address))?;
            tls_stores.push((listener.address, store));
        }
    }

    // ACME managers, one per ACME-enabled listener; reloads push updated
    // domain lists through the watch channels.
    let mut acme_senders: Vec<(SocketAddr, watch::Sender<AcmeConfig>)> = Vec::new();
    let mut acme_tasks = Vec::new();
    for listener in &config.listeners {
        if let Some(acme) = listener.tls.as_ref().and_then(|t| t.acme.clone()) {
            let store = tls_stores
                .iter()
                .find(|(addr, _)| *addr == listener.address)
                .map(|(_, s)| s.clone())
                .expect("store created for every TLS listener");
            let (tx, rx) = watch::channel(acme);
            acme_tasks.push(crate::acme::spawn(listener.address, rx, store));
            acme_senders.push((listener.address, tx));
        }
    }

    let mut change_rx = config_manager.subscribe();
    let reload_manager = config_manager.clone();
    let reload_stores = tls_stores.clone();
    let reload_task = tokio::spawn(async move {
        loop {
            if change_rx.changed().await.is_err() {
                break;
            }
            let new_config = reload_manager.get().await;
            // Certificate paths may change with the config; files may have
            // been rotated in place either way.
            for (address, store) in &reload_stores {
                let paths = new_config
                    .listeners
                    .iter()
                    .find(|l| l.address == *address)
                    .and_then(|l| l.tls.as_ref());
                let result = match paths {
                    Some(tls) => store.set_static(tls),
                    None => store.reload_static(),
                };
                if let Err(err) = result {
                    warn!(%address, %err, "TLS certificate reload failed — keeping previous certificate");
                }
            }
            for (address, tx) in &acme_senders {
                let acme = new_config
                    .listeners
                    .iter()
                    .find(|l| l.address == *address)
                    .and_then(|l| l.tls.as_ref())
                    .and_then(|t| t.acme.clone());
                if let Some(acme) = acme {
                    tx.send_if_modified(|current| {
                        let changed = *current != acme;
                        *current = acme;
                        changed
                    });
                }
            }
            let engine = crate::bootstrap::build_routing_engine(&new_config);
            let new_state = build_app_state(reload_manager.clone(), &new_config, engine);
            if state_tx.send(new_state).is_err() {
                break;
            }
            info!("Data plane rebuilt from updated configuration (listeners unchanged)");
        }
    });

    // Pick up certificates rotated on disk (cert-manager, certbot) even
    // when the config itself does not change.
    let rotation_stores: Vec<Arc<CertStore>> = tls_stores.iter().map(|(_, s)| s.clone()).collect();
    let rotation_task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(CERT_RELOAD_INTERVAL);
        tick.tick().await;
        loop {
            tick.tick().await;
            crate::tls::reload_all(&rotation_stores);
        }
    });

    let mut listener_handles = Vec::new();

    for listener_config in &config.listeners {
        let acceptor = match &listener_config.tls {
            Some(tls) => {
                let store = tls_stores
                    .iter()
                    .find(|(addr, _)| *addr == listener_config.address)
                    .map(|(_, s)| s.clone())
                    .expect("store created for every TLS listener");
                Some(crate::tls::build_acceptor(&tls.min_version, store)?)
            }
            None => None,
        };
        let handle = spawn_listener(listener_config.clone(), state_rx.clone(), acceptor).await?;
        listener_handles.push(handle);
    }

    if let Some(ready) = &ready {
        ready.store(true, Ordering::Relaxed);
    }

    info!(
        listener_count = config.listeners.len(),
        workers = config.worker_count,
        "Intellaro HTTP server started"
    );

    // Wait for shutdown signal
    shutdown_rx
        .changed()
        .await
        .ok();

    info!("Shutdown signal received, draining connections...");

    // Allow in-flight requests to complete (graceful shutdown).
    for handle in listener_handles {
        handle.abort();
    }
    reload_task.abort();
    rotation_task.abort();
    for task in acme_tasks {
        task.abort();
    }

    info!("Server shut down gracefully");
    Ok(())
}

/// Build the full request-path state from a configuration snapshot.
fn build_app_state(
    config_manager: ConfigManager,
    config: &crate::config::ServerConfig,
    routing_engine: Option<RoutingEngine>,
) -> Arc<AppState> {
    let circuit_breakers = CircuitBreakerRegistry::new();
    for upstream in &config.upstreams {
        if let Some(ref cb_config) = upstream.circuit_breaker {
            circuit_breakers.register(&upstream.name, cb_config.clone());
            info!(upstream = %upstream.name, "Circuit breaker registered");
        }
    }

    let proxy_engine = Arc::new(ProxyEngine::new(&config.upstreams));
    proxy_engine.start_health_checks();

    Arc::new(AppState {
        config_manager,
        proxy_engine,
        cache_layer: CacheLayer::new(&config.cache),
        security_engine: SecurityEngine::new(&config.security),
        static_roots: config.static_roots.clone(),
        routing_engine,
        circuit_breakers,
        fallback: config.fallback.clone(),
        host_policies: config.host_policies.clone(),
    })
}

/// Spawn a TCP listener task for a single bind address.
async fn spawn_listener(
    listener_config: ListenerConfig,
    state_rx: watch::Receiver<Arc<AppState>>,
    acceptor: Option<TlsAcceptor>,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
    let tcp_listener = TcpListener::bind(listener_config.address).await?;

    info!(
        address = %listener_config.address,
        tls = listener_config.tls.is_some(),
        protocol = %listener_config.protocol,
        "Listener bound"
    );

    let handle = tokio::spawn(async move {
        accept_loop(tcp_listener, state_rx, acceptor).await;
    });

    Ok(handle)
}

/// Core accept loop — accepts TCP connections and spawns a task per
/// connection, completing the TLS handshake first on HTTPS listeners.
async fn accept_loop(
    listener: TcpListener,
    state_rx: watch::Receiver<Arc<AppState>>,
    acceptor: Option<TlsAcceptor>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let state_rx = state_rx.clone();
                let acceptor = acceptor.clone();
                metrics::gauge!("active_connections").increment(1.0);

                tokio::spawn(async move {
                    let _ = stream.set_nodelay(true);
                    let result = match acceptor {
                        None => handle_connection(stream, peer_addr, state_rx, "http").await,
                        Some(acceptor) => {
                            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                                Ok(Ok(tls_stream)) => {
                                    handle_connection(tls_stream, peer_addr, state_rx, "https").await
                                }
                                Ok(Err(err)) => {
                                    metrics::counter!("tls_handshake_errors_total").increment(1);
                                    debug!(%peer_addr, %err, "TLS handshake failed");
                                    Ok(())
                                }
                                Err(_) => {
                                    metrics::counter!("tls_handshake_errors_total").increment(1);
                                    debug!(%peer_addr, "TLS handshake timed out");
                                    Ok(())
                                }
                            }
                        }
                    };
                    if let Err(err) = result {
                        warn!(%peer_addr, %err, "Connection error");
                    }
                    metrics::gauge!("active_connections").decrement(1.0);
                });
            }
            Err(err) => {
                error!(%err, "Failed to accept connection");
            }
        }
    }
}

/// Handle a single TCP connection: run HTTP protocol over it.
///
/// State is resolved per request (not per connection) so long-lived
/// keep-alive connections observe config reloads immediately.
async fn handle_connection<S>(
    stream: S,
    peer_addr: SocketAddr,
    state_rx: watch::Receiver<Arc<AppState>>,
    scheme: &'static str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);

    let service = hyper::service::service_fn(move |req: Request<Incoming>| {
        let state = state_rx.borrow().clone();
        let addr = peer_addr;
        async move { handle_request(req, addr, state, scheme).await }
    });

    // `with_upgrades` keeps the socket available to hyper::upgrade so
    // WebSocket (and other HTTP/1.1 upgrade) requests can be tunnelled.
    ConnectionBuilder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(io, service)
        .await?;

    Ok(())
}

/// Transport policy layer around the pipeline: force-HTTPS redirects
/// before anything else runs, HSTS on every HTTPS response after.
async fn handle_request(
    req: Request<Incoming>,
    peer_addr: SocketAddr,
    state: Arc<AppState>,
    scheme: &'static str,
) -> Result<Response<BoxBody>, hyper::Error> {
    // ACME HTTP-01 challenges are answered before any policy, security
    // check or redirect can interfere with validation.
    if req.uri().path().starts_with(crate::acme::CHALLENGE_PREFIX) {
        if let Some(response) = crate::acme::challenge_response(req.uri().path()) {
            return Ok(response);
        }
    }

    let host = crate::proxy::request_host(&req).map(|h| strip_host_port(h).to_string());
    let policy = host
        .as_deref()
        .and_then(|h| lookup_host_policy(&state.host_policies, h))
        .cloned();
    let Some(policy) = policy else {
        return handle_pipeline(req, peer_addr, state, scheme).await;
    };

    // A front proxy that terminated TLS reports the original scheme.
    let secure = scheme == "https"
        || req
            .headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("https"));

    if policy.force_https && !secure && !req.uri().path().starts_with(crate::acme::CHALLENGE_PREFIX) {
        let response = https_redirect(&req, host.as_deref().unwrap_or_default(), policy.https_port);
        logging::record_response(response.status().as_u16(), req.method().as_str());
        metrics::counter!("https_redirects_total").increment(1);
        return Ok(response);
    }

    let mut response = handle_pipeline(req, peer_addr, state, scheme).await?;
    if secure {
        if let Some(hsts) = policy.hsts.as_deref() {
            if let Ok(value) = hyper::header::HeaderValue::from_str(hsts) {
                response
                    .headers_mut()
                    .insert(hyper::header::STRICT_TRANSPORT_SECURITY, value);
            }
        }
    }
    Ok(response)
}

/// 301 (GET/HEAD) or 308 (methods with bodies) to the HTTPS URL.
fn https_redirect<B>(req: &Request<B>, host: &str, https_port: Option<u16>) -> Response<BoxBody> {
    let mut location = format!("https://{host}");
    if let Some(port) = https_port.filter(|p| *p != 443) {
        location.push_str(&format!(":{port}"));
    }
    location.push_str(req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/"));
    let status = if matches!(*req.method(), hyper::Method::GET | hyper::Method::HEAD) {
        StatusCode::MOVED_PERMANENTLY
    } else {
        StatusCode::PERMANENT_REDIRECT
    };
    Response::builder()
        .status(status)
        .header(hyper::header::LOCATION, location)
        .body(full(Bytes::new()))
        .unwrap_or_else(|_| internal_error_response())
}

/// Central request pipeline: security -> cache -> static -> routing -> proxy.
async fn handle_pipeline(
    req: Request<Incoming>,
    peer_addr: SocketAddr,
    state: Arc<AppState>,
    scheme: &'static str,
) -> Result<Response<BoxBody>, hyper::Error> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let start = std::time::Instant::now();

    logging::record_request(&method, &path);

    // The body is held unread and streamed straight upstream when the
    // request is forwarded; it is only buffered when a retry policy needs
    // to replay it. The client's upgrade handle (WebSocket) travels with
    // the forward so the connection can be tunnelled after a 101.
    let (mut parts, body) = req.into_parts();
    let on_upgrade = parts.extensions.remove::<hyper::upgrade::OnUpgrade>();
    let mut req_body: Option<Incoming> = Some(body);
    // Body-less view of the request for match/cache/security layers.
    let req_view: Request<()> = Request::from_parts(parts, ());
    let req = &req_view;

    // 1. Security checks
    if let Some(response) = state.security_engine.check(req, peer_addr).await {
        let status = response.status().as_u16();
        logging::record_response(status, &method);
        logging::record_latency(start.elapsed().as_secs_f64(), &method, &path);
        return Ok(response);
    }

    // 2. Cache lookup (for cacheable requests)
    if let Some(cached_response) = state.cache_layer.get(req).await {
        metrics::counter!("cache_hits_total").increment(1);
        let status = cached_response.status().as_u16();
        logging::record_response(status, &method);
        logging::record_latency(start.elapsed().as_secs_f64(), &method, &path);
        return Ok(cached_response);
    }

    metrics::counter!("cache_misses_total").increment(1);

    // 3. Static file serving
    if let Some(response) = serve_static_file(&path, &state.static_roots).await {
        let response = cache_and_finalize(&state, req, response).await;
        let status = response.status().as_u16();
        logging::record_response(status, &method);
        logging::record_latency(start.elapsed().as_secs_f64(), &method, &path);
        return Ok(response);
    }

    // 4. Intelligent routing engine (if configured)
    if let Some(ref engine) = state.routing_engine {
        let owned_info = OwnedRequestInfo::from_request(req, peer_addr.ip().to_string());
        let request_info = owned_info.as_request_info();
        let source_ip = peer_addr.ip().to_string();

        match engine.route(&request_info, None, Some(&source_ip)) {
            // Direct response: static page or redirect — no backend.
            Ok(RouteOutcome::Respond {
                rule_name,
                action,
                header_manipulation,
            }) => {
                debug!(rule = %rule_name, "Routing engine direct-response action");
                let mut response = build_action_response(&action);
                apply_response_headers(&mut response, header_manipulation.as_ref());
                let status = response.status().as_u16();
                logging::record_response(status, &method);
                logging::record_latency(start.elapsed().as_secs_f64(), &method, &path);
                return Ok(response);
            }

            Ok(RouteOutcome::Forward(decision)) => {
                let route_start = std::time::Instant::now();
                debug!(
                    rule = %decision.matched_rule,
                    backend = %decision.backend_id,
                    group = %decision.backend_group,
                    canary = decision.is_canary,
                    "Routing engine decision"
                );

                let mut opts = crate::proxy::ForwardOptions {
                    client_addr: peer_addr,
                    scheme,
                    path_override: rewrite_path(
                        req.uri(),
                        decision.strip_path_prefix.as_deref(),
                        decision.rewrite_prefix_with.as_deref(),
                    ),
                    headers: decision.header_manipulation.clone(),
                    read_timeout: decision.timeout_secs.map(std::time::Duration::from_secs),
                    upgrade: on_upgrade,
                };
                let body = req_body.take().map(stream).unwrap_or_else(|| full(Bytes::new()));

                let response = match state
                    .proxy_engine
                    .forward_to(req, &decision.backend_id, body, &mut opts)
                    .await
                {
                    Ok(mut resp) => {
                        let latency_ms = route_start.elapsed().as_secs_f64() * 1000.0;
                        engine.record_backend_latency(&decision.backend_id, latency_ms);
                        engine.release_backend(&decision.backend_state);
                        apply_response_headers(&mut resp, decision.header_manipulation.as_ref());
                        resp
                    }
                    Err(err) => {
                        engine.record_backend_error(
                            &decision.backend_id,
                            &decision.backend_group,
                            decision.is_canary,
                            decision.canary_deployment.as_deref(),
                        );
                        engine.release_backend(&decision.backend_state);
                        error!(%err, %path, backend = %decision.backend_id, "Routed proxy error");
                        metrics::counter!("proxy_errors_total").increment(1);
                        proxy_error_response(&err)
                    }
                };

                let response = cache_and_finalize(&state, req, response).await;
                let status = response.status().as_u16();
                logging::record_response(status, &method);
                logging::record_latency(start.elapsed().as_secs_f64(), &method, &path);
                return Ok(response);
            }
            Err(RoutingError::NoMatchingRule) => {
                // WSLProxy `no_server`/`no_rule` parity: configurable
                // fallback page instead of proxying to the first upstream.
                if state.fallback.mode == "not_found" {
                    debug!(%path, "No routing rule matched — serving fallback page");
                    let response = fallback_response(&state.fallback);
                    logging::record_response(response.status().as_u16(), &method);
                    logging::record_latency(start.elapsed().as_secs_f64(), &method, &path);
                    return Ok(response);
                }
                debug!(%path, "No routing rule matched, falling back to default proxy");
            }
            Err(err) => {
                warn!(%err, %path, "Routing engine error");
                metrics::counter!("routing_errors_total").increment(1);
                let status_code = match err {
                    RoutingError::CircuitBreakerOpen(_) => StatusCode::SERVICE_UNAVAILABLE,
                    _ => StatusCode::BAD_GATEWAY,
                };
                let response = Response::builder()
                    .status(status_code)
                    .body(full(hyper::body::Bytes::from(err.to_string())))
                    .unwrap();
                logging::record_response(status_code.as_u16(), &method);
                logging::record_latency(start.elapsed().as_secs_f64(), &method, &path);
                return Ok(response);
            }
        }
    }

    // 5. Default proxy to upstream with circuit breaker + retry
    let upstream_name = state.proxy_engine.resolve_upstream(req);

    // Check circuit breaker before forwarding.
    if let Some(cb) = state.circuit_breakers.get(&upstream_name) {
        if !cb.allow_request().await {
            metrics::counter!("circuit_breaker_rejections_total").increment(1);
            let response = Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(full(hyper::body::Bytes::from(
                    "Service Unavailable (circuit breaker open)",
                )))
                .unwrap();
            logging::record_response(503, &method);
            logging::record_latency(start.elapsed().as_secs_f64(), &method, &path);
            return Ok(response);
        }
    }

    // Determine retry config for this upstream.
    let retry_config = {
        let config = state.config_manager.get().await;
        config
            .upstreams
            .iter()
            .find(|u| u.name == upstream_name)
            .and_then(|u| u.retry.clone())
    };

    let max_attempts = retry_config
        .as_ref()
        .map(|r| r.max_retries + 1)
        .unwrap_or(1);

    let mut last_response = None;

    let mut fwd_opts = crate::proxy::ForwardOptions {
        client_addr: peer_addr,
        scheme,
        upgrade: on_upgrade,
        ..Default::default()
    };

    // Retries replay the body, so only then is it buffered (bounded).
    let replay_body = if max_attempts > 1 {
        let body = req_body.take().expect("request body unread");
        match read_body_limited(body).await {
            Ok(bytes) => Some(bytes),
            Err(response) => {
                warn!(%path, status = response.status().as_u16(), "Failed to read request body");
                logging::record_response(response.status().as_u16(), &method);
                return Ok(response);
            }
        }
    } else {
        None
    };

    for attempt in 0..max_attempts {
        let body = match &replay_body {
            Some(bytes) => full(bytes.clone()),
            None => req_body.take().map(stream).unwrap_or_else(|| full(Bytes::new())),
        };
        match state
            .proxy_engine
            .forward(req, body, &mut fwd_opts)
            .await
        {
            Ok(resp) => {
                let status_code = resp.status().as_u16();

                // Check if we should retry this status code.
                if attempt + 1 < max_attempts {
                    if let Some(ref rc) = retry_config {
                        if circuit_breaker::is_retryable_status(status_code, rc) {
                            debug!(
                                attempt = attempt + 1,
                                status = status_code,
                                "Retryable status, will retry"
                            );
                            let backoff = circuit_breaker::calculate_backoff(attempt, rc);
                            tokio::time::sleep(backoff).await;
                            metrics::counter!("proxy_retries_total").increment(1);
                            last_response = Some(resp);
                            continue;
                        }
                    }
                }

                // Record circuit breaker success.
                if let Some(cb) = state.circuit_breakers.get(&upstream_name) {
                    cb.record_success().await;
                }

                let resp = cache_and_finalize(&state, req, resp).await;
                let status = resp.status().as_u16();
                logging::record_response(status, &method);
                logging::record_latency(start.elapsed().as_secs_f64(), &method, &path);
                return Ok(resp);
            }
            Err(err) => {
                // Record circuit breaker failure.
                if let Some(cb) = state.circuit_breakers.get(&upstream_name) {
                    cb.record_failure().await;
                }

                if attempt + 1 < max_attempts {
                    if let Some(ref rc) = retry_config {
                        debug!(
                            attempt = attempt + 1,
                            %err,
                            "Proxy error, will retry"
                        );
                        let backoff = circuit_breaker::calculate_backoff(attempt, rc);
                        tokio::time::sleep(backoff).await;
                        metrics::counter!("proxy_retries_total").increment(1);
                        continue;
                    }
                }

                error!(%err, %path, "Proxy error");
                metrics::counter!("proxy_errors_total").increment(1);
                let response = proxy_error_response(&err);
                logging::record_response(response.status().as_u16(), &method);
                logging::record_latency(start.elapsed().as_secs_f64(), &method, &path);
                return Ok(response);
            }
        }
    }

    // All retries exhausted — return the last response.
    let response = last_response.unwrap_or_else(|| {
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(full(hyper::body::Bytes::from("Bad Gateway")))
            .unwrap()
    });

    let status = response.status().as_u16();
    logging::record_response(status, &method);
    logging::record_latency(start.elapsed().as_secs_f64(), &method, &path);

    Ok(response)
}

/// Buffer a request body (bounded) so it can be replayed across retries.
async fn read_body_limited(body: Incoming) -> Result<Bytes, Response<BoxBody>> {
    match http_body_util::Limited::new(body, MAX_REQUEST_BODY_BYTES).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(err) => {
            let status = if err.downcast_ref::<http_body_util::LengthLimitError>().is_some() {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            };
            Err(Response::builder()
                .status(status)
                .body(full(status.canonical_reason().unwrap_or("error")))
                .unwrap_or_else(|_| internal_error_response()))
        }
    }
}

/// 502 for a failed upstream exchange, 504 when it timed out.
fn proxy_error_response(err: &crate::proxy::ProxyError) -> Response<BoxBody> {
    let (status, body) = match err {
        crate::proxy::ProxyError::Timeout(_) => (StatusCode::GATEWAY_TIMEOUT, "Gateway Timeout"),
        _ => (StatusCode::BAD_GATEWAY, "Bad Gateway"),
    };
    Response::builder()
        .status(status)
        .body(full(body))
        .unwrap_or_else(|_| internal_error_response())
}

/// Store a response in the cache when it is cacheable, then hand it on.
///
/// Only cacheable responses are buffered — everything else streams
/// untouched. A cacheable body that turns out larger than
/// `MAX_CACHEABLE_BODY_BYTES` is not cached: the bytes read so far are
/// replayed ahead of the rest of the stream.
async fn cache_and_finalize(
    state: &AppState,
    req: &Request<()>,
    resp: Response<BoxBody>,
) -> Response<BoxBody> {
    if !state.cache_layer.should_store(req, &resp) {
        return resp;
    }
    let declared_len = resp
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared_len.is_some_and(|len| len > MAX_CACHEABLE_BODY_BYTES) {
        return resp;
    }

    let (parts, mut body) = resp.into_parts();
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match body.frame().await {
            None => break,
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => {
                    buf.extend_from_slice(&data);
                    if buf.len() > MAX_CACHEABLE_BODY_BYTES {
                        return Response::from_parts(parts, prepend(vec![hyper::body::Frame::data(buf.into())], body));
                    }
                }
                // Trailers are not cached; relay what we have and stop.
                Err(trailers) => {
                    return Response::from_parts(
                        parts,
                        prepend(vec![hyper::body::Frame::data(buf.into()), trailers], body),
                    );
                }
            },
            Some(Err(err)) => {
                warn!(%err, "Upstream body failed while buffering for cache");
                return proxy_error_response(&crate::proxy::ProxyError::BackendError(err.to_string()));
            }
        }
    }

    let cached = Response::from_parts(parts, Bytes::from(buf));
    state.cache_layer.store(req, &cached).await;
    let (parts, bytes) = cached.into_parts();
    Response::from_parts(parts, full(bytes))
}

/// A body that yields `frames` first, then the rest of `rest`.
fn prepend(frames: Vec<hyper::body::Frame<Bytes>>, rest: BoxBody) -> BoxBody {
    use futures::StreamExt;
    let head = futures::stream::iter(frames.into_iter().map(Ok::<_, BoxError>));
    let tail = http_body_util::BodyStream::new(rest);
    stream(http_body_util::StreamBody::new(head.chain(tail)))
}

/// Serve a static file if the request path matches a configured static root.
async fn serve_static_file(
    request_path: &str,
    static_roots: &[StaticRootConfig],
) -> Option<Response<BoxBody>> {
    for root in static_roots {
        if !request_path.starts_with(&root.url_prefix) {
            continue;
        }

        let relative = request_path.strip_prefix(&root.url_prefix).unwrap_or("");
        // Default to index.html for the root path
        let relative = if relative.is_empty() || relative == "/" {
            "index.html"
        } else {
            relative.trim_start_matches('/')
        };

        // Prevent path traversal
        if relative.contains("..") {
            return Some(
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(full(hyper::body::Bytes::from("Forbidden")))
                    .unwrap(),
            );
        }

        let file_path = root.directory.join(relative);
        match tokio::fs::read(&file_path).await {
            Ok(contents) => {
                let content_type = guess_content_type(&file_path);
                return Some(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", content_type)
                        .body(full(hyper::body::Bytes::from(contents)))
                        .unwrap(),
                );
            }
            Err(_) => continue,
        }
    }
    None
}

/// Guess the Content-Type based on file extension.
fn guess_content_type(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("txt") => "text/plain",
        _ => "application/octet-stream",
    }
}


/// Build the response for a direct rule action (static page or redirect).
fn build_action_response(action: &RuleAction) -> Response<BoxBody> {
    match action {
        RuleAction::Static {
            status,
            body,
            content_type,
        } => {
            let status = StatusCode::from_u16(*status).unwrap_or(StatusCode::OK);
            Response::builder()
                .status(status)
                .header(
                    "Content-Type",
                    content_type.as_deref().unwrap_or("text/html; charset=utf-8"),
                )
                .body(full(Bytes::from(body.clone().unwrap_or_default())))
                .unwrap_or_else(|_| internal_error_response())
        }
        RuleAction::Redirect { location, status } => {
            let status = StatusCode::from_u16(*status).unwrap_or(StatusCode::FOUND);
            Response::builder()
                .status(status)
                .header("Location", location.as_str())
                .body(full(Bytes::new()))
                .unwrap_or_else(|_| internal_error_response())
        }
    }
}

fn internal_error_response() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(full(Bytes::from("Internal Server Error")))
        .expect("static response")
}

/// The configurable fallback page for requests no rule matches
/// (WSLProxy `no_server` / `no_rule` parity).
fn fallback_response(fallback: &FallbackConfig) -> Response<BoxBody> {
    let status = StatusCode::from_u16(fallback.status).unwrap_or(StatusCode::NOT_FOUND);
    let body = fallback.body.clone().unwrap_or_else(|| {
        format!(
            "<html><head><title>{s}</title></head><body><center><h1>{s}</h1></center>\
             <hr><center>intellaro</center></body></html>",
            s = status
        )
    });
    Response::builder()
        .status(status)
        .header("Content-Type", fallback.content_type.as_str())
        .body(full(Bytes::from(body)))
        .unwrap_or_else(|_| internal_error_response())
}

/// Apply rule-level response header manipulation.
fn apply_response_headers(resp: &mut Response<BoxBody>, hm: Option<&HeaderManipulation>) {
    let Some(hm) = hm else { return };
    for (name, value) in &hm.response_set {
        if let (Ok(n), Ok(v)) = (
            hyper::header::HeaderName::try_from(name.as_str()),
            hyper::header::HeaderValue::try_from(value.as_str()),
        ) {
            resp.headers_mut().insert(n, v);
        }
    }
    for name in &hm.response_remove {
        if let Ok(n) = hyper::header::HeaderName::try_from(name.as_str()) {
            resp.headers_mut().remove(n);
        }
    }
}

/// Compute the upstream path when a rule strips/replaces the matched
/// prefix. Returns None when the request path is unaffected.
fn rewrite_path(
    uri: &hyper::Uri,
    strip_prefix: Option<&str>,
    replace_with: Option<&str>,
) -> Option<String> {
    let strip = strip_prefix?;
    let path = uri.path();
    let rest = path.strip_prefix(strip)?;

    let mut new_path = String::from(replace_with.unwrap_or(""));
    if !new_path.starts_with('/') {
        new_path.insert(0, '/');
    }
    if !rest.is_empty() {
        if new_path.ends_with('/') && rest.starts_with('/') {
            new_path.pop();
        } else if !new_path.ends_with('/') && !rest.starts_with('/') && new_path != "/" {
            new_path.push('/');
        }
        if new_path == "/" && rest.starts_with('/') {
            new_path.pop();
        }
        new_path.push_str(rest);
    }
    if new_path.is_empty() {
        new_path.push('/');
    }
    if let Some(q) = uri.query() {
        new_path.push('?');
        new_path.push_str(q);
    }
    Some(new_path)
}

/// Strip an optional `:port` suffix from a Host header value, tolerating
/// IPv6 literals (`[::1]:8080` → `[::1]`).
fn strip_host_port(host: &str) -> &str {
    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            return &host[..=end];
        }
        return host;
    }
    match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    }
}

/// Owned request info data that can produce a borrowed `RequestInfo`.
struct OwnedRequestInfo {
    host: Option<String>,
    path: String,
    method: String,
    headers: HashMap<String, String>,
    query_params: HashMap<String, String>,
    cookies: HashMap<String, String>,
    content_type: Option<String>,
    source_ip: String,
}

impl OwnedRequestInfo {
    fn from_request<B>(req: &Request<B>, source_ip: String) -> Self {
        // Extract headers
        let mut headers = HashMap::new();
        for (key, value) in req.headers().iter() {
            if let Ok(v) = value.to_str() {
                headers.insert(key.as_str().to_lowercase(), v.to_string());
            }
        }

        // Extract host, stripping any :port suffix (RFC 9110 §7.2) so
        // vhost rules match requests that arrive on non-default ports
        // (NodePort, dev setups, etc.).
        let host = crate::proxy::request_host(req).map(|h| strip_host_port(h).to_string());

        // Extract content type
        let content_type = headers.get("content-type").cloned();

        // Extract query params
        let mut query_params = HashMap::new();
        if let Some(query) = req.uri().query() {
            for pair in query.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    query_params.insert(k.to_string(), v.to_string());
                }
            }
        }

        // Extract cookies
        let mut cookies = HashMap::new();
        if let Some(cookie_header) = headers.get("cookie") {
            for cookie in cookie_header.split(';') {
                let cookie = cookie.trim();
                if let Some((k, v)) = cookie.split_once('=') {
                    cookies.insert(k.trim().to_string(), v.trim().to_string());
                }
            }
        }

        Self {
            host,
            path: req.uri().path().to_string(),
            method: req.method().as_str().to_string(),
            headers,
            query_params,
            cookies,
            content_type,
            source_ip,
        }
    }

    fn as_request_info(&self) -> RequestInfo<'_> {
        RequestInfo {
            host: self.host.as_deref(),
            path: &self.path,
            method: &self.method,
            headers: &self.headers,
            query_params: &self.query_params,
            cookies: &self.cookies,
            content_type: self.content_type.as_deref(),
            source_ip: Some(&self.source_ip),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{rewrite_path, strip_host_port};

    #[test]
    fn rewrites_paths() {
        let uri: hyper::Uri = "/api/v1/users?limit=5".parse().unwrap();
        assert_eq!(
            rewrite_path(&uri, Some("/api"), None).as_deref(),
            Some("/v1/users?limit=5")
        );
        assert_eq!(
            rewrite_path(&uri, Some("/api"), Some("/internal")).as_deref(),
            Some("/internal/v1/users?limit=5")
        );
        // Prefix not present — no rewrite.
        assert_eq!(rewrite_path(&uri, Some("/other"), None), None);
        // No strip configured — no rewrite.
        assert_eq!(rewrite_path(&uri, None, None), None);
        // Stripping the entire path yields "/".
        let uri: hyper::Uri = "/legacy".parse().unwrap();
        assert_eq!(rewrite_path(&uri, Some("/legacy"), None).as_deref(), Some("/"));
    }

    #[test]
    fn strips_port_from_host_header() {
        assert_eq!(strip_host_port("example.com"), "example.com");
        assert_eq!(strip_host_port("example.com:30880"), "example.com");
        assert_eq!(strip_host_port("localhost:8080"), "localhost");
        assert_eq!(strip_host_port("[::1]:8080"), "[::1]");
        assert_eq!(strip_host_port("[2001:db8::1]"), "[2001:db8::1]");
        // Not a port — leave untouched.
        assert_eq!(strip_host_port("weird:host:name"), "weird:host:name");
    }
}
