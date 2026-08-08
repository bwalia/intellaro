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
use intellaro_http_router::engine::RoutingError;
use intellaro_http_router::matcher::RequestInfo;
use intellaro_http_router::RoutingEngine;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::cache::CacheLayer;
use crate::circuit_breaker::{self, CircuitBreakerRegistry};
use crate::config::{ConfigManager, ListenerConfig, StaticRootConfig};
use crate::logging;
use crate::proxy::ProxyEngine;
use crate::security::SecurityEngine;

/// Full-body response type used throughout the server.
pub type BoxBody = http_body_util::Full<hyper::body::Bytes>;

/// Maximum buffered request body size (Phase-0 store-and-forward cap).
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Shared application state accessible from all request handlers.
pub struct AppState {
    pub config_manager: ConfigManager,
    pub proxy_engine: Arc<ProxyEngine>,
    pub cache_layer: CacheLayer,
    pub security_engine: SecurityEngine,
    pub static_roots: Vec<StaticRootConfig>,
    pub routing_engine: Option<RoutingEngine>,
    pub circuit_breakers: CircuitBreakerRegistry,
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

    let mut change_rx = config_manager.subscribe();
    let reload_manager = config_manager.clone();
    let reload_task = tokio::spawn(async move {
        loop {
            if change_rx.changed().await.is_err() {
                break;
            }
            let new_config = reload_manager.get().await;
            let engine = crate::bootstrap::build_routing_engine(&new_config);
            let new_state = build_app_state(reload_manager.clone(), &new_config, engine);
            if state_tx.send(new_state).is_err() {
                break;
            }
            info!("Data plane rebuilt from updated configuration (listeners unchanged)");
        }
    });

    let mut listener_handles = Vec::new();

    for listener_config in &config.listeners {
        let handle = spawn_listener(listener_config.clone(), state_rx.clone()).await?;
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
    })
}

/// Spawn a TCP listener task for a single bind address.
async fn spawn_listener(
    listener_config: ListenerConfig,
    state_rx: watch::Receiver<Arc<AppState>>,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
    let tcp_listener = TcpListener::bind(listener_config.address).await?;

    info!(
        address = %listener_config.address,
        tls = listener_config.tls.is_some(),
        protocol = %listener_config.protocol,
        "Listener bound"
    );

    let handle = tokio::spawn(async move {
        accept_loop(tcp_listener, state_rx).await;
    });

    Ok(handle)
}

/// Core accept loop — accepts TCP connections and spawns a task per connection.
async fn accept_loop(listener: TcpListener, state_rx: watch::Receiver<Arc<AppState>>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let state_rx = state_rx.clone();
                metrics::gauge!("active_connections").increment(1.0);

                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, peer_addr, state_rx).await {
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
async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    state_rx: watch::Receiver<Arc<AppState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let io = TokioIo::new(stream);

    let service = hyper::service::service_fn(move |req: Request<Incoming>| {
        let state = state_rx.borrow().clone();
        let addr = peer_addr;
        async move { handle_request(req, addr, state).await }
    });

    ConnectionBuilder::new(TokioExecutor::new())
        .serve_connection(io, service)
        .await?;

    Ok(())
}

/// Central request handler: security -> cache -> proxy -> static.
async fn handle_request(
    req: Request<Incoming>,
    peer_addr: SocketAddr,
    state: Arc<AppState>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let start = std::time::Instant::now();

    logging::record_request(&method, &path);

    // Buffer the request body up-front (bounded) so it can be forwarded
    // and replayed across retries. Streaming pass-through is Phase 1.
    let (parts, body) = req.into_parts();
    let body_bytes: Bytes =
        match http_body_util::Limited::new(body, MAX_REQUEST_BODY_BYTES).collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => {
                let too_large = err.downcast_ref::<http_body_util::LengthLimitError>().is_some();
                let status = if too_large {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::BAD_REQUEST
                };
                warn!(%path, too_large, "Failed to read request body");
                logging::record_response(status.as_u16(), &method);
                return Ok(Response::builder()
                    .status(status)
                    .body(BoxBody::new(hyper::body::Bytes::from(
                        status.canonical_reason().unwrap_or("error").to_string(),
                    )))
                    .unwrap());
            }
        };
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
        state.cache_layer.store(req, &response).await;
        let status = response.status().as_u16();
        logging::record_response(status, &method);
        logging::record_latency(start.elapsed().as_secs_f64(), &method, &path);
        return Ok(response);
    }

    // 4. Intelligent routing engine (if configured)
    if let Some(ref engine) = state.routing_engine {
        let owned_info = OwnedRequestInfo::from_request(req);
        let request_info = owned_info.as_request_info();
        let source_ip = peer_addr.ip().to_string();

        match engine.route(&request_info, None, Some(&source_ip)) {
            Ok(decision) => {
                let route_start = std::time::Instant::now();
                debug!(
                    rule = %decision.matched_rule,
                    backend = %decision.backend_id,
                    group = %decision.backend_group,
                    canary = decision.is_canary,
                    "Routing engine decision"
                );

                let response = match state
                    .proxy_engine
                    .forward_to(req, &decision.backend_id, body_bytes.clone(), peer_addr)
                    .await
                {
                    Ok(resp) => {
                        let latency_ms = route_start.elapsed().as_secs_f64() * 1000.0;
                        engine.record_backend_latency(&decision.backend_id, latency_ms);
                        engine.release_backend(&decision.backend_state);
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
                        Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(BoxBody::new(hyper::body::Bytes::from("Bad Gateway")))
                            .unwrap()
                    }
                };

                state.cache_layer.store(req, &response).await;
                let status = response.status().as_u16();
                logging::record_response(status, &method);
                logging::record_latency(start.elapsed().as_secs_f64(), &method, &path);
                return Ok(response);
            }
            Err(RoutingError::NoMatchingRule) => {
                // Fall through to default proxy behavior
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
                    .body(BoxBody::new(hyper::body::Bytes::from(err.to_string())))
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
                .body(BoxBody::new(hyper::body::Bytes::from(
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

    for attempt in 0..max_attempts {
        match state
            .proxy_engine
            .forward(req, body_bytes.clone(), peer_addr)
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

                state.cache_layer.store(req, &resp).await;
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
                let response = Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(BoxBody::new(hyper::body::Bytes::from("Bad Gateway")))
                    .unwrap();
                logging::record_response(502, &method);
                logging::record_latency(start.elapsed().as_secs_f64(), &method, &path);
                return Ok(response);
            }
        }
    }

    // All retries exhausted — return the last response.
    let response = last_response.unwrap_or_else(|| {
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(BoxBody::new(hyper::body::Bytes::from("Bad Gateway")))
            .unwrap()
    });

    let status = response.status().as_u16();
    logging::record_response(status, &method);
    logging::record_latency(start.elapsed().as_secs_f64(), &method, &path);

    Ok(response)
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
                    .body(BoxBody::new(hyper::body::Bytes::from("Forbidden")))
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
                        .body(BoxBody::new(hyper::body::Bytes::from(contents)))
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
}

impl OwnedRequestInfo {
    fn from_request<B>(req: &Request<B>) -> Self {
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
        let host = headers.get("host").map(|h| strip_host_port(h).to_string());

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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::strip_host_port;

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
