//! HTTP server setup and event-driven worker engine.
//!
//! Manages listener binding, TLS termination, connection acceptance,
//! and request dispatching across an async worker pool.

use std::net::SocketAddr;
use std::sync::Arc;

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::cache::CacheLayer;
use crate::config::{ConfigManager, ListenerConfig, StaticRootConfig};
use crate::logging;
use crate::proxy::ProxyEngine;
use crate::security::SecurityEngine;

/// Full-body response type used throughout the server.
pub type BoxBody = http_body_util::Full<hyper::body::Bytes>;

/// Shared application state accessible from all request handlers.
pub struct AppState {
    pub config_manager: ConfigManager,
    pub proxy_engine: ProxyEngine,
    pub cache_layer: CacheLayer,
    pub security_engine: SecurityEngine,
    pub static_roots: Vec<StaticRootConfig>,
}

/// Start the HTTP server with all configured listeners.
///
/// Each listener runs in its own task, accepting connections and
/// dispatching them to the shared worker pool.
pub async fn run(
    config_manager: ConfigManager,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = config_manager.get().await;

    let state = Arc::new(AppState {
        config_manager: config_manager.clone(),
        proxy_engine: ProxyEngine::new(&config.upstreams),
        cache_layer: CacheLayer::new(&config.cache),
        security_engine: SecurityEngine::new(&config.security),
        static_roots: config.static_roots.clone(),
    });

    let mut listener_handles = Vec::new();

    for listener_config in &config.listeners {
        let handle = spawn_listener(listener_config.clone(), Arc::clone(&state)).await?;
        listener_handles.push(handle);
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

    info!("Server shut down gracefully");
    Ok(())
}

/// Spawn a TCP listener task for a single bind address.
async fn spawn_listener(
    listener_config: ListenerConfig,
    state: Arc<AppState>,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
    let tcp_listener = TcpListener::bind(listener_config.address).await?;

    info!(
        address = %listener_config.address,
        tls = listener_config.tls.is_some(),
        protocol = %listener_config.protocol,
        "Listener bound"
    );

    let handle = tokio::spawn(async move {
        accept_loop(tcp_listener, state).await;
    });

    Ok(handle)
}

/// Core accept loop — accepts TCP connections and spawns a task per connection.
async fn accept_loop(listener: TcpListener, state: Arc<AppState>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let state = Arc::clone(&state);
                metrics::gauge!("active_connections").increment(1.0);

                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, peer_addr, state).await {
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
async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    state: Arc<AppState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let io = TokioIo::new(stream);

    let service = hyper::service::service_fn(move |req: Request<Incoming>| {
        let state = Arc::clone(&state);
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

    // 1. Security checks
    if let Some(response) = state.security_engine.check(&req, peer_addr).await {
        let status = response.status().as_u16();
        logging::record_response(status, &method);
        logging::record_latency(start.elapsed().as_secs_f64(), &method, &path);
        return Ok(response);
    }

    // 2. Cache lookup (for cacheable requests)
    if let Some(cached_response) = state.cache_layer.get(&req).await {
        metrics::counter!("cache_hits_total").increment(1);
        let status = cached_response.status().as_u16();
        logging::record_response(status, &method);
        logging::record_latency(start.elapsed().as_secs_f64(), &method, &path);
        return Ok(cached_response);
    }

    metrics::counter!("cache_misses_total").increment(1);

    // 3. Static file serving
    if let Some(response) = serve_static_file(&path, &state.static_roots).await {
        state.cache_layer.store(&req, &response).await;
        let status = response.status().as_u16();
        logging::record_response(status, &method);
        logging::record_latency(start.elapsed().as_secs_f64(), &method, &path);
        return Ok(response);
    }

    // 4. Proxy to upstream
    let response = match state.proxy_engine.forward(&req).await {
        Ok(resp) => resp,
        Err(err) => {
            error!(%err, %path, "Proxy error");
            metrics::counter!("proxy_errors_total").increment(1);
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(BoxBody::new(hyper::body::Bytes::from("Bad Gateway")))
                .unwrap()
        }
    };

    // 4. Store in cache if cacheable
    state.cache_layer.store(&req, &response).await;

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
