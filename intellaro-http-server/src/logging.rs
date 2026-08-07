//! Structured logging and Prometheus-compatible metrics module.
//!
//! Provides JSON-formatted structured logging via `tracing` and
//! Prometheus metrics export via a dedicated HTTP endpoint.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use hyper::{body::Incoming, Request, Response};
use hyper_util::rt::TokioIo;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::net::TcpListener;
use tracing::{info, Level};
use tracing_subscriber::{fmt, EnvFilter};

use crate::config::LoggingConfig;

/// Initializes the global tracing subscriber based on configuration.
///
/// Call this once at startup before any tracing macros are used.
pub fn init_tracing(config: &LoggingConfig) {
    let level_filter = match config.level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let env_filter = EnvFilter::new(level_filter.to_string());

    // try_init: tolerate an already-installed subscriber so the server can
    // be embedded (unified `intellaro` binary, integration tests).
    match config.format.as_str() {
        "json" => {
            let _ = fmt()
                .json()
                .with_env_filter(env_filter)
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
                .try_init();
        }
        _ => {
            let _ = fmt()
                .with_env_filter(env_filter)
                .with_target(true)
                .try_init();
        }
    }

    info!(level = %config.level, format = %config.format, "Tracing initialized");
}

/// Installs the Prometheus metrics recorder and returns the handle
/// for rendering metrics output.
pub fn init_metrics() -> PrometheusHandle {
    let builder = PrometheusBuilder::new();
    let handle = builder
        .install_recorder()
        .expect("Failed to install Prometheus metrics recorder");

    register_default_metrics();

    info!("Prometheus metrics recorder installed");
    handle
}

/// Register default application-level metrics.
fn register_default_metrics() {
    // Request counters
    metrics::describe_counter!(
        "http_requests_total",
        "Total number of HTTP requests received"
    );
    metrics::describe_histogram!(
        "http_request_duration_seconds",
        "HTTP request latency in seconds"
    );
    metrics::describe_counter!(
        "http_responses_total",
        "Total number of HTTP responses sent"
    );

    // Proxy metrics
    metrics::describe_counter!(
        "proxy_requests_total",
        "Total number of proxied requests"
    );
    metrics::describe_counter!(
        "proxy_errors_total",
        "Total number of proxy errors"
    );

    // Cache metrics
    metrics::describe_counter!("cache_hits_total", "Total cache hits");
    metrics::describe_counter!("cache_misses_total", "Total cache misses");
    metrics::describe_gauge!("cache_entries", "Current number of cache entries");

    // Connection metrics
    metrics::describe_gauge!(
        "active_connections",
        "Number of currently active connections"
    );

    // Cluster metrics
    metrics::describe_gauge!("cluster_peers", "Number of known cluster peers");
}

/// Record an incoming HTTP request in metrics.
pub fn record_request(method: &str, path: &str) {
    metrics::counter!("http_requests_total", "method" => method.to_string(), "path" => path.to_string())
        .increment(1);
}

/// Record an HTTP response in metrics.
pub fn record_response(status: u16, method: &str) {
    metrics::counter!(
        "http_responses_total",
        "status" => status.to_string(),
        "method" => method.to_string()
    )
    .increment(1);
}

/// Record request latency in seconds.
pub fn record_latency(duration_secs: f64, method: &str, path: &str) {
    metrics::histogram!(
        "http_request_duration_seconds",
        "method" => method.to_string(),
        "path" => path.to_string()
    )
    .record(duration_secs);
}

/// Serve the ops endpoints on the given address:
///
/// * `GET /metrics`  — Prometheus exposition
/// * `GET /health`   — liveness (also `/healthz`)
/// * `GET /ready`    — readiness, 503 until listeners are bound (also `/readyz`)
pub async fn serve_ops(
    address: SocketAddr,
    handle: PrometheusHandle,
    ready: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(address).await?;
    info!(%address, "Ops server listening (/metrics /health /ready)");

    loop {
        let (stream, _) = listener.accept().await?;
        let handle = handle.clone();
        let ready = ready.clone();

        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                let handle = handle.clone();
                let ready = ready.clone();
                async move { Ok::<_, hyper::Error>(ops_response(req.uri().path(), &handle, &ready)) }
            });

            if let Err(err) = hyper_util::server::conn::auto::Builder::new(
                hyper_util::rt::TokioExecutor::new(),
            )
            .serve_connection(io, service)
            .await
            {
                tracing::error!(%err, "Ops server connection error");
            }
        });
    }
}

fn ops_response(
    path: &str,
    handle: &PrometheusHandle,
    ready: &AtomicBool,
) -> Response<http_body_util::Full<hyper::body::Bytes>> {
    let (status, content_type, body): (u16, &str, String) = match path {
        "/metrics" => (
            200,
            "text/plain; version=0.0.4",
            handle.render(),
        ),
        "/health" | "/healthz" => (
            200,
            "application/json",
            format!(
                "{{\"status\":\"ok\",\"version\":\"{}\"}}",
                env!("CARGO_PKG_VERSION")
            ),
        ),
        "/ready" | "/readyz" => {
            if ready.load(Ordering::Relaxed) {
                (200, "application/json", "{\"ready\":true}".to_string())
            } else {
                (503, "application/json", "{\"ready\":false}".to_string())
            }
        }
        _ => (404, "text/plain", "not found".to_string()),
    };

    Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .body(http_body_util::Full::new(hyper::body::Bytes::from(body)))
        .expect("static response")
}

/// Backwards-compatible alias for the old metrics-only server.
pub async fn serve_metrics(
    address: SocketAddr,
    handle: PrometheusHandle,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    serve_ops(address, handle, Arc::new(AtomicBool::new(true))).await
}
