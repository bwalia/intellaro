//! Structured logging and Prometheus-compatible metrics module.
//!
//! Provides JSON-formatted structured logging via `tracing` and
//! Prometheus metrics export via a dedicated HTTP endpoint.

use std::net::SocketAddr;

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

    match config.format.as_str() {
        "json" => {
            fmt()
                .json()
                .with_env_filter(env_filter)
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
                .init();
        }
        _ => {
            fmt()
                .with_env_filter(env_filter)
                .with_target(true)
                .init();
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

/// Serve the Prometheus metrics endpoint on the given address.
///
/// This runs a minimal HTTP server that responds to GET requests
/// with the current Prometheus metrics output.
pub async fn serve_metrics(
    address: SocketAddr,
    handle: PrometheusHandle,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(address).await?;
    info!(%address, "Metrics server listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let handle = handle.clone();

        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = hyper::service::service_fn(move |_req: Request<Incoming>| {
                let metrics_output = handle.render();
                async move {
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .header("Content-Type", "text/plain; version=0.0.4")
                            .body(http_body_util::Full::new(
                                hyper::body::Bytes::from(metrics_output),
                            ))
                            .unwrap(),
                    )
                }
            });

            if let Err(err) = hyper_util::server::conn::auto::Builder::new(
                hyper_util::rt::TokioExecutor::new(),
            )
            .serve_connection(io, service)
            .await
            {
                tracing::error!(%err, "Metrics server connection error");
            }
        });
    }
}
