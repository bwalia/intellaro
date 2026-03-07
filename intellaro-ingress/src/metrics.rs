//! Prometheus metrics for the ingress controller.
//!
//! Exposes reconciliation counters, durations, and CRD status gauges
//! via a dedicated HTTP endpoint that Kubernetes can scrape.

use std::net::SocketAddr;

use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use tokio::net::TcpListener;
use tracing::{error, info};

/// Default metrics port.
const DEFAULT_METRICS_PORT: u16 = 9090;

/// Install the Prometheus metrics recorder and return the render handle.
pub fn install_recorder() -> metrics_exporter_prometheus::PrometheusHandle {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("Failed to install Prometheus recorder");

    // Register default metrics with initial values.
    counter!("intellaro_reconcile_total", "result" => "success").absolute(0);
    counter!("intellaro_reconcile_total", "result" => "error").absolute(0);
    gauge!("intellaro_crd_count", "kind" => "IntellaroVHost").set(0.0);
    gauge!("intellaro_crd_count", "kind" => "IntellaroRoute").set(0.0);
    gauge!("intellaro_crd_count", "kind" => "IntellaroLBPolicy").set(0.0);
    gauge!("intellaro_crd_count", "kind" => "IntellaroSecurityPolicy").set(0.0);
    gauge!("intellaro_crd_count", "kind" => "IntellaroCachePolicy").set(0.0);
    gauge!("intellaro_crd_count", "kind" => "IntellaroServiceDiscovery").set(0.0);
    gauge!("intellaro_crd_count", "kind" => "IntellaroRoutingPolicy").set(0.0);
    gauge!("intellaro_mcp_healthy").set(0.0);

    // Service discovery metrics.
    gauge!("intellaro_discovered_services").set(0.0);
    gauge!("intellaro_discovered_endpoints").set(0.0);
    gauge!("intellaro_registered_backend_groups").set(0.0);
    counter!("intellaro_discovery_passes_total", "result" => "success").absolute(0);
    counter!("intellaro_discovery_passes_total", "result" => "error").absolute(0);

    // Routing policy metrics.
    gauge!("intellaro_routing_policies_total").set(0.0);
    gauge!("intellaro_routing_policies_active").set(0.0);
    gauge!("intellaro_canary_deployments").set(0.0);
    gauge!("intellaro_sla_tiers").set(0.0);
    gauge!("intellaro_traffic_split_rules").set(0.0);

    handle
}

/// Record a successful reconciliation for a CRD kind.
pub fn record_reconcile_success(kind: &str) {
    counter!("intellaro_reconcile_total", "result" => "success", "kind" => kind.to_string())
        .increment(1);
}

/// Record a failed reconciliation for a CRD kind.
pub fn record_reconcile_error(kind: &str) {
    counter!("intellaro_reconcile_total", "result" => "error", "kind" => kind.to_string())
        .increment(1);
}

/// Record reconciliation duration.
pub fn record_reconcile_duration(kind: &str, duration_secs: f64) {
    histogram!("intellaro_reconcile_duration_seconds", "kind" => kind.to_string())
        .record(duration_secs);
}

/// Update the CRD count gauge.
pub fn set_crd_count(kind: &str, count: f64) {
    gauge!("intellaro_crd_count", "kind" => kind.to_string()).set(count);
}

/// Update the MCP health gauge.
pub fn set_mcp_healthy(healthy: bool) {
    gauge!("intellaro_mcp_healthy").set(if healthy { 1.0 } else { 0.0 });
}

// ── Service discovery metrics ────────────────────────────────────────

/// Update discovered services/endpoints gauges.
pub fn set_discovery_counts(services: u32, endpoints: u32, groups: u32) {
    gauge!("intellaro_discovered_services").set(services as f64);
    gauge!("intellaro_discovered_endpoints").set(endpoints as f64);
    gauge!("intellaro_registered_backend_groups").set(groups as f64);
}

/// Record a successful discovery pass.
pub fn record_discovery_success() {
    counter!("intellaro_discovery_passes_total", "result" => "success").increment(1);
}

/// Record a failed discovery pass.
pub fn record_discovery_error() {
    counter!("intellaro_discovery_passes_total", "result" => "error").increment(1);
}

// ── Routing policy metrics ──────────────────────────────────────────

/// Update routing policy gauges.
pub fn set_routing_policy_counts(
    total: u32,
    active: u32,
    canary: usize,
    sla_tiers: usize,
    traffic_splits: usize,
) {
    gauge!("intellaro_routing_policies_total").set(total as f64);
    gauge!("intellaro_routing_policies_active").set(active as f64);
    gauge!("intellaro_canary_deployments").set(canary as f64);
    gauge!("intellaro_sla_tiers").set(sla_tiers as f64);
    gauge!("intellaro_traffic_split_rules").set(traffic_splits as f64);
}

/// Start the HTTP server that serves `/metrics` for Prometheus scraping.
pub async fn serve_metrics(handle: metrics_exporter_prometheus::PrometheusHandle, port: Option<u16>) {
    let port = port.unwrap_or(DEFAULT_METRICS_PORT);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(port = port, error = %e, "Failed to bind metrics server");
            return;
        }
    };

    info!(port = port, "Metrics server listening");

    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                let handle = handle.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};

                    // Read and discard the request.
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;

                    let body = handle.render();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body,
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
            Err(e) => {
                error!(error = %e, "Failed to accept metrics connection");
            }
        }
    }
}
