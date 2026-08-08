//! Intellaro Ingress Controller — library crate.
//!
//! A Kubernetes-native ingress controller that watches Intellaro CRDs
//! and reconciles them into `intellaro-http-server` configuration via
//! the Management Control Plane (MCP) API.
//!
//! Consumed by the standalone `intellaro-ingress` binary and by the
//! unified `intellaro` binary as `--role ingress`.

pub mod config;
pub mod controller;
pub mod crd;
pub mod discovery;
pub mod error;
pub mod health;
pub mod logging;
pub mod mcp;
pub mod metrics;
pub mod reconciler;
pub mod routing;

use std::sync::atomic::Ordering;

use tracing::{error, info};

/// Run the ingress controller until Ctrl+C (or controller exit).
///
/// Callers are responsible for initializing tracing first (see
/// [`logging::init`]).
pub async fn run(ctrl_config: config::ControllerConfig) -> anyhow::Result<()> {
    // The unified binary links rustls with both `ring` (kube/reqwest) and
    // `aws-lc-rs` (data-plane TLS) compiled in; rustls then refuses to pick
    // a process-level CryptoProvider automatically. Install one explicitly
    // before any TLS client is built.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    info!(
        mcp_url = %ctrl_config.mcp_url,
        namespace = ?ctrl_config.namespace,
        metrics_port = ctrl_config.metrics_port,
        health_port = ctrl_config.health_port,
        "Intellaro Ingress Controller starting"
    );

    // Install Prometheus metrics.
    let metrics_handle = metrics::install_recorder();

    // Health/readiness probe.
    let ready_flag = health::new_ready_flag();

    // Create Kubernetes client.
    let kube_client = kube::Client::try_default().await?;

    // Create MCP client.
    let mcp_client = mcp::McpClient::new(
        &ctrl_config.mcp_url,
        ctrl_config.mcp_api_key.clone(),
        ctrl_config.mcp_timeout_secs,
    )?;

    // Check MCP connectivity.
    match mcp_client.health().await {
        Ok(true) => {
            info!("MCP server is reachable");
            metrics::set_mcp_healthy(true);
        }
        _ => {
            error!(
                url = %ctrl_config.mcp_url,
                "MCP server is not reachable — controller will retry"
            );
            metrics::set_mcp_healthy(false);
        }
    }

    // Run an initial full reconciliation.
    let init_ctx = reconciler::ReconcilerContext::new(
        kube_client.clone(),
        mcp_client.clone(),
        ctrl_config.namespace.clone(),
    );

    match reconciler::full_reconcile(&init_ctx).await {
        Ok(()) => {
            info!("Initial reconciliation succeeded");
            ready_flag.store(true, Ordering::Relaxed);
        }
        Err(e) => {
            error!(error = %e, "Initial reconciliation failed — controller will retry via watches");
        }
    }

    // Start background services.
    let metrics_task = tokio::spawn(metrics::serve_metrics(
        metrics_handle,
        Some(ctrl_config.metrics_port),
    ));
    let health_task = tokio::spawn(health::serve_health(
        ctrl_config.health_port,
        ready_flag.clone(),
    ));

    // Start the CRD controllers (blocks until signal).
    let controller_task = tokio::spawn(controller::run(
        kube_client,
        mcp_client,
        ctrl_config.namespace,
        ready_flag.clone(),
    ));

    // Wait for shutdown signal.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
        result = controller_task => {
            match result {
                Ok(Ok(())) => info!("Controller exited normally"),
                Ok(Err(e)) => error!(error = %e, "Controller exited with error"),
                Err(e) => error!(error = %e, "Controller task panicked"),
            }
        }
    }

    // Clean shutdown.
    metrics_task.abort();
    health_task.abort();

    info!("Intellaro Ingress Controller stopped");
    Ok(())
}

/// The CRD manifests served by `--print-crds`, as YAML documents.
pub fn crd_manifests() -> Vec<String> {
    use kube::CustomResourceExt;

    vec![
        serde_yaml::to_string(&crd::IntellaroVHost::crd()).unwrap(),
        serde_yaml::to_string(&crd::IntellaroRoute::crd()).unwrap(),
        serde_yaml::to_string(&crd::IntellaroLBPolicy::crd()).unwrap(),
        serde_yaml::to_string(&crd::IntellaroSecurityPolicy::crd()).unwrap(),
        serde_yaml::to_string(&crd::IntellaroCachePolicy::crd()).unwrap(),
        serde_yaml::to_string(&crd::IntellaroServiceDiscovery::crd()).unwrap(),
        serde_yaml::to_string(&crd::IntellaroRoutingPolicy::crd()).unwrap(),
    ]
}
