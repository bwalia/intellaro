//! Intellaro Ingress Controller — entry point.
//!
//! A Kubernetes-native ingress controller that watches Intellaro CRDs
//! and reconciles them into `intellaro-http-server` configuration via
//! the Management Control Plane (MCP) API.

mod config;
mod controller;
mod crd;
mod discovery;
mod error;
mod health;
mod logging;
mod mcp;
mod metrics;
mod reconciler;
mod routing;

use std::sync::atomic::Ordering;

use clap::Parser;
use tracing::{error, info};

/// Intellaro Kubernetes Ingress Controller.
#[derive(Debug, Parser)]
#[command(name = "intellaro-ingress", version, about)]
struct Cli {
    /// Base URL of the intellaro-http-server MCP API.
    #[arg(long, env = "INTELLARO_MCP_URL")]
    mcp_url: Option<String>,

    /// API key for the MCP API.
    #[arg(long, env = "INTELLARO_MCP_API_KEY")]
    mcp_api_key: Option<String>,

    /// Namespace to watch (omit for cluster-wide).
    #[arg(long, env = "INTELLARO_NAMESPACE")]
    namespace: Option<String>,

    /// Metrics server port.
    #[arg(long, env = "INTELLARO_METRICS_PORT", default_value = "9090")]
    metrics_port: u16,

    /// Health probe port.
    #[arg(long, env = "INTELLARO_HEALTH_PORT", default_value = "8081")]
    health_port: u16,

    /// Print the CRD YAML manifests and exit.
    #[arg(long)]
    print_crds: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::init();

    let cli = Cli::parse();

    // If --print-crds, output the CRD YAML and exit.
    if cli.print_crds {
        print_crd_manifests();
        return Ok(());
    }

    // Build controller config from env + CLI overrides.
    let mut ctrl_config = config::ControllerConfig::from_env();
    if let Some(url) = cli.mcp_url {
        ctrl_config.mcp_url = url;
    }
    if let Some(key) = cli.mcp_api_key {
        ctrl_config.mcp_api_key = Some(key);
    }
    if cli.namespace.is_some() {
        ctrl_config.namespace = cli.namespace;
    }
    ctrl_config.metrics_port = cli.metrics_port;
    ctrl_config.health_port = cli.health_port;

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

/// Print CRD manifests to stdout (for `kubectl apply -f -`).
fn print_crd_manifests() {
    use kube::CustomResourceExt;

    let crds = vec![
        serde_yaml::to_string(&crd::IntellaroVHost::crd()).unwrap(),
        serde_yaml::to_string(&crd::IntellaroRoute::crd()).unwrap(),
        serde_yaml::to_string(&crd::IntellaroLBPolicy::crd()).unwrap(),
        serde_yaml::to_string(&crd::IntellaroSecurityPolicy::crd()).unwrap(),
        serde_yaml::to_string(&crd::IntellaroCachePolicy::crd()).unwrap(),
        serde_yaml::to_string(&crd::IntellaroServiceDiscovery::crd()).unwrap(),
        serde_yaml::to_string(&crd::IntellaroRoutingPolicy::crd()).unwrap(),
    ];

    for (i, crd) in crds.iter().enumerate() {
        if i > 0 {
            println!("---");
        }
        print!("{crd}");
    }
}
