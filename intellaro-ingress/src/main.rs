//! Intellaro Ingress Controller — standalone binary entry point.
//!
//! Kept for backwards compatibility; the unified `intellaro` binary
//! (`intellaro --role ingress`) is the preferred way to run the platform.

use clap::Parser;

use intellaro_ingress::{config, crd_manifests, logging};

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
        for (i, crd) in crd_manifests().iter().enumerate() {
            if i > 0 {
                println!("---");
            }
            print!("{crd}");
        }
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

    intellaro_ingress::run(ctrl_config).await
}
