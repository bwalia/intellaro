//! Intellaro HTTP Server — entry point.
//!
//! A high-performance, modular HTTP(S) server with reverse proxy, load balancing,
//! caching, security policy enforcement, clustering, and a management control plane.

mod audit;
mod cache;
mod circuit_breaker;
mod cluster;
mod config;
mod config_versioning;
mod logging;
mod mcp;
mod oidc;
mod proxy;
mod rbac;
mod security;
mod server;
mod tenant;
mod transform;

use std::sync::Arc;

use clap::Parser;
use intellaro_http_router::balancer::Backend;
use intellaro_http_router::config::BalancerStrategy;
use intellaro_http_router::{RouterState, RoutingEngine};
use tokio::signal;
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::cluster::ClusterManager;
use crate::config::ConfigManager;
use crate::mcp::McpServer;

/// Command-line arguments for the Intellaro HTTP server.
#[derive(Parser, Debug)]
#[command(
    name = "intellaro-http-server",
    version,
    about = "Intellaro — High-performance HTTP(S) server with reverse proxy, caching & clustering"
)]
struct CliArgs {
    /// Path to the configuration file (JSON or YAML).
    #[arg(short, long, default_value = "config.yaml")]
    config: String,

    /// Validate configuration and exit without starting the server.
    #[arg(long, default_value_t = false)]
    validate: bool,
}

#[tokio::main]
async fn main() {
    let args = CliArgs::parse();

    // ── Load configuration ───────────────────────────────────────────
    let config_manager = match ConfigManager::load(&args.config) {
        Ok(cm) => cm,
        Err(err) => {
            eprintln!("Failed to load configuration: {err}");
            std::process::exit(1);
        }
    };

    let config = config_manager.get().await;

    // ── Validate-only mode ───────────────────────────────────────────
    if args.validate {
        println!("Configuration is valid.");
        return;
    }

    // ── Initialize logging ───────────────────────────────────────────
    logging::init_tracing(&config.logging);
    let metrics_handle = logging::init_metrics();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config_path = %args.config,
        "Intellaro HTTP Server starting"
    );

    // ── Start file watcher for hot reload ────────────────────────────
    let _watcher = match config_manager.start_file_watcher() {
        Ok(w) => Some(w),
        Err(err) => {
            error!(%err, "Failed to start config file watcher");
            None
        }
    };

    // ── Shutdown signal ──────────────────────────────────────────────
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // ── Start metrics server ─────────────────────────────────────────
    if let Some(ref metrics_path) = config.logging.metrics_path {
        // Serve metrics on the first listener's address + 1 port, or a dedicated address.
        let metrics_addr = "0.0.0.0:9090".parse().unwrap();
        let handle = metrics_handle.clone();
        tokio::spawn(async move {
            if let Err(err) = logging::serve_metrics(metrics_addr, handle).await {
                error!(%err, "Metrics server failed");
            }
        });
        info!(address = "0.0.0.0:9090", path = %metrics_path, "Metrics endpoint started");
    }

    // ── Start MCP management API ─────────────────────────────────────
    if let Some(ref mcp_config) = config.management_api {
        let mcp_server = Arc::new(McpServer::new(config_manager.clone(), mcp_config));
        let mcp_address = mcp_config.address;
        tokio::spawn(async move {
            if let Err(err) = mcp_server.serve(mcp_address).await {
                error!(%err, "MCP management API server failed");
            }
        });
    }

    // ── Start cluster manager ────────────────────────────────────────
    if let Some(ref cluster_config) = config.cluster {
        let cluster = Arc::new(ClusterManager::new(cluster_config));
        if let Err(err) = cluster.start().await {
            error!(%err, "Cluster manager failed to start");
        }
    }

    // ── Build routing engine (if configured) ─────────────────────────
    let routing_engine = if let Some(ref router_config) = config.router {
        match RouterState::from_config(router_config.clone()) {
            Ok(state) => {
                let shared_state = Arc::new(state);

                // Register server upstreams as backend groups in the routing engine.
                for upstream in &config.upstreams {
                    let backends: Vec<Backend> = upstream
                        .servers
                        .iter()
                        .map(|s| Backend {
                            id: s.address.clone(),
                            weight: s.weight,
                            healthy: true,
                        })
                        .collect();

                    let strategy = match upstream.load_balancing.as_str() {
                        "round_robin" => BalancerStrategy::RoundRobin,
                        "least_connections" => BalancerStrategy::LeastConnections,
                        "weighted" => BalancerStrategy::Weighted,
                        "random" => BalancerStrategy::Random,
                        "consistent_hash" => BalancerStrategy::ConsistentHash,
                        _ => BalancerStrategy::RoundRobin,
                    };

                    shared_state.register_backend_group(&upstream.name, backends, strategy);
                    info!(
                        upstream = %upstream.name,
                        backends = upstream.servers.len(),
                        strategy = %upstream.load_balancing,
                        "Registered upstream as router backend group"
                    );
                }

                let engine = RoutingEngine::new(shared_state);
                info!(
                    rules = router_config.rules.len(),
                    "Routing engine initialized"
                );
                Some(engine)
            }
            Err(err) => {
                warn!(%err, "Failed to initialize routing engine, falling back to default proxy");
                None
            }
        }
    } else {
        None
    };

    // ── Start the HTTP server ────────────────────────────────────────
    if let Err(err) = server::run(config_manager, shutdown_rx, routing_engine).await {
        error!(%err, "HTTP server error");
    }

    // ── Wait for shutdown signal (Ctrl+C or SIGTERM) ─────────────────
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Received Ctrl+C, initiating shutdown...");
        }
    }

    let _ = shutdown_tx.send(true);
    info!("Intellaro HTTP Server shut down.");
}
