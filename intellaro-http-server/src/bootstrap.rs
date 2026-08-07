//! Full-server bootstrap: config, logging, metrics, ops endpoints,
//! management API, cluster, routing engine, and the HTTP listeners.
//!
//! Extracted from `main.rs` so both the legacy `intellaro-http-server`
//! binary and the unified `intellaro` binary (`--role proxy|all`) share
//! one startup path.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use intellaro_http_router::balancer::Backend;
use intellaro_http_router::config::BalancerStrategy;
use intellaro_http_router::{RouterState, RoutingEngine};
use tokio::signal;
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::cluster::ClusterManager;
use crate::config::ConfigManager;
use crate::logging;
use crate::mcp::McpServer;
use crate::server;

/// Options for [`run`].
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Path to the configuration file (legacy flat format or
    /// `intellaro.io/v1` multi-document YAML/JSON).
    pub config_path: String,
}

/// Load configuration, start every subsystem, and serve until Ctrl+C.
pub async fn run(options: RunOptions) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config_manager = ConfigManager::load(&options.config_path)
        .map_err(|err| format!("failed to load configuration: {err}"))?;

    let config = config_manager.get().await;

    logging::init_tracing(&config.logging);
    let metrics_handle = logging::init_metrics();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config_path = %options.config_path,
        "Intellaro HTTP Server starting"
    );

    // ── File watcher for hot reload ──────────────────────────────────
    let _watcher = match config_manager.start_file_watcher() {
        Ok(w) => Some(w),
        Err(err) => {
            error!(%err, "Failed to start config file watcher");
            None
        }
    };

    // ── Readiness flag, flipped once listeners are bound ─────────────
    let ready = Arc::new(AtomicBool::new(false));

    // ── Shutdown signal ──────────────────────────────────────────────
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // ── Ops server: /metrics, /health, /ready ────────────────────────
    // Address resolution: INTELLARO_OPS_ADDR env > logging.ops_address > :9090.
    if config.logging.metrics_path.is_some() {
        let ops_addr = std::env::var("INTELLARO_OPS_ADDR")
            .ok()
            .and_then(|addr| addr.parse().ok())
            .or(config.logging.ops_address)
            .unwrap_or_else(|| "0.0.0.0:9090".parse().expect("static addr"));
        let handle = metrics_handle.clone();
        let ops_ready = ready.clone();
        tokio::spawn(async move {
            if let Err(err) = logging::serve_ops(ops_addr, handle, ops_ready).await {
                error!(%err, "Ops server failed");
            }
        });
        info!(address = %ops_addr, "Ops endpoints started (/metrics /health /ready)");
    }

    // ── MCP management API ───────────────────────────────────────────
    if let Some(ref mcp_config) = config.management_api {
        let mcp_server = Arc::new(McpServer::new(config_manager.clone(), mcp_config));
        let mcp_address = mcp_config.address;
        tokio::spawn(async move {
            if let Err(err) = mcp_server.serve(mcp_address).await {
                error!(%err, "MCP management API server failed");
            }
        });
    }

    // ── Cluster manager ──────────────────────────────────────────────
    if let Some(ref cluster_config) = config.cluster {
        let cluster = Arc::new(ClusterManager::new(cluster_config));
        if let Err(err) = cluster.start().await {
            error!(%err, "Cluster manager failed to start");
        }
    }

    // ── Routing engine ───────────────────────────────────────────────
    let routing_engine = build_routing_engine(&config);

    // ── HTTP listeners ───────────────────────────────────────────────
    let mut server_task = tokio::spawn(server::run(
        config_manager,
        shutdown_rx,
        routing_engine,
        Some(ready.clone()),
    ));

    // ── Wait for Ctrl+C or an unexpected server exit ─────────────────
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Received Ctrl+C, initiating shutdown...");
        }
        result = &mut server_task => {
            ready.store(false, Ordering::Relaxed);
            match result {
                Ok(Ok(())) => info!("HTTP server exited"),
                Ok(Err(err)) => return Err(err),
                Err(err) => return Err(Box::new(err)),
            }
            return Ok(());
        }
    }

    ready.store(false, Ordering::Relaxed);
    let _ = shutdown_tx.send(true);
    let _ = server_task.await;

    info!("Intellaro HTTP Server shut down.");
    Ok(())
}

/// Build the routing engine from config (if configured) and register
/// every upstream as a backend group.
pub fn build_routing_engine(config: &crate::config::ServerConfig) -> Option<RoutingEngine> {
    let router_config = config.router.as_ref()?;

    match RouterState::from_config(router_config.clone()) {
        Ok(state) => {
            let shared_state = Arc::new(state);

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
            info!(rules = router_config.rules.len(), "Routing engine initialized");
            Some(engine)
        }
        Err(err) => {
            warn!(%err, "Failed to initialize routing engine, falling back to default proxy");
            None
        }
    }
}
