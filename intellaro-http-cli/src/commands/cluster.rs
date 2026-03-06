//! Cluster management commands — status, list-nodes, sync, broadcast.

use clap::Subcommand;

use crate::client::McpClient;
use crate::error::CliResult;
use crate::output::{self, OutputFormat};

/// Cluster management subcommands.
#[derive(Debug, Subcommand)]
pub enum ClusterCmd {
    /// Show cluster configuration.
    Status,

    /// List known cluster peer nodes.
    ListNodes,

    /// Sync the local configuration to all cluster peers.
    Sync {
        /// Skip confirmation.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },

    /// Set the cluster node ID for this server.
    SetNodeId {
        /// New node identifier.
        node_id: String,
    },

    /// Add a peer address to the cluster.
    AddPeer {
        /// Peer address (e.g., "10.0.0.5:7946").
        address: String,
    },

    /// Remove a peer address from the cluster.
    RemovePeer {
        /// Peer address to remove.
        address: String,
    },
}

/// Execute a cluster subcommand.
pub async fn execute(cmd: &ClusterCmd, client: &McpClient, format: OutputFormat) -> CliResult<()> {
    match cmd {
        ClusterCmd::Status => {
            let config: serde_json::Value = client.get_config().await?;
            let cluster = config.get("cluster").cloned().unwrap_or(serde_json::Value::Null);

            if cluster.is_null() {
                output::print_info("Clustering is not configured on this server");
                return Ok(());
            }

            match format {
                OutputFormat::Table => {
                    let node_id = cluster.get("node_id").and_then(|v| v.as_str()).unwrap_or("-");
                    let port = cluster.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
                    let peer_count = cluster
                        .get("peers")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);

                    output::render_kv(&[
                        ("Node ID", node_id),
                        ("Cluster Port", &port.to_string()),
                        ("Known Peers", &peer_count.to_string()),
                    ]);
                }
                _ => output::render_value(&cluster, format),
            }
            Ok(())
        }

        ClusterCmd::ListNodes => {
            let config: serde_json::Value = client.get_config().await?;
            let peers = config
                .get("cluster")
                .and_then(|c| c.get("peers"))
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            if peers.is_empty() {
                output::print_info("No cluster peers configured");
                return Ok(());
            }

            match format {
                OutputFormat::Table => {
                    let rows: Vec<Vec<String>> = peers
                        .iter()
                        .enumerate()
                        .map(|(i, p)| {
                            vec![
                                (i + 1).to_string(),
                                p.as_str().unwrap_or("-").to_string(),
                            ]
                        })
                        .collect();
                    output::render_table(&["#", "Peer Address"], &rows);
                }
                _ => output::render_value(&serde_json::Value::Array(peers), format),
            }
            Ok(())
        }

        ClusterCmd::Sync { yes } => {
            if !yes {
                output::print_warn(
                    "This will push the current configuration to all cluster peers. Pass --yes to confirm.",
                );
                return Ok(());
            }

            // Sync is done by triggering a config reload — the cluster manager
            // broadcasts the updated version to peers automatically.
            let _: serde_json::Value = client.reload_config().await?;
            output::print_success("Configuration reload triggered; cluster sync initiated");
            Ok(())
        }

        ClusterCmd::SetNodeId { node_id } => {
            let mut config: serde_json::Value = client.get_config().await?;

            if let Some(cluster) = config.get_mut("cluster") {
                cluster["node_id"] = serde_json::Value::String(node_id.clone());
            } else {
                config["cluster"] = serde_json::json!({
                    "node_id": node_id,
                    "peers": [],
                    "port": 7946,
                });
            }

            let _: serde_json::Value = client.update_config(&config).await?;
            output::print_success(&format!("Cluster node ID set to '{node_id}'"));
            Ok(())
        }

        ClusterCmd::AddPeer { address } => {
            let mut config: serde_json::Value = client.get_config().await?;

            if let Some(peers) = config
                .get_mut("cluster")
                .and_then(|c| c.get_mut("peers"))
                .and_then(|v| v.as_array_mut())
            {
                let entry = serde_json::Value::String(address.clone());
                if peers.contains(&entry) {
                    output::print_info(&format!("Peer '{address}' already configured"));
                    return Ok(());
                }
                peers.push(entry);
            } else {
                return Err(crate::error::CliError::InputError(
                    "Clustering is not configured. Set a node ID first.".to_string(),
                ));
            }

            let _: serde_json::Value = client.update_config(&config).await?;
            output::print_success(&format!("Peer '{address}' added to cluster"));
            Ok(())
        }

        ClusterCmd::RemovePeer { address } => {
            let mut config: serde_json::Value = client.get_config().await?;

            if let Some(peers) = config
                .get_mut("cluster")
                .and_then(|c| c.get_mut("peers"))
                .and_then(|v| v.as_array_mut())
            {
                let before = peers.len();
                peers.retain(|p| p.as_str() != Some(address));
                if peers.len() == before {
                    return Err(crate::error::CliError::InputError(format!(
                        "Peer '{address}' not found in cluster"
                    )));
                }
            }

            let _: serde_json::Value = client.update_config(&config).await?;
            output::print_success(&format!("Peer '{address}' removed from cluster"));
            Ok(())
        }
    }
}
