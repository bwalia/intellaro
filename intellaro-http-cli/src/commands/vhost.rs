//! Virtual host management commands — add, update, delete, list.
//!
//! Virtual hosts map to upstream groups in the server configuration.
//! This module manipulates the `upstreams` section of the config.

use clap::Subcommand;

use crate::client::McpClient;
use crate::error::{CliError, CliResult};
use crate::output::{self, OutputFormat};

/// Virtual host subcommands.
#[derive(Debug, Subcommand)]
pub enum VhostCmd {
    /// List all configured virtual hosts (upstream groups).
    List,

    /// Show details for a specific virtual host.
    Get {
        /// Name of the virtual host / upstream.
        name: String,
    },

    /// Add a new virtual host with backends.
    Add {
        /// Virtual host name.
        #[arg(short, long)]
        name: String,

        /// Backend server addresses (comma-separated, e.g., "10.0.0.1:80,10.0.0.2:80").
        #[arg(short, long)]
        backends: String,

        /// Load balancing strategy (round_robin, least_connections, weighted).
        #[arg(short, long, default_value = "round_robin")]
        lb_strategy: String,
    },

    /// Update an existing virtual host.
    Update {
        /// Virtual host name to update.
        name: String,

        /// New backend server addresses (comma-separated).
        #[arg(short, long)]
        backends: Option<String>,

        /// New load balancing strategy.
        #[arg(short, long)]
        lb_strategy: Option<String>,
    },

    /// Remove a virtual host.
    Delete {
        /// Virtual host name to delete.
        name: String,

        /// Skip confirmation prompt.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
}

/// Execute a virtual host subcommand.
pub async fn execute(cmd: &VhostCmd, client: &McpClient, format: OutputFormat) -> CliResult<()> {
    match cmd {
        VhostCmd::List => {
            let config: serde_json::Value = client.get_config().await?;
            let upstreams = config
                .get("upstreams")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            if upstreams.is_empty() {
                output::print_info("No virtual hosts configured");
                return Ok(());
            }

            match format {
                OutputFormat::Table => {
                    let rows: Vec<Vec<String>> = upstreams
                        .iter()
                        .map(|u| {
                            let name = u.get("name").and_then(|v| v.as_str()).unwrap_or("-");
                            let strategy = u.get("load_balancing").and_then(|v| v.as_str()).unwrap_or("-");
                            let server_count = u
                                .get("servers")
                                .and_then(|v| v.as_array())
                                .map(|a| a.len())
                                .unwrap_or(0);
                            let has_hc = u.get("health_check").is_some();
                            vec![
                                name.to_string(),
                                strategy.to_string(),
                                server_count.to_string(),
                                if has_hc { "yes" } else { "no" }.to_string(),
                            ]
                        })
                        .collect();
                    output::render_table(&["Name", "LB Strategy", "Backends", "Health Check"], &rows);
                }
                _ => {
                    let value = serde_json::Value::Array(upstreams);
                    output::render_value(&value, format);
                }
            }
            Ok(())
        }

        VhostCmd::Get { name } => {
            let config: serde_json::Value = client.get_config().await?;
            let upstream = find_upstream(&config, name)?;

            match format {
                OutputFormat::Table => {
                    let strategy = upstream.get("load_balancing").and_then(|v| v.as_str()).unwrap_or("-");
                    output::render_kv(&[
                        ("Name", name.as_str()),
                        ("LB Strategy", strategy),
                    ]);
                    println!();

                    if let Some(servers) = upstream.get("servers").and_then(|v| v.as_array()) {
                        let rows: Vec<Vec<String>> = servers
                            .iter()
                            .map(|s| {
                                let addr = s.get("address").and_then(|v| v.as_str()).unwrap_or("-");
                                let weight = s.get("weight").and_then(|v| v.as_u64()).unwrap_or(1);
                                vec![addr.to_string(), weight.to_string()]
                            })
                            .collect();
                        output::render_table(&["Address", "Weight"], &rows);
                    }
                }
                _ => output::render_value(&upstream, format),
            }
            Ok(())
        }

        VhostCmd::Add {
            name,
            backends,
            lb_strategy,
        } => {
            let mut config: serde_json::Value = client.get_config().await?;

            let servers: Vec<serde_json::Value> = backends
                .split(',')
                .map(|addr| {
                    serde_json::json!({
                        "address": addr.trim(),
                        "weight": 1
                    })
                })
                .collect();

            let new_upstream = serde_json::json!({
                "name": name,
                "servers": servers,
                "load_balancing": lb_strategy,
            });

            if let Some(upstreams) = config.get_mut("upstreams").and_then(|v| v.as_array_mut()) {
                // Check for duplicate
                if upstreams.iter().any(|u| u.get("name").and_then(|n| n.as_str()) == Some(name)) {
                    return Err(CliError::InputError(format!(
                        "Virtual host '{}' already exists. Use `vhost update` instead.",
                        name
                    )));
                }
                upstreams.push(new_upstream);
            }

            let _: serde_json::Value = client.update_config(&config).await?;
            output::print_success(&format!("Virtual host '{name}' added with {} backend(s)", servers.len()));
            Ok(())
        }

        VhostCmd::Update {
            name,
            backends,
            lb_strategy,
        } => {
            let mut config: serde_json::Value = client.get_config().await?;

            let upstream = config
                .get_mut("upstreams")
                .and_then(|v| v.as_array_mut())
                .and_then(|arr| arr.iter_mut().find(|u| u.get("name").and_then(|n| n.as_str()) == Some(name)))
                .ok_or_else(|| CliError::InputError(format!("Virtual host '{name}' not found")))?;

            if let Some(addrs) = backends {
                let servers: Vec<serde_json::Value> = addrs
                    .split(',')
                    .map(|addr| serde_json::json!({"address": addr.trim(), "weight": 1}))
                    .collect();
                upstream["servers"] = serde_json::Value::Array(servers);
            }

            if let Some(strategy) = lb_strategy {
                upstream["load_balancing"] = serde_json::Value::String(strategy.clone());
            }

            let _: serde_json::Value = client.update_config(&config).await?;
            output::print_success(&format!("Virtual host '{name}' updated"));
            Ok(())
        }

        VhostCmd::Delete { name, yes } => {
            if !yes {
                output::print_warn(&format!(
                    "This will delete virtual host '{name}'. Pass --yes to confirm."
                ));
                return Ok(());
            }

            let mut config: serde_json::Value = client.get_config().await?;

            if let Some(upstreams) = config.get_mut("upstreams").and_then(|v| v.as_array_mut()) {
                let before = upstreams.len();
                upstreams.retain(|u| u.get("name").and_then(|n| n.as_str()) != Some(name));
                if upstreams.len() == before {
                    return Err(CliError::InputError(format!("Virtual host '{name}' not found")));
                }
            }

            let _: serde_json::Value = client.update_config(&config).await?;
            output::print_success(&format!("Virtual host '{name}' deleted"));
            Ok(())
        }
    }
}

/// Find an upstream by name in the full config.
fn find_upstream(config: &serde_json::Value, name: &str) -> CliResult<serde_json::Value> {
    config
        .get("upstreams")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.iter().find(|u| u.get("name").and_then(|n| n.as_str()) == Some(name)))
        .cloned()
        .ok_or_else(|| CliError::InputError(format!("Virtual host '{name}' not found")))
}
