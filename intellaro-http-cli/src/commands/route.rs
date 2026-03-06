//! Route management commands — add, update, delete, list.
//!
//! Routes associate URL path prefixes with upstream groups and
//! per-route policies (caching, security, timeouts).

use clap::Subcommand;

use crate::client::McpClient;
use crate::error::{CliError, CliResult};
use crate::output::{self, OutputFormat};

/// Route management subcommands.
#[derive(Debug, Subcommand)]
pub enum RouteCmd {
    /// List all configured routes (static roots).
    List,

    /// Show details for a specific route by URL prefix.
    Get {
        /// URL path prefix (e.g., "/api" or "/static").
        prefix: String,
    },

    /// Add a new route mapping a URL prefix to a backend directory or upstream.
    Add {
        /// URL path prefix (e.g., "/static").
        #[arg(short = 'p', long)]
        prefix: String,

        /// Directory to serve (for static routes).
        #[arg(short, long)]
        directory: Option<String>,

        /// Target upstream name (for proxy routes).
        #[arg(short, long)]
        upstream: Option<String>,

        /// Enable directory listing for static routes.
        #[arg(long, default_value_t = false)]
        dir_listing: bool,
    },

    /// Update an existing route.
    Update {
        /// URL path prefix to update.
        prefix: String,

        /// New directory path.
        #[arg(short, long)]
        directory: Option<String>,

        /// Toggle directory listing.
        #[arg(long)]
        dir_listing: Option<bool>,
    },

    /// Delete a route by URL prefix.
    Delete {
        /// URL path prefix to delete.
        prefix: String,

        /// Skip confirmation prompt.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
}

/// Execute a route subcommand.
pub async fn execute(cmd: &RouteCmd, client: &McpClient, format: OutputFormat) -> CliResult<()> {
    match cmd {
        RouteCmd::List => {
            let config: serde_json::Value = client.get_config().await?;
            let routes = config
                .get("static_roots")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            if routes.is_empty() {
                output::print_info("No routes configured");
                return Ok(());
            }

            match format {
                OutputFormat::Table => {
                    let rows: Vec<Vec<String>> = routes
                        .iter()
                        .map(|r| {
                            let prefix = r.get("url_prefix").and_then(|v| v.as_str()).unwrap_or("-");
                            let dir = r.get("directory").and_then(|v| v.as_str()).unwrap_or("-");
                            let listing = r
                                .get("directory_listing")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            vec![
                                prefix.to_string(),
                                dir.to_string(),
                                if listing { "yes" } else { "no" }.to_string(),
                            ]
                        })
                        .collect();
                    output::render_table(&["URL Prefix", "Directory", "Dir Listing"], &rows);
                }
                _ => {
                    output::render_value(&serde_json::Value::Array(routes), format);
                }
            }
            Ok(())
        }

        RouteCmd::Get { prefix } => {
            let config: serde_json::Value = client.get_config().await?;
            let route = find_route(&config, prefix)?;
            output::render_value(&route, format);
            Ok(())
        }

        RouteCmd::Add {
            prefix,
            directory,
            upstream,
            dir_listing,
        } => {
            let mut config: serde_json::Value = client.get_config().await?;

            if directory.is_none() && upstream.is_none() {
                return Err(CliError::InputError(
                    "Specify --directory (static) or --upstream (proxy) for the route".to_string(),
                ));
            }

            if let Some(dir) = directory {
                let new_route = serde_json::json!({
                    "url_prefix": prefix,
                    "directory": dir,
                    "directory_listing": dir_listing,
                });

                if let Some(roots) = config.get_mut("static_roots").and_then(|v| v.as_array_mut()) {
                    if roots.iter().any(|r| r.get("url_prefix").and_then(|v| v.as_str()) == Some(prefix)) {
                        return Err(CliError::InputError(format!(
                            "Route '{prefix}' already exists. Use `route update` instead."
                        )));
                    }
                    roots.push(new_route);
                }

                let _: serde_json::Value = client.update_config(&config).await?;
                output::print_success(&format!("Static route '{prefix}' → '{dir}' added"));
            } else if let Some(_upstream_name) = upstream {
                output::print_info("Proxy-based route mapping is not yet implemented on the server");
            }

            Ok(())
        }

        RouteCmd::Update {
            prefix,
            directory,
            dir_listing,
        } => {
            let mut config: serde_json::Value = client.get_config().await?;

            let route = config
                .get_mut("static_roots")
                .and_then(|v| v.as_array_mut())
                .and_then(|arr| {
                    arr.iter_mut()
                        .find(|r| r.get("url_prefix").and_then(|v| v.as_str()) == Some(prefix))
                })
                .ok_or_else(|| CliError::InputError(format!("Route '{prefix}' not found")))?;

            if let Some(dir) = directory {
                route["directory"] = serde_json::Value::String(dir.clone());
            }
            if let Some(listing) = dir_listing {
                route["directory_listing"] = serde_json::Value::Bool(*listing);
            }

            let _: serde_json::Value = client.update_config(&config).await?;
            output::print_success(&format!("Route '{prefix}' updated"));
            Ok(())
        }

        RouteCmd::Delete { prefix, yes } => {
            if !yes {
                output::print_warn(&format!(
                    "This will delete route '{prefix}'. Pass --yes to confirm."
                ));
                return Ok(());
            }

            let mut config: serde_json::Value = client.get_config().await?;

            if let Some(roots) = config.get_mut("static_roots").and_then(|v| v.as_array_mut()) {
                let before = roots.len();
                roots.retain(|r| r.get("url_prefix").and_then(|v| v.as_str()) != Some(prefix));
                if roots.len() == before {
                    return Err(CliError::InputError(format!("Route '{prefix}' not found")));
                }
            }

            let _: serde_json::Value = client.update_config(&config).await?;
            output::print_success(&format!("Route '{prefix}' deleted"));
            Ok(())
        }
    }
}

fn find_route(config: &serde_json::Value, prefix: &str) -> CliResult<serde_json::Value> {
    config
        .get("static_roots")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.iter().find(|r| r.get("url_prefix").and_then(|v| v.as_str()) == Some(prefix)))
        .cloned()
        .ok_or_else(|| CliError::InputError(format!("Route '{prefix}' not found")))
}
