//! Server management commands — health, status, config, reload.

use clap::Subcommand;

use crate::client::McpClient;
use crate::error::CliResult;
use crate::output::{self, OutputFormat};

/// Server management subcommands.
#[derive(Debug, Subcommand)]
pub enum ServerCmd {
    /// Check server health.
    Health,

    /// Show detailed server status (version, listeners, upstreams).
    Status,

    /// Retrieve the running server configuration.
    GetConfig {
        /// Write configuration to a local file instead of stdout.
        #[arg(short, long)]
        output_file: Option<String>,
    },

    /// Push a local configuration file to the running server.
    PushConfig {
        /// Path to the JSON or YAML configuration file.
        #[arg(short, long)]
        file: String,
    },

    /// Trigger a hot-reload of the server configuration from disk.
    Reload,

    /// Diff local configuration file against the running server config.
    Diff {
        /// Path to the local configuration file to compare.
        #[arg(short, long)]
        file: String,
    },
}

/// Execute a server subcommand.
pub async fn execute(cmd: &ServerCmd, client: &McpClient, format: OutputFormat) -> CliResult<()> {
    match cmd {
        ServerCmd::Health => {
            let data: serde_json::Value = client.health().await?;
            match format {
                OutputFormat::Table => {
                    let status = data
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    output::render_kv(&[
                        ("Server", client.base_url()),
                        ("Status", status),
                    ]);
                }
                _ => output::render_value(&data, format),
            }
            Ok(())
        }

        ServerCmd::Status => {
            let data: serde_json::Value = client.status().await?;
            match format {
                OutputFormat::Table => {
                    let version = data.get("version").and_then(|v| v.as_str()).unwrap_or("-");
                    let listeners = data.get("listeners").and_then(|v| v.as_u64()).unwrap_or(0);
                    let upstreams = data.get("upstreams").and_then(|v| v.as_u64()).unwrap_or(0);
                    let cache = data.get("cache_enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                    output::render_kv(&[
                        ("Server", client.base_url()),
                        ("Version", version),
                        ("Listeners", &listeners.to_string()),
                        ("Upstreams", &upstreams.to_string()),
                        ("Cache", if cache { "enabled" } else { "disabled" }),
                    ]);
                }
                _ => output::render_value(&data, format),
            }
            Ok(())
        }

        ServerCmd::GetConfig { output_file } => {
            let data: serde_json::Value = client.get_config().await?;

            if let Some(path) = output_file {
                let content = if path.ends_with(".yaml") || path.ends_with(".yml") {
                    serde_yaml::to_string(&data)
                        .map_err(|e| crate::error::CliError::SerializationError(e.to_string()))?
                } else {
                    serde_json::to_string_pretty(&data)
                        .map_err(|e| crate::error::CliError::SerializationError(e.to_string()))?
                };
                std::fs::write(path, &content)?;
                output::print_success(&format!("Configuration written to {path}"));
            } else {
                output::render_value(&data, format);
            }
            Ok(())
        }

        ServerCmd::PushConfig { file } => {
            let content = std::fs::read_to_string(file)?;
            let config_value: serde_json::Value = if file.ends_with(".yaml") || file.ends_with(".yml") {
                serde_yaml::from_str(&content)
                    .map_err(|e| crate::error::CliError::ParseError(e.to_string()))?
            } else {
                serde_json::from_str(&content)
                    .map_err(|e| crate::error::CliError::ParseError(e.to_string()))?
            };

            let result: serde_json::Value = client.update_config(&config_value).await?;
            output::print_success("Configuration pushed to server");
            output::render_value(&result, format);
            Ok(())
        }

        ServerCmd::Reload => {
            let _: serde_json::Value = client.reload_config().await?;
            output::print_success("Server configuration reloaded from disk");
            Ok(())
        }

        ServerCmd::Diff { file } => {
            let local_content = std::fs::read_to_string(file)?;
            let remote: serde_json::Value = client.get_config().await?;

            // Normalize both to YAML for readable diffing.
            let remote_yaml = serde_yaml::to_string(&remote)
                .map_err(|e| crate::error::CliError::SerializationError(e.to_string()))?;

            let local_value: serde_json::Value = if file.ends_with(".yaml") || file.ends_with(".yml") {
                serde_yaml::from_str(&local_content)
                    .map_err(|e| crate::error::CliError::ParseError(e.to_string()))?
            } else {
                serde_json::from_str(&local_content)
                    .map_err(|e| crate::error::CliError::ParseError(e.to_string()))?
            };
            let local_yaml = serde_yaml::to_string(&local_value)
                .map_err(|e| crate::error::CliError::SerializationError(e.to_string()))?;

            if local_yaml == remote_yaml {
                output::print_success("Local and remote configurations are identical");
            } else {
                output::render_diff(&format!("local ({file})"), "remote (server)", &local_yaml, &remote_yaml);
            }
            Ok(())
        }
    }
}
