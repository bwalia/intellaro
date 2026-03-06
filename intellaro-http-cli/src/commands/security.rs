//! Security policy management — IP allow/block, rate limiting, JWT config.

use clap::Subcommand;

use crate::client::McpClient;
use crate::error::{CliError, CliResult};
use crate::output::{self, OutputFormat};

/// Security policy subcommands.
#[derive(Debug, Subcommand)]
pub enum SecurityCmd {
    /// Show current security policy configuration.
    Status,

    /// Manage the IP allow list.
    IpAllow {
        #[command(subcommand)]
        action: IpListAction,
    },

    /// Manage the IP block list.
    IpBlock {
        #[command(subcommand)]
        action: IpListAction,
    },

    /// Configure rate limiting.
    RateLimit {
        /// Maximum requests per window. Omit to disable rate limiting.
        #[arg(long)]
        max_requests: Option<u64>,

        /// Window duration in seconds.
        #[arg(long, default_value = "60")]
        window: u64,
    },

    /// Configure JWT validation.
    Jwt {
        #[command(subcommand)]
        action: JwtAction,
    },
}

/// Actions for IP allow/block list management.
#[derive(Debug, Subcommand)]
pub enum IpListAction {
    /// List current entries.
    List,

    /// Add a CIDR entry (e.g., "192.168.1.0/24").
    Add {
        /// CIDR notation entry.
        cidr: String,
    },

    /// Remove a CIDR entry.
    Remove {
        /// CIDR notation entry to remove.
        cidr: String,
    },

    /// Clear the entire list.
    Clear {
        /// Skip confirmation.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
}

/// Actions for JWT configuration.
#[derive(Debug, Subcommand)]
pub enum JwtAction {
    /// Show current JWT configuration.
    Show,

    /// Set JWT validation parameters.
    Set {
        /// HMAC secret or path to public key.
        #[arg(long)]
        secret: String,

        /// Expected issuer.
        #[arg(long)]
        issuer: Option<String>,

        /// Expected audience.
        #[arg(long)]
        audience: Option<String>,
    },

    /// Remove JWT validation (disable it).
    Remove,
}

/// Execute a security subcommand.
pub async fn execute(cmd: &SecurityCmd, client: &McpClient, format: OutputFormat) -> CliResult<()> {
    match cmd {
        SecurityCmd::Status => {
            let config: serde_json::Value = client.get_config().await?;
            let security = config.get("security").cloned().unwrap_or(serde_json::json!({}));

            match format {
                OutputFormat::Table => {
                    let allow_count = security
                        .get("ip_allow")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let block_count = security
                        .get("ip_block")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let rate_limit = security.get("rate_limit").is_some();
                    let jwt = security.get("jwt").is_some();

                    output::render_kv(&[
                        ("IP Allow Rules", &allow_count.to_string()),
                        ("IP Block Rules", &block_count.to_string()),
                        ("Rate Limiting", if rate_limit { "enabled" } else { "disabled" }),
                        ("JWT Validation", if jwt { "enabled" } else { "disabled" }),
                    ]);
                }
                _ => output::render_value(&security, format),
            }
            Ok(())
        }

        SecurityCmd::IpAllow { action } => {
            execute_ip_list(client, format, "ip_allow", action).await
        }

        SecurityCmd::IpBlock { action } => {
            execute_ip_list(client, format, "ip_block", action).await
        }

        SecurityCmd::RateLimit {
            max_requests,
            window,
        } => {
            let mut config: serde_json::Value = client.get_config().await?;

            if let Some(security) = config.get_mut("security") {
                match max_requests {
                    Some(max) => {
                        security["rate_limit"] = serde_json::json!({
                            "max_requests": max,
                            "window_secs": window,
                        });
                        let _: serde_json::Value = client.update_config(&config).await?;
                        output::print_success(&format!(
                            "Rate limit set: {max} requests per {window}s"
                        ));
                    }
                    None => {
                        security["rate_limit"] = serde_json::Value::Null;
                        let _: serde_json::Value = client.update_config(&config).await?;
                        output::print_success("Rate limiting disabled");
                    }
                }
            }
            Ok(())
        }

        SecurityCmd::Jwt { action } => execute_jwt(client, format, action).await,
    }
}

/// Handle IP allow/block list actions.
async fn execute_ip_list(
    client: &McpClient,
    _format: OutputFormat,
    field: &str,
    action: &IpListAction,
) -> CliResult<()> {
    match action {
        IpListAction::List => {
            let config: serde_json::Value = client.get_config().await?;
            let entries = config
                .get("security")
                .and_then(|s| s.get(field))
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            if entries.is_empty() {
                output::print_info(&format!("No entries in {field}"));
            } else {
                let rows: Vec<Vec<String>> = entries
                    .iter()
                    .enumerate()
                    .map(|(i, e)| {
                        vec![
                            (i + 1).to_string(),
                            e.as_str().unwrap_or("-").to_string(),
                        ]
                    })
                    .collect();
                output::render_table(&["#", "CIDR"], &rows);
            }
            Ok(())
        }

        IpListAction::Add { cidr } => {
            // Validate CIDR format locally before sending.
            cidr.parse::<std::net::IpAddr>()
                .map(|_| ())
                .or_else(|_| cidr.parse::<ipnet::IpNet>().map(|_| ()))
                .map_err(|_| CliError::InputError(format!("Invalid CIDR: {cidr}")))?;

            let mut config: serde_json::Value = client.get_config().await?;

            if let Some(list) = config
                .get_mut("security")
                .and_then(|s| s.get_mut(field))
                .and_then(|v| v.as_array_mut())
            {
                let entry = serde_json::Value::String(cidr.clone());
                if list.contains(&entry) {
                    output::print_info(&format!("'{cidr}' already in {field}"));
                    return Ok(());
                }
                list.push(entry);
            }

            let _: serde_json::Value = client.update_config(&config).await?;
            output::print_success(&format!("Added '{cidr}' to {field}"));
            Ok(())
        }

        IpListAction::Remove { cidr } => {
            let mut config: serde_json::Value = client.get_config().await?;

            if let Some(list) = config
                .get_mut("security")
                .and_then(|s| s.get_mut(field))
                .and_then(|v| v.as_array_mut())
            {
                let before = list.len();
                list.retain(|e| e.as_str() != Some(cidr));
                if list.len() == before {
                    return Err(CliError::InputError(format!("'{cidr}' not found in {field}")));
                }
            }

            let _: serde_json::Value = client.update_config(&config).await?;
            output::print_success(&format!("Removed '{cidr}' from {field}"));
            Ok(())
        }

        IpListAction::Clear { yes } => {
            if !yes {
                output::print_warn(&format!(
                    "This will clear ALL entries in {field}. Pass --yes to confirm."
                ));
                return Ok(());
            }

            let mut config: serde_json::Value = client.get_config().await?;
            if let Some(security) = config.get_mut("security") {
                security[field] = serde_json::json!([]);
            }

            let _: serde_json::Value = client.update_config(&config).await?;
            output::print_success(&format!("{field} cleared"));
            Ok(())
        }
    }
}

/// Handle JWT configuration actions.
async fn execute_jwt(
    client: &McpClient,
    format: OutputFormat,
    action: &JwtAction,
) -> CliResult<()> {
    match action {
        JwtAction::Show => {
            let config: serde_json::Value = client.get_config().await?;
            let jwt = config
                .get("security")
                .and_then(|s| s.get("jwt"))
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            if jwt.is_null() {
                output::print_info("JWT validation is not configured");
            } else {
                output::render_value(&jwt, format);
            }
            Ok(())
        }

        JwtAction::Set {
            secret,
            issuer,
            audience,
        } => {
            let mut config: serde_json::Value = client.get_config().await?;

            let jwt_config = serde_json::json!({
                "secret_or_key_path": secret,
                "issuer": issuer,
                "audience": audience,
            });

            if let Some(security) = config.get_mut("security") {
                security["jwt"] = jwt_config;
            }

            let _: serde_json::Value = client.update_config(&config).await?;
            output::print_success("JWT validation configured");
            Ok(())
        }

        JwtAction::Remove => {
            let mut config: serde_json::Value = client.get_config().await?;
            if let Some(security) = config.get_mut("security") {
                security["jwt"] = serde_json::Value::Null;
            }

            let _: serde_json::Value = client.update_config(&config).await?;
            output::print_success("JWT validation removed");
            Ok(())
        }
    }
}
