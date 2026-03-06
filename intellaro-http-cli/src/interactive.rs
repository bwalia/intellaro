//! Interactive prompt-based CLI mode.
//!
//! Provides a REPL that accepts the same commands as the non-interactive
//! CLI, useful for exploratory management sessions.

use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

use crate::client::McpClient;
use crate::output::{self, OutputFormat};

/// Run the interactive REPL.
///
/// Accepts space-separated commands matching the top-level CLI subcommands
/// (e.g., `server status`, `vhost list`, `cache purge --yes`).
pub async fn run(client: &McpClient, format: OutputFormat) -> anyhow::Result<()> {
    let mut rl = DefaultEditor::new()?;
    let history_path = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("intellaro")
        .join("cli_history.txt");

    // Load history if available.
    if history_path.exists() {
        let _ = rl.load_history(&history_path);
    }

    println!("Intellaro CLI — Interactive Mode");
    println!("Type 'help' for available commands, 'quit' to exit.\n");

    loop {
        let prompt = format!("intellaro({})> ", short_url(client.base_url()));

        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let _ = rl.add_history_entry(line);

                match line {
                    "quit" | "exit" | "q" => {
                        output::print_info("Goodbye.");
                        break;
                    }
                    "help" | "?" => {
                        print_interactive_help();
                    }
                    _ => {
                        if let Err(err) = dispatch_interactive(line, client, format).await {
                            output::print_error(&err.to_string());
                        }
                    }
                }
            }
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
                output::print_info("Goodbye.");
                break;
            }
            Err(err) => {
                output::print_error(&format!("Input error: {err}"));
                break;
            }
        }
    }

    // Save history.
    if let Some(parent) = history_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = rl.save_history(&history_path);

    Ok(())
}

/// Dispatch a single interactive command line.
async fn dispatch_interactive(
    line: &str,
    client: &McpClient,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(());
    }

    match parts[0] {
        "server" => match parts.get(1).copied() {
            Some("health") => {
                let cmd = crate::commands::server::ServerCmd::Health;
                crate::commands::server::execute(&cmd, client, format).await?;
            }
            Some("status") => {
                let cmd = crate::commands::server::ServerCmd::Status;
                crate::commands::server::execute(&cmd, client, format).await?;
            }
            Some("reload") => {
                let cmd = crate::commands::server::ServerCmd::Reload;
                crate::commands::server::execute(&cmd, client, format).await?;
            }
            Some("get-config") => {
                let cmd = crate::commands::server::ServerCmd::GetConfig { output_file: None };
                crate::commands::server::execute(&cmd, client, format).await?;
            }
            _ => output::print_warn("Usage: server {health|status|reload|get-config}"),
        },

        "vhost" => match parts.get(1).copied() {
            Some("list") => {
                let cmd = crate::commands::vhost::VhostCmd::List;
                crate::commands::vhost::execute(&cmd, client, format).await?;
            }
            Some("get") if parts.len() >= 3 => {
                let cmd = crate::commands::vhost::VhostCmd::Get {
                    name: parts[2].to_string(),
                };
                crate::commands::vhost::execute(&cmd, client, format).await?;
            }
            _ => output::print_warn("Usage: vhost {list|get <name>|add|update|delete}"),
        },

        "cache" => match parts.get(1).copied() {
            Some("status") => {
                let cmd = crate::commands::cache::CacheCmd::Status;
                crate::commands::cache::execute(&cmd, client, format).await?;
            }
            Some("purge") => {
                let cmd = crate::commands::cache::CacheCmd::Purge { yes: true };
                crate::commands::cache::execute(&cmd, client, format).await?;
            }
            Some("invalidate") if parts.len() >= 3 => {
                let cmd = crate::commands::cache::CacheCmd::Invalidate {
                    key: parts[2].to_string(),
                };
                crate::commands::cache::execute(&cmd, client, format).await?;
            }
            _ => output::print_warn("Usage: cache {status|purge|invalidate <key>}"),
        },

        "security" => match parts.get(1).copied() {
            Some("status") => {
                let cmd = crate::commands::security::SecurityCmd::Status;
                crate::commands::security::execute(&cmd, client, format).await?;
            }
            _ => output::print_warn("Usage: security {status|ip-allow|ip-block|rate-limit|jwt}"),
        },

        "cluster" => match parts.get(1).copied() {
            Some("status") => {
                let cmd = crate::commands::cluster::ClusterCmd::Status;
                crate::commands::cluster::execute(&cmd, client, format).await?;
            }
            Some("list-nodes") => {
                let cmd = crate::commands::cluster::ClusterCmd::ListNodes;
                crate::commands::cluster::execute(&cmd, client, format).await?;
            }
            _ => output::print_warn("Usage: cluster {status|list-nodes|sync|add-peer|remove-peer}"),
        },

        "swagger" => match parts.get(1).copied() {
            Some("show") => {
                let cmd = crate::commands::swagger::SwaggerCmd::Show;
                crate::commands::swagger::execute(&cmd, client, format).await?;
            }
            Some("validate") => {
                let cmd = crate::commands::swagger::SwaggerCmd::Validate;
                crate::commands::swagger::execute(&cmd, client, format).await?;
            }
            _ => output::print_warn("Usage: swagger {show|export|validate|generate}"),
        },

        other => {
            output::print_warn(&format!("Unknown command: '{other}'. Type 'help' for usage."));
        }
    }

    Ok(())
}

/// Print interactive mode help.
fn print_interactive_help() {
    println!(
        r#"
Available commands:

  server health          Check server health
  server status          Show detailed server status
  server reload          Hot-reload server configuration
  server get-config      Display running configuration

  vhost list             List virtual hosts
  vhost get <name>       Show virtual host details

  cache status           Show cache configuration
  cache purge            Purge entire cache
  cache invalidate <key> Invalidate a cache entry

  security status        Show security policy overview

  cluster status         Show cluster configuration
  cluster list-nodes     List cluster peers

  swagger show           Display OpenAPI spec
  swagger validate       Validate OpenAPI spec

  help / ?               Show this help
  quit / exit            Exit interactive mode
"#
    );
}

/// Shorten a URL for the prompt (show host:port only).
fn short_url(url: &str) -> String {
    url.strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url)
        .to_string()
}
