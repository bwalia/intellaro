//! Cache management commands — show config, purge, invalidate.

use clap::Subcommand;

use crate::client::McpClient;
use crate::error::CliResult;
use crate::output::{self, OutputFormat};

/// Cache management subcommands.
#[derive(Debug, Subcommand)]
pub enum CacheCmd {
    /// Show current cache configuration.
    Status,

    /// Purge the entire server cache.
    Purge {
        /// Skip confirmation prompt.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },

    /// Invalidate a specific cache entry by key.
    Invalidate {
        /// Cache key to invalidate (method:uri:accept).
        key: String,
    },

    /// Update cache configuration.
    Config {
        /// Enable or disable caching.
        #[arg(long)]
        enabled: Option<bool>,

        /// Maximum number of cached entries.
        #[arg(long)]
        max_entries: Option<usize>,

        /// Default TTL in seconds.
        #[arg(long)]
        ttl: Option<u64>,

        /// Enable caching of POST responses.
        #[arg(long)]
        cache_post: Option<bool>,
    },
}

/// Execute a cache subcommand.
pub async fn execute(cmd: &CacheCmd, client: &McpClient, format: OutputFormat) -> CliResult<()> {
    match cmd {
        CacheCmd::Status => {
            let config: serde_json::Value = client.get_config().await?;
            let cache = config.get("cache").cloned().unwrap_or(serde_json::json!({}));

            match format {
                OutputFormat::Table => {
                    let enabled = cache.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                    let max = cache.get("max_entries").and_then(|v| v.as_u64()).unwrap_or(0);
                    let ttl = cache.get("default_ttl_secs").and_then(|v| v.as_u64()).unwrap_or(0);
                    let post = cache.get("cache_post").and_then(|v| v.as_bool()).unwrap_or(false);

                    output::render_kv(&[
                        ("Enabled", if enabled { "yes" } else { "no" }),
                        ("Max Entries", &max.to_string()),
                        ("Default TTL", &format!("{ttl}s")),
                        ("Cache POST", if post { "yes" } else { "no" }),
                    ]);
                }
                _ => output::render_value(&cache, format),
            }
            Ok(())
        }

        CacheCmd::Purge { yes } => {
            if !yes {
                output::print_warn("This will purge the ENTIRE server cache. Pass --yes to confirm.");
                return Ok(());
            }

            let _: serde_json::Value = client.purge_cache().await?;
            output::print_success("Cache purged");
            Ok(())
        }

        CacheCmd::Invalidate { key } => {
            let _: serde_json::Value = client.invalidate_cache(key).await?;
            output::print_success(&format!("Cache entry '{key}' invalidated"));
            Ok(())
        }

        CacheCmd::Config {
            enabled,
            max_entries,
            ttl,
            cache_post,
        } => {
            let mut config: serde_json::Value = client.get_config().await?;

            if let Some(cache) = config.get_mut("cache") {
                if let Some(e) = enabled {
                    cache["enabled"] = serde_json::Value::Bool(*e);
                }
                if let Some(m) = max_entries {
                    cache["max_entries"] = serde_json::json!(m);
                }
                if let Some(t) = ttl {
                    cache["default_ttl_secs"] = serde_json::json!(t);
                }
                if let Some(p) = cache_post {
                    cache["cache_post"] = serde_json::Value::Bool(*p);
                }
            }

            let _: serde_json::Value = client.update_config(&config).await?;
            output::print_success("Cache configuration updated");
            Ok(())
        }
    }
}
