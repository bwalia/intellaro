//! Intellaro HTTP CLI — entry point.
//!
//! A full-featured CLI for managing Intellaro HTTP Server remotely
//! via its MCP management API.

mod client;
mod commands;
mod config;
mod error;
mod interactive;
mod output;

use clap::{CommandFactory, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::client::McpClient;
use crate::config::{CliConfig, resolve_profile};
use crate::output::OutputFormat;

/// Intellaro HTTP CLI — manage Intellaro HTTP Server remotely.
#[derive(Parser, Debug)]
#[command(
    name = "intellaro-cli",
    version,
    about = "CLI for managing Intellaro HTTP Server via MCP/REST APIs",
    long_about = "A full-featured CLI tool to configure, monitor, and manage \
                  Intellaro HTTP Server instances remotely. Supports virtual hosts, \
                  routes, caching, security policies, clustering, and OpenAPI management."
)]
struct Cli {
    /// Output format: table, json, yaml.
    #[arg(short, long, value_enum, global = true, default_value = "table")]
    output: OutputFormat,

    /// Connection profile name (from ~/.config/intellaro/cli.toml).
    #[arg(short, long, global = true, env = "INTELLARO_PROFILE")]
    profile: Option<String>,

    /// Server URL override (e.g., "http://localhost:9091").
    #[arg(short, long, global = true, env = "INTELLARO_URL")]
    server: Option<String>,

    /// API key override.
    #[arg(short = 'k', long, global = true, env = "INTELLARO_API_KEY")]
    api_key: Option<String>,

    /// Enable verbose/debug logging.
    #[arg(short, long, global = true, default_value_t = false)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
enum Commands {
    /// Server management (health, status, config, reload, diff).
    #[command(subcommand)]
    Server(commands::server::ServerCmd),

    /// Virtual host management (list, add, update, delete).
    #[command(subcommand)]
    Vhost(commands::vhost::VhostCmd),

    /// Route management (list, add, update, delete).
    #[command(subcommand)]
    Route(commands::route::RouteCmd),

    /// Cache management (status, purge, invalidate, config).
    #[command(subcommand)]
    Cache(commands::cache::CacheCmd),

    /// Security policy management (IP lists, rate limit, JWT).
    #[command(subcommand)]
    Security(commands::security::SecurityCmd),

    /// Cluster management (status, nodes, sync, peers).
    #[command(subcommand)]
    Cluster(commands::cluster::ClusterCmd),

    /// Swagger/OpenAPI management (show, export, validate, generate).
    #[command(subcommand)]
    Swagger(commands::swagger::SwaggerCmd),

    /// Shell completion generation.
    #[command(subcommand)]
    Completions(commands::completions::CompletionsCmd),

    /// Enter interactive (REPL) mode.
    Interactive,

    /// Initialize or manage CLI configuration profiles.
    #[command(subcommand)]
    Config(ConfigCmd),
}

/// CLI configuration management subcommands.
#[derive(Debug, Subcommand)]
enum ConfigCmd {
    /// Initialize a default configuration file.
    Init {
        /// Overwrite existing config if present.
        #[arg(long, default_value_t = false)]
        force: bool,
    },

    /// Show the current CLI configuration.
    Show,

    /// Set the active profile.
    UseProfile {
        /// Profile name to activate.
        name: String,
    },

    /// Add a new server profile.
    AddProfile {
        /// Profile name.
        name: String,

        /// Server URL.
        #[arg(short, long)]
        url: String,

        /// API key for authentication.
        #[arg(short = 'k', long)]
        api_key: Option<String>,
    },

    /// Remove a server profile.
    RemoveProfile {
        /// Profile name to remove.
        name: String,
    },

    /// Show the configuration file path.
    Path,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging.
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("warn")
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Run the command.
    if let Err(err) = run(cli).await {
        output::print_error(&err.to_string());
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let format = cli.output;

    // Handle config commands without needing a server connection.
    if let Commands::Config(ref config_cmd) = cli.command {
        return execute_config_cmd(config_cmd, format).await;
    }

    // Handle completions without needing a server connection.
    if let Commands::Completions(ref comp_cmd) = cli.command {
        let mut cmd = Cli::command();
        commands::completions::execute(comp_cmd, &mut cmd)?;
        return Ok(());
    }

    // Load CLI config and resolve connection profile.
    let cli_config = CliConfig::load()?;
    let profile = resolve_profile(
        &cli_config,
        cli.profile.as_deref(),
        cli.server.as_deref(),
        cli.api_key.as_deref(),
    )?;

    let client = McpClient::from_profile(&profile)?;

    match cli.command {
        Commands::Server(ref cmd) => commands::server::execute(cmd, &client, format).await?,
        Commands::Vhost(ref cmd) => commands::vhost::execute(cmd, &client, format).await?,
        Commands::Route(ref cmd) => commands::route::execute(cmd, &client, format).await?,
        Commands::Cache(ref cmd) => commands::cache::execute(cmd, &client, format).await?,
        Commands::Security(ref cmd) => commands::security::execute(cmd, &client, format).await?,
        Commands::Cluster(ref cmd) => commands::cluster::execute(cmd, &client, format).await?,
        Commands::Swagger(ref cmd) => commands::swagger::execute(cmd, &client, format).await?,
        Commands::Interactive => interactive::run(&client, format).await?,
        Commands::Config(_) | Commands::Completions(_) => unreachable!(),
    }

    Ok(())
}

/// Execute CLI configuration management commands.
async fn execute_config_cmd(
    cmd: &ConfigCmd,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        ConfigCmd::Init { force } => {
            let path = CliConfig::config_path();
            if path.exists() && !force {
                output::print_warn(&format!(
                    "Config already exists at {}. Pass --force to overwrite.",
                    path.display()
                ));
                return Ok(());
            }

            let config = CliConfig::load()?;
            config.save()?;
            output::print_success(&format!("Configuration initialized at {}", path.display()));
        }

        ConfigCmd::Show => {
            let config = CliConfig::load()?;
            let value = serde_json::to_value(&config)?;
            output::render_value(&value, format);
        }

        ConfigCmd::UseProfile { name } => {
            let mut config = CliConfig::load()?;
            if !config.profiles.contains_key(name) {
                return Err(format!("Profile '{}' not found", name).into());
            }
            config.active_profile = name.clone();
            config.save()?;
            output::print_success(&format!("Active profile set to '{name}'"));
        }

        ConfigCmd::AddProfile { name, url, api_key } => {
            let mut config = CliConfig::load()?;
            let profile = crate::config::ServerProfile {
                url: url.clone(),
                auth: crate::config::AuthConfig {
                    api_key: api_key.clone(),
                    bearer_token: None,
                },
                ..Default::default()
            };
            config.profiles.insert(name.clone(), profile);
            config.save()?;
            output::print_success(&format!("Profile '{name}' added ({url})"));
        }

        ConfigCmd::RemoveProfile { name } => {
            let mut config = CliConfig::load()?;
            if config.profiles.remove(name).is_none() {
                return Err(format!("Profile '{}' not found", name).into());
            }
            if config.active_profile == *name {
                config.active_profile = "default".to_string();
            }
            config.save()?;
            output::print_success(&format!("Profile '{name}' removed"));
        }

        ConfigCmd::Path => {
            println!("{}", CliConfig::config_path().display());
        }
    }

    Ok(())
}
