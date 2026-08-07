//! Intellaro HTTP Server — standalone binary entry point.
//!
//! Kept for backwards compatibility; the unified `intellaro` binary
//! (`intellaro --role proxy`) is the preferred way to run the platform.

use clap::Parser;

use intellaro_http_server::bootstrap::{self, RunOptions};
use intellaro_http_server::config::ConfigManager;

/// Command-line arguments for the Intellaro HTTP server.
#[derive(Parser, Debug)]
#[command(
    name = "intellaro-http-server",
    version,
    about = "Intellaro — High-performance HTTP(S) server with reverse proxy, caching & clustering"
)]
struct CliArgs {
    /// Path to the configuration file (JSON, YAML, or intellaro.io/v1).
    #[arg(short, long, default_value = "config.yaml")]
    config: String,

    /// Validate configuration and exit without starting the server.
    #[arg(long, default_value_t = false)]
    validate: bool,
}

#[tokio::main]
async fn main() {
    let args = CliArgs::parse();

    if args.validate {
        match ConfigManager::load(&args.config) {
            Ok(_) => {
                println!("Configuration is valid.");
                return;
            }
            Err(err) => {
                eprintln!("Configuration is invalid: {err}");
                std::process::exit(1);
            }
        }
    }

    if let Err(err) = bootstrap::run(RunOptions {
        config_path: args.config,
    })
    .await
    {
        eprintln!("Fatal: {err}");
        std::process::exit(1);
    }
}
