//! `intellaro` — the unified platform binary.
//!
//! One Rust binary, many roles (build-prompt §1.1):
//!
//! | Role      | Purpose                                                    |
//! |-----------|------------------------------------------------------------|
//! | `proxy`   | Data plane: L7 reverse proxy, cache, security, API gateway |
//! | `ingress` | Kubernetes Ingress controller (same data plane)            |
//! | `gateway` | Kubernetes Gateway API controller (Phase 4)                |
//! | `agent`   | Fleet agent for remote config/metrics/certs (Phase 5)      |
//! | `control` | Embedded control plane (Phase 5/6)                         |
//! | `all`     | Combined single-node mode (POP deploys, WSLProxy-like)     |
//!
//! Roles marked with a phase exit with a roadmap pointer instead of
//! pretending to work.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use intellaro_http_server::bootstrap::{self, RunOptions};
use intellaro_http_server::config::ConfigManager;

#[derive(Parser, Debug)]
#[command(
    name = "intellaro",
    version,
    about = "Intellaro — Rust-native application delivery platform (proxy, ingress, gateway, fleet)",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Arguments used when no subcommand is given (implicit `run`).
    #[command(flatten)]
    run: RunArgs,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the platform in the selected role.
    Run(RunArgs),

    /// Validate a configuration file (legacy or intellaro.io/v1) and exit.
    Validate {
        /// Path to the configuration file.
        #[arg(short, long, default_value = "config.yaml")]
        config: String,
    },

    /// Emit the JSON Schemas for the intellaro.io/v1 config model
    /// (Gateway, Route, Upstream, WafPolicy).
    Schema {
        /// Directory to write `<kind>.schema.json` files into.
        #[arg(long, default_value = "docs/schemas")]
        out_dir: PathBuf,

        /// Print schemas to stdout instead of writing files.
        #[arg(long)]
        stdout: bool,
    },

    /// Print the Kubernetes CRD manifests (for `kubectl apply -f -`).
    Crds,
}

#[derive(Parser, Debug)]
struct RunArgs {
    /// Role to run.
    #[arg(long, value_enum, default_value_t = Role::Proxy)]
    role: Role,

    /// Path to the configuration file (proxy/all roles).
    #[arg(short, long, default_value = "config.yaml")]
    config: String,

    /// Base URL of the data-plane MCP API (ingress role).
    #[arg(long, env = "INTELLARO_MCP_URL")]
    mcp_url: Option<String>,

    /// API key for the MCP API (ingress role).
    #[arg(long, env = "INTELLARO_MCP_API_KEY")]
    mcp_api_key: Option<String>,

    /// Namespace to watch; omit for cluster-wide (ingress role).
    #[arg(long, env = "INTELLARO_NAMESPACE")]
    namespace: Option<String>,

    /// Metrics server port (ingress role).
    #[arg(long, env = "INTELLARO_METRICS_PORT")]
    metrics_port: Option<u16>,

    /// Health probe port (ingress role).
    #[arg(long, env = "INTELLARO_HEALTH_PORT")]
    health_port: Option<u16>,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// L7 reverse proxy / API gateway data plane.
    Proxy,
    /// Kubernetes Ingress controller.
    Ingress,
    /// Kubernetes Gateway API controller (Phase 4).
    Gateway,
    /// Fleet agent (Phase 5).
    Agent,
    /// Control plane (Phase 5/6).
    Control,
    /// Combined single-node mode: data plane + management API + ops.
    All,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Some(Command::Run(args)) => run(args).await,
        None => run(cli.run).await,
        Some(Command::Validate { config }) => validate(&config),
        Some(Command::Schema { out_dir, stdout }) => schema(&out_dir, stdout),
        Some(Command::Crds) => {
            for (i, crd) in intellaro_ingress::crd_manifests().iter().enumerate() {
                if i > 0 {
                    println!("---");
                }
                print!("{crd}");
            }
            Ok(ExitCode::SUCCESS)
        }
    };

    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("Error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: RunArgs) -> anyhow::Result<ExitCode> {
    match args.role {
        Role::Proxy | Role::All => {
            bootstrap::run(RunOptions {
                config_path: args.config,
            })
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?;
            Ok(ExitCode::SUCCESS)
        }

        Role::Ingress => {
            intellaro_ingress::logging::init();

            let mut ctrl_config = intellaro_ingress::config::ControllerConfig::from_env();
            if let Some(url) = args.mcp_url {
                ctrl_config.mcp_url = url;
            }
            if let Some(key) = args.mcp_api_key {
                ctrl_config.mcp_api_key = Some(key);
            }
            if args.namespace.is_some() {
                ctrl_config.namespace = args.namespace;
            }
            if let Some(port) = args.metrics_port {
                ctrl_config.metrics_port = port;
            }
            if let Some(port) = args.health_port {
                ctrl_config.health_port = port;
            }

            intellaro_ingress::run(ctrl_config).await?;
            Ok(ExitCode::SUCCESS)
        }

        Role::Gateway => {
            eprintln!(
                "--role gateway (Kubernetes Gateway API controller) is Phase 4 of the roadmap.\n\
                 The Ingress controller is available today: `intellaro --role ingress`.\n\
                 See docs/parity-matrix.md."
            );
            Ok(ExitCode::from(2))
        }

        Role::Agent => {
            eprintln!(
                "--role agent (fleet agent, NGINX Instance Manager/One parity) is Phase 5 of the roadmap.\n\
                 See docs/parity-matrix.md."
            );
            Ok(ExitCode::from(2))
        }

        Role::Control => {
            eprintln!(
                "--role control (control plane) is Phase 5/6 of the roadmap.\n\
                 Single-node deployments need no control plane: use `--role all`.\n\
                 See docs/parity-matrix.md."
            );
            Ok(ExitCode::from(2))
        }
    }
}

fn validate(config_path: &str) -> anyhow::Result<ExitCode> {
    // ConfigManager understands both the legacy flat format and
    // intellaro.io/v1 (including compile-time validation).
    match ConfigManager::load(config_path) {
        Ok(_) => {
            let content = std::fs::read_to_string(config_path)?;
            if intellaro_config::is_v1_config(&content) {
                let set = intellaro_config::load_str(&content)
                    .map_err(|err| anyhow::anyhow!("{err}"))?;
                println!(
                    "Configuration is valid (intellaro.io/v1): {} gateway(s), {} upstream(s), {} wafPolicy(ies).",
                    set.gateways.len(),
                    set.upstreams.len(),
                    set.waf_policies.len()
                );
            } else {
                println!("Configuration is valid (legacy flat format).");
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(err) => {
            eprintln!("Configuration is invalid:\n{err}");
            Ok(ExitCode::FAILURE)
        }
    }
}

fn schema(out_dir: &PathBuf, stdout: bool) -> anyhow::Result<ExitCode> {
    if stdout {
        let map: serde_json::Map<String, serde_json::Value> = intellaro_config::schema::all_schemas()
            .into_iter()
            .map(|(name, schema)| (name.to_string(), serde_json::to_value(schema).unwrap()))
            .collect();
        println!("{}", serde_json::to_string_pretty(&map)?);
        return Ok(ExitCode::SUCCESS);
    }

    let written = intellaro_config::schema::write_schemas(out_dir)?;
    for path in &written {
        println!("wrote {}", path.display());
    }
    Ok(ExitCode::SUCCESS)
}
