# Intellaro

A modular **web traffic management ecosystem** built for performance, security, and extensibility.

## Architecture

Intellaro is composed of independent, cooperating modules:

| Module                     | Description                              | Status       |
|----------------------------|------------------------------------------|--------------|
| `intellaro-http-server`    | Core HTTP(S) server & reverse proxy      | In Progress  |
| `intellaro-http-cli`       | CLI tool for remote server management    | In Progress  |
| `intellaro-ingress`        | Kubernetes-native ingress controller     | In Progress  |
| `intellaro-ai-router`      | AI-based intelligent traffic routing     | Planned      |
| `intellaro-monitoring`     | Observability, metrics & alerting        | Planned      |
| `intellaro-cache-manager`  | Distributed cache orchestration          | Planned      |

## Getting Started

### Prerequisites

- Rust 1.75+ (stable)
- OpenSSL development headers (for TLS support)

### Build

```bash
cd intellaro-http-server
cargo build --release
```

### Run

```bash
cd intellaro-http-server
cargo run -- --config config.yaml
```

## Project Structure

```
intellaro/
├── intellaro-http-server/         # Core Rust-based HTTP(S) server
│   ├── Cargo.toml
│   ├── Dockerfile
│   ├── src/
│   │   ├── main.rs                # Entry point
│   │   ├── server.rs              # HTTP server setup, worker engine
│   │   ├── proxy.rs               # Reverse proxy & load balancer
│   │   ├── cache.rs               # Caching layer
│   │   ├── security.rs            # Security policy engine
│   │   ├── mcp.rs                 # MCP server & API management
│   │   ├── logging.rs             # Logging & metrics
│   │   ├── config.rs              # Dynamic JSON/YAML configuration
│   │   └── cluster.rs             # Clustering & HA
│   └── examples/
│       └── kubernetes.yaml        # Example Kubernetes deployment
├── intellaro-http-cli/            # CLI management tool
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                # CLI entry point
│       ├── client.rs              # MCP API client
│       ├── config.rs              # Multi-profile configuration
│       ├── output.rs              # Table/JSON/YAML output rendering
│       ├── interactive.rs         # Interactive REPL mode
│       └── commands/              # Subcommand modules
├── intellaro-ingress/             # Kubernetes-native ingress controller
│   ├── Cargo.toml
│   ├── Dockerfile
│   ├── src/
│   │   ├── main.rs                # Controller entry point
│   │   ├── controller.rs          # CRD watchers & reconciliation
│   │   ├── reconciler.rs          # CRD → server config translation
│   │   ├── mcp.rs                 # MCP API client
│   │   ├── metrics.rs             # Prometheus metrics
│   │   ├── health.rs              # Liveness & readiness probes
│   │   └── crd/                   # Custom Resource Definitions
│   │       ├── vhost.rs           # IntellaroVHost
│   │       ├── route.rs           # IntellaroRoute
│   │       ├── lb_policy.rs       # IntellaroLBPolicy
│   │       ├── security.rs        # IntellaroSecurityPolicy
│   │       └── cache.rs           # IntellaroCachePolicy
│   └── manifests/
│       ├── crds/                  # CRD YAML definitions
│       ├── deployment.yaml        # K8s Deployment, RBAC, Service
│       └── examples/              # Sample CRD configurations
├── docker-compose.yml             # Local test environment
├── docker/                        # Docker support files
├── intellaro-ai-router/           # Future AI-based routing module
├── intellaro-monitoring/          # Future observability & metrics module
├── intellaro-cache-manager/       # Future cache management module
└── README.md
```

## License

Proprietary. All rights reserved.
