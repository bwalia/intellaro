# Intellaro

A Rust-native **application delivery platform**: reverse proxy, load
balancer, cache, security engine, and Kubernetes ingress — one data plane,
one binary, typed configuration.

Intellaro is the successor to the WSLProxy (OpenResty/Lua) stack and is
absorbing the capability surface of NGINX Plus + F5 WAF + Instance
Manager/One Console + Ingress Controller/Gateway Fabric. Progress is tracked
honestly in [docs/parity-matrix.md](docs/parity-matrix.md).

## One binary, many roles

```bash
intellaro --role proxy   --config examples/gateway-v1.yaml   # edge data plane
intellaro --role all     --config config.yaml                # data plane + management API (POP mode)
intellaro --role ingress                                     # Kubernetes ingress controller
intellaro --role gateway                                     # Gateway API (Phase 4 — exits with roadmap pointer)
intellaro validate --config examples/gateway-v1.yaml         # validate config, exit
intellaro schema   --out-dir docs/schemas                    # regenerate JSON Schemas
intellaro crds                                               # print Kubernetes CRD manifests
```

## Typed configuration (`intellaro.io/v1`)

Configuration is data — YAML/JSON documents validated against
[JSON Schemas](docs/schemas/) generated from the parser itself:

```yaml
apiVersion: intellaro.io/v1
kind: Gateway
metadata: { name: pop1-edge }
spec:
  listeners:
    - { name: http, port: 8080, protocol: HTTP }
  hosts:
    - name: api.example.com
      routes:
        - match: { path: { type: Prefix, value: /api } }
          upstreamRef: api-pool
          timeouts: { connect: 5s, read: 30s }
          policies: [{ ref: waf-strict }]
```

Full example: [examples/gateway-v1.yaml](examples/gateway-v1.yaml). The
legacy flat `ServerConfig` format is still accepted everywhere.

Edit the file while the server runs: routes, backends, and policies
hot-reload atomically (last-good config is kept on parse errors). Ops
endpoints live on `:9090` — `/metrics`, `/health`, `/ready`.

## Workspace

| Crate | Description |
|-------|-------------|
| `intellaro-cli` | The unified `intellaro` binary (roles, validate, schema, crds) |
| `intellaro-config` | `intellaro.io/v1` typed model, validation, JSON Schema generation |
| `intellaro-http-server` | Data-plane library + legacy standalone binary |
| `intellaro-http-router` | Match engine, balancer strategies, canary, priority tiers |
| `intellaro-ingress` | Kubernetes controller (CRDs → data plane via MCP API) |
| `intellaro-http-cli` | Operator CLI for the management API |

## Build & test

```bash
cargo build --release            # everything; binary at target/release/intellaro
cargo test                       # unit + end-to-end tests (proxy, hot reload, ops)
```

Requires Rust 1.75+. TLS is rustls — no OpenSSL needed on the request path.

## Documentation

* [docs/architecture.md](docs/architecture.md) — roles, request pipeline,
  config compile pipeline, hot-reload semantics, fail-open/fail-closed map,
  roadmap.
* [docs/parity-matrix.md](docs/parity-matrix.md) — WSLProxy × status and
  NGINX Plus/F5 × status ledgers, plus known Phase-0 limitations.
* [docs/schemas/](docs/schemas/) — JSON Schemas for `Gateway`, `Route`,
  `Upstream`, `WafPolicy`.

## License

Proprietary. All rights reserved.
