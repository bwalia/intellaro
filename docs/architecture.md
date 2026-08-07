# Intellaro Architecture

Intellaro is a Rust-native **application delivery platform**: one data-plane
binary that replaces the WSLProxy (OpenResty/Lua) stack and absorbs, module by
module, the capability surface of NGINX Plus, F5 WAF for NGINX, NGINX Instance
Manager, NGINX Ingress Controller, NGINX Gateway Fabric, and NGINX One Console.

Status: **Phase 0 complete** (workspace, typed config, working proxy data
plane, ops endpoints, hot reload, unified binary). See
[parity-matrix.md](parity-matrix.md) for the feature-by-feature ledger.

## Design principles

1. **Single binary, many roles.** `intellaro --role proxy|ingress|gateway|agent|control|all`.
   Kubernetes is a *config source*, not a different product: the ingress and
   gateway roles reuse the same request pipeline as a bare-metal POP proxy.
2. **Configuration is data.** Typed YAML/JSON (`intellaro.io/v1`) validated
   against JSON Schemas that are *generated from the parser structs* — the
   schema can never drift from behavior. No Lua, no base64 nginx snippets.
3. **Hot path stays in-process.** Routing, LB, caching, security checks, and
   (Phase 3) WAF evaluation run inside the data-plane process. Anything that
   tolerates 50–500 ms latency (fleet control, AI analysis, UI) may become a
   microservice later; nothing on the request path ever does.
4. **Fail-open vs fail-closed is explicit.** Routing/health fail open
   (documented below); authn and block-mode security fail closed.
5. **Hot reload, not restarts.** Routes, backends, and policies swap live.
   Only bind addresses / listener sockets require a restart.

## Roles

| Role | Status | What it runs |
|------|--------|--------------|
| `proxy` | ✅ working | Data plane: listeners, router, LB, cache, security, ops endpoints |
| `all` | ✅ working | `proxy` + management API (MCP) — the single-node / POP mode; no control plane required |
| `ingress` | ✅ working | Kubernetes controller watching Intellaro CRDs, reconciling into the data plane via the MCP API |
| `gateway` | 🚧 Phase 4 | Gateway API (GatewayClass/HTTPRoute/…) on the same data plane |
| `agent` | 🚧 Phase 5 | Fleet agent (Instance Manager / One Console parity) |
| `control` | 🚧 Phase 5/6 | Config distribution, versioning, CR approval |

Unimplemented roles exit with code 2 and a roadmap pointer — they never
pretend to work.

## Workspace layout

```
intellaro/                      Cargo workspace
├── intellaro-cli/              the unified `intellaro` binary (roles, validate, schema, crds)
├── intellaro-config/           intellaro.io/v1 typed model + validation + JSON Schema generation
├── intellaro-http-server/      data plane library + legacy standalone binary
│   ├── bootstrap.rs            shared startup (config, ops, MCP, listeners)
│   ├── server.rs               accept loop, request pipeline, live state swap
│   ├── proxy.rs                forwarding, LB strategies, active + passive health, fail-open
│   ├── config.rs               runtime config + ConfigManager (file watch, reload)
│   ├── config_v1.rs            intellaro.io/v1 → runtime config compiler
│   ├── cache.rs                in-memory cache (TTL, SWR, stale-if-error, purge)
│   ├── security.rs             IP ACLs, rate limiting, JWT
│   ├── mcp.rs                  management REST API (config CRUD, reload, cache purge)
│   └── …                       circuit_breaker, oidc, rbac, audit, tenant, cluster, transform
├── intellaro-http-router/      match engine, balancer strategies, canary, priority tiers
├── intellaro-ingress/          Kubernetes controller library + standalone binary (CRDs: VHost,
│                               Route, LBPolicy, SecurityPolicy, CachePolicy, ServiceDiscovery)
└── intellaro-http-cli/         operator CLI for the management API
```

Mapping to the target crate map from the build prompt: `adp-core`/`adp-http`
≈ `intellaro-http-server` (server/proxy), `adp-router`/`adp-lb` ≈
`intellaro-http-router`, `adp-config` ≈ `intellaro-config`, `adp-k8s` ≈
`intellaro-ingress`, `adp-cli` ≈ `intellaro-cli`. Later phases split
`adp-waf`, `adp-tls` (ACME), `adp-stream` (L4), `adp-agent`, and `adp-mcp`
out of the server crate as they grow.

## Configuration model

Two formats are accepted by every entry point; detection is automatic:

* **`intellaro.io/v1`** (preferred): multi-document YAML/JSON of `Gateway`,
  `Upstream`, and `WafPolicy` objects. See
  [`examples/gateway-v1.yaml`](../examples/gateway-v1.yaml) and the JSON
  Schemas in [`docs/schemas/`](schemas/) (regenerate with
  `intellaro schema --out-dir docs/schemas`).
* **Legacy flat format**: the original `ServerConfig` YAML/JSON, kept for
  existing deployments and the management API.

### Compile pipeline

```
YAML/JSON file ──▶ intellaro-config: parse (kind-dispatched, deny_unknown_fields)
                              │  validate (names, refs, ports, CIDRs, phase limits)
                              ▼
              intellaro-http-server::config_v1: compile
                              │  Gateway listeners → ListenerConfig
                              │  Upstreams + inline backends → UpstreamConfig
                              │  Host/route matches → router rules
                              │     priority = Exact > longer Prefix > Regex
                              │  WafPolicy → SecurityConfig (global until Phase 3)
                              ▼
                       runtime ServerConfig
```

Everything the data plane cannot enforce yet (ACME, tcp probes, WAF signature
packs, per-route policy binding, monitor mode) is either **rejected at
validation** or surfaced as an explicit **compile warning** — never silently
dropped.

### Hot reload

`ConfigManager` watches the config file (also reloadable via
`POST /api/v1/config/reload` on the management API). On change:

1. The file is re-parsed and (for v1) re-validated + re-compiled. A bad file
   keeps the last-good config running.
2. A fresh `AppState` (proxy engine, router, cache, security, circuit
   breakers) is built and published over a `tokio::sync::watch` channel.
3. Every request resolves the current state at dispatch time, so keep-alive
   connections pick up the new config on their next request. In-flight
   requests finish on the state they started with.
4. Health-check loops belonging to the replaced engine are cancelled
   (`Drop` on the proxy engine).

Listener sockets are fixed for the process lifetime; changing bind addresses
requires a restart. Rebuilding on reload currently resets passive-health
state (Phase 1 carries it over by backend key).

## Request pipeline

```
client ──▶ listener (HTTP/1.1, h2c; TLS terminate when configured)
             │ buffer request body (bounded, 16 MiB) for replay across retries
             ▼
        1. security engine        IP allow/deny → rate limit → JWT      [fail-closed]
        2. cache lookup           GET/HEAD short-circuit (TTL, SWR)
        3. static files           configured roots, traversal-safe
        4. routing engine         host/path/method/header match → backend group
             │                     canary, sticky, priority tiers
             ▼
        5. proxy                  strip hop-by-hop headers
                                   + X-Forwarded-For / X-Forwarded-Host / X-Origin-IP
                                   circuit breaker → retry w/ backoff → LB pick
             ▼
        upstream backend  ──▶ response (hop-by-hop stripped) ──▶ cache store ──▶ client
```

The Phase-0 data plane is **store-and-forward** (bodies buffered both ways,
via a pooled HTTP client). The streaming hyper-conn rewrite — required for
WebSocket/gRPC pass-through, SSE, and the <1 ms P50 overhead target — is the
first Phase 1 milestone.

## Health & resilience

* **Active health checks** — per-upstream HTTP probes (interval, threshold),
  started with the engine, cancelled on reload.
* **Passive ejection** — 3 consecutive transport errors / 5xx take a backend
  out of rotation for 10 s (thresholds become config in Phase 1).
* **Fail-open** — if *every* backend is unhealthy, selection proceeds over
  the full set instead of refusing traffic (WSLProxy parity), with a metric
  (`proxy_fail_open_total`) and warning log.
* **Circuit breaker** — per-upstream failure threshold, open/half-open state.
* **Retries** — per-upstream max retries, retryable status codes,
  exponential/linear/constant backoff. Bodies are buffered, so replays are safe.

## Fail-open vs fail-closed

| Path | Mode |
|------|------|
| Backend health (all down) | fail-open (configurable in Phase 1) |
| Routing engine error | fail-open to default proxy for `NoMatchingRule`; 502/503 otherwise |
| Config reload failure | fail-open: last-good config keeps serving |
| IP ACL / rate limit / JWT | fail-closed |
| WAF block mode (Phase 3) | fail-closed |

## Observability

* **Ops server** (default `0.0.0.0:9090`, configurable via
  `logging.ops_address`): `/metrics` (Prometheus), `/health` (liveness),
  `/ready` (readiness — 503 until listeners are bound).
* Structured JSON logs (`tracing`), request/response/latency metrics,
  cache hit/miss, per-upstream proxy counters, passive-ejection and
  fail-open counters.
* Management API (`--role all` / legacy config `management_api`): config
  CRUD + reload, status, system info, upstream health, cache purge, OpenAPI.

## Security posture

* Memory-safe Rust throughout; rustls for TLS (no OpenSSL on the request path).
* Request bodies bounded (413 above 16 MiB) before any buffering.
* Hop-by-hop headers stripped in both directions (RFC 9110 §7.6.1).
* Mock auth from the prototypes is **not** ported; the management API uses
  API key + RBAC, and platform RBAC/OIDC hardening is tracked for Phase 2.

## Roadmap (build-prompt phases)

| Phase | Scope | Status |
|-------|-------|--------|
| 0 | Workspace, typed config + schemas, proxy + RR/health, ops endpoints, hot reload | ✅ done |
| 1 | WSLProxy parity: streaming data plane, response-code rules, ACME, CAPTCHA, geo, traffic-split APIs, importer | next |
| 2 | Plus parity: TCP/UDP streams, least-time, sticky, KV store, HTTP/3, dynamic upstream API | |
| 3 | WAF/DoS: policy IR, signature packs, bot, OpenAPI validation, per-route binding | |
| 4 | Kubernetes: Gateway API controller in the same binary, conformance | |
| 5 | Fleet: agent protocol, self-hosted console, cert inventory, drift | |
| 6 | Microservice split (control/insights/policy) while `--role all` stays monolithic | |
