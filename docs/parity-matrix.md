# Intellaro Parity Matrix

Feature-by-feature ledger against the two reference surfaces from the build
prompt: **WSLProxy** (the OpenResty/Lua platform being replaced) and the
**NGINX Plus / F5 product family** being absorbed.

Legend: ✅ implemented and tested · 🟡 partial (noted) · 📋 schema/config
accepted, enforcement pending (never silently dropped — compile warns) ·
❌ not started (phase noted).

## WSLProxy parity

### Dynamic request pipeline

| Feature | Status | Notes |
|---|---|---|
| Host → server config load | ✅ | v1 `Gateway.hosts` → router rules; wildcard + catch-all hosts |
| Rule match: path (`starts_with`/`equals`/regex) | ✅ | `Prefix` / `Exact` / `Regex` path matches |
| Deterministic selection (priority > specificity) | ✅ | Exact > longer Prefix > Regex; explicit `priority` override |
| Rule match: method / header conditions | ✅ | `match.methods`, `match.headers` |
| Rule match: IP/CIDR, country/GeoIP | 🟡 | IP allow/deny via WafPolicy (global); per-rule IP + GeoIP ❌ Phase 1 |
| Rule match: JWT (cookie/header), cookie KV | 🟡 | JWT bearer validation global; per-rule conditions ❌ Phase 1 |
| Response actions 200/403 static, 301/302, 305 proxy | 🟡 | Proxy (305-equivalent) ✅; static/redirect actions ❌ Phase 1 |
| 306 CAPTCHA challenge (+`/__captcha/verify`) | ❌ | Phase 1 |
| Per-server proxy timeouts (connect/send/read) | 🟡 | Schema ✅; `read` enforced per route; connect/send are client-level (5 s/30 s) until the streaming rewrite |
| Custom request/response headers | 🟡 | Router supports `HeaderManipulation`; not yet exposed in v1 schema |
| Strip path / auto-HTTPS redirect | ❌ | Phase 1 |
| Consul SRV + resolver fallback | ❌ | Phase 1 (DNS names in backend addresses resolve via system resolver) |
| TCP stream proxy (k3s-style L4) | ❌ | Phase 2 (`adp-stream`) |
| Unix socket backends, S3 SigV4 signing, LLM translate, MCP gateway | ❌ | Phase 1–3 (inventory §2.10) |
| Fallback branded pages (`no_server`, `no_rule`) | ❌ | Phase 1 |

### Traffic routing

| Feature | Status | Notes |
|---|---|---|
| Round-robin / weighted / least-conn | ✅ | Unit-tested; weighted is cumulative-weight RR |
| Random / consistent-hash | 🟡 | Routing-engine strategies exist; default proxy falls back to RR |
| Header-based canary, cookie sticky | 🟡 | Canary + sticky implemented in `intellaro-http-router`; not yet in v1 schema |
| Passive health (N consecutive 5xx → unhealthy TTL) | ✅ | 3 fails → 10 s ejection; thresholds configurable in Phase 1 |
| Active health checks (HTTP) | ✅ | Per-upstream probes; started/cancelled with engine lifecycle |
| Active health checks (TCP/gRPC) | ❌ | Phase 2 (validation rejects `type: tcp` today) |
| Fail-open when all backends unhealthy | ✅ | Metric + warning; policy knob in Phase 1 |
| Live weight update / promote / rollback APIs | 🟡 | Config PUT + reload swaps weights live; dedicated traffic-split API ❌ Phase 1 |

### TLS / ACME

| Feature | Status | Notes |
|---|---|---|
| TLS terminate (per-listener certs, min version) | ✅ | rustls; static PEM cert/key |
| ACME HTTP-01/DNS-01, staging/prod | 📋 | `tls.acme` in schema; validation requires static certs until Phase 1 |
| Per-domain allow-list, force HTTPS, HSTS, dual RSA/ECC, mTLS | ❌ | Phase 1–2 |

### Cache

| Feature | Status | Notes |
|---|---|---|
| In-memory cache: TTL, stale-while-revalidate, stale-if-error | ✅ | `cache.rs`; purge-all + per-key via management API |
| Bypass cookie/auth, extension/MIME rules | ❌ | Phase 1 |
| Docker registry blob/manifest cache, Varnish path | ❌ | Phase 2 (native cache preferred) |

### WAF / security

| Feature | Status | Notes |
|---|---|---|
| IP ACL allow/deny (CIDR) | ✅ | Global via `WafPolicy` → security engine |
| Rate limiting (RPS + window) | ✅ | Per-client-IP fixed window; shared/distributed state Phase 2 |
| JWT validation (HMAC/public key, iss/aud) | ✅ | Bearer header |
| WAF rules: targets, regex/string patterns, packs (`sqli`,`xss`,…) | 📋 | Full schema + validation; in-process engine is Phase 3 |
| Block vs monitor modes | 📋 | Schema ✅; monitor mode needs the Phase 3 engine (compile warns) |
| Per-route policy binding | 📋 | Schema ✅ (`route.policies`); first policy applies globally until Phase 3 |
| CAPTCHA (Turnstile/reCAPTCHA), geo block, anomaly scoring | ❌ | Phase 1/3 |
| Audit trail (NDJSON) | 🟡 | `audit.rs` exists; wiring across mutating APIs in Phase 1 |

### Admin / control plane

| Feature | Status | Notes |
|---|---|---|
| Config CRUD + reload API | ✅ | `GET/PUT /api/v1/config` (PUT hot-swaps state; idempotent on identical pushes), `POST /api/v1/config/reload` — k3s-verified |
| Live hot reload on file change | ✅ | Watcher → validate → atomic state swap; last-good on error |
| Status/system/services endpoints, OpenAPI | ✅ | `mcp.rs` |
| Operator CLI | ✅ | `intellaro-http-cli` (vhosts, routes, security, cache, cluster) |
| Versioned configs, change requests (4-eyes), profiles (`dev…prod`) | 🟡 | `config_versioning.rs` scaffold; CR workflow ❌ Phase 1 |
| Users/RBAC (real, not mock) | 🟡 | API-key + RBAC on management API; full user store Phase 2 |
| WSLProxy `/opt/nginx/data` importer | ❌ | Phase 1 (`adp-migrate`) |
| POP registry / DNS CDN (Cloudflare), instance push/pull | ❌ | Phase 5 |

### Observability

| Feature | Status | Notes |
|---|---|---|
| Prometheus metrics | ✅ | Unified ops server; metrics crate versions aligned so router metrics register too |
| `/health` + `/ready` | ✅ | Readiness gated on listener bind |
| Access/error log APIs, topology graph, AI analysis | ❌ | Phase 1/5 (`adp-insights`) |

## NGINX Plus / F5 parity

### NGINX Plus data plane

| Capability | Status | Notes |
|---|---|---|
| HTTP/1.1 + HTTP/2 terminate & proxy | ✅ | hyper auto-detect (h2c); TLS-ALPN h2 with TLS listeners |
| HTTP/3 (QUIC) | ❌ | Phase 2 (quinn/h3) |
| WebSocket / gRPC proxy / CONNECT | ❌ | Needs streaming data plane — Phase 1/2 |
| TCP/UDP/TLS stream LB | ❌ | Phase 2 |
| RR / least-conn / weighted / hash / random LB | 🟡 | RR, least-conn, weighted ✅; random + consistent-hash in router engine; least-time ❌ Phase 2 |
| Session persistence (sticky cookie/learn/route) | 🟡 | Sticky cookie in router engine; not in v1 schema yet |
| Active + passive health checks | ✅ | HTTP active, passive ejection, fail-open |
| Slow-start, max_conns, queueing, backup, drain | ❌ | Phase 2 |
| Dynamic upstream membership API (no reload) | 🟡 | Config PUT swaps upstreams live; imperative per-member API ❌ Phase 2 |
| Content cache + purge API, SWR/stale-if-error, cache lock | 🟡 | All but cache lock ✅ |
| Bandwidth/connection/request limits | 🟡 | Request rate limit ✅; bandwidth/conn ❌ Phase 2 |
| Key-value store API | ❌ | Phase 2 |
| JWT authn ✅ · OIDC SSO 🟡 (`oidc.rs` scaffold) · mTLS ❌ | mixed | Phase 2 |
| Live activity dashboard API | 🟡 | Status endpoint + dashboard HTML; Plus-grade per-zone stats Phase 2 |
| SSL offload ✅ · dual certs ❌ · PROXY protocol ❌ | mixed | Phase 1–2 |

### F5 WAF / DoS

| Capability | Status | Notes |
|---|---|---|
| Policy as YAML/JSON/CRD | ✅ | `WafPolicy` (+ `IntellaroSecurityPolicy` CRD) |
| Signature + behavioral WAF, bot, OpenAPI validation | ❌ | Phase 3, in-process engine |
| Block/monitor/transparent modes, FP workflow | 📋 | Schema now, engine Phase 3 |
| L7 DoS (adaptive rate, challenge) | ❌ | Phase 3 |

### Instance Manager / One Console (fleet)

| Capability | Status | Notes |
|---|---|---|
| Instance discovery/registration, config push, cert inventory, drift/CVE | ❌ | Phase 5 (`--role agent` / `--role control` reserved and stubbed) |
| Self-hosted operation (air-gapped) | ✅ by design | `--role all` runs with zero external services |

### Ingress Controller / Gateway Fabric

| Capability | Status | Notes |
|---|---|---|
| Kubernetes controller, CRDs, reconcile into data plane | ✅ | `--role ingress` — verified end-to-end in k3s: CRs → router rules + service-DNS upstreams via MCP push, weighted traffic splits, status writeback (`SYNCED`), transition-only status patches |
| Native `Ingress` resource + IngressClass | 🟡 | CRD-first today; core `Ingress` watch Phase 4 |
| Same binary as the POP proxy | ✅ | `intellaro --role ingress` |
| Gateway API (GatewayClass/HTTPRoute/…), conformance | ❌ | Phase 4 (`--role gateway` reserved) |
| Leader election | ❌ | Phase 4 |

## Known Phase-0 limitations (deliberate, documented)

1. **Store-and-forward data plane** — request bodies buffered (16 MiB cap),
   responses buffered; no WebSocket/SSE/gRPC streaming. First Phase 1 item.
2. **Host header** — upstream sees the backend host; the original host
   arrives as `X-Forwarded-Host` until the streaming rewrite.
3. **Global security policy** — the first referenced `WafPolicy` applies
   process-wide; per-route binding lands with the Phase 3 WAF engine.
4. **Listener changes need a restart**; everything else hot-reloads.
5. **Reload resets passive-health state** (fresh engine per reload).
