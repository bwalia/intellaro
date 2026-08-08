//! The `intellaro.io/v1` typed configuration model.
//!
//! Three top-level kinds exist today:
//!
//! * [`Gateway`] — listeners + virtual hosts + routes (the edge intent)
//! * [`Upstream`] — a named backend pool with LB / health / resilience policy
//! * [`WafPolicy`] — security policy (IP ACLs, rate limits, WAF rules)
//!
//! Every struct derives `JsonSchema`, so the published JSON Schemas are
//! generated from — and can never drift from — the actual parser.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::duration::HumanDuration;

// ─────────────────────────────────────────────────────────────────────
// Shared
// ─────────────────────────────────────────────────────────────────────

/// Object metadata shared by every kind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    /// Unique name for this object (per kind).
    pub name: String,

    /// Free-form labels (environment, POP, team, …).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

/// A single backend endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Backend {
    /// Backend address, `host:port` (e.g. `10.8.0.9:6443`, `app.internal:8080`).
    pub address: String,

    /// Relative weight for weighted balancing. Defaults to 1.
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    1
}

/// Load-balancing strategy for a backend pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancing {
    #[default]
    RoundRobin,
    #[serde(alias = "least_connections")]
    LeastConn,
    Weighted,
    Random,
    ConsistentHash,
}

impl LoadBalancing {
    /// The strategy name understood by the data plane.
    pub fn as_dataplane_str(&self) -> &'static str {
        match self {
            LoadBalancing::RoundRobin => "round_robin",
            LoadBalancing::LeastConn => "least_connections",
            LoadBalancing::Weighted => "weighted",
            LoadBalancing::Random => "random",
            LoadBalancing::ConsistentHash => "consistent_hash",
        }
    }
}

/// Active health-check probe definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveHealthCheck {
    /// Probe type. `http` is fully supported today; `tcp` is reserved for
    /// the L4 stream engine (Phase 2) and is rejected at compile time.
    #[serde(rename = "type", default)]
    pub probe_type: ProbeType,

    /// HTTP path to probe (ignored for `tcp`).
    #[serde(default = "default_health_path")]
    pub path: String,

    /// Interval between probes.
    #[serde(default = "default_health_interval")]
    pub interval: HumanDuration,

    /// Per-probe timeout.
    #[serde(default = "default_health_timeout")]
    pub timeout: HumanDuration,

    /// Consecutive failures before a backend is marked unhealthy.
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,

    /// Consecutive successes before an unhealthy backend recovers.
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProbeType {
    #[default]
    Http,
    Tcp,
}

fn default_health_path() -> String {
    "/healthz".to_string()
}
fn default_health_interval() -> HumanDuration {
    HumanDuration::from_secs(10)
}
fn default_health_timeout() -> HumanDuration {
    HumanDuration::from_secs(5)
}
fn default_unhealthy_threshold() -> u32 {
    3
}
fn default_healthy_threshold() -> u32 {
    2
}

// ─────────────────────────────────────────────────────────────────────
// Gateway
// ─────────────────────────────────────────────────────────────────────

/// A `Gateway` binds listeners to virtual hosts and routes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Gateway {
    /// Must be `intellaro.io/v1`.
    pub api_version: String,

    /// Must be `Gateway`.
    pub kind: String,

    pub metadata: Metadata,
    pub spec: GatewaySpec,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewaySpec {
    /// Sockets this gateway accepts traffic on.
    pub listeners: Vec<Listener>,

    /// Virtual hosts served by this gateway.
    pub hosts: Vec<Host>,

    /// Page served when no route matches (WSLProxy `no_server` parity).
    /// Omitted = requests fall through to the default proxy behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<FallbackPage>,
}

/// Branded fallback page for unmatched requests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FallbackPage {
    #[serde(default = "default_fallback_status")]
    pub status: u16,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,

    #[serde(default = "default_fallback_content_type")]
    pub content_type: String,
}

fn default_fallback_status() -> u16 {
    404
}
fn default_fallback_content_type() -> String {
    "text/html; charset=utf-8".to_string()
}

/// A listening socket.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Listener {
    /// Listener name, unique within the gateway.
    pub name: String,

    /// Bind address. Defaults to `0.0.0.0`.
    #[serde(default = "default_bind_address")]
    pub address: String,

    /// Port to listen on.
    pub port: u16,

    /// `HTTP` or `HTTPS`.
    #[serde(default)]
    pub protocol: ListenerProtocol,

    /// TLS settings; required when `protocol: HTTPS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsSettings>,
}

fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum ListenerProtocol {
    #[default]
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TlsSettings {
    /// TLS mode. Only `Terminate` is supported today.
    #[serde(default)]
    pub mode: TlsMode,

    /// Path to the PEM certificate chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_path: Option<String>,

    /// Path to the PEM private key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,

    /// Minimum TLS version: `"1.2"` (default) or `"1.3"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_version: Option<String>,

    /// ACME (Let's Encrypt) automation. Schema-reserved: automation lands
    /// in Phase 1; until then certPath/keyPath must be provided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme: Option<AcmeSettings>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub enum TlsMode {
    #[default]
    Terminate,
    Passthrough,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcmeSettings {
    #[serde(default)]
    pub enabled: bool,

    /// Contact e-mail for the ACME account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Use the staging directory (recommended while testing).
    #[serde(default)]
    pub staging: bool,
}

/// A virtual host: a hostname plus its ordered routes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Host {
    /// Hostname to match. Supports a leading wildcard (`*.example.com`)
    /// and the catch-all `"*"`.
    pub name: String,

    /// Routes evaluated for requests to this host.
    pub routes: Vec<Route>,
}

/// A single route: match conditions plus a destination and its policies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Route {
    /// Match conditions. Defaults to `path: {type: Prefix, value: /}`.
    #[serde(rename = "match", default)]
    pub route_match: RouteMatch,

    /// Inline backend pool. Mutually exclusive with `upstreamRef`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backends: Vec<Backend>,

    /// Reference to a named `Upstream`. Mutually exclusive with `backends`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_ref: Option<String>,

    /// Load-balancing strategy for inline `backends`.
    #[serde(default)]
    pub load_balancing: LoadBalancing,

    /// Proxy timeouts for this route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeouts: Option<Timeouts>,

    /// Health checking for inline `backends`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<RouteHealthCheck>,

    /// Policies attached to this route (by name), e.g. a `WafPolicy`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<PolicyRef>,

    /// Explicit priority override. Higher wins. When omitted, priority is
    /// derived from path specificity (Exact > longer Prefix > Regex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,

    /// Direct response action (static page or redirect) instead of
    /// proxying. WSLProxy response-code parity: 200/403 static,
    /// 301/302 redirect; omitted = proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<RouteAction>,

    /// Path rewrite applied before forwarding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite: Option<RouteRewrite>,

    /// Headers to set/remove on the proxied request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_headers: Option<HeaderOps>,

    /// Headers to set/remove on the response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<HeaderOps>,
}

/// Direct response action for a route.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", rename_all_fields = "camelCase")]
pub enum RouteAction {
    /// Serve a static response (block/landing pages).
    Static {
        #[serde(default = "default_action_status")]
        status: u16,
        /// Plain text/HTML body.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        body: Option<String>,
        /// Base64-encoded body (WSLProxy stored pages this way).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        body_base64: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content_type: Option<String>,
    },
    /// Redirect to a location (301/302/303/307/308).
    Redirect {
        location: String,
        #[serde(default = "default_redirect_status")]
        status: u16,
    },
}

fn default_action_status() -> u16 {
    200
}
fn default_redirect_status() -> u16 {
    302
}

/// Path rewrite: strip a prefix and optionally replace it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteRewrite {
    /// Prefix to strip from the request path (usually the matched prefix).
    pub strip_prefix: String,

    /// Replacement for the stripped prefix (defaults to empty).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace_with: Option<String>,
}

/// Header set/remove operations.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HeaderOps {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub set: BTreeMap<String, String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteMatch {
    /// Path condition.
    #[serde(default)]
    pub path: PathMatch,

    /// HTTP methods to match (empty = all).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,

    /// Header equality conditions (all must match).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,

    /// Client source IPs/CIDRs to match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_cidrs: Vec<String>,
}

impl Default for RouteMatch {
    fn default() -> Self {
        Self {
            path: PathMatch::default(),
            methods: Vec::new(),
            headers: BTreeMap::new(),
            source_cidrs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PathMatch {
    #[serde(rename = "type", default)]
    pub match_type: PathMatchType,

    /// The path value, must start with `/` (a regex for `Regex` matches).
    pub value: String,
}

impl Default for PathMatch {
    fn default() -> Self {
        Self {
            match_type: PathMatchType::Prefix,
            value: "/".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub enum PathMatchType {
    #[default]
    Prefix,
    Exact,
    Regex,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Timeouts {
    /// Connection establishment timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect: Option<HumanDuration>,

    /// Time allowed for the upstream response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<HumanDuration>,

    /// Time allowed to send the request upstream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send: Option<HumanDuration>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteHealthCheck {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<ActiveHealthCheck>,
}

/// A named reference to a policy object (e.g. a `WafPolicy`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyRef {
    /// Name of the referenced policy.
    #[serde(rename = "ref")]
    pub policy_ref: String,
}

// ─────────────────────────────────────────────────────────────────────
// Upstream
// ─────────────────────────────────────────────────────────────────────

/// A named backend pool that routes can reference via `upstreamRef`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Upstream {
    /// Must be `intellaro.io/v1`.
    pub api_version: String,

    /// Must be `Upstream`.
    pub kind: String,

    pub metadata: Metadata,
    pub spec: UpstreamSpec,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpstreamSpec {
    /// Backend endpoints in this pool.
    pub backends: Vec<Backend>,

    #[serde(default)]
    pub load_balancing: LoadBalancing,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<ActiveHealthCheck>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_breaker: Option<CircuitBreaker>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<Retry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircuitBreaker {
    /// Consecutive failures that trip the circuit.
    #[serde(default = "default_cb_failure_threshold")]
    pub failure_threshold: u64,

    /// How long the circuit stays open before probing half-open.
    #[serde(default = "default_cb_open_duration")]
    pub open_duration: HumanDuration,

    /// Requests allowed through while half-open.
    #[serde(default = "default_cb_half_open_max")]
    pub half_open_max_requests: u64,
}

fn default_cb_failure_threshold() -> u64 {
    5
}
fn default_cb_open_duration() -> HumanDuration {
    HumanDuration::from_secs(30)
}
fn default_cb_half_open_max() -> u64 {
    3
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Retry {
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Upstream status codes that trigger a retry.
    #[serde(default = "default_retry_on_status")]
    pub retry_on_status: Vec<u16>,

    #[serde(default)]
    pub backoff: BackoffStrategy,

    /// Base delay for the backoff schedule.
    #[serde(default = "default_backoff_base")]
    pub backoff_base: HumanDuration,
}

fn default_max_retries() -> u32 {
    2
}
fn default_retry_on_status() -> Vec<u16> {
    vec![502, 503, 504]
}
fn default_backoff_base() -> HumanDuration {
    HumanDuration::from_millis(100)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BackoffStrategy {
    #[default]
    Exponential,
    Linear,
    Constant,
}

// ─────────────────────────────────────────────────────────────────────
// WafPolicy
// ─────────────────────────────────────────────────────────────────────

/// A security policy: IP ACLs, rate limiting, JWT auth, and WAF rules.
///
/// Phase-0 enforcement covers IP ACLs, rate limiting, and JWT validation
/// (via the in-process security engine). Signature rule packs and custom
/// rules are schema-complete now and enforced by the Phase-3 WAF engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WafPolicy {
    /// Must be `intellaro.io/v1`.
    pub api_version: String,

    /// Must be `WafPolicy`.
    pub kind: String,

    pub metadata: Metadata,
    pub spec: WafPolicySpec,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WafPolicySpec {
    /// `block` rejects offending requests; `monitor` only logs them.
    #[serde(default)]
    pub mode: WafMode,

    /// CIDR allow-list. When non-empty, only these sources are admitted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_allow: Vec<String>,

    /// CIDR deny-list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_deny: Vec<String>,

    /// Request rate limiting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,

    /// Built-in signature packs to enable (Phase 3 enforcement).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_packs: Vec<RulePack>,

    /// Custom WAF rules (Phase 3 enforcement).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<WafRule>,

    /// JWT bearer validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<JwtAuth>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WafMode {
    #[default]
    Block,
    Monitor,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimit {
    /// Maximum requests allowed per window.
    pub max_requests: u64,

    /// Window size.
    pub window: HumanDuration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RulePack {
    Sqli,
    Xss,
    Cmdi,
    Lfi,
    Protocol,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WafRule {
    /// Stable rule identifier (used in events and audit).
    pub id: String,

    /// Request parts to inspect.
    #[serde(default = "default_waf_targets")]
    pub targets: Vec<WafTarget>,

    pub pattern: WafPattern,

    /// Per-rule action override; defaults to the policy mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<WafAction>,
}

fn default_waf_targets() -> Vec<WafTarget> {
    vec![WafTarget::All]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WafTarget {
    All,
    Url,
    Headers,
    Body,
    Args,
    Cookies,
    UserAgent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WafPattern {
    #[serde(rename = "type", default)]
    pub pattern_type: WafPatternType,

    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WafPatternType {
    #[default]
    Regex,
    String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WafAction {
    Block,
    Monitor,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JwtAuth {
    /// HMAC secret, or a path to a PEM public key.
    pub secret_or_key_path: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
}
