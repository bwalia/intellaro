//! IntellaroRoutingPolicy — Rules-driven routing CRD.
//!
//! Defines dynamic, policy-driven routing rules that apply across
//! virtual hosts and backends. Supports weighted routing, header/cookie
//! matching, tenant isolation, SLA prioritization, canary deployments,
//! and optional AI-assisted routing decisions.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::IntellaroCondition;

/// Spec for the IntellaroRoutingPolicy custom resource.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "ingress.intellaro.io",
    version = "v1alpha1",
    kind = "IntellaroRoutingPolicy",
    plural = "intellaroroutingpolicies",
    shortname = "irp",
    namespaced,
    status = "IntellaroRoutingPolicyStatus",
    printcolumn = r#"{"name":"Type","type":"string","jsonPath":".spec.policyType"}"#,
    printcolumn = r#"{"name":"Priority","type":"integer","jsonPath":".spec.priority"}"#,
    printcolumn = r#"{"name":"Synced","type":"string","jsonPath":".status.synced"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct IntellaroRoutingPolicySpec {
    /// Human-readable description of this policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Policy type categorization.
    #[serde(default)]
    pub policy_type: RoutingPolicyType,

    /// Priority (higher = evaluated first). Default: 100.
    #[serde(default = "default_priority")]
    pub priority: u32,

    /// Whether this policy is currently active.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Target references: which vhosts, routes, or backend groups this policy applies to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_refs: Vec<RoutingTargetRef>,

    /// Match conditions: when should this policy activate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_conditions: Option<RoutingMatchConditions>,

    /// Traffic splitting rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub traffic_split: Vec<TrafficSplitRule>,

    /// SLA/tenant-based priority routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sla_routing: Option<SlaRoutingConfig>,

    /// Canary/blue-green deployment configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary: Option<CanaryPolicyConfig>,

    /// Failover/fallback configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failover: Option<FailoverPolicyConfig>,

    /// AI-assisted routing hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_routing: Option<AiRoutingConfig>,

    /// Request/response header manipulation when this policy matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<PolicyHeaderManipulation>,

    /// Rate limiting specific to this routing policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<PolicyRateLimit>,
}

fn default_priority() -> u32 {
    100
}
fn default_true() -> bool {
    true
}

/// Categorization of routing policy types.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum RoutingPolicyType {
    /// General-purpose routing policy.
    #[default]
    General,
    /// Canary/blue-green deployment policy.
    Canary,
    /// SLA/tenant prioritization policy.
    SlaPriority,
    /// Traffic mirroring policy.
    Mirror,
    /// Failover/fallback policy.
    Failover,
    /// AI-assisted adaptive routing.
    AiAssisted,
}

/// Reference to a target resource this policy applies to.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RoutingTargetRef {
    /// Kind of the target ("IntellaroVHost", "IntellaroRoute", or "BackendGroup").
    pub kind: String,

    /// Name of the target.
    pub name: String,

    /// Namespace of the target (defaults to policy's namespace).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// Match conditions for activating this routing policy.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RoutingMatchConditions {
    /// Match by request headers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HeaderMatchRule>,

    /// Match by cookie values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cookies: Vec<CookieMatchRule>,

    /// Match by query parameters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query_params: Vec<QueryMatchRule>,

    /// Match by source IP CIDR ranges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_cidrs: Vec<String>,

    /// Match by HTTP methods.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,

    /// Match by Content-Type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// Match by path prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,

    /// Match by path regex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_regex: Option<String>,
}

/// Header-based match rule.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HeaderMatchRule {
    /// Header name (case-insensitive).
    pub name: String,
    /// Exact value to match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
    /// Regex pattern to match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    /// Just check for presence (any value).
    #[serde(default)]
    pub present: bool,
}

/// Cookie-based match rule.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CookieMatchRule {
    /// Cookie name.
    pub name: String,
    /// Exact value to match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
    /// Regex pattern to match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
}

/// Query parameter match rule.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct QueryMatchRule {
    /// Query parameter name.
    pub name: String,
    /// Exact value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
    /// Regex pattern.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
}

/// Traffic split rule: distribute traffic across multiple backends.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TrafficSplitRule {
    /// Backend group to route to.
    pub backend_group: String,

    /// Weight (0–100). Weights across all rules should sum to 100.
    pub weight: u32,

    /// Optional header to set when routed to this backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_header: Option<String>,
}

/// SLA/tenant-based priority routing configuration.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SlaRoutingConfig {
    /// How to identify the SLA tier.
    #[schemars(schema_with = "super::preserve_unknown")]
    pub identifier: SlaIdentifier,

    /// Tier definitions, ordered by priority (highest first).
    pub tiers: Vec<SlaTier>,
}

/// How to extract the SLA tier from a request.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum SlaIdentifier {
    /// Extract from a request header.
    Header(String),
    /// Extract from a JWT claim.
    JwtClaim(String),
    /// Extract from a cookie.
    Cookie(String),
    /// Extract from source IP CIDR mapping.
    SourceIp,
}

/// Definition of an SLA tier.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SlaTier {
    /// Tier name (e.g., "premium", "standard", "free").
    pub name: String,

    /// Value that identifies this tier (header value, claim value, etc.).
    pub value: String,

    /// Dedicated backend group for this tier (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedicated_backend: Option<String>,

    /// Rate limit multiplier (1.0 = default, 2.0 = double the limits).
    #[serde(default = "default_rate_multiplier")]
    pub rate_multiplier: f64,

    /// Priority level (higher = more important).
    #[serde(default = "default_priority")]
    pub priority_level: u32,
}

fn default_rate_multiplier() -> f64 {
    1.0
}

/// Canary/blue-green deployment configuration.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CanaryPolicyConfig {
    /// Primary (stable) backend group.
    pub primary_group: String,

    /// Canary backend group.
    pub canary_group: String,

    /// Percentage of traffic to send to canary (0–100).
    #[serde(default)]
    pub canary_weight: u32,

    /// Header that forces canary routing when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary_header: Option<String>,

    /// Cookie that forces canary routing when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary_cookie: Option<String>,

    /// Whether AI should adaptively adjust canary weight based on error rates.
    #[serde(default)]
    pub adaptive: bool,

    /// Maximum canary weight when adaptive adjustment is enabled.
    #[serde(default = "default_max_canary_weight")]
    pub max_adaptive_weight: u32,
}

fn default_max_canary_weight() -> u32 {
    50
}

/// Failover/fallback policy configuration.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FailoverPolicyConfig {
    /// Primary backend group.
    pub primary_group: String,

    /// Fallback backend group to use when primary is unhealthy.
    pub fallback_group: String,

    /// Error rate threshold (0.0–1.0) that triggers failover.
    #[serde(default = "default_error_threshold")]
    pub error_threshold: f64,

    /// Consecutive failures before failover.
    #[serde(default = "default_failure_count")]
    pub consecutive_failures: u32,

    /// Seconds to wait before attempting to recover to primary.
    #[serde(default = "default_recovery_secs")]
    pub recovery_secs: u64,
}

fn default_error_threshold() -> f64 {
    0.5
}
fn default_failure_count() -> u32 {
    5
}
fn default_recovery_secs() -> u64 {
    60
}

/// AI-assisted routing configuration.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AiRoutingConfig {
    /// Enable AI-predictive backend selection.
    #[serde(default)]
    pub predictive_enabled: bool,

    /// Enable anomaly-based rerouting.
    #[serde(default)]
    pub anomaly_rerouting: bool,

    /// Enable AI request classification for routing.
    #[serde(default)]
    pub classification_enabled: bool,

    /// Classification-to-backend mappings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub class_routes: Vec<ClassRoute>,
}

/// Mapping from an AI classification label to a backend group.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClassRoute {
    /// Classification label (e.g., "api", "static", "heavy_compute").
    pub class_label: String,
    /// Backend group to route to.
    pub backend_group: String,
}

/// Header manipulation when a routing policy matches.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyHeaderManipulation {
    /// Headers to add/set on the request.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_set: Vec<HeaderKV>,

    /// Headers to add/set on the response.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_set: Vec<HeaderKV>,

    /// Headers to remove from the request.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_remove: Vec<String>,

    /// Headers to remove from the response.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_remove: Vec<String>,
}

/// Key-value pair for header manipulation.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HeaderKV {
    pub name: String,
    pub value: String,
}

/// Per-policy rate limiting.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRateLimit {
    /// Maximum requests allowed in the window.
    pub max_requests: u64,

    /// Window duration in seconds.
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,

    /// Rate limit key: how to identify rate-limited entities.
    #[serde(default)]
    pub key: PolicyRateLimitKey,

    /// Header to key on when `key: header`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_header: Option<String>,
}

fn default_window_secs() -> u64 {
    60
}

/// Rate limit key type.
///
/// All variants are plain strings so the generated CRD schema is a
/// consistent string enum; for `header` the name lives in `keyHeader`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum PolicyRateLimitKey {
    /// Rate limit per client IP.
    #[default]
    ClientIp,
    /// Rate limit per header value (see `keyHeader`).
    Header,
    /// Rate limit per authenticated user.
    User,
    /// Rate limit per SLA tier.
    SlaTier,
}

/// Observed status of the IntellaroRoutingPolicy.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IntellaroRoutingPolicyStatus {
    /// Whether the policy is synced to intellaro-http-server.
    #[serde(default)]
    pub synced: bool,

    /// Last time the policy was pushed to the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_at: Option<String>,

    /// Number of targets this policy is applied to.
    #[serde(default)]
    pub applied_targets: u32,

    /// Controller-observed generation.
    #[serde(default)]
    pub observed_generation: i64,

    /// Status conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<IntellaroCondition>,
}
