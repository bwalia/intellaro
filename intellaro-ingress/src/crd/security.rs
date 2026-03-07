//! IntellaroSecurityPolicy — Security policy CRD.
//!
//! Defines per-vhost or per-route security enforcement rules
//! including JWT/OAuth2 validation, IP allow/block lists,
//! rate limiting, and CORS policies.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::IntellaroCondition;

/// Spec for the IntellaroSecurityPolicy custom resource.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "ingress.intellaro.io",
    version = "v1alpha1",
    kind = "IntellaroSecurityPolicy",
    plural = "intellarosecuritypolicies",
    shortname = "isp",
    namespaced,
    status = "IntellaroSecurityPolicyStatus",
    printcolumn = r#"{"name":"JWT","type":"boolean","jsonPath":".spec.jwt.enabled"}"#,
    printcolumn = r#"{"name":"RateLimit","type":"boolean","jsonPath":".spec.rateLimit.enabled"}"#,
    printcolumn = r#"{"name":"Synced","type":"string","jsonPath":".status.synced"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct IntellaroSecurityPolicySpec {
    /// JWT / OAuth2 validation settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<JwtPolicy>,

    /// IP allow list (CIDR notation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_allow: Vec<String>,

    /// IP block list (CIDR notation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_block: Vec<String>,

    /// Rate limiting configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitPolicy>,

    /// CORS policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cors: Option<CorsPolicy>,

    /// Scope: which vhosts or routes this policy applies to.
    /// Empty means cluster-wide default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_refs: Vec<PolicyTargetRef>,
}

/// JWT validation policy.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct JwtPolicy {
    /// Enable JWT validation.
    #[serde(default)]
    pub enabled: bool,

    /// Name of a Kubernetes Secret containing the verification key/secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<String>,

    /// Expected issuer claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    /// Expected audience claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,

    /// JWKS URI for dynamic key fetching (for OAuth2 / OIDC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// Header name to extract the token from (default: "Authorization").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_header: Option<String>,

    /// Forward validated claims as headers to the backend.
    #[serde(default)]
    pub forward_claims: bool,
}

/// Rate limiting policy.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitPolicy {
    /// Enable rate limiting.
    #[serde(default)]
    pub enabled: bool,

    /// Maximum requests per window.
    pub max_requests: u64,

    /// Sliding window duration in seconds.
    #[serde(default = "default_window")]
    pub window_secs: u64,

    /// Key to rate-limit on.
    #[serde(default)]
    pub key: RateLimitKey,

    /// HTTP status code to return when rate limited (default: 429).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
}

fn default_window() -> u64 {
    60
}

/// Key used to identify rate-limit buckets.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKey {
    /// Rate limit by client IP address.
    #[default]
    ClientIp,
    /// Rate limit by a specific request header value.
    Header(String),
    /// Rate limit by authenticated user identity (from JWT sub claim).
    User,
}

/// CORS (Cross-Origin Resource Sharing) policy.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CorsPolicy {
    /// Allowed origins ("*" for any).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_origins: Vec<String>,

    /// Allowed HTTP methods.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_methods: Vec<String>,

    /// Allowed request headers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_headers: Vec<String>,

    /// Headers exposed to the browser.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expose_headers: Vec<String>,

    /// Whether to allow credentials.
    #[serde(default)]
    pub allow_credentials: bool,

    /// Preflight cache duration in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_secs: Option<u64>,
}

/// Reference to a target resource this policy applies to.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyTargetRef {
    /// Kind of the target ("IntellaroVHost" or "IntellaroRoute").
    pub kind: String,

    /// Name of the target resource.
    pub name: String,
}

/// Observed status of the IntellaroSecurityPolicy.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IntellaroSecurityPolicyStatus {
    /// Whether the policy is synced to intellaro-http-server.
    #[serde(default)]
    pub synced: bool,

    /// Last time the policy was pushed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_at: Option<String>,

    /// Controller-observed generation.
    #[serde(default)]
    pub observed_generation: i64,

    /// Status conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<IntellaroCondition>,
}
