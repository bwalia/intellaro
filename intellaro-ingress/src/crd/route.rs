//! IntellaroRoute — Route/path CRD.
//!
//! Defines path-based routing rules that map URL prefixes or regex
//! patterns to backend services, with optional header-based matching,
//! rewrites, and traffic splitting for canary/blue-green deployments.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::IntellaroCondition;
use super::vhost::BackendRef;

/// Spec for the IntellaroRoute custom resource.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "ingress.intellaro.io",
    version = "v1alpha1",
    kind = "IntellaroRoute",
    plural = "intellaroroutes",
    shortname = "irt",
    namespaced,
    status = "IntellaroRouteStatus",
    printcolumn = r#"{"name":"VHost","type":"string","jsonPath":".spec.vhostRef"}"#,
    printcolumn = r#"{"name":"Path","type":"string","jsonPath":".spec.match.pathPrefix"}"#,
    printcolumn = r#"{"name":"Synced","type":"string","jsonPath":".status.synced"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct IntellaroRouteSpec {
    /// Reference to the parent IntellaroVHost name (must be in the same namespace).
    pub vhost_ref: String,

    /// Matching criteria for this route.
    pub r#match: RouteMatch,

    /// Primary backend for matched requests.
    pub backend: BackendRef,

    /// Optional traffic-split targets for canary / blue-green.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub traffic_split: Vec<WeightedBackend>,

    /// Optional URL rewrite rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite: Option<RouteRewrite>,

    /// Request/response header manipulation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HeaderPolicy>,

    /// Optional per-route timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,

    /// Optional per-route retry policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<RetryPolicy>,

    /// Priority for ordering routes (higher = matched first). Default: 100.
    #[serde(default = "default_priority")]
    pub priority: u32,
}

fn default_priority() -> u32 {
    100
}

/// Criteria to match incoming requests against this route.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouteMatch {
    /// Match requests whose path starts with this prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,

    /// Match requests whose path matches this exact value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_exact: Option<String>,

    /// Match requests whose path matches this regex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_regex: Option<String>,

    /// HTTP methods to match (empty = all).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,

    /// Header-based matching conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub header_matches: Vec<HeaderMatch>,

    /// Client source IPs/CIDRs to match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_cidrs: Vec<String>,
}

/// Header matching condition.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HeaderMatch {
    /// Header name.
    pub name: String,

    /// Exact value to match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,

    /// Regex to match the header value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
}

/// A backend with a traffic weight for canary/blue-green splits.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WeightedBackend {
    /// Backend service reference.
    pub backend: BackendRef,

    /// Traffic weight (0–100).
    pub weight: u32,
}

/// URL rewrite configuration.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouteRewrite {
    /// Replace the matched path prefix with this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace_path_prefix: Option<String>,

    /// Replace the matched hostname.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace_host: Option<String>,
}

/// Header manipulation policy.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HeaderPolicy {
    /// Headers to add/set on the proxied request.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_set: Vec<HeaderKV>,

    /// Headers to add/set on the proxied response.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_set: Vec<HeaderKV>,

    /// Header names to remove from the proxied request.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_remove: Vec<String>,

    /// Header names to remove from the proxied response.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_remove: Vec<String>,
}

/// A key-value pair representing a header.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct HeaderKV {
    pub name: String,
    pub value: String,
}

/// Retry policy for failed requests.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RetryPolicy {
    /// Maximum number of retry attempts.
    pub max_retries: u32,

    /// HTTP status codes that trigger a retry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retry_on_status: Vec<u16>,

    /// Per-retry timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_retry_timeout_secs: Option<u64>,
}

/// Observed status of the IntellaroRoute.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IntellaroRouteStatus {
    /// Whether the route is synced to intellaro-http-server.
    #[serde(default)]
    pub synced: bool,

    /// Last time the route was pushed to the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_at: Option<String>,

    /// Controller-observed generation.
    #[serde(default)]
    pub observed_generation: i64,

    /// Status conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<IntellaroCondition>,
}
