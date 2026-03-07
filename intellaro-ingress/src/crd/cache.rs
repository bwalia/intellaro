//! IntellaroCachePolicy — Caching policy CRD.
//!
//! Defines caching rules, eviction strategies, TTL overrides, and
//! predictive prefetching settings. Applied per-vhost or per-route.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::IntellaroCondition;
use super::security::PolicyTargetRef;

/// Spec for the IntellaroCachePolicy custom resource.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "ingress.intellaro.io",
    version = "v1alpha1",
    kind = "IntellaroCachePolicy",
    plural = "intellarocachepolicies",
    shortname = "icp",
    namespaced,
    status = "IntellaroCachePolicyStatus",
    printcolumn = r#"{"name":"Enabled","type":"boolean","jsonPath":".spec.enabled"}"#,
    printcolumn = r#"{"name":"Strategy","type":"string","jsonPath":".spec.evictionStrategy"}"#,
    printcolumn = r#"{"name":"Synced","type":"string","jsonPath":".status.synced"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct IntellaroCachePolicySpec {
    /// Enable caching for matched targets.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Default TTL in seconds for cached responses.
    #[serde(default = "default_ttl")]
    pub default_ttl_secs: u64,

    /// Maximum number of entries in the cache.
    #[serde(default = "default_max_entries")]
    pub max_entries: u64,

    /// Cache eviction strategy.
    #[serde(default)]
    pub eviction_strategy: EvictionStrategy,

    /// Per-path TTL overrides.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_rules: Vec<CachePathRule>,

    /// HTTP methods to cache (default: GET, HEAD).
    #[serde(default = "default_cacheable_methods")]
    pub cacheable_methods: Vec<String>,

    /// Status codes to cache (default: 200, 301, 302).
    #[serde(default = "default_cacheable_statuses")]
    pub cacheable_statuses: Vec<u16>,

    /// Respect Cache-Control headers from the origin.
    #[serde(default = "default_true")]
    pub respect_origin_headers: bool,

    /// Enable predictive prefetching based on access patterns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefetch: Option<PrefetchConfig>,

    /// Vary headers to include in the cache key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vary_headers: Vec<String>,

    /// Scope: which vhosts or routes this policy applies to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_refs: Vec<PolicyTargetRef>,
}

fn default_true() -> bool {
    true
}
fn default_ttl() -> u64 {
    300
}
fn default_max_entries() -> u64 {
    10_000
}
fn default_cacheable_methods() -> Vec<String> {
    vec!["GET".to_string(), "HEAD".to_string()]
}
fn default_cacheable_statuses() -> Vec<u16> {
    vec![200, 301, 302]
}

/// Cache eviction strategy.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvictionStrategy {
    /// Least Recently Used.
    #[default]
    Lru,
    /// Least Frequently Used.
    Lfu,
    /// Time-based expiration only (no eviction pressure).
    TtlOnly,
}

/// Path-specific cache rule override.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CachePathRule {
    /// Path prefix to match.
    pub path_prefix: String,

    /// TTL override in seconds for this path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,

    /// Disable caching for this path.
    #[serde(default)]
    pub bypass: bool,
}

/// Predictive prefetch configuration.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PrefetchConfig {
    /// Enable prefetching.
    #[serde(default)]
    pub enabled: bool,

    /// Minimum request count before prefetching activates for a pattern.
    #[serde(default = "default_min_hits")]
    pub min_hits: u64,

    /// Look-ahead window in seconds for prefetch prediction.
    #[serde(default = "default_lookahead")]
    pub lookahead_secs: u64,
}

fn default_min_hits() -> u64 {
    10
}
fn default_lookahead() -> u64 {
    60
}

/// Observed status of the IntellaroCachePolicy.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IntellaroCachePolicyStatus {
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
