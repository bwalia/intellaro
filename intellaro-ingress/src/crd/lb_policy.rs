//! IntellaroLBPolicy — Load balancing policy CRD.
//!
//! Defines load balancing strategies, health check parameters,
//! sticky sessions, and failover behaviour for upstream backends.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::IntellaroCondition;

/// Spec for the IntellaroLBPolicy custom resource.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "ingress.intellaro.io",
    version = "v1alpha1",
    kind = "IntellaroLBPolicy",
    plural = "intellarolbpolicies",
    shortname = "ilb",
    namespaced,
    status = "IntellaroLBPolicyStatus",
    printcolumn = r#"{"name":"Strategy","type":"string","jsonPath":".spec.strategy"}"#,
    printcolumn = r#"{"name":"Synced","type":"string","jsonPath":".status.synced"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct IntellaroLBPolicySpec {
    /// Load balancing strategy.
    pub strategy: LBStrategy,

    /// Health check configuration for backends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthCheck>,

    /// Sticky session (session affinity) configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sticky_session: Option<StickySession>,

    /// Failover configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failover: Option<FailoverConfig>,

    /// Connection limits per backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections_per_backend: Option<u32>,

    /// Slow-start window in seconds for newly healthy backends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slow_start_secs: Option<u64>,
}

/// Supported load balancing strategies.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LBStrategy {
    /// Round-robin across healthy backends.
    RoundRobin,
    /// Route to the backend with fewest active connections.
    LeastConnections,
    /// Weighted distribution based on per-backend weights.
    Weighted,
    /// Random selection.
    Random,
    /// Consistent hashing on a request attribute (for session affinity).
    ConsistentHash,
}

/// Health check parameters for backend probes.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheck {
    /// HTTP path to probe (e.g., "/healthz").
    pub path: String,

    /// Interval between probes in seconds.
    #[serde(default = "default_interval")]
    pub interval_secs: u64,

    /// Probe timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Consecutive failures before marking unhealthy.
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,

    /// Consecutive successes before marking healthy.
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,

    /// Expected HTTP status code (200 if omitted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_status: Option<u16>,
}

fn default_interval() -> u64 {
    10
}
fn default_timeout() -> u64 {
    5
}
fn default_unhealthy_threshold() -> u32 {
    3
}
fn default_healthy_threshold() -> u32 {
    2
}

/// Sticky session / session affinity settings.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StickySession {
    /// Affinity mode.
    pub mode: StickyMode,

    /// Cookie name when mode is `Cookie`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie_name: Option<String>,

    /// Cookie TTL in seconds (0 = session cookie).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie_ttl_secs: Option<u64>,

    /// Header name when mode is `Header`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_name: Option<String>,
}

/// Sticky session mode.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StickyMode {
    /// Affinity based on client IP.
    SourceIp,
    /// Affinity based on a cookie.
    Cookie,
    /// Affinity based on a request header.
    Header,
}

/// Failover behaviour when backends go unhealthy.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FailoverConfig {
    /// Return a static error page instead of 502 when all backends are down.
    #[serde(default)]
    pub custom_error_page: bool,

    /// Fallback upstream group name to try when primary is exhausted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_upstream: Option<String>,
}

/// Observed status of the IntellaroLBPolicy.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IntellaroLBPolicyStatus {
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
