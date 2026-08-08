//! IntellaroServiceDiscovery — Service mesh auto-discovery CRD.
//!
//! Defines how the ingress controller discovers services, pods, and
//! endpoints in Kubernetes clusters. Supports label selectors,
//! multi-namespace scoping, and configurable polling intervals.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::IntellaroCondition;

/// Spec for the IntellaroServiceDiscovery custom resource.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "ingress.intellaro.io",
    version = "v1alpha1",
    kind = "IntellaroServiceDiscovery",
    plural = "intellaroservicediscoveries",
    shortname = "isd",
    namespaced,
    status = "IntellaroServiceDiscoveryStatus",
    printcolumn = r#"{"name":"Mode","type":"string","jsonPath":".spec.mode"}"#,
    printcolumn = r#"{"name":"Services","type":"integer","jsonPath":".status.discoveredServices"}"#,
    printcolumn = r#"{"name":"Endpoints","type":"integer","jsonPath":".status.discoveredEndpoints"}"#,
    printcolumn = r#"{"name":"Synced","type":"string","jsonPath":".status.synced"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct IntellaroServiceDiscoverySpec {
    /// Discovery mode.
    #[serde(default)]
    pub mode: DiscoveryMode,

    /// Namespaces to discover services in. Empty = same namespace as this CRD.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<String>,

    /// If true, discover services across all namespaces (overrides `namespaces`).
    #[serde(default)]
    pub cluster_wide: bool,

    /// Label selector to filter discovered services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_selector: Option<String>,

    /// Annotation selector to filter discovered services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotation_selector: Option<String>,

    /// How frequently to poll for changes (seconds). 0 = event-driven only.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,

    /// Port discovery strategy.
    #[serde(default)]
    #[schemars(schema_with = "super::preserve_unknown")]
    pub port_discovery: PortDiscovery,

    /// Whether to auto-register discovered services as backend groups.
    #[serde(default = "default_true")]
    pub auto_register: bool,

    /// Backend group naming template. Supported variables: {namespace}, {name}, {port}.
    #[serde(default = "default_group_template")]
    pub group_name_template: String,

    /// Default load balancing strategy for auto-registered backends.
    #[serde(default = "default_lb_strategy")]
    pub default_lb_strategy: String,

    /// Health check configuration for discovered services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<DiscoveryHealthCheck>,

    /// Exclusion rules: services matching these patterns are ignored.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_services: Vec<ServiceFilter>,

    /// Inclusion rules: only services matching these patterns are included.
    /// If empty, all services (minus exclusions) are included.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_services: Vec<ServiceFilter>,

    /// Cross-cluster discovery configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_cluster: Option<CrossClusterConfig>,
}

fn default_poll_interval() -> u64 {
    30
}
fn default_true() -> bool {
    true
}
fn default_group_template() -> String {
    "{namespace}-{name}".to_string()
}
fn default_lb_strategy() -> String {
    "round_robin".to_string()
}

/// Discovery mode for how the controller detects services.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum DiscoveryMode {
    /// Watch Kubernetes Services and their Endpoints (default).
    #[default]
    Kubernetes,
    /// Watch Kubernetes EndpointSlices (preferred for large clusters).
    EndpointSlice,
    /// DNS-based service discovery.
    Dns,
}

/// How to discover ports on services.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum PortDiscovery {
    /// Use all named ports from the Service spec.
    #[default]
    AllNamed,
    /// Use only ports with specific names.
    ByName(Vec<String>),
    /// Use only ports with specific numbers.
    ByNumber(Vec<u16>),
    /// Use the first available port.
    FirstAvailable,
}

/// Health check configuration for discovered endpoints.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryHealthCheck {
    /// HTTP path to probe.
    pub path: String,

    /// Probe interval in seconds.
    #[serde(default = "default_hc_interval")]
    pub interval_secs: u64,

    /// Probe timeout in seconds.
    #[serde(default = "default_hc_timeout")]
    pub timeout_secs: u64,

    /// Consecutive failures to mark unhealthy.
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
}

fn default_hc_interval() -> u64 {
    10
}
fn default_hc_timeout() -> u64 {
    5
}
fn default_unhealthy_threshold() -> u32 {
    3
}

/// Filter for including/excluding services by name or label.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceFilter {
    /// Glob pattern for service name (e.g., "kube-*", "*.internal").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_pattern: Option<String>,

    /// Namespace pattern.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_pattern: Option<String>,

    /// Label selector (e.g., "app=nginx").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_selector: Option<String>,
}

/// Cross-cluster discovery using kubeconfig contexts or service accounts.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CrossClusterConfig {
    /// Whether cross-cluster discovery is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Remote clusters to discover services from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clusters: Vec<RemoteCluster>,
}

/// Reference to a remote Kubernetes cluster.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RemoteCluster {
    /// Human-readable name for this cluster.
    pub name: String,

    /// Kubeconfig context name, or a Secret reference containing kubeconfig.
    pub kubeconfig_secret: String,

    /// Namespace containing the kubeconfig Secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubeconfig_namespace: Option<String>,

    /// Weight for cross-cluster load balancing (higher = more traffic).
    #[serde(default = "default_cluster_weight")]
    pub weight: u32,
}

fn default_cluster_weight() -> u32 {
    100
}

/// Observed status of the IntellaroServiceDiscovery.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IntellaroServiceDiscoveryStatus {
    /// Whether the discovery configuration is synced.
    #[serde(default)]
    pub synced: bool,

    /// Last time the discovery scan completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_at: Option<String>,

    /// Number of services currently discovered.
    #[serde(default)]
    pub discovered_services: u32,

    /// Number of healthy endpoints discovered.
    #[serde(default)]
    pub discovered_endpoints: u32,

    /// Number of backend groups registered via auto-discovery.
    #[serde(default)]
    pub registered_groups: u32,

    /// Controller-observed generation.
    #[serde(default)]
    pub observed_generation: i64,

    /// Status conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<IntellaroCondition>,
}
