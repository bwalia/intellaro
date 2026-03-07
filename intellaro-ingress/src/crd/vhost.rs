//! IntellaroVHost — Virtual host CRD.
//!
//! Maps a hostname (with optional TLS) to one or more upstream backends,
//! which are then reconciled into `intellaro-http-server` listener and
//! upstream configuration via the MCP API.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::IntellaroCondition;

/// Spec for the IntellaroVHost custom resource.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "ingress.intellaro.io",
    version = "v1alpha1",
    kind = "IntellaroVHost",
    plural = "intellarovhosts",
    shortname = "ivh",
    namespaced,
    status = "IntellaroVHostStatus",
    printcolumn = r#"{"name":"Host","type":"string","jsonPath":".spec.hostname"}"#,
    printcolumn = r#"{"name":"TLS","type":"boolean","jsonPath":".spec.tls.enabled"}"#,
    printcolumn = r#"{"name":"Synced","type":"string","jsonPath":".status.synced"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct IntellaroVHostSpec {
    /// Fully-qualified hostname this vhost serves (e.g., "api.example.com").
    pub hostname: String,

    /// Optional list of hostname aliases.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,

    /// TLS configuration for this vhost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<VHostTls>,

    /// Name of the upstream backend group to forward traffic to.
    pub upstream: String,

    /// Optional reference to an IntellaroLBPolicy for this vhost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lb_policy_ref: Option<String>,

    /// Optional reference to an IntellaroSecurityPolicy for this vhost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_policy_ref: Option<String>,

    /// Optional reference to an IntellaroCachePolicy for this vhost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_policy_ref: Option<String>,

    /// Default backend service to use when no route matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_backend: Option<BackendRef>,
}

/// TLS settings for a virtual host.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VHostTls {
    /// Enable TLS termination for this vhost.
    #[serde(default)]
    pub enabled: bool,

    /// Name of the Kubernetes Secret containing tls.crt and tls.key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,

    /// Enable automatic certificate provisioning via ACME / Let's Encrypt.
    #[serde(default)]
    pub acme: bool,

    /// Minimum TLS version (e.g., "1.2", "1.3").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_version: Option<String>,
}

/// Reference to a Kubernetes Service backend.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendRef {
    /// Service name.
    pub service_name: String,

    /// Service port number.
    pub service_port: u16,

    /// Optional namespace (defaults to the CRD's namespace).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// Observed status of the IntellaroVHost.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IntellaroVHostStatus {
    /// Whether the vhost configuration is synced to intellaro-http-server.
    #[serde(default)]
    pub synced: bool,

    /// Last time the configuration was pushed to the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_at: Option<String>,

    /// Number of active backends serving this vhost.
    #[serde(default)]
    pub active_backends: u32,

    /// Controller-observed generation.
    #[serde(default)]
    pub observed_generation: i64,

    /// Status conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<IntellaroCondition>,
}
