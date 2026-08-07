//! Custom Resource Definitions for Intellaro Ingress.
//!
//! Defines the seven core CRDs that map Kubernetes resources
//! to `intellaro-http-server` configuration via the MCP API.

pub mod vhost;
pub mod route;
pub mod lb_policy;
pub mod security;
pub mod cache;
pub mod service_discovery;
pub mod routing_policy;

pub use vhost::IntellaroVHost;
pub use route::IntellaroRoute;
pub use lb_policy::IntellaroLBPolicy;
pub use security::IntellaroSecurityPolicy;
pub use cache::IntellaroCachePolicy;
pub use service_discovery::IntellaroServiceDiscovery;
pub use routing_policy::IntellaroRoutingPolicy;

/// Common status condition attached to every Intellaro CRD.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct IntellaroCondition {
    /// Machine-readable condition type (e.g., "Synced", "Ready", "Error").
    pub r#type: String,

    /// "True", "False", or "Unknown".
    pub status: String,

    /// Human-readable reason for the transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Last time the condition transitioned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<String>,
}

/// Schema override for polymorphic fields (enums mixing string and object
/// variants), which Kubernetes structural schemas cannot express. Emits
/// `x-kubernetes-preserve-unknown-fields: true`, matching the hand-written
/// CRD manifests this crate originally shipped.
pub(crate) fn preserve_unknown(
    _gen: &mut schemars::gen::SchemaGenerator,
) -> schemars::schema::Schema {
    let mut obj = schemars::schema::SchemaObject::default();
    obj.extensions.insert(
        "x-kubernetes-preserve-unknown-fields".to_string(),
        serde_json::json!(true),
    );
    schemars::schema::Schema::Object(obj)
}
