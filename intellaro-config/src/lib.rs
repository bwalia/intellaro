//! # intellaro-config
//!
//! The typed `intellaro.io/v1` configuration model for the Intellaro
//! application delivery platform.
//!
//! Configuration is **data, not code**: operators write YAML or JSON
//! documents (`Gateway`, `Upstream`, `WafPolicy`) that are parsed into
//! strongly-typed structs, validated, and compiled into the data-plane
//! runtime configuration. The same model maps 1:1 onto Kubernetes CRDs.
//!
//! ```yaml
//! apiVersion: intellaro.io/v1
//! kind: Gateway
//! metadata:
//!   name: pop1-edge
//! spec:
//!   listeners:
//!     - name: http
//!       port: 8080
//!       protocol: HTTP
//!   hosts:
//!     - name: example.com
//!       routes:
//!         - match:
//!             path: { type: Prefix, value: / }
//!           backends:
//!             - address: 127.0.0.1:9000
//!               weight: 1
//! ```
//!
//! JSON Schemas for every kind are generated from these types via
//! [`schema::write_schemas`] (exposed as `intellaro schema` on the CLI),
//! so the published schema can never drift from the parser.

pub mod duration;
pub mod loader;
pub mod schema;
pub mod types;
pub mod validate;

pub use duration::HumanDuration;
pub use loader::{is_v1_config, load_str, ConfigSet};
pub use types::*;
pub use validate::validate;

/// The API version accepted by this crate.
pub const API_VERSION: &str = "intellaro.io/v1";

/// Errors produced while loading or validating `intellaro.io/v1` documents.
#[derive(Debug, thiserror::Error)]
pub enum ConfigV1Error {
    #[error("failed to parse document {index}: {message}")]
    Parse { index: usize, message: String },

    #[error("document {index} has unsupported apiVersion {found:?} (expected {expected:?})")]
    UnsupportedApiVersion {
        index: usize,
        found: String,
        expected: &'static str,
    },

    #[error("document {index} has unknown kind {kind:?} (expected Gateway, Upstream, or WafPolicy)")]
    UnknownKind { index: usize, kind: String },

    #[error("document {index} is missing required field {field:?}")]
    MissingField { index: usize, field: &'static str },

    #[error("configuration is invalid:\n{}", .0.join("\n"))]
    Validation(Vec<String>),
}
