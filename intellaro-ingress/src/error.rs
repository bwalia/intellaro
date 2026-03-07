//! Error types for the ingress controller.

/// Top-level error type for the ingress controller.
#[derive(Debug, thiserror::Error)]
pub enum IngressError {
    /// Kubernetes API error.
    #[error("Kubernetes API error: {0}")]
    KubeError(#[from] kube::Error),

    /// MCP / server communication error.
    #[error("MCP error: {0}")]
    McpError(String),

    /// Configuration or reconciliation error.
    #[error("Reconciliation error: {0}")]
    ReconcileError(String),

    /// CRD validation error.
    #[error("Validation error: {0}")]
    ValidationError(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Convenience alias.
pub type IngressResult<T> = Result<T, IngressError>;
