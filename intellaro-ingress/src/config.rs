//! Controller configuration.
//!
//! Read from environment variables or CLI flags.

use serde::{Deserialize, Serialize};

/// Configuration for the ingress controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerConfig {
    /// Base URL of the intellaro-http-server MCP API.
    pub mcp_url: String,

    /// API key for authenticating with the MCP API.
    pub mcp_api_key: Option<String>,

    /// MCP request timeout in seconds.
    pub mcp_timeout_secs: u64,

    /// Namespace to watch (None = all namespaces).
    pub namespace: Option<String>,

    /// Metrics server port.
    pub metrics_port: u16,

    /// Health probe port.
    pub health_port: u16,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            mcp_url: "http://intellaro-http-server:9091".to_string(),
            mcp_api_key: None,
            mcp_timeout_secs: 30,
            namespace: None,
            metrics_port: 9090,
            health_port: 8081,
        }
    }
}

impl ControllerConfig {
    /// Build configuration from environment variables with CLI flag overrides.
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(url) = std::env::var("INTELLARO_MCP_URL") {
            config.mcp_url = url;
        }
        if let Ok(key) = std::env::var("INTELLARO_MCP_API_KEY") {
            config.mcp_api_key = Some(key);
        }
        if let Ok(val) = std::env::var("INTELLARO_MCP_TIMEOUT") {
            if let Ok(secs) = val.parse::<u64>() {
                config.mcp_timeout_secs = secs;
            }
        }
        if let Ok(ns) = std::env::var("INTELLARO_NAMESPACE") {
            if !ns.is_empty() {
                config.namespace = Some(ns);
            }
        }
        if let Ok(val) = std::env::var("INTELLARO_METRICS_PORT") {
            if let Ok(port) = val.parse::<u16>() {
                config.metrics_port = port;
            }
        }
        if let Ok(val) = std::env::var("INTELLARO_HEALTH_PORT") {
            if let Ok(port) = val.parse::<u16>() {
                config.health_port = port;
            }
        }

        config
    }
}
