//! MCP client for communicating with `intellaro-http-server`.
//!
//! The controller uses this client to push reconciled configuration
//! (derived from CRDs) to the running server instances via their
//! Management Control Plane REST API.

use std::time::Duration;

use serde::{de::DeserializeOwned, Deserialize};
use tracing::{debug, warn};

use crate::error::{IngressError, IngressResult};

/// Envelope returned by the MCP API.
#[derive(Debug, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

/// HTTP client for the intellaro-http-server MCP API.
#[derive(Clone)]
pub struct McpClient {
    client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
}

impl McpClient {
    /// Create a new MCP client targeting the given server instance.
    pub fn new(base_url: &str, api_key: Option<String>, timeout_secs: u64) -> IngressResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| IngressError::McpError(format!("Failed to build HTTP client: {e}")))?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key,
        })
    }

    /// Return the base URL for display / logging.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    // ── Health ───────────────────────────────────────────────────────

    /// Check if the server is reachable.
    pub async fn health(&self) -> IngressResult<bool> {
        let resp = self.get::<serde_json::Value>("/api/v1/health").await;
        Ok(resp.is_ok())
    }

    // ── Configuration ───────────────────────────────────────────────

    /// Fetch the full server configuration.
    pub async fn get_config(&self) -> IngressResult<serde_json::Value> {
        self.get("/api/v1/config").await
    }

    /// Push a full configuration update.
    pub async fn update_config(&self, config: &serde_json::Value) -> IngressResult<serde_json::Value> {
        self.put("/api/v1/config", config).await
    }

    /// Trigger a hot-reload of the server configuration.
    pub async fn reload(&self) -> IngressResult<serde_json::Value> {
        self.post("/api/v1/config/reload", &serde_json::json!({})).await
    }

    // ── Cache ───────────────────────────────────────────────────────

    /// Purge the entire cache.
    pub async fn purge_cache(&self) -> IngressResult<serde_json::Value> {
        self.delete("/api/v1/cache").await
    }

    /// Invalidate a single cache entry.
    pub async fn invalidate_cache(&self, key: &str) -> IngressResult<serde_json::Value> {
        self.delete(&format!("/api/v1/cache/{key}")).await
    }

    // ── Internal HTTP helpers ───────────────────────────────────────

    /// Send a GET request and parse the API envelope.
    async fn get<T: DeserializeOwned>(&self, path: &str) -> IngressResult<T> {
        let url = format!("{}{}", self.base_url, path);
        debug!(url = %url, "MCP GET");

        let mut req = self.client.get(&url);
        req = self.apply_auth(req);

        let resp = req.send().await.map_err(|e| {
            warn!(url = %url, error = %e, "MCP request failed");
            IngressError::McpError(format!("GET {url}: {e}"))
        })?;

        self.parse_response(resp).await
    }

    /// Send a PUT request and parse the API envelope.
    async fn put<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> IngressResult<T> {
        let url = format!("{}{}", self.base_url, path);
        debug!(url = %url, "MCP PUT");

        let mut req = self.client.put(&url).json(body);
        req = self.apply_auth(req);

        let resp = req.send().await.map_err(|e| {
            warn!(url = %url, error = %e, "MCP request failed");
            IngressError::McpError(format!("PUT {url}: {e}"))
        })?;

        self.parse_response(resp).await
    }

    /// Send a POST request and parse the API envelope.
    async fn post<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> IngressResult<T> {
        let url = format!("{}{}", self.base_url, path);
        debug!(url = %url, "MCP POST");

        let mut req = self.client.post(&url).json(body);
        req = self.apply_auth(req);

        let resp = req.send().await.map_err(|e| {
            warn!(url = %url, error = %e, "MCP request failed");
            IngressError::McpError(format!("POST {url}: {e}"))
        })?;

        self.parse_response(resp).await
    }

    /// Send a DELETE request and parse the API envelope.
    async fn delete<T: DeserializeOwned>(&self, path: &str) -> IngressResult<T> {
        let url = format!("{}{}", self.base_url, path);
        debug!(url = %url, "MCP DELETE");

        let mut req = self.client.delete(&url);
        req = self.apply_auth(req);

        let resp = req.send().await.map_err(|e| {
            warn!(url = %url, error = %e, "MCP request failed");
            IngressError::McpError(format!("DELETE {url}: {e}"))
        })?;

        self.parse_response(resp).await
    }

    /// Attach authentication headers.
    fn apply_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.api_key {
            Some(key) => req.header("x-api-key", key),
            None => req,
        }
    }

    /// Parse the standard API response envelope.
    async fn parse_response<T: DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> IngressResult<T> {
        let status = resp.status().as_u16();
        let body = resp.text().await.map_err(|e| {
            IngressError::McpError(format!("Failed to read response body: {e}"))
        })?;

        let envelope: ApiResponse<T> = serde_json::from_str(&body).map_err(|e| {
            IngressError::McpError(format!("Failed to parse response: {e} — body: {body}"))
        })?;

        if envelope.success {
            envelope.data.ok_or_else(|| {
                IngressError::McpError("Server returned success but no data".to_string())
            })
        } else {
            Err(IngressError::McpError(format!(
                "Server error ({}): {}",
                status,
                envelope.error.unwrap_or_else(|| "Unknown error".to_string())
            )))
        }
    }
}
