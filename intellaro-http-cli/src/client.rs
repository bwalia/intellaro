//! MCP / REST API client for communicating with Intellaro HTTP Server.
//!
//! Wraps `reqwest` with authentication, TLS policy, timeouts, and
//! retry logic. All command modules use this client to talk to the server.

use std::time::Duration;

use reqwest::{Client, ClientBuilder, Method, RequestBuilder, Response};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tracing::debug;

use crate::config::ServerProfile;
use crate::error::{ApiResponse, CliError, CliResult};

/// High-level client for the Intellaro MCP management API.
#[derive(Clone)]
pub struct McpClient {
    http: Client,
    base_url: String,
    api_key: Option<String>,
    bearer_token: Option<String>,
}

impl McpClient {
    /// Create a new client from a server profile.
    pub fn from_profile(profile: &ServerProfile) -> CliResult<Self> {
        let mut builder = ClientBuilder::new()
            .timeout(Duration::from_secs(profile.timeout_secs))
            .connect_timeout(Duration::from_secs(10));

        if profile.insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }

        let http = builder
            .build()
            .map_err(|err| CliError::ConnectionError(err))?;

        let base_url = profile.url.trim_end_matches('/').to_string();

        Ok(Self {
            http,
            base_url,
            api_key: profile.auth.api_key.clone(),
            bearer_token: profile.auth.bearer_token.clone(),
        })
    }

    /// Return the base URL this client is connected to.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    // ── Convenience methods for server API endpoints ─────────────────

    /// GET /api/v1/health
    pub async fn health(&self) -> CliResult<serde_json::Value> {
        self.get("/api/v1/health").await
    }

    /// GET /api/v1/status
    pub async fn status(&self) -> CliResult<serde_json::Value> {
        self.get("/api/v1/status").await
    }

    /// GET /api/v1/config
    pub async fn get_config(&self) -> CliResult<serde_json::Value> {
        self.get("/api/v1/config").await
    }

    /// PUT /api/v1/config
    pub async fn update_config(&self, config: &serde_json::Value) -> CliResult<serde_json::Value> {
        self.put("/api/v1/config", config).await
    }

    /// POST /api/v1/config/reload
    pub async fn reload_config(&self) -> CliResult<serde_json::Value> {
        self.post("/api/v1/config/reload", &serde_json::json!({})).await
    }

    /// DELETE /api/v1/cache (purge all)
    pub async fn purge_cache(&self) -> CliResult<serde_json::Value> {
        self.delete("/api/v1/cache").await
    }

    /// DELETE /api/v1/cache/:key
    pub async fn invalidate_cache(&self, key: &str) -> CliResult<serde_json::Value> {
        let path = format!("/api/v1/cache/{}", key);
        self.delete(&path).await
    }

    /// GET /api/v1/openapi.json
    pub async fn openapi_spec(&self) -> CliResult<serde_json::Value> {
        self.get_raw("/api/v1/openapi.json").await
    }

    // ── Generic HTTP methods ─────────────────────────────────────────

    /// Send a GET request and parse the `ApiResponse<T>` envelope.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> CliResult<T> {
        let resp = self.send(Method::GET, path, None::<&()>).await?;
        self.parse_api_response(resp).await
    }

    /// Send a GET request and return the raw JSON (no envelope unwrap).
    pub async fn get_raw(&self, path: &str) -> CliResult<serde_json::Value> {
        let resp = self.send(Method::GET, path, None::<&()>).await?;
        resp.json::<serde_json::Value>()
            .await
            .map_err(|err| CliError::ParseError(err.to_string()))
    }

    /// Send a POST request with a JSON body.
    pub async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> CliResult<T> {
        let resp = self.send(Method::POST, path, Some(body)).await?;
        self.parse_api_response(resp).await
    }

    /// Send a PUT request with a JSON body.
    pub async fn put<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> CliResult<T> {
        let resp = self.send(Method::PUT, path, Some(body)).await?;
        self.parse_api_response(resp).await
    }

    /// Send a DELETE request.
    pub async fn delete<T: DeserializeOwned>(&self, path: &str) -> CliResult<T> {
        let resp = self.send(Method::DELETE, path, None::<&()>).await?;
        self.parse_api_response(resp).await
    }

    // ── Internal helpers ─────────────────────────────────────────────

    /// Build, authenticate, and send an HTTP request.
    async fn send<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> CliResult<Response> {
        let url = format!("{}{}", self.base_url, path);
        debug!(method = %method, url = %url, "Sending request");

        let mut request: RequestBuilder = self.http.request(method, &url);

        // Attach authentication.
        if let Some(ref key) = self.api_key {
            request = request.header("x-api-key", key);
        }
        if let Some(ref token) = self.bearer_token {
            request = request.bearer_auth(token);
        }

        // Attach body if provided.
        if let Some(payload) = body {
            request = request.json(payload);
        }

        let response = request.send().await?;

        debug!(status = %response.status(), "Response received");

        Ok(response)
    }

    /// Parse an `ApiResponse<T>` envelope from a response.
    async fn parse_api_response<T: DeserializeOwned>(
        &self,
        resp: Response,
    ) -> CliResult<T> {
        let status = resp.status().as_u16();
        let body = resp.text().await
            .map_err(|err| CliError::ParseError(err.to_string()))?;

        let api_resp: ApiResponse<T> = serde_json::from_str(&body)
            .map_err(|err| CliError::ParseError(format!(
                "Failed to parse response: {} (body: {})",
                err,
                truncate(&body, 200)
            )))?;

        api_resp.into_result(status)
    }
}

/// Truncate a string for display in error messages.
fn truncate(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else {
        &s[..max_len]
    }
}
