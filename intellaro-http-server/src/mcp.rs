//! MCP (Management Control Plane) server and API management module.
//!
//! Provides a REST API for dynamic runtime configuration, health status,
//! cache management, cluster operations, and Swagger/OpenAPI documentation.

use std::net::SocketAddr;
use std::sync::Arc;

use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use serde::Serialize;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::config::{ConfigManager, ManagementApiConfig};
use crate::server::BoxBody;

/// Represents a standard JSON API response envelope.
#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// MCP server state.
pub struct McpServer {
    config_manager: ConfigManager,
    api_key: Option<String>,
}

impl McpServer {
    /// Create a new MCP server instance.
    pub fn new(config_manager: ConfigManager, mcp_config: &ManagementApiConfig) -> Self {
        Self {
            config_manager,
            api_key: mcp_config.api_key.clone(),
        }
    }

    /// Start the MCP management API server.
    pub async fn serve(
        self: Arc<Self>,
        address: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(address).await?;
        info!(%address, "MCP management API server listening");

        loop {
            let (stream, _peer_addr) = listener.accept().await?;
            let mcp = Arc::clone(&self);

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let mcp = Arc::clone(&mcp);
                    async move { mcp.handle_request(req).await }
                });

                if let Err(err) = ConnectionBuilder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await
                {
                    error!(%err, "MCP connection error");
                }
            });
        }
    }

    /// Route incoming MCP API requests to the appropriate handler.
    async fn handle_request(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody>, hyper::Error> {
        // Authenticate the request if an API key is configured.
        if let Some(ref expected_key) = self.api_key {
            let provided_key = req
                .headers()
                .get("x-api-key")
                .and_then(|v| v.to_str().ok());

            match provided_key {
                Some(key) if key == expected_key => {}
                _ => {
                    return Ok(json_response(
                        StatusCode::UNAUTHORIZED,
                        &ApiResponse::<()> {
                            success: false,
                            data: None,
                            error: Some("Invalid or missing API key".to_string()),
                        },
                    ));
                }
            }
        }

        let path = req.uri().path().to_string();
        let method = req.method().clone();

        let response = match (method, path.as_str()) {
            // Health & status
            (Method::GET, "/api/v1/health") => self.handle_health().await,
            (Method::GET, "/api/v1/status") => self.handle_status().await,

            // Configuration management
            (Method::GET, "/api/v1/config") => self.handle_get_config().await,
            (Method::PUT, "/api/v1/config") => self.handle_update_config(req).await,
            (Method::POST, "/api/v1/config/reload") => self.handle_reload_config().await,

            // Cache management
            (Method::DELETE, "/api/v1/cache") => self.handle_purge_cache().await,
            (Method::DELETE, _) if path.starts_with("/api/v1/cache/") => {
                let key = &path["/api/v1/cache/".len()..];
                self.handle_invalidate_cache(key).await
            }

            // OpenAPI spec
            (Method::GET, "/api/v1/openapi.json") => self.handle_openapi_spec().await,

            // 404 for unknown routes
            _ => json_response(
                StatusCode::NOT_FOUND,
                &ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some(format!("Route not found: {}", req.uri().path())),
                },
            ),
        };

        Ok(response)
    }

    /// GET /api/v1/health — simple health check.
    async fn handle_health(&self) -> Response<BoxBody> {
        #[derive(Serialize)]
        struct Health {
            status: &'static str,
        }

        json_response(
            StatusCode::OK,
            &ApiResponse {
                success: true,
                data: Some(Health { status: "healthy" }),
                error: None,
            },
        )
    }

    /// GET /api/v1/status — detailed server status.
    async fn handle_status(&self) -> Response<BoxBody> {
        #[derive(Serialize)]
        struct Status {
            version: &'static str,
            uptime_notice: &'static str,
            listeners: usize,
            upstreams: usize,
            cache_enabled: bool,
        }

        let config = self.config_manager.get().await;

        json_response(
            StatusCode::OK,
            &ApiResponse {
                success: true,
                data: Some(Status {
                    version: env!("CARGO_PKG_VERSION"),
                    uptime_notice: "See metrics endpoint for uptime",
                    listeners: config.listeners.len(),
                    upstreams: config.upstreams.len(),
                    cache_enabled: config.cache.enabled,
                }),
                error: None,
            },
        )
    }

    /// GET /api/v1/config — return the current configuration.
    async fn handle_get_config(&self) -> Response<BoxBody> {
        let config = self.config_manager.get().await;
        json_response(
            StatusCode::OK,
            &ApiResponse {
                success: true,
                data: Some(config),
                error: None,
            },
        )
    }

    /// PUT /api/v1/config — update the running configuration.
    async fn handle_update_config(&self, _req: Request<Incoming>) -> Response<BoxBody> {
        // TODO: Parse body into ServerConfig and apply via config_manager.apply_update().
        json_response(
            StatusCode::NOT_IMPLEMENTED,
            &ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Runtime config update not yet implemented".to_string()),
            },
        )
    }

    /// POST /api/v1/config/reload — reload configuration from disk.
    async fn handle_reload_config(&self) -> Response<BoxBody> {
        match self.config_manager.reload().await {
            Ok(()) => json_response(
                StatusCode::OK,
                &ApiResponse {
                    success: true,
                    data: Some("Configuration reloaded"),
                    error: None,
                },
            ),
            Err(err) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some(err.to_string()),
                },
            ),
        }
    }

    /// DELETE /api/v1/cache — purge the entire cache.
    async fn handle_purge_cache(&self) -> Response<BoxBody> {
        // TODO: Call cache_layer.purge() when accessible from MCP context.
        json_response(
            StatusCode::OK,
            &ApiResponse {
                success: true,
                data: Some("Cache purge requested"),
                error: None,
            },
        )
    }

    /// DELETE /api/v1/cache/:key — invalidate a specific cache entry.
    async fn handle_invalidate_cache(&self, key: &str) -> Response<BoxBody> {
        // TODO: Call cache_layer.invalidate(key) when accessible from MCP context.
        json_response(
            StatusCode::OK,
            &ApiResponse {
                success: true,
                data: Some(format!("Cache entry '{}' invalidation requested", key)),
                error: None,
            },
        )
    }

    /// GET /api/v1/openapi.json — return the OpenAPI specification.
    async fn handle_openapi_spec(&self) -> Response<BoxBody> {
        let spec = serde_json::json!({
            "openapi": "3.0.3",
            "info": {
                "title": "Intellaro HTTP Server Management API",
                "version": env!("CARGO_PKG_VERSION"),
                "description": "Management Control Plane for Intellaro HTTP Server"
            },
            "paths": {
                "/api/v1/health": {
                    "get": {
                        "summary": "Health check",
                        "responses": { "200": { "description": "Server is healthy" } }
                    }
                },
                "/api/v1/status": {
                    "get": {
                        "summary": "Server status",
                        "responses": { "200": { "description": "Detailed server status" } }
                    }
                },
                "/api/v1/config": {
                    "get": {
                        "summary": "Get current configuration",
                        "responses": { "200": { "description": "Current server configuration" } }
                    },
                    "put": {
                        "summary": "Update running configuration",
                        "responses": { "200": { "description": "Configuration updated" } }
                    }
                },
                "/api/v1/config/reload": {
                    "post": {
                        "summary": "Reload configuration from disk",
                        "responses": { "200": { "description": "Configuration reloaded" } }
                    }
                },
                "/api/v1/cache": {
                    "delete": {
                        "summary": "Purge entire cache",
                        "responses": { "200": { "description": "Cache purged" } }
                    }
                }
            }
        });

        json_response(
            StatusCode::OK,
            &spec,
        )
    }
}

/// Helper: serialize a value to a JSON response.
fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response<BoxBody> {
    let json_bytes = serde_json::to_vec(body).unwrap_or_default();

    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(BoxBody::new(hyper::body::Bytes::from(json_bytes)))
        .unwrap()
}
