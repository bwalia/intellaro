//! MCP (Management Control Plane) server and API management module.
//!
//! Provides a REST API for dynamic runtime configuration, health status,
//! cache management, cluster operations, system diagnostics, and a
//! self-contained health status dashboard.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Instant;

use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use serde::Serialize;
use sysinfo::{Disks, System};
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
    start_time: Instant,
}

impl McpServer {
    /// Create a new MCP server instance.
    pub fn new(config_manager: ConfigManager, mcp_config: &ManagementApiConfig) -> Self {
        Self {
            config_manager,
            api_key: mcp_config.api_key.clone(),
            start_time: Instant::now(),
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
        let path = req.uri().path().to_string();
        let method = req.method().clone();

        // Serve dashboard and CORS preflight without authentication.
        if method == Method::GET && path == "/dashboard" {
            return Ok(self.handle_dashboard_page());
        }
        if method == Method::OPTIONS {
            return Ok(cors_preflight());
        }

        // Authenticate API endpoints if an API key is configured.
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

        let response = match (method, path.as_str()) {
            // Health & status
            (Method::GET, "/api/v1/health") => self.handle_health().await,
            (Method::GET, "/api/v1/status") => self.handle_status().await,
            (Method::GET, "/api/v1/system") => self.handle_system_info().await,
            (Method::GET, "/api/v1/services") => self.handle_services_check().await,

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

    /// GET /api/v1/status — detailed server status with config summary.
    async fn handle_status(&self) -> Response<BoxBody> {
        let config = self.config_manager.get().await;
        let uptime_secs = self.start_time.elapsed().as_secs();

        let data = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_secs": uptime_secs,
            "listeners": config.listeners.len(),
            "upstreams": config.upstreams.len(),
            "cache": {
                "enabled": config.cache.enabled,
                "max_entries": config.cache.max_entries,
                "default_ttl_secs": config.cache.default_ttl_secs,
                "cache_post": config.cache.cache_post,
            },
            "rate_limit": config.security.rate_limit.as_ref().map(|rl| {
                serde_json::json!({
                    "max_requests": rl.max_requests,
                    "window_secs": rl.window_secs,
                })
            }),
            "worker_count": config.worker_count,
        });

        json_response(
            StatusCode::OK,
            &ApiResponse {
                success: true,
                data: Some(data),
                error: None,
            },
        )
    }

    /// GET /api/v1/system — system resource information (CPU, memory, disk, network).
    async fn handle_system_info(&self) -> Response<BoxBody> {
        let mut sys = System::new_all();
        sys.refresh_all();

        let disks = Disks::new_with_refreshed_list();

        // Server uptime
        let uptime_secs = self.start_time.elapsed().as_secs();
        let uptime_days = uptime_secs / 86400;
        let uptime_hours = (uptime_secs % 86400) / 3600;
        let uptime_minutes = (uptime_secs % 3600) / 60;
        let uptime_str = format!("{}d {}h {}m", uptime_days, uptime_hours, uptime_minutes);

        // Hostname
        let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());

        // Primary IP via UDP socket trick (no packets sent)
        let ip_address = UdpSocket::bind("0.0.0.0:0")
            .and_then(|socket| {
                socket.connect("8.8.8.8:53")?;
                socket.local_addr()
            })
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        // CPU info
        let cpu_count = sys.cpus().len();
        let cpu_usage: f32 = if cpu_count > 0 {
            sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>() / cpu_count as f32
        } else {
            0.0
        };
        let cpu_brand = sys
            .cpus()
            .first()
            .map(|c| c.brand().to_string())
            .unwrap_or_default();

        // Memory info (bytes)
        let total_memory = sys.total_memory();
        let used_memory = sys.used_memory();
        let available_memory = sys.available_memory();

        // Disk info
        let disk_info: Vec<serde_json::Value> = disks
            .iter()
            .map(|d| {
                serde_json::json!({
                    "mount_point": d.mount_point().to_string_lossy(),
                    "total_bytes": d.total_space(),
                    "available_bytes": d.available_space(),
                    "used_bytes": d.total_space().saturating_sub(d.available_space()),
                    "filesystem": d.file_system().to_string_lossy(),
                })
            })
            .collect();

        // Listener port bindings from config
        let config = self.config_manager.get().await;
        let listeners: Vec<serde_json::Value> = config
            .listeners
            .iter()
            .map(|l| {
                serde_json::json!({
                    "address": l.address.to_string(),
                    "protocol": l.protocol,
                    "tls": l.tls.is_some(),
                })
            })
            .collect();

        // OS info
        let os_name = System::name().unwrap_or_else(|| "unknown".to_string());
        let os_version = System::os_version().unwrap_or_else(|| "unknown".to_string());
        let kernel_version = System::kernel_version().unwrap_or_else(|| "unknown".to_string());

        let data = serde_json::json!({
            "hostname": hostname,
            "ip_address": ip_address,
            "os": format!("{} {}", os_name, os_version),
            "kernel": kernel_version,
            "uptime": uptime_str,
            "uptime_secs": uptime_secs,
            "cpu": {
                "count": cpu_count,
                "brand": cpu_brand,
                "usage_percent": (cpu_usage * 100.0).round() / 100.0,
            },
            "memory": {
                "total_bytes": total_memory,
                "used_bytes": used_memory,
                "available_bytes": available_memory,
            },
            "disks": disk_info,
            "listeners": listeners,
        });

        json_response(
            StatusCode::OK,
            &ApiResponse {
                success: true,
                data: Some(data),
                error: None,
            },
        )
    }

    /// GET /api/v1/services — health check all upstream backends and infrastructure.
    async fn handle_services_check(&self) -> Response<BoxBody> {
        let config = self.config_manager.get().await;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap_or_default();

        let mut services = Vec::new();

        // Check all upstream backends
        for upstream in &config.upstreams {
            for server in &upstream.servers {
                let health_path = upstream
                    .health_check
                    .as_ref()
                    .map(|hc| hc.path.as_str())
                    .unwrap_or("/");

                let url = format!("http://{}{}", server.address, health_path);
                let status = match client.get(&url).send().await {
                    Ok(resp) if resp.status().is_success() => "healthy",
                    Ok(_) => "degraded",
                    Err(_) => "unhealthy",
                };

                services.push(serde_json::json!({
                    "name": format!("{}/{}", upstream.name, server.address),
                    "type": "backend",
                    "address": server.address,
                    "status": status,
                    "upstream": upstream.name,
                    "load_balancing": upstream.load_balancing,
                }));
            }
        }

        // Check Prometheus
        let prom_status = match client.get("http://prometheus:9090/-/healthy").send().await {
            Ok(resp) if resp.status().is_success() => "healthy",
            Ok(_) => "degraded",
            Err(_) => "unreachable",
        };
        services.push(serde_json::json!({
            "name": "prometheus",
            "type": "infrastructure",
            "address": "prometheus:9090",
            "status": prom_status,
        }));

        // Check Grafana
        let grafana_status = match client.get("http://grafana:3000/api/health").send().await {
            Ok(resp) if resp.status().is_success() => "healthy",
            Ok(_) => "degraded",
            Err(_) => "unreachable",
        };
        services.push(serde_json::json!({
            "name": "grafana",
            "type": "infrastructure",
            "address": "grafana:3000",
            "status": grafana_status,
        }));

        json_response(
            StatusCode::OK,
            &ApiResponse {
                success: true,
                data: Some(services),
                error: None,
            },
        )
    }

    /// GET /dashboard — serve the self-contained health status dashboard HTML.
    fn handle_dashboard_page(&self) -> Response<BoxBody> {
        let html = include_str!("../static/dashboard.html");
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(BoxBody::new(hyper::body::Bytes::from(html)))
            .unwrap()
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
                        "description": "Returns version, uptime, listener/upstream counts, cache and rate-limit config",
                        "responses": { "200": { "description": "Detailed server status" } }
                    }
                },
                "/api/v1/system": {
                    "get": {
                        "summary": "System information",
                        "description": "Returns CPU, memory, disk, hostname, IP, uptime, and port bindings",
                        "responses": { "200": { "description": "System resource information" } }
                    }
                },
                "/api/v1/services": {
                    "get": {
                        "summary": "Service health checks",
                        "description": "Probes all upstream backends and infrastructure services",
                        "responses": { "200": { "description": "Array of service health statuses" } }
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
                },
                "/dashboard": {
                    "get": {
                        "summary": "Health status dashboard",
                        "description": "Self-contained HTML dashboard showing system health and status",
                        "responses": { "200": { "description": "HTML page" } }
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

/// Helper: serialize a value to a JSON response with CORS headers.
fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response<BoxBody> {
    let json_bytes = serde_json::to_vec(body).unwrap_or_default();

    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "X-Api-Key, Content-Type")
        .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        .body(BoxBody::new(hyper::body::Bytes::from(json_bytes)))
        .unwrap()
}

/// Helper: CORS preflight response for OPTIONS requests.
fn cors_preflight() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "X-Api-Key, Content-Type")
        .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        .header("Access-Control-Max-Age", "86400")
        .body(BoxBody::new(hyper::body::Bytes::new()))
        .unwrap()
}
