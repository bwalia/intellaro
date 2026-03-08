//! Reverse proxy and load balancer module.
//!
//! Supports multiple load-balancing strategies (round-robin, least-connections,
//! weighted, sticky sessions) with active health checking and failover.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use hyper::body::Incoming;
use hyper::{Request, Response};
use reqwest::Client;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::{BackendServer, HealthCheckConfig, UpstreamConfig};
use crate::server::BoxBody;

/// Health state of a backend server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
}

/// Runtime state for a single backend server.
#[derive(Debug)]
pub struct BackendState {
    pub server: BackendServer,
    pub status: RwLock<HealthStatus>,
    pub active_connections: AtomicUsize,
}

/// Runtime state for an upstream group.
pub struct UpstreamState {
    pub name: String,
    pub backends: Vec<Arc<BackendState>>,
    pub strategy: String,
    pub round_robin_index: AtomicUsize,
    pub health_check: Option<HealthCheckConfig>,
}

/// The proxy engine manages all upstream groups and performs request forwarding.
pub struct ProxyEngine {
    upstreams: DashMap<String, Arc<UpstreamState>>,
    http_client: Client,
}

impl ProxyEngine {
    /// Create a new proxy engine from upstream configuration.
    pub fn new(upstream_configs: &[UpstreamConfig]) -> Self {
        let upstreams = DashMap::new();

        for config in upstream_configs {
            let backends: Vec<Arc<BackendState>> = config
                .servers
                .iter()
                .map(|server| {
                    Arc::new(BackendState {
                        server: server.clone(),
                        status: RwLock::new(HealthStatus::Healthy),
                        active_connections: AtomicUsize::new(0),
                    })
                })
                .collect();

            let state = Arc::new(UpstreamState {
                name: config.name.clone(),
                backends,
                strategy: config.load_balancing.clone(),
                round_robin_index: AtomicUsize::new(0),
                health_check: config.health_check.clone(),
            });

            upstreams.insert(config.name.clone(), state);
        }

        let http_client = Client::builder()
            .pool_max_idle_per_host(100)
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to build HTTP client");

        info!(
            upstream_count = upstream_configs.len(),
            "Proxy engine initialized"
        );

        Self {
            upstreams,
            http_client,
        }
    }

    /// Forward a request to an appropriate upstream backend.
    ///
    /// Uses the `Host` header or first available upstream to route the request.
    pub async fn forward(
        &self,
        req: &Request<Incoming>,
    ) -> Result<Response<BoxBody>, ProxyError> {
        let upstream_name = self.resolve_upstream(req);

        let upstream = self
            .upstreams
            .get(&upstream_name)
            .ok_or_else(|| ProxyError::NoUpstream(upstream_name.clone()))?;

        let backend = self.select_backend(&upstream)?;

        let target_url = format!(
            "http://{}{}",
            backend.server.address,
            req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/")
        );

        backend.active_connections.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("proxy_requests_total", "upstream" => upstream_name.clone()).increment(1);

        let result = self
            .http_client
            .request(
                req.method().clone(),
                &target_url,
            )
            .headers(clone_headers(req.headers()))
            .send()
            .await;

        backend.active_connections.fetch_sub(1, Ordering::Relaxed);

        match result {
            Ok(resp) => {
                let status = resp.status();
                let headers = resp.headers().clone();
                let body_bytes = resp
                    .bytes()
                    .await
                    .map_err(|err| ProxyError::BackendError(err.to_string()))?;

                let mut builder = Response::builder().status(status);
                for (key, value) in headers.iter() {
                    builder = builder.header(key, value);
                }

                builder
                    .body(BoxBody::new(hyper::body::Bytes::from(body_bytes.to_vec())))
                    .map_err(|err| ProxyError::BackendError(err.to_string()))
            }
            Err(err) => Err(ProxyError::BackendError(err.to_string())),
        }
    }

    /// Resolve which upstream group should handle this request.
    pub fn resolve_upstream(&self, req: &Request<Incoming>) -> String {
        // Default strategy: use Host header or fall back to first upstream.
        if let Some(host) = req.headers().get("host").and_then(|h| h.to_str().ok()) {
            if self.upstreams.contains_key(host) {
                return host.to_string();
            }
        }

        // Fall back to the first registered upstream.
        self.upstreams
            .iter()
            .next()
            .map(|entry| entry.key().clone())
            .unwrap_or_default()
    }

    /// Select a backend from an upstream using the configured strategy.
    fn select_backend(
        &self,
        upstream: &UpstreamState,
    ) -> Result<Arc<BackendState>, ProxyError> {
        let healthy_backends: Vec<Arc<BackendState>> = upstream
            .backends
            .iter()
            .filter(|b| {
                // Only use a synchronous try_read to avoid blocking
                b.status
                    .try_read()
                    .map(|s| *s == HealthStatus::Healthy)
                    .unwrap_or(false)
            })
            .cloned()
            .collect();

        if healthy_backends.is_empty() {
            return Err(ProxyError::NoHealthyBackend(upstream.name.clone()));
        }

        match upstream.strategy.as_str() {
            "round_robin" => {
                let index = upstream
                    .round_robin_index
                    .fetch_add(1, Ordering::Relaxed)
                    % healthy_backends.len();
                Ok(healthy_backends[index].clone())
            }
            "least_connections" => {
                let selected = healthy_backends
                    .iter()
                    .min_by_key(|b| b.active_connections.load(Ordering::Relaxed))
                    .unwrap();
                Ok(selected.clone())
            }
            "weighted" => {
                // Weighted round-robin: expand entries by weight, then round-robin.
                let total_weight: u32 = healthy_backends.iter().map(|b| b.server.weight).sum();
                let index = upstream
                    .round_robin_index
                    .fetch_add(1, Ordering::Relaxed)
                    % total_weight as usize;

                let mut cumulative: u32 = 0;
                for backend in &healthy_backends {
                    cumulative += backend.server.weight;
                    if index < cumulative as usize {
                        return Ok(backend.clone());
                    }
                }

                Ok(healthy_backends.last().unwrap().clone())
            }
            _ => {
                // Default to round-robin for unknown strategies.
                let index = upstream
                    .round_robin_index
                    .fetch_add(1, Ordering::Relaxed)
                    % healthy_backends.len();
                Ok(healthy_backends[index].clone())
            }
        }
    }

    /// Forward a request to a specific backend address (used by the routing engine).
    pub async fn forward_to(
        &self,
        req: &Request<Incoming>,
        backend_address: &str,
    ) -> Result<Response<BoxBody>, ProxyError> {
        let target_url = format!(
            "http://{}{}",
            backend_address,
            req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/")
        );

        metrics::counter!("proxy_requests_total", "backend" => backend_address.to_string())
            .increment(1);

        let result = self
            .http_client
            .request(req.method().clone(), &target_url)
            .headers(clone_headers(req.headers()))
            .send()
            .await;

        match result {
            Ok(resp) => {
                let status = resp.status();
                let headers = resp.headers().clone();
                let body_bytes = resp
                    .bytes()
                    .await
                    .map_err(|err| ProxyError::BackendError(err.to_string()))?;

                let mut builder = Response::builder().status(status);
                for (key, value) in headers.iter() {
                    builder = builder.header(key, value);
                }

                builder
                    .body(BoxBody::new(hyper::body::Bytes::from(body_bytes.to_vec())))
                    .map_err(|err| ProxyError::BackendError(err.to_string()))
            }
            Err(err) => Err(ProxyError::BackendError(err.to_string())),
        }
    }

    /// Start background health checks for all upstreams.
    pub fn start_health_checks(self: &Arc<Self>) {
        for entry in self.upstreams.iter() {
            let upstream = entry.value().clone();

            if let Some(ref hc_config) = upstream.health_check {
                let client = self.http_client.clone();
                let interval = Duration::from_secs(hc_config.interval_secs);
                let path = hc_config.path.clone();
                let threshold = hc_config.unhealthy_threshold;

                tokio::spawn(async move {
                    health_check_loop(upstream, client, interval, path, threshold).await;
                });
            }
        }
    }
}

/// Continuous health check loop for one upstream group.
async fn health_check_loop(
    upstream: Arc<UpstreamState>,
    client: Client,
    interval: Duration,
    path: String,
    unhealthy_threshold: u32,
) {
    let mut failure_counts: Vec<u32> = vec![0; upstream.backends.len()];

    loop {
        tokio::time::sleep(interval).await;

        for (i, backend) in upstream.backends.iter().enumerate() {
            let url = format!("http://{}{}", backend.server.address, path);

            let is_healthy = match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => true,
                _ => false,
            };

            if is_healthy {
                failure_counts[i] = 0;
                let mut status = backend.status.write().await;
                if *status == HealthStatus::Unhealthy {
                    info!(
                        backend = %backend.server.address,
                        upstream = %upstream.name,
                        "Backend recovered"
                    );
                }
                *status = HealthStatus::Healthy;
            } else {
                failure_counts[i] += 1;
                if failure_counts[i] >= unhealthy_threshold {
                    let mut status = backend.status.write().await;
                    if *status == HealthStatus::Healthy {
                        warn!(
                            backend = %backend.server.address,
                            upstream = %upstream.name,
                            failures = failure_counts[i],
                            "Backend marked unhealthy"
                        );
                    }
                    *status = HealthStatus::Unhealthy;
                }
            }
        }
    }
}

/// Clone hyper headers into a reqwest HeaderMap.
fn clone_headers(headers: &hyper::HeaderMap) -> reqwest::header::HeaderMap {
    let mut map = reqwest::header::HeaderMap::new();
    for (key, value) in headers.iter() {
        if let Ok(name) = reqwest::header::HeaderName::from_bytes(key.as_str().as_bytes()) {
            if let Ok(val) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                map.insert(name, val);
            }
        }
    }
    map
}

/// Proxy-related errors.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("No upstream configured for: {0}")]
    NoUpstream(String),

    #[error("No healthy backend in upstream: {0}")]
    NoHealthyBackend(String),

    #[error("Backend communication error: {0}")]
    BackendError(String),
}

impl std::fmt::Display for ProxyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProxyEngine({} upstreams)", self.upstreams.len())
    }
}
