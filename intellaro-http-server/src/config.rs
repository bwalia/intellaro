//! Dynamic JSON/YAML configuration module.
//!
//! Supports loading configuration from files, hot-reloading on file changes,
//! and runtime updates via the management API.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use intellaro_http_router::RouterConfig;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use crate::transform::TransformConfig;
use serde::{Deserialize, Serialize};
use tokio::sync::{watch, RwLock};
use tracing::{error, info, warn};

/// Top-level server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Listener configuration.
    pub listeners: Vec<ListenerConfig>,

    /// Worker thread count. Defaults to number of CPU cores.
    #[serde(default = "default_worker_count")]
    pub worker_count: usize,

    /// Reverse proxy / upstream configuration.
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,

    /// Cache configuration.
    #[serde(default)]
    pub cache: CacheConfig,

    /// Security policy configuration.
    #[serde(default)]
    pub security: SecurityConfig,

    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Cluster configuration.
    #[serde(default)]
    pub cluster: Option<ClusterConfig>,

    /// MCP management API configuration.
    #[serde(default)]
    pub management_api: Option<ManagementApiConfig>,

    /// Static file serving roots.
    #[serde(default)]
    pub static_roots: Vec<StaticRootConfig>,

    /// Intelligent routing engine configuration.
    #[serde(default)]
    pub router: Option<RouterConfig>,

    /// Multi-tenancy configuration.
    #[serde(default)]
    pub tenants: Vec<crate::tenant::TenantConfig>,
}

/// Listener (bind address + optional TLS).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    /// Socket address to bind (e.g., "0.0.0.0:8080").
    pub address: SocketAddr,

    /// Optional TLS configuration.
    pub tls: Option<TlsConfig>,

    /// Protocol: "http1", "http2", "auto". Defaults to "auto".
    #[serde(default = "default_protocol")]
    pub protocol: String,
}

/// TLS certificate configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the PEM certificate file.
    pub cert_path: PathBuf,

    /// Path to the PEM private key file.
    pub key_path: PathBuf,

    /// Minimum TLS version. Defaults to "1.2".
    #[serde(default = "default_tls_min_version")]
    pub min_version: String,
}

/// Upstream / backend origin configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Logical name for the upstream group.
    pub name: String,

    /// Backend servers.
    pub servers: Vec<BackendServer>,

    /// Load balancing strategy: "round_robin", "least_connections", "weighted", "sticky".
    #[serde(default = "default_lb_strategy")]
    pub load_balancing: String,

    /// Health check configuration.
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,

    /// Circuit breaker configuration.
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,

    /// Retry policy configuration.
    #[serde(default)]
    pub retry: Option<RetryConfig>,

    /// Request/response transformation configuration.
    #[serde(default)]
    pub transform: Option<TransformConfig>,
}

/// A single backend server entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendServer {
    /// Address of the backend (e.g., "127.0.0.1:3000").
    pub address: String,

    /// Relative weight for weighted load balancing. Defaults to 1.
    #[serde(default = "default_weight")]
    pub weight: u32,
}

/// Health check configuration for an upstream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Path to probe (e.g., "/healthz").
    #[serde(default = "default_health_path")]
    pub path: String,

    /// Interval between checks in seconds.
    #[serde(default = "default_health_interval")]
    pub interval_secs: u64,

    /// Number of consecutive failures before marking unhealthy.
    #[serde(default = "default_health_threshold")]
    pub unhealthy_threshold: u32,

    /// Outlier detection configuration.
    #[serde(default)]
    pub outlier_detection: Option<OutlierDetectionConfig>,
}

/// Outlier detection configuration — automatically ejects backends
/// exhibiting anomalous error rates or latency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutlierDetectionConfig {
    /// Consecutive 5xx errors before ejecting a backend.
    #[serde(default = "default_consecutive_5xx")]
    pub consecutive_5xx: u32,

    /// Base ejection time in seconds.
    #[serde(default = "default_base_ejection_time")]
    pub base_ejection_time_secs: u64,

    /// Maximum percentage of backends that can be ejected.
    #[serde(default = "default_max_ejection_percent")]
    pub max_ejection_percent: u32,

    /// Latency threshold multiplier — eject if latency exceeds N× median.
    #[serde(default = "default_latency_threshold_multiplier")]
    pub latency_threshold_multiplier: f64,
}

/// Circuit breaker configuration for an upstream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures to trip the circuit.
    #[serde(default = "default_cb_failure_threshold")]
    pub failure_threshold: u64,

    /// Duration in seconds the circuit stays open before transitioning to half-open.
    #[serde(default = "default_cb_open_duration")]
    pub open_duration_secs: u64,

    /// Maximum requests allowed through in half-open state.
    #[serde(default = "default_cb_half_open_max")]
    pub half_open_max_requests: u64,
}

/// Retry policy configuration for an upstream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts.
    #[serde(default = "default_retry_max")]
    pub max_retries: u32,

    /// HTTP status codes that trigger a retry.
    #[serde(default = "default_retry_statuses")]
    pub retry_on_status: Vec<u16>,

    /// Backoff strategy: "exponential", "linear", "constant".
    #[serde(default = "default_retry_backoff")]
    pub backoff: String,

    /// Base backoff delay in milliseconds.
    #[serde(default = "default_retry_backoff_base_ms")]
    pub backoff_base_ms: u64,
}

/// Cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CacheConfig {
    /// Enable caching.
    #[serde(default)]
    pub enabled: bool,

    /// Maximum number of cached entries.
    #[serde(default = "default_cache_max_entries")]
    pub max_entries: usize,

    /// Default TTL in seconds.
    #[serde(default = "default_cache_ttl")]
    pub default_ttl_secs: u64,

    /// Cache cacheable POST responses.
    #[serde(default)]
    pub cache_post: bool,

    /// Stale-while-revalidate window in seconds.
    /// Serves stale content while refreshing in the background.
    #[serde(default)]
    pub stale_while_revalidate_secs: u64,

    /// Stale-if-error window in seconds.
    /// Serves stale content when upstream returns an error.
    #[serde(default)]
    pub stale_if_error_secs: u64,
}

/// Security policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityConfig {
    /// IP allow list (CIDR notation).
    #[serde(default)]
    pub ip_allow: Vec<String>,

    /// IP block list (CIDR notation).
    #[serde(default)]
    pub ip_block: Vec<String>,

    /// Rate limiting configuration.
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,

    /// JWT validation configuration.
    #[serde(default)]
    pub jwt: Option<JwtConfig>,

    /// OIDC configuration (alternative to static JWT).
    #[serde(default)]
    pub oidc: Option<crate::oidc::OidcConfig>,
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per window.
    pub max_requests: u64,

    /// Window duration in seconds.
    pub window_secs: u64,
}

/// JWT validation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// HMAC secret or path to public key.
    pub secret_or_key_path: String,

    /// Expected issuer.
    pub issuer: Option<String>,

    /// Expected audience.
    pub audience: Option<String>,
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level: "trace", "debug", "info", "warn", "error".
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Output format: "json", "pretty".
    #[serde(default = "default_log_format")]
    pub format: String,

    /// Prometheus metrics endpoint path (e.g., "/metrics").
    #[serde(default)]
    pub metrics_path: Option<String>,
}

/// Cluster configuration for multi-node HA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Unique node identifier.
    pub node_id: String,

    /// Peer addresses for cluster membership.
    pub peers: Vec<String>,

    /// Cluster communication port.
    pub port: u16,
}

/// Management API configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementApiConfig {
    /// Address to bind the management API.
    pub address: SocketAddr,

    /// Optional API key for authentication.
    pub api_key: Option<String>,

    /// RBAC configuration for the management API.
    #[serde(default)]
    pub rbac: Option<crate::rbac::RbacConfig>,
}

/// Static file serving root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticRootConfig {
    /// URL path prefix (e.g., "/static").
    pub url_prefix: String,

    /// Filesystem directory to serve from.
    pub directory: PathBuf,

    /// Enable directory listing.
    #[serde(default)]
    pub directory_listing: bool,
}

// ── Default value functions ──────────────────────────────────────────

fn default_worker_count() -> usize {
    num_cpus()
}

fn default_protocol() -> String {
    "auto".to_string()
}

fn default_tls_min_version() -> String {
    "1.2".to_string()
}

fn default_lb_strategy() -> String {
    "round_robin".to_string()
}

fn default_weight() -> u32 {
    1
}

fn default_health_path() -> String {
    "/healthz".to_string()
}

fn default_health_interval() -> u64 {
    10
}

fn default_health_threshold() -> u32 {
    3
}

fn default_consecutive_5xx() -> u32 {
    5
}

fn default_base_ejection_time() -> u64 {
    30
}

fn default_max_ejection_percent() -> u32 {
    50
}

fn default_latency_threshold_multiplier() -> f64 {
    3.0
}

fn default_cb_failure_threshold() -> u64 {
    5
}

fn default_cb_open_duration() -> u64 {
    30
}

fn default_cb_half_open_max() -> u64 {
    3
}

fn default_retry_max() -> u32 {
    2
}

fn default_retry_statuses() -> Vec<u16> {
    vec![502, 503, 504]
}

fn default_retry_backoff() -> String {
    "exponential".to_string()
}

fn default_retry_backoff_base_ms() -> u64 {
    100
}

fn default_cache_max_entries() -> usize {
    10_000
}

fn default_cache_ttl() -> u64 {
    300
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            metrics_path: Some("/metrics".to_string()),
        }
    }
}

// ── Configuration loader ─────────────────────────────────────────────

/// Thread-safe, hot-reloadable configuration holder.
#[derive(Clone)]
pub struct ConfigManager {
    inner: Arc<RwLock<ServerConfig>>,
    config_path: PathBuf,
    change_tx: watch::Sender<()>,
    change_rx: watch::Receiver<()>,
}

impl ConfigManager {
    /// Load configuration from a file path.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref().to_path_buf();
        let config = Self::read_config(&path)?;
        let (change_tx, change_rx) = watch::channel(());

        info!(path = %path.display(), "Configuration loaded");

        Ok(Self {
            inner: Arc::new(RwLock::new(config)),
            config_path: path,
            change_tx,
            change_rx,
        })
    }

    /// Get a read snapshot of the current configuration.
    pub async fn get(&self) -> ServerConfig {
        self.inner.read().await.clone()
    }

    /// Subscribe to configuration change notifications.
    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.change_rx.clone()
    }

    /// Reload configuration from disk.
    pub async fn reload(&self) -> Result<(), ConfigError> {
        let new_config = Self::read_config(&self.config_path)?;
        let mut writer = self.inner.write().await;
        *writer = new_config;
        let _ = self.change_tx.send(());
        info!("Configuration reloaded");
        Ok(())
    }

    /// Apply a runtime configuration update (e.g., from the management API).
    pub async fn apply_update(&self, updated_config: ServerConfig) {
        let mut writer = self.inner.write().await;
        *writer = updated_config;
        let _ = self.change_tx.send(());
        info!("Configuration updated via API");
    }

    /// Start watching the configuration file for changes (hot reload).
    pub fn start_file_watcher(&self) -> Result<RecommendedWatcher, ConfigError> {
        let manager = self.clone();
        let watch_path = self.config_path.clone();

        let mut watcher = notify::recommended_watcher(move |result: Result<Event, _>| {
            match result {
                Ok(event) if event.kind.is_modify() => {
                    let manager = manager.clone();
                    tokio::spawn(async move {
                        if let Err(err) = manager.reload().await {
                            error!(%err, "Failed to hot-reload configuration");
                        }
                    });
                }
                Err(err) => {
                    warn!(%err, "File watcher error");
                }
                _ => {}
            }
        })
        .map_err(|err| ConfigError::WatchError(err.to_string()))?;

        watcher
            .watch(&watch_path, RecursiveMode::NonRecursive)
            .map_err(|err| ConfigError::WatchError(err.to_string()))?;

        info!(path = %watch_path.display(), "File watcher started for hot reload");

        Ok(watcher)
    }

    /// Read and parse a config file (supports .json and .yaml/.yml).
    fn read_config(path: &Path) -> Result<ServerConfig, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|err| ConfigError::IoError(err.to_string()))?;

        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("");

        match extension {
            "json" => serde_json::from_str(&content)
                .map_err(|err| ConfigError::ParseError(err.to_string())),
            "yaml" | "yml" => serde_yaml::from_str(&content)
                .map_err(|err| ConfigError::ParseError(err.to_string())),
            other => Err(ConfigError::UnsupportedFormat(other.to_string())),
        }
    }
}

// ── Errors ───────────────────────────────────────────────────────────

/// Configuration-related errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    IoError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Unsupported config format: {0}")]
    UnsupportedFormat(String),

    #[error("File watch error: {0}")]
    WatchError(String),
}
