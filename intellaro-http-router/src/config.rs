//! Router configuration types.
//!
//! All configuration is JSON/YAML serializable and can be pushed
//! via the MCP API for hot-reload without downtime.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Top-level router configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    /// Named routing rules, evaluated in priority order.
    #[serde(default)]
    pub rules: Vec<RoutingRule>,

    /// Global load balancing defaults.
    #[serde(default)]
    pub default_balancer: BalancerConfig,

    /// AI feature toggles and parameters.
    #[serde(default)]
    pub ai: AiConfig,

    /// Canary / blue-green deployment definitions.
    #[serde(default)]
    pub canary: Vec<CanaryConfig>,

    /// SLA / priority tiers.
    #[serde(default)]
    pub priority_tiers: Vec<PriorityTier>,

    /// Anomaly detection settings.
    #[serde(default)]
    pub anomaly_detection: AnomalyDetectionConfig,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default_balancer: BalancerConfig::default(),
            ai: AiConfig::default(),
            canary: Vec::new(),
            priority_tiers: Vec::new(),
            anomaly_detection: AnomalyDetectionConfig::default(),
        }
    }
}

/// A single routing rule that maps a match condition to a backend group
/// or a direct response action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    /// Human-readable name for logging and metrics.
    pub name: String,

    /// Priority (higher = evaluated first). Default: 100.
    #[serde(default = "default_priority")]
    pub priority: u32,

    /// Match conditions (all must be true for the rule to fire).
    pub r#match: MatchConfig,

    /// Target backend group name. May be empty when `action` is set
    /// (static/redirect rules never reach a backend).
    #[serde(default)]
    pub backend_group: String,

    /// Direct response action (static page or redirect) instead of
    /// proxying. WSLProxy response-code parity: 200/403 static,
    /// 301/302 redirect; absent = proxy (305).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<RuleAction>,

    /// Path prefix to strip from the request before forwarding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strip_path_prefix: Option<String>,

    /// Replacement for the stripped prefix (defaults to empty).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite_prefix_with: Option<String>,

    /// Per-rule balancer override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balancer: Option<BalancerConfig>,

    /// Per-rule timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,

    /// Request/response header manipulation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HeaderManipulation>,

    /// Whether this rule is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_priority() -> u32 {
    100
}

/// Direct response action for a routing rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleAction {
    /// Serve a static response (custom block/landing pages).
    Static {
        #[serde(default = "default_static_status")]
        status: u16,
        /// Response body, plain text/HTML.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        body: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content_type: Option<String>,
    },
    /// Redirect to a location.
    Redirect {
        location: String,
        /// 301, 302, 307, or 308. Default: 302.
        #[serde(default = "default_redirect_status")]
        status: u16,
    },
}

fn default_static_status() -> u16 {
    200
}
fn default_redirect_status() -> u16 {
    302
}
fn default_true() -> bool {
    true
}

/// Match conditions for a routing rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchConfig {
    /// Match by hostname (exact or glob, e.g., "*.example.com").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// Match by path prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,

    /// Match by exact path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_exact: Option<String>,

    /// Match by path regex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_regex: Option<String>,

    /// Match by HTTP method(s).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,

    /// Match by request header key-value pairs.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,

    /// Match by query parameter key-value pairs.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub query_params: HashMap<String, String>,

    /// Match by cookie key-value pairs.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub cookies: HashMap<String, String>,

    /// Match by content type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// Match by client source IP (CIDR notation; bare IPs allowed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_cidrs: Vec<String>,
}

/// Load balancer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerConfig {
    /// Balancing strategy.
    #[serde(default)]
    pub strategy: BalancerStrategy,

    /// Sticky session configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sticky: Option<StickyConfig>,

    /// Health check configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthCheckConfig>,
}

impl Default for BalancerConfig {
    fn default() -> Self {
        Self {
            strategy: BalancerStrategy::RoundRobin,
            sticky: None,
            health_check: None,
        }
    }
}

/// Supported load balancing strategies.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BalancerStrategy {
    #[default]
    RoundRobin,
    LeastConnections,
    Weighted,
    Random,
    ConsistentHash,
    /// AI-driven: uses the predictor to pick the optimal backend.
    AiPredictive,
}

/// Sticky session configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StickyConfig {
    /// Cookie name for session affinity.
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,

    /// Cookie TTL in seconds (0 = session cookie).
    #[serde(default)]
    pub ttl_secs: u64,

    /// Use client IP as fallback when cookie is absent.
    #[serde(default)]
    pub fallback_to_ip: bool,
}

fn default_cookie_name() -> String {
    "INTELLARO_STICKY".to_string()
}

/// Health check configuration for backends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// HTTP path to probe.
    pub path: String,

    /// Probe interval in seconds.
    #[serde(default = "default_interval")]
    pub interval_secs: u64,

    /// Probe timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Consecutive failures to mark unhealthy.
    #[serde(default = "default_unhealthy")]
    pub unhealthy_threshold: u32,

    /// Consecutive successes to mark healthy.
    #[serde(default = "default_healthy")]
    pub healthy_threshold: u32,
}

fn default_interval() -> u64 { 10 }
fn default_timeout() -> u64 { 5 }
fn default_unhealthy() -> u32 { 3 }
fn default_healthy() -> u32 { 2 }

/// AI feature configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// Enable AI-powered request classification.
    #[serde(default)]
    pub classification_enabled: bool,

    /// Enable predictive load balancing.
    #[serde(default)]
    pub prediction_enabled: bool,

    /// Enable anomaly detection.
    #[serde(default)]
    pub anomaly_enabled: bool,

    /// Enable adaptive canary decisions.
    #[serde(default)]
    pub adaptive_canary_enabled: bool,

    /// Window size (in seconds) for collecting traffic samples.
    #[serde(default = "default_sample_window")]
    pub sample_window_secs: u64,

    /// Number of historical data points to retain per backend.
    #[serde(default = "default_history_size")]
    pub history_size: usize,

    /// Classification rules: map class labels to backend groups.
    #[serde(default)]
    pub class_routes: HashMap<String, String>,
}

fn default_sample_window() -> u64 { 60 }
fn default_history_size() -> usize { 1000 }

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            classification_enabled: false,
            prediction_enabled: false,
            anomaly_enabled: false,
            adaptive_canary_enabled: false,
            sample_window_secs: default_sample_window(),
            history_size: default_history_size(),
            class_routes: HashMap::new(),
        }
    }
}

/// Canary / blue-green deployment configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryConfig {
    /// Deployment name.
    pub name: String,

    /// Primary (stable) backend group.
    pub primary: String,

    /// Canary backend group.
    pub canary: String,

    /// Percentage of traffic to send to canary (0–100).
    #[serde(default)]
    pub canary_weight: u32,

    /// Header that forces canary routing when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary_header: Option<String>,

    /// Cookie that forces canary routing when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary_cookie: Option<String>,

    /// Whether AI should adaptively adjust canary weight.
    #[serde(default)]
    pub adaptive: bool,
}

/// SLA / priority tier definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityTier {
    /// Tier name (e.g., "premium", "standard", "free").
    pub name: String,

    /// Priority level (higher = more important).
    pub level: u32,

    /// How to identify requests in this tier.
    pub identifier: PriorityIdentifier,

    /// Dedicated backend group (if different from default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedicated_backend: Option<String>,

    /// Rate limit multiplier (1.0 = default limits).
    #[serde(default = "default_rate_multiplier")]
    pub rate_multiplier: f64,
}

fn default_rate_multiplier() -> f64 { 1.0 }

/// How to identify which priority tier a request belongs to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityIdentifier {
    /// Identify by a header value (e.g., `X-Tenant-Tier: premium`).
    Header { name: String, value: String },
    /// Identify by JWT claim value.
    JwtClaim { claim: String, value: String },
    /// Identify by source IP CIDR.
    SourceCidr(String),
    /// Identify by cookie value.
    Cookie { name: String, value: String },
}

/// Anomaly detection settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetectionConfig {
    /// Enable anomaly detection.
    #[serde(default)]
    pub enabled: bool,

    /// Z-score threshold for flagging an anomaly.
    #[serde(default = "default_z_threshold")]
    pub z_score_threshold: f64,

    /// Evaluation window in seconds.
    #[serde(default = "default_eval_window")]
    pub window_secs: u64,

    /// Action to take when an anomaly is detected.
    #[serde(default)]
    pub action: AnomalyAction,
}

fn default_z_threshold() -> f64 { 3.0 }
fn default_eval_window() -> u64 { 60 }

impl Default for AnomalyDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            z_score_threshold: default_z_threshold(),
            window_secs: default_eval_window(),
            action: AnomalyAction::default(),
        }
    }
}

/// Action to take on anomaly detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyAction {
    /// Log the anomaly but take no routing action.
    #[default]
    LogOnly,
    /// Throttle traffic to the affected backend.
    Throttle,
    /// Remove the backend from the rotation until recovered.
    CircuitBreak,
    /// Redirect traffic to a fallback backend group.
    Redirect { fallback_group: String },
}

/// Header manipulation rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderManipulation {
    /// Headers to set on the proxied request.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub request_set: HashMap<String, String>,

    /// Headers to set on the proxied response.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub response_set: HashMap<String, String>,

    /// Headers to remove from the proxied request.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_remove: Vec<String>,

    /// Headers to remove from the proxied response.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_remove: Vec<String>,
}
