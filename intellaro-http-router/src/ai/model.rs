//! ML model interface.
//!
//! Defines the trait that all AI models implement, plus built-in
//! heuristic models that require no external dependencies.

use std::collections::HashMap;

/// Feature vector extracted from a request for model input.
#[derive(Debug, Clone)]
pub struct RequestFeatures {
    /// Request path.
    pub path: String,

    /// HTTP method.
    pub method: String,

    /// Content-Type header value.
    pub content_type: Option<String>,

    /// Content-Length (body size in bytes).
    pub content_length: u64,

    /// User-Agent header.
    pub user_agent: Option<String>,

    /// Source IP address.
    pub source_ip: Option<String>,

    /// Whether the request carries authentication.
    pub authenticated: bool,

    /// Custom extracted features as key-value pairs.
    pub custom: HashMap<String, f64>,
}

/// Trait for pluggable AI models.
///
/// Implementations can range from simple heuristic rules to full
/// neural network inference. The trait is designed to be lightweight
/// enough to call on every request.
pub trait RoutingModel: Send + Sync {
    /// Classify a request into a named category.
    ///
    /// Returns a class label (e.g., "api", "static", "heavy_compute")
    /// and a confidence score between 0.0 and 1.0.
    fn classify(&self, features: &RequestFeatures) -> (String, f64);

    /// Predict the expected latency (in milliseconds) for a request
    /// routed to the given backend.
    fn predict_latency(&self, features: &RequestFeatures, backend_id: &str) -> f64;

    /// Return a human-readable model name for logging.
    fn name(&self) -> &str;
}

/// Built-in heuristic model that classifies requests by URL pattern
/// and content characteristics. No ML framework required.
pub struct HeuristicModel;

impl HeuristicModel {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HeuristicModel {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingModel for HeuristicModel {
    fn classify(&self, features: &RequestFeatures) -> (String, f64) {
        let path = &features.path;

        // Static assets.
        if path.starts_with("/static/")
            || path.ends_with(".css")
            || path.ends_with(".js")
            || path.ends_with(".png")
            || path.ends_with(".jpg")
            || path.ends_with(".woff2")
            || path.ends_with(".svg")
            || path.ends_with(".ico")
        {
            return ("static".to_string(), 0.95);
        }

        // API endpoints.
        if path.starts_with("/api/") || path.starts_with("/v1/") || path.starts_with("/v2/") {
            // Large payload API calls are likely heavy compute.
            if features.content_length > 1_000_000 {
                return ("heavy_compute".to_string(), 0.8);
            }
            return ("api".to_string(), 0.9);
        }

        // Health/status probes.
        if path == "/healthz" || path == "/readyz" || path == "/metrics" || path == "/health" {
            return ("probe".to_string(), 0.99);
        }

        // WebSocket upgrade.
        if features
            .custom
            .get("upgrade")
            .map(|v| *v > 0.0)
            .unwrap_or(false)
        {
            return ("websocket".to_string(), 0.95);
        }

        // Default: general web request.
        ("web".to_string(), 0.5)
    }

    fn predict_latency(&self, features: &RequestFeatures, _backend_id: &str) -> f64 {
        // Simple heuristic: larger requests take longer.
        let base_ms = 10.0;
        let size_factor = (features.content_length as f64 / 100_000.0).min(100.0);

        let method_factor = match features.method.as_str() {
            "GET" | "HEAD" => 1.0,
            "POST" | "PUT" | "PATCH" => 1.5,
            "DELETE" => 1.2,
            _ => 1.0,
        };

        base_ms + size_factor * method_factor
    }

    fn name(&self) -> &str {
        "heuristic-v1"
    }
}
