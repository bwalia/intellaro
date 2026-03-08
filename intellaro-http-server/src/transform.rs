//! Request/response transformation module.
//!
//! Applies header manipulation, path rewriting, request ID injection,
//! and response timing headers to proxied requests and responses.

use std::collections::HashMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tracing::debug;
use uuid::Uuid;

/// Transform configuration for an upstream.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransformConfig {
    /// Headers to set on the outgoing request.
    #[serde(default)]
    pub request_headers_set: HashMap<String, String>,

    /// Headers to remove from the outgoing request.
    #[serde(default)]
    pub request_headers_remove: Vec<String>,

    /// Headers to set on the response back to the client.
    #[serde(default)]
    pub response_headers_set: HashMap<String, String>,

    /// Headers to remove from the response back to the client.
    #[serde(default)]
    pub response_headers_remove: Vec<String>,

    /// Strip a path prefix before forwarding to the backend.
    #[serde(default)]
    pub strip_path_prefix: Option<String>,

    /// Add a path prefix before forwarding to the backend.
    #[serde(default)]
    pub add_path_prefix: Option<String>,

    /// Inject a unique X-Request-Id header if not already present.
    #[serde(default)]
    pub inject_request_id: bool,

    /// Inject X-Response-Time header with milliseconds elapsed.
    #[serde(default)]
    pub inject_response_time: bool,
}

/// Apply request transformations to a reqwest HeaderMap before sending to backend.
pub fn apply_request_transforms(
    headers: &mut reqwest::header::HeaderMap,
    uri_path: &str,
    config: &TransformConfig,
) -> String {
    // Set configured request headers.
    for (key, value) in &config.request_headers_set {
        if let (Ok(name), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(key.as_bytes()),
            reqwest::header::HeaderValue::from_str(value),
        ) {
            headers.insert(name, val);
        }
    }

    // Remove configured request headers.
    for key in &config.request_headers_remove {
        if let Ok(name) = reqwest::header::HeaderName::from_bytes(key.as_bytes()) {
            headers.remove(name);
        }
    }

    // Inject X-Request-Id if configured and not present.
    if config.inject_request_id {
        let request_id_key =
            reqwest::header::HeaderName::from_static("x-request-id");
        if !headers.contains_key(&request_id_key) {
            let id = Uuid::new_v4().to_string();
            if let Ok(val) = reqwest::header::HeaderValue::from_str(&id) {
                headers.insert(request_id_key, val);
                debug!(request_id = %id, "Injected X-Request-Id");
            }
        }
    }

    // Apply path transformations.
    let mut path = uri_path.to_string();
    if let Some(ref prefix) = config.strip_path_prefix {
        if let Some(stripped) = path.strip_prefix(prefix.as_str()) {
            path = if stripped.is_empty() {
                "/".to_string()
            } else {
                stripped.to_string()
            };
        }
    }
    if let Some(ref prefix) = config.add_path_prefix {
        path = format!("{}{}", prefix, path);
    }

    path
}

/// Apply response transformations to a hyper HeaderMap.
pub fn apply_response_transforms(
    headers: &mut hyper::HeaderMap,
    config: &TransformConfig,
    request_start: Option<Instant>,
) {
    // Set configured response headers.
    for (key, value) in &config.response_headers_set {
        if let (Ok(name), Ok(val)) = (
            hyper::header::HeaderName::from_bytes(key.as_bytes()),
            hyper::header::HeaderValue::from_str(value),
        ) {
            headers.insert(name, val);
        }
    }

    // Remove configured response headers.
    for key in &config.response_headers_remove {
        if let Ok(name) = hyper::header::HeaderName::from_bytes(key.as_bytes()) {
            headers.remove(name);
        }
    }

    // Inject X-Response-Time.
    if config.inject_response_time {
        if let Some(start) = request_start {
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            let value = format!("{:.2}ms", elapsed_ms);
            if let Ok(val) = hyper::header::HeaderValue::from_str(&value) {
                headers.insert("x-response-time", val);
            }
        }
    }
}
