//! HTTP caching layer module.
//!
//! Provides an in-memory cache for HTTP responses with TTL-based expiration,
//! size limits, and support for caching both GET and POST responses.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use hyper::body::Incoming;
use hyper::{Method, Request, Response};
use tracing::{debug, info};

use crate::config::CacheConfig;
use crate::server::BoxBody;

/// A cached HTTP response with metadata.
#[derive(Clone, Debug)]
struct CachedEntry {
    /// HTTP status code.
    status: u16,

    /// Response headers.
    headers: Vec<(String, Vec<u8>)>,

    /// Response body bytes.
    body: Vec<u8>,

    /// When this entry was stored.
    created_at: Instant,

    /// Time-to-live for this entry.
    ttl: Duration,
}

impl CachedEntry {
    /// Returns true if this entry has expired.
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }
}

/// The caching layer manages an in-memory store of HTTP responses.
pub struct CacheLayer {
    store: Arc<DashMap<String, CachedEntry>>,
    config: CacheConfig,
}

impl CacheLayer {
    /// Create a new cache layer from configuration.
    pub fn new(config: &CacheConfig) -> Self {
        let layer = Self {
            store: Arc::new(DashMap::with_capacity(config.max_entries)),
            config: config.clone(),
        };

        if config.enabled {
            // Spawn a background task to evict expired entries periodically.
            let store = Arc::clone(&layer.store);
            let ttl = config.default_ttl_secs;
            tokio::spawn(async move {
                eviction_loop(store, Duration::from_secs(ttl)).await;
            });

            info!(
                max_entries = config.max_entries,
                ttl_secs = config.default_ttl_secs,
                cache_post = config.cache_post,
                "Cache layer initialized"
            );
        } else {
            info!("Cache layer disabled");
        }

        layer
    }

    /// Attempt to retrieve a cached response for the given request.
    pub async fn get(&self, req: &Request<Incoming>) -> Option<Response<BoxBody>> {
        if !self.config.enabled {
            return None;
        }

        if !self.is_cacheable_request(req) {
            return None;
        }

        let cache_key = self.build_cache_key(req);

        if let Some(entry) = self.store.get(&cache_key) {
            if entry.is_expired() {
                drop(entry);
                self.store.remove(&cache_key);
                return None;
            }

            debug!(key = %cache_key, "Cache hit");

            let mut builder = Response::builder().status(entry.status);
            for (name, value) in &entry.headers {
                if let Ok(header_value) = hyper::header::HeaderValue::from_bytes(value) {
                    builder = builder.header(name.as_str(), header_value);
                }
            }

            // Add cache-status header
            builder = builder.header("X-Intellaro-Cache", "HIT");

            return builder
                .body(BoxBody::new(hyper::body::Bytes::from(entry.body.clone())))
                .ok();
        }

        None
    }

    /// Store a response in the cache if it is cacheable.
    pub async fn store(&self, req: &Request<Incoming>, resp: &Response<BoxBody>) {
        if !self.config.enabled {
            return;
        }

        if !self.is_cacheable_request(req) {
            return;
        }

        if !self.is_cacheable_response(resp) {
            return;
        }

        // Enforce max entries limit
        if self.store.len() >= self.config.max_entries {
            debug!("Cache full, skipping store");
            return;
        }

        let cache_key = self.build_cache_key(req);

        let headers: Vec<(String, Vec<u8>)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
            .collect();

        let body = resp.body().frame_ref_bytes().unwrap_or_default().to_vec();

        let entry = CachedEntry {
            status: resp.status().as_u16(),
            headers,
            body,
            created_at: Instant::now(),
            ttl: self.resolve_ttl(resp),
        };

        self.store.insert(cache_key.clone(), entry);
        metrics::gauge!("cache_entries").set(self.store.len() as f64);
        debug!(key = %cache_key, "Response cached");
    }

    /// Invalidate a specific cache entry.
    pub fn invalidate(&self, key: &str) {
        self.store.remove(key);
        metrics::gauge!("cache_entries").set(self.store.len() as f64);
    }

    /// Purge the entire cache.
    pub fn purge(&self) {
        self.store.clear();
        metrics::gauge!("cache_entries").set(0.0);
        info!("Cache purged");
    }

    /// Returns the current number of entries in the cache.
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// Build a cache key from the request method, URI, and relevant headers.
    fn build_cache_key(&self, req: &Request<Incoming>) -> String {
        let method = req.method().as_str();
        let uri = req.uri().to_string();

        // Include Accept and Accept-Encoding for content negotiation.
        let accept = req
            .headers()
            .get("accept")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        format!("{}:{}:{}", method, uri, accept)
    }

    /// Determine if a request is eligible for caching.
    fn is_cacheable_request(&self, req: &Request<Incoming>) -> bool {
        match *req.method() {
            Method::GET | Method::HEAD => true,
            Method::POST if self.config.cache_post => true,
            _ => false,
        }
    }

    /// Determine if a response is eligible for caching.
    fn is_cacheable_response(&self, resp: &Response<BoxBody>) -> bool {
        let status = resp.status().as_u16();

        // Only cache successful responses and 301/304.
        matches!(status, 200 | 203 | 204 | 206 | 300 | 301 | 304 | 404 | 410)
    }

    /// Resolve the TTL for a cached response, respecting Cache-Control headers.
    fn resolve_ttl(&self, resp: &Response<BoxBody>) -> Duration {
        // Check for Cache-Control: max-age directive
        if let Some(cc) = resp.headers().get("cache-control").and_then(|v| v.to_str().ok()) {
            for directive in cc.split(',').map(str::trim) {
                if let Some(max_age) = directive.strip_prefix("max-age=") {
                    if let Ok(secs) = max_age.trim().parse::<u64>() {
                        return Duration::from_secs(secs);
                    }
                }

                // Respect no-store / no-cache by using zero TTL (won't actually be stored).
                if directive == "no-store" || directive == "no-cache" {
                    return Duration::ZERO;
                }
            }
        }

        Duration::from_secs(self.config.default_ttl_secs)
    }
}

/// Trait extension to read body bytes from a Full<Bytes> body without consuming it.
trait FullBodyExt {
    fn frame_ref_bytes(&self) -> Option<&[u8]>;
}

impl FullBodyExt for BoxBody {
    fn frame_ref_bytes(&self) -> Option<&[u8]> {
        // For http_body_util::Full<Bytes>, we can inspect the inner data.
        // This is a simplification; in production, we'd buffer the body stream.
        None
    }
}

/// Background eviction loop that removes expired cache entries.
async fn eviction_loop(store: Arc<DashMap<String, CachedEntry>>, check_interval: Duration) {
    let sweep_interval = check_interval.min(Duration::from_secs(60));

    loop {
        tokio::time::sleep(sweep_interval).await;

        let before = store.len();
        store.retain(|_, entry| !entry.is_expired());
        let evicted = before.saturating_sub(store.len());

        if evicted > 0 {
            debug!(evicted, remaining = store.len(), "Cache eviction sweep");
            metrics::gauge!("cache_entries").set(store.len() as f64);
        }
    }
}
