//! HTTP caching layer module.
//!
//! Provides an in-memory cache for HTTP responses with TTL-based expiration,
//! size limits, tag-based invalidation, stale-while-revalidate, and
//! stale-if-error support.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Method, Request, Response};
use serde::Serialize;
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

    /// Tags associated with this cache entry for bulk invalidation.
    tags: Vec<String>,
}

impl CachedEntry {
    /// Returns true if this entry has expired.
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }

    /// Returns true if the entry is stale but within the stale-while-revalidate window.
    fn is_stale_revalidate(&self, swr_secs: u64) -> bool {
        if swr_secs == 0 {
            return false;
        }
        let age = self.created_at.elapsed();
        age > self.ttl && age <= self.ttl + Duration::from_secs(swr_secs)
    }

    /// Returns true if the entry is stale but within the stale-if-error window.
    fn is_stale_error(&self, sie_secs: u64) -> bool {
        if sie_secs == 0 {
            return false;
        }
        let age = self.created_at.elapsed();
        age > self.ttl && age <= self.ttl + Duration::from_secs(sie_secs)
    }

    /// Build a hyper Response from this cached entry.
    fn to_response(&self, cache_status: &str) -> Option<Response<BoxBody>> {
        let mut builder = Response::builder().status(self.status);
        for (name, value) in &self.headers {
            if let Ok(header_value) = hyper::header::HeaderValue::from_bytes(value) {
                builder = builder.header(name.as_str(), header_value);
            }
        }
        builder = builder.header("X-Intellaro-Cache", cache_status);

        builder
            .body(BoxBody::new(hyper::body::Bytes::from(self.body.clone())))
            .ok()
    }
}

/// Tag index for bulk cache invalidation.
struct TagIndex {
    /// Maps tag → set of cache keys.
    index: DashMap<String, Vec<String>>,
}

impl TagIndex {
    fn new() -> Self {
        Self {
            index: DashMap::new(),
        }
    }

    /// Associate a cache key with a set of tags.
    fn associate(&self, key: &str, tags: &[String]) {
        for tag in tags {
            self.index
                .entry(tag.clone())
                .or_default()
                .push(key.to_string());
        }
    }

    /// Get all cache keys associated with a tag.
    fn keys_for_tag(&self, tag: &str) -> Vec<String> {
        self.index
            .get(tag)
            .map(|entry| entry.value().clone())
            .unwrap_or_default()
    }

    /// Remove a tag and return its associated keys.
    fn remove_tag(&self, tag: &str) -> Vec<String> {
        self.index
            .remove(tag)
            .map(|(_, keys)| keys)
            .unwrap_or_default()
    }

    /// Remove a key from all tag associations.
    fn remove_key(&self, key: &str) {
        self.index.iter_mut().for_each(|mut entry| {
            entry.value_mut().retain(|k| k != key);
        });
    }

    /// Clear the entire tag index.
    fn clear(&self) {
        self.index.clear();
    }
}

/// Cache statistics for monitoring.
#[derive(Debug, Clone, Serialize)]
pub struct CacheStats {
    pub entries: usize,
    pub max_entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub stale_hits: u64,
    pub evictions: u64,
    pub hit_rate: f64,
}

/// The caching layer manages an in-memory store of HTTP responses.
pub struct CacheLayer {
    store: Arc<DashMap<String, CachedEntry>>,
    tag_index: Arc<TagIndex>,
    config: CacheConfig,
    stats_hits: AtomicU64,
    stats_misses: AtomicU64,
    stats_stale_hits: AtomicU64,
    stats_evictions: AtomicU64,
}

impl CacheLayer {
    /// Create a new cache layer from configuration.
    pub fn new(config: &CacheConfig) -> Self {
        let layer = Self {
            store: Arc::new(DashMap::with_capacity(config.max_entries)),
            tag_index: Arc::new(TagIndex::new()),
            config: config.clone(),
            stats_hits: AtomicU64::new(0),
            stats_misses: AtomicU64::new(0),
            stats_stale_hits: AtomicU64::new(0),
            stats_evictions: AtomicU64::new(0),
        };

        if config.enabled {
            // Spawn a background task to evict expired entries periodically.
            let store = Arc::clone(&layer.store);
            let tag_index = Arc::clone(&layer.tag_index);
            let ttl = config.default_ttl_secs;
            let swr = config.stale_while_revalidate_secs;
            let sie = config.stale_if_error_secs;
            tokio::spawn(async move {
                eviction_loop(store, tag_index, Duration::from_secs(ttl), swr, sie).await;
            });

            info!(
                max_entries = config.max_entries,
                ttl_secs = config.default_ttl_secs,
                stale_while_revalidate_secs = config.stale_while_revalidate_secs,
                stale_if_error_secs = config.stale_if_error_secs,
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
            if !entry.is_expired() {
                self.stats_hits.fetch_add(1, Ordering::Relaxed);
                debug!(key = %cache_key, "Cache hit");
                return entry.to_response("HIT");
            }

            // Check stale-while-revalidate: serve stale and background refresh.
            if entry.is_stale_revalidate(self.config.stale_while_revalidate_secs) {
                self.stats_stale_hits.fetch_add(1, Ordering::Relaxed);
                debug!(key = %cache_key, "Cache stale-while-revalidate hit");
                return entry.to_response("STALE-WHILE-REVALIDATE");
            }

            // Entry is fully expired beyond any stale window.
            drop(entry);
            self.store.remove(&cache_key);
            self.tag_index.remove_key(&cache_key);
        }

        self.stats_misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Get a stale cached response for use when upstream returns an error.
    /// Called when the proxy gets an error and stale-if-error is configured.
    pub async fn get_stale_if_error(&self, req: &Request<Incoming>) -> Option<Response<BoxBody>> {
        if !self.config.enabled || self.config.stale_if_error_secs == 0 {
            return None;
        }

        let cache_key = self.build_cache_key(req);

        if let Some(entry) = self.store.get(&cache_key) {
            if entry.is_stale_error(self.config.stale_if_error_secs) {
                self.stats_stale_hits.fetch_add(1, Ordering::Relaxed);
                debug!(key = %cache_key, "Cache stale-if-error hit");
                return entry.to_response("STALE-IF-ERROR");
            }
        }

        None
    }

    /// Store a response in the cache if it is cacheable.
    pub async fn store(&self, req: &Request<Incoming>, resp: &Response<BoxBody>) {
        self.store_with_tags(req, resp, &[]).await;
    }

    /// Store a response with associated tags for bulk invalidation.
    pub async fn store_with_tags(
        &self,
        req: &Request<Incoming>,
        resp: &Response<BoxBody>,
        tags: &[String],
    ) {
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

        let body = resp
            .body()
            .clone()
            .collect()
            .await
            .map(|collected| collected.to_bytes().to_vec())
            .unwrap_or_default();

        let entry = CachedEntry {
            status: resp.status().as_u16(),
            headers,
            body,
            created_at: Instant::now(),
            ttl: self.resolve_ttl(resp),
            tags: tags.to_vec(),
        };

        // Register tags in the index.
        if !tags.is_empty() {
            self.tag_index.associate(&cache_key, tags);
        }

        self.store.insert(cache_key.clone(), entry);
        metrics::gauge!("cache_entries").set(self.store.len() as f64);
        debug!(key = %cache_key, "Response cached");
    }

    /// Invalidate a specific cache entry.
    pub fn invalidate(&self, key: &str) {
        self.store.remove(key);
        self.tag_index.remove_key(key);
        metrics::gauge!("cache_entries").set(self.store.len() as f64);
    }

    /// Invalidate all cache entries associated with a tag.
    pub fn invalidate_by_tag(&self, tag: &str) -> usize {
        let keys = self.tag_index.remove_tag(tag);
        let count = keys.len();
        for key in &keys {
            self.store.remove(key);
        }
        if count > 0 {
            metrics::gauge!("cache_entries").set(self.store.len() as f64);
            debug!(tag, invalidated = count, "Cache entries invalidated by tag");
        }
        count
    }

    /// Purge the entire cache.
    pub fn purge(&self) {
        self.store.clear();
        self.tag_index.clear();
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

    /// Get cache statistics for monitoring.
    pub fn stats(&self) -> CacheStats {
        let hits = self.stats_hits.load(Ordering::Relaxed);
        let misses = self.stats_misses.load(Ordering::Relaxed);
        let total = hits + misses;
        let hit_rate = if total > 0 {
            hits as f64 / total as f64
        } else {
            0.0
        };

        CacheStats {
            entries: self.store.len(),
            max_entries: self.config.max_entries,
            hits,
            misses,
            stale_hits: self.stats_stale_hits.load(Ordering::Relaxed),
            evictions: self.stats_evictions.load(Ordering::Relaxed),
            hit_rate,
        }
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

/// Background eviction loop that removes expired cache entries.
async fn eviction_loop(
    store: Arc<DashMap<String, CachedEntry>>,
    tag_index: Arc<TagIndex>,
    check_interval: Duration,
    swr_secs: u64,
    sie_secs: u64,
) {
    let sweep_interval = check_interval.min(Duration::from_secs(60));
    // Max stale window is the greater of SWR and SIE.
    let max_stale = Duration::from_secs(swr_secs.max(sie_secs));

    loop {
        tokio::time::sleep(sweep_interval).await;

        let before = store.len();
        store.retain(|key, entry| {
            // Keep if not expired, or if within any stale window.
            let age = entry.created_at.elapsed();
            let keep = age <= entry.ttl + max_stale;
            if !keep {
                tag_index.remove_key(key);
            }
            keep
        });
        let evicted = before.saturating_sub(store.len());

        if evicted > 0 {
            debug!(evicted, remaining = store.len(), "Cache eviction sweep");
            metrics::gauge!("cache_entries").set(store.len() as f64);
        }
    }
}
