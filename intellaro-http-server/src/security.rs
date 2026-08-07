//! Security policy engine module.
//!
//! Enforces IP allow/block lists, rate limiting, JWT validation,
//! and per-route security policies.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use hyper::{Request, Response, StatusCode};
use ipnet::IpNet;
use jsonwebtoken::{decode, DecodingKey, Validation};
use tracing::{debug, warn};

use crate::config::{JwtConfig, SecurityConfig};
use crate::server::BoxBody;

/// Security engine that evaluates all security policies against incoming requests.
pub struct SecurityEngine {
    ip_allow_list: Vec<IpNet>,
    ip_block_list: Vec<IpNet>,
    rate_limiter: Option<RateLimiter>,
    jwt_config: Option<JwtConfig>,
}

impl SecurityEngine {
    /// Create a new security engine from configuration.
    pub fn new(config: &SecurityConfig) -> Self {
        let ip_allow_list = parse_ip_nets(&config.ip_allow);
        let ip_block_list = parse_ip_nets(&config.ip_block);

        let rate_limiter = config.rate_limit.as_ref().map(|rl| {
            RateLimiter::new(rl.max_requests, Duration::from_secs(rl.window_secs))
        });

        tracing::info!(
            allow_rules = ip_allow_list.len(),
            block_rules = ip_block_list.len(),
            rate_limiting = rate_limiter.is_some(),
            jwt = config.jwt.is_some(),
            "Security engine initialized"
        );

        Self {
            ip_allow_list,
            ip_block_list,
            rate_limiter,
            jwt_config: config.jwt.clone(),
        }
    }

    /// Evaluate all security policies against an incoming request.
    ///
    /// Returns `Some(Response)` if the request is denied (the response is the
    /// denial response to send back). Returns `None` if the request passes.
    pub async fn check<B>(
        &self,
        req: &Request<B>,
        peer_addr: SocketAddr,
    ) -> Option<Response<BoxBody>> {
        let client_ip = peer_addr.ip();

        // 1. IP block list check
        if self.is_blocked(client_ip) {
            warn!(%client_ip, "Request blocked by IP block list");
            return Some(forbidden_response("Forbidden: IP blocked"));
        }

        // 2. IP allow list check (if configured, only allowed IPs pass)
        if !self.ip_allow_list.is_empty() && !self.is_allowed(client_ip) {
            warn!(%client_ip, "Request denied: IP not in allow list");
            return Some(forbidden_response("Forbidden: IP not allowed"));
        }

        // 3. Rate limiting
        if let Some(ref limiter) = self.rate_limiter {
            if !limiter.check(client_ip) {
                warn!(%client_ip, "Rate limit exceeded");
                return Some(rate_limited_response());
            }
        }

        // 4. JWT validation (if configured)
        if let Some(ref jwt_config) = self.jwt_config {
            if let Some(response) = self.validate_jwt(req, jwt_config) {
                return Some(response);
            }
        }

        None
    }

    /// Check if an IP is in the block list.
    fn is_blocked(&self, ip: IpAddr) -> bool {
        self.ip_block_list.iter().any(|net| net.contains(&ip))
    }

    /// Check if an IP is in the allow list.
    fn is_allowed(&self, ip: IpAddr) -> bool {
        self.ip_allow_list.iter().any(|net| net.contains(&ip))
    }

    /// Validate the JWT token in the Authorization header.
    fn validate_jwt<B>(
        &self,
        req: &Request<B>,
        jwt_config: &JwtConfig,
    ) -> Option<Response<BoxBody>> {
        let auth_header = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok());

        let token = match auth_header {
            Some(header) if header.starts_with("Bearer ") => &header[7..],
            _ => {
                return Some(unauthorized_response("Missing or invalid Authorization header"));
            }
        };

        let mut validation = Validation::default();

        if let Some(ref issuer) = jwt_config.issuer {
            validation.set_issuer(&[issuer]);
        }

        if let Some(ref audience) = jwt_config.audience {
            validation.set_audience(&[audience]);
        }

        let decoding_key = DecodingKey::from_secret(jwt_config.secret_or_key_path.as_bytes());

        match decode::<serde_json::Value>(token, &decoding_key, &validation) {
            Ok(_token_data) => {
                debug!("JWT validation passed");
                None
            }
            Err(err) => {
                warn!(%err, "JWT validation failed");
                Some(unauthorized_response("Invalid or expired token"))
            }
        }
    }
}

// ── Rate Limiter ─────────────────────────────────────────────────────

/// Sliding-window rate limiter using per-IP token buckets.
struct RateLimiter {
    buckets: Arc<DashMap<IpAddr, RateBucket>>,
    max_requests: u64,
    window: Duration,
}

/// Token bucket for a single IP.
struct RateBucket {
    tokens: u64,
    last_refill: Instant,
}

impl RateLimiter {
    fn new(max_requests: u64, window: Duration) -> Self {
        let limiter = Self {
            buckets: Arc::new(DashMap::new()),
            max_requests,
            window,
        };

        // Spawn a background cleanup task to evict stale buckets.
        let buckets = Arc::clone(&limiter.buckets);
        let window_duration = window;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(window_duration).await;
                buckets.retain(|_, bucket: &mut RateBucket| {
                    bucket.last_refill.elapsed() < window_duration * 2
                });
            }
        });

        limiter
    }

    /// Returns true if the request is allowed, false if rate-limited.
    fn check(&self, ip: IpAddr) -> bool {
        let mut entry = self.buckets.entry(ip).or_insert_with(|| RateBucket {
            tokens: self.max_requests,
            last_refill: Instant::now(),
        });

        let bucket = entry.value_mut();

        // Refill tokens if the window has elapsed.
        if bucket.last_refill.elapsed() >= self.window {
            bucket.tokens = self.max_requests;
            bucket.last_refill = Instant::now();
        }

        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            true
        } else {
            false
        }
    }
}

// ── Helper functions ─────────────────────────────────────────────────

/// Parse a list of CIDR strings into `IpNet` values, skipping invalid entries.
fn parse_ip_nets(cidrs: &[String]) -> Vec<IpNet> {
    cidrs
        .iter()
        .filter_map(|cidr| {
            cidr.parse::<IpNet>()
                .map_err(|err| {
                    warn!(cidr = %cidr, %err, "Invalid CIDR notation, skipping");
                    err
                })
                .ok()
        })
        .collect()
}

/// Build a 403 Forbidden response.
fn forbidden_response(message: &str) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("Content-Type", "text/plain")
        .body(BoxBody::new(hyper::body::Bytes::from(
            message.to_string(),
        )))
        .unwrap()
}

/// Build a 401 Unauthorized response.
fn unauthorized_response(message: &str) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("Content-Type", "text/plain")
        .header("WWW-Authenticate", "Bearer")
        .body(BoxBody::new(hyper::body::Bytes::from(
            message.to_string(),
        )))
        .unwrap()
}

/// Build a 429 Too Many Requests response.
fn rate_limited_response() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("Content-Type", "text/plain")
        .header("Retry-After", "60")
        .body(BoxBody::new(hyper::body::Bytes::from(
            "Too Many Requests",
        )))
        .unwrap()
}
