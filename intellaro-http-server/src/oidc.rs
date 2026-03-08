//! OIDC (OpenID Connect) support module.
//!
//! Provides OIDC discovery, JWKS key caching, and token validation
//! as an alternative to static JWT secret validation.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{decode, Algorithm, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// OIDC configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// OIDC discovery endpoint URL.
    /// E.g., "https://auth.example.com/.well-known/openid-configuration"
    pub discovery_url: String,

    /// Expected client ID (audience claim).
    pub client_id: String,

    /// How long to cache JWKS keys (in seconds).
    #[serde(default = "default_jwks_cache_secs")]
    pub jwks_cache_secs: u64,

    /// Expected issuer (if not provided, will be read from discovery).
    #[serde(default)]
    pub expected_issuer: Option<String>,
}

fn default_jwks_cache_secs() -> u64 {
    3600
}

/// A cached JWKS key set.
struct JwksCache {
    /// JSON Web Keys indexed by key ID (kid).
    keys: HashMap<String, JwkKey>,
    /// When the cache was last refreshed.
    fetched_at: Instant,
    /// How long to cache.
    cache_duration: Duration,
    /// JWKS endpoint URL (from discovery).
    jwks_uri: String,
    /// Expected issuer (from discovery).
    issuer: String,
}

/// A single JWK key entry.
#[derive(Clone)]
struct JwkKey {
    /// Key ID.
    kid: String,
    /// Algorithm.
    algorithm: Algorithm,
    /// The decoding key.
    decoding_key: DecodingKey,
}

/// OIDC discovery document (subset of fields we need).
#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

/// JWKS key set response.
#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<JwkEntry>,
}

/// A single entry in a JWKS response.
#[derive(Debug, Deserialize)]
struct JwkEntry {
    kid: Option<String>,
    kty: String,
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

/// Standard JWT claims we validate.
#[derive(Debug, Deserialize)]
pub struct OidcClaims {
    pub sub: Option<String>,
    pub iss: Option<String>,
    pub aud: Option<serde_json::Value>,
    pub exp: Option<u64>,
    pub iat: Option<u64>,
}

/// OIDC token validator with JWKS caching.
pub struct OidcValidator {
    config: OidcConfig,
    cache: Arc<RwLock<Option<JwksCache>>>,
    http_client: reqwest::Client,
}

impl OidcValidator {
    /// Create a new OIDC validator.
    pub fn new(config: OidcConfig) -> Self {
        info!(
            discovery_url = %config.discovery_url,
            client_id = %config.client_id,
            "OIDC validator initialized"
        );

        Self {
            config,
            cache: Arc::new(RwLock::new(None)),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to build OIDC HTTP client"),
        }
    }

    /// Validate an OIDC/JWT bearer token.
    ///
    /// Returns the decoded claims on success, or an error message on failure.
    pub async fn validate_token(&self, token: &str) -> Result<OidcClaims, String> {
        let cache = self.ensure_cache().await?;
        let cache_guard = cache.read().await;
        let jwks = cache_guard
            .as_ref()
            .ok_or("JWKS cache not available")?;

        // Parse the JWT header to get the key ID.
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| format!("Invalid JWT header: {}", e))?;

        let kid = header.kid.ok_or("JWT missing 'kid' header")?;

        let key = jwks
            .keys
            .get(&kid)
            .ok_or_else(|| format!("Unknown key ID: {}", kid))?;

        // Build validation parameters.
        let mut validation = Validation::new(key.algorithm);
        validation.set_audience(&[&self.config.client_id]);
        validation.set_issuer(&[&jwks.issuer]);

        let token_data: TokenData<OidcClaims> =
            decode(token, &key.decoding_key, &validation)
                .map_err(|e| format!("Token validation failed: {}", e))?;

        debug!(sub = ?token_data.claims.sub, "OIDC token validated");
        Ok(token_data.claims)
    }

    /// Ensure the JWKS cache is populated and fresh.
    async fn ensure_cache(
        &self,
    ) -> Result<Arc<RwLock<Option<JwksCache>>>, String> {
        {
            let cache = self.cache.read().await;
            if let Some(ref jwks) = *cache {
                if jwks.fetched_at.elapsed() < jwks.cache_duration {
                    return Ok(Arc::clone(&self.cache));
                }
            }
        }

        // Cache is empty or stale — refresh.
        self.refresh_cache().await?;
        Ok(Arc::clone(&self.cache))
    }

    /// Fetch the OIDC discovery document and JWKS keys.
    async fn refresh_cache(&self) -> Result<(), String> {
        info!("Refreshing OIDC JWKS cache");

        // Fetch discovery document.
        let discovery: DiscoveryDocument = self
            .http_client
            .get(&self.config.discovery_url)
            .send()
            .await
            .map_err(|e| format!("OIDC discovery fetch failed: {}", e))?
            .json()
            .await
            .map_err(|e| format!("OIDC discovery parse failed: {}", e))?;

        // Fetch JWKS.
        let jwks_response: JwksResponse = self
            .http_client
            .get(&discovery.jwks_uri)
            .send()
            .await
            .map_err(|e| format!("JWKS fetch failed: {}", e))?
            .json()
            .await
            .map_err(|e| format!("JWKS parse failed: {}", e))?;

        // Parse keys.
        let mut keys = HashMap::new();
        for entry in &jwks_response.keys {
            if entry.kty != "RSA" {
                continue;
            }
            let kid = match &entry.kid {
                Some(k) => k.clone(),
                None => continue,
            };
            let (n, e) = match (&entry.n, &entry.e) {
                (Some(n), Some(e)) => (n, e),
                _ => continue,
            };

            let algorithm = match entry.alg.as_deref() {
                Some("RS256") => Algorithm::RS256,
                Some("RS384") => Algorithm::RS384,
                Some("RS512") => Algorithm::RS512,
                _ => Algorithm::RS256,
            };

            match DecodingKey::from_rsa_components(n, e) {
                Ok(decoding_key) => {
                    keys.insert(
                        kid.clone(),
                        JwkKey {
                            kid,
                            algorithm,
                            decoding_key,
                        },
                    );
                }
                Err(err) => {
                    warn!(kid = %kid, %err, "Failed to parse JWK RSA key");
                }
            }
        }

        if keys.is_empty() {
            error!("No usable keys found in JWKS response");
            return Err("No usable keys in JWKS".to_string());
        }

        let issuer = self
            .config
            .expected_issuer
            .clone()
            .unwrap_or(discovery.issuer);

        let cache = JwksCache {
            keys,
            fetched_at: Instant::now(),
            cache_duration: Duration::from_secs(self.config.jwks_cache_secs),
            jwks_uri: discovery.jwks_uri,
            issuer,
        };

        let mut cache_guard = self.cache.write().await;
        *cache_guard = Some(cache);

        info!("OIDC JWKS cache refreshed");
        Ok(())
    }
}
