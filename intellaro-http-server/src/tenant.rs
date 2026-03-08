//! Multi-tenancy model module.
//!
//! Defines tenant configurations that can be flattened into effective
//! upstreams, routes, security policies, and cache settings at startup.
//! Each tenant can have multiple environments (dev, staging, prod)
//! and services within each environment.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::config::{BackendServer, CacheConfig, RateLimitConfig, UpstreamConfig};
use crate::transform::TransformConfig;

/// Top-level tenant configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantConfig {
    /// Unique tenant identifier (e.g., "acme-corp").
    pub id: String,

    /// Human-readable display name.
    pub display_name: String,

    /// Whether this tenant is active.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Resource quotas for this tenant.
    #[serde(default)]
    pub quotas: Option<TenantQuotas>,

    /// Security defaults for all services in this tenant.
    #[serde(default)]
    pub security: Option<TenantSecurityDefaults>,

    /// Cache defaults for all services in this tenant.
    #[serde(default)]
    pub cache: Option<TenantCacheDefaults>,

    /// Environments (dev, staging, prod, etc.).
    #[serde(default)]
    pub environments: Vec<EnvironmentConfig>,

    /// Custom metadata.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

/// Resource quotas for a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantQuotas {
    /// Maximum requests per second across all services.
    #[serde(default)]
    pub max_rps: Option<u64>,

    /// Maximum concurrent connections.
    #[serde(default)]
    pub max_connections: Option<u64>,

    /// Maximum cache entries.
    #[serde(default)]
    pub max_cache_entries: Option<usize>,
}

/// Default security settings for a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSecurityDefaults {
    /// Default rate limit for all services.
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,

    /// IP allow list.
    #[serde(default)]
    pub ip_allow: Vec<String>,

    /// IP block list.
    #[serde(default)]
    pub ip_block: Vec<String>,
}

/// Default cache settings for a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantCacheDefaults {
    /// Enable caching by default.
    #[serde(default)]
    pub enabled: bool,

    /// Default TTL in seconds.
    #[serde(default)]
    pub default_ttl_secs: Option<u64>,
}

/// An environment within a tenant (e.g., dev, staging, prod).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    /// Environment name (e.g., "prod", "staging").
    pub name: String,

    /// Services in this environment.
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
}

/// A single service within a tenant environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Service name (e.g., "api", "frontend").
    pub name: String,

    /// Hostname for routing to this service.
    #[serde(default)]
    pub hostname: Option<String>,

    /// Path prefix for routing.
    #[serde(default)]
    pub path_prefix: Option<String>,

    /// Upstream configuration for this service.
    pub upstream: ServiceUpstreamConfig,

    /// Service-specific transform overrides.
    #[serde(default)]
    pub transform: Option<TransformConfig>,
}

/// Simplified upstream config for tenant services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceUpstreamConfig {
    /// Backend servers.
    pub servers: Vec<BackendServer>,

    /// Load balancing strategy.
    #[serde(default = "default_lb")]
    pub load_balancing: String,
}

fn default_lb() -> String {
    "round_robin".to_string()
}

/// Flatten tenant configurations into effective upstream configs.
///
/// Each tenant/environment/service combination produces a uniquely-named
/// upstream that the routing engine or proxy can reference.
pub fn flatten_tenants(tenants: &[TenantConfig]) -> Vec<UpstreamConfig> {
    let mut upstreams = Vec::new();

    for tenant in tenants {
        if !tenant.enabled {
            continue;
        }

        for env in &tenant.environments {
            for service in &env.services {
                // Generate a unique upstream name: "tenant-id.env.service"
                let upstream_name =
                    format!("{}.{}.{}", tenant.id, env.name, service.name);

                let upstream = UpstreamConfig {
                    name: upstream_name,
                    servers: service.upstream.servers.clone(),
                    load_balancing: service.upstream.load_balancing.clone(),
                    health_check: None,
                    circuit_breaker: None,
                    retry: None,
                    transform: service.transform.clone(),
                };

                upstreams.push(upstream);
            }
        }
    }

    upstreams
}

/// Summary of a tenant for API responses.
#[derive(Debug, Clone, Serialize)]
pub struct TenantSummary {
    pub id: String,
    pub display_name: String,
    pub enabled: bool,
    pub environments: Vec<String>,
    pub total_services: usize,
}

/// Summarize tenants for the management API.
pub fn summarize_tenants(tenants: &[TenantConfig]) -> Vec<TenantSummary> {
    tenants
        .iter()
        .map(|t| {
            let total_services: usize =
                t.environments.iter().map(|e| e.services.len()).sum();
            TenantSummary {
                id: t.id.clone(),
                display_name: t.display_name.clone(),
                enabled: t.enabled,
                environments: t.environments.iter().map(|e| e.name.clone()).collect(),
                total_services,
            }
        })
        .collect()
}
