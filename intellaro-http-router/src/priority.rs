//! SLA / priority-based routing.
//!
//! Routes requests to dedicated backend pools or adjusts rate limits
//! based on the request's priority tier. Tiers are identified by
//! headers, JWT claims, source IP, or cookies.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::debug;

use crate::config::{PriorityIdentifier, PriorityTier};

/// Result of priority tier identification.
#[derive(Debug, Clone)]
pub struct PriorityResult {
    /// Tier name (e.g., "premium", "standard").
    pub tier_name: String,

    /// Priority level (higher = more important).
    pub level: u32,

    /// Override backend group (if this tier has a dedicated pool).
    pub dedicated_backend: Option<String>,

    /// Rate limit multiplier (1.0 = default, 2.0 = double the limits).
    pub rate_multiplier: f64,
}

/// The priority router evaluates incoming requests to determine
/// their SLA tier.
pub struct PriorityRouter {
    /// Tiers sorted by level descending (highest priority first).
    tiers: Vec<Arc<PriorityTier>>,
}

impl PriorityRouter {
    /// Build a priority router from configuration.
    pub fn new(mut tiers: Vec<PriorityTier>) -> Self {
        // Sort highest priority first for early exit.
        tiers.sort_by(|a, b| b.level.cmp(&a.level));

        Self {
            tiers: tiers.into_iter().map(Arc::new).collect(),
        }
    }

    /// Identify the priority tier for a request.
    ///
    /// Returns `None` if no tier matches (request gets default treatment).
    pub fn identify(
        &self,
        headers: &HashMap<String, String>,
        jwt_claims: Option<&HashMap<String, String>>,
        source_ip: Option<&str>,
        cookies: &HashMap<String, String>,
    ) -> Option<PriorityResult> {
        for tier in &self.tiers {
            if self.matches_identifier(&tier.identifier, headers, jwt_claims, source_ip, cookies) {
                debug!(
                    tier = %tier.name,
                    level = tier.level,
                    "Request matched priority tier"
                );

                return Some(PriorityResult {
                    tier_name: tier.name.clone(),
                    level: tier.level,
                    dedicated_backend: tier.dedicated_backend.clone(),
                    rate_multiplier: tier.rate_multiplier,
                });
            }
        }

        None
    }

    /// Check if a request matches a priority identifier.
    fn matches_identifier(
        &self,
        identifier: &PriorityIdentifier,
        headers: &HashMap<String, String>,
        jwt_claims: Option<&HashMap<String, String>>,
        source_ip: Option<&str>,
        cookies: &HashMap<String, String>,
    ) -> bool {
        match identifier {
            PriorityIdentifier::Header { name, value } => {
                headers.get(&name.to_lowercase()) == Some(value)
            }

            PriorityIdentifier::JwtClaim { claim, value } => {
                jwt_claims
                    .and_then(|claims| claims.get(claim))
                    .map(|v| v == value)
                    .unwrap_or(false)
            }

            PriorityIdentifier::SourceCidr(cidr) => {
                match (source_ip, cidr.parse::<std::net::IpAddr>()) {
                    (Some(ip), Ok(cidr_ip)) => {
                        // Simple exact IP match. For CIDR ranges, a full
                        // ipnet check would be used in production.
                        ip == cidr_ip.to_string()
                    }
                    _ => false,
                }
            }

            PriorityIdentifier::Cookie { name, value } => {
                cookies.get(name.as_str()) == Some(value)
            }
        }
    }

    /// Update the tier list at runtime (hot-reload).
    pub fn update(&mut self, mut tiers: Vec<PriorityTier>) {
        tiers.sort_by(|a, b| b.level.cmp(&a.level));
        self.tiers = tiers.into_iter().map(Arc::new).collect();
    }
}
