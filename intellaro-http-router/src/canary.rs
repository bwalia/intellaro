//! Canary and blue-green deployment routing.
//!
//! Supports percentage-based traffic splitting, header/cookie-based
//! overrides, and AI-adaptive weight adjustment based on error rates
//! and latency comparisons between primary and canary backends.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use tracing::{debug, info, warn};

use crate::config::CanaryConfig;

/// Runtime state for a canary deployment.
pub struct CanaryDeployment {
    pub name: String,
    pub primary_group: String,
    pub canary_group: String,
    /// Current canary weight (0–100).
    pub canary_weight: AtomicU32,
    /// Header that forces canary routing.
    pub canary_header: Option<String>,
    /// Cookie that forces canary routing.
    pub canary_cookie: Option<String>,
    /// Whether adaptive adjustment is enabled.
    pub adaptive: bool,
    /// Request counter for deterministic splitting.
    counter: AtomicU64,
    /// Metrics for adaptive decision-making.
    primary_errors: AtomicU64,
    primary_requests: AtomicU64,
    canary_errors: AtomicU64,
    canary_requests: AtomicU64,
}

impl CanaryDeployment {
    pub fn from_config(config: &CanaryConfig) -> Self {
        Self {
            name: config.name.clone(),
            primary_group: config.primary.clone(),
            canary_group: config.canary.clone(),
            canary_weight: AtomicU32::new(config.canary_weight),
            canary_header: config.canary_header.clone(),
            canary_cookie: config.canary_cookie.clone(),
            adaptive: config.adaptive,
            counter: AtomicU64::new(0),
            primary_errors: AtomicU64::new(0),
            primary_requests: AtomicU64::new(0),
            canary_errors: AtomicU64::new(0),
            canary_requests: AtomicU64::new(0),
        }
    }

    /// Decide which backend group to route to for this request.
    ///
    /// Returns `(backend_group_name, is_canary)`.
    pub fn route(
        &self,
        headers: &std::collections::HashMap<String, String>,
        cookies: &std::collections::HashMap<String, String>,
    ) -> (&str, bool) {
        // Check for explicit canary header override.
        if let Some(ref header_name) = self.canary_header {
            if headers.contains_key(header_name) {
                debug!(deployment = %self.name, "Canary routing via header override");
                self.canary_requests.fetch_add(1, Ordering::Relaxed);
                return (&self.canary_group, true);
            }
        }

        // Check for explicit canary cookie override.
        if let Some(ref cookie_name) = self.canary_cookie {
            if cookies.contains_key(cookie_name) {
                debug!(deployment = %self.name, "Canary routing via cookie override");
                self.canary_requests.fetch_add(1, Ordering::Relaxed);
                return (&self.canary_group, true);
            }
        }

        // Percentage-based split.
        let weight = self.canary_weight.load(Ordering::Relaxed);
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);

        if (counter % 100) < weight as u64 {
            self.canary_requests.fetch_add(1, Ordering::Relaxed);
            (&self.canary_group, true)
        } else {
            self.primary_requests.fetch_add(1, Ordering::Relaxed);
            (&self.primary_group, false)
        }
    }

    /// Record an error for the primary or canary group.
    pub fn record_error(&self, is_canary: bool) {
        if is_canary {
            self.canary_errors.fetch_add(1, Ordering::Relaxed);
        } else {
            self.primary_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Run adaptive weight adjustment based on error rates.
    ///
    /// If canary error rate is significantly higher than primary,
    /// reduce canary weight. If canary is performing well, gradually
    /// increase weight.
    pub fn adapt(&self) {
        if !self.adaptive {
            return;
        }

        let p_req = self.primary_requests.load(Ordering::Relaxed).max(1) as f64;
        let p_err = self.primary_errors.load(Ordering::Relaxed) as f64;
        let c_req = self.canary_requests.load(Ordering::Relaxed).max(1) as f64;
        let c_err = self.canary_errors.load(Ordering::Relaxed) as f64;

        let primary_error_rate = p_err / p_req;
        let canary_error_rate = c_err / c_req;

        let current_weight = self.canary_weight.load(Ordering::Relaxed);

        if canary_error_rate > primary_error_rate * 2.0 && current_weight > 1 {
            // Canary is performing badly — reduce weight.
            let new_weight = (current_weight / 2).max(1);
            self.canary_weight.store(new_weight, Ordering::Relaxed);
            warn!(
                deployment = %self.name,
                old_weight = current_weight,
                new_weight = new_weight,
                canary_err_rate = canary_error_rate,
                primary_err_rate = primary_error_rate,
                "Adaptive canary: reducing weight due to high error rate"
            );
        } else if canary_error_rate <= primary_error_rate * 1.1 && current_weight < 50 {
            // Canary is performing well — gradually increase weight.
            let new_weight = (current_weight + 5).min(50);
            self.canary_weight.store(new_weight, Ordering::Relaxed);
            info!(
                deployment = %self.name,
                old_weight = current_weight,
                new_weight = new_weight,
                "Adaptive canary: increasing weight"
            );
        }
    }

    /// Get current canary weight for metrics.
    pub fn current_weight(&self) -> u32 {
        self.canary_weight.load(Ordering::Relaxed)
    }
}

/// Registry of active canary deployments.
pub struct CanaryRegistry {
    deployments: DashMap<String, Arc<CanaryDeployment>>,
}

impl CanaryRegistry {
    pub fn new() -> Self {
        Self {
            deployments: DashMap::new(),
        }
    }

    /// Register a canary deployment from config.
    pub fn register(&self, config: &CanaryConfig) {
        let deployment = CanaryDeployment::from_config(config);
        self.deployments
            .insert(config.name.clone(), Arc::new(deployment));
    }

    /// Look up a canary deployment that matches a given backend group.
    ///
    /// Returns the deployment if the backend group is either the primary
    /// or canary group of any registered deployment.
    pub fn find_for_group(&self, group_name: &str) -> Option<Arc<CanaryDeployment>> {
        for entry in self.deployments.iter() {
            let d = entry.value();
            if d.primary_group == group_name || d.canary_group == group_name {
                return Some(Arc::clone(d));
            }
        }
        None
    }

    /// Get a deployment by name.
    pub fn get(&self, name: &str) -> Option<Arc<CanaryDeployment>> {
        self.deployments.get(name).map(|e| Arc::clone(e.value()))
    }

    /// Run adaptive adjustments on all deployments.
    pub fn adapt_all(&self) {
        for entry in self.deployments.iter() {
            entry.value().adapt();
        }
    }
}

impl Default for CanaryRegistry {
    fn default() -> Self {
        Self::new()
    }
}
