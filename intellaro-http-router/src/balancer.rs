//! Load balancing strategies.
//!
//! Implements round-robin, least-connections, weighted, random,
//! consistent-hash, and AI-predictive backend selection.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use tracing::debug;

use crate::config::BalancerStrategy;

/// A backend server in a backend group.
#[derive(Debug, Clone)]
pub struct Backend {
    /// Unique identifier (e.g., "host:port" or service name).
    pub id: String,

    /// Weight for weighted load balancing (higher = more traffic).
    pub weight: u32,

    /// Whether this backend is currently healthy.
    pub healthy: bool,
}

/// Runtime state for a backend (shared across threads).
#[derive(Debug)]
pub struct BackendState {
    pub id: String,
    pub weight: u32,
    pub healthy: std::sync::atomic::AtomicBool,
    pub active_connections: AtomicU64,
    pub total_requests: AtomicU64,
    pub total_errors: AtomicU64,
    /// Smooth weighted-round-robin accumulator (nginx algorithm).
    pub current_weight: std::sync::atomic::AtomicI64,
}

impl BackendState {
    pub fn new(backend: &Backend) -> Self {
        Self {
            id: backend.id.clone(),
            weight: backend.weight,
            healthy: std::sync::atomic::AtomicBool::new(backend.healthy),
            active_connections: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            current_weight: std::sync::atomic::AtomicI64::new(0),
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }
}

/// A backend group with its balancing state.
pub struct BackendGroup {
    pub name: String,
    pub backends: Vec<Arc<BackendState>>,
    pub strategy: BalancerStrategy,
    /// Round-robin counter.
    rr_counter: AtomicU64,
}

impl BackendGroup {
    pub fn new(name: &str, backends: Vec<Backend>, strategy: BalancerStrategy) -> Self {
        let backend_states = backends
            .iter()
            .map(|b| Arc::new(BackendState::new(b)))
            .collect();

        Self {
            name: name.to_string(),
            backends: backend_states,
            strategy,
            rr_counter: AtomicU64::new(0),
        }
    }

    /// Select a backend according to the configured strategy.
    ///
    /// `key` is used for consistent hashing and sticky sessions.
    pub fn select(&self, key: Option<&str>) -> Option<Arc<BackendState>> {
        let healthy: Vec<&Arc<BackendState>> = self
            .backends
            .iter()
            .filter(|b| b.is_healthy())
            .collect();

        if healthy.is_empty() {
            return None;
        }

        let selected = match self.strategy {
            BalancerStrategy::RoundRobin => self.select_round_robin(&healthy),
            BalancerStrategy::LeastConnections => self.select_least_connections(&healthy),
            BalancerStrategy::Weighted => self.select_weighted(&healthy),
            BalancerStrategy::Random => self.select_random(&healthy),
            BalancerStrategy::ConsistentHash => self.select_consistent_hash(&healthy, key),
            BalancerStrategy::AiPredictive => {
                // Fallback to least-connections; the AI predictor overrides
                // this at the engine level.
                self.select_least_connections(&healthy)
            }
        };

        if let Some(ref backend) = selected {
            backend.active_connections.fetch_add(1, Ordering::Relaxed);
            backend.total_requests.fetch_add(1, Ordering::Relaxed);
            debug!(
                group = %self.name,
                backend = %backend.id,
                strategy = ?self.strategy,
                "Backend selected"
            );
        }

        selected
    }

    fn select_round_robin(&self, healthy: &[&Arc<BackendState>]) -> Option<Arc<BackendState>> {
        let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize % healthy.len();
        Some(Arc::clone(healthy[idx]))
    }

    fn select_least_connections(
        &self,
        healthy: &[&Arc<BackendState>],
    ) -> Option<Arc<BackendState>> {
        healthy
            .iter()
            .min_by_key(|b| b.active_connections.load(Ordering::Relaxed))
            .map(|b| Arc::clone(b))
    }

    /// Smooth weighted round-robin (nginx algorithm): interleaves backends
    /// proportionally instead of walking weight blocks, so an 80/20 split
    /// looks like a,a,a,a,b,… rather than 80×a followed by 20×b.
    fn select_weighted(&self, healthy: &[&Arc<BackendState>]) -> Option<Arc<BackendState>> {
        let total_weight: i64 = healthy.iter().map(|b| b.weight as i64).sum();
        if total_weight == 0 {
            return self.select_round_robin(healthy);
        }

        let mut best: Option<&Arc<BackendState>> = None;
        let mut best_current = i64::MIN;

        for backend in healthy {
            let current = backend
                .current_weight
                .fetch_add(backend.weight as i64, Ordering::Relaxed)
                + backend.weight as i64;
            if current > best_current {
                best_current = current;
                best = Some(backend);
            }
        }

        let selected = best?;
        selected.current_weight.fetch_sub(total_weight, Ordering::Relaxed);
        Some(Arc::clone(selected))
    }

    fn select_random(&self, healthy: &[&Arc<BackendState>]) -> Option<Arc<BackendState>> {
        use rand::Rng;
        let mut rng = rand::rng();
        let idx = rng.random_range(0..healthy.len());
        Some(Arc::clone(healthy[idx]))
    }

    fn select_consistent_hash(
        &self,
        healthy: &[&Arc<BackendState>],
        key: Option<&str>,
    ) -> Option<Arc<BackendState>> {
        let key = key.unwrap_or("default");
        let hash = ahash::RandomState::with_seeds(1, 2, 3, 4)
            .hash_one(key);
        let idx = (hash as usize) % healthy.len();
        Some(Arc::clone(healthy[idx]))
    }
}

/// Global registry of backend groups.
pub struct BackendRegistry {
    groups: DashMap<String, Arc<BackendGroup>>,
}

impl BackendRegistry {
    pub fn new() -> Self {
        Self {
            groups: DashMap::new(),
        }
    }

    /// Register or replace a backend group.
    pub fn register(&self, group: BackendGroup) {
        self.groups.insert(group.name.clone(), Arc::new(group));
    }

    /// Get a backend group by name.
    pub fn get(&self, name: &str) -> Option<Arc<BackendGroup>> {
        self.groups.get(name).map(|entry| Arc::clone(entry.value()))
    }

    /// Remove a backend group.
    pub fn remove(&self, name: &str) {
        self.groups.remove(name);
    }

    /// List all group names.
    pub fn group_names(&self) -> Vec<String> {
        self.groups.iter().map(|entry| entry.key().clone()).collect()
    }
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Record that a connection to a backend has been released.
pub fn release_connection(backend: &BackendState) {
    backend.active_connections.fetch_sub(1, Ordering::Relaxed);
}

/// Record that a request to a backend resulted in an error.
pub fn record_error(backend: &BackendState) {
    backend.total_errors.fetch_add(1, Ordering::Relaxed);
}

/// Record an error by backend ID within a backend group (looked up via registry).
pub fn record_error_by_id(registry: &BackendRegistry, group_name: &str, backend_id: &str) {
    if let Some(group) = registry.get(group_name) {
        if let Some(backend) = group.backends.iter().find(|b| b.id == backend_id) {
            backend.total_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod smooth_wrr_tests {
    use super::*;

    #[test]
    fn smooth_wrr_interleaves_and_honors_weights() {
        let group = BackendGroup::new(
            "t",
            vec![
                Backend { id: "a".into(), weight: 80, healthy: true },
                Backend { id: "b".into(), weight: 20, healthy: true },
            ],
            BalancerStrategy::Weighted,
        );

        let mut picks = Vec::new();
        for _ in 0..100 {
            picks.push(group.select(None).unwrap().id.clone());
        }
        for backend in picks.iter() {
            // release the connection we "opened"
            let _ = backend;
        }

        let a = picks.iter().filter(|p| *p == "a").count();
        let b = picks.iter().filter(|p| *p == "b").count();
        assert_eq!(a, 80, "80/20 over 100 picks");
        assert_eq!(b, 20);

        // Interleaving: within any window of 10 picks there is at least one b.
        assert!(
            picks.chunks(10).all(|w| w.iter().any(|p| p == "b")),
            "picks must interleave, got {picks:?}"
        );
    }
}
