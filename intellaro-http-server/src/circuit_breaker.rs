//! Circuit breaker and retry policy module.
//!
//! Implements the circuit breaker pattern (Closed → Open → HalfOpen → Closed)
//! to prevent cascading failures, plus configurable retry policies with
//! exponential backoff for transient errors.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::{CircuitBreakerConfig, RetryConfig};

/// Circuit breaker states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation — requests pass through.
    Closed,
    /// Failures exceeded threshold — requests are rejected immediately.
    Open,
    /// Trial period — a limited number of requests are allowed through.
    HalfOpen,
}

/// A single circuit breaker instance for one upstream.
pub struct CircuitBreaker {
    state: RwLock<CircuitState>,
    failure_count: AtomicU64,
    success_count: AtomicU64,
    last_failure_time: RwLock<Option<Instant>>,
    config: CircuitBreakerConfig,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: RwLock::new(CircuitState::Closed),
            failure_count: AtomicU64::new(0),
            success_count: AtomicU64::new(0),
            last_failure_time: RwLock::new(None),
            config,
        }
    }

    /// Check if a request is allowed through.
    /// Returns `true` if the request should proceed, `false` if rejected.
    pub async fn allow_request(&self) -> bool {
        let state = *self.state.read().await;
        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if enough time has passed to transition to HalfOpen.
                let last_failure = self.last_failure_time.read().await;
                if let Some(last) = *last_failure {
                    if last.elapsed() >= Duration::from_secs(self.config.open_duration_secs) {
                        drop(last_failure);
                        let mut state_w = self.state.write().await;
                        if *state_w == CircuitState::Open {
                            *state_w = CircuitState::HalfOpen;
                            self.success_count.store(0, Ordering::Relaxed);
                            debug!("Circuit breaker transitioned to HalfOpen");
                        }
                        return true;
                    }
                }
                false
            }
            CircuitState::HalfOpen => {
                // Allow a limited number of trial requests.
                let successes = self.success_count.load(Ordering::Relaxed);
                successes < self.config.half_open_max_requests
            }
        }
    }

    /// Record a successful request.
    pub async fn record_success(&self) {
        let state = *self.state.read().await;
        match state {
            CircuitState::HalfOpen => {
                let count = self.success_count.fetch_add(1, Ordering::Relaxed) + 1;
                if count >= self.config.half_open_max_requests {
                    let mut state_w = self.state.write().await;
                    *state_w = CircuitState::Closed;
                    self.failure_count.store(0, Ordering::Relaxed);
                    self.success_count.store(0, Ordering::Relaxed);
                    info!("Circuit breaker closed after successful trial requests");
                }
            }
            CircuitState::Closed => {
                // Reset failure count on success in closed state.
                self.failure_count.store(0, Ordering::Relaxed);
            }
            CircuitState::Open => {}
        }
    }

    /// Record a failed request.
    pub async fn record_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
        let mut last_failure = self.last_failure_time.write().await;
        *last_failure = Some(Instant::now());

        let state = *self.state.read().await;
        match state {
            CircuitState::Closed => {
                if count >= self.config.failure_threshold {
                    let mut state_w = self.state.write().await;
                    *state_w = CircuitState::Open;
                    warn!(
                        failures = count,
                        threshold = self.config.failure_threshold,
                        "Circuit breaker opened"
                    );
                    metrics::counter!("circuit_breaker_trips_total").increment(1);
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open goes back to open.
                let mut state_w = self.state.write().await;
                *state_w = CircuitState::Open;
                self.success_count.store(0, Ordering::Relaxed);
                warn!("Circuit breaker re-opened after half-open failure");
            }
            CircuitState::Open => {}
        }
    }

    /// Get the current circuit state.
    pub async fn state(&self) -> CircuitState {
        *self.state.read().await
    }

    /// Get the current failure count.
    pub fn failure_count(&self) -> u64 {
        self.failure_count.load(Ordering::Relaxed)
    }
}

/// Registry of circuit breakers keyed by upstream name.
pub struct CircuitBreakerRegistry {
    breakers: DashMap<String, Arc<CircuitBreaker>>,
}

impl CircuitBreakerRegistry {
    pub fn new() -> Self {
        Self {
            breakers: DashMap::new(),
        }
    }

    /// Register a circuit breaker for an upstream.
    pub fn register(&self, upstream_name: &str, config: CircuitBreakerConfig) {
        self.breakers.insert(
            upstream_name.to_string(),
            Arc::new(CircuitBreaker::new(config)),
        );
    }

    /// Get the circuit breaker for an upstream.
    pub fn get(&self, upstream_name: &str) -> Option<Arc<CircuitBreaker>> {
        self.breakers.get(upstream_name).map(|r| r.value().clone())
    }

    /// Get all circuit breaker states for status reporting.
    pub async fn states(&self) -> Vec<(String, CircuitState, u64)> {
        let mut result = Vec::new();
        for entry in self.breakers.iter() {
            let state = entry.value().state().await;
            let failures = entry.value().failure_count();
            result.push((entry.key().clone(), state, failures));
        }
        result
    }
}

/// Determine if a response status code is retryable.
pub fn is_retryable_status(status: u16, retry_config: &RetryConfig) -> bool {
    retry_config.retry_on_status.contains(&status)
}

/// Calculate backoff duration for a retry attempt.
pub fn calculate_backoff(attempt: u32, retry_config: &RetryConfig) -> Duration {
    let base_ms = retry_config.backoff_base_ms;
    let delay_ms = match retry_config.backoff.as_str() {
        "exponential" => base_ms * 2u64.pow(attempt),
        "linear" => base_ms * (attempt as u64 + 1),
        _ => base_ms, // constant
    };
    // Cap at 10 seconds.
    Duration::from_millis(delay_ms.min(10_000))
}
