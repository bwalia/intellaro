//! Predictive load balancer.
//!
//! Uses historical latency data and real-time metrics to predict
//! which backend will provide the best response time for a given
//! request. Works alongside the standard load balancers to provide
//! AI-enhanced backend selection.

use std::collections::VecDeque;
use std::sync::Arc;

use dashmap::DashMap;
use tracing::debug;

use super::model::{RequestFeatures, RoutingModel};
use crate::balancer::BackendState;

/// A single latency observation.
#[derive(Debug, Clone, Copy)]
struct LatencySample {
    /// Observed latency in milliseconds.
    latency_ms: f64,
    /// Timestamp (epoch seconds).
    timestamp: i64,
}

/// Predictive backend selector that maintains per-backend latency
/// histograms and uses the AI model to score backends.
pub struct PredictiveBalancer {
    model: Arc<dyn RoutingModel>,
    /// Per-backend latency history: backend_id → ring buffer of samples.
    history: DashMap<String, VecDeque<LatencySample>>,
    /// Maximum samples to retain per backend.
    max_history: usize,
}

impl PredictiveBalancer {
    pub fn new(model: Arc<dyn RoutingModel>, max_history: usize) -> Self {
        Self {
            model,
            history: DashMap::new(),
            max_history,
        }
    }

    /// Record an observed latency for a backend.
    pub fn record_latency(&self, backend_id: &str, latency_ms: f64) {
        let now = chrono::Utc::now().timestamp();
        let sample = LatencySample {
            latency_ms,
            timestamp: now,
        };

        let mut entry = self
            .history
            .entry(backend_id.to_string())
            .or_insert_with(VecDeque::new);

        entry.push_back(sample);
        if entry.len() > self.max_history {
            entry.pop_front();
        }
    }

    /// Select the best backend from the given candidates.
    ///
    /// Scoring combines:
    /// 1. Model-predicted latency for the request type
    /// 2. Observed p50 latency for the backend
    /// 3. Current active connections (load factor)
    /// 4. Error rate
    pub fn select_best(
        &self,
        features: &RequestFeatures,
        candidates: &[Arc<BackendState>],
    ) -> Option<Arc<BackendState>> {
        if candidates.is_empty() {
            return None;
        }

        let mut best: Option<(f64, &Arc<BackendState>)> = None;

        for backend in candidates {
            if !backend.is_healthy() {
                continue;
            }

            let score = self.score_backend(features, backend);

            match best {
                None => best = Some((score, backend)),
                Some((best_score, _)) if score < best_score => {
                    best = Some((score, backend));
                }
                _ => {}
            }
        }

        if let Some((score, backend)) = best {
            debug!(
                backend = %backend.id,
                score = score,
                model = self.model.name(),
                "Predictive balancer selected backend"
            );
            Some(Arc::clone(backend))
        } else {
            None
        }
    }

    /// Score a backend: lower is better.
    fn score_backend(&self, features: &RequestFeatures, backend: &BackendState) -> f64 {
        // Model-predicted latency.
        let predicted_ms = self.model.predict_latency(features, &backend.id);

        // Historical p50 latency.
        let observed_p50 = self.percentile_latency(&backend.id, 0.5);

        // Load factor: penalize backends with many active connections.
        let active = backend
            .active_connections
            .load(std::sync::atomic::Ordering::Relaxed) as f64;
        let load_penalty = active * 5.0; // 5ms penalty per active connection

        // Error rate penalty.
        let total = backend
            .total_requests
            .load(std::sync::atomic::Ordering::Relaxed)
            .max(1) as f64;
        let errors = backend
            .total_errors
            .load(std::sync::atomic::Ordering::Relaxed) as f64;
        let error_rate = errors / total;
        let error_penalty = error_rate * 500.0; // heavy penalty for high error rates

        // Composite score: weighted blend of predicted + observed + penalties.
        let score = predicted_ms * 0.3
            + observed_p50 * 0.4
            + load_penalty * 0.2
            + error_penalty * 0.1;

        score
    }

    /// Calculate a percentile latency from the history buffer.
    fn percentile_latency(&self, backend_id: &str, percentile: f64) -> f64 {
        let entry = match self.history.get(backend_id) {
            Some(e) => e,
            None => return 50.0, // Default assumption when no data.
        };

        if entry.is_empty() {
            return 50.0;
        }

        let mut latencies: Vec<f64> = entry.iter().map(|s| s.latency_ms).collect();
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let idx = ((latencies.len() as f64) * percentile).floor() as usize;
        let idx = idx.min(latencies.len() - 1);
        latencies[idx]
    }

    /// Get summary statistics for a backend (for metrics/API).
    pub fn backend_stats(&self, backend_id: &str) -> Option<BackendPredictionStats> {
        let entry = self.history.get(backend_id)?;

        if entry.is_empty() {
            return None;
        }

        let mut latencies: Vec<f64> = entry.iter().map(|s| s.latency_ms).collect();
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let count = latencies.len();
        let p50 = latencies[count / 2];
        let p95 = latencies[(count as f64 * 0.95).floor() as usize];
        let p99 = latencies[(count as f64 * 0.99).floor() as usize];
        let avg = latencies.iter().sum::<f64>() / count as f64;

        Some(BackendPredictionStats {
            sample_count: count,
            avg_ms: avg,
            p50_ms: p50,
            p95_ms: p95,
            p99_ms: p99,
        })
    }
}

/// Summary statistics for a backend's predicted/observed performance.
#[derive(Debug, Clone)]
pub struct BackendPredictionStats {
    pub sample_count: usize,
    pub avg_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}
