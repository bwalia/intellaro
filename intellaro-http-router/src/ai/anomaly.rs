//! Anomaly detection.
//!
//! Monitors traffic patterns per backend and per route, detecting
//! sudden spikes, unusual error rates, or latency degradation using
//! statistical methods (z-score over sliding windows).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};

use dashmap::DashMap;
use tracing::{info, warn};

use crate::config::{AnomalyAction, AnomalyDetectionConfig};

/// A single traffic sample in the sliding window.
#[derive(Debug, Clone, Copy)]
struct TrafficSample {
    /// Requests per second observed at this timestamp.
    rps: f64,
    /// Average latency in ms.
    latency_ms: f64,
    /// Error rate (0.0–1.0).
    error_rate: f64,
    /// Timestamp (epoch seconds).
    timestamp: i64,
}

/// Anomaly detection state for a single entity (backend or route).
struct AnomalyWindow {
    samples: VecDeque<TrafficSample>,
    max_samples: usize,
    /// Whether an anomaly is currently active.
    anomaly_active: AtomicBool,
}

impl AnomalyWindow {
    fn new(max_samples: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(max_samples),
            max_samples,
            anomaly_active: AtomicBool::new(false),
        }
    }

    fn push(&mut self, sample: TrafficSample) {
        self.samples.push_back(sample);
        if self.samples.len() > self.max_samples {
            self.samples.pop_front();
        }
    }
}

/// Result of an anomaly evaluation.
#[derive(Debug, Clone)]
pub struct AnomalyResult {
    /// Entity being monitored (backend ID or route name).
    pub entity: String,
    /// Whether an anomaly was detected.
    pub is_anomaly: bool,
    /// Which metric triggered the anomaly.
    pub trigger: Option<AnomalyTrigger>,
    /// Z-score of the triggering metric.
    pub z_score: f64,
    /// Recommended action.
    pub action: AnomalyAction,
}

/// Which metric triggered the anomaly.
#[derive(Debug, Clone)]
pub enum AnomalyTrigger {
    /// RPS spike or drop.
    RequestRate { current: f64, mean: f64 },
    /// Latency degradation.
    Latency { current_ms: f64, mean_ms: f64 },
    /// Error rate spike.
    ErrorRate { current: f64, mean: f64 },
}

/// The anomaly detector monitors all registered entities.
pub struct AnomalyDetector {
    config: AnomalyDetectionConfig,
    /// Per-entity sliding windows.
    windows: DashMap<String, AnomalyWindow>,
    /// Max samples per window (derived from config).
    max_samples: usize,
}

impl AnomalyDetector {
    pub fn new(config: AnomalyDetectionConfig) -> Self {
        // Assume ~1 sample per second, window_secs determines buffer size.
        let max_samples = config.window_secs.max(60) as usize;

        Self {
            config,
            windows: DashMap::new(),
            max_samples,
        }
    }

    /// Record a traffic observation for an entity.
    pub fn record(
        &self,
        entity: &str,
        rps: f64,
        latency_ms: f64,
        error_rate: f64,
    ) {
        if !self.config.enabled {
            return;
        }

        let now = chrono::Utc::now().timestamp();
        let sample = TrafficSample {
            rps,
            latency_ms,
            error_rate,
            timestamp: now,
        };

        let mut window = self
            .windows
            .entry(entity.to_string())
            .or_insert_with(|| AnomalyWindow::new(self.max_samples));

        window.push(sample);
    }

    /// Evaluate whether the latest observation for an entity is anomalous.
    pub fn evaluate(&self, entity: &str) -> AnomalyResult {
        let default_result = AnomalyResult {
            entity: entity.to_string(),
            is_anomaly: false,
            trigger: None,
            z_score: 0.0,
            action: self.config.action.clone(),
        };

        if !self.config.enabled {
            return default_result;
        }

        let window = match self.windows.get(entity) {
            Some(w) => w,
            None => return default_result,
        };

        if window.samples.len() < 10 {
            // Not enough data to detect anomalies.
            return default_result;
        }

        let latest = match window.samples.back() {
            Some(s) => *s,
            None => return default_result,
        };

        // Check each metric for z-score exceeding threshold.
        let threshold = self.config.z_score_threshold;

        // RPS anomaly.
        let (rps_mean, rps_std) = Self::mean_std(window.samples.iter().map(|s| s.rps));
        if rps_std > 0.0 {
            let rps_z = (latest.rps - rps_mean).abs() / rps_std;
            if rps_z > threshold {
                let result = AnomalyResult {
                    entity: entity.to_string(),
                    is_anomaly: true,
                    trigger: Some(AnomalyTrigger::RequestRate {
                        current: latest.rps,
                        mean: rps_mean,
                    }),
                    z_score: rps_z,
                    action: self.config.action.clone(),
                };
                self.on_anomaly_detected(&result);
                return result;
            }
        }

        // Latency anomaly.
        let (lat_mean, lat_std) = Self::mean_std(window.samples.iter().map(|s| s.latency_ms));
        if lat_std > 0.0 {
            let lat_z = (latest.latency_ms - lat_mean) / lat_std;
            if lat_z > threshold {
                let result = AnomalyResult {
                    entity: entity.to_string(),
                    is_anomaly: true,
                    trigger: Some(AnomalyTrigger::Latency {
                        current_ms: latest.latency_ms,
                        mean_ms: lat_mean,
                    }),
                    z_score: lat_z,
                    action: self.config.action.clone(),
                };
                self.on_anomaly_detected(&result);
                return result;
            }
        }

        // Error rate anomaly.
        let (err_mean, err_std) = Self::mean_std(window.samples.iter().map(|s| s.error_rate));
        if err_std > 0.0 {
            let err_z = (latest.error_rate - err_mean) / err_std;
            if err_z > threshold {
                let result = AnomalyResult {
                    entity: entity.to_string(),
                    is_anomaly: true,
                    trigger: Some(AnomalyTrigger::ErrorRate {
                        current: latest.error_rate,
                        mean: err_mean,
                    }),
                    z_score: err_z,
                    action: self.config.action.clone(),
                };
                self.on_anomaly_detected(&result);
                return result;
            }
        }

        // No anomaly — clear active flag if it was set.
        if let Some(w) = self.windows.get(entity) {
            if w.anomaly_active.load(Ordering::Relaxed) {
                w.anomaly_active.store(false, Ordering::Relaxed);
                info!(entity = %entity, "Anomaly resolved");
            }
        }

        default_result
    }

    /// Check if an entity currently has an active anomaly.
    pub fn is_anomaly_active(&self, entity: &str) -> bool {
        self.windows
            .get(entity)
            .map(|w| w.anomaly_active.load(Ordering::Relaxed))
            .unwrap_or(false)
    }

    /// Called when a new anomaly is detected.
    fn on_anomaly_detected(&self, result: &AnomalyResult) {
        if let Some(w) = self.windows.get(&result.entity) {
            w.anomaly_active.store(true, Ordering::Relaxed);
        }

        warn!(
            entity = %result.entity,
            z_score = result.z_score,
            trigger = ?result.trigger,
            action = ?result.action,
            "Anomaly detected"
        );

        metrics::counter!("intellaro_router_anomalies_total", "entity" => result.entity.clone())
            .increment(1);
    }

    /// Compute mean and standard deviation from an iterator of f64.
    fn mean_std(values: impl Iterator<Item = f64>) -> (f64, f64) {
        let data: Vec<f64> = values.collect();
        if data.is_empty() {
            return (0.0, 0.0);
        }

        let n = data.len() as f64;
        let mean = data.iter().sum::<f64>() / n;
        let variance = data.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
        let std = variance.sqrt();

        (mean, std)
    }
}
