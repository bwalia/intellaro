//! Prometheus metrics for routing decisions.
//!
//! Emits counters, histograms, and gauges that integrate with the
//! metrics crate (already used by `intellaro-http-server`).

use std::time::Instant;

/// Record that a routing decision was made.
pub fn record_route_decision(
    rule_name: &str,
    backend_group: &str,
    backend_id: &str,
) {
    metrics::counter!(
        "intellaro_router_decisions_total",
        "rule" => rule_name.to_string(),
        "group" => backend_group.to_string(),
        "backend" => backend_id.to_string(),
    )
    .increment(1);
}

/// Record the latency of the routing decision itself (not the backend).
pub fn record_decision_latency(start: Instant) {
    let elapsed_us = start.elapsed().as_micros() as f64;
    metrics::histogram!("intellaro_router_decision_duration_us").record(elapsed_us);
}

/// Record a request being classified by the AI model.
pub fn record_classification(class: &str, confidence: f64) {
    metrics::counter!(
        "intellaro_router_classifications_total",
        "class" => class.to_string(),
    )
    .increment(1);
    metrics::histogram!("intellaro_router_classification_confidence").record(confidence);
}

/// Record a canary routing decision.
pub fn record_canary_decision(deployment: &str, is_canary: bool) {
    let target = if is_canary { "canary" } else { "primary" };
    metrics::counter!(
        "intellaro_router_canary_decisions_total",
        "deployment" => deployment.to_string(),
        "target" => target,
    )
    .increment(1);
}

/// Record a priority tier match.
pub fn record_priority_match(tier_name: &str, level: u32) {
    metrics::counter!(
        "intellaro_router_priority_matches_total",
        "tier" => tier_name.to_string(),
        "level" => level.to_string(),
    )
    .increment(1);
}

/// Record a routing fallback (no rule matched).
pub fn record_fallback() {
    metrics::counter!("intellaro_router_fallbacks_total").increment(1);
}

/// Record that no backend was available for a group.
pub fn record_no_backend(backend_group: &str) {
    metrics::counter!(
        "intellaro_router_no_backend_total",
        "group" => backend_group.to_string(),
    )
    .increment(1);
}

/// Record an anomaly detection event.
pub fn record_anomaly(entity: &str, trigger: &str) {
    metrics::counter!(
        "intellaro_router_anomaly_events_total",
        "entity" => entity.to_string(),
        "trigger" => trigger.to_string(),
    )
    .increment(1);
}

/// Record a hot-reload event.
pub fn record_reload(success: bool) {
    let status = if success { "success" } else { "failure" };
    metrics::counter!(
        "intellaro_router_reloads_total",
        "status" => status,
    )
    .increment(1);
}

/// Record active canary weight as a gauge.
pub fn set_canary_weight(deployment: &str, weight: u32) {
    metrics::gauge!(
        "intellaro_router_canary_weight",
        "deployment" => deployment.to_string(),
    )
    .set(weight as f64);
}
