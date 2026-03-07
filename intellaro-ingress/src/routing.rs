//! Rules-driven routing evaluator.
//!
//! Evaluates IntellaroRoutingPolicy CRDs and translates them into
//! concrete routing configuration for `intellaro-http-server`. Supports
//! traffic splitting, SLA routing, canary deployments, failover, and
//! AI-assisted routing decisions.

use std::sync::Arc;

use serde_json::json;
use tracing::{debug, info, warn};

use crate::crd::routing_policy::{
    IntellaroRoutingPolicy, RoutingPolicyType,
};
use crate::error::IngressResult;

/// Evaluated routing rules ready for MCP configuration push.
#[derive(Debug, Clone, Default)]
pub struct EvaluatedRouting {
    /// Traffic split rules for the router config.
    pub traffic_splits: Vec<serde_json::Value>,
    /// SLA/priority tier definitions.
    pub priority_tiers: Vec<serde_json::Value>,
    /// Canary deployment definitions.
    pub canary_deployments: Vec<serde_json::Value>,
    /// Failover rules.
    pub failover_rules: Vec<serde_json::Value>,
    /// AI routing configuration.
    pub ai_config: Option<serde_json::Value>,
    /// Per-policy rate limits.
    pub rate_limits: Vec<serde_json::Value>,
    /// Header manipulation rules.
    pub header_rules: Vec<serde_json::Value>,
    /// Total policies evaluated.
    pub total_policies: u32,
    /// Active policies count.
    pub active_policies: u32,
}

/// Evaluate all routing policies and produce a merged routing configuration.
pub fn evaluate_policies(
    policies: &[Arc<IntellaroRoutingPolicy>],
) -> IngressResult<EvaluatedRouting> {
    let mut result = EvaluatedRouting::default();

    // Sort policies by priority descending.
    let mut sorted: Vec<&Arc<IntellaroRoutingPolicy>> = policies.iter().collect();
    sorted.sort_by(|a, b| b.spec.priority.cmp(&a.spec.priority));

    result.total_policies = sorted.len() as u32;

    for policy in sorted {
        let spec = &policy.spec;
        let name = policy.metadata.name.clone().unwrap_or_default();

        if !spec.enabled {
            debug!(policy = %name, "Skipping disabled routing policy");
            continue;
        }

        result.active_policies += 1;
        debug!(
            policy = %name,
            policy_type = ?spec.policy_type,
            priority = spec.priority,
            "Evaluating routing policy"
        );

        // Evaluate by policy type.
        match spec.policy_type {
            RoutingPolicyType::General => {
                evaluate_general_policy(&name, spec, &mut result);
            }
            RoutingPolicyType::Canary => {
                evaluate_canary_policy(&name, spec, &mut result);
            }
            RoutingPolicyType::SlaPriority => {
                evaluate_sla_policy(&name, spec, &mut result);
            }
            RoutingPolicyType::Mirror => {
                // Traffic mirroring is a future extension.
                debug!(policy = %name, "Mirror policy type — not yet implemented");
            }
            RoutingPolicyType::Failover => {
                evaluate_failover_policy(&name, spec, &mut result);
            }
            RoutingPolicyType::AiAssisted => {
                evaluate_ai_policy(&name, spec, &mut result);
            }
        }

        // Evaluate match conditions and header manipulation common to all types.
        if let Some(ref headers) = spec.headers {
            let header_rule = json!({
                "policy": name,
                "priority": spec.priority,
                "request_set": headers.request_set.iter().map(|h| json!({
                    "name": h.name,
                    "value": h.value,
                })).collect::<Vec<_>>(),
                "response_set": headers.response_set.iter().map(|h| json!({
                    "name": h.name,
                    "value": h.value,
                })).collect::<Vec<_>>(),
                "request_remove": headers.request_remove,
                "response_remove": headers.response_remove,
            });
            result.header_rules.push(header_rule);
        }

        if let Some(ref rl) = spec.rate_limit {
            let rate_limit = json!({
                "policy": name,
                "max_requests": rl.max_requests,
                "window_secs": rl.window_secs,
                "key": serde_json::to_value(&rl.key).unwrap_or(json!("clientIp")),
            });
            result.rate_limits.push(rate_limit);
        }
    }

    info!(
        total = result.total_policies,
        active = result.active_policies,
        traffic_splits = result.traffic_splits.len(),
        canary = result.canary_deployments.len(),
        sla_tiers = result.priority_tiers.len(),
        failover = result.failover_rules.len(),
        "Routing policy evaluation complete"
    );

    Ok(result)
}

/// Evaluate a general-purpose routing policy (traffic splitting).
fn evaluate_general_policy(
    name: &str,
    spec: &crate::crd::routing_policy::IntellaroRoutingPolicySpec,
    result: &mut EvaluatedRouting,
) {
    if spec.traffic_split.is_empty() {
        return;
    }

    let mut split_entry = json!({
        "policy": name,
        "priority": spec.priority,
        "targets": [],
    });

    // Build match conditions if present.
    if let Some(ref conditions) = spec.match_conditions {
        split_entry["match"] = build_match_json(conditions);
    }

    // Build target refs.
    if !spec.target_refs.is_empty() {
        split_entry["target_refs"] = json!(spec.target_refs.iter().map(|t| json!({
            "kind": t.kind,
            "name": t.name,
        })).collect::<Vec<_>>());
    }

    let splits: Vec<serde_json::Value> = spec
        .traffic_split
        .iter()
        .map(|ts| {
            json!({
                "backend_group": ts.backend_group,
                "weight": ts.weight,
                "response_header": ts.response_header,
            })
        })
        .collect();

    split_entry["splits"] = json!(splits);
    result.traffic_splits.push(split_entry);
}

/// Evaluate a canary deployment policy.
fn evaluate_canary_policy(
    name: &str,
    spec: &crate::crd::routing_policy::IntellaroRoutingPolicySpec,
    result: &mut EvaluatedRouting,
) {
    let canary = match &spec.canary {
        Some(c) => c,
        None => {
            warn!(policy = %name, "Canary policy has no canary configuration");
            return;
        }
    };

    let entry = json!({
        "name": name,
        "primary_group": canary.primary_group,
        "canary_group": canary.canary_group,
        "canary_weight": canary.canary_weight,
        "canary_header": canary.canary_header,
        "canary_cookie": canary.canary_cookie,
        "adaptive": canary.adaptive,
        "max_adaptive_weight": canary.max_adaptive_weight,
    });

    result.canary_deployments.push(entry);
}

/// Evaluate an SLA/priority routing policy.
fn evaluate_sla_policy(
    name: &str,
    spec: &crate::crd::routing_policy::IntellaroRoutingPolicySpec,
    result: &mut EvaluatedRouting,
) {
    let sla = match &spec.sla_routing {
        Some(s) => s,
        None => {
            warn!(policy = %name, "SLA policy has no SLA routing configuration");
            return;
        }
    };

    let identifier = serde_json::to_value(&sla.identifier).unwrap_or(json!("header"));

    for tier in &sla.tiers {
        let tier_entry = json!({
            "policy": name,
            "name": tier.name,
            "value": tier.value,
            "identifier": identifier,
            "dedicated_backend": tier.dedicated_backend,
            "rate_multiplier": tier.rate_multiplier,
            "priority_level": tier.priority_level,
        });
        result.priority_tiers.push(tier_entry);
    }
}

/// Evaluate a failover routing policy.
fn evaluate_failover_policy(
    name: &str,
    spec: &crate::crd::routing_policy::IntellaroRoutingPolicySpec,
    result: &mut EvaluatedRouting,
) {
    let failover = match &spec.failover {
        Some(f) => f,
        None => {
            warn!(policy = %name, "Failover policy has no failover configuration");
            return;
        }
    };

    let entry = json!({
        "policy": name,
        "primary_group": failover.primary_group,
        "fallback_group": failover.fallback_group,
        "error_threshold": failover.error_threshold,
        "consecutive_failures": failover.consecutive_failures,
        "recovery_secs": failover.recovery_secs,
    });

    result.failover_rules.push(entry);
}

/// Evaluate an AI-assisted routing policy.
fn evaluate_ai_policy(
    name: &str,
    spec: &crate::crd::routing_policy::IntellaroRoutingPolicySpec,
    result: &mut EvaluatedRouting,
) {
    let ai = match &spec.ai_routing {
        Some(a) => a,
        None => {
            warn!(policy = %name, "AI policy has no AI routing configuration");
            return;
        }
    };

    let class_routes: Vec<serde_json::Value> = ai
        .class_routes
        .iter()
        .map(|cr| {
            json!({
                "class": cr.class_label,
                "backend_group": cr.backend_group,
            })
        })
        .collect();

    let entry = json!({
        "policy": name,
        "predictive_enabled": ai.predictive_enabled,
        "anomaly_rerouting": ai.anomaly_rerouting,
        "classification_enabled": ai.classification_enabled,
        "class_routes": class_routes,
    });

    // AI config is merged (last-wins for global settings).
    result.ai_config = Some(entry);
}

/// Build a JSON match conditions object from the CRD spec.
fn build_match_json(
    conditions: &crate::crd::routing_policy::RoutingMatchConditions,
) -> serde_json::Value {
    let mut match_obj = json!({});

    if !conditions.headers.is_empty() {
        match_obj["headers"] = json!(conditions.headers.iter().map(|h| json!({
            "name": h.name,
            "exact": h.exact,
            "regex": h.regex,
            "present": h.present,
        })).collect::<Vec<_>>());
    }

    if !conditions.cookies.is_empty() {
        match_obj["cookies"] = json!(conditions.cookies.iter().map(|c| json!({
            "name": c.name,
            "exact": c.exact,
            "regex": c.regex,
        })).collect::<Vec<_>>());
    }

    if !conditions.query_params.is_empty() {
        match_obj["query_params"] = json!(conditions.query_params.iter().map(|q| json!({
            "name": q.name,
            "exact": q.exact,
            "regex": q.regex,
        })).collect::<Vec<_>>());
    }

    if !conditions.source_cidrs.is_empty() {
        match_obj["source_cidrs"] = json!(conditions.source_cidrs);
    }

    if !conditions.methods.is_empty() {
        match_obj["methods"] = json!(conditions.methods);
    }

    if let Some(ref ct) = conditions.content_type {
        match_obj["content_type"] = json!(ct);
    }

    if let Some(ref prefix) = conditions.path_prefix {
        match_obj["path_prefix"] = json!(prefix);
    }

    if let Some(ref regex) = conditions.path_regex {
        match_obj["path_regex"] = json!(regex);
    }

    match_obj
}
