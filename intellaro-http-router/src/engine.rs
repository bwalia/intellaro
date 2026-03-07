//! Core routing engine.
//!
//! Orchestrates the full request pipeline:
//!
//! ```text
//! Request ──▶ Matcher ──▶ Priority/SLA ──▶ AI Classifier ──▶ Canary ──▶ Balancer ──▶ Backend
//! ```
//!
//! The engine is the single entry point called by `intellaro-http-server`
//! on every incoming request. It returns a `RoutingDecision` describing
//! which backend to forward to and any header manipulations to apply.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tracing::{debug, warn};

use crate::ai::model::RequestFeatures;
use crate::balancer::BackendState;
use crate::config::{AnomalyAction, BalancerStrategy, HeaderManipulation};
use crate::matcher::{find_match, RequestInfo};
use crate::metrics as route_metrics;
use crate::state::SharedRouterState;

/// The result of routing a single request.
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    /// Backend to forward the request to (host:port or service name).
    pub backend_id: String,

    /// Backend group the backend belongs to.
    pub backend_group: String,

    /// The routing rule that matched (or "default" / "ai_classifier" etc.).
    pub matched_rule: String,

    /// Priority tier (if any).
    pub priority_tier: Option<String>,

    /// Whether this was routed to a canary backend.
    pub is_canary: bool,

    /// Canary deployment name (if applicable).
    pub canary_deployment: Option<String>,

    /// AI classification label (if classification is enabled).
    pub classification: Option<String>,

    /// Header manipulations to apply.
    pub header_manipulation: Option<HeaderManipulation>,

    /// Per-rule timeout override (seconds).
    pub timeout_secs: Option<u64>,

    /// Opaque reference to the backend state (for recording latency/errors).
    pub backend_state: Arc<BackendState>,
}

/// Errors from the routing engine.
#[derive(Debug, thiserror::Error)]
pub enum RoutingError {
    #[error("No matching rule found and no default backend configured")]
    NoMatchingRule,

    #[error("Backend group '{0}' not found in registry")]
    BackendGroupNotFound(String),

    #[error("No healthy backends available in group '{0}'")]
    NoHealthyBackends(String),

    #[error("Anomaly detected for entity '{0}': circuit breaker active")]
    CircuitBreakerOpen(String),
}

/// The routing engine — call `route()` on every incoming request.
pub struct RoutingEngine {
    state: SharedRouterState,
}

impl RoutingEngine {
    /// Create a new routing engine backed by shared state.
    pub fn new(state: SharedRouterState) -> Self {
        Self { state }
    }

    /// Route a request through the full pipeline.
    ///
    /// This is the hot-path function called on every incoming request.
    /// It must be fast — all heavy initialization happens in `RouterState`.
    pub fn route(
        &self,
        request: &RequestInfo<'_>,
        jwt_claims: Option<&HashMap<String, String>>,
        source_ip: Option<&str>,
    ) -> Result<RoutingDecision, RoutingError> {
        let start = Instant::now();

        // ── Step 1: Priority/SLA tier identification ────────────────────
        let priority_result = {
            let priority_router = self
                .state
                .priority_router
                .read()
                .expect("priority_router lock poisoned");
            priority_router.identify(
                request.headers,
                jwt_claims,
                source_ip,
                request.cookies,
            )
        };

        if let Some(ref pr) = priority_result {
            route_metrics::record_priority_match(&pr.tier_name, pr.level);
        }

        // If the priority tier has a dedicated backend, use that directly.
        if let Some(ref pr) = priority_result {
            if let Some(ref dedicated) = pr.dedicated_backend {
                return self.select_from_group(
                    dedicated,
                    "priority_dedicated",
                    priority_result.as_ref().map(|p| p.tier_name.as_str()),
                    false,
                    None,
                    None,
                    None,
                    None,
                    source_ip,
                    start,
                );
            }
        }

        // ── Step 2: AI request classification ──────────────────────────
        let classification = {
            let classifier_guard = self
                .state
                .classifier
                .read()
                .expect("classifier lock poisoned");
            classifier_guard.as_ref().map(|c| {
                let features = self.extract_features(request, source_ip);
                c.classify(&features)
            })
        };

        if let Some(ref cl) = classification {
            route_metrics::record_classification(&cl.class, cl.confidence);

            // If the classifier mapped this to a backend group, use it.
            if let Some(ref target_group) = cl.target_group {
                return self.select_from_group(
                    target_group,
                    &format!("ai_classifier:{}", cl.class),
                    priority_result.as_ref().map(|p| p.tier_name.as_str()),
                    false,
                    None,
                    Some(cl.class.clone()),
                    None,
                    None,
                    source_ip,
                    start,
                );
            }
        }

        // ── Step 3: Rule matching ──────────────────────────────────────
        let matchers = self
            .state
            .matchers
            .read()
            .expect("matchers lock poisoned");

        let matched = find_match(&matchers, request);

        let (backend_group_name, rule_name, header_manipulation, timeout_secs) =
            if let Some(m) = matched {
                (
                    m.backend_group.clone(),
                    m.rule_name.clone(),
                    None::<HeaderManipulation>,
                    None::<u64>,
                )
            } else {
                route_metrics::record_fallback();
                return Err(RoutingError::NoMatchingRule);
            };
        // Drop the read lock before doing further work.
        drop(matchers);

        // Look up header manipulation and timeout from config.
        let (header_manipulation, timeout_secs) = {
            let config = self.state.config.read().expect("config lock poisoned");
            let rule = config
                .rules
                .iter()
                .find(|r| r.name == rule_name);
            match rule {
                Some(r) => (r.headers.clone(), r.timeout_secs),
                None => (header_manipulation, timeout_secs),
            }
        };

        // ── Step 4: Canary check ──────────────────────────────────────
        let canary_deployment = self
            .state
            .canary_registry
            .find_for_group(&backend_group_name);

        if let Some(ref deployment) = canary_deployment {
            let (target_group, is_canary) = deployment.route(request.headers, request.cookies);
            route_metrics::record_canary_decision(&deployment.name, is_canary);
            route_metrics::set_canary_weight(&deployment.name, deployment.current_weight());

            return self.select_from_group(
                target_group,
                &rule_name,
                priority_result.as_ref().map(|p| p.tier_name.as_str()),
                is_canary,
                Some(deployment.name.clone()),
                classification.as_ref().map(|c| c.class.clone()),
                header_manipulation,
                timeout_secs,
                source_ip,
                start,
            );
        }

        // ── Step 5: Anomaly check on the target group ─────────────────
        self.check_anomaly(&backend_group_name)?;

        // ── Step 6: Backend selection ─────────────────────────────────
        self.select_from_group(
            &backend_group_name,
            &rule_name,
            priority_result.as_ref().map(|p| p.tier_name.as_str()),
            false,
            None,
            classification.as_ref().map(|c| c.class.clone()),
            header_manipulation,
            timeout_secs,
            source_ip,
            start,
        )
    }

    /// Select a backend from a named group, applying AI prediction if enabled.
    #[allow(clippy::too_many_arguments)]
    fn select_from_group(
        &self,
        group_name: &str,
        rule_name: &str,
        priority_tier: Option<&str>,
        is_canary: bool,
        canary_deployment: Option<String>,
        classification: Option<String>,
        header_manipulation: Option<HeaderManipulation>,
        timeout_secs: Option<u64>,
        source_ip: Option<&str>,
        start: Instant,
    ) -> Result<RoutingDecision, RoutingError> {
        let group = self
            .state
            .backends
            .get(group_name)
            .ok_or_else(|| RoutingError::BackendGroupNotFound(group_name.to_string()))?;

        // Try AI-predictive selection if the strategy is AiPredictive.
        if group.strategy == BalancerStrategy::AiPredictive {
            if let Some(backend) = self.try_predictive_select(&group.backends, source_ip) {
                route_metrics::record_route_decision(rule_name, group_name, &backend.id);
                route_metrics::record_decision_latency(start);

                return Ok(RoutingDecision {
                    backend_id: backend.id.clone(),
                    backend_group: group_name.to_string(),
                    matched_rule: rule_name.to_string(),
                    priority_tier: priority_tier.map(String::from),
                    is_canary,
                    canary_deployment,
                    classification,
                    header_manipulation,
                    timeout_secs,
                    backend_state: backend,
                });
            }
            // Fall through to standard selection if predictor unavailable.
        }

        // Standard load balancer selection using the group's strategy.
        let hash_key = source_ip.unwrap_or("default");
        let backend = group
            .select(Some(hash_key))
            .ok_or_else(|| RoutingError::NoHealthyBackends(group_name.to_string()))?;

        route_metrics::record_route_decision(rule_name, group_name, &backend.id);
        route_metrics::record_decision_latency(start);

        debug!(
            rule = %rule_name,
            group = %group_name,
            backend = %backend.id,
            canary = is_canary,
            "Routing decision made"
        );

        Ok(RoutingDecision {
            backend_id: backend.id.clone(),
            backend_group: group_name.to_string(),
            matched_rule: rule_name.to_string(),
            priority_tier: priority_tier.map(String::from),
            is_canary,
            canary_deployment,
            classification,
            header_manipulation,
            timeout_secs,
            backend_state: backend,
        })
    }

    /// Attempt to use the AI predictor for backend selection.
    fn try_predictive_select(
        &self,
        candidates: &[Arc<BackendState>],
        source_ip: Option<&str>,
    ) -> Option<Arc<BackendState>> {
        let predictor_guard = self
            .state
            .predictor
            .read()
            .expect("predictor lock poisoned");

        let predictor = predictor_guard.as_ref()?;

        let features = RequestFeatures {
            path: String::new(),
            method: String::new(),
            content_type: None,
            content_length: 0,
            user_agent: None,
            source_ip: source_ip.map(String::from),
            authenticated: false,
            custom: HashMap::new(),
        };

        predictor.select_best(&features, candidates)
    }

    /// Check anomaly detection for a backend group and apply the configured action.
    fn check_anomaly(&self, group_name: &str) -> Result<(), RoutingError> {
        let detector_guard = self
            .state
            .anomaly_detector
            .read()
            .expect("anomaly_detector lock poisoned");

        if let Some(ref detector) = *detector_guard {
            if detector.is_anomaly_active(group_name) {
                let config = self.state.config.read().expect("config lock poisoned");
                match &config.anomaly_detection.action {
                    AnomalyAction::CircuitBreak => {
                        warn!(group = %group_name, "Circuit breaker open — rejecting request");
                        return Err(RoutingError::CircuitBreakerOpen(group_name.to_string()));
                    }
                    AnomalyAction::Redirect { fallback_group } => {
                        debug!(
                            group = %group_name,
                            fallback = %fallback_group,
                            "Anomaly redirect to fallback group"
                        );
                        // The caller should retry with the fallback group.
                        // For simplicity we just log; the full redirect would
                        // re-enter select_from_group with the fallback group.
                    }
                    AnomalyAction::Throttle => {
                        debug!(group = %group_name, "Anomaly throttle active");
                        // Throttle logic would reduce concurrency.
                        // For now, allow the request through with a warning.
                    }
                    AnomalyAction::LogOnly => {
                        // Already logged by the anomaly detector.
                    }
                }
            }
        }

        Ok(())
    }

    /// Extract AI model features from a request.
    fn extract_features(
        &self,
        request: &RequestInfo<'_>,
        source_ip: Option<&str>,
    ) -> RequestFeatures {
        let content_length: u64 = request
            .headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let mut custom = HashMap::new();

        // Mark WebSocket upgrades.
        if request
            .headers
            .get("upgrade")
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
        {
            custom.insert("upgrade".to_string(), 1.0);
        }

        RequestFeatures {
            path: request.path.to_string(),
            method: request.method.to_string(),
            content_type: request.content_type.map(String::from),
            content_length,
            user_agent: request.headers.get("user-agent").cloned(),
            source_ip: source_ip.map(String::from),
            authenticated: request.headers.contains_key("authorization"),
            custom,
        }
    }

    /// Record observed latency for a backend (feeds the AI predictor).
    pub fn record_backend_latency(&self, backend_id: &str, latency_ms: f64) {
        if let Ok(predictor_guard) = self.state.predictor.read() {
            if let Some(ref predictor) = *predictor_guard {
                predictor.record_latency(backend_id, latency_ms);
            }
        }
    }

    /// Record a backend error (feeds anomaly detector + canary adapter).
    pub fn record_backend_error(
        &self,
        backend_id: &str,
        backend_group: &str,
        is_canary: bool,
        canary_deployment: Option<&str>,
    ) {
        crate::balancer::record_error_by_id(&self.state.backends, backend_group, backend_id);

        // Feed canary error tracking.
        if let Some(deployment_name) = canary_deployment {
            if let Some(deployment) = self.state.canary_registry.get(deployment_name) {
                deployment.record_error(is_canary);
            }
        }
    }

    /// Release a backend connection (call after response is forwarded).
    pub fn release_backend(&self, backend: &BackendState) {
        crate::balancer::release_connection(backend);
    }

    /// Run adaptive canary weight adjustments (call periodically).
    pub fn adapt_canaries(&self) {
        self.state.canary_registry.adapt_all();
    }

    /// Record traffic metrics for anomaly detection (call periodically).
    pub fn record_anomaly_observation(
        &self,
        entity: &str,
        rps: f64,
        latency_ms: f64,
        error_rate: f64,
    ) {
        if let Ok(detector_guard) = self.state.anomaly_detector.read() {
            if let Some(ref detector) = *detector_guard {
                detector.record(entity, rps, latency_ms, error_rate);
            }
        }
    }

    /// Evaluate anomaly status for an entity (call periodically).
    pub fn evaluate_anomaly(&self, entity: &str) {
        if let Ok(detector_guard) = self.state.anomaly_detector.read() {
            if let Some(ref detector) = *detector_guard {
                let result = detector.evaluate(entity);
                if result.is_anomaly {
                    if let Some(ref trigger) = result.trigger {
                        let trigger_name = match trigger {
                            crate::ai::anomaly::AnomalyTrigger::RequestRate { .. } => {
                                "request_rate"
                            }
                            crate::ai::anomaly::AnomalyTrigger::Latency { .. } => "latency",
                            crate::ai::anomaly::AnomalyTrigger::ErrorRate { .. } => "error_rate",
                        };
                        route_metrics::record_anomaly(entity, trigger_name);
                    }
                }
            }
        }
    }

    /// Get a reference to the shared state (for server integration).
    pub fn state(&self) -> &SharedRouterState {
        &self.state
    }
}
