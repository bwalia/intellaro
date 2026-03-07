//! Shared routing state.
//!
//! Holds all runtime state for the routing engine: compiled matchers,
//! backend registry, AI components, canary deployments, and priority
//! router. Designed for concurrent access from multiple async tasks.

use std::sync::{Arc, RwLock};

use tracing::{info, warn};

use crate::ai::anomaly::AnomalyDetector;
use crate::ai::classifier::RequestClassifier;
use crate::ai::model::{HeuristicModel, RoutingModel};
use crate::ai::predictor::PredictiveBalancer;
use crate::balancer::{Backend, BackendGroup, BackendRegistry};
use crate::canary::CanaryRegistry;
use crate::config::RouterConfig;
use crate::matcher::{CompiledMatcher, MatcherError};
use crate::priority::PriorityRouter;

/// Central routing state shared across all request-handling tasks.
///
/// This struct is wrapped in an `Arc` and handed to the routing engine.
/// Hot-reload swaps the inner state atomically via `RwLock`.
pub struct RouterState {
    /// Compiled routing rules, sorted by (priority DESC, index ASC).
    pub matchers: RwLock<Vec<CompiledMatcher>>,

    /// Backend group registry.
    pub backends: BackendRegistry,

    /// AI request classifier.
    pub classifier: RwLock<Option<RequestClassifier>>,

    /// AI predictive balancer.
    pub predictor: RwLock<Option<Arc<PredictiveBalancer>>>,

    /// Anomaly detector.
    pub anomaly_detector: RwLock<Option<Arc<AnomalyDetector>>>,

    /// Canary deployment registry.
    pub canary_registry: CanaryRegistry,

    /// SLA/priority router.
    pub priority_router: RwLock<PriorityRouter>,

    /// Current configuration (for introspection / API).
    pub config: RwLock<RouterConfig>,
}

impl RouterState {
    /// Build routing state from a configuration.
    pub fn from_config(config: RouterConfig) -> Result<Self, StateError> {
        // Compile routing matchers, sorted by priority descending.
        let mut matchers = Vec::with_capacity(config.rules.len());
        for (index, rule) in config.rules.iter().enumerate() {
            if !rule.enabled {
                continue;
            }
            let compiled = CompiledMatcher::compile(
                &rule.name,
                rule.priority,
                &rule.backend_group,
                index,
                &rule.r#match,
            )?;
            matchers.push(compiled);
        }
        // Sort: highest priority first, then by original index for tiebreaking.
        matchers.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| a.rule_index.cmp(&b.rule_index))
        });

        // Initialize AI model (shared across classifier + predictor).
        let model: Arc<dyn RoutingModel> = Arc::new(HeuristicModel::new());

        // Build classifier if enabled.
        let classifier = if config.ai.classification_enabled {
            let rc = RequestClassifier::new(
                Arc::clone(&model),
                config.ai.class_routes.clone(),
            );
            info!("AI request classification enabled");
            Some(rc)
        } else {
            None
        };

        // Build predictor if enabled.
        let predictor = if config.ai.prediction_enabled {
            let pb = PredictiveBalancer::new(
                Arc::clone(&model),
                config.ai.history_size,
            );
            info!("AI predictive load balancing enabled");
            Some(Arc::new(pb))
        } else {
            None
        };

        // Build anomaly detector if enabled.
        let anomaly_detector = if config.anomaly_detection.enabled {
            let ad = AnomalyDetector::new(config.anomaly_detection.clone());
            info!("Anomaly detection enabled");
            Some(Arc::new(ad))
        } else {
            None
        };

        // Register canary deployments.
        let canary_registry = CanaryRegistry::new();
        for canary_config in &config.canary {
            canary_registry.register(canary_config);
            info!(deployment = %canary_config.name, "Canary deployment registered");
        }

        // Build priority router.
        let priority_router = PriorityRouter::new(config.priority_tiers.clone());
        if !config.priority_tiers.is_empty() {
            info!(
                tiers = config.priority_tiers.len(),
                "SLA priority routing enabled"
            );
        }

        Ok(Self {
            matchers: RwLock::new(matchers),
            backends: BackendRegistry::new(),
            classifier: RwLock::new(classifier),
            predictor: RwLock::new(predictor),
            anomaly_detector: RwLock::new(anomaly_detector),
            canary_registry,
            priority_router: RwLock::new(priority_router),
            config: RwLock::new(config),
        })
    }

    /// Hot-reload: apply a new configuration without dropping state.
    ///
    /// Recompiles matchers, updates AI components and canary/priority
    /// registries. Backend groups are NOT cleared — they must be
    /// registered separately by the server.
    pub fn reload(&self, new_config: RouterConfig) -> Result<(), StateError> {
        info!("Hot-reloading router configuration");

        // Recompile matchers.
        let mut new_matchers = Vec::with_capacity(new_config.rules.len());
        for (index, rule) in new_config.rules.iter().enumerate() {
            if !rule.enabled {
                continue;
            }
            let compiled = CompiledMatcher::compile(
                &rule.name,
                rule.priority,
                &rule.backend_group,
                index,
                &rule.r#match,
            )?;
            new_matchers.push(compiled);
        }
        new_matchers.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| a.rule_index.cmp(&b.rule_index))
        });

        // Swap matchers.
        if let Ok(mut matchers) = self.matchers.write() {
            *matchers = new_matchers;
        } else {
            warn!("Failed to acquire matchers write lock during reload");
        }

        // Re-initialize AI model.
        let model: Arc<dyn RoutingModel> = Arc::new(HeuristicModel::new());

        // Update classifier.
        if let Ok(mut classifier) = self.classifier.write() {
            if new_config.ai.classification_enabled {
                *classifier = Some(RequestClassifier::new(
                    Arc::clone(&model),
                    new_config.ai.class_routes.clone(),
                ));
            } else {
                *classifier = None;
            }
        }

        // Update predictor.
        if let Ok(mut predictor) = self.predictor.write() {
            if new_config.ai.prediction_enabled {
                *predictor = Some(Arc::new(PredictiveBalancer::new(
                    Arc::clone(&model),
                    new_config.ai.history_size,
                )));
            } else {
                *predictor = None;
            }
        }

        // Update anomaly detector.
        if let Ok(mut anomaly) = self.anomaly_detector.write() {
            if new_config.anomaly_detection.enabled {
                *anomaly = Some(Arc::new(AnomalyDetector::new(
                    new_config.anomaly_detection.clone(),
                )));
            } else {
                *anomaly = None;
            }
        }

        // Update priority router.
        if let Ok(mut priority) = self.priority_router.write() {
            priority.update(new_config.priority_tiers.clone());
        }

        // Store the new config for introspection.
        if let Ok(mut config) = self.config.write() {
            *config = new_config;
        }

        info!("Router configuration reloaded successfully");
        Ok(())
    }

    /// Register a backend group from server-side backend definitions.
    pub fn register_backend_group(
        &self,
        name: &str,
        backends: Vec<Backend>,
        strategy: crate::config::BalancerStrategy,
    ) {
        let group = BackendGroup::new(name, backends, strategy);
        self.backends.register(group);
    }

    /// Get a snapshot of the current config for the MCP API.
    pub fn current_config(&self) -> Option<RouterConfig> {
        self.config.read().ok().map(|c| c.clone())
    }
}

/// Errors that can occur during state construction or reload.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("Matcher compilation failed: {0}")]
    MatcherCompilation(#[from] MatcherError),
}

/// Convenience type alias used by the engine and server.
pub type SharedRouterState = Arc<RouterState>;

/// Create a new shared router state from config.
pub fn build_shared_state(config: RouterConfig) -> Result<SharedRouterState, StateError> {
    let state = RouterState::from_config(config)?;
    Ok(Arc::new(state))
}
