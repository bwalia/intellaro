//! Request classifier.
//!
//! Uses an AI model to classify incoming requests into categories
//! (e.g., "api", "static", "heavy_compute", "websocket") and then
//! maps those categories to backend groups via configuration.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, trace};

use super::model::{RequestFeatures, RoutingModel};

/// Request classification result.
#[derive(Debug, Clone)]
pub struct Classification {
    /// Class label assigned by the model.
    pub class: String,

    /// Confidence score (0.0 – 1.0).
    pub confidence: f64,

    /// Backend group to route to (if a mapping exists).
    pub target_group: Option<String>,
}

/// The request classifier evaluates requests against an AI model
/// and maps the resulting class labels to backend groups.
pub struct RequestClassifier {
    model: Arc<dyn RoutingModel>,
    /// Mapping from class label → backend group name.
    class_routes: HashMap<String, String>,
    /// Minimum confidence threshold to trust a classification.
    confidence_threshold: f64,
}

impl RequestClassifier {
    /// Create a new classifier with the given model and routing map.
    pub fn new(
        model: Arc<dyn RoutingModel>,
        class_routes: HashMap<String, String>,
    ) -> Self {
        Self {
            model,
            class_routes,
            confidence_threshold: 0.6,
        }
    }

    /// Set the minimum confidence required to use the classification.
    pub fn with_confidence_threshold(mut self, threshold: f64) -> Self {
        self.confidence_threshold = threshold;
        self
    }

    /// Classify a request and return the routing recommendation.
    pub fn classify(&self, features: &RequestFeatures) -> Classification {
        let (class, confidence) = self.model.classify(features);

        let target_group = if confidence >= self.confidence_threshold {
            self.class_routes.get(&class).cloned()
        } else {
            trace!(
                class = %class,
                confidence = confidence,
                threshold = self.confidence_threshold,
                "Classification below confidence threshold — using default routing"
            );
            None
        };

        debug!(
            class = %class,
            confidence = confidence,
            target = ?target_group,
            model = self.model.name(),
            "Request classified"
        );

        Classification {
            class,
            confidence,
            target_group,
        }
    }

    /// Update the class-to-backend routing map at runtime.
    pub fn update_class_routes(&mut self, routes: HashMap<String, String>) {
        self.class_routes = routes;
    }
}
