//! AI-powered routing intelligence.
//!
//! Provides request classification, predictive load balancing,
//! anomaly detection, and adaptive traffic decisions.
//!
//! All AI features are designed to run in-process with minimal
//! latency overhead — no external model serving is required
//! for the built-in heuristic models.

pub mod anomaly;
pub mod classifier;
pub mod model;
pub mod predictor;
