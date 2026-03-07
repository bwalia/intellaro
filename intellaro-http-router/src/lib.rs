//! # Intellaro HTTP Router
//!
//! An intelligent, AI-powered HTTP routing engine designed to be compiled
//! directly into `intellaro-http-server`. All routing decisions happen
//! in-process with zero network overhead.
//!
//! ## Architecture
//!
//! ```text
//! Request ──▶ Matcher ──▶ Priority/SLA ──▶ AI Classifier ──▶ Balancer ──▶ Backend
//!                │               │               │               │
//!                └── Anomaly ────┘── Canary ─────┘── Predictor ──┘
//! ```
//!
//! The router sits in the `intellaro-http-server` request pipeline between
//! security checks and proxy forwarding. Configuration is managed via the
//! MCP API with hot-reload support.

pub mod ai;
pub mod balancer;
pub mod canary;
pub mod config;
pub mod engine;
pub mod matcher;
pub mod metrics;
pub mod priority;
pub mod state;

// Re-export primary public API.
pub use config::RouterConfig;
pub use engine::RoutingEngine;
pub use state::RouterState;
