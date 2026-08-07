//! Intellaro HTTP Server — library crate.
//!
//! The data plane of the Intellaro application delivery platform: an
//! HTTP(S) reverse proxy with load balancing, caching, security policy
//! enforcement, clustering, and a management control plane (MCP).
//!
//! This crate is consumed two ways:
//!
//! * the `intellaro-http-server` binary (this package's `main.rs`), kept
//!   for backwards compatibility, and
//! * the unified `intellaro` binary (`intellaro-cli`), which runs it as
//!   `--role proxy` / `--role all`.
//!
//! Use [`bootstrap::run`] to start the full server from a config path.

pub mod audit;
pub mod bootstrap;
pub mod cache;
pub mod circuit_breaker;
pub mod cluster;
pub mod config;
pub mod config_v1;
pub mod config_versioning;
pub mod logging;
pub mod mcp;
pub mod oidc;
pub mod proxy;
pub mod rbac;
pub mod security;
pub mod server;
pub mod tenant;
pub mod transform;
