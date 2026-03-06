//! CLI command modules.
//!
//! Each submodule implements one top-level CLI subcommand group
//! (e.g., `server`, `vhost`, `cache`). Commands are registered
//! in `main.rs` via the `Cli` enum.

pub mod cache;
pub mod cluster;
pub mod completions;
pub mod route;
pub mod security;
pub mod server;
pub mod swagger;
pub mod vhost;
