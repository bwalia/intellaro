//! Structured logging setup for the ingress controller.
//!
//! Configures `tracing-subscriber` with JSON or pretty output depending
//! on the `RUST_LOG_FORMAT` environment variable.

use tracing_subscriber::{fmt, EnvFilter};

/// Initialise the global tracing subscriber.
///
/// - `RUST_LOG` controls filter levels (default: `info`).
/// - `RUST_LOG_FORMAT=json` switches to JSON output.
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let is_json = std::env::var("RUST_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    // try_init: tolerate an already-installed subscriber so the controller
    // can be embedded in the unified `intellaro` binary.
    if is_json {
        let _ = fmt()
            .json()
            .with_env_filter(filter)
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true)
            .try_init();
    } else {
        let _ = fmt()
            .with_env_filter(filter)
            .with_target(true)
            .try_init();
    }
}
