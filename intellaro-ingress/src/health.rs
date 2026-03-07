//! Health and readiness probe server.
//!
//! Provides `/healthz` (liveness) and `/readyz` (readiness) endpoints
//! that Kubernetes uses to manage pod lifecycle.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info};

/// Shared readiness state — set to `true` once the controller
/// establishes a connection to the MCP API and the initial
/// reconciliation succeeds.
pub type ReadyFlag = Arc<AtomicBool>;

/// Create a new readiness flag (initially not ready).
pub fn new_ready_flag() -> ReadyFlag {
    Arc::new(AtomicBool::new(false))
}

/// Start the health/readiness HTTP server.
pub async fn serve_health(port: u16, ready: ReadyFlag) {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(port = port, error = %e, "Failed to bind health server");
            return;
        }
    };

    info!(port = port, "Health server listening");

    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                let ready = ready.clone();
                tokio::spawn(async move {
                    // Read the request line to determine the path.
                    let mut buf = [0u8; 1024];
                    let n = match stream.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };

                    let request = String::from_utf8_lossy(&buf[..n]);
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");

                    let (status, body) = match path {
                        "/healthz" => ("200 OK", "ok"),
                        "/readyz" => {
                            if ready.load(Ordering::Relaxed) {
                                ("200 OK", "ready")
                            } else {
                                ("503 Service Unavailable", "not ready")
                            }
                        }
                        _ => ("404 Not Found", "not found"),
                    };

                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len(),
                    );

                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
            Err(e) => {
                error!(error = %e, "Failed to accept health connection");
            }
        }
    }
}
