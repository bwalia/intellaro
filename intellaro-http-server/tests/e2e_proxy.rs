//! End-to-end tests: `intellaro.io/v1` config → running proxy → real backend.
//!
//! Covers the Phase-0 contract: proxy to a configurable upstream, forward
//! request bodies and X-Forwarded-For, and hot-reload the YAML so traffic
//! repoints without a restart.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use intellaro_http_server::bootstrap;
use intellaro_http_server::config::ConfigManager;
use intellaro_http_server::server;

/// Spawn a tiny backend that echoes its tag, the X-Forwarded-For it saw,
/// and the request body.
async fn spawn_backend(tag: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| async move {
                    let xff = req
                        .headers()
                        .get("x-forwarded-for")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let body = req.into_body().collect().await.unwrap().to_bytes();
                    let reply = format!(
                        "{tag}|xff={xff}|body={}",
                        String::from_utf8_lossy(&body)
                    );
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(reply))))
                });
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    addr
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn v1_config(listen_port: u16, backend: SocketAddr) -> String {
    format!(
        r#"
apiVersion: intellaro.io/v1
kind: Gateway
metadata: {{ name: e2e }}
spec:
  listeners:
    - {{ name: http, address: "127.0.0.1", port: {listen_port} }}
  hosts:
    - name: "*"
      routes:
        - match:
            path: {{ type: Prefix, value: / }}
          backends:
            - {{ address: "{backend}" }}
"#
    )
}

#[tokio::test]
async fn proxies_via_v1_config_and_hot_reloads() {
    let backend_a = spawn_backend("backend-a").await;
    let backend_b = spawn_backend("backend-b").await;
    let port = free_port();

    let dir = std::env::temp_dir().join(format!(
        "intellaro-e2e-{}-{port}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("gateway.yaml");
    std::fs::write(&config_path, v1_config(port, backend_a)).unwrap();

    let manager = ConfigManager::load(&config_path).unwrap();
    let config = manager.get().await;
    assert_eq!(config.listeners.len(), 1, "v1 config compiled one listener");

    let engine = bootstrap::build_routing_engine(&config);
    let ready = Arc::new(AtomicBool::new(false));
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    tokio::spawn(server::run(
        manager.clone(),
        shutdown_rx,
        engine,
        Some(ready.clone()),
    ));

    for _ in 0..200 {
        if ready.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(ready.load(Ordering::Relaxed), "server did not become ready");

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/api/echo");

    // GET is proxied to backend A with X-Forwarded-For appended.
    let text = client.get(&url).send().await.unwrap().text().await.unwrap();
    assert!(text.contains("backend-a"), "unexpected response: {text}");
    assert!(text.contains("xff=127.0.0.1"), "missing X-Forwarded-For: {text}");

    // POST bodies are forwarded intact.
    let text = client
        .post(&url)
        .body("ping-pong")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(text.contains("body=ping-pong"), "body not forwarded: {text}");

    // Hot reload: repoint the route at backend B; no restart.
    std::fs::write(&config_path, v1_config(port, backend_b)).unwrap();
    manager.reload().await.unwrap();

    let mut swapped = false;
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let text = client.get(&url).send().await.unwrap().text().await.unwrap();
        if text.contains("backend-b") {
            swapped = true;
            break;
        }
    }
    assert!(swapped, "hot reload did not repoint traffic to backend-b");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn ops_endpoints_report_health_and_readiness() {
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let ready = Arc::new(AtomicBool::new(false));

    // The global metrics recorder may already be installed by another test
    // binary run; ignore failure and build a bare handle in that case.
    let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .unwrap_or_else(|_| {
            metrics_exporter_prometheus::PrometheusBuilder::new()
                .build_recorder()
                .handle()
        });

    let ops_ready = ready.clone();
    tokio::spawn(async move {
        let _ = intellaro_http_server::logging::serve_ops(addr, handle, ops_ready).await;
    });

    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");

    // Wait for the ops server to come up.
    let mut health_ok = false;
    for _ in 0..200 {
        if let Ok(resp) = client.get(format!("{base}/health")).send().await {
            assert_eq!(resp.status(), 200);
            assert!(resp.text().await.unwrap().contains("\"status\":\"ok\""));
            health_ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(health_ok, "ops server never became reachable");

    // Not ready yet → 503.
    let resp = client.get(format!("{base}/ready")).send().await.unwrap();
    assert_eq!(resp.status(), 503);

    ready.store(true, Ordering::Relaxed);
    let resp = client.get(format!("{base}/ready")).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // Prometheus exposition responds.
    let resp = client.get(format!("{base}/metrics")).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // Unknown path → 404.
    let resp = client.get(format!("{base}/nope")).send().await.unwrap();
    assert_eq!(resp.status(), 404);
}

fn v1_phase1_config(listen_port: u16, backend: SocketAddr) -> String {
    format!(
        r#"
apiVersion: intellaro.io/v1
kind: Gateway
metadata: {{ name: phase1 }}
spec:
  listeners:
    - {{ name: http, address: "127.0.0.1", port: {listen_port} }}
  fallback:
    status: 404
    body: "<h1>no such host</h1>"
  hosts:
    - name: phase1.test
      routes:
        - match:
            path: {{ type: Exact, value: /old-login }}
          action: {{ type: redirect, location: "https://sso.example.com/login", status: 301 }}
        - match:
            path: {{ type: Prefix, value: /blocked }}
          action:
            type: static
            status: 403
            bodyBase64: "PGgxPmJsb2NrZWQ8L2gxPg=="
            contentType: text/html
        - match:
            path: {{ type: Prefix, value: /api }}
          backends: [{{ address: "{backend}" }}]
          rewrite: {{ stripPrefix: /api }}
          requestHeaders:
            set: {{ X-Injected: "phase1" }}
          responseHeaders:
            set: {{ X-Powered-By: "intellaro" }}
        - match:
            path: {{ type: Prefix, value: / }}
            sourceCidrs: ["127.0.0.0/8"]
          backends: [{{ address: "{backend}" }}]
"#
    )
}

/// Backend that echoes the request path and selected headers.
async fn spawn_echo_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| async move {
                    let reply = format!(
                        "path={}|xfp={}|inj={}",
                        req.uri().path(),
                        req.headers()
                            .get("x-forwarded-proto")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or(""),
                        req.headers()
                            .get("x-injected")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or(""),
                    );
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(reply))))
                });
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn phase1_actions_rewrites_headers_fallback() {
    let backend = spawn_echo_backend().await;
    let port = free_port();

    let dir = std::env::temp_dir().join(format!("intellaro-p1-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("gateway.yaml");
    std::fs::write(&config_path, v1_phase1_config(port, backend)).unwrap();

    let manager = ConfigManager::load(&config_path).unwrap();
    let config = manager.get().await;
    assert_eq!(config.fallback.mode, "not_found");

    let engine = bootstrap::build_routing_engine(&config);
    let ready = Arc::new(AtomicBool::new(false));
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(server::run(manager.clone(), shutdown_rx, engine, Some(ready.clone())));
    for _ in 0..200 {
        if ready.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(ready.load(Ordering::Relaxed));

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let base = format!("http://127.0.0.1:{port}");
    let host = |req: reqwest::RequestBuilder| req.header("Host", "phase1.test");

    // Redirect action (301 + Location).
    let resp = host(client.get(format!("{base}/old-login"))).send().await.unwrap();
    assert_eq!(resp.status(), 301);
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "https://sso.example.com/login"
    );

    // Static action: 403 with base64-decoded body.
    let resp = host(client.get(format!("{base}/blocked/page"))).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(resp.text().await.unwrap(), "<h1>blocked</h1>");

    // Strip prefix + request header injection + X-Forwarded-Proto +
    // response header set.
    let resp = host(client.get(format!("{base}/api/users?x=1"))).send().await.unwrap();
    assert_eq!(resp.headers().get("x-powered-by").unwrap(), "intellaro");
    let text = resp.text().await.unwrap();
    assert!(text.contains("path=/users"), "prefix not stripped: {text}");
    assert!(text.contains("xfp=http"), "missing X-Forwarded-Proto: {text}");
    assert!(text.contains("inj=phase1"), "request header not injected: {text}");

    // Source-CIDR route matches loopback clients.
    let resp = host(client.get(format!("{base}/anything"))).send().await.unwrap();
    assert!(resp.text().await.unwrap().contains("path=/anything"));

    // Unknown host → branded fallback page, not first-upstream proxying.
    let resp = client
        .get(format!("{base}/whatever"))
        .header("Host", "unknown.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.text().await.unwrap(), "<h1>no such host</h1>");

    let _ = std::fs::remove_dir_all(&dir);
}
