//! End-to-end tests for the streaming data plane: progressive response
//! delivery (SSE), unbuffered request uploads, Host preservation, per-route
//! read timeouts, WebSocket-style upgrades, and gRPC trailers over h2c.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

use intellaro_http_server::bootstrap;
use intellaro_http_server::config::ConfigManager;
use intellaro_http_server::server;

type TestBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

fn boxed(body: impl Into<Bytes>) -> TestBody {
    Full::new(body.into()).boxed()
}

/// Lets the SSE test release the backend's second event on demand.
type Gate = Arc<Mutex<Option<tokio::sync::oneshot::Receiver<()>>>>;

async fn backend_handler(
    mut req: Request<Incoming>,
    gate: Gate,
) -> Result<Response<TestBody>, Infallible> {
    let is_grpc = req
        .headers()
        .get("content-type")
        .is_some_and(|v| v.as_bytes().starts_with(b"application/grpc"));
    if is_grpc {
        let te = req.headers().get("te").cloned();
        let body = req.into_body().collect().await.unwrap().to_bytes();
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        trailers.insert("grpc-message", "ok".parse().unwrap());
        let frames = vec![
            Ok::<_, Infallible>(Frame::data(body)),
            Ok(Frame::trailers(trailers)),
        ];
        let mut resp = Response::new(StreamBody::new(futures::stream::iter(frames)).boxed());
        resp.headers_mut()
            .insert("content-type", "application/grpc".parse().unwrap());
        if let Some(te) = te {
            resp.headers_mut().insert("x-saw-te", te);
        }
        return Ok(resp);
    }

    match req.uri().path() {
        "/sse" => {
            let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(4);
            let release = gate.lock().await.take();
            tokio::spawn(async move {
                let _ = tx.send(Ok(Frame::data(Bytes::from("data: one\n\n")))).await;
                if let Some(release) = release {
                    let _ = release.await;
                }
                let _ = tx.send(Ok(Frame::data(Bytes::from("data: two\n\n")))).await;
            });
            let stream = futures::stream::unfold(rx, |mut rx| async move {
                rx.recv().await.map(|item| (item, rx))
            });
            let mut resp = Response::new(StreamBody::new(stream).boxed());
            resp.headers_mut()
                .insert("content-type", "text/event-stream".parse().unwrap());
            Ok(resp)
        }
        "/upload" => {
            let mut total = 0usize;
            let mut body = req.into_body();
            while let Some(frame) = body.frame().await {
                if let Ok(data) = frame.unwrap().into_data() {
                    total += data.len();
                }
            }
            Ok(Response::new(boxed(format!("received={total}"))))
        }
        "/host" => {
            let host = req
                .headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            Ok(Response::new(boxed(format!("host={host}"))))
        }
        "/slow" => {
            tokio::time::sleep(Duration::from_secs(3)).await;
            Ok(Response::new(boxed("too late")))
        }
        "/ws" => {
            // Protocol-agnostic upgrade: echo raw bytes after the 101.
            let on_upgrade = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                if let Ok(upgraded) = on_upgrade.await {
                    let mut io = TokioIo::new(upgraded);
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = io.read(&mut buf).await {
                        if n == 0 || io.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            });
            let mut resp = Response::new(boxed(Bytes::new()));
            *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            resp.headers_mut().insert("connection", "upgrade".parse().unwrap());
            resp.headers_mut().insert("upgrade", "websocket".parse().unwrap());
            resp.headers_mut()
                .insert("sec-websocket-accept", "test-accept".parse().unwrap());
            Ok(resp)
        }
        _ => Ok(Response::new(boxed("ok"))),
    }
}

async fn spawn_backend(gate: Gate) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => return,
            };
            let gate = gate.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| backend_handler(req, gate.clone()));
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(stream), svc)
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

fn config(listen_port: u16, backend: SocketAddr) -> String {
    format!(
        r#"
apiVersion: intellaro.io/v1
kind: Gateway
metadata: {{ name: streaming }}
spec:
  listeners:
    - {{ name: http, address: "127.0.0.1", port: {listen_port} }}
  hosts:
    - name: "*"
      routes:
        - match:
            path: {{ type: Prefix, value: /slow }}
          backends: [{{ address: "{backend}" }}]
          timeouts: {{ read: 1s }}
        - match:
            path: {{ type: Prefix, value: / }}
          backends: [{{ address: "{backend}" }}]
"#
    )
}

/// Legacy flat config with the response cache enabled.
fn cached_config(listen_port: u16, backend: SocketAddr) -> String {
    format!(
        r#"
listeners:
  - address: "127.0.0.1:{listen_port}"
upstreams:
  - name: default
    servers: [{{ address: "{backend}", weight: 1 }}]
cache:
  enabled: true
  max_entries: 100
  default_ttl_secs: 60
"#
    )
}

/// Start a proxy in front of the test backend; returns (proxy port, gate).
async fn start() -> (u16, Gate, std::path::PathBuf) {
    start_with(config).await
}

async fn start_with(
    make_config: fn(u16, SocketAddr) -> String,
) -> (u16, Gate, std::path::PathBuf) {
    let gate: Gate = Arc::new(Mutex::new(None));
    let backend = spawn_backend(gate.clone()).await;
    let port = free_port();

    let dir = std::env::temp_dir().join(format!("intellaro-stream-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gateway.yaml");
    std::fs::write(&path, make_config(port, backend)).unwrap();

    let manager = ConfigManager::load(&path).unwrap();
    let engine = bootstrap::build_routing_engine(&manager.get().await);
    let ready = Arc::new(AtomicBool::new(false));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    // Keep the shutdown sender alive for the test's duration.
    std::mem::forget(shutdown_tx);
    tokio::spawn(server::run(manager, shutdown_rx, engine, Some(ready.clone())));
    for _ in 0..200 {
        if ready.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(ready.load(Ordering::Relaxed), "proxy did not become ready");
    (port, gate, dir)
}

#[tokio::test]
async fn sse_events_arrive_before_the_stream_ends() {
    let (port, gate, dir) = start().await;
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    *gate.lock().await = Some(release_rx);

    let mut resp = reqwest::get(format!("http://127.0.0.1:{port}/sse")).await.unwrap();
    assert_eq!(resp.headers().get("content-type").unwrap(), "text/event-stream");

    // The first event must reach the client while the backend is still
    // holding the second one — a buffering proxy would block here.
    let first = tokio::time::timeout(Duration::from_secs(2), resp.chunk())
        .await
        .expect("first event was buffered, not streamed")
        .unwrap()
        .unwrap();
    assert_eq!(first, "data: one\n\n");

    release_tx.send(()).unwrap();
    let second = resp.chunk().await.unwrap().unwrap();
    assert_eq!(second, "data: two\n\n");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn uploads_beyond_the_old_buffer_cap_stream_through() {
    let (port, _gate, dir) = start().await;
    // 20 MiB: above the former 16 MiB store-and-forward cap.
    let body = vec![b'x'; 20 * 1024 * 1024];
    let text = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/upload"))
        .body(body)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(text, format!("received={}", 20 * 1024 * 1024));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn client_host_header_reaches_the_backend() {
    let (port, _gate, dir) = start().await;
    let text = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/host"))
        .header("Host", "app.example.test")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(text, "host=app.example.test");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn route_read_timeout_returns_504() {
    let (port, _gate, dir) = start().await;
    let started = std::time::Instant::now();
    let resp = reqwest::get(format!("http://127.0.0.1:{port}/slow")).await.unwrap();
    assert_eq!(resp.status(), 504);
    assert!(
        started.elapsed() < Duration::from_millis(2500),
        "timeout not enforced: {:?}",
        started.elapsed()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn upgrade_requests_are_tunnelled() {
    let (port, _gate, dir) = start().await;
    let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    conn.write_all(
        b"GET /ws HTTP/1.1\r\nHost: ws.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .await
    .unwrap();

    // Read the 101 response head.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(2), conn.read(&mut byte))
            .await
            .expect("no 101 from proxy")
            .unwrap();
        assert!(n > 0, "connection closed before 101");
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 101"), "unexpected head: {head}");
    assert!(head.contains("upgrade: websocket"), "missing upgrade header: {head}");
    assert!(head.contains("sec-websocket-accept: test-accept"), "handshake header lost: {head}");

    // Bytes now flow both ways through the tunnel.
    conn.write_all(b"hello through the tunnel").await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), conn.read(&mut buf))
        .await
        .expect("no echo through tunnel")
        .unwrap();
    assert_eq!(&buf[..n], b"hello through the tunnel");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn grpc_over_h2c_keeps_trailers() {
    let (port, _gate, dir) = start().await;
    let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build_http::<Full<Bytes>>();

    let req = Request::post(format!("http://127.0.0.1:{port}/pkg.Svc/Method"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::from_static(b"\0\0\0\0\x03abc")))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("x-saw-te").unwrap(), "trailers");

    let collected = resp.into_body().collect().await.unwrap();
    let trailers = collected.trailers().cloned().expect("trailers dropped by proxy");
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    assert_eq!(collected.to_bytes(), Bytes::from_static(b"\0\0\0\0\x03abc"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cacheable_responses_are_still_cached_and_sse_bypasses_cache() {
    let (port, gate, dir) = start_with(cached_config).await;
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/host");

    let first = client.get(&url).header("Host", "c.test").send().await.unwrap();
    assert!(first.headers().get("x-intellaro-cache").is_none());
    assert_eq!(first.text().await.unwrap(), "host=c.test");

    let second = client.get(&url).header("Host", "c.test").send().await.unwrap();
    assert_eq!(second.headers().get("x-intellaro-cache").unwrap(), "HIT");
    assert_eq!(second.text().await.unwrap(), "host=c.test");

    // An event stream on a cache-enabled proxy is relayed live, never
    // buffered for the cache.
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    *gate.lock().await = Some(release_rx);
    let mut resp = client.get(format!("http://127.0.0.1:{port}/sse")).send().await.unwrap();
    let first = tokio::time::timeout(Duration::from_secs(2), resp.chunk())
        .await
        .expect("SSE buffered by cache layer")
        .unwrap()
        .unwrap();
    assert_eq!(first, "data: one\n\n");
    release_tx.send(()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
