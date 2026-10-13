//! End-to-end TLS termination: HTTPS listeners complete real rustls
//! handshakes (ALPN h2), stamp `X-Forwarded-Proto: https`, enforce the
//! minimum protocol version, refuse plaintext, and pick up rotated
//! certificates on reload.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use intellaro_http_server::bootstrap;
use intellaro_http_server::config::ConfigManager;
use intellaro_http_server::server;

/// Backend that echoes the X-Forwarded-Proto it received.
async fn spawn_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let xfp = req
                        .headers()
                        .get("x-forwarded-proto")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(format!("xfp={xfp}")))))
                });
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    addr
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Write a fresh self-signed certificate for `names`; returns its PEM.
fn write_cert(dir: &Path, names: &[&str]) -> String {
    let cert = rcgen::generate_simple_self_signed(
        names.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
    )
    .unwrap();
    let pem = cert.cert.pem();
    std::fs::write(dir.join("tls.crt"), &pem).unwrap();
    std::fs::write(dir.join("tls.key"), cert.signing_key.serialize_pem()).unwrap();
    pem
}

fn config(dir: &Path, port12: u16, port13: u16, http_port: u16, backend: SocketAddr) -> String {
    let crt = dir.join("tls.crt").display().to_string();
    let key = dir.join("tls.key").display().to_string();
    format!(
        r#"
apiVersion: intellaro.io/v1
kind: Gateway
metadata: {{ name: tls }}
spec:
  listeners:
    - {{ name: http, address: "127.0.0.1", port: {http_port} }}
    - name: https
      address: "127.0.0.1"
      port: {port12}
      protocol: HTTPS
      tls: {{ certPath: "{crt}", keyPath: "{key}" }}
    - name: https13
      address: "127.0.0.1"
      port: {port13}
      protocol: HTTPS
      tls: {{ certPath: "{crt}", keyPath: "{key}", minVersion: "1.3" }}
  hosts:
    - name: secure.test
      forceHttps: true
      hsts: {{ maxAge: 365d, includeSubdomains: true }}
      routes:
        - match: {{ path: {{ type: Prefix, value: / }} }}
          backends: [{{ address: "{backend}" }}]
    - name: "*"
      routes:
        - match: {{ path: {{ type: Prefix, value: / }} }}
          backends: [{{ address: "{backend}" }}]
"#
    )
}

fn client(trust_pem: &str, port: u16) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(trust_pem.as_bytes()).unwrap())
        .resolve("secure.test", SocketAddr::from(([127, 0, 0, 1], port)))
        .tls_info(true)
}

fn peer_cert_der(resp: &reqwest::Response) -> Vec<u8> {
    resp.extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|info| info.peer_certificate())
        .expect("TLS info")
        .to_vec()
}

#[tokio::test]
async fn https_listeners_terminate_tls() {
    let backend = spawn_backend().await;
    let (port12, port13, http_port) = (free_port(), free_port(), free_port());
    let dir = std::env::temp_dir().join(format!("intellaro-tls-{}-{port12}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pem = write_cert(&dir, &["secure.test"]);
    let path = dir.join("gateway.yaml");
    std::fs::write(&path, config(&dir, port12, port13, http_port, backend)).unwrap();

    let manager = ConfigManager::load(&path).unwrap();
    let engine = bootstrap::build_routing_engine(&manager.get().await);
    let ready = Arc::new(AtomicBool::new(false));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(server::run(manager.clone(), shutdown_rx, engine, Some(ready.clone())));
    for _ in 0..200 {
        if ready.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(ready.load(Ordering::Relaxed), "proxy did not become ready");

    // Real handshake, h2 via ALPN, scheme reported to the backend.
    let https = client(&pem, port12).build().unwrap();
    let resp = https.get(format!("https://secure.test:{port12}/")).send().await.unwrap();
    assert_eq!(resp.version(), reqwest::Version::HTTP_2, "ALPN did not negotiate h2");
    assert_eq!(
        resp.headers().get("strict-transport-security").unwrap(),
        "max-age=31536000; includeSubDomains"
    );
    let original_der = peer_cert_der(&resp);
    assert_eq!(resp.text().await.unwrap(), "xfp=https");

    // Plaintext HTTP on a TLS port is not served.
    let plain = reqwest::get(format!("http://127.0.0.1:{port12}/")).await;
    assert!(plain.is_err(), "plaintext request was served on an HTTPS listener");

    // minVersion 1.3: a TLS 1.2-only client is refused; 1.3 works.
    let tls12_only = client(&pem, port13)
        .max_tls_version(reqwest::tls::Version::TLS_1_2)
        .build()
        .unwrap();
    assert!(
        tls12_only.get(format!("https://secure.test:{port13}/")).send().await.is_err(),
        "TLS 1.2 accepted on a 1.3-minimum listener"
    );
    let tls12_ok = client(&pem, port12)
        .max_tls_version(reqwest::tls::Version::TLS_1_2)
        .build()
        .unwrap();
    assert!(tls12_ok.get(format!("https://secure.test:{port12}/")).send().await.is_ok());
    let tls13 = client(&pem, port13).build().unwrap();
    assert!(tls13.get(format!("https://secure.test:{port13}/")).send().await.is_ok());

    // forceHttps: plain HTTP is redirected to the HTTPS listener's port,
    // 301 for GET and 308 (method-preserving) for POST.
    let plain = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let http_base = format!("http://127.0.0.1:{http_port}");
    let resp = plain
        .get(format!("{http_base}/a/b?c=1"))
        .header("Host", "secure.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 301);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        format!("https://secure.test:{port12}/a/b?c=1")
    );
    assert!(resp.headers().get("strict-transport-security").is_none(), "HSTS sent over HTTP");
    let resp = plain
        .post(format!("{http_base}/submit"))
        .header("Host", "secure.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 308);

    // ACME HTTP-01 challenges are never redirected.
    let resp = plain
        .get(format!("{http_base}/.well-known/acme-challenge/token"))
        .header("Host", "secure.test")
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 301);

    // TLS terminated by a front proxy: no redirect loop, HSTS still sent.
    let resp = plain
        .get(format!("{http_base}/"))
        .header("Host", "secure.test")
        .header("X-Forwarded-Proto", "https")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("strict-transport-security").is_some());

    // Hosts without the policy are served over HTTP as before.
    let resp = plain
        .get(format!("{http_base}/"))
        .header("Host", "other.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "xfp=http");

    // Rotate the certificate on disk; a config reload picks it up.
    let rotated_pem = write_cert(&dir, &["secure.test"]);
    manager.reload().await.unwrap();
    let rotated = client(&rotated_pem, port12).build().unwrap();
    let mut served_new = false;
    for _ in 0..100 {
        if let Ok(resp) = rotated.get(format!("https://secure.test:{port12}/")).send().await {
            assert_ne!(peer_cert_der(&resp), original_der);
            served_new = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(served_new, "rotated certificate was not picked up on reload");

    drop(shutdown_tx);
    let _ = std::fs::remove_dir_all(&dir);
}
