//! TLS termination (rustls).
//!
//! Each HTTPS listener gets a [`CertStore`]: a rustls certificate resolver
//! holding the listener's static PEM certificate as the default, plus
//! per-hostname certificates selected by SNI (where ACME-issued
//! certificates are installed). Certificates are re-read from disk on
//! config reload and periodically, so rotated files (cert-manager,
//! certbot) take effect without a restart.

use std::collections::HashMap;
use std::io::BufReader;
use std::path::Path;
use std::sync::{Arc, RwLock};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::config::TlsConfig;

/// TLS setup errors.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("{path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("{0}: no certificates found in PEM file")]
    NoCertificates(String),
    #[error("{0}: no private key found in PEM file")]
    NoPrivateKey(String),
    #[error("{path}: unsupported private key: {reason}")]
    BadKey { path: String, reason: String },
    #[error("unsupported minimum TLS version {0:?} (expected \"1.2\" or \"1.3\")")]
    BadVersion(String),
}

/// Ensure a process-level crypto provider is installed (idempotent).
fn ensure_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Load a PEM certificate chain and private key into a signing key.
pub fn load_certified_key(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey, TlsError> {
    let cert_pem = std::fs::read(cert_path).map_err(|source| TlsError::Io {
        path: cert_path.display().to_string(),
        source,
    })?;
    let key_pem = std::fs::read(key_path).map_err(|source| TlsError::Io {
        path: key_path.display().to_string(),
        source,
    })?;
    certified_key_from_pem(&cert_pem, &key_pem, &cert_path.display().to_string())
}

/// Build a signing key from in-memory PEM (used for ACME-issued certs).
pub fn certified_key_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
    label: &str,
) -> Result<CertifiedKey, TlsError> {
    ensure_provider();
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(cert_pem))
        .collect::<Result<_, _>>()
        .map_err(|source| TlsError::Io {
            path: label.to_string(),
            source,
        })?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificates(label.to_string()));
    }
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut BufReader::new(key_pem))
        .map_err(|source| TlsError::Io {
            path: label.to_string(),
            source,
        })?
        .ok_or_else(|| TlsError::NoPrivateKey(label.to_string()))?;

    let provider = rustls::crypto::CryptoProvider::get_default()
        .expect("crypto provider installed above");
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|err| TlsError::BadKey {
            path: label.to_string(),
            reason: err.to_string(),
        })?;
    Ok(CertifiedKey::new(certs, signing_key))
}

/// A self-signed certificate for `intellaro.invalid`.
fn placeholder_key() -> Result<CertifiedKey, TlsError> {
    let generated = rcgen::generate_simple_self_signed(vec!["intellaro.invalid".to_string()])
        .map_err(|err| TlsError::BadKey {
            path: "placeholder".into(),
            reason: err.to_string(),
        })?;
    certified_key_from_pem(
        generated.cert.pem().as_bytes(),
        generated.signing_key.serialize_pem().as_bytes(),
        "placeholder",
    )
}

/// SNI-aware certificate resolver for one listener.
#[derive(Debug)]
pub struct CertStore {
    /// Static listener certificate (served when no SNI entry matches).
    default: RwLock<Option<Arc<CertifiedKey>>>,
    /// Per-hostname certificates (lower-cased; `*.example.com` wildcards).
    by_host: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    /// Where the static certificate is read from.
    static_paths: RwLock<Option<TlsConfig>>,
}

impl CertStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            default: RwLock::new(None),
            by_host: RwLock::new(HashMap::new()),
            static_paths: RwLock::new(None),
        })
    }

    /// Point the store at a static certificate and load it. On failure the
    /// previously loaded certificate (if any) keeps serving.
    pub fn set_static(&self, tls: &TlsConfig) -> Result<(), TlsError> {
        *self.static_paths.write().unwrap() = Some(tls.clone());
        self.reload_static()
    }

    /// Re-read the static certificate from disk. Listeners without one
    /// (ACME-only) get a self-signed placeholder until certificates are
    /// issued, so handshakes fail on trust rather than on a missing key.
    pub fn reload_static(&self) -> Result<(), TlsError> {
        let Some(tls) = self.static_paths.read().unwrap().clone() else {
            return Ok(());
        };
        match (&tls.cert_path, &tls.key_path) {
            (Some(cert), Some(key)) => {
                let key = load_certified_key(cert, key)?;
                *self.default.write().unwrap() = Some(Arc::new(key));
            }
            _ => {
                let mut default = self.default.write().unwrap();
                if default.is_none() {
                    *default = Some(Arc::new(placeholder_key()?));
                }
            }
        }
        Ok(())
    }

    /// Install (or replace) the certificate served for `host` via SNI.
    pub fn insert_host(&self, host: &str, key: CertifiedKey) {
        self.by_host
            .write()
            .unwrap()
            .insert(host.to_ascii_lowercase(), Arc::new(key));
    }

    /// Whether a host-specific certificate is installed.
    pub fn has_host(&self, host: &str) -> bool {
        self.by_host
            .read()
            .unwrap()
            .contains_key(&host.to_ascii_lowercase())
    }

    fn lookup(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        if let Some(name) = server_name {
            let name = name.to_ascii_lowercase();
            let by_host = self.by_host.read().unwrap();
            if let Some(key) = by_host.get(&name) {
                return Some(key.clone());
            }
            if let Some((_, parent)) = name.split_once('.') {
                if let Some(key) = by_host.get(&format!("*.{parent}")) {
                    return Some(key.clone());
                }
            }
        }
        self.default.read().unwrap().clone()
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.lookup(client_hello.server_name())
    }
}

/// Build the acceptor for a listener: protocol floor from `min_version`,
/// ALPN `h2` + `http/1.1`, certificates from `store`.
pub fn build_acceptor(min_version: &str, store: Arc<CertStore>) -> Result<TlsAcceptor, TlsError> {
    ensure_provider();
    let versions: &[&'static rustls::SupportedProtocolVersion] = match min_version {
        "1.2" | "" => &[&rustls::version::TLS12, &rustls::version::TLS13],
        "1.3" => &[&rustls::version::TLS13],
        other => return Err(TlsError::BadVersion(other.to_string())),
    };
    let mut config = rustls::ServerConfig::builder_with_protocol_versions(versions)
        .with_no_client_auth()
        .with_cert_resolver(store);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Re-read static certificates for every listener store, logging (not
/// failing) on errors so a bad rotation keeps the last good certificate.
pub fn reload_all(stores: &[Arc<CertStore>]) {
    for store in stores {
        match store.reload_static() {
            Ok(()) => {}
            Err(err) => warn!(%err, "TLS certificate reload failed — keeping previous certificate"),
        }
    }
    if !stores.is_empty() {
        info!(listeners = stores.len(), "TLS certificates reloaded");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_signed(names: &[&str]) -> (String, String) {
        let cert = rcgen::generate_simple_self_signed(
            names.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        (cert.cert.pem(), cert.signing_key.serialize_pem())
    }

    #[test]
    fn sni_lookup_prefers_exact_then_wildcard_then_default() {
        let store = CertStore::new();
        let (c, k) = self_signed(&["default.test"]);
        let default = certified_key_from_pem(c.as_bytes(), k.as_bytes(), "default").unwrap();
        *store.default.write().unwrap() = Some(Arc::new(default));

        let (c, k) = self_signed(&["a.example.com"]);
        store.insert_host("A.example.com", certified_key_from_pem(c.as_bytes(), k.as_bytes(), "a").unwrap());
        let (c, k) = self_signed(&["*.example.com"]);
        store.insert_host("*.example.com", certified_key_from_pem(c.as_bytes(), k.as_bytes(), "w").unwrap());

        let exact = store.lookup(Some("a.example.com")).unwrap();
        let wild = store.lookup(Some("b.example.com")).unwrap();
        let fallback = store.lookup(Some("other.test")).unwrap();
        let no_sni = store.lookup(None).unwrap();

        assert!(!Arc::ptr_eq(&exact, &wild));
        assert!(!Arc::ptr_eq(&wild, &fallback));
        assert!(Arc::ptr_eq(&fallback, &no_sni));
        assert!(store.has_host("a.example.com"));
    }

    #[test]
    fn rejects_bad_pem_and_versions() {
        assert!(matches!(
            certified_key_from_pem(b"nope", b"nope", "x"),
            Err(TlsError::NoCertificates(_))
        ));
        assert!(matches!(
            build_acceptor("1.0", CertStore::new()),
            Err(TlsError::BadVersion(_))
        ));
    }
}
