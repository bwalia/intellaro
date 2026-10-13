//! ACME (RFC 8555) certificate automation via HTTP-01.
//!
//! One manager task per ACME-enabled HTTPS listener keeps a certificate
//! per domain in that listener's [`CertStore`]:
//!
//! * the account and issued certificates persist under `storage_dir`
//!   (`accounts/<directory-hash>.json`, `certs/<domain>.{crt,key}`) and
//!   are reinstalled at startup, so restarts never re-issue;
//! * a certificate is (re)issued when missing or within
//!   [`RENEW_BEFORE`] of expiry, checked every [`CHECK_INTERVAL`] and
//!   whenever the domain list changes on reload;
//! * failures back off for [`FAILURE_BACKOFF`] per domain (CA rate limits);
//! * HTTP-01 key authorizations are published in a process-wide table and
//!   served by the data plane at `/.well-known/acme-challenge/<token>`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use hyper::{Response, StatusCode};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::AcmeConfig;
use crate::server::{full, BoxBody};
use crate::tls::{certified_key_from_pem, CertStore};

type AcmeError = Box<dyn std::error::Error + Send + Sync>;

/// Renew certificates this long before they expire.
pub const RENEW_BEFORE: Duration = Duration::from_secs(30 * 24 * 3600);

/// How often certificate expiry is re-checked.
const CHECK_INTERVAL: Duration = Duration::from_secs(12 * 3600);

/// Wait this long before retrying a domain whose issuance failed.
const FAILURE_BACKOFF: Duration = Duration::from_secs(3600);

/// Path prefix of HTTP-01 challenge requests.
pub const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// Pending HTTP-01 challenges: token → key authorization.
fn challenges() -> &'static DashMap<String, String> {
    static CHALLENGES: OnceLock<DashMap<String, String>> = OnceLock::new();
    CHALLENGES.get_or_init(DashMap::new)
}

/// Answer an HTTP-01 challenge request, if `path` is one we are serving.
pub fn challenge_response(path: &str) -> Option<Response<BoxBody>> {
    let token = path.strip_prefix(CHALLENGE_PREFIX)?;
    let key_auth = challenges().get(token)?.clone();
    metrics::counter!("acme_challenges_served_total").increment(1);
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .body(full(key_auth))
        .ok()
}

/// Removes published challenge tokens when an issuance attempt ends.
struct ChallengeTokens(Vec<String>);

impl Drop for ChallengeTokens {
    fn drop(&mut self) {
        for token in &self.0 {
            challenges().remove(token);
        }
    }
}

/// Start the manager for one listener. Send updated configs on `config`
/// (reloads); dropping the sender stops the task.
pub fn spawn(
    listener: std::net::SocketAddr,
    config: watch::Receiver<AcmeConfig>,
    store: Arc<CertStore>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run(listener, config, store))
}

async fn run(
    listener: std::net::SocketAddr,
    mut config_rx: watch::Receiver<AcmeConfig>,
    store: Arc<CertStore>,
) {
    let mut retry_after: HashMap<String, Instant> = HashMap::new();
    let mut account: Option<(String, Account)> = None;

    loop {
        let config = config_rx.borrow_and_update().clone();

        // Reinstall whatever is already on disk (startup, new domains).
        for domain in &config.domains {
            if !store.has_host(domain) {
                if let Some(key) = load_stored(&config.storage_dir, domain) {
                    store.insert_host(domain, key);
                    info!(%listener, %domain, "Installed stored ACME certificate");
                }
            }
        }

        let due: Vec<String> = config
            .domains
            .iter()
            .filter(|d| needs_issuance(&config.storage_dir, d))
            .filter(|d| retry_after.get(*d).map_or(true, |t| Instant::now() >= *t))
            .cloned()
            .collect();

        if !due.is_empty() {
            // Reuse the account unless the directory changed.
            if account.as_ref().map_or(true, |(url, _)| *url != config.directory_url) {
                account = match load_or_create_account(&config).await {
                    Ok(acc) => Some((config.directory_url.clone(), acc)),
                    Err(err) => {
                        warn!(%listener, %err, directory = %config.directory_url, "ACME account setup failed");
                        for d in &due {
                            retry_after.insert(d.clone(), Instant::now() + FAILURE_BACKOFF);
                        }
                        None
                    }
                };
            }
            if let Some((_, acc)) = &account {
                for domain in due {
                    match issue(acc, &config, &domain).await {
                        Ok(key) => {
                            store.insert_host(&domain, key);
                            retry_after.remove(&domain);
                            metrics::counter!("acme_certificates_issued_total").increment(1);
                            info!(%listener, %domain, "ACME certificate issued and installed");
                        }
                        Err(err) => {
                            metrics::counter!("acme_issuance_failures_total").increment(1);
                            warn!(%listener, %domain, %err, retry_in_secs = FAILURE_BACKOFF.as_secs(),
                                "ACME issuance failed");
                            retry_after.insert(domain, Instant::now() + FAILURE_BACKOFF);
                        }
                    }
                }
            }
        }

        let next_retry = retry_after
            .values()
            .map(|t| t.saturating_duration_since(Instant::now()))
            .min()
            .unwrap_or(CHECK_INTERVAL)
            .min(CHECK_INTERVAL);
        tokio::select! {
            _ = tokio::time::sleep(next_retry) => {}
            changed = config_rx.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
    }
}

fn cert_paths(storage: &Path, domain: &str) -> (PathBuf, PathBuf) {
    let dir = storage.join("certs");
    (dir.join(format!("{domain}.crt")), dir.join(format!("{domain}.key")))
}

/// Load a stored certificate if present and parseable.
fn load_stored(storage: &Path, domain: &str) -> Option<rustls::sign::CertifiedKey> {
    let (crt, key) = cert_paths(storage, domain);
    let (crt_pem, key_pem) = (std::fs::read(&crt).ok()?, std::fs::read(&key).ok()?);
    match certified_key_from_pem(&crt_pem, &key_pem, &crt.display().to_string()) {
        Ok(key) => Some(key),
        Err(err) => {
            warn!(%domain, %err, "Ignoring unreadable stored ACME certificate");
            None
        }
    }
}

/// Whether `domain` has no stored certificate or one expiring soon.
fn needs_issuance(storage: &Path, domain: &str) -> bool {
    let (crt, _) = cert_paths(storage, domain);
    match std::fs::read(&crt).ok().and_then(|pem| not_after(&pem)) {
        Some(expires) => expires < std::time::SystemTime::now() + RENEW_BEFORE,
        None => true,
    }
}

/// Expiry of the first certificate in a PEM chain.
pub fn not_after(pem: &[u8]) -> Option<std::time::SystemTime> {
    let der = rustls_pemfile::certs(&mut std::io::BufReader::new(pem)).next()?.ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
    let secs = cert.validity().not_after.timestamp();
    Some(std::time::UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64))
}

async fn load_or_create_account(config: &AcmeConfig) -> Result<Account, AcmeError> {
    let digest = Sha256::digest(config.directory_url.as_bytes());
    let id: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    let path = config.storage_dir.join("accounts").join(format!("{id}.json"));

    let builder = || match &config.ca_bundle {
        Some(ca) => Account::builder_with_root(ca),
        None => Account::builder(),
    };

    if let Ok(json) = std::fs::read(&path) {
        let credentials: AccountCredentials = serde_json::from_slice(&json)?;
        return Ok(builder()?.from_credentials(credentials).await?);
    }

    let contact = config.email.as_ref().map(|e| format!("mailto:{e}"));
    let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (account, credentials) = builder()?
        .create(
            &NewAccount {
                contact: &contacts,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            config.directory_url.clone(),
            None,
        )
        .await?;
    write_private(&path, serde_json::to_string_pretty(&credentials)?.as_bytes())?;
    info!(directory = %config.directory_url, "ACME account registered");
    Ok(account)
}

/// Run one HTTP-01 order for `domain`, persist and return the result.
async fn issue(
    account: &Account,
    config: &AcmeConfig,
    domain: &str,
) -> Result<rustls::sign::CertifiedKey, AcmeError> {
    let identifiers = [Identifier::Dns(domain.to_string())];
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;
    let mut tokens = ChallengeTokens(Vec::new());

    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => return Err(format!("authorization is {other:?}").into()),
            }
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or("CA offered no http-01 challenge")?;
            let key_auth = challenge.key_authorization().as_str().to_string();
            challenges().insert(challenge.token.clone(), key_auth);
            tokens.0.push(challenge.token.clone());
            challenge.set_ready().await?;
        }
    }

    let retry = RetryPolicy::new().timeout(Duration::from_secs(120));
    let status = order.poll_ready(&retry).await?;
    if status != OrderStatus::Ready {
        return Err(format!("order ended {status:?}").into());
    }
    drop(tokens);

    let key_pem = order.finalize().await?;
    let cert_pem = order.poll_certificate(&retry).await?;

    let key = certified_key_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), domain)?;
    let (crt_path, key_path) = cert_paths(&config.storage_dir, domain);
    write_private(&key_path, key_pem.as_bytes())?;
    write_private(&crt_path, cert_pem.as_bytes())?;
    Ok(key)
}

/// Atomically write a file readable only by the owner.
fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    std::fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("intellaro-acme-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn write_cert(storage: &Path, domain: &str, days_valid: i64) {
        let mut params = rcgen::CertificateParams::new(vec![domain.to_string()]).unwrap();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(days_valid);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let (crt, key_path) = cert_paths(storage, domain);
        write_private(&crt, cert.pem().as_bytes()).unwrap();
        write_private(&key_path, key.serialize_pem().as_bytes()).unwrap();
    }

    #[test]
    fn renewal_window() {
        let dir = temp_dir("renew");
        assert!(needs_issuance(&dir, "missing.test"), "no certificate yet");
        write_cert(&dir, "fresh.test", 80);
        assert!(!needs_issuance(&dir, "fresh.test"));
        write_cert(&dir, "expiring.test", 10);
        assert!(needs_issuance(&dir, "expiring.test"), "inside the 30-day window");
        assert!(load_stored(&dir, "fresh.test").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn serves_only_published_challenges() {
        challenges().insert("tok123".into(), "tok123.thumb".into());
        assert!(challenge_response("/.well-known/acme-challenge/tok123").is_some());
        assert!(challenge_response("/.well-known/acme-challenge/other").is_none());
        assert!(challenge_response("/tok123").is_none());
        drop(ChallengeTokens(vec!["tok123".into()]));
        assert!(challenge_response("/.well-known/acme-challenge/tok123").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn private_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perm");
        let path = dir.join("certs").join("x.key");
        write_private(&path, b"secret").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
