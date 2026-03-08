//! Configuration versioning and rollback module.
//!
//! Tracks configuration changes with SHA-256 hashing, maintains a bounded
//! version history, and supports rollback to previous versions with
//! drift detection.

use std::collections::VecDeque;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::info;

use crate::config::ServerConfig;

/// A stored configuration version.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigVersion {
    /// Monotonically increasing version number.
    pub version: u64,

    /// SHA-256 hash of the serialized configuration.
    pub hash: String,

    /// Who created this version.
    pub created_by: String,

    /// When this version was created.
    pub created_at: DateTime<Utc>,

    /// Optional description of the change.
    pub description: Option<String>,

    /// Full serialized configuration snapshot.
    #[serde(skip_serializing)]
    pub config_snapshot: String,
}

/// Drift detection result.
#[derive(Debug, Clone, Serialize)]
pub struct DriftResult {
    /// Whether the running config differs from the last stored version.
    pub has_drift: bool,

    /// Hash of the running configuration.
    pub running_hash: String,

    /// Hash of the last stored version.
    pub stored_hash: Option<String>,

    /// Last stored version number.
    pub stored_version: Option<u64>,
}

/// Configuration version store with bounded history.
pub struct ConfigVersionStore {
    versions: Arc<RwLock<VecDeque<ConfigVersion>>>,
    max_versions: usize,
    next_version: Arc<RwLock<u64>>,
}

impl ConfigVersionStore {
    /// Create a new version store with a maximum history size.
    pub fn new(max_versions: usize) -> Self {
        info!(max_versions, "Config version store initialized");
        Self {
            versions: Arc::new(RwLock::new(VecDeque::with_capacity(max_versions))),
            max_versions,
            next_version: Arc::new(RwLock::new(1)),
        }
    }

    /// Record a new configuration version.
    pub async fn record(
        &self,
        config: &ServerConfig,
        created_by: &str,
        description: Option<String>,
    ) -> ConfigVersion {
        let snapshot =
            serde_json::to_string_pretty(config).unwrap_or_else(|_| "{}".to_string());
        let hash = compute_hash(&snapshot);

        let mut version_num = self.next_version.write().await;
        let version = ConfigVersion {
            version: *version_num,
            hash: hash.clone(),
            created_by: created_by.to_string(),
            created_at: Utc::now(),
            description,
            config_snapshot: snapshot,
        };

        let mut versions = self.versions.write().await;

        // Check if this is actually different from the latest version.
        if let Some(latest) = versions.back() {
            if latest.hash == hash {
                return latest.clone();
            }
        }

        if versions.len() >= self.max_versions {
            versions.pop_front();
        }

        let result = version.clone();
        versions.push_back(version);
        *version_num += 1;

        info!(
            version = result.version,
            hash = %result.hash,
            created_by = %result.created_by,
            "Configuration version recorded"
        );

        result
    }

    /// List all stored versions (metadata only, no config snapshots).
    pub async fn list(&self) -> Vec<ConfigVersion> {
        self.versions.read().await.iter().cloned().collect()
    }

    /// Get a specific version by number.
    pub async fn get(&self, version: u64) -> Option<ConfigVersion> {
        self.versions
            .read()
            .await
            .iter()
            .find(|v| v.version == version)
            .cloned()
    }

    /// Get the configuration snapshot for a specific version (for rollback).
    pub async fn get_config_for_rollback(&self, version: u64) -> Option<ServerConfig> {
        let versions = self.versions.read().await;
        let version_entry = versions.iter().find(|v| v.version == version)?;

        serde_json::from_str(&version_entry.config_snapshot).ok()
    }

    /// Detect drift between the running configuration and the last stored version.
    pub async fn detect_drift(&self, running_config: &ServerConfig) -> DriftResult {
        let running_snapshot =
            serde_json::to_string_pretty(running_config).unwrap_or_else(|_| "{}".to_string());
        let running_hash = compute_hash(&running_snapshot);

        let versions = self.versions.read().await;
        let latest = versions.back();

        DriftResult {
            has_drift: latest.map(|v| v.hash != running_hash).unwrap_or(false),
            running_hash,
            stored_hash: latest.map(|v| v.hash.clone()),
            stored_version: latest.map(|v| v.version),
        }
    }

    /// Get the latest version number.
    pub async fn latest_version(&self) -> Option<u64> {
        self.versions.read().await.back().map(|v| v.version)
    }
}

/// Compute a SHA-256 hash of a string.
fn compute_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}
