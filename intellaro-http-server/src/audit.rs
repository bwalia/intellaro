//! Audit logging module.
//!
//! Records all management API operations with who did what, when, and from where.
//! Maintains a bounded in-memory audit log queryable via the MCP API.

use std::collections::VecDeque;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::RwLock;
use tracing::info;

/// A single audit log entry.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    /// When the action occurred.
    pub timestamp: DateTime<Utc>,

    /// Who performed the action (API key, user ID, or "system").
    pub principal: String,

    /// What action was performed (e.g., "config.update", "cache.purge").
    pub action: String,

    /// What resource was affected (e.g., "config", "cache/tag/api").
    pub resource: String,

    /// Tenant context (if applicable).
    pub tenant: Option<String>,

    /// Source IP of the request.
    pub source_ip: String,

    /// Whether the action succeeded.
    pub success: bool,

    /// Additional details or error message.
    pub details: Option<String>,
}

/// Bounded in-memory audit log.
pub struct AuditLog {
    entries: Arc<RwLock<VecDeque<AuditEntry>>>,
    max_entries: usize,
}

impl AuditLog {
    /// Create a new audit log with a maximum capacity.
    pub fn new(max_entries: usize) -> Self {
        info!(max_entries, "Audit log initialized");
        Self {
            entries: Arc::new(RwLock::new(VecDeque::with_capacity(max_entries))),
            max_entries,
        }
    }

    /// Record an audit entry.
    pub async fn record(&self, entry: AuditEntry) {
        info!(
            principal = %entry.principal,
            action = %entry.action,
            resource = %entry.resource,
            success = entry.success,
            "Audit log entry"
        );

        let mut entries = self.entries.write().await;
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Convenience method to record a successful action.
    pub async fn record_success(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        source_ip: &str,
        details: Option<String>,
    ) {
        self.record(AuditEntry {
            timestamp: Utc::now(),
            principal: principal.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            tenant: None,
            source_ip: source_ip.to_string(),
            success: true,
            details,
        })
        .await;
    }

    /// Convenience method to record a failed action.
    pub async fn record_failure(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        source_ip: &str,
        error: &str,
    ) {
        self.record(AuditEntry {
            timestamp: Utc::now(),
            principal: principal.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            tenant: None,
            source_ip: source_ip.to_string(),
            success: false,
            details: Some(error.to_string()),
        })
        .await;
    }

    /// Query the audit log, returning entries in reverse chronological order.
    /// Optionally filter by action prefix and limit results.
    pub async fn query(
        &self,
        action_filter: Option<&str>,
        limit: Option<usize>,
    ) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;
        let limit = limit.unwrap_or(100).min(1000);

        entries
            .iter()
            .rev()
            .filter(|e| {
                action_filter
                    .map(|f| e.action.starts_with(f))
                    .unwrap_or(true)
            })
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get the total number of audit entries.
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }
}
