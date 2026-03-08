//! Role-Based Access Control (RBAC) module.
//!
//! Maps API keys to roles and checks permissions for management API operations.
//! Supports wildcard matching on resource and action patterns.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::debug;

/// RBAC configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacConfig {
    /// Whether RBAC is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Defined roles with their permissions.
    #[serde(default)]
    pub roles: Vec<Role>,

    /// Mapping of API keys to role names.
    #[serde(default)]
    pub api_key_roles: HashMap<String, Vec<String>>,
}

impl Default for RbacConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            roles: Vec::new(),
            api_key_roles: HashMap::new(),
        }
    }
}

/// A role definition with a name and set of permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Role name (e.g., "admin", "viewer", "operator").
    pub name: String,

    /// Permissions granted by this role.
    pub permissions: Vec<Permission>,
}

/// A single permission granting access to a resource/action combination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    /// Resource pattern (supports "*" wildcard). E.g., "config", "cache", "*".
    pub resource: String,

    /// Action pattern (supports "*" wildcard). E.g., "read", "write", "delete", "*".
    pub action: String,
}

/// Check whether an API key has permission to perform an action on a resource.
///
/// Returns `true` if RBAC is disabled or if the key has a matching permission.
/// Returns `false` if RBAC is enabled and the key lacks permission.
pub fn check_permission(
    rbac: &Option<RbacConfig>,
    api_key: &str,
    resource: &str,
    action: &str,
) -> bool {
    let rbac = match rbac {
        Some(r) if r.enabled => r,
        _ => return true, // RBAC disabled — allow all.
    };

    // Find roles for this API key.
    let role_names = match rbac.api_key_roles.get(api_key) {
        Some(roles) => roles,
        None => {
            debug!(api_key, "No roles found for API key");
            return false;
        }
    };

    // Check each role's permissions.
    for role_name in role_names {
        if let Some(role) = rbac.roles.iter().find(|r| &r.name == role_name) {
            for perm in &role.permissions {
                if matches_pattern(&perm.resource, resource)
                    && matches_pattern(&perm.action, action)
                {
                    debug!(
                        role = %role_name,
                        resource,
                        action,
                        "RBAC permission granted"
                    );
                    return true;
                }
            }
        }
    }

    debug!(api_key, resource, action, "RBAC permission denied");
    false
}

/// Match a pattern against a value, supporting "*" as a wildcard.
fn matches_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    // Support prefix wildcard: "config.*" matches "config.read", "config.update"
    if let Some(prefix) = pattern.strip_suffix(".*") {
        return value.starts_with(prefix);
    }

    // Support suffix wildcard: "*.read" matches "config.read", "cache.read"
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return value.ends_with(suffix);
    }

    pattern == value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rbac() -> RbacConfig {
        RbacConfig {
            enabled: true,
            roles: vec![
                Role {
                    name: "admin".to_string(),
                    permissions: vec![Permission {
                        resource: "*".to_string(),
                        action: "*".to_string(),
                    }],
                },
                Role {
                    name: "viewer".to_string(),
                    permissions: vec![Permission {
                        resource: "*".to_string(),
                        action: "read".to_string(),
                    }],
                },
            ],
            api_key_roles: HashMap::from([
                ("admin-key".to_string(), vec!["admin".to_string()]),
                ("viewer-key".to_string(), vec!["viewer".to_string()]),
            ]),
        }
    }

    #[test]
    fn admin_can_do_everything() {
        let rbac = Some(make_rbac());
        assert!(check_permission(&rbac, "admin-key", "config", "write"));
        assert!(check_permission(&rbac, "admin-key", "cache", "delete"));
    }

    #[test]
    fn viewer_can_only_read() {
        let rbac = Some(make_rbac());
        assert!(check_permission(&rbac, "viewer-key", "config", "read"));
        assert!(!check_permission(&rbac, "viewer-key", "config", "write"));
    }

    #[test]
    fn unknown_key_denied() {
        let rbac = Some(make_rbac());
        assert!(!check_permission(&rbac, "unknown", "config", "read"));
    }

    #[test]
    fn disabled_rbac_allows_all() {
        let rbac = Some(RbacConfig {
            enabled: false,
            ..Default::default()
        });
        assert!(check_permission(&rbac, "any-key", "config", "write"));
    }
}
