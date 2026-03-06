//! CLI configuration — server profiles, authentication, and defaults.
//!
//! Persists connection profiles in `~/.config/intellaro/cli.toml` so users
//! can manage multiple Intellaro server instances by name.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{CliError, CliResult};

/// Name of the default profile when none is specified.
const DEFAULT_PROFILE_NAME: &str = "default";

/// Top-level CLI configuration file structure.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CliConfig {
    /// Which profile to use when `--profile` is not specified.
    #[serde(default = "default_active_profile")]
    pub active_profile: String,

    /// Named server profiles.
    #[serde(default)]
    pub profiles: HashMap<String, ServerProfile>,
}

/// A named connection profile for a single Intellaro server instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerProfile {
    /// Base URL of the MCP management API (e.g., "http://localhost:9091").
    pub url: String,

    /// Authentication method for this profile.
    #[serde(default)]
    pub auth: AuthConfig,

    /// Skip TLS certificate verification (for self-signed certs in dev).
    #[serde(default)]
    pub insecure: bool,

    /// Request timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    /// API key sent via `x-api-key` header.
    pub api_key: Option<String>,

    /// Bearer token (JWT / OAuth2).
    pub bearer_token: Option<String>,
}

impl AuthConfig {
    /// Returns true if no authentication is configured.
    pub fn is_empty(&self) -> bool {
        self.api_key.is_none() && self.bearer_token.is_none()
    }
}

// ── Defaults ─────────────────────────────────────────────────────────

fn default_active_profile() -> String {
    DEFAULT_PROFILE_NAME.to_string()
}

fn default_timeout() -> u64 {
    30
}

impl Default for ServerProfile {
    fn default() -> Self {
        Self {
            url: "http://localhost:9091".to_string(),
            auth: AuthConfig::default(),
            insecure: false,
            timeout_secs: default_timeout(),
        }
    }
}

// ── Config file operations ───────────────────────────────────────────

impl CliConfig {
    /// Resolve the configuration file path.
    ///
    /// Precedence: `$INTELLARO_CONFIG` env var → `~/.config/intellaro/cli.toml`.
    pub fn config_path() -> PathBuf {
        if let Ok(path) = std::env::var("INTELLARO_CONFIG") {
            return PathBuf::from(path);
        }

        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("intellaro")
            .join("cli.toml")
    }

    /// Load configuration from disk, falling back to defaults if the file
    /// does not exist.
    pub fn load() -> CliResult<Self> {
        let path = Self::config_path();

        if !path.exists() {
            return Ok(Self::with_defaults());
        }

        let content = std::fs::read_to_string(&path)
            .map_err(|err| CliError::ConfigError(format!("Failed to read {}: {}", path.display(), err)))?;

        toml::from_str(&content)
            .map_err(|err| CliError::ConfigError(format!("Failed to parse {}: {}", path.display(), err)))
    }

    /// Save configuration to disk, creating parent directories as needed.
    pub fn save(&self) -> CliResult<()> {
        let path = Self::config_path();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| CliError::IoError(err))?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|err| CliError::SerializationError(err.to_string()))?;

        std::fs::write(&path, content)?;

        Ok(())
    }

    /// Get the currently active profile.
    pub fn active_profile(&self) -> CliResult<&ServerProfile> {
        self.profiles
            .get(&self.active_profile)
            .ok_or_else(|| CliError::ConfigError(format!(
                "Profile '{}' not found. Run `intellaro-cli config init` to create one.",
                self.active_profile
            )))
    }

    /// Get a specific named profile.
    pub fn get_profile(&self, name: &str) -> CliResult<&ServerProfile> {
        self.profiles
            .get(name)
            .ok_or_else(|| CliError::ConfigError(format!("Profile '{}' not found", name)))
    }

    /// Create a default configuration with a single "default" profile.
    fn with_defaults() -> Self {
        let mut profiles = HashMap::new();
        profiles.insert(
            DEFAULT_PROFILE_NAME.to_string(),
            ServerProfile::default(),
        );

        Self {
            active_profile: DEFAULT_PROFILE_NAME.to_string(),
            profiles,
        }
    }
}

/// Build a `ServerProfile` from CLI flag overrides, falling back to
/// the config file profile.
pub fn resolve_profile(
    config: &CliConfig,
    profile_name: Option<&str>,
    server_url: Option<&str>,
    api_key: Option<&str>,
) -> CliResult<ServerProfile> {
    let name = profile_name.unwrap_or(&config.active_profile);
    let base = config.get_profile(name).cloned().unwrap_or_default();

    Ok(ServerProfile {
        url: server_url.map(String::from).unwrap_or(base.url),
        auth: AuthConfig {
            api_key: api_key.map(String::from).or(base.auth.api_key),
            bearer_token: base.auth.bearer_token,
        },
        insecure: base.insecure,
        timeout_secs: base.timeout_secs,
    })
}
