//! Request matching engine.
//!
//! Evaluates incoming requests against configured match conditions
//! (host, path, headers, query params, cookies, method, content type).
//! All matching is done in-process with zero allocation on the fast path.

use std::collections::HashMap;

use regex::Regex;
use tracing::debug;

use crate::config::MatchConfig;

/// A compiled match rule ready for fast evaluation.
#[derive(Debug)]
pub struct CompiledMatcher {
    /// Original rule name for logging.
    pub rule_name: String,

    /// Original rule priority.
    pub priority: u32,

    /// Backend group to route to if matched.
    pub backend_group: String,

    /// Rule index in the config (for tiebreaking).
    pub rule_index: usize,

    host: Option<HostMatcher>,
    path: Option<PathMatcher>,
    methods: Vec<String>,
    headers: Vec<(String, String)>,
    query_params: Vec<(String, String)>,
    cookies: Vec<(String, String)>,
    content_type: Option<String>,
}

/// Host matching mode.
#[derive(Debug)]
enum HostMatcher {
    /// Exact hostname match.
    Exact(String),
    /// Glob match (e.g., "*.example.com").
    Suffix(String),
}

/// Path matching mode.
#[derive(Debug)]
enum PathMatcher {
    Prefix(String),
    Exact(String),
    Regex(Regex),
}

/// Information extracted from an incoming request for matching.
pub struct RequestInfo<'a> {
    pub host: Option<&'a str>,
    pub path: &'a str,
    pub method: &'a str,
    pub headers: &'a HashMap<String, String>,
    pub query_params: &'a HashMap<String, String>,
    pub cookies: &'a HashMap<String, String>,
    pub content_type: Option<&'a str>,
}

impl CompiledMatcher {
    /// Compile a match configuration into a fast-evaluation matcher.
    pub fn compile(
        rule_name: &str,
        priority: u32,
        backend_group: &str,
        rule_index: usize,
        config: &MatchConfig,
    ) -> Result<Self, MatcherError> {
        let host = config.host.as_ref().map(|h| {
            if h.starts_with('*') {
                HostMatcher::Suffix(h.trim_start_matches('*').to_string())
            } else {
                HostMatcher::Exact(h.clone())
            }
        });

        let path = if let Some(ref exact) = config.path_exact {
            Some(PathMatcher::Exact(exact.clone()))
        } else if let Some(ref prefix) = config.path_prefix {
            Some(PathMatcher::Prefix(prefix.clone()))
        } else if let Some(ref regex_str) = config.path_regex {
            let regex = Regex::new(regex_str).map_err(|e| {
                MatcherError::InvalidRegex(format!("Rule '{}': {}", rule_name, e))
            })?;
            Some(PathMatcher::Regex(regex))
        } else {
            None
        };

        let methods: Vec<String> = config
            .methods
            .iter()
            .map(|m| m.to_uppercase())
            .collect();

        let headers: Vec<(String, String)> = config
            .headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();

        let query_params: Vec<(String, String)> = config
            .query_params
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let cookies: Vec<(String, String)> = config
            .cookies
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        Ok(Self {
            rule_name: rule_name.to_string(),
            priority,
            backend_group: backend_group.to_string(),
            rule_index,
            host,
            path,
            methods,
            headers,
            query_params,
            cookies,
            content_type: config.content_type.clone(),
        })
    }

    /// Evaluate whether this matcher matches the given request.
    /// Returns `true` if all conditions match.
    pub fn matches(&self, req: &RequestInfo<'_>) -> bool {
        // Host match.
        if let Some(ref host_matcher) = self.host {
            match req.host {
                None => return false,
                Some(host) => match host_matcher {
                    HostMatcher::Exact(expected) => {
                        if !host.eq_ignore_ascii_case(expected) {
                            return false;
                        }
                    }
                    HostMatcher::Suffix(suffix) => {
                        if !host.to_lowercase().ends_with(&suffix.to_lowercase()) {
                            return false;
                        }
                    }
                },
            }
        }

        // Path match.
        if let Some(ref path_matcher) = self.path {
            match path_matcher {
                PathMatcher::Exact(expected) => {
                    if req.path != expected.as_str() {
                        return false;
                    }
                }
                PathMatcher::Prefix(prefix) => {
                    if !req.path.starts_with(prefix.as_str()) {
                        return false;
                    }
                }
                PathMatcher::Regex(regex) => {
                    if !regex.is_match(req.path) {
                        return false;
                    }
                }
            }
        }

        // Method match.
        if !self.methods.is_empty() && !self.methods.iter().any(|m| m == req.method) {
            return false;
        }

        // Header match.
        for (key, value) in &self.headers {
            match req.headers.get(key) {
                Some(v) if v == value => {}
                _ => return false,
            }
        }

        // Query param match.
        for (key, value) in &self.query_params {
            match req.query_params.get(key) {
                Some(v) if v == value => {}
                _ => return false,
            }
        }

        // Cookie match.
        for (key, value) in &self.cookies {
            match req.cookies.get(key) {
                Some(v) if v == value => {}
                _ => return false,
            }
        }

        // Content-Type match.
        if let Some(ref expected_ct) = self.content_type {
            match req.content_type {
                Some(ct) if ct.starts_with(expected_ct.as_str()) => {}
                _ => return false,
            }
        }

        debug!(rule = %self.rule_name, "Request matched routing rule");
        true
    }
}

/// Errors during matcher compilation.
#[derive(Debug, thiserror::Error)]
pub enum MatcherError {
    #[error("Invalid regex pattern: {0}")]
    InvalidRegex(String),
}

/// Find the first matching rule for a request from a sorted list of matchers.
///
/// Matchers should be pre-sorted by (priority DESC, rule_index ASC).
pub fn find_match<'a>(
    matchers: &'a [CompiledMatcher],
    req: &RequestInfo<'_>,
) -> Option<&'a CompiledMatcher> {
    matchers.iter().find(|m| m.matches(req))
}
