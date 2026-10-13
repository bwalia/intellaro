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
    source_cidrs: Vec<ipnet::IpNet>,
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
    /// Client source IP (for CIDR match conditions).
    pub source_ip: Option<&'a str>,
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

        // Bare IPs are accepted as /32 (v4) or /128 (v6).
        let mut source_cidrs = Vec::new();
        for cidr in &config.source_cidrs {
            let net: ipnet::IpNet = cidr
                .parse()
                .or_else(|_| cidr.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                .map_err(|_| {
                    MatcherError::InvalidCidr(format!("Rule '{rule_name}': {cidr:?}"))
                })?;
            source_cidrs.push(net);
        }

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
            source_cidrs,
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

        // Source IP CIDR match.
        if !self.source_cidrs.is_empty() {
            let Some(ip) = req.source_ip.and_then(|s| s.parse::<std::net::IpAddr>().ok())
            else {
                return false;
            };
            if !self.source_cidrs.iter().any(|net| net.contains(&ip)) {
                return false;
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

    #[error("Invalid CIDR: {0}")]
    InvalidCidr(String),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MatchConfig;

    fn req<'a>(
        maps: &'a (HashMap<String, String>, HashMap<String, String>, HashMap<String, String>),
        source_ip: Option<&'a str>,
    ) -> RequestInfo<'a> {
        RequestInfo {
            host: Some("example.com"),
            path: "/x",
            method: "GET",
            headers: &maps.0,
            query_params: &maps.1,
            cookies: &maps.2,
            content_type: None,
            source_ip,
        }
    }

    #[test]
    fn source_cidr_matching() {
        let config = MatchConfig {
            host: None,
            path_prefix: None,
            path_exact: None,
            path_regex: None,
            methods: vec![],
            headers: HashMap::new(),
            query_params: HashMap::new(),
            cookies: HashMap::new(),
            content_type: None,
            source_cidrs: vec!["10.0.0.0/8".into(), "192.0.2.7".into()],
        };
        let matcher = CompiledMatcher::compile("t", 100, "g", 0, &config).unwrap();
        let maps = (HashMap::new(), HashMap::new(), HashMap::new());

        assert!(matcher.matches(&req(&maps, Some("10.1.2.3"))));
        assert!(matcher.matches(&req(&maps, Some("192.0.2.7"))));
        assert!(!matcher.matches(&req(&maps, Some("203.0.113.9"))));
        assert!(!matcher.matches(&req(&maps, None)));
    }

    #[test]
    fn invalid_cidr_is_a_compile_error() {
        let config = MatchConfig {
            host: None,
            path_prefix: None,
            path_exact: None,
            path_regex: None,
            methods: vec![],
            headers: HashMap::new(),
            query_params: HashMap::new(),
            cookies: HashMap::new(),
            content_type: None,
            source_cidrs: vec!["not-a-cidr".into()],
        };
        assert!(matches!(
            CompiledMatcher::compile("t", 100, "g", 0, &config),
            Err(MatcherError::InvalidCidr(_))
        ));
    }
}
