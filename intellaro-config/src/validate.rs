//! Cross-object semantic validation for a parsed [`ConfigSet`].
//!
//! The loader guarantees shape; this module guarantees meaning: unique
//! names, resolvable references, sane ports/weights, and Phase-0 support
//! boundaries (e.g. ACME and TCP probes are schema-reserved, not yet live).

use std::collections::HashSet;

use crate::loader::ConfigSet;
use crate::types::*;
use crate::ConfigV1Error;

/// Validate a config set, returning every problem found (not just the first).
pub fn validate(set: &ConfigSet) -> Result<(), ConfigV1Error> {
    let mut errors: Vec<String> = Vec::new();

    check_unique_names(set, &mut errors);

    let upstream_names: HashSet<&str> = set
        .upstreams
        .iter()
        .map(|u| u.metadata.name.as_str())
        .collect();
    let policy_names: HashSet<&str> = set
        .waf_policies
        .iter()
        .map(|p| p.metadata.name.as_str())
        .collect();

    let mut seen_ports: HashSet<(String, u16)> = HashSet::new();

    for gw in &set.gateways {
        let gw_name = &gw.metadata.name;

        if gw.spec.listeners.is_empty() {
            errors.push(format!("gateway {gw_name:?}: at least one listener is required"));
        }
        if gw.spec.hosts.is_empty() {
            errors.push(format!("gateway {gw_name:?}: at least one host is required"));
        }

        if let Some(fb) = &gw.spec.fallback {
            if !(100..=599).contains(&fb.status) {
                errors.push(format!(
                    "gateway {gw_name:?}: fallback status {} is not a valid HTTP status",
                    fb.status
                ));
            }
        }

        let mut listener_names: HashSet<&str> = HashSet::new();
        for listener in &gw.spec.listeners {
            let ctx = format!("gateway {gw_name:?} listener {:?}", listener.name);

            if !listener_names.insert(listener.name.as_str()) {
                errors.push(format!("{ctx}: duplicate listener name"));
            }
            if listener.port == 0 {
                errors.push(format!("{ctx}: port must be 1-65535"));
            }
            if !seen_ports.insert((listener.address.clone(), listener.port)) {
                errors.push(format!(
                    "{ctx}: {}:{} is already bound by another listener",
                    listener.address, listener.port
                ));
            }
            if listener.address.parse::<std::net::IpAddr>().is_err() {
                errors.push(format!(
                    "{ctx}: bind address {:?} is not a valid IP address",
                    listener.address
                ));
            }

            match listener.protocol {
                ListenerProtocol::Https => match &listener.tls {
                    None => errors.push(format!("{ctx}: HTTPS requires tls settings")),
                    Some(tls) => validate_tls(&ctx, tls, &mut errors),
                },
                ListenerProtocol::Http => {
                    if listener.tls.is_some() {
                        errors.push(format!("{ctx}: tls settings require protocol HTTPS"));
                    }
                }
            }
        }

        let mut host_names: HashSet<&str> = HashSet::new();
        for host in &gw.spec.hosts {
            let hctx = format!("gateway {gw_name:?} host {:?}", host.name);

            if host.name.is_empty() {
                errors.push(format!("{hctx}: host name must not be empty"));
            }
            if !host_names.insert(host.name.as_str()) {
                errors.push(format!("{hctx}: duplicate host name"));
            }
            if host.routes.is_empty() {
                errors.push(format!("{hctx}: at least one route is required"));
            }

            for (idx, route) in host.routes.iter().enumerate() {
                let rctx = format!("{hctx} route[{idx}]");
                validate_route(&rctx, route, &upstream_names, &policy_names, &mut errors);
            }
        }
    }

    for upstream in &set.upstreams {
        let ctx = format!("upstream {:?}", upstream.metadata.name);
        validate_backends(&ctx, &upstream.spec.backends, &mut errors);
        if let Some(hc) = &upstream.spec.health_check {
            validate_health_check(&ctx, hc, &mut errors);
        }
    }

    for policy in &set.waf_policies {
        let ctx = format!("wafPolicy {:?}", policy.metadata.name);
        for cidr in policy.spec.ip_allow.iter().chain(&policy.spec.ip_deny) {
            if !looks_like_ip_or_cidr(cidr) {
                errors.push(format!("{ctx}: {cidr:?} is not a valid IP or CIDR"));
            }
        }
        if let Some(rl) = &policy.spec.rate_limit {
            if rl.max_requests == 0 {
                errors.push(format!("{ctx}: rateLimit.maxRequests must be > 0"));
            }
            if rl.window.0.is_zero() {
                errors.push(format!("{ctx}: rateLimit.window must be > 0"));
            }
        }
        for rule in &policy.spec.rules {
            if rule.pattern.pattern_type == WafPatternType::Regex {
                // Cheap sanity check without pulling a full regex engine into
                // this crate: reject empty patterns.
                if rule.pattern.value.is_empty() {
                    errors.push(format!("{ctx} rule {:?}: pattern must not be empty", rule.id));
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ConfigV1Error::Validation(errors))
    }
}

fn check_unique_names(set: &ConfigSet, errors: &mut Vec<String>) {
    for (kind, names) in [
        (
            "Gateway",
            set.gateways.iter().map(|g| &g.metadata.name).collect::<Vec<_>>(),
        ),
        (
            "Upstream",
            set.upstreams.iter().map(|u| &u.metadata.name).collect(),
        ),
        (
            "WafPolicy",
            set.waf_policies.iter().map(|p| &p.metadata.name).collect(),
        ),
    ] {
        let mut seen = HashSet::new();
        for name in names {
            if name.is_empty() {
                errors.push(format!("{kind}: metadata.name must not be empty"));
            }
            if !seen.insert(name.as_str()) {
                errors.push(format!("{kind} {name:?}: duplicate name"));
            }
        }
    }
}

fn validate_tls(ctx: &str, tls: &TlsSettings, errors: &mut Vec<String>) {
    let has_static = tls.cert_path.is_some() && tls.key_path.is_some();
    let acme_on = tls.acme.as_ref().is_some_and(|a| a.enabled);

    if acme_on && !has_static {
        errors.push(format!(
            "{ctx}: ACME automation lands in Phase 1 — provide certPath/keyPath for now"
        ));
    } else if !has_static {
        errors.push(format!("{ctx}: certPath and keyPath are required for HTTPS"));
    }

    if let Some(v) = &tls.min_version {
        if v != "1.2" && v != "1.3" {
            errors.push(format!("{ctx}: minVersion must be \"1.2\" or \"1.3\", got {v:?}"));
        }
    }
}

fn validate_route(
    ctx: &str,
    route: &Route,
    upstream_names: &HashSet<&str>,
    policy_names: &HashSet<&str>,
    errors: &mut Vec<String>,
) {
    match (&route.upstream_ref, route.backends.is_empty()) {
        (Some(_), false) => {
            errors.push(format!("{ctx}: backends and upstreamRef are mutually exclusive"))
        }
        (None, true) => {
            // Action routes (static/redirect) never reach a backend.
            if route.action.is_none() {
                errors.push(format!("{ctx}: either backends or upstreamRef is required"))
            }
        }
        (Some(name), true) => {
            if !upstream_names.contains(name.as_str()) {
                errors.push(format!("{ctx}: upstreamRef {name:?} does not resolve to an Upstream"));
            }
        }
        (None, false) => validate_backends(ctx, &route.backends, errors),
    }

    match &route.action {
        Some(RouteAction::Static { status, body, body_base64, .. }) => {
            if !(100..=599).contains(status) {
                errors.push(format!("{ctx}: action status {status} is not a valid HTTP status"));
            }
            if body.is_some() && body_base64.is_some() {
                errors.push(format!("{ctx}: body and bodyBase64 are mutually exclusive"));
            }
            if let Some(b64) = body_base64 {
                use base64::Engine as _;
                if base64::engine::general_purpose::STANDARD.decode(b64).is_err() {
                    errors.push(format!("{ctx}: bodyBase64 is not valid base64"));
                }
            }
        }
        Some(RouteAction::Redirect { location, status }) => {
            if location.is_empty() {
                errors.push(format!("{ctx}: redirect location must not be empty"));
            }
            if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                errors.push(format!("{ctx}: redirect status must be 301/302/303/307/308, got {status}"));
            }
        }
        None => {}
    }

    if let Some(rewrite) = &route.rewrite {
        if !rewrite.strip_prefix.starts_with('/') {
            errors.push(format!("{ctx}: rewrite.stripPrefix must start with '/'"));
        }
    }

    for cidr in &route.route_match.source_cidrs {
        if !looks_like_ip_or_cidr(cidr) {
            errors.push(format!("{ctx}: sourceCidr {cidr:?} is not a valid IP or CIDR"));
        }
    }

    if route.route_match.path.match_type != PathMatchType::Regex
        && !route.route_match.path.value.starts_with('/')
    {
        errors.push(format!(
            "{ctx}: path value {:?} must start with '/'",
            route.route_match.path.value
        ));
    }

    for policy in &route.policies {
        if !policy_names.contains(policy.policy_ref.as_str()) {
            errors.push(format!(
                "{ctx}: policy ref {:?} does not resolve to a WafPolicy",
                policy.policy_ref
            ));
        }
    }

    if let Some(hc) = route.health_check.as_ref().and_then(|h| h.active.as_ref()) {
        validate_health_check(ctx, hc, errors);
    }
}

fn validate_backends(ctx: &str, backends: &[Backend], errors: &mut Vec<String>) {
    if backends.is_empty() {
        errors.push(format!("{ctx}: at least one backend is required"));
    }
    for backend in backends {
        if backend.weight == 0 {
            errors.push(format!("{ctx}: backend {:?} weight must be >= 1", backend.address));
        }
        // host:port shape — permissive on host (DNS names allowed), strict on port.
        match backend.address.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() => {
                if port.parse::<u16>().map(|p| p == 0).unwrap_or(true) {
                    errors.push(format!(
                        "{ctx}: backend {:?} must end in a valid :port",
                        backend.address
                    ));
                }
            }
            _ => errors.push(format!(
                "{ctx}: backend {:?} must be host:port",
                backend.address
            )),
        }
    }
}

fn validate_health_check(ctx: &str, hc: &ActiveHealthCheck, errors: &mut Vec<String>) {
    if hc.probe_type == ProbeType::Tcp {
        errors.push(format!(
            "{ctx}: tcp health probes land with the L4 stream engine (Phase 2) — use type: http"
        ));
    }
    if hc.probe_type == ProbeType::Http && !hc.path.starts_with('/') {
        errors.push(format!("{ctx}: health check path must start with '/'"));
    }
    if hc.interval.0.is_zero() {
        errors.push(format!("{ctx}: health check interval must be > 0"));
    }
    if hc.unhealthy_threshold == 0 {
        errors.push(format!("{ctx}: unhealthyThreshold must be >= 1"));
    }
}

fn looks_like_ip_or_cidr(value: &str) -> bool {
    let ip_part = value.split_once('/').map(|(ip, prefix)| {
        if prefix.parse::<u8>().is_err() {
            return "";
        }
        ip
    });
    let candidate = ip_part.unwrap_or(value);
    !candidate.is_empty() && candidate.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::load_str;

    fn errors_of(yaml: &str) -> Vec<String> {
        let set = load_str(yaml).unwrap();
        match validate(&set) {
            Ok(()) => Vec::new(),
            Err(ConfigV1Error::Validation(errs)) => errs,
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn accepts_valid_config() {
        let yaml = r#"
apiVersion: intellaro.io/v1
kind: Gateway
metadata: { name: edge }
spec:
  listeners: [{ name: http, port: 8080 }]
  hosts:
    - name: "*"
      routes:
        - upstreamRef: pool
---
apiVersion: intellaro.io/v1
kind: Upstream
metadata: { name: pool }
spec:
  backends: [{ address: "127.0.0.1:9000" }]
"#;
        assert!(errors_of(yaml).is_empty());
    }

    #[test]
    fn flags_dangling_upstream_ref_and_policy_ref() {
        let yaml = r#"
apiVersion: intellaro.io/v1
kind: Gateway
metadata: { name: edge }
spec:
  listeners: [{ name: http, port: 8080 }]
  hosts:
    - name: "*"
      routes:
        - upstreamRef: missing-pool
          policies: [{ ref: missing-waf }]
"#;
        let errs = errors_of(yaml);
        assert!(errs.iter().any(|e| e.contains("missing-pool")), "{errs:?}");
        assert!(errs.iter().any(|e| e.contains("missing-waf")), "{errs:?}");
    }

    #[test]
    fn flags_duplicate_ports_and_names() {
        let yaml = r#"
apiVersion: intellaro.io/v1
kind: Gateway
metadata: { name: edge }
spec:
  listeners:
    - { name: a, port: 8080 }
    - { name: a, port: 8080 }
  hosts:
    - name: "*"
      routes: [{ backends: [{ address: "127.0.0.1:9000" }] }]
"#;
        let errs = errors_of(yaml);
        assert!(errs.iter().any(|e| e.contains("duplicate listener name")), "{errs:?}");
        assert!(errs.iter().any(|e| e.contains("already bound")), "{errs:?}");
    }

    #[test]
    fn flags_backends_and_ref_conflict() {
        let yaml = r#"
apiVersion: intellaro.io/v1
kind: Gateway
metadata: { name: edge }
spec:
  listeners: [{ name: http, port: 8080 }]
  hosts:
    - name: "*"
      routes:
        - upstreamRef: pool
          backends: [{ address: "127.0.0.1:9000" }]
---
apiVersion: intellaro.io/v1
kind: Upstream
metadata: { name: pool }
spec:
  backends: [{ address: "127.0.0.1:9000" }]
"#;
        let errs = errors_of(yaml);
        assert!(errs.iter().any(|e| e.contains("mutually exclusive")), "{errs:?}");
    }

    #[test]
    fn flags_https_without_tls_and_bad_weight() {
        let yaml = r#"
apiVersion: intellaro.io/v1
kind: Gateway
metadata: { name: edge }
spec:
  listeners: [{ name: tls, port: 443, protocol: HTTPS }]
  hosts:
    - name: "*"
      routes:
        - backends: [{ address: "127.0.0.1:9000", weight: 0 }]
"#;
        let errs = errors_of(yaml);
        assert!(errs.iter().any(|e| e.contains("HTTPS requires tls")), "{errs:?}");
        assert!(errs.iter().any(|e| e.contains("weight must be >= 1")), "{errs:?}");
    }

    #[test]
    fn flags_bad_cidr_and_zero_rate_limit() {
        let yaml = r#"
apiVersion: intellaro.io/v1
kind: WafPolicy
metadata: { name: waf }
spec:
  ipDeny: ["not-an-ip"]
  rateLimit: { maxRequests: 0, window: 1m }
"#;
        let errs = errors_of(yaml);
        assert!(errs.iter().any(|e| e.contains("not-an-ip")), "{errs:?}");
        assert!(errs.iter().any(|e| e.contains("maxRequests")), "{errs:?}");
    }

    #[test]
    fn flags_tcp_probe_as_phase_2() {
        let yaml = r#"
apiVersion: intellaro.io/v1
kind: Upstream
metadata: { name: pool }
spec:
  backends: [{ address: "127.0.0.1:9000" }]
  healthCheck: { type: tcp }
"#;
        let errs = errors_of(yaml);
        assert!(errs.iter().any(|e| e.contains("Phase 2")), "{errs:?}");
    }
}
