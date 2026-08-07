//! Compiler from the typed `intellaro.io/v1` model to the runtime
//! [`ServerConfig`].
//!
//! `intellaro-config` owns the public schema (Gateway / Upstream /
//! WafPolicy); this module maps it onto the data-plane configuration:
//!
//! * Gateway listeners → [`ListenerConfig`]s
//! * Named upstreams and inline route backends → [`UpstreamConfig`]s
//! * Host/route matches → routing-engine rules, with priority derived
//!   from path specificity (Exact > longer Prefix > Regex)
//! * The referenced `WafPolicy` → the global [`SecurityConfig`]
//!
//! Anything the data plane cannot enforce yet is surfaced as an explicit
//! compile warning rather than silently dropped.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use intellaro_config::{
    ActiveHealthCheck, BackoffStrategy, ConfigSet, Gateway, ListenerProtocol, LoadBalancing,
    PathMatchType, Route, WafMode, WafPolicy,
};
use intellaro_http_router::config::{
    BalancerConfig, BalancerStrategy, MatchConfig, RouterConfig, RoutingRule,
};

use crate::config::{
    BackendServer, CacheConfig, CircuitBreakerConfig, ConfigError, HealthCheckConfig,
    JwtConfig, ListenerConfig, LoggingConfig, RateLimitConfig, RetryConfig, SecurityConfig,
    ServerConfig, TlsConfig, UpstreamConfig,
};

/// Result of compiling a v1 config set.
pub struct CompiledConfig {
    pub config: ServerConfig,
    /// Human-readable notes about intent the data plane cannot fully
    /// enforce yet. Callers should log these.
    pub warnings: Vec<String>,
}

/// Compile a validated [`ConfigSet`] into the runtime [`ServerConfig`].
pub fn compile(set: &ConfigSet) -> Result<CompiledConfig, ConfigError> {
    intellaro_config::validate(set).map_err(|err| ConfigError::Invalid(err.to_string()))?;

    let mut warnings: Vec<String> = Vec::new();
    let mut listeners: Vec<ListenerConfig> = Vec::new();
    let mut upstreams: Vec<UpstreamConfig> = Vec::new();
    let mut rules: Vec<RoutingRule> = Vec::new();

    // ── Named upstreams ──────────────────────────────────────────────
    for upstream in &set.upstreams {
        upstreams.push(UpstreamConfig {
            name: upstream.metadata.name.clone(),
            servers: to_backend_servers(&upstream.spec.backends),
            load_balancing: upstream.spec.load_balancing.as_dataplane_str().to_string(),
            health_check: upstream.spec.health_check.as_ref().map(to_health_check),
            circuit_breaker: upstream.spec.circuit_breaker.as_ref().map(|cb| {
                CircuitBreakerConfig {
                    failure_threshold: cb.failure_threshold,
                    open_duration_secs: cb.open_duration.as_secs(),
                    half_open_max_requests: cb.half_open_max_requests,
                }
            }),
            retry: upstream.spec.retry.as_ref().map(|r| RetryConfig {
                max_retries: r.max_retries,
                retry_on_status: r.retry_on_status.clone(),
                backoff: match r.backoff {
                    BackoffStrategy::Exponential => "exponential".to_string(),
                    BackoffStrategy::Linear => "linear".to_string(),
                    BackoffStrategy::Constant => "constant".to_string(),
                },
                backoff_base_ms: r.backoff_base.as_millis() as u64,
            }),
            transform: None,
        });
    }

    // ── Gateways: listeners + routes ─────────────────────────────────
    for gateway in &set.gateways {
        compile_listeners(gateway, &mut listeners, &mut warnings)?;

        for host in &gateway.spec.hosts {
            for (idx, route) in host.routes.iter().enumerate() {
                let group = match &route.upstream_ref {
                    Some(name) => name.clone(),
                    None => {
                        let name = synthesized_upstream_name(&gateway.metadata.name, &host.name, idx);
                        upstreams.push(inline_upstream(&name, route));
                        name
                    }
                };

                rules.push(to_routing_rule(gateway, &host.name, idx, route, group));
            }
        }
    }

    // ── Security policy ──────────────────────────────────────────────
    let security = compile_security(set, &mut warnings);

    let config = ServerConfig {
        listeners,
        worker_count: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4),
        upstreams,
        cache: CacheConfig::default(),
        security,
        logging: LoggingConfig::default(),
        cluster: None,
        management_api: None,
        static_roots: Vec::new(),
        router: Some(RouterConfig {
            rules,
            ..RouterConfig::default()
        }),
        tenants: Vec::new(),
    };

    Ok(CompiledConfig { config, warnings })
}

fn compile_listeners(
    gateway: &Gateway,
    listeners: &mut Vec<ListenerConfig>,
    warnings: &mut Vec<String>,
) -> Result<(), ConfigError> {
    for listener in &gateway.spec.listeners {
        let address: SocketAddr = format!("{}:{}", listener.address, listener.port)
            .parse()
            .map_err(|err| {
                ConfigError::Invalid(format!(
                    "gateway {:?} listener {:?}: invalid bind address: {err}",
                    gateway.metadata.name, listener.name
                ))
            })?;

        let tls = match listener.protocol {
            ListenerProtocol::Https => {
                let tls = listener.tls.as_ref().expect("validated: HTTPS has tls");
                if tls.acme.as_ref().is_some_and(|a| a.enabled) {
                    warnings.push(format!(
                        "listener {:?}: ACME automation is Phase 1 — using the provided static certificate",
                        listener.name
                    ));
                }
                Some(TlsConfig {
                    cert_path: PathBuf::from(tls.cert_path.as_ref().expect("validated")),
                    key_path: PathBuf::from(tls.key_path.as_ref().expect("validated")),
                    min_version: tls.min_version.clone().unwrap_or_else(|| "1.2".to_string()),
                })
            }
            ListenerProtocol::Http => None,
        };

        listeners.push(ListenerConfig {
            address,
            tls,
            protocol: "auto".to_string(),
        });
    }
    Ok(())
}

fn to_backend_servers(backends: &[intellaro_config::Backend]) -> Vec<BackendServer> {
    backends
        .iter()
        .map(|b| BackendServer {
            address: b.address.clone(),
            weight: b.weight,
        })
        .collect()
}

fn to_health_check(hc: &ActiveHealthCheck) -> HealthCheckConfig {
    HealthCheckConfig {
        path: hc.path.clone(),
        interval_secs: hc.interval.as_secs().max(1),
        unhealthy_threshold: hc.unhealthy_threshold,
        outlier_detection: None,
    }
}

fn synthesized_upstream_name(gateway: &str, host: &str, route_idx: usize) -> String {
    let host = host.replace('*', "any");
    format!("gw-{gateway}--{host}--r{route_idx}")
}

fn inline_upstream(name: &str, route: &Route) -> UpstreamConfig {
    UpstreamConfig {
        name: name.to_string(),
        servers: to_backend_servers(&route.backends),
        load_balancing: route.load_balancing.as_dataplane_str().to_string(),
        health_check: route
            .health_check
            .as_ref()
            .and_then(|h| h.active.as_ref())
            .map(to_health_check),
        circuit_breaker: None,
        retry: None,
        transform: None,
    }
}

fn to_routing_rule(
    gateway: &Gateway,
    host: &str,
    route_idx: usize,
    route: &Route,
    backend_group: String,
) -> RoutingRule {
    let path = &route.route_match.path;
    let (path_prefix, path_exact, path_regex) = match path.match_type {
        PathMatchType::Prefix => (Some(path.value.clone()), None, None),
        PathMatchType::Exact => (None, Some(path.value.clone()), None),
        PathMatchType::Regex => (None, None, Some(path.value.clone())),
    };

    let priority = route.priority.unwrap_or_else(|| derive_priority(path));

    RoutingRule {
        name: format!("{}/{}/route{}", gateway.metadata.name, host, route_idx),
        priority,
        r#match: MatchConfig {
            host: (host != "*").then(|| host.to_string()),
            path_prefix,
            path_exact,
            path_regex,
            methods: route.route_match.methods.clone(),
            headers: route
                .route_match
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<HashMap<_, _>>(),
            query_params: HashMap::new(),
            cookies: HashMap::new(),
            content_type: None,
        },
        backend_group,
        balancer: Some(BalancerConfig {
            strategy: to_balancer_strategy(route.load_balancing),
            sticky: None,
            health_check: None,
        }),
        timeout_secs: route
            .timeouts
            .as_ref()
            .and_then(|t| t.read)
            .map(|d| d.as_secs()),
        headers: None,
        enabled: true,
    }
}

/// Deterministic selection: Exact beats Prefix beats Regex, and within a
/// class, longer (more specific) paths win. Mirrors WSLProxy's
/// priority > path-specificity ordering.
fn derive_priority(path: &intellaro_config::PathMatch) -> u32 {
    let len = path.value.len().min(4_000) as u32;
    match path.match_type {
        PathMatchType::Exact => 30_000 + len,
        PathMatchType::Prefix => 20_000 + len,
        PathMatchType::Regex => 10_000 + len,
    }
}

fn to_balancer_strategy(lb: LoadBalancing) -> BalancerStrategy {
    match lb {
        LoadBalancing::RoundRobin => BalancerStrategy::RoundRobin,
        LoadBalancing::LeastConn => BalancerStrategy::LeastConnections,
        LoadBalancing::Weighted => BalancerStrategy::Weighted,
        LoadBalancing::Random => BalancerStrategy::Random,
        LoadBalancing::ConsistentHash => BalancerStrategy::ConsistentHash,
    }
}

/// Map the referenced (or sole) `WafPolicy` onto the global security
/// engine. Per-route policy binding arrives with the Phase 3 WAF engine.
fn compile_security(set: &ConfigSet, warnings: &mut Vec<String>) -> SecurityConfig {
    // Policies referenced by routes, in declaration order.
    let mut referenced: Vec<&WafPolicy> = Vec::new();
    for gateway in &set.gateways {
        for host in &gateway.spec.hosts {
            for route in &host.routes {
                for policy_ref in &route.policies {
                    if let Some(policy) = set
                        .waf_policies
                        .iter()
                        .find(|p| p.metadata.name == policy_ref.policy_ref)
                    {
                        if !referenced.iter().any(|p| p.metadata.name == policy.metadata.name) {
                            referenced.push(policy);
                        }
                    }
                }
            }
        }
    }

    if referenced.is_empty() {
        referenced = set.waf_policies.iter().collect();
    }

    let Some(policy) = referenced.first() else {
        return SecurityConfig::default();
    };

    if referenced.len() > 1 {
        warnings.push(format!(
            "multiple WafPolicies defined; per-route binding is Phase 3 — applying {:?} globally",
            policy.metadata.name
        ));
    }

    if policy.spec.mode == WafMode::Monitor {
        warnings.push(format!(
            "wafPolicy {:?}: monitor mode arrives with the Phase 3 WAF engine — IP/rate/JWT rules enforce as block",
            policy.metadata.name
        ));
    }

    if !policy.spec.rules.is_empty() || !policy.spec.rule_packs.is_empty() {
        warnings.push(format!(
            "wafPolicy {:?}: signature rules/rulePacks are schema-accepted but enforced by the Phase 3 WAF engine",
            policy.metadata.name
        ));
    }

    SecurityConfig {
        ip_allow: policy.spec.ip_allow.clone(),
        ip_block: policy.spec.ip_deny.clone(),
        rate_limit: policy.spec.rate_limit.as_ref().map(|rl| RateLimitConfig {
            max_requests: rl.max_requests,
            window_secs: rl.window.as_secs().max(1),
        }),
        jwt: policy.spec.jwt.as_ref().map(|jwt| JwtConfig {
            secret_or_key_path: jwt.secret_or_key_path.clone(),
            issuer: jwt.issuer.clone(),
            audience: jwt.audience.clone(),
        }),
        oidc: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1: &str = r#"
apiVersion: intellaro.io/v1
kind: Gateway
metadata: { name: edge }
spec:
  listeners:
    - { name: http, port: 18080 }
  hosts:
    - name: example.com
      routes:
        - match:
            path: { type: Prefix, value: /api }
          upstreamRef: api-pool
          timeouts: { read: 30s }
          policies: [{ ref: waf }]
        - match:
            path: { type: Exact, value: /api/login }
          backends: [{ address: "127.0.0.1:9001" }]
    - name: "*"
      routes:
        - backends: [{ address: "127.0.0.1:9000", weight: 3 }]
          loadBalancing: weighted
---
apiVersion: intellaro.io/v1
kind: Upstream
metadata: { name: api-pool }
spec:
  backends:
    - { address: "10.0.0.1:8080", weight: 2 }
    - { address: "10.0.0.2:8080" }
  loadBalancing: least_conn
  healthCheck: { path: /healthz, interval: 5s, unhealthyThreshold: 2 }
  circuitBreaker: { failureThreshold: 4, openDuration: 10s }
  retry: { maxRetries: 3, backoffBase: 250ms }
---
apiVersion: intellaro.io/v1
kind: WafPolicy
metadata: { name: waf }
spec:
  mode: block
  ipDeny: ["203.0.113.0/24"]
  rateLimit: { maxRequests: 100, window: 1m }
"#;

    fn compiled() -> CompiledConfig {
        let set = intellaro_config::load_str(V1).unwrap();
        compile(&set).unwrap()
    }

    #[test]
    fn compiles_listeners_and_upstreams() {
        let out = compiled();
        assert_eq!(out.config.listeners.len(), 1);
        assert_eq!(out.config.listeners[0].address.port(), 18080);

        // 1 named + 2 synthesized inline upstreams
        assert_eq!(out.config.upstreams.len(), 3);
        let api = out
            .config
            .upstreams
            .iter()
            .find(|u| u.name == "api-pool")
            .unwrap();
        assert_eq!(api.load_balancing, "least_connections");
        assert_eq!(api.servers[0].weight, 2);
        assert_eq!(api.health_check.as_ref().unwrap().interval_secs, 5);
        assert_eq!(api.circuit_breaker.as_ref().unwrap().open_duration_secs, 10);
        assert_eq!(api.retry.as_ref().unwrap().backoff_base_ms, 250);
    }

    #[test]
    fn compiles_routing_rules_with_specificity_priority() {
        let out = compiled();
        let router = out.config.router.as_ref().unwrap();
        assert_eq!(router.rules.len(), 3);

        let prefix_rule = &router.rules[0];
        assert_eq!(prefix_rule.r#match.host.as_deref(), Some("example.com"));
        assert_eq!(prefix_rule.r#match.path_prefix.as_deref(), Some("/api"));
        assert_eq!(prefix_rule.backend_group, "api-pool");
        assert_eq!(prefix_rule.timeout_secs, Some(30));

        let exact_rule = &router.rules[1];
        assert_eq!(exact_rule.r#match.path_exact.as_deref(), Some("/api/login"));
        assert!(
            exact_rule.priority > prefix_rule.priority,
            "exact match must outrank prefix"
        );

        let wildcard_rule = &router.rules[2];
        assert_eq!(wildcard_rule.r#match.host, None, "host * matches all hosts");
        assert!(wildcard_rule.backend_group.starts_with("gw-edge--any--"));
    }

    #[test]
    fn compiles_waf_policy_into_security_config() {
        let out = compiled();
        assert_eq!(out.config.security.ip_block, vec!["203.0.113.0/24"]);
        let rl = out.config.security.rate_limit.as_ref().unwrap();
        assert_eq!(rl.max_requests, 100);
        assert_eq!(rl.window_secs, 60);
    }

    #[test]
    fn rejects_invalid_set() {
        let set = intellaro_config::load_str(
            "apiVersion: intellaro.io/v1\nkind: Gateway\nmetadata: {name: g}\nspec: {listeners: [], hosts: []}\n",
        )
        .unwrap();
        assert!(matches!(compile(&set), Err(ConfigError::Invalid(_))));
    }
}
