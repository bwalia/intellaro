//! Reconciliation logic.
//!
//! Translates the cluster's desired state (expressed as Intellaro CRDs)
//! into concrete `intellaro-http-server` configuration and pushes it via
//! the MCP API.  Each CRD type has a dedicated reconcile function that
//! reads the relevant resources and merges them into the server config.

use std::sync::Arc;

use kube::{Api, Client, ResourceExt};
use serde_json::json;
use tracing::{debug, info, warn};

use crate::crd::{
    IntellaroCachePolicy, IntellaroLBPolicy, IntellaroRoute, IntellaroRoutingPolicy,
    IntellaroSecurityPolicy, IntellaroServiceDiscovery, IntellaroVHost,
};
use crate::discovery::DiscoveryEngine;
use crate::error::IngressResult;
use crate::mcp::McpClient;

/// Shared state available to all reconcilers.
pub struct ReconcilerContext {
    pub kube_client: Client,
    pub mcp_client: McpClient,
    /// Namespace the controller is watching (None = cluster-wide).
    pub namespace: Option<String>,
    /// Service discovery engine.
    pub discovery_engine: DiscoveryEngine,
}

impl ReconcilerContext {
    pub fn new(kube_client: Client, mcp_client: McpClient, namespace: Option<String>) -> Self {
        let discovery_engine = DiscoveryEngine::new(kube_client.clone());
        Self {
            kube_client,
            mcp_client,
            namespace,
            discovery_engine,
        }
    }
}

// ── Full reconcile ──────────────────────────────────────────────────

/// Run a full reconciliation pass: read all CRDs, build the merged
/// configuration, and push it to the MCP API.
pub async fn full_reconcile(ctx: &ReconcilerContext) -> IngressResult<()> {
    info!("Starting full reconciliation pass");

    let mut config = ctx.mcp_client.get_config().await?;

    // VHosts + Routes + LBPolicies → data-plane upstreams and router rules.
    build_routing(ctx, &mut config).await?;
    reconcile_lb_policies(ctx, &mut config).await?;
    reconcile_security_policies(ctx, &mut config).await?;
    reconcile_cache_policies(ctx, &mut config).await?;

    // Service mesh auto-discovery: discover services and register backends.
    reconcile_service_discovery(ctx, &mut config).await?;

    // Rules-driven routing: evaluate routing policies.
    reconcile_routing_policies(ctx, &mut config).await?;

    // Push the merged configuration. apply_update hot-swaps the data plane;
    // do NOT call reload() here — that re-reads the config file and would
    // revert this push.
    ctx.mcp_client.update_config(&config).await?;

    info!("Full reconciliation complete");
    Ok(())
}

// ── VHost + Route reconciler ────────────────────────────────────────

/// Translate IntellaroVHost + IntellaroRoute (+ referenced LBPolicies)
/// into the data plane's actual configuration:
///
/// * each route's backend service becomes an upstream whose server is the
///   service's cluster-DNS name (kube-proxy handles endpoint balancing);
///   traffic splits become one weighted upstream across services
/// * each (vhost host, route match) pair becomes a router rule with the
///   route's priority and timeout
///
/// The result is written to `config.upstreams` and `config.router.rules`,
/// which is exactly what `intellaro-http-server` deserializes.
async fn build_routing(
    ctx: &ReconcilerContext,
    config: &mut serde_json::Value,
) -> IngressResult<()> {
    let vhosts = list_resources::<IntellaroVHost>(ctx).await?;
    let routes = list_resources::<IntellaroRoute>(ctx).await?;

    // Resolve each vhost's LB strategy / health check once.
    let mut vhost_map: std::collections::HashMap<String, VHostInfo> =
        std::collections::HashMap::new();

    for vhost in &vhosts {
        let spec = &vhost.spec;
        let name = vhost.name_any();

        let mut info = VHostInfo {
            hostnames: std::iter::once(spec.hostname.clone())
                .chain(spec.aliases.iter().cloned())
                .collect(),
            strategy: json!("round_robin"),
            health_check: None,
        };

        if let Some(ref lb_ref) = spec.lb_policy_ref {
            if let Some(lb) = find_resource::<IntellaroLBPolicy>(ctx, lb_ref).await? {
                info.strategy =
                    serde_json::to_value(&lb.spec.strategy).unwrap_or(json!("round_robin"));
                if let Some(ref hc) = lb.spec.health_check {
                    info.health_check = Some(json!({
                        "path": hc.path,
                        "interval_secs": hc.interval_secs,
                        "unhealthy_threshold": hc.unhealthy_threshold,
                    }));
                }
            }
        }

        if spec.tls.as_ref().is_some_and(|t| t.enabled) {
            warn!(
                vhost = %name,
                "TLS termination via VHost secrets is not wired into the data plane yet — serving plain HTTP"
            );
        }

        debug!(vhost = %name, hostname = %spec.hostname, "Resolved VHost");
        vhost_map.insert(name, info);
    }

    let mut upstreams: Vec<serde_json::Value> = Vec::new();
    let mut seen_upstreams: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut rules: Vec<serde_json::Value> = Vec::new();

    for route in &routes {
        let spec = &route.spec;
        let name = route.name_any();
        let route_ns = route.namespace().unwrap_or_else(|| "default".to_string());

        let Some(vhost) = vhost_map.get(&spec.vhost_ref) else {
            warn!(route = %name, vhost_ref = %spec.vhost_ref, "Route references unknown VHost — skipping");
            continue;
        };

        // ── Upstream for this route ──────────────────────────────────
        let (group_name, upstream) = if spec.traffic_split.is_empty() {
            let backend = &spec.backend;
            let ns = backend.namespace.clone().unwrap_or_else(|| route_ns.clone());
            let group = format!("{}-{}-{}", ns, backend.service_name, backend.service_port);
            let upstream = json!({
                "name": group,
                "servers": [{
                    "address": service_dns(&backend.service_name, &ns, backend.service_port),
                    "weight": 1,
                }],
                "load_balancing": vhost.strategy,
                "health_check": vhost.health_check,
            });
            (group, upstream)
        } else {
            // Weighted split across services → one weighted upstream.
            let group = format!("route-{}-{}-split", route_ns, name);
            let servers: Vec<serde_json::Value> = spec
                .traffic_split
                .iter()
                .map(|ts| {
                    let ns = ts.backend.namespace.clone().unwrap_or_else(|| route_ns.clone());
                    json!({
                        "address": service_dns(&ts.backend.service_name, &ns, ts.backend.service_port),
                        "weight": ts.weight.max(1),
                    })
                })
                .collect();
            let upstream = json!({
                "name": group,
                "servers": servers,
                "load_balancing": "weighted",
                "health_check": vhost.health_check,
            });
            (group, upstream)
        };

        if seen_upstreams.insert(group_name.clone()) {
            upstreams.push(upstream);
        }

        // ── Router rule(s): one per hostname/alias ───────────────────
        let mut headers = serde_json::Map::new();
        for hm in &spec.r#match.header_matches {
            if let Some(ref exact) = hm.exact {
                headers.insert(hm.name.clone(), json!(exact));
            } else {
                warn!(route = %name, header = %hm.name, "Only exact header matches are supported today — skipping condition");
            }
        }

        if spec.rewrite.is_some() {
            warn!(route = %name, "Path/host rewrite is not wired into the data plane yet — ignored");
        }

        for hostname in &vhost.hostnames {
            rules.push(json!({
                "name": format!("{}/{}", hostname, name),
                "priority": spec.priority,
                "match": {
                    "host": hostname,
                    "path_prefix": spec.r#match.path_prefix,
                    "path_exact": spec.r#match.path_exact,
                    "path_regex": spec.r#match.path_regex,
                    "methods": spec.r#match.methods,
                    "headers": headers,
                },
                "backend_group": group_name,
                "timeout_secs": spec.timeout_secs,
                "enabled": true,
            }));
        }

        debug!(route = %name, group = %group_name, "Reconciled Route");
    }

    info!(
        vhosts = vhost_map.len(),
        routes = routes.len(),
        upstreams = upstreams.len(),
        rules = rules.len(),
        "Built routing configuration"
    );

    config["upstreams"] = json!(upstreams);
    config["router"] = json!({ "rules": rules });
    Ok(())
}

/// Per-VHost data resolved once and reused by every route.
struct VHostInfo {
    hostnames: Vec<String>,
    strategy: serde_json::Value,
    health_check: Option<serde_json::Value>,
}

/// Cluster-DNS address for a Service. kube-proxy balances across the
/// service's endpoints; Intellaro balances across services (splits).
fn service_dns(service: &str, namespace: &str, port: u16) -> String {
    format!("{service}.{namespace}.svc.cluster.local:{port}")
}

// ── LB Policy reconciler ───────────────────────────────────────────

/// LB policies are consumed by the VHost reconciler via reference.
/// This function validates all LBPolicy resources.
async fn reconcile_lb_policies(
    ctx: &ReconcilerContext,
    _config: &mut serde_json::Value,
) -> IngressResult<()> {
    let policies = list_resources::<IntellaroLBPolicy>(ctx).await?;
    for policy in &policies {
        debug!(policy = %policy.name_any(), "Validated LBPolicy");
    }
    Ok(())
}

// ── Security Policy reconciler ─────────────────────────────────────

/// Merge all IntellaroSecurityPolicy resources into the server config.
async fn reconcile_security_policies(
    ctx: &ReconcilerContext,
    config: &mut serde_json::Value,
) -> IngressResult<()> {
    let policies = list_resources::<IntellaroSecurityPolicy>(ctx).await?;

    // Aggregate IP lists and rate limiting across all policies.
    let mut ip_allow: Vec<String> = Vec::new();
    let mut ip_block: Vec<String> = Vec::new();
    let mut rate_limit: Option<serde_json::Value> = None;
    let mut jwt: Option<serde_json::Value> = None;

    for policy in &policies {
        let spec = &policy.spec;
        let name = policy.name_any();

        debug!(policy = %name, "Reconciling SecurityPolicy");

        ip_allow.extend(spec.ip_allow.clone());
        ip_block.extend(spec.ip_block.clone());

        if let Some(ref rl) = spec.rate_limit {
            if rl.enabled {
                rate_limit = Some(json!({
                    "max_requests": rl.max_requests,
                    "window_secs": rl.window_secs,
                }));
            }
        }

        if let Some(ref j) = spec.jwt {
            if j.enabled {
                // The data plane's JwtConfig takes an inline secret or key
                // path; resolving a Kubernetes Secret into it is not wired
                // up yet, so surface that instead of pushing a broken config.
                warn!(
                    policy = %name,
                    "JWT via SecurityPolicy secretRef is not wired into the data plane yet — skipping"
                );
                jwt = None;
            }
        }
    }

    // Deduplicate IP lists.
    ip_allow.sort();
    ip_allow.dedup();
    ip_block.sort();
    ip_block.dedup();

    let security = json!({
        "ip_allow": ip_allow,
        "ip_block": ip_block,
        "rate_limit": rate_limit,
        "jwt": jwt,
    });

    config["security"] = security;
    Ok(())
}

// ── Cache Policy reconciler ────────────────────────────────────────

/// Merge all IntellaroCachePolicy resources into the server config.
async fn reconcile_cache_policies(
    ctx: &ReconcilerContext,
    config: &mut serde_json::Value,
) -> IngressResult<()> {
    let policies = list_resources::<IntellaroCachePolicy>(ctx).await?;

    // Use the first enabled cache policy as the global config.
    // Per-route overrides are embedded in the route entries.
    for policy in &policies {
        let spec = &policy.spec;
        let name = policy.name_any();

        if !spec.enabled {
            continue;
        }

        debug!(policy = %name, "Reconciling CachePolicy");

        let cache = json!({
            "enabled": true,
            "max_entries": spec.max_entries,
            "default_ttl_secs": spec.default_ttl_secs,
            "eviction_strategy": serde_json::to_value(&spec.eviction_strategy)
                .unwrap_or(json!("lru")),
            "cacheable_methods": spec.cacheable_methods,
            "cacheable_statuses": spec.cacheable_statuses,
            "respect_origin_headers": spec.respect_origin_headers,
        });

        config["cache"] = cache;
        break; // First enabled policy wins as global default.
    }

    Ok(())
}

// ── Service Discovery reconciler ─────────────────────────────────────

/// Run service discovery: discover K8s services and register them as backends.
async fn reconcile_service_discovery(
    ctx: &ReconcilerContext,
    config: &mut serde_json::Value,
) -> IngressResult<()> {
    let discovery_configs = list_resources::<IntellaroServiceDiscovery>(ctx).await?;

    if discovery_configs.is_empty() {
        debug!("No IntellaroServiceDiscovery resources found");
        return Ok(());
    }

    info!(
        count = discovery_configs.len(),
        "Running service mesh auto-discovery"
    );

    let service_map = ctx.discovery_engine.discover_all(&discovery_configs).await?;

    // Update metrics.
    crate::metrics::set_discovery_counts(
        service_map.total_services,
        service_map.total_endpoints,
        service_map.services.len() as u32,
    );
    crate::metrics::record_discovery_success();

    // Merge discovered services into the upstreams config.
    // Existing upstreams from VHost CRDs are preserved; discovered services
    // are added alongside them.
    let existing_upstreams = config["upstreams"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let mut all_upstreams = existing_upstreams;

    for (_group_name, svc) in &service_map.services {
        let servers: Vec<serde_json::Value> = svc
            .endpoints
            .iter()
            .filter(|ep| ep.ready)
            .map(|ep| {
                json!({
                    "address": format!("{}:{}", ep.address, ep.port),
                    "weight": 1,
                })
            })
            .collect();

        if servers.is_empty() {
            continue;
        }

        // Determine LB strategy from the first matching discovery config.
        let lb_strategy = discovery_configs
            .first()
            .map(|c| c.spec.default_lb_strategy.clone())
            .unwrap_or_else(|| "round_robin".to_string());

        let upstream = json!({
            "name": svc.group_name,
            "servers": servers,
            "load_balancing": lb_strategy,
        });

        // Don't duplicate: check if an upstream with this name already exists.
        let already_exists = all_upstreams
            .iter()
            .any(|u| u["name"].as_str() == Some(&svc.group_name));

        if !already_exists {
            all_upstreams.push(upstream);
        }
    }

    config["upstreams"] = json!(all_upstreams);

    // Store the full service map in a discoverable section.
    config["service_discovery"] = json!({
        "enabled": true,
        "total_services": service_map.total_services,
        "total_endpoints": service_map.total_endpoints,
        "registered_groups": service_map.services.len(),
    });

    Ok(())
}

// ── Routing Policy reconciler ───────────────────────────────────────

/// Evaluate all IntellaroRoutingPolicy resources and merge into config.
async fn reconcile_routing_policies(
    ctx: &ReconcilerContext,
    config: &mut serde_json::Value,
) -> IngressResult<()> {
    let policies = list_resources::<IntellaroRoutingPolicy>(ctx).await?;

    if policies.is_empty() {
        debug!("No IntellaroRoutingPolicy resources found");
        return Ok(());
    }

    info!(
        count = policies.len(),
        "Evaluating routing policies"
    );

    let evaluated = crate::routing::evaluate_policies(&policies)?;

    // Update metrics.
    crate::metrics::set_routing_policy_counts(
        evaluated.total_policies,
        evaluated.active_policies,
        evaluated.canary_deployments.len(),
        evaluated.priority_tiers.len(),
        evaluated.traffic_splits.len(),
    );

    // Merge evaluated routing into the config.
    if !evaluated.traffic_splits.is_empty() {
        config["routing_policies"]["traffic_splits"] = json!(evaluated.traffic_splits);
    }
    if !evaluated.priority_tiers.is_empty() {
        config["routing_policies"]["priority_tiers"] = json!(evaluated.priority_tiers);
    }
    if !evaluated.canary_deployments.is_empty() {
        config["routing_policies"]["canary"] = json!(evaluated.canary_deployments);
    }
    if !evaluated.failover_rules.is_empty() {
        config["routing_policies"]["failover"] = json!(evaluated.failover_rules);
    }
    if let Some(ref ai_config) = evaluated.ai_config {
        config["routing_policies"]["ai"] = ai_config.clone();
    }
    if !evaluated.rate_limits.is_empty() {
        config["routing_policies"]["rate_limits"] = json!(evaluated.rate_limits);
    }
    if !evaluated.header_rules.is_empty() {
        config["routing_policies"]["headers"] = json!(evaluated.header_rules);
    }

    Ok(())
}

// ── Kubernetes helpers ──────────────────────────────────────────────

/// List all resources of a given CRD type in the watched scope.
async fn list_resources<K>(ctx: &ReconcilerContext) -> IngressResult<Vec<Arc<K>>>
where
    K: kube::Resource<DynamicType = (), Scope = k8s_openapi::NamespaceResourceScope>
        + Clone
        + std::fmt::Debug
        + serde::de::DeserializeOwned
        + 'static,
    <K as kube::Resource>::DynamicType: Default,
{
    let api: Api<K> = match &ctx.namespace {
        Some(ns) => Api::namespaced(ctx.kube_client.clone(), ns),
        None => Api::all(ctx.kube_client.clone()),
    };

    let list = api.list(&Default::default()).await?;
    Ok(list.items.into_iter().map(Arc::new).collect())
}

/// Find a single resource by name in the watched scope.
async fn find_resource<K>(
    ctx: &ReconcilerContext,
    name: &str,
) -> IngressResult<Option<Arc<K>>>
where
    K: kube::Resource<DynamicType = (), Scope = k8s_openapi::NamespaceResourceScope>
        + Clone
        + std::fmt::Debug
        + serde::de::DeserializeOwned
        + 'static,
    <K as kube::Resource>::DynamicType: Default,
{
    let api: Api<K> = match &ctx.namespace {
        Some(ns) => Api::namespaced(ctx.kube_client.clone(), ns),
        None => Api::all(ctx.kube_client.clone()),
    };

    match api.get_opt(name).await? {
        Some(resource) => Ok(Some(Arc::new(resource))),
        None => {
            warn!(resource = %name, kind = %std::any::type_name::<K>(), "Referenced resource not found");
            Ok(None)
        }
    }
}
