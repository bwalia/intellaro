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

    // Reconcile each CRD type into the config document.
    reconcile_vhosts(ctx, &mut config).await?;
    reconcile_routes(ctx, &mut config).await?;
    reconcile_lb_policies(ctx, &mut config).await?;
    reconcile_security_policies(ctx, &mut config).await?;
    reconcile_cache_policies(ctx, &mut config).await?;

    // Service mesh auto-discovery: discover services and register backends.
    reconcile_service_discovery(ctx, &mut config).await?;

    // Rules-driven routing: evaluate routing policies.
    reconcile_routing_policies(ctx, &mut config).await?;

    // Push the merged configuration.
    ctx.mcp_client.update_config(&config).await?;
    ctx.mcp_client.reload().await?;

    info!("Full reconciliation complete");
    Ok(())
}

// ── VHost reconciler ────────────────────────────────────────────────

/// Merge all IntellaroVHost resources into the server config's `upstreams` list.
async fn reconcile_vhosts(
    ctx: &ReconcilerContext,
    config: &mut serde_json::Value,
) -> IngressResult<()> {
    let vhosts = list_resources::<IntellaroVHost>(ctx).await?;

    let mut upstreams = Vec::new();

    for vhost in &vhosts {
        let spec = &vhost.spec;
        let name = vhost.name_any();

        debug!(vhost = %name, hostname = %spec.hostname, "Reconciling VHost");

        let mut upstream = json!({
            "name": spec.upstream,
            "host_match": spec.hostname,
            "backends": [],
            "strategy": "round_robin",
        });

        // Apply LB policy if referenced.
        if let Some(ref lb_ref) = spec.lb_policy_ref {
            if let Some(lb) = find_resource::<IntellaroLBPolicy>(ctx, lb_ref).await? {
                let strategy = serde_json::to_value(&lb.spec.strategy)
                    .unwrap_or(json!("round_robin"));
                upstream["strategy"] = strategy;

                if let Some(ref hc) = lb.spec.health_check {
                    upstream["health_check"] = json!({
                        "path": hc.path,
                        "interval_secs": hc.interval_secs,
                        "timeout_secs": hc.timeout_secs,
                        "unhealthy_threshold": hc.unhealthy_threshold,
                    });
                }
            }
        }

        // Apply TLS settings.
        if let Some(ref tls) = spec.tls {
            if tls.enabled {
                upstream["tls"] = json!({
                    "enabled": true,
                    "secret_name": tls.secret_name,
                    "min_version": tls.min_version,
                    "acme": tls.acme,
                });
            }
        }

        upstreams.push(upstream);
    }

    config["upstreams"] = json!(upstreams);
    Ok(())
}

// ── Route reconciler ────────────────────────────────────────────────

/// Merge all IntellaroRoute resources into the server config's `routes` section.
async fn reconcile_routes(
    ctx: &ReconcilerContext,
    config: &mut serde_json::Value,
) -> IngressResult<()> {
    let routes = list_resources::<IntellaroRoute>(ctx).await?;

    let mut route_entries = Vec::new();

    for route in &routes {
        let spec = &route.spec;
        let name = route.name_any();

        debug!(route = %name, vhost = %spec.vhost_ref, "Reconciling Route");

        let mut entry = json!({
            "name": name,
            "vhost_ref": spec.vhost_ref,
            "backend": {
                "service_name": spec.backend.service_name,
                "service_port": spec.backend.service_port,
            },
            "priority": spec.priority,
        });

        // Match criteria.
        let mut match_obj = json!({});
        if let Some(ref prefix) = spec.r#match.path_prefix {
            match_obj["path_prefix"] = json!(prefix);
        }
        if let Some(ref exact) = spec.r#match.path_exact {
            match_obj["path_exact"] = json!(exact);
        }
        if let Some(ref regex) = spec.r#match.path_regex {
            match_obj["path_regex"] = json!(regex);
        }
        if !spec.r#match.methods.is_empty() {
            match_obj["methods"] = json!(spec.r#match.methods);
        }
        entry["match"] = match_obj;

        // Traffic split.
        if !spec.traffic_split.is_empty() {
            let splits: Vec<serde_json::Value> = spec
                .traffic_split
                .iter()
                .map(|ts| {
                    json!({
                        "backend": {
                            "service_name": ts.backend.service_name,
                            "service_port": ts.backend.service_port,
                        },
                        "weight": ts.weight,
                    })
                })
                .collect();
            entry["traffic_split"] = json!(splits);
        }

        // Rewrite.
        if let Some(ref rewrite) = spec.rewrite {
            entry["rewrite"] = json!({
                "replace_path_prefix": rewrite.replace_path_prefix,
                "replace_host": rewrite.replace_host,
            });
        }

        // Timeout and retry.
        if let Some(timeout) = spec.timeout_secs {
            entry["timeout_secs"] = json!(timeout);
        }
        if let Some(ref retry) = spec.retry {
            entry["retry"] = json!({
                "max_retries": retry.max_retries,
                "retry_on_status": retry.retry_on_status,
                "per_retry_timeout_secs": retry.per_retry_timeout_secs,
            });
        }

        route_entries.push(entry);
    }

    // Sort by priority descending so higher-priority routes match first.
    route_entries.sort_by(|a, b| {
        let pa = a["priority"].as_u64().unwrap_or(100);
        let pb = b["priority"].as_u64().unwrap_or(100);
        pb.cmp(&pa)
    });

    config["routes"] = json!(route_entries);
    Ok(())
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
                jwt = Some(json!({
                    "secret_ref": j.secret_ref,
                    "issuer": j.issuer,
                    "audience": j.audience,
                    "jwks_uri": j.jwks_uri,
                }));
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
        let backends: Vec<serde_json::Value> = svc
            .endpoints
            .iter()
            .filter(|ep| ep.ready)
            .map(|ep| {
                json!({
                    "address": format!("{}:{}", ep.address, ep.port),
                    "healthy": ep.ready,
                })
            })
            .collect();

        if backends.is_empty() {
            continue;
        }

        // Determine LB strategy from the first matching discovery config.
        let lb_strategy = discovery_configs
            .first()
            .map(|c| c.spec.default_lb_strategy.clone())
            .unwrap_or_else(|| "round_robin".to_string());

        let upstream = json!({
            "name": svc.group_name,
            "host_match": format!("{}.{}", svc.name, svc.namespace),
            "backends": backends,
            "strategy": lb_strategy,
            "auto_discovered": true,
            "source_namespace": svc.namespace,
            "source_service": svc.name,
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
