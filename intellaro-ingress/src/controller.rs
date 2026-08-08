//! Kubernetes controller — watches Intellaro CRDs and triggers reconciliation.
//!
//! Uses `kube-runtime` `Controller` to watch for changes to each CRD type.
//! On every event (create, update, delete) the controller runs the full
//! reconciliation pipeline, merging CRD state into the MCP configuration.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use kube::api::PatchParams;
use kube::runtime::controller::Action;
use kube::runtime::Controller;
use kube::{Api, Client, ResourceExt};
use tracing::{error, info, warn};

use crate::crd::{
    IntellaroCachePolicy, IntellaroCondition, IntellaroLBPolicy,
    IntellaroRoute, IntellaroRoutingPolicy, IntellaroSecurityPolicy,
    IntellaroServiceDiscovery, IntellaroVHost,
};
use crate::crd::cache::IntellaroCachePolicyStatus;
use crate::crd::lb_policy::IntellaroLBPolicyStatus;
use crate::crd::route::IntellaroRouteStatus;
use crate::crd::routing_policy::IntellaroRoutingPolicyStatus;
use crate::crd::security::IntellaroSecurityPolicyStatus;
use crate::crd::service_discovery::IntellaroServiceDiscoveryStatus;
use crate::crd::vhost::IntellaroVHostStatus;
use crate::error::IngressError;
use crate::mcp::McpClient;
use crate::reconciler::{self, ReconcilerContext};

/// Context shared across all controller instances.
struct ControllerCtx {
    reconciler_ctx: Arc<ReconcilerContext>,
    /// Flipped true on any successful reconcile so /readyz reflects a
    /// functioning controller even if the very first pass failed.
    ready: crate::health::ReadyFlag,
}

/// Start all CRD controllers as concurrent tasks.
///
/// Each controller watches a single CRD type but they all share the same
/// `ReconcilerContext` so that reconciliation has access to the full
/// cluster state and the MCP client.
pub async fn run(
    kube_client: Client,
    mcp_client: McpClient,
    namespace: Option<String>,
    ready: crate::health::ReadyFlag,
) -> anyhow::Result<()> {
    let reconciler_ctx = Arc::new(ReconcilerContext::new(
        kube_client.clone(),
        mcp_client,
        namespace.clone(),
    ));

    let ctx = Arc::new(ControllerCtx {
        reconciler_ctx: reconciler_ctx.clone(),
        ready,
    });

    info!("Starting Intellaro CRD controllers");

    // Build per-CRD API handles.
    let vhost_api: Api<IntellaroVHost> = namespaced_or_all(kube_client.clone(), &namespace);
    let route_api: Api<IntellaroRoute> = namespaced_or_all(kube_client.clone(), &namespace);
    let lb_api: Api<IntellaroLBPolicy> = namespaced_or_all(kube_client.clone(), &namespace);
    let sec_api: Api<IntellaroSecurityPolicy> = namespaced_or_all(kube_client.clone(), &namespace);
    let cache_api: Api<IntellaroCachePolicy> = namespaced_or_all(kube_client.clone(), &namespace);
    let discovery_api: Api<IntellaroServiceDiscovery> = namespaced_or_all(kube_client.clone(), &namespace);
    let routing_api: Api<IntellaroRoutingPolicy> = namespaced_or_all(kube_client.clone(), &namespace);

    // Spawn controller tasks.
    let vhost_ctrl = {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            Controller::new(vhost_api.clone(), Default::default())
                .run(
                    move |obj, ctx| reconcile_vhost(obj, ctx),
                    error_policy::<IntellaroVHost>,
                    ctx,
                )
                .for_each(|result| async {
                    match result {
                        Ok((obj, _action)) => {
                            info!(name = %obj.name, "VHost reconciled");
                        }
                        Err(e) => {
                            warn!(error = %e, "VHost reconciliation error");
                        }
                    }
                })
                .await;
        })
    };

    let route_ctrl = {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            Controller::new(route_api.clone(), Default::default())
                .run(
                    move |obj, ctx| reconcile_route(obj, ctx),
                    error_policy::<IntellaroRoute>,
                    ctx,
                )
                .for_each(|result| async {
                    match result {
                        Ok((obj, _action)) => {
                            info!(name = %obj.name, "Route reconciled");
                        }
                        Err(e) => {
                            warn!(error = %e, "Route reconciliation error");
                        }
                    }
                })
                .await;
        })
    };

    let lb_ctrl = {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            Controller::new(lb_api.clone(), Default::default())
                .run(
                    move |obj, ctx| reconcile_lb_policy(obj, ctx),
                    error_policy::<IntellaroLBPolicy>,
                    ctx,
                )
                .for_each(|result| async {
                    match result {
                        Ok((obj, _action)) => {
                            info!(name = %obj.name, "LBPolicy reconciled");
                        }
                        Err(e) => {
                            warn!(error = %e, "LBPolicy reconciliation error");
                        }
                    }
                })
                .await;
        })
    };

    let sec_ctrl = {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            Controller::new(sec_api.clone(), Default::default())
                .run(
                    move |obj, ctx| reconcile_security_policy(obj, ctx),
                    error_policy::<IntellaroSecurityPolicy>,
                    ctx,
                )
                .for_each(|result| async {
                    match result {
                        Ok((obj, _action)) => {
                            info!(name = %obj.name, "SecurityPolicy reconciled");
                        }
                        Err(e) => {
                            warn!(error = %e, "SecurityPolicy reconciliation error");
                        }
                    }
                })
                .await;
        })
    };

    let cache_ctrl = {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            Controller::new(cache_api.clone(), Default::default())
                .run(
                    move |obj, ctx| reconcile_cache_policy(obj, ctx),
                    error_policy::<IntellaroCachePolicy>,
                    ctx,
                )
                .for_each(|result| async {
                    match result {
                        Ok((obj, _action)) => {
                            info!(name = %obj.name, "CachePolicy reconciled");
                        }
                        Err(e) => {
                            warn!(error = %e, "CachePolicy reconciliation error");
                        }
                    }
                })
                .await;
        })
    };

    let discovery_ctrl = {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            Controller::new(discovery_api.clone(), Default::default())
                .run(
                    move |obj, ctx| reconcile_service_discovery(obj, ctx),
                    error_policy::<IntellaroServiceDiscovery>,
                    ctx,
                )
                .for_each(|result| async {
                    match result {
                        Ok((obj, _action)) => {
                            info!(name = %obj.name, "ServiceDiscovery reconciled");
                        }
                        Err(e) => {
                            warn!(error = %e, "ServiceDiscovery reconciliation error");
                        }
                    }
                })
                .await;
        })
    };

    let routing_ctrl = {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            Controller::new(routing_api.clone(), Default::default())
                .run(
                    move |obj, ctx| reconcile_routing_policy(obj, ctx),
                    error_policy::<IntellaroRoutingPolicy>,
                    ctx,
                )
                .for_each(|result| async {
                    match result {
                        Ok((obj, _action)) => {
                            info!(name = %obj.name, "RoutingPolicy reconciled");
                        }
                        Err(e) => {
                            warn!(error = %e, "RoutingPolicy reconciliation error");
                        }
                    }
                })
                .await;
        })
    };

    // Wait for all controllers (they run indefinitely).
    tokio::select! {
        _ = vhost_ctrl => warn!("VHost controller exited"),
        _ = route_ctrl => warn!("Route controller exited"),
        _ = lb_ctrl => warn!("LBPolicy controller exited"),
        _ = sec_ctrl => warn!("SecurityPolicy controller exited"),
        _ = cache_ctrl => warn!("CachePolicy controller exited"),
        _ = discovery_ctrl => warn!("ServiceDiscovery controller exited"),
        _ = routing_ctrl => warn!("RoutingPolicy controller exited"),
    }

    Ok(())
}

// ── Per-CRD reconcile functions ─────────────────────────────────────

async fn reconcile_vhost(
    obj: Arc<IntellaroVHost>,
    ctx: Arc<ControllerCtx>,
) -> Result<Action, IngressError> {
    let name = obj.name_any();
    info!(vhost = %name, "Reconciling IntellaroVHost");

    match reconciler::full_reconcile(&ctx.reconciler_ctx).await {
        Ok(()) => {
            ctx.ready.store(true, std::sync::atomic::Ordering::Relaxed);
            update_vhost_status(&ctx.reconciler_ctx, &obj, true, None).await;
            Ok(Action::requeue(Duration::from_secs(300)))
        }
        Err(e) => {
            error!(vhost = %name, error = %e, "Reconciliation failed");
            update_vhost_status(&ctx.reconciler_ctx, &obj, false, Some(e.to_string())).await;
            Ok(Action::requeue(Duration::from_secs(30)))
        }
    }
}

async fn reconcile_route(
    obj: Arc<IntellaroRoute>,
    ctx: Arc<ControllerCtx>,
) -> Result<Action, IngressError> {
    let name = obj.name_any();
    info!(route = %name, "Reconciling IntellaroRoute");

    match reconciler::full_reconcile(&ctx.reconciler_ctx).await {
        Ok(()) => {
            ctx.ready.store(true, std::sync::atomic::Ordering::Relaxed);
            update_route_status(&ctx.reconciler_ctx, &obj, true, None).await;
            Ok(Action::requeue(Duration::from_secs(300)))
        }
        Err(e) => {
            error!(route = %name, error = %e, "Reconciliation failed");
            update_route_status(&ctx.reconciler_ctx, &obj, false, Some(e.to_string())).await;
            Ok(Action::requeue(Duration::from_secs(30)))
        }
    }
}

async fn reconcile_lb_policy(
    obj: Arc<IntellaroLBPolicy>,
    ctx: Arc<ControllerCtx>,
) -> Result<Action, IngressError> {
    let name = obj.name_any();
    info!(policy = %name, "Reconciling IntellaroLBPolicy");

    match reconciler::full_reconcile(&ctx.reconciler_ctx).await {
        Ok(()) => {
            ctx.ready.store(true, std::sync::atomic::Ordering::Relaxed);
            update_lb_status(&ctx.reconciler_ctx, &obj, true, None).await;
            Ok(Action::requeue(Duration::from_secs(300)))
        }
        Err(e) => {
            error!(policy = %name, error = %e, "Reconciliation failed");
            update_lb_status(&ctx.reconciler_ctx, &obj, false, Some(e.to_string())).await;
            Ok(Action::requeue(Duration::from_secs(30)))
        }
    }
}

async fn reconcile_security_policy(
    obj: Arc<IntellaroSecurityPolicy>,
    ctx: Arc<ControllerCtx>,
) -> Result<Action, IngressError> {
    let name = obj.name_any();
    info!(policy = %name, "Reconciling IntellaroSecurityPolicy");

    match reconciler::full_reconcile(&ctx.reconciler_ctx).await {
        Ok(()) => {
            ctx.ready.store(true, std::sync::atomic::Ordering::Relaxed);
            update_security_status(&ctx.reconciler_ctx, &obj, true, None).await;
            Ok(Action::requeue(Duration::from_secs(300)))
        }
        Err(e) => {
            error!(policy = %name, error = %e, "Reconciliation failed");
            update_security_status(&ctx.reconciler_ctx, &obj, false, Some(e.to_string())).await;
            Ok(Action::requeue(Duration::from_secs(30)))
        }
    }
}

async fn reconcile_cache_policy(
    obj: Arc<IntellaroCachePolicy>,
    ctx: Arc<ControllerCtx>,
) -> Result<Action, IngressError> {
    let name = obj.name_any();
    info!(policy = %name, "Reconciling IntellaroCachePolicy");

    match reconciler::full_reconcile(&ctx.reconciler_ctx).await {
        Ok(()) => {
            ctx.ready.store(true, std::sync::atomic::Ordering::Relaxed);
            update_cache_status(&ctx.reconciler_ctx, &obj, true, None).await;
            Ok(Action::requeue(Duration::from_secs(300)))
        }
        Err(e) => {
            error!(policy = %name, error = %e, "Reconciliation failed");
            update_cache_status(&ctx.reconciler_ctx, &obj, false, Some(e.to_string())).await;
            Ok(Action::requeue(Duration::from_secs(30)))
        }
    }
}

async fn reconcile_service_discovery(
    obj: Arc<IntellaroServiceDiscovery>,
    ctx: Arc<ControllerCtx>,
) -> Result<Action, IngressError> {
    let name = obj.name_any();
    info!(discovery = %name, "Reconciling IntellaroServiceDiscovery");

    match reconciler::full_reconcile(&ctx.reconciler_ctx).await {
        Ok(()) => {
            ctx.ready.store(true, std::sync::atomic::Ordering::Relaxed);
            update_discovery_status(&ctx.reconciler_ctx, &obj, true, None).await;
            Ok(Action::requeue(Duration::from_secs(300)))
        }
        Err(e) => {
            error!(discovery = %name, error = %e, "Reconciliation failed");
            update_discovery_status(&ctx.reconciler_ctx, &obj, false, Some(e.to_string())).await;
            Ok(Action::requeue(Duration::from_secs(30)))
        }
    }
}

async fn reconcile_routing_policy(
    obj: Arc<IntellaroRoutingPolicy>,
    ctx: Arc<ControllerCtx>,
) -> Result<Action, IngressError> {
    let name = obj.name_any();
    info!(policy = %name, "Reconciling IntellaroRoutingPolicy");

    match reconciler::full_reconcile(&ctx.reconciler_ctx).await {
        Ok(()) => {
            ctx.ready.store(true, std::sync::atomic::Ordering::Relaxed);
            update_routing_policy_status(&ctx.reconciler_ctx, &obj, true, None).await;
            Ok(Action::requeue(Duration::from_secs(300)))
        }
        Err(e) => {
            error!(policy = %name, error = %e, "Reconciliation failed");
            update_routing_policy_status(&ctx.reconciler_ctx, &obj, false, Some(e.to_string()))
                .await;
            Ok(Action::requeue(Duration::from_secs(30)))
        }
    }
}

// ── Error policy ────────────────────────────────────────────────────

fn error_policy<K: kube::Resource>(
    _obj: Arc<K>,
    error: &IngressError,
    _ctx: Arc<ControllerCtx>,
) -> Action {
    warn!(error = %error, "Controller error, retrying in 30s");
    Action::requeue(Duration::from_secs(30))
}

// ── Status update helpers ───────────────────────────────────────────

fn synced_condition(synced: bool, message: Option<String>) -> IntellaroCondition {
    let now = chrono::Utc::now().to_rfc3339();
    IntellaroCondition {
        r#type: "Synced".to_string(),
        status: if synced { "True" } else { "False" }.to_string(),
        reason: Some(if synced { "ReconcileSucceeded" } else { "ReconcileFailed" }.to_string()),
        message,
        last_transition_time: Some(now),
    }
}

async fn update_vhost_status(
    ctx: &ReconcilerContext,
    obj: &IntellaroVHost,
    synced: bool,
    message: Option<String>,
) {
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<IntellaroVHost> = Api::namespaced(ctx.kube_client.clone(), &ns);
    let name = obj.name_any();
    let now = chrono::Utc::now().to_rfc3339();

    // Skip no-op status writes: re-patching with a fresh timestamp bumps
    // resourceVersion and re-triggers our own watch — a reconcile hot loop.
    if obj.status.as_ref().is_some_and(|s| {
        s.synced == synced && s.observed_generation == obj.metadata.generation.unwrap_or(0)
    }) {
        return;
    }

    let status = IntellaroVHostStatus {
        synced,
        last_synced_at: if synced { Some(now) } else { None },
        active_backends: 0,
        observed_generation: obj.metadata.generation.unwrap_or(0),
        conditions: vec![synced_condition(synced, message)],
    };

    let patch = serde_json::json!({ "status": status });
    if let Err(e) = api
        .patch_status(&name, &PatchParams::default(), &kube::api::Patch::Merge(&patch))
        .await
    {
        warn!(vhost = %name, error = %e, "Failed to update VHost status");
    }
}

async fn update_route_status(
    ctx: &ReconcilerContext,
    obj: &IntellaroRoute,
    synced: bool,
    message: Option<String>,
) {
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<IntellaroRoute> = Api::namespaced(ctx.kube_client.clone(), &ns);
    let name = obj.name_any();
    let now = chrono::Utc::now().to_rfc3339();

    // Skip no-op status writes: re-patching with a fresh timestamp bumps
    // resourceVersion and re-triggers our own watch — a reconcile hot loop.
    if obj.status.as_ref().is_some_and(|s| {
        s.synced == synced && s.observed_generation == obj.metadata.generation.unwrap_or(0)
    }) {
        return;
    }

    let status = IntellaroRouteStatus {
        synced,
        last_synced_at: if synced { Some(now) } else { None },
        observed_generation: obj.metadata.generation.unwrap_or(0),
        conditions: vec![synced_condition(synced, message)],
    };

    let patch = serde_json::json!({ "status": status });
    if let Err(e) = api
        .patch_status(&name, &PatchParams::default(), &kube::api::Patch::Merge(&patch))
        .await
    {
        warn!(route = %name, error = %e, "Failed to update Route status");
    }
}

async fn update_lb_status(
    ctx: &ReconcilerContext,
    obj: &IntellaroLBPolicy,
    synced: bool,
    message: Option<String>,
) {
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<IntellaroLBPolicy> = Api::namespaced(ctx.kube_client.clone(), &ns);
    let name = obj.name_any();
    let now = chrono::Utc::now().to_rfc3339();

    // Skip no-op status writes: re-patching with a fresh timestamp bumps
    // resourceVersion and re-triggers our own watch — a reconcile hot loop.
    if obj.status.as_ref().is_some_and(|s| {
        s.synced == synced && s.observed_generation == obj.metadata.generation.unwrap_or(0)
    }) {
        return;
    }

    let status = IntellaroLBPolicyStatus {
        synced,
        last_synced_at: if synced { Some(now) } else { None },
        observed_generation: obj.metadata.generation.unwrap_or(0),
        conditions: vec![synced_condition(synced, message)],
    };

    let patch = serde_json::json!({ "status": status });
    if let Err(e) = api
        .patch_status(&name, &PatchParams::default(), &kube::api::Patch::Merge(&patch))
        .await
    {
        warn!(policy = %name, error = %e, "Failed to update LBPolicy status");
    }
}

async fn update_security_status(
    ctx: &ReconcilerContext,
    obj: &IntellaroSecurityPolicy,
    synced: bool,
    message: Option<String>,
) {
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<IntellaroSecurityPolicy> = Api::namespaced(ctx.kube_client.clone(), &ns);
    let name = obj.name_any();
    let now = chrono::Utc::now().to_rfc3339();

    // Skip no-op status writes: re-patching with a fresh timestamp bumps
    // resourceVersion and re-triggers our own watch — a reconcile hot loop.
    if obj.status.as_ref().is_some_and(|s| {
        s.synced == synced && s.observed_generation == obj.metadata.generation.unwrap_or(0)
    }) {
        return;
    }

    let status = IntellaroSecurityPolicyStatus {
        synced,
        last_synced_at: if synced { Some(now) } else { None },
        observed_generation: obj.metadata.generation.unwrap_or(0),
        conditions: vec![synced_condition(synced, message)],
    };

    let patch = serde_json::json!({ "status": status });
    if let Err(e) = api
        .patch_status(&name, &PatchParams::default(), &kube::api::Patch::Merge(&patch))
        .await
    {
        warn!(policy = %name, error = %e, "Failed to update SecurityPolicy status");
    }
}

async fn update_cache_status(
    ctx: &ReconcilerContext,
    obj: &IntellaroCachePolicy,
    synced: bool,
    message: Option<String>,
) {
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<IntellaroCachePolicy> = Api::namespaced(ctx.kube_client.clone(), &ns);
    let name = obj.name_any();
    let now = chrono::Utc::now().to_rfc3339();

    // Skip no-op status writes: re-patching with a fresh timestamp bumps
    // resourceVersion and re-triggers our own watch — a reconcile hot loop.
    if obj.status.as_ref().is_some_and(|s| {
        s.synced == synced && s.observed_generation == obj.metadata.generation.unwrap_or(0)
    }) {
        return;
    }

    let status = IntellaroCachePolicyStatus {
        synced,
        last_synced_at: if synced { Some(now) } else { None },
        observed_generation: obj.metadata.generation.unwrap_or(0),
        conditions: vec![synced_condition(synced, message)],
    };

    let patch = serde_json::json!({ "status": status });
    if let Err(e) = api
        .patch_status(&name, &PatchParams::default(), &kube::api::Patch::Merge(&patch))
        .await
    {
        warn!(policy = %name, error = %e, "Failed to update CachePolicy status");
    }
}

async fn update_discovery_status(
    ctx: &ReconcilerContext,
    obj: &IntellaroServiceDiscovery,
    synced: bool,
    message: Option<String>,
) {
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<IntellaroServiceDiscovery> = Api::namespaced(ctx.kube_client.clone(), &ns);
    let name = obj.name_any();
    let now = chrono::Utc::now().to_rfc3339();

    // Skip no-op status writes: re-patching with a fresh timestamp bumps
    // resourceVersion and re-triggers our own watch — a reconcile hot loop.
    if obj.status.as_ref().is_some_and(|s| {
        s.synced == synced && s.observed_generation == obj.metadata.generation.unwrap_or(0)
    }) {
        return;
    }

    let status = IntellaroServiceDiscoveryStatus {
        synced,
        last_synced_at: if synced { Some(now) } else { None },
        discovered_services: 0,
        discovered_endpoints: 0,
        registered_groups: 0,
        observed_generation: obj.metadata.generation.unwrap_or(0),
        conditions: vec![synced_condition(synced, message)],
    };

    let patch = serde_json::json!({ "status": status });
    if let Err(e) = api
        .patch_status(&name, &PatchParams::default(), &kube::api::Patch::Merge(&patch))
        .await
    {
        warn!(discovery = %name, error = %e, "Failed to update ServiceDiscovery status");
    }
}

async fn update_routing_policy_status(
    ctx: &ReconcilerContext,
    obj: &IntellaroRoutingPolicy,
    synced: bool,
    message: Option<String>,
) {
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<IntellaroRoutingPolicy> = Api::namespaced(ctx.kube_client.clone(), &ns);
    let name = obj.name_any();
    let now = chrono::Utc::now().to_rfc3339();

    // Skip no-op status writes: re-patching with a fresh timestamp bumps
    // resourceVersion and re-triggers our own watch — a reconcile hot loop.
    if obj.status.as_ref().is_some_and(|s| {
        s.synced == synced && s.observed_generation == obj.metadata.generation.unwrap_or(0)
    }) {
        return;
    }

    let status = IntellaroRoutingPolicyStatus {
        synced,
        last_synced_at: if synced { Some(now) } else { None },
        applied_targets: 0,
        observed_generation: obj.metadata.generation.unwrap_or(0),
        conditions: vec![synced_condition(synced, message)],
    };

    let patch = serde_json::json!({ "status": status });
    if let Err(e) = api
        .patch_status(&name, &PatchParams::default(), &kube::api::Patch::Merge(&patch))
        .await
    {
        warn!(policy = %name, error = %e, "Failed to update RoutingPolicy status");
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn namespaced_or_all<K>(client: Client, namespace: &Option<String>) -> Api<K>
where
    K: kube::Resource<DynamicType = (), Scope = k8s_openapi::NamespaceResourceScope>,
    <K as kube::Resource>::DynamicType: Default,
{
    match namespace {
        Some(ns) => Api::namespaced(client, ns),
        None => Api::all(client),
    }
}
