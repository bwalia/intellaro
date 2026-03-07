//! Service mesh auto-discovery engine.
//!
//! Watches Kubernetes Services and Endpoints/EndpointSlices to
//! automatically discover backend services. Maintains a live service
//! map that the reconciler uses to populate backend groups in the
//! MCP configuration.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use k8s_openapi::api::core::v1::{Endpoints, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::api::ListParams;
use kube::{Api, Client, ResourceExt};
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::crd::service_discovery::{
    DiscoveryMode, IntellaroServiceDiscovery, PortDiscovery, ServiceFilter,
};
use crate::error::IngressResult;

/// A discovered service endpoint ready for backend registration.
#[derive(Debug, Clone)]
pub struct DiscoveredEndpoint {
    /// IP address or hostname.
    pub address: String,
    /// Port number.
    pub port: u16,
    /// Port name (from the Service spec).
    pub port_name: Option<String>,
    /// Whether this endpoint is currently ready.
    pub ready: bool,
}

/// A discovered service with all its resolved endpoints.
#[derive(Debug, Clone)]
pub struct DiscoveredService {
    /// Service name.
    pub name: String,
    /// Service namespace.
    pub namespace: String,
    /// Service labels.
    pub labels: BTreeMap<String, String>,
    /// Service annotations.
    pub annotations: BTreeMap<String, String>,
    /// Cluster IP (if any).
    pub cluster_ip: Option<String>,
    /// Resolved healthy endpoints.
    pub endpoints: Vec<DiscoveredEndpoint>,
    /// Backend group name (rendered from template).
    pub group_name: String,
}

/// Snapshot of all discovered services across all discovery configs.
#[derive(Debug, Clone, Default)]
pub struct ServiceMap {
    /// All discovered services, keyed by group name.
    pub services: HashMap<String, DiscoveredService>,
    /// Total services discovered.
    pub total_services: u32,
    /// Total healthy endpoints discovered.
    pub total_endpoints: u32,
}

/// The service discovery engine that maintains the live service map.
pub struct DiscoveryEngine {
    kube_client: Client,
    /// Current service map, updated on each discovery pass.
    service_map: Arc<RwLock<ServiceMap>>,
}

impl DiscoveryEngine {
    pub fn new(kube_client: Client) -> Self {
        Self {
            kube_client,
            service_map: Arc::new(RwLock::new(ServiceMap::default())),
        }
    }

    /// Run a full discovery pass for all IntellaroServiceDiscovery CRDs.
    pub async fn discover_all(
        &self,
        discovery_configs: &[Arc<IntellaroServiceDiscovery>],
    ) -> IngressResult<ServiceMap> {
        let mut merged_map = ServiceMap::default();

        for config in discovery_configs {
            let spec = &config.spec;
            let config_name = config.name_any();
            let config_ns = config.namespace().unwrap_or_default();

            debug!(config = %config_name, "Running service discovery pass");

            // Determine which namespaces to scan.
            let namespaces = self.resolve_namespaces(spec, &config_ns).await?;

            for ns in &namespaces {
                let services = self.discover_in_namespace(ns, spec).await?;

                for svc in services {
                    let group_name = render_group_name(
                        &spec.group_name_template,
                        &svc.namespace,
                        &svc.name,
                    );

                    // Apply include/exclude filters.
                    if !passes_filters(&svc, &spec.include_services, &spec.exclude_services) {
                        debug!(
                            service = %svc.name,
                            namespace = %svc.namespace,
                            "Service excluded by filter"
                        );
                        continue;
                    }

                    let endpoint_count = svc.endpoints.iter().filter(|e| e.ready).count() as u32;

                    let discovered = DiscoveredService {
                        name: svc.name.clone(),
                        namespace: svc.namespace.clone(),
                        labels: svc.labels.clone(),
                        annotations: svc.annotations.clone(),
                        cluster_ip: svc.cluster_ip.clone(),
                        endpoints: svc.endpoints,
                        group_name: group_name.clone(),
                    };

                    merged_map.total_services += 1;
                    merged_map.total_endpoints += endpoint_count;
                    merged_map.services.insert(group_name, discovered);
                }
            }

            info!(
                config = %config_name,
                services = merged_map.total_services,
                endpoints = merged_map.total_endpoints,
                "Discovery pass complete"
            );
        }

        // Update the stored map.
        {
            let mut map = self.service_map.write().await;
            *map = merged_map.clone();
        }

        Ok(merged_map)
    }

    /// Get a snapshot of the current service map.
    pub async fn current_map(&self) -> ServiceMap {
        self.service_map.read().await.clone()
    }

    /// Resolve which namespaces to scan based on the discovery spec.
    async fn resolve_namespaces(
        &self,
        spec: &crate::crd::service_discovery::IntellaroServiceDiscoverySpec,
        default_ns: &str,
    ) -> IngressResult<Vec<String>> {
        if spec.cluster_wide {
            // List all namespaces.
            let ns_api: Api<k8s_openapi::api::core::v1::Namespace> =
                Api::all(self.kube_client.clone());
            let ns_list = ns_api.list(&ListParams::default()).await?;
            Ok(ns_list
                .items
                .into_iter()
                .filter_map(|ns| ns.metadata.name)
                .collect())
        } else if spec.namespaces.is_empty() {
            Ok(vec![default_ns.to_string()])
        } else {
            Ok(spec.namespaces.clone())
        }
    }

    /// Discover services in a single namespace.
    async fn discover_in_namespace(
        &self,
        namespace: &str,
        spec: &crate::crd::service_discovery::IntellaroServiceDiscoverySpec,
    ) -> IngressResult<Vec<DiscoveredService>> {
        let svc_api: Api<Service> = Api::namespaced(self.kube_client.clone(), namespace);

        // Build label selector for the list call.
        let list_params = if let Some(ref selector) = spec.label_selector {
            ListParams::default().labels(selector)
        } else {
            ListParams::default()
        };

        let svc_list = svc_api.list(&list_params).await?;
        let mut discovered = Vec::new();

        for svc in svc_list.items {
            let svc_name = svc.metadata.name.clone().unwrap_or_default();
            let svc_ns = svc.metadata.namespace.clone().unwrap_or_default();

            // Check annotation selector if configured.
            if let Some(ref anno_selector) = spec.annotation_selector {
                if !matches_annotation_selector(&svc, anno_selector) {
                    continue;
                }
            }

            let labels = svc.metadata.labels.clone().unwrap_or_default();
            let annotations = svc.metadata.annotations.clone().unwrap_or_default();

            let cluster_ip = svc
                .spec
                .as_ref()
                .and_then(|s| s.cluster_ip.clone())
                .filter(|ip| ip != "None");

            // Resolve endpoints based on discovery mode.
            let endpoints = match spec.mode {
                DiscoveryMode::Kubernetes => {
                    self.resolve_endpoints_v1(namespace, &svc_name, &spec.port_discovery)
                        .await?
                }
                DiscoveryMode::EndpointSlice => {
                    self.resolve_endpoint_slices(namespace, &svc_name, &spec.port_discovery)
                        .await?
                }
                DiscoveryMode::Dns => {
                    // For DNS mode, use the ClusterIP or service DNS name.
                    self.resolve_dns_endpoints(&svc, namespace, &spec.port_discovery)
                }
            };

            let group_name = render_group_name(
                &spec.group_name_template,
                &svc_ns,
                &svc_name,
            );

            discovered.push(DiscoveredService {
                name: svc_name,
                namespace: svc_ns,
                labels,
                annotations,
                cluster_ip,
                endpoints,
                group_name,
            });
        }

        Ok(discovered)
    }

    /// Resolve endpoints using Endpoints v1 API.
    async fn resolve_endpoints_v1(
        &self,
        namespace: &str,
        service_name: &str,
        port_discovery: &PortDiscovery,
    ) -> IngressResult<Vec<DiscoveredEndpoint>> {
        let ep_api: Api<Endpoints> = Api::namespaced(self.kube_client.clone(), namespace);

        let endpoints = match ep_api.get_opt(service_name).await? {
            Some(ep) => ep,
            None => return Ok(Vec::new()),
        };

        let mut result = Vec::new();

        if let Some(subsets) = endpoints.subsets {
            for subset in &subsets {
                // Determine which ports to use.
                let ports = match &subset.ports {
                    Some(ports) => filter_ports(ports, port_discovery),
                    None => Vec::new(),
                };

                // Ready addresses.
                if let Some(ref addresses) = subset.addresses {
                    for addr in addresses {
                        for (port_num, port_name) in &ports {
                            result.push(DiscoveredEndpoint {
                                address: addr.ip.clone(),
                                port: *port_num,
                                port_name: port_name.clone(),
                                ready: true,
                            });
                        }
                    }
                }

                // Not-ready addresses (tracked but marked unready).
                if let Some(ref addresses) = subset.not_ready_addresses {
                    for addr in addresses {
                        for (port_num, port_name) in &ports {
                            result.push(DiscoveredEndpoint {
                                address: addr.ip.clone(),
                                port: *port_num,
                                port_name: port_name.clone(),
                                ready: false,
                            });
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    /// Resolve endpoints using EndpointSlice API (preferred for large clusters).
    async fn resolve_endpoint_slices(
        &self,
        namespace: &str,
        service_name: &str,
        port_discovery: &PortDiscovery,
    ) -> IngressResult<Vec<DiscoveredEndpoint>> {
        let slice_api: Api<EndpointSlice> = Api::namespaced(self.kube_client.clone(), namespace);

        // EndpointSlices are labeled with kubernetes.io/service-name.
        let params = ListParams::default().labels(&format!(
            "kubernetes.io/service-name={}",
            service_name
        ));

        let slices = slice_api.list(&params).await?;
        let mut result = Vec::new();

        for slice in slices.items {
            // Determine which ports from this slice match.
            let ports: Vec<(u16, Option<String>)> = slice
                .ports
                .as_ref()
                .map(|ports| {
                    ports
                        .iter()
                        .filter(|p| {
                            let port_num = p.port.unwrap_or(0) as u16;
                            let port_name = p.name.clone();
                            should_include_port(port_num, port_name.as_deref(), port_discovery)
                        })
                        .map(|p| (p.port.unwrap_or(0) as u16, p.name.clone()))
                        .collect()
                })
                .unwrap_or_default();

            for ep in &slice.endpoints {
                let ready = ep
                    .conditions
                    .as_ref()
                    .and_then(|c| c.ready)
                    .unwrap_or(true);

                for addr in &ep.addresses {
                    for (port_num, port_name) in &ports {
                        result.push(DiscoveredEndpoint {
                            address: addr.clone(),
                            port: *port_num,
                            port_name: port_name.clone(),
                            ready,
                        });
                    }
                }
            }
        }

        Ok(result)
    }

    /// Resolve endpoints using DNS (uses ClusterIP + service ports).
    fn resolve_dns_endpoints(
        &self,
        svc: &Service,
        namespace: &str,
        port_discovery: &PortDiscovery,
    ) -> Vec<DiscoveredEndpoint> {
        let svc_name = svc.metadata.name.clone().unwrap_or_default();
        let dns_name = format!("{}.{}.svc.cluster.local", svc_name, namespace);

        let mut result = Vec::new();

        if let Some(ref spec) = svc.spec {
            if let Some(ref ports) = spec.ports {
                for port in ports {
                    let port_num = port.port as u16;
                    let port_name = port.name.clone();

                    if !should_include_port(port_num, port_name.as_deref(), port_discovery) {
                        continue;
                    }

                    result.push(DiscoveredEndpoint {
                        address: dns_name.clone(),
                        port: port_num,
                        port_name,
                        ready: true, // DNS resolution assumes reachability.
                    });
                }
            }
        }

        result
    }
}

// ── Helper functions ────────────────────────────────────────────────

/// Render a backend group name from a template.
fn render_group_name(template: &str, namespace: &str, name: &str) -> String {
    template
        .replace("{namespace}", namespace)
        .replace("{name}", name)
}

/// Filter ports from an Endpoints subset based on the port discovery strategy.
fn filter_ports(
    ports: &[k8s_openapi::api::core::v1::EndpointPort],
    port_discovery: &PortDiscovery,
) -> Vec<(u16, Option<String>)> {
    let all: Vec<(u16, Option<String>)> = ports
        .iter()
        .map(|p| (p.port as u16, p.name.clone()))
        .collect();

    match port_discovery {
        PortDiscovery::AllNamed => all,
        PortDiscovery::ByName(names) => all
            .into_iter()
            .filter(|(_, name)| name.as_ref().map(|n| names.contains(n)).unwrap_or(false))
            .collect(),
        PortDiscovery::ByNumber(numbers) => all
            .into_iter()
            .filter(|(port, _)| numbers.contains(port))
            .collect(),
        PortDiscovery::FirstAvailable => all.into_iter().take(1).collect(),
    }
}

/// Check if a port should be included based on the port discovery strategy.
fn should_include_port(port: u16, name: Option<&str>, discovery: &PortDiscovery) -> bool {
    match discovery {
        PortDiscovery::AllNamed => true,
        PortDiscovery::ByName(names) => {
            name.map(|n| names.iter().any(|allowed| allowed == n))
                .unwrap_or(false)
        }
        PortDiscovery::ByNumber(numbers) => numbers.contains(&port),
        PortDiscovery::FirstAvailable => true, // Caller handles limiting.
    }
}

/// Check if a service passes the include/exclude filter rules.
fn passes_filters(
    svc: &DiscoveredService,
    include: &[ServiceFilter],
    exclude: &[ServiceFilter],
) -> bool {
    // Check exclusions first.
    for filter in exclude {
        if matches_service_filter(svc, filter) {
            return false;
        }
    }

    // If include list is empty, include everything not excluded.
    if include.is_empty() {
        return true;
    }

    // Must match at least one include filter.
    include.iter().any(|filter| matches_service_filter(svc, filter))
}

/// Check if a service matches a single filter.
fn matches_service_filter(svc: &DiscoveredService, filter: &ServiceFilter) -> bool {
    // Name pattern match (simple glob: * prefix/suffix).
    if let Some(ref pattern) = filter.name_pattern {
        if !glob_match(pattern, &svc.name) {
            return false;
        }
    }

    // Namespace pattern match.
    if let Some(ref pattern) = filter.namespace_pattern {
        if !glob_match(pattern, &svc.namespace) {
            return false;
        }
    }

    // Label selector (simple key=value matching).
    if let Some(ref selector) = filter.label_selector {
        if !matches_label_selector(&svc.labels, selector) {
            return false;
        }
    }

    true
}

/// Simple glob matching: supports `*` prefix, `*` suffix, or exact match.
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return value.ends_with(suffix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    pattern == value
}

/// Simple label selector matching (supports comma-separated key=value pairs).
fn matches_label_selector(labels: &BTreeMap<String, String>, selector: &str) -> bool {
    for constraint in selector.split(',') {
        let constraint = constraint.trim();
        if let Some((key, value)) = constraint.split_once('=') {
            match labels.get(key.trim()) {
                Some(v) if v == value.trim() => {}
                _ => return false,
            }
        }
    }
    true
}

/// Check if a Service matches an annotation selector (key=value format).
fn matches_annotation_selector(svc: &Service, selector: &str) -> bool {
    let annotations = svc.metadata.annotations.as_ref();
    for constraint in selector.split(',') {
        let constraint = constraint.trim();
        if let Some((key, value)) = constraint.split_once('=') {
            match annotations.and_then(|a| a.get(key.trim())) {
                Some(v) if v == value.trim() => {}
                _ => return false,
            }
        }
    }
    true
}
