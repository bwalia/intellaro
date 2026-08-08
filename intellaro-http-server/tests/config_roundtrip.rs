//! Round-trip guard: the JSON the ingress reconciler pushes to
//! `PUT /api/v1/config` must deserialize into `ServerConfig`.
//!
//! Mirrors the exact shapes `intellaro-ingress::reconciler::build_routing`
//! emits (including explicit nulls and unknown forward-compat keys).

use intellaro_http_server::config::ServerConfig;
use serde_json::json;

#[test]
fn reconciler_shaped_config_deserializes() {
    let pushed = json!({
        "listeners": [
            { "address": "0.0.0.0:8080", "tls": null, "protocol": "auto" }
        ],
        "worker_count": 4,
        "upstreams": [
            {
                "name": "intellaro-demo-echo-a-80",
                "servers": [
                    { "address": "echo-a.intellaro-demo.svc.cluster.local:80", "weight": 1 }
                ],
                "load_balancing": "round_robin",
                "health_check": {
                    "path": "/",
                    "interval_secs": 10,
                    "unhealthy_threshold": 3
                }
            },
            {
                "name": "route-intellaro-demo-demo-split-split",
                "servers": [
                    { "address": "echo-a.intellaro-demo.svc.cluster.local:80", "weight": 50 },
                    { "address": "echo-b.intellaro-demo.svc.cluster.local:80", "weight": 50 }
                ],
                "load_balancing": "weighted",
                "health_check": null
            }
        ],
        "cache": {},
        "security": {
            "ip_allow": [],
            "ip_block": ["203.0.113.0/24"],
            "rate_limit": { "max_requests": 10000, "window_secs": 60 },
            "jwt": null
        },
        "logging": {
            "level": "info",
            "format": "json",
            "metrics_path": "/metrics",
            "ops_address": "0.0.0.0:9090"
        },
        "cluster": null,
        "management_api": { "address": "0.0.0.0:9091", "api_key": null },
        "static_roots": [],
        "router": {
            "rules": [
                {
                    "name": "demo.intellaro.local/demo-root",
                    "priority": 100,
                    "match": {
                        "host": "demo.intellaro.local",
                        "path_prefix": "/",
                        "path_exact": null,
                        "path_regex": null,
                        "methods": [],
                        "headers": {}
                    },
                    "backend_group": "intellaro-demo-echo-a-80",
                    "timeout_secs": 30,
                    "enabled": true
                },
                {
                    "name": "demo.intellaro.local/demo-split",
                    "priority": 200,
                    "match": {
                        "host": "demo.intellaro.local",
                        "path_prefix": "/split",
                        "path_exact": null,
                        "path_regex": null,
                        "methods": [],
                        "headers": {}
                    },
                    "backend_group": "route-intellaro-demo-demo-split-split",
                    "timeout_secs": null,
                    "enabled": true
                }
            ]
        },
        "tenants": [],
        // Forward-compat keys the reconciler may attach; must be ignored.
        "routing_policies": { "traffic_splits": [] },
        "service_discovery": { "enabled": true }
    });

    let config: ServerConfig =
        serde_json::from_value(pushed).expect("reconciler-shaped config must deserialize");

    assert_eq!(config.upstreams.len(), 2);
    assert_eq!(config.upstreams[0].load_balancing, "round_robin");
    assert_eq!(config.upstreams[1].servers[1].weight, 50);
    assert_eq!(
        config.upstreams[0].health_check.as_ref().unwrap().unhealthy_threshold,
        3
    );

    let router = config.router.as_ref().expect("router section present");
    assert_eq!(router.rules.len(), 2);
    assert_eq!(router.rules[0].backend_group, "intellaro-demo-echo-a-80");
    assert_eq!(router.rules[0].timeout_secs, Some(30));
    assert_eq!(
        router.rules[1].r#match.path_prefix.as_deref(),
        Some("/split")
    );

    assert_eq!(config.security.ip_block, vec!["203.0.113.0/24"]);
    assert_eq!(
        config.security.rate_limit.as_ref().unwrap().max_requests,
        10000
    );

    // Re-serialize → re-parse: the GET → mutate → PUT cycle must be stable.
    let round = serde_json::to_value(&config).unwrap();
    let again: ServerConfig = serde_json::from_value(round).unwrap();
    assert_eq!(again.upstreams.len(), 2);
    assert_eq!(again.router.unwrap().rules.len(), 2);
}
