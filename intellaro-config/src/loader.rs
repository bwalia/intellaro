//! Multi-document loader for `intellaro.io/v1` YAML/JSON files.
//!
//! A config file is one or more documents separated by `---` (YAML) or a
//! top-level JSON/YAML array. Each document is dispatched on its `kind`.

use serde::Deserialize;
use serde_yaml::Value;

use crate::types::{Gateway, Upstream, WafPolicy};
use crate::{ConfigV1Error, API_VERSION};

/// A parsed set of `intellaro.io/v1` objects.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConfigSet {
    pub gateways: Vec<Gateway>,
    pub upstreams: Vec<Upstream>,
    pub waf_policies: Vec<WafPolicy>,
}

impl ConfigSet {
    pub fn is_empty(&self) -> bool {
        self.gateways.is_empty() && self.upstreams.is_empty() && self.waf_policies.is_empty()
    }
}

/// Cheap sniff: does this file look like an `intellaro.io/v1` config?
///
/// Used to decide between the v1 loader and the legacy flat config format
/// without fully parsing the file twice.
pub fn is_v1_config(content: &str) -> bool {
    content.lines().any(|line| {
        let line = line.trim();
        line.starts_with("apiVersion") && line.contains(API_VERSION)
    }) || content.contains(&format!("\"apiVersion\": \"{API_VERSION}\""))
        || content.contains(&format!("\"apiVersion\":\"{API_VERSION}\""))
}

/// Parse a multi-document YAML (or JSON) string into a [`ConfigSet`].
///
/// This only parses and shape-checks; call [`crate::validate`] afterwards
/// for cross-object semantic validation.
pub fn load_str(content: &str) -> Result<ConfigSet, ConfigV1Error> {
    let mut documents: Vec<Value> = Vec::new();

    for de in serde_yaml::Deserializer::from_str(content) {
        let value = Value::deserialize(de).map_err(|err| ConfigV1Error::Parse {
            index: documents.len(),
            message: err.to_string(),
        })?;

        match value {
            Value::Null => continue,
            // A top-level array (e.g. a JSON list of objects) is flattened.
            Value::Sequence(items) => documents.extend(items),
            other => documents.push(other),
        }
    }

    let mut set = ConfigSet::default();

    for (index, doc) in documents.into_iter().enumerate() {
        let api_version = doc
            .get("apiVersion")
            .and_then(Value::as_str)
            .ok_or(ConfigV1Error::MissingField {
                index,
                field: "apiVersion",
            })?
            .to_string();

        if api_version != API_VERSION {
            return Err(ConfigV1Error::UnsupportedApiVersion {
                index,
                found: api_version,
                expected: API_VERSION,
            });
        }

        let kind = doc
            .get("kind")
            .and_then(Value::as_str)
            .ok_or(ConfigV1Error::MissingField {
                index,
                field: "kind",
            })?
            .to_string();

        let parse_err = |err: serde_yaml::Error| ConfigV1Error::Parse {
            index,
            message: err.to_string(),
        };

        match kind.as_str() {
            "Gateway" => set
                .gateways
                .push(serde_yaml::from_value(doc).map_err(parse_err)?),
            "Upstream" => set
                .upstreams
                .push(serde_yaml::from_value(doc).map_err(parse_err)?),
            "WafPolicy" => set
                .waf_policies
                .push(serde_yaml::from_value(doc).map_err(parse_err)?),
            other => {
                return Err(ConfigV1Error::UnknownKind {
                    index,
                    kind: other.to_string(),
                })
            }
        }
    }

    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ListenerProtocol, PathMatchType};

    const SAMPLE: &str = r#"
apiVersion: intellaro.io/v1
kind: Gateway
metadata:
  name: pop1-edge
  labels:
    env: prod
spec:
  listeners:
    - name: http
      port: 8080
  hosts:
    - name: example.com
      routes:
        - match:
            path: { type: Prefix, value: /api }
          upstreamRef: api-pool
          timeouts:
            connect: 5s
            read: 30s
        - backends:
            - address: 127.0.0.1:9000
---
apiVersion: intellaro.io/v1
kind: Upstream
metadata:
  name: api-pool
spec:
  backends:
    - address: 10.0.0.1:8080
      weight: 2
    - address: 10.0.0.2:8080
  loadBalancing: least_conn
---
apiVersion: intellaro.io/v1
kind: WafPolicy
metadata:
  name: waf-strict
spec:
  mode: block
  ipDeny: ["203.0.113.0/24"]
  rateLimit:
    maxRequests: 100
    window: 1m
"#;

    #[test]
    fn parses_multi_document_yaml() {
        let set = load_str(SAMPLE).unwrap();
        assert_eq!(set.gateways.len(), 1);
        assert_eq!(set.upstreams.len(), 1);
        assert_eq!(set.waf_policies.len(), 1);

        let gw = &set.gateways[0];
        assert_eq!(gw.metadata.name, "pop1-edge");
        assert_eq!(gw.spec.listeners[0].port, 8080);
        assert_eq!(gw.spec.listeners[0].protocol, ListenerProtocol::Http);

        let routes = &gw.spec.hosts[0].routes;
        assert_eq!(routes[0].route_match.path.match_type, PathMatchType::Prefix);
        assert_eq!(routes[0].route_match.path.value, "/api");
        assert_eq!(routes[0].upstream_ref.as_deref(), Some("api-pool"));
        assert_eq!(routes[0].timeouts.as_ref().unwrap().read.unwrap().as_secs(), 30);
        // Second route uses the default match (Prefix /).
        assert_eq!(routes[1].route_match.path.value, "/");

        let up = &set.upstreams[0];
        assert_eq!(up.spec.backends[0].weight, 2);
        assert_eq!(up.spec.backends[1].weight, 1);

        let waf = &set.waf_policies[0];
        assert_eq!(waf.spec.rate_limit.as_ref().unwrap().max_requests, 100);
        assert_eq!(waf.spec.rate_limit.as_ref().unwrap().window.as_secs(), 60);
    }

    #[test]
    fn sniffs_v1_config() {
        assert!(is_v1_config(SAMPLE));
        assert!(is_v1_config("{\"apiVersion\": \"intellaro.io/v1\", \"kind\": \"Gateway\"}"));
        assert!(!is_v1_config("listeners:\n  - address: 0.0.0.0:8080\n"));
    }

    #[test]
    fn rejects_unknown_kind() {
        let err = load_str("apiVersion: intellaro.io/v1\nkind: Widget\nmetadata: {name: x}\n")
            .unwrap_err();
        assert!(matches!(err, ConfigV1Error::UnknownKind { .. }));
    }

    #[test]
    fn rejects_wrong_api_version() {
        let err = load_str("apiVersion: intellaro.io/v2\nkind: Gateway\n").unwrap_err();
        assert!(matches!(err, ConfigV1Error::UnsupportedApiVersion { .. }));
    }

    #[test]
    fn rejects_unknown_fields() {
        let doc = r#"
apiVersion: intellaro.io/v1
kind: Gateway
metadata: { name: g }
spec:
  listeners: [{ name: http, port: 8080, bogus: true }]
  hosts: []
"#;
        let err = load_str(doc).unwrap_err();
        match err {
            ConfigV1Error::Parse { message, .. } => assert!(message.contains("bogus")),
            other => panic!("expected parse error, got {other:?}"),
        }
    }

    #[test]
    fn parses_json_array_form() {
        let json = r#"[
          {"apiVersion":"intellaro.io/v1","kind":"Upstream",
           "metadata":{"name":"u1"},
           "spec":{"backends":[{"address":"127.0.0.1:1234"}]}}
        ]"#;
        let set = load_str(json).unwrap();
        assert_eq!(set.upstreams.len(), 1);
        assert_eq!(set.upstreams[0].spec.backends[0].address, "127.0.0.1:1234");
    }
}
