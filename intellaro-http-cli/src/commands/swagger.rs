//! Swagger / OpenAPI management — fetch, generate, export, validate.

use clap::Subcommand;

use crate::client::McpClient;
use crate::error::{CliError, CliResult};
use crate::output::{self, OutputFormat};

/// Swagger / OpenAPI subcommands.
#[derive(Debug, Subcommand)]
pub enum SwaggerCmd {
    /// Fetch and display the current OpenAPI spec from the server.
    Show,

    /// Export the OpenAPI spec to a local file.
    Export {
        /// Output file path (defaults to "openapi.json").
        #[arg(short, long, default_value = "openapi.json")]
        output_file: String,

        /// Export as YAML instead of JSON.
        #[arg(long, default_value_t = false)]
        yaml: bool,
    },

    /// Validate the server's OpenAPI spec for completeness.
    Validate,

    /// Generate an enriched OpenAPI spec from the live server config.
    ///
    /// Builds a full OpenAPI 3.0.3 document that includes dynamic
    /// information like configured upstreams, security policies,
    /// and cache settings, beyond the static spec the server ships.
    Generate {
        /// Output file path.
        #[arg(short, long, default_value = "openapi-full.json")]
        output_file: String,

        /// Export as YAML instead of JSON.
        #[arg(long, default_value_t = false)]
        yaml: bool,
    },
}

/// Execute a swagger subcommand.
pub async fn execute(cmd: &SwaggerCmd, client: &McpClient, format: OutputFormat) -> CliResult<()> {
    match cmd {
        SwaggerCmd::Show => {
            let spec: serde_json::Value = client.openapi_spec().await?;
            output::render_value(&spec, format);
            Ok(())
        }

        SwaggerCmd::Export { output_file, yaml } => {
            let spec: serde_json::Value = client.openapi_spec().await?;

            let content = if *yaml {
                serde_yaml::to_string(&spec)
                    .map_err(|e| CliError::SerializationError(e.to_string()))?
            } else {
                serde_json::to_string_pretty(&spec)
                    .map_err(|e| CliError::SerializationError(e.to_string()))?
            };

            let path = if *yaml && !output_file.ends_with(".yaml") && !output_file.ends_with(".yml") {
                format!("{}.yaml", output_file.trim_end_matches(".json"))
            } else {
                output_file.clone()
            };

            std::fs::write(&path, &content)?;
            output::print_success(&format!("OpenAPI spec exported to {path}"));
            Ok(())
        }

        SwaggerCmd::Validate => {
            let spec: serde_json::Value = client.openapi_spec().await?;
            let mut issues: Vec<String> = Vec::new();

            // Basic structural validation.
            if spec.get("openapi").is_none() {
                issues.push("Missing 'openapi' version field".to_string());
            }

            if spec.get("info").is_none() {
                issues.push("Missing 'info' section".to_string());
            } else {
                if spec["info"].get("title").is_none() {
                    issues.push("Missing 'info.title'".to_string());
                }
                if spec["info"].get("version").is_none() {
                    issues.push("Missing 'info.version'".to_string());
                }
            }

            if spec.get("paths").is_none() {
                issues.push("Missing 'paths' section".to_string());
            } else if let Some(paths) = spec["paths"].as_object() {
                for (path, methods) in paths {
                    if let Some(methods_obj) = methods.as_object() {
                        for (method, operation) in methods_obj {
                            if operation.get("summary").is_none() && operation.get("description").is_none() {
                                issues.push(format!(
                                    "{} {} — missing summary/description",
                                    method.to_uppercase(),
                                    path
                                ));
                            }
                            if operation.get("responses").is_none() {
                                issues.push(format!(
                                    "{} {} — missing responses",
                                    method.to_uppercase(),
                                    path
                                ));
                            }
                        }
                    }
                }
            }

            if issues.is_empty() {
                output::print_success("OpenAPI spec validation passed — no issues found");
            } else {
                output::print_warn(&format!("Found {} issue(s):", issues.len()));
                let rows: Vec<Vec<String>> = issues
                    .iter()
                    .enumerate()
                    .map(|(i, issue)| vec![(i + 1).to_string(), issue.clone()])
                    .collect();
                output::render_table(&["#", "Issue"], &rows);
            }
            Ok(())
        }

        SwaggerCmd::Generate { output_file, yaml } => {
            // Fetch both the static spec and the live config.
            let base_spec: serde_json::Value = client.openapi_spec().await?;
            let config: serde_json::Value = client.get_config().await?;

            let full_spec = enrich_openapi_spec(&base_spec, &config);

            let content = if *yaml {
                serde_yaml::to_string(&full_spec)
                    .map_err(|e| CliError::SerializationError(e.to_string()))?
            } else {
                serde_json::to_string_pretty(&full_spec)
                    .map_err(|e| CliError::SerializationError(e.to_string()))?
            };

            let path = if *yaml && !output_file.ends_with(".yaml") && !output_file.ends_with(".yml") {
                format!("{}.yaml", output_file.trim_end_matches(".json"))
            } else {
                output_file.clone()
            };

            std::fs::write(&path, &content)?;
            output::print_success(&format!("Enriched OpenAPI spec generated at {path}"));
            Ok(())
        }
    }
}

/// Build an enriched OpenAPI spec that includes live configuration details.
fn enrich_openapi_spec(
    base: &serde_json::Value,
    config: &serde_json::Value,
) -> serde_json::Value {
    let mut spec = base.clone();

    // Add server entries from listeners.
    if let Some(listeners) = config.get("listeners").and_then(|v| v.as_array()) {
        let servers: Vec<serde_json::Value> = listeners
            .iter()
            .map(|l| {
                let addr = l.get("address").and_then(|v| v.as_str()).unwrap_or("0.0.0.0:8080");
                let tls = l.get("tls").is_some();
                let scheme = if tls { "https" } else { "http" };
                serde_json::json!({
                    "url": format!("{scheme}://{addr}"),
                    "description": format!("Listener on {addr}{}", if tls { " (TLS)" } else { "" })
                })
            })
            .collect();
        spec["servers"] = serde_json::Value::Array(servers);
    }

    // Add security scheme if JWT or API key auth is configured.
    let mut security_schemes = serde_json::Map::new();

    if config.get("security").and_then(|s| s.get("jwt")).is_some() {
        security_schemes.insert(
            "bearerAuth".to_string(),
            serde_json::json!({
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            }),
        );
    }

    if config.get("management_api").and_then(|m| m.get("api_key")).is_some() {
        security_schemes.insert(
            "apiKeyAuth".to_string(),
            serde_json::json!({
                "type": "apiKey",
                "in": "header",
                "name": "x-api-key"
            }),
        );
    }

    if !security_schemes.is_empty() {
        spec["components"] = serde_json::json!({
            "securitySchemes": serde_json::Value::Object(security_schemes)
        });
    }

    // Add upstream names as tags.
    if let Some(upstreams) = config.get("upstreams").and_then(|v| v.as_array()) {
        let tags: Vec<serde_json::Value> = upstreams
            .iter()
            .filter_map(|u| {
                u.get("name").and_then(|n| n.as_str()).map(|name| {
                    let server_count = u
                        .get("servers")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    serde_json::json!({
                        "name": format!("upstream:{name}"),
                        "description": format!("Upstream '{}' with {} backend(s)", name, server_count)
                    })
                })
            })
            .collect();

        if let Some(existing_tags) = spec.get_mut("tags").and_then(|t| t.as_array_mut()) {
            existing_tags.extend(tags);
        } else {
            spec["tags"] = serde_json::Value::Array(tags);
        }
    }

    // Enrich info with cache status.
    if let Some(info) = spec.get_mut("info") {
        let cache_enabled = config
            .get("cache")
            .and_then(|c| c.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let description = info
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        info["description"] = serde_json::Value::String(format!(
            "{description}\n\nCache: {}\nGenerated by intellaro-http-cli",
            if cache_enabled { "enabled" } else { "disabled" }
        ));
    }

    spec
}
