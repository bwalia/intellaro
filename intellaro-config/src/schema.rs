//! JSON Schema generation for the `intellaro.io/v1` model.
//!
//! Schemas are derived from the same structs the parser uses, so the
//! published schema files can never drift from actual behavior. The CLI
//! exposes this as `intellaro schema --out-dir docs/schemas`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use schemars::schema::RootSchema;
use schemars::schema_for;

use crate::types::{Gateway, Route, Upstream, WafPolicy};

/// Every published schema, as `(file_stem, schema)` pairs.
pub fn all_schemas() -> Vec<(&'static str, RootSchema)> {
    vec![
        ("gateway", schema_for!(Gateway)),
        ("route", schema_for!(Route)),
        ("upstream", schema_for!(Upstream)),
        ("wafpolicy", schema_for!(WafPolicy)),
    ]
}

/// Write all schemas as pretty-printed JSON files into `dir`.
///
/// Returns the list of files written.
pub fn write_schemas(dir: &Path) -> io::Result<Vec<PathBuf>> {
    fs::create_dir_all(dir)?;
    let mut written = Vec::new();

    for (stem, schema) in all_schemas() {
        let path = dir.join(format!("{stem}.schema.json"));
        let json = serde_json::to_string_pretty(&schema)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        fs::write(&path, json + "\n")?;
        written.push(path);
    }

    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schemas_generate_and_mention_key_fields() {
        for (stem, schema) in all_schemas() {
            let json = serde_json::to_string(&schema).unwrap();
            assert!(!json.is_empty(), "{stem} schema is empty");
        }

        let gateway = serde_json::to_string(&schema_for!(Gateway)).unwrap();
        assert!(gateway.contains("listeners"));
        assert!(gateway.contains("upstreamRef"));

        let waf = serde_json::to_string(&schema_for!(WafPolicy)).unwrap();
        assert!(waf.contains("rulePacks"));
        assert!(waf.contains("rateLimit"));
    }
}
