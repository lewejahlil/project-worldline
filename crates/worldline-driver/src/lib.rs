use std::path::Path;

use anyhow::{Context, Result};
use worldline_compat::{build_compat_snapshot, ensure_plugin_exists};
use worldline_registry::{self as registry};

/// Fetch a registry snapshot from a remote URL and save it locally.
pub async fn sync_registry(url: &str, output: &Path) -> Result<()> {
    let body = reqwest::get(url)
        .await
        .context("failed to fetch registry")?
        .text()
        .await
        .context("failed to read response body")?;

    let snapshot: registry::RegistrySnapshot =
        serde_json::from_str(&body).context("failed to parse remote registry JSON")?;

    registry::save(output, &snapshot).context("failed to save registry snapshot")?;

    Ok(())
}

/// Load a registry snapshot and export it as a JSON compat snapshot.
pub fn export_compat(input: &Path) -> Result<String> {
    let snapshot = registry::load(input).context("failed to load registry")?;
    let compat = build_compat_snapshot(&snapshot);
    serde_json::to_string_pretty(&compat).context("failed to serialize compat snapshot")
}

/// Verify that a plugin exists in a local registry snapshot.
pub fn check_plugin(input: &Path, plugin_id: &str) -> Result<()> {
    let snapshot = registry::load(input).context("failed to load registry")?;
    ensure_plugin_exists(&snapshot, plugin_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use worldline_registry::{BackendMeta, CircuitMeta, PluginMeta, RegistrySnapshot};

    fn write_sample_registry(path: &Path) {
        let mut snap = RegistrySnapshot::default();
        snap.register_circuit(CircuitMeta {
            id: "c1".to_string(),
            version: "1.0.0".to_string(),
            public_inputs: vec![],
        })
        .unwrap();
        snap.register_backend(BackendMeta {
            id: "b1".to_string(),
            kind: "groth16".to_string(),
            versions: vec![],
        })
        .unwrap();
        snap.register_plugin(PluginMeta {
            id: "p1".to_string(),
            version: "1.0.0".to_string(),
            backend: "b1".to_string(),
        })
        .unwrap();
        registry::save(path, &snap).unwrap();
    }

    #[test]
    fn export_compat_produces_valid_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        write_sample_registry(&path);

        let json = export_compat(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["circuits"][0], "c1");
        assert_eq!(parsed["backends"][0], "b1");
        assert_eq!(parsed["plugins"][0]["id"], "p1");
    }

    #[test]
    fn check_plugin_found() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        write_sample_registry(&path);

        assert!(check_plugin(&path, "p1").is_ok());
    }

    #[test]
    fn check_plugin_not_found() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        write_sample_registry(&path);

        assert!(check_plugin(&path, "missing").is_err());
    }
}
