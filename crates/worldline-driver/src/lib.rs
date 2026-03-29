//! Worldline driver — CLI orchestrator for aggregation, recursion, and blob encoding.
//!
//! Library modules use `thiserror`-derived typed errors. The binary entrypoint
//! (`main.rs`) uses `anyhow` for ergonomic error context chaining at the boundary.

pub mod aggregator;
pub mod blob;
pub mod error;
pub mod recursion;

use std::path::Path;

use tracing::info;
use worldline_compat::{build_compat_snapshot, ensure_plugin_exists};
use worldline_registry::{self as registry};

use error::{RegistryError, SyncError};

/// Maximum allowed response size for registry sync (2 MiB).
const MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;

/// Fetch a registry snapshot from a remote URL and save it locally.
///
/// Enforces a response size limit to prevent resource exhaustion from
/// unexpectedly large payloads.
pub async fn sync_registry(url: &str, output: &Path) -> Result<(), SyncError> {
    info!(url = %url, "fetching remote registry");

    let response = reqwest::get(url).await?;

    // Check content-length before reading body
    if let Some(len) = response.content_length() {
        if len > MAX_RESPONSE_BYTES {
            return Err(SyncError::TooLarge {
                size: len,
                max: MAX_RESPONSE_BYTES,
            });
        }
    }

    let bytes = response.bytes().await?;

    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(SyncError::TooLarge {
            size: bytes.len() as u64,
            max: MAX_RESPONSE_BYTES,
        });
    }

    let body = std::str::from_utf8(&bytes)
        .map_err(|e| SyncError::InvalidUtf8(e.to_string()))?;

    let snapshot: registry::RegistrySnapshot =
        serde_json::from_str(body).map_err(|e| SyncError::ParseJson(e.to_string()))?;

    info!(
        circuits = snapshot.circuits.len(),
        plugins = snapshot.plugins.len(),
        backends = snapshot.backends.len(),
        "parsed registry snapshot"
    );

    registry::save(output, &snapshot)
        .map_err(|e| SyncError::Save(e.to_string()))?;
    info!(
        output = %output.display(),
        bytes = bytes.len(),
        "registry sync complete"
    );

    Ok(())
}

/// Load a registry snapshot and export it as a JSON compat snapshot.
pub fn export_compat(input: &Path) -> Result<String, RegistryError> {
    info!(input = %input.display(), "exporting compat snapshot");
    let snapshot =
        registry::load(input).map_err(|e| RegistryError::Load(e.to_string()))?;
    let compat = build_compat_snapshot(&snapshot);
    let json = serde_json::to_string_pretty(&compat)
        .map_err(|e| RegistryError::Serialize(e.to_string()))?;
    info!(
        circuits = snapshot.circuits.len(),
        plugins = snapshot.plugins.len(),
        "compat export complete"
    );
    Ok(json)
}

/// Verify that a plugin exists in a local registry snapshot.
pub fn check_plugin(input: &Path, plugin_id: &str) -> Result<(), RegistryError> {
    info!(input = %input.display(), plugin_id = %plugin_id, "checking plugin existence");
    let snapshot =
        registry::load(input).map_err(|e| RegistryError::Load(e.to_string()))?;
    ensure_plugin_exists(&snapshot, plugin_id)
        .map_err(|e| RegistryError::PluginNotFound(e.to_string()))?;
    Ok(())
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
