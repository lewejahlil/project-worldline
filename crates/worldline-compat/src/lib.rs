use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use worldline_registry::RegistrySnapshot;

/// SDK-facing plugin representation with flattened fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatPlugin {
    pub id: String,
    pub version: String,
    pub backend: String,
}

/// SDK-facing registry with simplified ID lists for circuits and backends,
/// plus full plugin metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatRegistry {
    pub circuits: Vec<String>,
    pub backends: Vec<String>,
    pub plugins: Vec<CompatPlugin>,
}

/// Build a compatibility snapshot from an internal registry snapshot.
///
/// Extracts circuit and backend IDs into flat lists, and maps plugins
/// into the simplified [`CompatPlugin`] representation.
pub fn build_compat_snapshot(registry: &RegistrySnapshot) -> CompatRegistry {
    let circuits = registry.circuits.iter().map(|c| c.id.clone()).collect();
    let backends = registry.backends.iter().map(|b| b.id.clone()).collect();
    let plugins = registry
        .plugins
        .iter()
        .map(|p| CompatPlugin {
            id: p.id.clone(),
            version: p.version.clone(),
            backend: p.backend.clone(),
        })
        .collect();

    CompatRegistry {
        circuits,
        backends,
        plugins,
    }
}

/// Verify that a plugin with the given ID exists in the registry.
///
/// Returns `Ok(())` if found, or an error describing the missing plugin.
pub fn ensure_plugin_exists(registry: &RegistrySnapshot, plugin_id: &str) -> Result<()> {
    if registry.plugins.iter().any(|p| p.id == plugin_id) {
        Ok(())
    } else {
        bail!("plugin '{}' not found in registry", plugin_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use worldline_registry::{BackendMeta, CircuitMeta, PluginMeta, RegistrySnapshot};

    fn sample_registry() -> RegistrySnapshot {
        let mut snap = RegistrySnapshot::default();
        snap.register_circuit(CircuitMeta {
            id: "sum2".to_string(),
            version: "1.0.0".to_string(),
            public_inputs: vec!["a".to_string(), "b".to_string()],
        })
        .unwrap();
        snap.register_backend(BackendMeta {
            id: "groth16".to_string(),
            kind: "groth16".to_string(),
            versions: vec!["0.6.0".to_string()],
        })
        .unwrap();
        snap.register_plugin(PluginMeta {
            id: "sum2-groth16".to_string(),
            version: "1.0.0".to_string(),
            backend: "groth16".to_string(),
        })
        .unwrap();
        snap
    }

    #[test]
    fn build_compat_snapshot_extracts_ids() {
        let registry = sample_registry();
        let compat = build_compat_snapshot(&registry);

        assert_eq!(compat.circuits, vec!["sum2"]);
        assert_eq!(compat.backends, vec!["groth16"]);
        assert_eq!(compat.plugins.len(), 1);
        assert_eq!(compat.plugins[0].id, "sum2-groth16");
        assert_eq!(compat.plugins[0].version, "1.0.0");
        assert_eq!(compat.plugins[0].backend, "groth16");
    }

    #[test]
    fn compat_snapshot_roundtrip_json() {
        let registry = sample_registry();
        let compat = build_compat_snapshot(&registry);
        let json = serde_json::to_string(&compat).unwrap();
        let deserialized: CompatRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(compat, deserialized);
    }

    #[test]
    fn ensure_plugin_exists_found() {
        let registry = sample_registry();
        assert!(ensure_plugin_exists(&registry, "sum2-groth16").is_ok());
    }

    #[test]
    fn ensure_plugin_exists_not_found() {
        let registry = sample_registry();
        let err = ensure_plugin_exists(&registry, "missing-plugin").unwrap_err();
        assert!(err.to_string().contains("missing-plugin"));
    }
}
