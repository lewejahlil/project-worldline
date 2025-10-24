use anyhow::Result;
use serde::{Deserialize, Serialize};
use worldline_registry::{RegistryError, RegistrySnapshot};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatPlugin {
    pub id: String,
    pub version: String,
    pub implementation: String,
    pub circuit_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatRegistry {
    pub circuits: Vec<String>,
    pub drivers: Vec<String>,
    pub plugins: Vec<CompatPlugin>,
}

pub fn build_compat_snapshot(registry: &RegistrySnapshot) -> Result<CompatRegistry> {
    let circuits = registry.circuits.keys().cloned().collect();
    let drivers = registry.drivers.keys().cloned().collect();
    let plugins = registry
        .plugins
        .values()
        .map(|plugin| CompatPlugin {
            id: plugin.id.clone(),
            version: plugin.version.clone(),
            implementation: plugin.implementation.clone(),
            circuit_id: plugin.circuit_id.clone(),
        })
        .collect();

    Ok(CompatRegistry {
        circuits,
        drivers,
        plugins,
    })
}

pub fn ensure_plugin_exists(registry: &RegistrySnapshot, plugin_id: &str) -> Result<()> {
    if registry.plugins.contains_key(plugin_id) {
        Ok(())
    } else {
        Err(RegistryError::MissingEntity(plugin_id.to_string()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use worldline_registry::{Circuit, Driver, Plugin};

    #[test]
    fn compat_snapshot_tracks_ids() {
        let mut snapshot = RegistrySnapshot::default();
        snapshot
            .register_circuit(Circuit {
                id: "0x01".into(),
                description: "Square".into(),
                verifier: "0xdead".into(),
                abi_uri: "https://example.com/abi.json".parse().unwrap(),
            })
            .unwrap();
        snapshot
            .register_driver(Driver {
                id: "0x02".into(),
                version: "1.0.0".into(),
                endpoint: "https://example.com".parse().unwrap(),
            })
            .unwrap();
        snapshot
            .register_plugin(Plugin {
                id: "0x03".into(),
                version: "1.0.0".into(),
                implementation: "0xbeef".into(),
                circuit_id: "0x01".into(),
                deprecated: false,
            })
            .unwrap();

        let compat = build_compat_snapshot(&snapshot).unwrap();
        assert_eq!(compat.circuits, vec!["0x01".to_string()]);
        assert_eq!(compat.drivers, vec!["0x02".to_string()]);
        assert_eq!(compat.plugins.len(), 1);
        ensure_plugin_exists(&snapshot, "0x03").unwrap();
        assert!(ensure_plugin_exists(&snapshot, "0x04").is_err());
    }
}
