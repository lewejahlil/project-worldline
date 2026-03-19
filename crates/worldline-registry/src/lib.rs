use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current schema version. Bump when the snapshot format changes.
const CURRENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("failed to read registry: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse registry: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("circuit '{id}'@'{version}' is already registered")]
    DuplicateCircuit { id: String, version: String },
    #[error("plugin '{id}'@'{version}' is already registered")]
    DuplicatePlugin { id: String, version: String },
    #[error("backend '{id}' is already registered")]
    DuplicateBackend { id: String },
    #[error("{kind} '{id}' not found")]
    NotFound { kind: String, id: String },
    #[error("unsupported schema version {0} (expected <= {CURRENT_SCHEMA_VERSION})")]
    UnsupportedSchemaVersion(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RegistrySnapshot {
    pub schema_version: u32,
    pub circuits: Vec<CircuitMeta>,
    pub plugins: Vec<PluginMeta>,
    pub backends: Vec<BackendMeta>,

    /// In-memory indexes for O(1) duplicate detection. Not serialized.
    #[serde(skip)]
    circuit_index: HashSet<String>,
    #[serde(skip)]
    plugin_index: HashSet<String>,
    #[serde(skip)]
    backend_index: HashSet<String>,
}

impl Default for RegistrySnapshot {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            circuits: Vec::new(),
            plugins: Vec::new(),
            backends: Vec::new(),
            circuit_index: HashSet::new(),
            plugin_index: HashSet::new(),
            backend_index: HashSet::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircuitMeta {
    pub id: String,
    pub version: String,
    #[serde(default)]
    pub public_inputs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginMeta {
    pub id: String,
    pub version: String,
    pub backend: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendMeta {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub versions: Vec<String>,
}

/// Composite key for circuit/plugin dedup.
fn circuit_key(id: &str, version: &str) -> String {
    format!("{id}@{version}")
}

fn plugin_key(id: &str, version: &str) -> String {
    format!("{id}@{version}")
}

impl RegistrySnapshot {
    /// Rebuild in-memory indexes from the deserialized Vecs.
    fn rebuild_indexes(&mut self) {
        self.circuit_index = self
            .circuits
            .iter()
            .map(|c| circuit_key(&c.id, &c.version))
            .collect();
        self.plugin_index = self
            .plugins
            .iter()
            .map(|p| plugin_key(&p.id, &p.version))
            .collect();
        self.backend_index = self.backends.iter().map(|b| b.id.clone()).collect();
    }

    pub fn register_circuit(&mut self, circuit: CircuitMeta) -> Result<(), RegistryError> {
        let key = circuit_key(&circuit.id, &circuit.version);
        if self.circuit_index.contains(&key) {
            return Err(RegistryError::DuplicateCircuit {
                id: circuit.id,
                version: circuit.version,
            });
        }
        self.circuit_index.insert(key);
        self.circuits.push(circuit);
        Ok(())
    }

    pub fn register_plugin(&mut self, plugin: PluginMeta) -> Result<(), RegistryError> {
        let key = plugin_key(&plugin.id, &plugin.version);
        if self.plugin_index.contains(&key) {
            return Err(RegistryError::DuplicatePlugin {
                id: plugin.id,
                version: plugin.version,
            });
        }
        self.plugin_index.insert(key);
        self.plugins.push(plugin);
        Ok(())
    }

    pub fn register_backend(&mut self, backend: BackendMeta) -> Result<(), RegistryError> {
        if self.backend_index.contains(&backend.id) {
            return Err(RegistryError::DuplicateBackend { id: backend.id });
        }
        self.backend_index.insert(backend.id.clone());
        self.backends.push(backend);
        Ok(())
    }

    pub fn remove_circuit(
        &mut self,
        id: &str,
        version: &str,
    ) -> Result<CircuitMeta, RegistryError> {
        let key = circuit_key(id, version);
        let pos = self
            .circuits
            .iter()
            .position(|c| c.id == id && c.version == version)
            .ok_or_else(|| RegistryError::NotFound {
                kind: "circuit".to_string(),
                id: format!("{id}@{version}"),
            })?;
        self.circuit_index.remove(&key);
        Ok(self.circuits.remove(pos))
    }

    pub fn remove_plugin(&mut self, id: &str, version: &str) -> Result<PluginMeta, RegistryError> {
        let key = plugin_key(id, version);
        let pos = self
            .plugins
            .iter()
            .position(|p| p.id == id && p.version == version)
            .ok_or_else(|| RegistryError::NotFound {
                kind: "plugin".to_string(),
                id: format!("{id}@{version}"),
            })?;
        self.plugin_index.remove(&key);
        Ok(self.plugins.remove(pos))
    }

    pub fn remove_backend(&mut self, id: &str) -> Result<BackendMeta, RegistryError> {
        let pos = self
            .backends
            .iter()
            .position(|b| b.id == id)
            .ok_or_else(|| RegistryError::NotFound {
                kind: "backend".to_string(),
                id: id.to_string(),
            })?;
        self.backend_index.remove(id);
        Ok(self.backends.remove(pos))
    }
}

pub fn load(path: impl AsRef<Path>) -> Result<RegistrySnapshot, RegistryError> {
    let path = path.as_ref();
    match fs::read_to_string(path) {
        Ok(raw) => {
            let mut snapshot: RegistrySnapshot = serde_json::from_str(&raw)?;
            if snapshot.schema_version > CURRENT_SCHEMA_VERSION {
                return Err(RegistryError::UnsupportedSchemaVersion(
                    snapshot.schema_version,
                ));
            }
            snapshot.rebuild_indexes();
            Ok(snapshot)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(RegistrySnapshot::default()),
        Err(err) => Err(RegistryError::Io(err)),
    }
}

pub fn save(path: impl AsRef<Path>, snapshot: &RegistrySnapshot) -> Result<PathBuf, RegistryError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let raw = serde_json::to_string_pretty(snapshot)?;
    let mut file = fs::File::create(path)?;
    file.write_all(raw.as_bytes())?;
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_snapshot() -> RegistrySnapshot {
        let mut snapshot = RegistrySnapshot::default();
        snapshot
            .register_backend(BackendMeta {
                id: "groth16-default".to_string(),
                kind: "groth16".to_string(),
                versions: vec!["0.6.0".to_string()],
            })
            .unwrap();
        snapshot
            .register_circuit(CircuitMeta {
                id: "sum2".to_string(),
                version: "1.0.0".to_string(),
                public_inputs: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            })
            .unwrap();
        snapshot
            .register_plugin(PluginMeta {
                id: "sum2-groth16".to_string(),
                version: "1.0.0".to_string(),
                backend: "groth16-default".to_string(),
            })
            .unwrap();
        snapshot
    }

    #[test]
    fn load_missing_file_returns_default() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let snapshot = load(&path).unwrap();
        assert!(snapshot.circuits.is_empty());
        assert!(snapshot.plugins.is_empty());
        assert!(snapshot.backends.is_empty());
        assert_eq!(snapshot.schema_version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let snapshot = sample_snapshot();

        save(&path, &snapshot).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(snapshot, loaded);
        assert_eq!(loaded.schema_version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn schema_version_persisted() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let snapshot = sample_snapshot();

        save(&path, &snapshot).unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"schema_version\": 1"));
    }

    #[test]
    fn reject_future_schema_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let json = r#"{"schema_version": 999, "circuits": [], "plugins": [], "backends": []}"#;
        fs::write(&path, json).unwrap();

        let err = load(&path).unwrap_err();
        assert!(matches!(err, RegistryError::UnsupportedSchemaVersion(999)));
    }

    #[test]
    fn prevent_duplicate_circuit_registration() {
        let mut snapshot = RegistrySnapshot::default();
        snapshot
            .register_circuit(CircuitMeta {
                id: "sum2".to_string(),
                version: "1.0.0".to_string(),
                public_inputs: vec![],
            })
            .unwrap();

        let err = snapshot
            .register_circuit(CircuitMeta {
                id: "sum2".to_string(),
                version: "1.0.0".to_string(),
                public_inputs: vec![],
            })
            .unwrap_err();

        assert!(matches!(err, RegistryError::DuplicateCircuit { .. }));
    }

    #[test]
    fn prevent_duplicate_plugin_registration() {
        let mut snapshot = RegistrySnapshot::default();
        snapshot
            .register_plugin(PluginMeta {
                id: "sum2".to_string(),
                version: "1.0.0".to_string(),
                backend: "groth16".to_string(),
            })
            .unwrap();

        let err = snapshot
            .register_plugin(PluginMeta {
                id: "sum2".to_string(),
                version: "1.0.0".to_string(),
                backend: "groth16".to_string(),
            })
            .unwrap_err();
        assert!(matches!(err, RegistryError::DuplicatePlugin { .. }));
    }

    #[test]
    fn remove_circuit_succeeds() {
        let mut snapshot = sample_snapshot();
        let removed = snapshot.remove_circuit("sum2", "1.0.0").unwrap();
        assert_eq!(removed.id, "sum2");
        assert!(snapshot.circuits.is_empty());
    }

    #[test]
    fn remove_circuit_not_found() {
        let mut snapshot = sample_snapshot();
        let err = snapshot.remove_circuit("missing", "1.0.0").unwrap_err();
        assert!(matches!(err, RegistryError::NotFound { .. }));
    }

    #[test]
    fn remove_plugin_succeeds() {
        let mut snapshot = sample_snapshot();
        let removed = snapshot.remove_plugin("sum2-groth16", "1.0.0").unwrap();
        assert_eq!(removed.id, "sum2-groth16");
        assert!(snapshot.plugins.is_empty());
    }

    #[test]
    fn remove_plugin_not_found() {
        let mut snapshot = sample_snapshot();
        let err = snapshot.remove_plugin("missing", "1.0.0").unwrap_err();
        assert!(matches!(err, RegistryError::NotFound { .. }));
    }

    #[test]
    fn remove_backend_succeeds() {
        let mut snapshot = sample_snapshot();
        let removed = snapshot.remove_backend("groth16-default").unwrap();
        assert_eq!(removed.id, "groth16-default");
        assert!(snapshot.backends.is_empty());
    }

    #[test]
    fn remove_backend_not_found() {
        let mut snapshot = sample_snapshot();
        let err = snapshot.remove_backend("missing").unwrap_err();
        assert!(matches!(err, RegistryError::NotFound { .. }));
    }

    #[test]
    fn prevent_duplicate_backend_registration() {
        let mut snapshot = RegistrySnapshot::default();
        snapshot
            .register_backend(BackendMeta {
                id: "groth16".to_string(),
                kind: "groth16".to_string(),
                versions: vec!["0.6.0".to_string()],
            })
            .unwrap();

        let err = snapshot
            .register_backend(BackendMeta {
                id: "groth16".to_string(),
                kind: "groth16".to_string(),
                versions: vec!["0.6.1".to_string()],
            })
            .unwrap_err();
        assert!(matches!(err, RegistryError::DuplicateBackend { .. }));
    }

    #[test]
    fn indexes_rebuilt_on_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let snapshot = sample_snapshot();
        save(&path, &snapshot).unwrap();

        let loaded = load(&path).unwrap();
        // Attempting to re-register should fail (indexes are active)
        let mut loaded = loaded;
        let err = loaded
            .register_circuit(CircuitMeta {
                id: "sum2".to_string(),
                version: "1.0.0".to_string(),
                public_inputs: vec![],
            })
            .unwrap_err();
        assert!(matches!(err, RegistryError::DuplicateCircuit { .. }));
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn roundtrip_any_snapshot(
                id in "[a-z]{1,10}",
                version in "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",
                backend_id in "[a-z]{1,10}",
            ) {
                let dir = tempdir().unwrap();
                let path = dir.path().join("prop.json");

                let mut snap = RegistrySnapshot::default();
                snap.register_backend(BackendMeta {
                    id: backend_id.clone(),
                    kind: "groth16".to_string(),
                    versions: vec![],
                }).unwrap();
                snap.register_circuit(CircuitMeta {
                    id: id.clone(),
                    version: version.clone(),
                    public_inputs: vec![],
                }).unwrap();
                snap.register_plugin(PluginMeta {
                    id: format!("{id}-plugin"),
                    version: version.clone(),
                    backend: backend_id,
                }).unwrap();

                save(&path, &snap).unwrap();
                let loaded = load(&path).unwrap();
                prop_assert_eq!(snap, loaded);
            }

            #[test]
            fn duplicate_circuit_always_fails(
                id in "[a-z]{1,10}",
                version in "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",
            ) {
                let mut snap = RegistrySnapshot::default();
                snap.register_circuit(CircuitMeta {
                    id: id.clone(),
                    version: version.clone(),
                    public_inputs: vec![],
                }).unwrap();

                let result = snap.register_circuit(CircuitMeta {
                    id,
                    version,
                    public_inputs: vec![],
                });
                prop_assert!(result.is_err());
            }

            #[test]
            fn remove_after_register_succeeds(
                id in "[a-z]{1,10}",
                version in "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",
            ) {
                let mut snap = RegistrySnapshot::default();
                snap.register_circuit(CircuitMeta {
                    id: id.clone(),
                    version: version.clone(),
                    public_inputs: vec![],
                }).unwrap();

                let removed = snap.remove_circuit(&id, &version);
                prop_assert!(removed.is_ok());
                prop_assert!(snap.circuits.is_empty());
            }
        }
    }
}
