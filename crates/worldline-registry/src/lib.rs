use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct RegistrySnapshot {
    pub circuits: Vec<CircuitMeta>,
    pub plugins: Vec<PluginMeta>,
    pub backends: Vec<BackendMeta>,
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

impl RegistrySnapshot {
    pub fn register_circuit(&mut self, circuit: CircuitMeta) -> Result<(), RegistryError> {
        if self
            .circuits
            .iter()
            .any(|c| c.id == circuit.id && c.version == circuit.version)
        {
            return Err(RegistryError::DuplicateCircuit {
                id: circuit.id,
                version: circuit.version,
            });
        }
        self.circuits.push(circuit);
        Ok(())
    }

    pub fn register_plugin(&mut self, plugin: PluginMeta) -> Result<(), RegistryError> {
        if self
            .plugins
            .iter()
            .any(|p| p.id == plugin.id && p.version == plugin.version)
        {
            return Err(RegistryError::DuplicatePlugin {
                id: plugin.id,
                version: plugin.version,
            });
        }
        self.plugins.push(plugin);
        Ok(())
    }

    pub fn register_backend(&mut self, backend: BackendMeta) -> Result<(), RegistryError> {
        if self.backends.iter().any(|b| b.id == backend.id) {
            return Err(RegistryError::DuplicateBackend { id: backend.id });
        }
        self.backends.push(backend);
        Ok(())
    }
}

pub fn load(path: impl AsRef<Path>) -> Result<RegistrySnapshot, RegistryError> {
    let path = path.as_ref();
    match fs::read_to_string(path) {
        Ok(raw) => Ok(serde_json::from_str(&raw)?),
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
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let snapshot = sample_snapshot();

        save(&path, &snapshot).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(snapshot, loaded);
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
}
