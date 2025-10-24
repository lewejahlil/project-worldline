use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[error("entity missing: {0}")]
    MissingEntity(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Circuit {
    pub id: String,
    pub description: String,
    pub verifier: String,
    pub abi_uri: Url,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Driver {
    pub id: String,
    pub version: String,
    pub endpoint: Url,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plugin {
    pub id: String,
    pub version: String,
    pub implementation: String,
    pub circuit_id: String,
    pub deprecated: bool,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RegistrySnapshot {
    pub circuits: BTreeMap<String, Circuit>,
    pub drivers: BTreeMap<String, Driver>,
    pub plugins: BTreeMap<String, Plugin>,
}

impl RegistrySnapshot {
    pub fn register_circuit(&mut self, circuit: Circuit) -> Result<(), RegistryError> {
        if !circuit.abi_uri.has_host() {
            return Err(RegistryError::InvalidUrl(circuit.abi_uri.to_string()));
        }
        self.circuits.insert(circuit.id.clone(), circuit);
        Ok(())
    }

    pub fn register_driver(&mut self, driver: Driver) -> Result<(), RegistryError> {
        if !driver.endpoint.has_host() {
            return Err(RegistryError::InvalidUrl(driver.endpoint.to_string()));
        }
        self.drivers.insert(driver.id.clone(), driver);
        Ok(())
    }

    pub fn register_plugin(&mut self, plugin: Plugin) -> Result<(), RegistryError> {
        if !self.circuits.contains_key(&plugin.circuit_id) {
            return Err(RegistryError::MissingEntity(plugin.circuit_id.clone()));
        }
        self.plugins.insert(plugin.id.clone(), plugin);
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, RegistryError> {
        if !path.as_ref().exists() {
            return Ok(Self::default());
        }
        let mut file = File::open(path)?;
        let mut buffer = String::new();
        file.read_to_string(&mut buffer)?;
        Ok(serde_json::from_str(&buffer)?)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), RegistryError> {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_entities() {
        let mut snapshot = RegistrySnapshot::default();
        let circuit = Circuit {
            id: "0x01".into(),
            description: "Square".into(),
            verifier: "0xdead".into(),
            abi_uri: Url::parse("https://example.com/abi.json").unwrap(),
        };
        snapshot.register_circuit(circuit).unwrap();
        let driver = Driver {
            id: "0x02".into(),
            version: "1.0.0".into(),
            endpoint: Url::parse("https://example.com").unwrap(),
        };
        snapshot.register_driver(driver).unwrap();
        let plugin = Plugin {
            id: "0x03".into(),
            version: "1.0.0".into(),
            implementation: "0xbeef".into(),
            circuit_id: "0x01".into(),
            deprecated: false,
        };
        snapshot.register_plugin(plugin).unwrap();
        assert_eq!(snapshot.plugins.len(), 1);
    }
}
