use std::collections::HashMap;

use crate::errors::RegistryError;
use crate::types::{ProofSystemId, ProverId, ProverRecord};

#[derive(Debug, Default)]
pub struct ProverRegistry {
    provers: HashMap<ProverId, ProverRecord>,
}

impl ProverRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a prover. Rejects id=0 and duplicate ids.
    pub fn register(&mut self, id: ProverId, system: ProofSystemId) -> Result<(), RegistryError> {
        if id == 0 {
            return Err(RegistryError::InvalidProverId);
        }
        if self.provers.contains_key(&id) {
            return Err(RegistryError::ProverAlreadyRegistered(id));
        }
        self.provers.insert(
            id,
            ProverRecord {
                id,
                proof_system: system,
                active: true,
            },
        );
        Ok(())
    }

    /// Deregister a prover (sets active=false). Errors if not found.
    pub fn deregister(&mut self, id: ProverId) -> Result<(), RegistryError> {
        let record = self
            .provers
            .get_mut(&id)
            .ok_or(RegistryError::ProverNotFound(id))?;
        record.active = false;
        Ok(())
    }

    #[must_use]
    pub fn get(&self, id: ProverId) -> Option<&ProverRecord> {
        self.provers.get(&id)
    }

    #[must_use]
    pub fn active_provers(&self) -> Vec<&ProverRecord> {
        self.provers.values().filter(|r| r.active).collect()
    }

    #[must_use]
    pub fn active_count(&self) -> u8 {
        self.provers.values().filter(|r| r.active).count() as u8
    }

    /// Check that at least `required` provers are active.
    /// `required` must be in 1..=3.
    pub fn check_quorum(&self, required: u8) -> Result<(), RegistryError> {
        if required == 0 || required > 3 {
            return Err(RegistryError::QuorumOutOfRange(required));
        }
        let active = self.active_count();
        if active < required {
            return Err(RegistryError::QuorumNotMet { required, active });
        }
        Ok(())
    }
}
