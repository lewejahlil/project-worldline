use thiserror::Error;

use crate::types::ProverId;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("prover {0} is already registered")]
    ProverAlreadyRegistered(ProverId),
    #[error("prover {0} not found")]
    ProverNotFound(ProverId),
    #[error("prover id must be non-zero")]
    InvalidProverId,
    #[error("quorum not met: required {required}, active {active}")]
    QuorumNotMet { required: u8, active: u8 },
    #[error("quorum {0} is out of range (must be 1..=3)")]
    QuorumOutOfRange(u8),
}
