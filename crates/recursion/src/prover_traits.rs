//! Common trait and types for inner proof generation.
//!
//! Each proof system (Groth16, Plonk, Halo2) implements `InnerProver` to
//! produce real proof bytes from STF inputs.

use crate::types::ProofSystemId;
use thiserror::Error;

/// STF circuit inputs shared across all proof systems.
///
/// These map to the private inputs of the Circom `WorldlineSTF(3, 1024)` template
/// and the Halo2 `WorldlineStfCircuit`.
#[derive(Debug, Clone)]
pub struct StfInputs {
    /// Pre-state root (BN254 field element as 32-byte little-endian).
    pub pre_state_root: [u8; 32],
    /// Post-state root (BN254 field element as 32-byte little-endian).
    pub post_state_root: [u8; 32],
    /// Batch commitment (BN254 field element as 32-byte little-endian).
    pub batch_commitment: [u8; 32],
    /// Batch size (1..=1024).
    pub batch_size: u64,
    /// Prover IDs (exactly 3, non-zero).
    pub prover_ids: [u64; 3],
    /// Proof system IDs (exactly 3, each in {1, 2, 3}).
    pub proof_system_ids: [u64; 3],
    /// Quorum count (1..=3).
    pub quorum_count: u64,
}

/// Output from an inner prover.
#[derive(Debug, Clone)]
pub struct InnerProofOutput {
    /// Raw proof bytes in the format expected by the corresponding on-chain adapter.
    pub proof_data: Vec<u8>,
    /// Public signals: [stfCommitment, proverSetDigest] as 32-byte little-endian.
    pub public_signals: [[u8; 32]; 2],
    /// Which proof system produced this proof.
    pub proof_system: ProofSystemId,
}

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("witness generation failed: {0}")]
    WitnessGeneration(String),
    #[error("proof generation failed: {0}")]
    ProofGeneration(String),
    #[error("snarkjs not found or failed to execute: {0}")]
    BackendNotFound(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("proof output parsing failed: {0}")]
    OutputParsing(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Trait for inner proof generators.
///
/// Each proof system implements this to produce real proof bytes from STF inputs.
pub trait InnerProver: Send + Sync {
    /// Generate a proof for the given STF inputs.
    fn prove(&self, inputs: &StfInputs) -> Result<InnerProofOutput, ProverError>;

    /// Which proof system this prover implements.
    fn proof_system_id(&self) -> ProofSystemId;

    /// Expected proof byte length for this proof system.
    fn expected_proof_length(&self) -> usize;
}
