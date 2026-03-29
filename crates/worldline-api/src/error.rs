//! Typed errors for the Prover API.

use thiserror::Error;
use worldline_recursion::ProofSystemId;

/// Errors from proof request validation.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("batch_size must be in [1, 1024], got {0}")]
    BatchSizeOutOfRange(u64),
    #[error("quorum_count must be in [1, 3], got {0}")]
    QuorumOutOfRange(u64),
    #[error("all prover_ids must be non-zero")]
    ZeroProverId,
    #[error("each proof_system_id must be in {{1, 2, 3}}, got {0}")]
    InvalidProofSystemId(u64),
    #[error("no proof systems requested")]
    NoSystemsRequested,
    #[error("requested {requested} proof systems but only {available} prover slots are non-zero")]
    ProverSlotMismatch { requested: usize, available: usize },
}

/// Errors from proof generation.
#[derive(Debug, Error)]
pub enum ProvingError {
    #[error("pipeline error: {0}")]
    Pipeline(String),
    #[error("prover {system:?} failed: {reason}")]
    ProverFailed {
        system: ProofSystemId,
        reason: String,
    },
    #[error("prover {system:?} is unavailable")]
    ProverUnavailable { system: ProofSystemId },
}

/// Errors from calldata encoding.
#[derive(Debug, Error)]
pub enum EncodingError {
    #[error("unknown proof system id: {0}")]
    UnknownProofSystem(u8),
    #[error("proof data length {actual} does not match expected {expected} for {system:?}")]
    ProofLengthMismatch {
        system: ProofSystemId,
        expected: usize,
        actual: usize,
    },
    #[error("public inputs encoding produced {0} bytes, expected 256")]
    PublicInputsLengthMismatch(usize),
}

/// Top-level API error.
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("validation error: {0}")]
    Validation(#[from] ValidationError),
    #[error("proving error: {0}")]
    Proving(#[from] ProvingError),
    #[error("encoding error: {0}")]
    Encoding(#[from] EncodingError),
}
