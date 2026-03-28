use crate::types::{AggregatedProof, RecursionMode, RecursiveProof};
use thiserror::Error;

const MAX_RECURSION_DEPTH: u8 = 4;

#[derive(Debug, Error)]
pub enum RecursionError {
    #[error("max depth exceeded: max {max}, requested {requested}")]
    MaxDepthExceeded { max: u8, requested: u8 },
    #[error("empty inner proof: aggregated proof contains no inner proofs")]
    EmptyInnerProof,
    #[error("invalid verification key")]
    InvalidVerificationKey,
    #[error("recursion failed at depth {depth}: {reason}")]
    RecursionFailed { depth: u8, reason: String },
}

pub struct RecursiveVerifier {
    max_depth: u8,
}

impl RecursiveVerifier {
    pub fn new(max_depth: u8) -> Result<Self, RecursionError> {
        if max_depth > MAX_RECURSION_DEPTH {
            return Err(RecursionError::MaxDepthExceeded {
                max: MAX_RECURSION_DEPTH,
                requested: max_depth,
            });
        }
        Ok(Self { max_depth })
    }

    pub fn wrap(
        &self,
        aggregated: AggregatedProof,
        _mode: RecursionMode,
    ) -> Result<RecursiveProof, RecursionError> {
        if aggregated.proofs.is_empty() {
            return Err(RecursionError::EmptyInnerProof);
        }
        let verification_key_hash = aggregated.stf_commitment;
        Ok(RecursiveProof {
            inner_proof: aggregated,
            recursion_depth: 1,
            outer_proof_data: vec![0u8; 32],
            verification_key_hash,
        })
    }

    pub fn recurse(
        &self,
        proof: RecursiveProof,
        mode: RecursionMode,
    ) -> Result<RecursiveProof, RecursionError> {
        let new_depth = match mode {
            RecursionMode::Single => proof.recursion_depth,
            RecursionMode::Incremental => proof.recursion_depth + 1,
        };
        if new_depth > self.max_depth {
            return Err(RecursionError::MaxDepthExceeded {
                max: self.max_depth,
                requested: new_depth,
            });
        }
        Ok(RecursiveProof {
            recursion_depth: new_depth,
            ..proof
        })
    }

    pub fn verify_structure(&self, proof: &RecursiveProof) -> bool {
        proof.recursion_depth <= self.max_depth
            && !proof.outer_proof_data.is_empty()
            && proof.verification_key_hash != [0u8; 32]
    }
}
