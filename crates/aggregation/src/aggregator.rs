use crate::types::{AggregatedProof, AggregationStrategy, IndividualProof, ProofSystemId};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AggregationError {
    #[error("insufficient proofs: required {required}, provided {provided}")]
    InsufficientProofs { required: u8, provided: u8 },
    #[error("invalid proof data for prover {prover_id}: {reason}")]
    InvalidProofData { prover_id: u64, reason: String },
    #[error("quorum not met: required {required}, valid {valid}")]
    QuorumNotMet { required: u8, valid: u8 },
    #[error("duplicate prover id: {0}")]
    DuplicateProver(u64),
    #[error("invalid prover id: must be non-zero")]
    InvalidProverId,
    #[error("batch commitment mismatch")]
    BatchCommitmentMismatch,
}

fn expected_proof_size(system: ProofSystemId) -> usize {
    match system {
        ProofSystemId::Groth16 => 320,
        ProofSystemId::Plonk => 256,
        ProofSystemId::Halo2 => 192,
    }
}

fn validate_proof(proof: &IndividualProof) -> bool {
    proof.proof_data.len() == expected_proof_size(proof.proof_system)
}

/// Compute a simple Poseidon-placeholder digest over a byte slice.
/// In production this would be a real Poseidon hash; here we XOR-fold
/// into a 32-byte array as a deterministic stand-in.
fn simple_digest(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in data.iter().enumerate() {
        out[i % 32] ^= byte;
    }
    out
}

pub struct ProofAggregator {
    quorum_required: u8,
    batch_commitment: [u8; 32],
    proofs: Vec<IndividualProof>,
}

impl ProofAggregator {
    pub fn new(quorum_required: u8, batch_commitment: [u8; 32]) -> Result<Self, AggregationError> {
        if quorum_required == 0 || quorum_required > 3 {
            return Err(AggregationError::InsufficientProofs {
                required: quorum_required,
                provided: 0,
            });
        }
        Ok(Self {
            quorum_required,
            batch_commitment,
            proofs: Vec::new(),
        })
    }

    pub fn add_proof(&mut self, proof: IndividualProof) -> Result<(), AggregationError> {
        if proof.prover_id == 0 {
            return Err(AggregationError::InvalidProverId);
        }
        if self.proofs.iter().any(|p| p.prover_id == proof.prover_id) {
            return Err(AggregationError::DuplicateProver(proof.prover_id));
        }
        let expected = expected_proof_size(proof.proof_system);
        if proof.proof_data.len() != expected {
            return Err(AggregationError::InvalidProofData {
                prover_id: proof.prover_id,
                reason: format!(
                    "expected {} bytes for {:?}, got {}",
                    expected,
                    proof.proof_system,
                    proof.proof_data.len()
                ),
            });
        }
        self.proofs.push(proof);
        Ok(())
    }

    pub fn aggregate(
        &self,
        strategy: AggregationStrategy,
    ) -> Result<AggregatedProof, AggregationError> {
        let provided = self.proofs.len() as u8;
        if provided < self.quorum_required {
            return Err(AggregationError::InsufficientProofs {
                required: self.quorum_required,
                provided,
            });
        }

        let included: Vec<IndividualProof> = match strategy {
            AggregationStrategy::Independent => {
                let valid_count = self.proofs.iter().filter(|p| validate_proof(p)).count() as u8;
                if valid_count < self.quorum_required {
                    return Err(AggregationError::QuorumNotMet {
                        required: self.quorum_required,
                        valid: valid_count,
                    });
                }
                self.proofs.clone()
            }
            AggregationStrategy::Sequential => {
                let mut collected = Vec::new();
                for proof in &self.proofs {
                    if validate_proof(proof) {
                        collected.push(proof.clone());
                    } else {
                        break;
                    }
                }
                let valid_count = collected.len() as u8;
                if valid_count < self.quorum_required {
                    return Err(AggregationError::QuorumNotMet {
                        required: self.quorum_required,
                        valid: valid_count,
                    });
                }
                collected
            }
        };

        let stf_commitment = self.compute_stf_commitment(&included);
        let prover_set_digest = self.compute_prover_set_digest(&included);

        Ok(AggregatedProof {
            proofs: included,
            quorum_count: self.quorum_required,
            batch_commitment: self.batch_commitment,
            stf_commitment,
            prover_set_digest,
        })
    }

    pub fn proof_count(&self) -> usize {
        self.proofs.len()
    }

    pub fn valid_proof_count(&self) -> usize {
        self.proofs.iter().filter(|p| validate_proof(p)).count()
    }

    fn compute_stf_commitment(&self, proofs: &[IndividualProof]) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(&self.batch_commitment);
        for proof in proofs {
            for input in &proof.public_inputs {
                data.extend_from_slice(input);
            }
        }
        simple_digest(&data)
    }

    fn compute_prover_set_digest(&self, proofs: &[IndividualProof]) -> [u8; 32] {
        let mut data = Vec::new();
        for proof in proofs {
            data.extend_from_slice(&proof.prover_id.to_le_bytes());
            data.push(proof.proof_system as u8);
        }
        data.push(self.quorum_required);
        simple_digest(&data)
    }
}
