use crate::types::{AggregatedProof, AggregationStrategy, IndividualProof, ProofSystemId};
use std::collections::HashMap;
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
    #[error("verifier not registered for proof system: {0:?}")]
    VerifierNotRegistered(ProofSystemId),
    #[error("verification failed for prover {prover_id}: {reason}")]
    VerificationFailed { prover_id: u64, reason: String },
}

#[derive(Debug, Clone)]
pub struct VerificationReport {
    pub results: Vec<(u64, ProofSystemId, bool)>,
    pub verified_count: u8,
}

fn expected_proof_size(system: ProofSystemId) -> usize {
    match system {
        ProofSystemId::Groth16 => 320,
        ProofSystemId::Plonk => 832,
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
    verifiers: HashMap<u8, Box<dyn crate::verifiers::traits::ProofVerifier>>,
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
            verifiers: HashMap::new(),
        })
    }

    pub fn register_verifier(
        &mut self,
        verifier: Box<dyn crate::verifiers::traits::ProofVerifier>,
    ) {
        let id = verifier.proof_system_id() as u8;
        self.verifiers.insert(id, verifier);
    }

    pub fn verify_proof(&self, proof: &IndividualProof) -> Result<bool, AggregationError> {
        let id = proof.proof_system as u8;
        match self.verifiers.get(&id) {
            Some(verifier) => verifier
                .verify(&proof.proof_data, &proof.public_inputs)
                .map_err(|e| AggregationError::VerificationFailed {
                    prover_id: proof.prover_id,
                    reason: e.to_string(),
                }),
            None => Err(AggregationError::VerifierNotRegistered(proof.proof_system)),
        }
    }

    pub fn verify_all(&self) -> Result<VerificationReport, AggregationError> {
        let mut results = Vec::new();
        for proof in &self.proofs {
            let id = proof.proof_system as u8;
            let passed = match self.verifiers.get(&id) {
                Some(verifier) => verifier
                    .verify(&proof.proof_data, &proof.public_inputs)
                    .map_err(|e| AggregationError::VerificationFailed {
                        prover_id: proof.prover_id,
                        reason: e.to_string(),
                    })?,
                None => return Err(AggregationError::VerifierNotRegistered(proof.proof_system)),
            };
            results.push((proof.prover_id, proof.proof_system, passed));
        }
        let verified_count = results.iter().filter(|(_, _, p)| *p).count() as u8;
        Ok(VerificationReport {
            results,
            verified_count,
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

        // If no verifiers registered, fall back to length-check only (backward compat)
        if self.verifiers.is_empty() {
            return self.aggregate_by_length_check(strategy);
        }

        let (included, verification_results) = match strategy {
            AggregationStrategy::Independent => {
                let mut results: Vec<(u64, ProofSystemId, bool)> = Vec::new();
                for proof in &self.proofs {
                    let passed = self.verify_proof(proof).unwrap_or(false);
                    results.push((proof.prover_id, proof.proof_system, passed));
                }
                let verified_count = results.iter().filter(|(_, _, p)| *p).count() as u8;
                if verified_count < self.quorum_required {
                    return Err(AggregationError::QuorumNotMet {
                        required: self.quorum_required,
                        valid: verified_count,
                    });
                }
                // Include only verified proofs
                let included: Vec<IndividualProof> = self
                    .proofs
                    .iter()
                    .zip(results.iter())
                    .filter(|(_, (_, _, passed))| *passed)
                    .map(|(p, _)| p.clone())
                    .collect();
                (included, results)
            }
            AggregationStrategy::Sequential => {
                let mut collected: Vec<IndividualProof> = Vec::new();
                let mut results: Vec<(u64, ProofSystemId, bool)> = Vec::new();
                for proof in &self.proofs {
                    let passed = self.verify_proof(proof).unwrap_or(false);
                    results.push((proof.prover_id, proof.proof_system, passed));
                    if passed {
                        collected.push(proof.clone());
                    } else {
                        break; // stop at first failure
                    }
                }
                let verified_count = collected.len() as u8;
                if verified_count < self.quorum_required {
                    return Err(AggregationError::QuorumNotMet {
                        required: self.quorum_required,
                        valid: verified_count,
                    });
                }
                (collected, results)
            }
        };

        let verified_count = verification_results.iter().filter(|(_, _, p)| *p).count() as u8;
        let stf_commitment = self.compute_stf_commitment(&included);
        let prover_set_digest = self.compute_prover_set_digest(&included);

        Ok(AggregatedProof {
            proofs: included,
            quorum_count: self.quorum_required,
            batch_commitment: self.batch_commitment,
            stf_commitment,
            prover_set_digest,
            verified_count,
            verification_results,
        })
    }

    fn aggregate_by_length_check(
        &self,
        strategy: AggregationStrategy,
    ) -> Result<AggregatedProof, AggregationError> {
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
            verified_count: 0,
            verification_results: vec![],
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
