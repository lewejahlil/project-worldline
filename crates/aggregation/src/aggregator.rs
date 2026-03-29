use crate::types::{
    AggregatedProof, AggregationStrategy, IndividualProof, ProofSystemId, GROTH16_PROOF_BYTE_SIZE,
    HALO2_PROOF_BYTE_SIZE, PLONK_PROOF_BYTE_SIZE,
};
use halo2curves::bn256::Fr;
use halo2curves::group::ff::{Field, PrimeField};
use std::collections::HashMap;
use thiserror::Error;
use worldline_halo2_circuit::{poseidon_compress_3, poseidon_compress_7};

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
        ProofSystemId::Groth16 => GROTH16_PROOF_BYTE_SIZE,
        ProofSystemId::Plonk => PLONK_PROOF_BYTE_SIZE,
        ProofSystemId::Halo2 => HALO2_PROOF_BYTE_SIZE,
    }
}

fn validate_proof(proof: &IndividualProof) -> bool {
    proof.proof_data.len() == expected_proof_size(proof.proof_system)
}

/// Convert a 32-byte array (little-endian) to a BN254 scalar field element.
/// Returns `Fr::ZERO` if the bytes do not represent a valid field element.
fn bytes_to_fr(bytes: &[u8; 32]) -> Fr {
    Fr::from_repr(*bytes).unwrap_or(Fr::ZERO)
}

/// Serialize a BN254 scalar field element to a 32-byte little-endian array.
fn fr_to_bytes(fr: Fr) -> [u8; 32] {
    fr.to_repr()
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

    #[must_use]
    pub fn proof_count(&self) -> usize {
        self.proofs.len()
    }

    #[must_use]
    pub fn valid_proof_count(&self) -> usize {
        self.proofs.iter().filter(|p| validate_proof(p)).count()
    }

    /// Compute `stfCommitment = Poseidon(preStateRoot, postStateRoot, batchCommitment)`.
    ///
    /// Uses circomlib-compatible Poseidon with `t=4`, `R_F=8`, `R_P=56`.
    /// The first public input of the first proof is treated as preStateRoot,
    /// the second as postStateRoot, and `self.batch_commitment` as batchCommitment.
    fn compute_stf_commitment(&self, proofs: &[IndividualProof]) -> [u8; 32] {
        // Extract preStateRoot and postStateRoot from the first proof's public inputs.
        // If fewer than 2 public inputs exist, default to Fr::ZERO.
        let pre_state_root = proofs
            .first()
            .and_then(|p| p.public_inputs.first())
            .map(bytes_to_fr)
            .unwrap_or(Fr::ZERO);
        let post_state_root = proofs
            .first()
            .and_then(|p| p.public_inputs.get(1))
            .map(bytes_to_fr)
            .unwrap_or(Fr::ZERO);
        let batch_commitment = bytes_to_fr(&self.batch_commitment);

        fr_to_bytes(poseidon_compress_3(
            pre_state_root,
            post_state_root,
            batch_commitment,
        ))
    }

    /// Compute `proverSetDigest = Poseidon(proverIds[0..3], proofSystemIds[0..3], quorumCount)`.
    ///
    /// Uses circomlib-compatible Poseidon with `t=8`, `R_F=8`, `R_P=64`.
    /// Pads to exactly 3 prover slots (matching the Circom circuit's `N=3`).
    fn compute_prover_set_digest(&self, proofs: &[IndividualProof]) -> [u8; 32] {
        let mut prover_ids = [Fr::ZERO; 3];
        let mut proof_system_ids = [Fr::ZERO; 3];
        for (i, proof) in proofs.iter().take(3).enumerate() {
            prover_ids[i] = Fr::from(proof.prover_id);
            proof_system_ids[i] = Fr::from(proof.proof_system as u64);
        }
        let quorum_count = Fr::from(u64::from(self.quorum_required));

        fr_to_bytes(poseidon_compress_7(
            prover_ids[0],
            prover_ids[1],
            prover_ids[2],
            proof_system_ids[0],
            proof_system_ids[1],
            proof_system_ids[2],
            quorum_count,
        ))
    }
}
