//! Multi-prover pipeline: STF inputs → inner provers → aggregation → recursive proof.
//!
//! Coordinates the full proof generation flow:
//! 1. Accept STF inputs and a set of inner provers
//! 2. Generate proofs from each prover in sequence
//! 3. Feed proof outputs into the aggregation layer
//! 4. Wrap the aggregated proof into a recursive proof structure
//!
//! The pipeline enforces cross-prover consistency: all inner provers must produce
//! identical `stfCommitment` and `proverSetDigest` for the same inputs.

use crate::prover_traits::{InnerProofOutput, InnerProver, ProverError, StfInputs};
use crate::recursive_verifier::{RecursionError, RecursiveVerifier};
use crate::types::{RecursionMode, RecursiveProof};
use thiserror::Error;
use worldline_aggregation::{AggregationStrategy, IndividualProof, ProofAggregator, ProofSystemId};

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("no provers configured")]
    NoProvers,
    #[error("prover error ({system:?}): {source}")]
    Prover {
        system: ProofSystemId,
        source: ProverError,
    },
    #[error("aggregation error: {0}")]
    Aggregation(#[from] worldline_aggregation::AggregationError),
    #[error("recursion error: {0}")]
    Recursion(#[from] RecursionError),
    #[error(
        "public signal mismatch between {system_a:?} and {system_b:?}: \
         {signal_name} differs"
    )]
    PublicSignalMismatch {
        system_a: ProofSystemId,
        system_b: ProofSystemId,
        signal_name: String,
    },
}

/// Output of the multi-prover pipeline.
#[derive(Debug, Clone)]
pub struct PipelineOutput {
    /// The recursive proof wrapping the aggregated inner proofs.
    pub recursive_proof: RecursiveProof,
    /// Individual proof outputs from each inner prover (for inspection/debugging).
    pub inner_outputs: Vec<InnerProofOutput>,
    /// The shared stfCommitment (identical across all inner proofs).
    pub stf_commitment: [u8; 32],
    /// The shared proverSetDigest (identical across all inner proofs).
    pub prover_set_digest: [u8; 32],
}

/// Multi-prover pipeline configuration.
pub struct MultiProverPipeline {
    provers: Vec<Box<dyn InnerProver>>,
    quorum_required: u8,
    max_recursion_depth: u8,
}

impl MultiProverPipeline {
    /// Create a new pipeline with the given quorum requirement.
    ///
    /// # Arguments
    /// * `quorum_required` — minimum number of valid proofs needed (1–3)
    /// * `max_recursion_depth` — maximum recursion depth for the verifier (1–4)
    pub fn new(quorum_required: u8, max_recursion_depth: u8) -> Result<Self, PipelineError> {
        // Validate quorum via ProofAggregator constructor (will error on 0 or >3)
        let _ = ProofAggregator::new(quorum_required, [0u8; 32])?;
        let _ = RecursiveVerifier::new(max_recursion_depth)?;
        Ok(Self {
            provers: Vec::new(),
            quorum_required,
            max_recursion_depth,
        })
    }

    /// Add an inner prover to the pipeline.
    pub fn add_prover(&mut self, prover: Box<dyn InnerProver>) {
        self.provers.push(prover);
    }

    /// Execute the full pipeline: generate proofs, aggregate, wrap.
    ///
    /// # Flow
    /// 1. Generate a proof from each configured inner prover
    /// 2. Verify cross-prover public signal consistency
    /// 3. Feed proofs into the aggregation layer
    /// 4. Wrap the aggregated proof into a recursive proof
    pub fn execute(&self, inputs: &StfInputs) -> Result<PipelineOutput, PipelineError> {
        if self.provers.is_empty() {
            return Err(PipelineError::NoProvers);
        }

        // 1. Generate proofs from all inner provers
        let mut inner_outputs = Vec::with_capacity(self.provers.len());
        for prover in &self.provers {
            let output = prover.prove(inputs).map_err(|e| PipelineError::Prover {
                system: prover.proof_system_id(),
                source: e,
            })?;
            inner_outputs.push(output);
        }

        // 2. Verify cross-prover public signal consistency
        let reference = &inner_outputs[0];
        for output in inner_outputs.iter().skip(1) {
            if output.public_signals[0] != reference.public_signals[0] {
                return Err(PipelineError::PublicSignalMismatch {
                    system_a: reference.proof_system,
                    system_b: output.proof_system,
                    signal_name: "stfCommitment".to_string(),
                });
            }
            if output.public_signals[1] != reference.public_signals[1] {
                return Err(PipelineError::PublicSignalMismatch {
                    system_a: reference.proof_system,
                    system_b: output.proof_system,
                    signal_name: "proverSetDigest".to_string(),
                });
            }
        }

        let stf_commitment = reference.public_signals[0];
        let prover_set_digest = reference.public_signals[1];

        // 3. Feed into aggregation
        let batch_commitment = inputs.batch_commitment;
        let mut aggregator = ProofAggregator::new(self.quorum_required, batch_commitment)?;

        for (i, output) in inner_outputs.iter().enumerate() {
            let prover_id = inputs.prover_ids[i];
            // The aggregation layer's compute_stf_commitment() treats
            // public_inputs[0] as preStateRoot and public_inputs[1] as
            // postStateRoot, then hashes them with batch_commitment via
            // Poseidon. Pass the raw state roots so the aggregation layer
            // independently recomputes the same stfCommitment.
            let proof = IndividualProof {
                prover_id,
                proof_system: output.proof_system,
                proof_data: output.proof_data.clone(),
                public_inputs: vec![inputs.pre_state_root, inputs.post_state_root],
            };
            aggregator.add_proof(proof)?;
        }

        let aggregated = aggregator.aggregate(AggregationStrategy::Independent)?;

        // 4. Build outer_proof_data from concatenated inner proof bytes
        let outer_proof_data = build_outer_proof_data(&inner_outputs);

        // 5. Wrap into recursive proof
        let verifier = RecursiveVerifier::new(self.max_recursion_depth)?;
        let mut recursive_proof = verifier.wrap(aggregated, RecursionMode::Single)?;
        // Replace placeholder outer_proof_data with real concatenated proof bytes
        recursive_proof.outer_proof_data = outer_proof_data;

        Ok(PipelineOutput {
            recursive_proof,
            inner_outputs,
            stf_commitment,
            prover_set_digest,
        })
    }
}

/// Build the outer proof data by concatenating all inner proof bytes with
/// a length-prefixed envelope.
///
/// Format: for each proof: [proof_system_id: u8][proof_len: u32 LE][proof_data: N bytes]
fn build_outer_proof_data(outputs: &[InnerProofOutput]) -> Vec<u8> {
    let total_size: usize = outputs.iter().map(|o| 1 + 4 + o.proof_data.len()).sum();
    let mut data = Vec::with_capacity(total_size);

    for output in outputs {
        data.push(output.proof_system as u8);
        data.extend_from_slice(&(output.proof_data.len() as u32).to_le_bytes());
        data.extend_from_slice(&output.proof_data);
    }

    data
}

/// Parse outer proof data back into individual proof segments.
///
/// Returns a list of (proof_system_id, proof_bytes) tuples.
pub fn parse_outer_proof_data(data: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, PipelineError> {
    let mut segments = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        if pos + 5 > data.len() {
            return Err(PipelineError::Recursion(RecursionError::RecursionFailed {
                depth: 0,
                reason: "truncated outer proof data".to_string(),
            }));
        }
        let system_id = data[pos];
        pos += 1;
        let len =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + len > data.len() {
            return Err(PipelineError::Recursion(RecursionError::RecursionFailed {
                depth: 0,
                reason: "proof data extends beyond outer proof boundary".to_string(),
            }));
        }
        segments.push((system_id, data[pos..pos + len].to_vec()));
        pos += len;
    }

    Ok(segments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Halo2Prover;
    use halo2curves::bn256::Fr;
    use halo2curves::group::ff::PrimeField;

    fn test_inputs() -> StfInputs {
        StfInputs {
            pre_state_root: Fr::from(1234567890u64).to_repr(),
            post_state_root: Fr::from(9876543210u64).to_repr(),
            batch_commitment: Fr::from(5555555555u64).to_repr(),
            batch_size: 100,
            prover_ids: [101, 102, 103],
            proof_system_ids: [1, 2, 3],
            quorum_count: 3,
        }
    }

    // ── Single-prover tests (Halo2 only — no snarkjs required) ───────────

    #[test]
    fn pipeline_single_halo2_prover() {
        let mut pipeline = MultiProverPipeline::new(1, 4).unwrap();
        pipeline.add_prover(Box::new(Halo2Prover::new().unwrap()));

        let mut inputs = test_inputs();
        // Single prover: only prover_ids[0] is used, pad others
        inputs.prover_ids = [101, 102, 103];
        inputs.proof_system_ids = [3, 2, 1]; // Halo2 first

        let output = pipeline.execute(&inputs).unwrap();

        assert_eq!(output.inner_outputs.len(), 1);
        assert_eq!(output.inner_outputs[0].proof_system, ProofSystemId::Halo2);
        assert_eq!(output.inner_outputs[0].proof_data.len(), 2016);
        assert_eq!(
            output.stf_commitment,
            output.inner_outputs[0].public_signals[0]
        );
        assert_eq!(
            output.prover_set_digest,
            output.inner_outputs[0].public_signals[1]
        );

        // Recursive proof structure is valid
        let verifier = RecursiveVerifier::new(4).unwrap();
        assert!(verifier.verify_structure(&output.recursive_proof));
        assert_eq!(output.recursive_proof.recursion_depth, 1);

        // outer_proof_data is real (not zeros)
        assert!(!output.recursive_proof.outer_proof_data.is_empty());
        assert!(output
            .recursive_proof
            .outer_proof_data
            .iter()
            .any(|&b| b != 0));
    }

    #[test]
    fn pipeline_no_provers_errors() {
        let pipeline = MultiProverPipeline::new(1, 4).unwrap();
        let inputs = test_inputs();
        let result = pipeline.execute(&inputs);
        assert!(matches!(result, Err(PipelineError::NoProvers)));
    }

    #[test]
    fn pipeline_quorum_not_met() {
        // quorum=2 but only 1 prover
        let mut pipeline = MultiProverPipeline::new(2, 4).unwrap();
        pipeline.add_prover(Box::new(Halo2Prover::new().unwrap()));

        let inputs = test_inputs();
        let result = pipeline.execute(&inputs);
        assert!(matches!(result, Err(PipelineError::Aggregation(_))));
    }

    #[test]
    fn pipeline_outer_proof_data_roundtrip() {
        let mut pipeline = MultiProverPipeline::new(1, 4).unwrap();
        pipeline.add_prover(Box::new(Halo2Prover::new().unwrap()));

        let inputs = test_inputs();
        let output = pipeline.execute(&inputs).unwrap();

        // Parse the outer proof data back
        let segments = parse_outer_proof_data(&output.recursive_proof.outer_proof_data).unwrap();
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].0, ProofSystemId::Halo2 as u8);
        assert_eq!(segments[0].1.len(), 2016);
        assert_eq!(segments[0].1, output.inner_outputs[0].proof_data);
    }

    #[test]
    fn pipeline_stf_commitment_threads_through() {
        let mut pipeline = MultiProverPipeline::new(1, 4).unwrap();
        pipeline.add_prover(Box::new(Halo2Prover::new().unwrap()));

        let inputs = test_inputs();
        let output = pipeline.execute(&inputs).unwrap();

        // The stfCommitment from the inner prover must match the aggregated
        // proof's stfCommitment (both use Poseidon(pre, post, batch)).
        assert_eq!(
            output.stf_commitment,
            output.recursive_proof.inner_proof.stf_commitment
        );

        // Verify against independent Poseidon computation
        let pre = Fr::from(1234567890u64);
        let post = Fr::from(9876543210u64);
        let batch = Fr::from(5555555555u64);
        let expected_stf = worldline_halo2_circuit::poseidon_compress_3(pre, post, batch);
        assert_eq!(output.stf_commitment, expected_stf.to_repr());

        // The proverSetDigest from the circuit (computed over all 3 prover
        // slots) matches the independent Poseidon computation.
        let expected_digest = worldline_halo2_circuit::poseidon_compress_7(
            Fr::from(101u64),
            Fr::from(102u64),
            Fr::from(103u64),
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(3u64),
        );
        assert_eq!(output.prover_set_digest, expected_digest.to_repr());

        // Note: when fewer than 3 provers are active, the aggregation layer's
        // prover_set_digest (computed from submitted proofs only) may differ
        // from the circuit's proverSetDigest (computed from all 3 slots).
        // The pipeline output uses the circuit's value as the ground truth.
    }

    #[test]
    fn pipeline_two_halo2_provers_quorum_2() {
        // Two Halo2 provers, quorum = 2
        let mut pipeline = MultiProverPipeline::new(2, 4).unwrap();
        pipeline.add_prover(Box::new(Halo2Prover::new().unwrap()));
        pipeline.add_prover(Box::new(Halo2Prover::new().unwrap()));

        let inputs = test_inputs();
        let output = pipeline.execute(&inputs).unwrap();

        assert_eq!(output.inner_outputs.len(), 2);
        // Both proofs must have identical public signals
        assert_eq!(
            output.inner_outputs[0].public_signals,
            output.inner_outputs[1].public_signals
        );

        let segments = parse_outer_proof_data(&output.recursive_proof.outer_proof_data).unwrap();
        assert_eq!(segments.len(), 2);
    }

    // ── Three-prover tests (requires snarkjs for Groth16 + Plonk) ────────

    #[test]
    #[ignore = "requires snarkjs installed and circuit artifacts"]
    fn pipeline_all_three_provers_full_attestation() {
        use crate::{Groth16Prover, PlonkProver};
        use std::path::PathBuf;

        let mut pipeline = MultiProverPipeline::new(3, 4).unwrap();

        pipeline.add_prover(Box::new(
            Groth16Prover::new(
                PathBuf::from(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../circuits/build/worldline_stf_js/worldline_stf.wasm"
                )),
                PathBuf::from(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../circuits/zkeys/worldline_stf_final.zkey"
                )),
            )
            .unwrap(),
        ));

        pipeline.add_prover(Box::new(
            PlonkProver::new(
                PathBuf::from(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../circuits/build/worldline_stf_plonk_js/worldline_stf_plonk.wasm"
                )),
                PathBuf::from(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../circuits/zkeys/worldline_stf_plonk_v2.zkey"
                )),
            )
            .unwrap(),
        ));

        pipeline.add_prover(Box::new(Halo2Prover::new().unwrap()));

        let inputs = test_inputs();
        let output = pipeline.execute(&inputs).unwrap();

        // All three provers produced proofs
        assert_eq!(output.inner_outputs.len(), 3);
        assert_eq!(output.inner_outputs[0].proof_system, ProofSystemId::Groth16);
        assert_eq!(output.inner_outputs[1].proof_system, ProofSystemId::Plonk);
        assert_eq!(output.inner_outputs[2].proof_system, ProofSystemId::Halo2);

        // Proof sizes match expected
        assert_eq!(output.inner_outputs[0].proof_data.len(), 320);
        assert_eq!(output.inner_outputs[1].proof_data.len(), 832);
        assert_eq!(output.inner_outputs[2].proof_data.len(), 2016);

        // All public signals identical
        for i in 1..3 {
            assert_eq!(
                output.inner_outputs[0].public_signals, output.inner_outputs[i].public_signals,
                "public signals mismatch at prover {i}"
            );
        }

        // Outer proof data contains all three proofs
        let segments = parse_outer_proof_data(&output.recursive_proof.outer_proof_data).unwrap();
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].0, 1); // Groth16
        assert_eq!(segments[1].0, 2); // Plonk
        assert_eq!(segments[2].0, 3); // Halo2

        // Recursive proof structure valid
        let verifier = RecursiveVerifier::new(4).unwrap();
        assert!(verifier.verify_structure(&output.recursive_proof));

        // Poseidon digests thread through correctly
        let pre = Fr::from(1234567890u64);
        let post = Fr::from(9876543210u64);
        let batch = Fr::from(5555555555u64);
        let expected_stf = worldline_halo2_circuit::poseidon_compress_3(pre, post, batch);
        assert_eq!(output.stf_commitment, expected_stf.to_repr());
    }

    #[test]
    #[ignore = "requires snarkjs installed and circuit artifacts"]
    fn pipeline_two_of_three_quorum() {
        use crate::Groth16Prover;
        use std::path::PathBuf;

        // quorum=2 with all 3 provers — should succeed
        let mut pipeline = MultiProverPipeline::new(2, 4).unwrap();

        pipeline.add_prover(Box::new(
            Groth16Prover::new(
                PathBuf::from(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../circuits/build/worldline_stf_js/worldline_stf.wasm"
                )),
                PathBuf::from(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../circuits/zkeys/worldline_stf_final.zkey"
                )),
            )
            .unwrap(),
        ));

        pipeline.add_prover(Box::new(Halo2Prover::new().unwrap()));

        let inputs = test_inputs();
        let output = pipeline.execute(&inputs).unwrap();

        assert_eq!(output.inner_outputs.len(), 2);
        assert_eq!(output.recursive_proof.inner_proof.quorum_count, 2);

        // Even with 2 provers, public signals must be consistent
        assert_eq!(
            output.inner_outputs[0].public_signals,
            output.inner_outputs[1].public_signals,
        );
    }
}
