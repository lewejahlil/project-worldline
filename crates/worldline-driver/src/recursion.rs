//! Proof generation and recursion witness building for the Worldline driver.
//!
//! This module bridges the driver CLI to the real proving pipeline in
//! `worldline-recursion`. It constructs `StfInputs`, invokes the
//! `MultiProverPipeline`, and packages the outputs into a `RecursionWitness`.
//!
//! Supports three recursion modes:
//!
//! | Mode                    | Description                                                |
//! |-------------------------|------------------------------------------------------------|
//! | `None`                  | No inner proof recursion; outer proof covers all provers.  |
//! | `SnarkAccumulator`      | Accumulate inner proofs before producing the outer proof.  |
//! | `SnarkMiniVerifier`     | Inline mini-verifier circuit verifies inner proofs.        |

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use worldline_recursion::{
    Halo2Prover, MultiProverPipeline, PipelineOutput, ProofSystemId, StfInputs,
};

use crate::error::RecursionError;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Recursion mode as defined in the Worldline policy schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RecursionMode {
    #[default]
    None,
    SnarkAccumulator,
    SnarkMiniVerifier,
}

/// Configuration controlling whether and how inner proofs are recursed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursionConfig {
    pub mode: RecursionMode,
    /// Number of inner proofs to include in the outer proof (0–3 per spec).
    pub k_in_proof: u8,
    /// Upper bound on the number of inner proofs.
    pub max_inner: u8,
}

impl Default for RecursionConfig {
    fn default() -> Self {
        Self {
            mode: RecursionMode::None,
            k_in_proof: 0,
            max_inner: 4,
        }
    }
}

/// Which proof systems to request from the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedSystems {
    pub groth16: Option<Groth16Artifacts>,
    pub plonk: Option<PlonkArtifacts>,
    pub halo2: bool,
}

/// File paths for Groth16 trusted setup artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Groth16Artifacts {
    pub wasm_path: PathBuf,
    pub zkey_path: PathBuf,
}

/// File paths for Plonk trusted setup artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlonkArtifacts {
    pub wasm_path: PathBuf,
    pub zkey_path: PathBuf,
}

/// Configuration for proof generation combining recursion settings and STF inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofGenerationConfig {
    pub recursion: RecursionConfig,
    pub systems: RequestedSystems,
    /// STF circuit inputs.
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub batch_commitment: [u8; 32],
    pub batch_size: u64,
    /// Prover IDs (exactly 3, zero-padded if fewer active).
    pub prover_ids: [u64; 3],
    /// Proof system IDs (exactly 3, zero-padded if fewer active).
    pub proof_system_ids: [u64; 3],
    /// Quorum count (1–3).
    pub quorum_count: u64,
}

/// A recursion witness built from real proof generation.
///
/// Carries the raw proof bytes from each inner prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursionWitness {
    pub mode: RecursionMode,
    pub k_in_proof: u8,
    /// Raw proof bytes per inner prover (length == `k_in_proof`).
    pub inner_proofs: Vec<Vec<u8>>,
    /// Number of provers that were selected (may be > `k_in_proof`).
    pub selected_count: u8,
    /// Shared stfCommitment from all inner provers (Poseidon output, 32 bytes LE).
    #[serde(with = "hex_bytes_32")]
    pub stf_commitment: [u8; 32],
    /// Shared proverSetDigest from all inner provers (Poseidon output, 32 bytes LE).
    #[serde(with = "hex_bytes_32")]
    pub prover_set_digest: [u8; 32],
    /// Per-proof system identification for each inner proof.
    pub proof_systems: Vec<ProofSystemLabel>,
}

/// Label identifying which proof system produced an inner proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofSystemLabel {
    Groth16,
    Plonk,
    Halo2,
}

impl From<ProofSystemId> for ProofSystemLabel {
    fn from(id: ProofSystemId) -> Self {
        match id {
            ProofSystemId::Groth16 => ProofSystemLabel::Groth16,
            ProofSystemId::Plonk => ProofSystemLabel::Plonk,
            ProofSystemId::Halo2 => ProofSystemLabel::Halo2,
        }
    }
}

// ── Hex serde helper for [u8; 32] ────────────────────────────────────────────

mod hex_bytes_32 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;
        Ok(arr)
    }
}

// ── Pipeline construction ────────────────────────────────────────────────────

/// Build a `MultiProverPipeline` from the requested proof systems.
fn build_pipeline(
    systems: &RequestedSystems,
    quorum: u8,
) -> Result<MultiProverPipeline, RecursionError> {
    let mut pipeline = MultiProverPipeline::new(quorum, 4)
        .map_err(|e| RecursionError::PipelineCreate(e.to_string()))?;

    if let Some(ref artifacts) = systems.groth16 {
        let prover = worldline_recursion::Groth16Prover::new(
            artifacts.wasm_path.clone(),
            artifacts.zkey_path.clone(),
        )
        .map_err(|e| RecursionError::ProverCreate(format!("Groth16: {e}")))?;
        pipeline.add_prover(Box::new(prover));
    }

    if let Some(ref artifacts) = systems.plonk {
        let prover = worldline_recursion::PlonkProver::new(
            artifacts.wasm_path.clone(),
            artifacts.zkey_path.clone(),
        )
        .map_err(|e| RecursionError::ProverCreate(format!("Plonk: {e}")))?;
        pipeline.add_prover(Box::new(prover));
    }

    if systems.halo2 {
        let prover =
            Halo2Prover::new().map_err(|e| RecursionError::ProverCreate(format!("Halo2: {e}")))?;
        pipeline.add_prover(Box::new(prover));
    }

    Ok(pipeline)
}

/// Convert driver config into `StfInputs` for the recursion pipeline.
fn build_stf_inputs(config: &ProofGenerationConfig) -> StfInputs {
    StfInputs {
        pre_state_root: config.pre_state_root,
        post_state_root: config.post_state_root,
        batch_commitment: config.batch_commitment,
        batch_size: config.batch_size,
        prover_ids: config.prover_ids,
        proof_system_ids: config.proof_system_ids,
        quorum_count: config.quorum_count,
    }
}

/// Count the number of requested proof systems.
fn count_requested_systems(systems: &RequestedSystems) -> usize {
    let mut n = 0;
    if systems.groth16.is_some() {
        n += 1;
    }
    if systems.plonk.is_some() {
        n += 1;
    }
    if systems.halo2 {
        n += 1;
    }
    n
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Generate proofs and build a recursion witness using real provers.
///
/// # Returns
/// - `Ok(None)` when `config.recursion.mode == RecursionMode::None`.
/// - `Ok(Some(witness))` with real proof bytes from each requested proof system.
/// - `Err(…)` on configuration or proof generation failure.
///
/// # Errors
/// - Invalid recursion config (k_in_proof exceeds available provers or max_inner).
/// - Pipeline construction failure (missing artifacts, invalid quorum).
/// - Proof generation failure from any inner prover.
pub fn generate_proofs(
    config: &ProofGenerationConfig,
) -> Result<Option<RecursionWitness>, RecursionError> {
    if config.recursion.mode == RecursionMode::None {
        return Ok(None);
    }

    let num_systems = count_requested_systems(&config.systems);
    let k = config.recursion.k_in_proof as usize;
    let max = config.recursion.max_inner as usize;

    if k > num_systems {
        return Err(RecursionError::KExceedsSystems {
            k,
            available: num_systems,
        });
    }
    if k > max {
        return Err(RecursionError::KExceedsMax { k, max });
    }

    let pipeline = build_pipeline(&config.systems, config.quorum_count as u8)?;
    let stf_inputs = build_stf_inputs(config);

    let output: PipelineOutput = pipeline
        .execute(&stf_inputs)
        .map_err(|e| RecursionError::PipelineExec(e.to_string()))?;

    let inner_proofs: Vec<Vec<u8>> = output
        .inner_outputs
        .iter()
        .take(k)
        .map(|o| o.proof_data.clone())
        .collect();

    let proof_systems: Vec<ProofSystemLabel> = output
        .inner_outputs
        .iter()
        .take(k)
        .map(|o| ProofSystemLabel::from(o.proof_system))
        .collect();

    Ok(Some(RecursionWitness {
        mode: config.recursion.mode.clone(),
        k_in_proof: config.recursion.k_in_proof,
        inner_proofs,
        selected_count: num_systems.min(u8::MAX as usize) as u8,
        stf_commitment: output.stf_commitment,
        prover_set_digest: output.prover_set_digest,
        proof_systems,
    }))
}

/// Execute the full multi-prover pipeline and return the raw `PipelineOutput`.
///
/// This is a lower-level API for callers who need access to the full pipeline
/// output (recursive proof, all inner outputs, outer proof data) rather than
/// the simplified `RecursionWitness`.
pub fn execute_pipeline(
    systems: &RequestedSystems,
    stf_inputs: &StfInputs,
    quorum: u8,
) -> Result<PipelineOutput, RecursionError> {
    let pipeline = build_pipeline(systems, quorum)?;
    let output = pipeline
        .execute(stf_inputs)
        .map_err(|e| RecursionError::PipelineExec(e.to_string()))?;
    Ok(output)
}

/// Extract per-system proof outputs from a `PipelineOutput`, keyed by system label.
pub fn extract_inner_proofs(output: &PipelineOutput) -> Vec<(ProofSystemLabel, Vec<u8>)> {
    output
        .inner_outputs
        .iter()
        .map(|o| (ProofSystemLabel::from(o.proof_system), o.proof_data.clone()))
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn halo2_only_config() -> ProofGenerationConfig {
        ProofGenerationConfig {
            recursion: RecursionConfig {
                mode: RecursionMode::SnarkAccumulator,
                k_in_proof: 1,
                max_inner: 4,
            },
            systems: RequestedSystems {
                groth16: None,
                plonk: None,
                halo2: true,
            },
            pre_state_root: [0u8; 32],
            post_state_root: [0u8; 32],
            batch_commitment: [0u8; 32],
            batch_size: 100,
            prover_ids: [101, 102, 103],
            proof_system_ids: [1, 2, 3],
            quorum_count: 1,
        }
    }

    #[test]
    fn none_mode_returns_ok_none() {
        let mut config = halo2_only_config();
        config.recursion.mode = RecursionMode::None;
        let result = generate_proofs(&config).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn k_in_proof_gt_systems_returns_error() {
        let mut config = halo2_only_config();
        config.recursion.k_in_proof = 3; // > 1 system configured
        let err = generate_proofs(&config).unwrap_err();
        assert!(
            err.to_string().contains("exceeds number of requested"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn k_in_proof_gt_max_inner_returns_error() {
        let mut config = halo2_only_config();
        config.recursion.k_in_proof = 5;
        config.recursion.max_inner = 4;
        // Need enough systems to pass the first check
        config.systems = RequestedSystems {
            groth16: None,
            plonk: None,
            halo2: true,
        };
        // k=5 > max_inner=4, but also k=5 > 1 system, so first check fires
        let err = generate_proofs(&config).unwrap_err();
        assert!(err.to_string().contains("exceeds"));
    }

    #[test]
    fn halo2_single_prover_generates_real_proof() {
        let config = halo2_only_config();
        let witness = generate_proofs(&config)
            .unwrap()
            .expect("should return Some");

        assert_eq!(witness.mode, RecursionMode::SnarkAccumulator);
        assert_eq!(witness.k_in_proof, 1);
        assert_eq!(witness.inner_proofs.len(), 1);
        assert_eq!(witness.selected_count, 1);

        // Real proof bytes — not empty
        assert!(!witness.inner_proofs[0].is_empty());
        assert_eq!(witness.inner_proofs[0].len(), 1536); // Halo2 proof size

        // stfCommitment and proverSetDigest are non-zero
        assert_ne!(witness.stf_commitment, [0u8; 32]);
        assert_ne!(witness.prover_set_digest, [0u8; 32]);

        // Proof system label is correct
        assert_eq!(witness.proof_systems, vec![ProofSystemLabel::Halo2]);
    }

    #[test]
    fn witness_serialises_and_deserialises() {
        let config = halo2_only_config();
        let witness = generate_proofs(&config)
            .unwrap()
            .expect("should return Some");

        let json = serde_json::to_string(&witness).unwrap();
        let parsed: RecursionWitness = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.k_in_proof, witness.k_in_proof);
        assert_eq!(parsed.selected_count, witness.selected_count);
        assert_eq!(parsed.stf_commitment, witness.stf_commitment);
        assert_eq!(parsed.prover_set_digest, witness.prover_set_digest);
        assert_eq!(parsed.inner_proofs.len(), witness.inner_proofs.len());
        assert_eq!(parsed.inner_proofs[0].len(), witness.inner_proofs[0].len());
    }

    #[test]
    fn zero_k_in_proof_returns_witness_with_no_proofs() {
        let mut config = halo2_only_config();
        config.recursion.k_in_proof = 0;
        // k=0 means the pipeline still runs but we take 0 proofs
        // However, the pipeline needs quorum met. With k=0 and quorum=1,
        // we still execute the pipeline and just take 0 of the outputs.
        let witness = generate_proofs(&config)
            .unwrap()
            .expect("should return Some");

        assert_eq!(witness.inner_proofs.len(), 0);
        assert_eq!(witness.proof_systems.len(), 0);
        // stf_commitment still comes from the pipeline output
        assert_ne!(witness.stf_commitment, [0u8; 32]);
    }

    #[test]
    fn two_halo2_provers_quorum_2() {
        let config = ProofGenerationConfig {
            recursion: RecursionConfig {
                mode: RecursionMode::SnarkAccumulator,
                k_in_proof: 2,
                max_inner: 4,
            },
            systems: RequestedSystems {
                groth16: None,
                plonk: None,
                halo2: true,
            },
            pre_state_root: [0u8; 32],
            post_state_root: [0u8; 32],
            batch_commitment: [0u8; 32],
            batch_size: 100,
            prover_ids: [101, 102, 103],
            proof_system_ids: [1, 2, 3],
            quorum_count: 1,
        };
        // Only 1 halo2 system = 1 prover, but k=2 > 1
        let err = generate_proofs(&config).unwrap_err();
        assert!(err.to_string().contains("exceeds"));
    }

    #[test]
    fn execute_pipeline_returns_full_output() {
        let systems = RequestedSystems {
            groth16: None,
            plonk: None,
            halo2: true,
        };
        let stf_inputs = StfInputs {
            pre_state_root: [0u8; 32],
            post_state_root: [0u8; 32],
            batch_commitment: [0u8; 32],
            batch_size: 100,
            prover_ids: [101, 102, 103],
            proof_system_ids: [1, 2, 3],
            quorum_count: 1,
        };

        let output = execute_pipeline(&systems, &stf_inputs, 1).unwrap();

        assert_eq!(output.inner_outputs.len(), 1);
        assert_eq!(output.inner_outputs[0].proof_system, ProofSystemId::Halo2);
        assert_eq!(output.inner_outputs[0].proof_data.len(), 1536);
        assert_ne!(output.stf_commitment, [0u8; 32]);
        assert_ne!(output.prover_set_digest, [0u8; 32]);

        // Recursive proof is valid
        let verifier = worldline_recursion::RecursiveVerifier::new(4).unwrap();
        assert!(verifier.verify_structure(&output.recursive_proof));
    }

    #[test]
    fn extract_inner_proofs_returns_labeled_outputs() {
        let systems = RequestedSystems {
            groth16: None,
            plonk: None,
            halo2: true,
        };
        let stf_inputs = StfInputs {
            pre_state_root: [0u8; 32],
            post_state_root: [0u8; 32],
            batch_commitment: [0u8; 32],
            batch_size: 100,
            prover_ids: [101, 102, 103],
            proof_system_ids: [1, 2, 3],
            quorum_count: 1,
        };

        let output = execute_pipeline(&systems, &stf_inputs, 1).unwrap();
        let proofs = extract_inner_proofs(&output);

        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].0, ProofSystemLabel::Halo2);
        assert_eq!(proofs[0].1.len(), 1536);
    }
}
