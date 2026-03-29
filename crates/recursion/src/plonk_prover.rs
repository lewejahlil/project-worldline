//! Plonk inner prover via snarkjs subprocess.
//!
//! Generates a real Plonk proof from STF inputs by:
//! 1. Constructing witness JSON from `StfInputs`
//! 2. Calling `npx snarkjs wtns calculate` to produce a witness file
//! 3. Calling `npx snarkjs plonk prove` to generate the proof
//! 4. Parsing the proof JSON into 832-byte raw format
//!
//! The 832-byte format matches `PlonkZkAdapter.sol`:
//!   G1 points: A, B, C, Z, T1, T2, T3, Wxi, Wxiw (9 × 64 bytes = 576)
//!   Fr scalars: eval_a, eval_b, eval_c, eval_s1, eval_s2, eval_zw (6 × 32 bytes = 192)
//!   Public signals: stfCommitment (32 bytes) + proverSetDigest (32 bytes) = 64
//!   Total: 576 + 192 + 64 = 832 bytes

use crate::groth16_prover::{decimal_str_to_32bytes, field_bytes_to_decimal, unique_id};
use crate::prover_traits::{InnerProofOutput, InnerProver, ProverError, StfInputs};
use crate::types::ProofSystemId;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Expected proof byte length for Plonk (BN254).
pub const PLONK_PROOF_BYTES: usize = 832;

/// G1 point names in the Plonk proof JSON, in serialization order.
const G1_POINT_KEYS: [&str; 9] = ["A", "B", "C", "Z", "T1", "T2", "T3", "Wxi", "Wxiw"];

/// Fr scalar evaluation names in the Plonk proof JSON, in serialization order.
const EVAL_KEYS: [&str; 6] = [
    "eval_a", "eval_b", "eval_c", "eval_s1", "eval_s2", "eval_zw",
];

/// Plonk prover configuration.
pub struct PlonkProver {
    /// Path to the compiled WASM file (witness calculator for Plonk circuit).
    wasm_path: PathBuf,
    /// Path to the `.zkey` file (Plonk universal SRS + circuit-specific key).
    zkey_path: PathBuf,
}

impl PlonkProver {
    /// Create a new Plonk prover.
    ///
    /// # Errors
    /// Returns `ProverError::InvalidInput` if the WASM or zkey files do not exist.
    pub fn new(wasm_path: PathBuf, zkey_path: PathBuf) -> Result<Self, ProverError> {
        if !wasm_path.exists() {
            return Err(ProverError::InvalidInput(format!(
                "WASM file not found: {}",
                wasm_path.display()
            )));
        }
        if !zkey_path.exists() {
            return Err(ProverError::InvalidInput(format!(
                "zkey file not found: {}",
                zkey_path.display()
            )));
        }
        Ok(Self {
            wasm_path,
            zkey_path,
        })
    }

    /// Build the witness JSON for the Plonk STF circuit.
    ///
    /// The Plonk circuit (`WorldlineSTFV2`) uses the same signal names as the
    /// Groth16 circuit (`WorldlineSTF`), so the witness JSON format is identical.
    fn build_witness_json(inputs: &StfInputs) -> String {
        let pre = field_bytes_to_decimal(&inputs.pre_state_root);
        let post = field_bytes_to_decimal(&inputs.post_state_root);
        let batch_cmt = field_bytes_to_decimal(&inputs.batch_commitment);

        format!(
            concat!(
                "{{",
                "\"preStateRoot\":\"{pre}\",",
                "\"postStateRoot\":\"{post}\",",
                "\"batchCommitment\":\"{batch_cmt}\",",
                "\"batchSize\":\"{batch_size}\",",
                "\"proverIds\":[\"{p0}\",\"{p1}\",\"{p2}\"],",
                "\"proofSystemIds\":[\"{s0}\",\"{s1}\",\"{s2}\"],",
                "\"quorumCount\":\"{qc}\"",
                "}}"
            ),
            pre = pre,
            post = post,
            batch_cmt = batch_cmt,
            batch_size = inputs.batch_size,
            p0 = inputs.prover_ids[0],
            p1 = inputs.prover_ids[1],
            p2 = inputs.prover_ids[2],
            s0 = inputs.proof_system_ids[0],
            s1 = inputs.proof_system_ids[1],
            s2 = inputs.proof_system_ids[2],
            qc = inputs.quorum_count,
        )
    }

    /// Generate the witness file using snarkjs.
    fn calculate_witness(
        wasm_path: &Path,
        input_json_path: &Path,
        witness_path: &Path,
    ) -> Result<(), ProverError> {
        let output = Command::new("npx")
            .args([
                "snarkjs",
                "wtns",
                "calculate",
                &wasm_path.to_string_lossy(),
                &input_json_path.to_string_lossy(),
                &witness_path.to_string_lossy(),
            ])
            .output()
            .map_err(|e| ProverError::BackendNotFound(format!("npx/snarkjs: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ProverError::WitnessGeneration(stderr.to_string()));
        }
        Ok(())
    }

    /// Generate the Plonk proof using snarkjs.
    fn generate_proof(
        zkey_path: &Path,
        witness_path: &Path,
        proof_json_path: &Path,
        public_json_path: &Path,
    ) -> Result<(), ProverError> {
        let output = Command::new("npx")
            .args([
                "snarkjs",
                "plonk",
                "prove",
                &zkey_path.to_string_lossy(),
                &witness_path.to_string_lossy(),
                &proof_json_path.to_string_lossy(),
                &public_json_path.to_string_lossy(),
            ])
            .output()
            .map_err(|e| ProverError::BackendNotFound(format!("npx/snarkjs: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ProverError::ProofGeneration(stderr.to_string()));
        }
        Ok(())
    }

    /// Parse snarkjs Plonk proof JSON into 832-byte raw format.
    ///
    /// Output layout (832 bytes):
    ///   [0..576)    9 G1 points × 64 bytes each (A, B, C, Z, T1, T2, T3, Wxi, Wxiw)
    ///   [576..768)  6 Fr scalars × 32 bytes each (eval_a..eval_zw)
    ///   [768..800)  stfCommitment (from public signals)
    ///   [800..832)  proverSetDigest (from public signals)
    fn parse_proof(
        proof_json: &str,
        public_signals: &[[u8; 32]; 2],
    ) -> Result<Vec<u8>, ProverError> {
        let proof: serde_json::Value = serde_json::from_str(proof_json)
            .map_err(|e| ProverError::OutputParsing(e.to_string()))?;

        let mut bytes = Vec::with_capacity(PLONK_PROOF_BYTES);

        // G1 points: each is [x, y, "1"] — take x and y as 32-byte field elements
        for key in &G1_POINT_KEYS {
            let point = proof[key]
                .as_array()
                .ok_or_else(|| ProverError::OutputParsing(format!("missing {key}")))?;
            bytes.extend_from_slice(&decimal_str_to_32bytes(
                point[0].as_str().unwrap_or_default(),
            )?);
            bytes.extend_from_slice(&decimal_str_to_32bytes(
                point[1].as_str().unwrap_or_default(),
            )?);
        }

        // Fr scalars: each is a decimal string
        for key in &EVAL_KEYS {
            let scalar = proof[key]
                .as_str()
                .ok_or_else(|| ProverError::OutputParsing(format!("missing {key}")))?;
            bytes.extend_from_slice(&decimal_str_to_32bytes(scalar)?);
        }

        // Append public signals (stfCommitment, proverSetDigest)
        bytes.extend_from_slice(&public_signals[0]);
        bytes.extend_from_slice(&public_signals[1]);

        debug_assert_eq!(bytes.len(), PLONK_PROOF_BYTES);
        Ok(bytes)
    }

    /// Parse snarkjs public.json into two 32-byte field elements.
    fn parse_public_signals(public_json: &str) -> Result<[[u8; 32]; 2], ProverError> {
        let signals: Vec<String> = serde_json::from_str(public_json)
            .map_err(|e| ProverError::OutputParsing(format!("public signals: {e}")))?;

        if signals.len() < 2 {
            return Err(ProverError::OutputParsing(format!(
                "expected 2 public signals, got {}",
                signals.len()
            )));
        }

        let stf = decimal_str_to_32bytes(&signals[0])?;
        let digest = decimal_str_to_32bytes(&signals[1])?;
        Ok([stf, digest])
    }
}

impl InnerProver for PlonkProver {
    fn prove(&self, inputs: &StfInputs) -> Result<InnerProofOutput, ProverError> {
        crate::groth16_prover::validate_stf_inputs(inputs)?;

        let uid = unique_id();
        let tmp = std::env::temp_dir();
        let input_path = tmp.join(format!("wl_plonk_input_{uid}.json"));
        let witness_path = tmp.join(format!("wl_plonk_witness_{uid}.wtns"));
        let proof_path = tmp.join(format!("wl_plonk_proof_{uid}.json"));
        let public_path = tmp.join(format!("wl_plonk_public_{uid}.json"));

        // 1. Write witness input JSON
        let witness_json = Self::build_witness_json(inputs);
        std::fs::write(&input_path, &witness_json)?;

        // 2. Calculate witness
        Self::calculate_witness(&self.wasm_path, &input_path, &witness_path)?;

        // 3. Generate proof
        Self::generate_proof(&self.zkey_path, &witness_path, &proof_path, &public_path)?;

        // 4. Parse outputs
        let proof_json = std::fs::read_to_string(&proof_path)?;
        let public_json = std::fs::read_to_string(&public_path)?;
        let public_signals = Self::parse_public_signals(&public_json)?;
        let proof_data = Self::parse_proof(&proof_json, &public_signals)?;

        // 5. Cleanup temp files (best-effort)
        let _ = std::fs::remove_file(&input_path);
        let _ = std::fs::remove_file(&witness_path);
        let _ = std::fs::remove_file(&proof_path);
        let _ = std::fs::remove_file(&public_path);

        Ok(InnerProofOutput {
            proof_data,
            public_signals,
            proof_system: ProofSystemId::Plonk,
        })
    }

    fn proof_system_id(&self) -> ProofSystemId {
        ProofSystemId::Plonk
    }

    fn expected_proof_length(&self) -> usize {
        PLONK_PROOF_BYTES
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn plonk_prover_rejects_missing_wasm() {
        let result = PlonkProver::new(
            PathBuf::from("/nonexistent/path.wasm"),
            PathBuf::from("/nonexistent/path.zkey"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn plonk_witness_json_format() {
        use halo2curves::bn256::Fr;
        use halo2curves::group::ff::PrimeField;

        let inputs = StfInputs {
            pre_state_root: Fr::from(42u64).to_repr(),
            post_state_root: Fr::from(99u64).to_repr(),
            batch_commitment: Fr::from(7u64).to_repr(),
            batch_size: 512,
            prover_ids: [10, 20, 30],
            proof_system_ids: [1, 2, 3],
            quorum_count: 2,
        };
        let json = PlonkProver::build_witness_json(&inputs);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["preStateRoot"].as_str().unwrap(), "42");
        assert_eq!(parsed["postStateRoot"].as_str().unwrap(), "99");
        assert_eq!(parsed["batchSize"].as_str().unwrap(), "512");
        assert_eq!(parsed["proverIds"][2].as_str().unwrap(), "30");
        assert_eq!(parsed["quorumCount"].as_str().unwrap(), "2");
    }

    #[test]
    fn plonk_parse_public_signals_valid() {
        let json = r#"["12345", "67890"]"#;
        let signals = PlonkProver::parse_public_signals(json).unwrap();
        assert_eq!(field_bytes_to_decimal(&signals[0]), "12345");
        assert_eq!(field_bytes_to_decimal(&signals[1]), "67890");
    }

    #[test]
    fn plonk_parse_public_signals_insufficient() {
        let json = r#"["12345"]"#;
        assert!(PlonkProver::parse_public_signals(json).is_err());
    }

    #[test]
    #[ignore = "requires snarkjs installed and circuit artifacts"]
    fn plonk_prove_real() {
        use halo2curves::bn256::Fr;
        use halo2curves::group::ff::PrimeField;

        let pre = Fr::from(1234567890u64);
        let post = Fr::from(9876543210u64);
        let batch = Fr::from(5555555555u64);

        let inputs = StfInputs {
            pre_state_root: pre.to_repr(),
            post_state_root: post.to_repr(),
            batch_commitment: batch.to_repr(),
            batch_size: 100,
            prover_ids: [101, 102, 103],
            proof_system_ids: [1, 2, 3],
            quorum_count: 3,
        };

        let prover = PlonkProver::new(
            PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../circuits/build/worldline_stf_plonk_js/worldline_stf_plonk.wasm"
            )),
            PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../circuits/zkeys/worldline_stf_plonk_v2.zkey"
            )),
        )
        .unwrap();

        let output = prover.prove(&inputs).unwrap();
        assert_eq!(output.proof_data.len(), PLONK_PROOF_BYTES);
        assert_eq!(output.proof_system, ProofSystemId::Plonk);

        // Verify public signals match Poseidon computation
        let stf = worldline_halo2_circuit::poseidon_compress_3(pre, post, batch);
        assert_eq!(output.public_signals[0], stf.to_repr());

        let digest = worldline_halo2_circuit::poseidon_compress_7(
            Fr::from(101u64),
            Fr::from(102u64),
            Fr::from(103u64),
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(3u64),
        );
        assert_eq!(output.public_signals[1], digest.to_repr());
    }

    /// Cross-prover consistency: Groth16 and Plonk must produce identical
    /// public signals for the same STF inputs.
    #[test]
    #[ignore = "requires snarkjs installed and circuit artifacts"]
    fn groth16_plonk_cross_prover_consistency() {
        use crate::Groth16Prover;
        use halo2curves::bn256::Fr;
        use halo2curves::group::ff::PrimeField;

        let pre = Fr::from(1234567890u64);
        let post = Fr::from(9876543210u64);
        let batch = Fr::from(5555555555u64);

        let inputs = StfInputs {
            pre_state_root: pre.to_repr(),
            post_state_root: post.to_repr(),
            batch_commitment: batch.to_repr(),
            batch_size: 100,
            prover_ids: [101, 102, 103],
            proof_system_ids: [1, 2, 3],
            quorum_count: 3,
        };

        let groth16 = Groth16Prover::new(
            PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../circuits/build/worldline_stf_js/worldline_stf.wasm"
            )),
            PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../circuits/zkeys/worldline_stf_final.zkey"
            )),
        )
        .unwrap();

        let plonk = PlonkProver::new(
            PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../circuits/build/worldline_stf_plonk_js/worldline_stf_plonk.wasm"
            )),
            PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../circuits/zkeys/worldline_stf_plonk_v2.zkey"
            )),
        )
        .unwrap();

        let g16_output = groth16.prove(&inputs).unwrap();
        let plonk_output = plonk.prove(&inputs).unwrap();

        // Public signals MUST be identical across proof systems
        assert_eq!(
            g16_output.public_signals[0], plonk_output.public_signals[0],
            "stfCommitment mismatch between Groth16 and Plonk"
        );
        assert_eq!(
            g16_output.public_signals[1], plonk_output.public_signals[1],
            "proverSetDigest mismatch between Groth16 and Plonk"
        );

        // Proof formats differ in length
        assert_eq!(g16_output.proof_data.len(), 320);
        assert_eq!(plonk_output.proof_data.len(), 832);
    }
}
