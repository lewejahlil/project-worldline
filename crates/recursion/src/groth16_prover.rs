//! Groth16 inner prover via snarkjs subprocess.
//!
//! Generates a real Groth16 proof from STF inputs by:
//! 1. Constructing witness JSON from `StfInputs`
//! 2. Calling `npx snarkjs wtns calculate` to produce a witness file
//! 3. Calling `npx snarkjs groth16 prove` to generate the proof
//! 4. Parsing the proof JSON into 320-byte raw format
//!
//! The 320-byte format matches `Groth16ZkAdapter.sol`:
//!   pi_a (64 bytes) + pi_b (128 bytes) + pi_c (64 bytes) + stfCommitment (32) + proverSetDigest (32)

use crate::prover_traits::{InnerProofOutput, InnerProver, ProverError, StfInputs};
use crate::types::ProofSystemId;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Expected proof byte length for Groth16 (BN254).
pub const GROTH16_PROOF_BYTES: usize = 320;

/// Groth16 prover configuration.
pub struct Groth16Prover {
    /// Path to the compiled WASM file (witness calculator).
    wasm_path: PathBuf,
    /// Path to the `.zkey` file (proving key from trusted setup).
    zkey_path: PathBuf,
}

impl Groth16Prover {
    /// Create a new Groth16 prover.
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

    /// Build the witness JSON for the STF circuit.
    ///
    /// The circom circuit expects field elements as decimal strings. BN254 field
    /// elements stored as 32-byte little-endian arrays are converted to decimal
    /// via big-integer arithmetic.
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

    /// Generate the Groth16 proof using snarkjs.
    fn generate_proof(
        zkey_path: &Path,
        witness_path: &Path,
        proof_json_path: &Path,
        public_json_path: &Path,
    ) -> Result<(), ProverError> {
        let output = Command::new("npx")
            .args([
                "snarkjs",
                "groth16",
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

    /// Parse snarkjs proof JSON into 320-byte raw format.
    ///
    /// The proof JSON contains `pi_a`, `pi_b`, `pi_c` as arrays of decimal strings
    /// representing BN254 curve point coordinates.
    ///
    /// Output layout (320 bytes):
    ///   [0..32)    pi_a.x
    ///   [32..64)   pi_a.y
    ///   [64..96)   pi_b.x[0]
    ///   [96..128)  pi_b.x[1]
    ///   [128..160) pi_b.y[0]
    ///   [160..192) pi_b.y[1]
    ///   [192..224) pi_c.x
    ///   [224..256) pi_c.y
    ///   [256..288) stfCommitment  (from public signals)
    ///   [288..320) proverSetDigest (from public signals)
    fn parse_proof(
        proof_json: &str,
        public_signals: &[[u8; 32]; 2],
    ) -> Result<Vec<u8>, ProverError> {
        let proof: serde_json::Value = serde_json::from_str(proof_json)
            .map_err(|e| ProverError::OutputParsing(e.to_string()))?;

        let mut bytes = Vec::with_capacity(GROTH16_PROOF_BYTES);

        // pi_a: [x, y, "1"] — take x and y
        let pi_a = proof["pi_a"]
            .as_array()
            .ok_or_else(|| ProverError::OutputParsing("missing pi_a".to_string()))?;
        bytes.extend_from_slice(&decimal_str_to_32bytes(
            pi_a[0].as_str().unwrap_or_default(),
        )?);
        bytes.extend_from_slice(&decimal_str_to_32bytes(
            pi_a[1].as_str().unwrap_or_default(),
        )?);

        // pi_b: [[x0, x1], [y0, y1], ["1", "0"]] — take x0, x1, y0, y1
        let pi_b = proof["pi_b"]
            .as_array()
            .ok_or_else(|| ProverError::OutputParsing("missing pi_b".to_string()))?;
        let pi_b_x = pi_b[0]
            .as_array()
            .ok_or_else(|| ProverError::OutputParsing("missing pi_b[0]".to_string()))?;
        let pi_b_y = pi_b[1]
            .as_array()
            .ok_or_else(|| ProverError::OutputParsing("missing pi_b[1]".to_string()))?;
        bytes.extend_from_slice(&decimal_str_to_32bytes(
            pi_b_x[0].as_str().unwrap_or_default(),
        )?);
        bytes.extend_from_slice(&decimal_str_to_32bytes(
            pi_b_x[1].as_str().unwrap_or_default(),
        )?);
        bytes.extend_from_slice(&decimal_str_to_32bytes(
            pi_b_y[0].as_str().unwrap_or_default(),
        )?);
        bytes.extend_from_slice(&decimal_str_to_32bytes(
            pi_b_y[1].as_str().unwrap_or_default(),
        )?);

        // pi_c: [x, y, "1"] — take x and y
        let pi_c = proof["pi_c"]
            .as_array()
            .ok_or_else(|| ProverError::OutputParsing("missing pi_c".to_string()))?;
        bytes.extend_from_slice(&decimal_str_to_32bytes(
            pi_c[0].as_str().unwrap_or_default(),
        )?);
        bytes.extend_from_slice(&decimal_str_to_32bytes(
            pi_c[1].as_str().unwrap_or_default(),
        )?);

        // Append public signals (stfCommitment, proverSetDigest)
        bytes.extend_from_slice(&public_signals[0]);
        bytes.extend_from_slice(&public_signals[1]);

        debug_assert_eq!(bytes.len(), GROTH16_PROOF_BYTES);
        Ok(bytes)
    }

    /// Parse snarkjs public.json into two 32-byte field elements.
    ///
    /// The public.json is an array of decimal strings: ["stfCommitment", "proverSetDigest"].
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

impl InnerProver for Groth16Prover {
    fn prove(&self, inputs: &StfInputs) -> Result<InnerProofOutput, ProverError> {
        validate_stf_inputs(inputs)?;

        let pid = std::process::id();
        let tmp = std::env::temp_dir();
        let input_path = tmp.join(format!("wl_g16_input_{pid}.json"));
        let witness_path = tmp.join(format!("wl_g16_witness_{pid}.wtns"));
        let proof_path = tmp.join(format!("wl_g16_proof_{pid}.json"));
        let public_path = tmp.join(format!("wl_g16_public_{pid}.json"));

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
            proof_system: ProofSystemId::Groth16,
        })
    }

    fn proof_system_id(&self) -> ProofSystemId {
        ProofSystemId::Groth16
    }

    fn expected_proof_length(&self) -> usize {
        GROTH16_PROOF_BYTES
    }
}

// ── Shared utility functions ─────────────────────────────────────────────────

/// Validate STF inputs against circuit constraints.
pub(crate) fn validate_stf_inputs(inputs: &StfInputs) -> Result<(), ProverError> {
    if inputs.batch_size == 0 || inputs.batch_size > 1024 {
        return Err(ProverError::InvalidInput(format!(
            "batch_size must be in [1, 1024], got {}",
            inputs.batch_size
        )));
    }
    if inputs.quorum_count == 0 || inputs.quorum_count > 3 {
        return Err(ProverError::InvalidInput(format!(
            "quorum_count must be in [1, 3], got {}",
            inputs.quorum_count
        )));
    }
    for (i, pid) in inputs.prover_ids.iter().enumerate() {
        if *pid == 0 {
            return Err(ProverError::InvalidInput(format!(
                "prover_ids[{i}] must be non-zero"
            )));
        }
    }
    for (i, psid) in inputs.proof_system_ids.iter().enumerate() {
        if *psid < 1 || *psid > 3 {
            return Err(ProverError::InvalidInput(format!(
                "proof_system_ids[{i}] must be in {{1, 2, 3}}, got {psid}"
            )));
        }
    }
    Ok(())
}

/// Convert a 32-byte little-endian field element to a decimal string.
///
/// BN254 field elements are stored as 32-byte little-endian arrays. Circom
/// expects decimal string representation of the integer value.
pub(crate) fn field_bytes_to_decimal(bytes: &[u8; 32]) -> String {
    // Convert little-endian bytes to big-endian for standard integer interpretation.
    let mut be = *bytes;
    be.reverse();
    // Convert big-endian bytes to decimal string via repeated division.
    bytes_be_to_decimal(&be)
}

/// Convert big-endian bytes to decimal string.
fn bytes_be_to_decimal(bytes: &[u8; 32]) -> String {
    // Use a simple big-integer-to-decimal conversion.
    // For 256-bit numbers, we accumulate in u128 chunks.
    let mut result = Vec::new();
    let mut val = [0u8; 32];
    val.copy_from_slice(bytes);

    if val.iter().all(|&b| b == 0) {
        return "0".to_string();
    }

    while val.iter().any(|&b| b != 0) {
        // Divide val by 10, collect remainder
        let mut remainder: u16 = 0;
        for byte in val.iter_mut() {
            let cur = (remainder << 8) | u16::from(*byte);
            *byte = (cur / 10) as u8;
            remainder = cur % 10;
        }
        result.push(b'0' + remainder as u8);
    }

    result.reverse();
    String::from_utf8(result).unwrap_or_else(|_| "0".to_string())
}

/// Convert a decimal string to a 32-byte little-endian field element.
///
/// Parses the decimal string and produces the little-endian byte representation
/// used by BN254 field elements.
pub(crate) fn decimal_str_to_32bytes(s: &str) -> Result<[u8; 32], ProverError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ProverError::OutputParsing(
            "empty decimal string".to_string(),
        ));
    }

    // Parse decimal string to big-endian bytes via repeated multiplication
    let mut val = [0u8; 32];
    for ch in s.bytes() {
        if !ch.is_ascii_digit() {
            return Err(ProverError::OutputParsing(format!(
                "non-digit character in decimal string: '{}'",
                ch as char
            )));
        }
        let digit = ch - b'0';
        // Multiply val by 10 and add digit
        let mut carry: u16 = u16::from(digit);
        for byte in val.iter_mut().rev() {
            let cur = u16::from(*byte) * 10 + carry;
            *byte = (cur & 0xff) as u8;
            carry = cur >> 8;
        }
    }

    // Convert big-endian to little-endian
    val.reverse();
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_bytes_roundtrip_zero() {
        let bytes = [0u8; 32];
        let dec = field_bytes_to_decimal(&bytes);
        assert_eq!(dec, "0");
        let back = decimal_str_to_32bytes(&dec).unwrap();
        assert_eq!(back, bytes);
    }

    #[test]
    fn field_bytes_roundtrip_small() {
        // 42 in little-endian: [42, 0, 0, ...]
        let mut bytes = [0u8; 32];
        bytes[0] = 42;
        let dec = field_bytes_to_decimal(&bytes);
        assert_eq!(dec, "42");
        let back = decimal_str_to_32bytes(&dec).unwrap();
        assert_eq!(back, bytes);
    }

    #[test]
    fn field_bytes_roundtrip_large() {
        // 1234567890 in little-endian
        let val: u64 = 1234567890;
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&val.to_le_bytes());
        let dec = field_bytes_to_decimal(&bytes);
        assert_eq!(dec, "1234567890");
        let back = decimal_str_to_32bytes(&dec).unwrap();
        assert_eq!(back, bytes);
    }

    #[test]
    fn decimal_str_to_bytes_invalid() {
        assert!(decimal_str_to_32bytes("").is_err());
        assert!(decimal_str_to_32bytes("abc").is_err());
    }

    #[test]
    fn validate_stf_inputs_valid() {
        let inputs = StfInputs {
            pre_state_root: [1u8; 32],
            post_state_root: [2u8; 32],
            batch_commitment: [3u8; 32],
            batch_size: 100,
            prover_ids: [101, 102, 103],
            proof_system_ids: [1, 2, 3],
            quorum_count: 3,
        };
        assert!(validate_stf_inputs(&inputs).is_ok());
    }

    #[test]
    fn validate_stf_inputs_batch_size_zero() {
        let inputs = StfInputs {
            pre_state_root: [1u8; 32],
            post_state_root: [2u8; 32],
            batch_commitment: [3u8; 32],
            batch_size: 0,
            prover_ids: [101, 102, 103],
            proof_system_ids: [1, 2, 3],
            quorum_count: 3,
        };
        assert!(validate_stf_inputs(&inputs).is_err());
    }

    #[test]
    fn validate_stf_inputs_batch_size_1025() {
        let inputs = StfInputs {
            pre_state_root: [1u8; 32],
            post_state_root: [2u8; 32],
            batch_commitment: [3u8; 32],
            batch_size: 1025,
            prover_ids: [101, 102, 103],
            proof_system_ids: [1, 2, 3],
            quorum_count: 3,
        };
        assert!(validate_stf_inputs(&inputs).is_err());
    }

    #[test]
    fn validate_stf_inputs_prover_id_zero() {
        let inputs = StfInputs {
            pre_state_root: [1u8; 32],
            post_state_root: [2u8; 32],
            batch_commitment: [3u8; 32],
            batch_size: 100,
            prover_ids: [101, 0, 103],
            proof_system_ids: [1, 2, 3],
            quorum_count: 3,
        };
        assert!(validate_stf_inputs(&inputs).is_err());
    }

    #[test]
    fn validate_stf_inputs_proof_system_id_4() {
        let inputs = StfInputs {
            pre_state_root: [1u8; 32],
            post_state_root: [2u8; 32],
            batch_commitment: [3u8; 32],
            batch_size: 100,
            prover_ids: [101, 102, 103],
            proof_system_ids: [1, 4, 3],
            quorum_count: 3,
        };
        assert!(validate_stf_inputs(&inputs).is_err());
    }

    #[test]
    fn build_witness_json_format() {
        let mut pre = [0u8; 32];
        pre[0] = 42; // 42 in LE
        let inputs = StfInputs {
            pre_state_root: pre,
            post_state_root: [0u8; 32],
            batch_commitment: [0u8; 32],
            batch_size: 100,
            prover_ids: [101, 102, 103],
            proof_system_ids: [1, 2, 3],
            quorum_count: 3,
        };
        let json = Groth16Prover::build_witness_json(&inputs);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["preStateRoot"].as_str().unwrap(), "42");
        assert_eq!(parsed["batchSize"].as_str().unwrap(), "100");
        assert_eq!(parsed["proverIds"][0].as_str().unwrap(), "101");
        assert_eq!(parsed["proofSystemIds"][1].as_str().unwrap(), "2");
        assert_eq!(parsed["quorumCount"].as_str().unwrap(), "3");
    }

    #[test]
    fn parse_public_signals_valid() {
        let json = r#"["12345", "67890"]"#;
        let signals = Groth16Prover::parse_public_signals(json).unwrap();
        assert_eq!(field_bytes_to_decimal(&signals[0]), "12345");
        assert_eq!(field_bytes_to_decimal(&signals[1]), "67890");
    }

    #[test]
    fn parse_public_signals_insufficient() {
        let json = r#"["12345"]"#;
        assert!(Groth16Prover::parse_public_signals(json).is_err());
    }

    #[test]
    #[ignore = "requires snarkjs installed and circuit artifacts"]
    fn groth16_prove_real() {
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

        let prover = Groth16Prover::new(
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

        let output = prover.prove(&inputs).unwrap();
        assert_eq!(output.proof_data.len(), GROTH16_PROOF_BYTES);
        assert_eq!(output.proof_system, ProofSystemId::Groth16);

        // Verify public signals match Poseidon computation from aggregation layer
        let stf = worldline_halo2_circuit::poseidon_compress_3(pre, post, batch);
        assert_eq!(output.public_signals[0], stf.to_repr());

        // Verify proverSetDigest matches Poseidon computation
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

    #[test]
    #[ignore = "requires snarkjs installed and circuit artifacts"]
    fn groth16_prove_boundary_batch_size() {
        use halo2curves::bn256::Fr;
        use halo2curves::group::ff::PrimeField;

        let prover = Groth16Prover::new(
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

        // Test batch_size = 1 (minimum)
        let inputs = StfInputs {
            pre_state_root: Fr::from(1u64).to_repr(),
            post_state_root: Fr::from(2u64).to_repr(),
            batch_commitment: Fr::from(3u64).to_repr(),
            batch_size: 1,
            prover_ids: [1, 2, 3],
            proof_system_ids: [1, 2, 3],
            quorum_count: 1,
        };
        let output = prover.prove(&inputs).unwrap();
        assert_eq!(output.proof_data.len(), GROTH16_PROOF_BYTES);

        // Test batch_size = 1024 (maximum)
        let inputs_max = StfInputs {
            batch_size: 1024,
            ..inputs
        };
        let output_max = prover.prove(&inputs_max).unwrap();
        assert_eq!(output_max.proof_data.len(), GROTH16_PROOF_BYTES);
    }
}
