#![allow(dead_code)]

use crate::types::ProofSystemId;
use crate::verifiers::traits::{ProofVerifier, VerificationError};
use std::path::PathBuf;

/// Off-chain Groth16 verifier using snarkjs subprocess.
///
/// Approach: subprocess (snarkjs groth16 verify)
/// - Writes vkey, proof, and public inputs as JSON to temp files
/// - Calls `npx snarkjs groth16 verify`
/// - Parses stdout for "OK!"
///
/// Real verification tests are marked #[ignore] since snarkjs must be installed.
pub struct Groth16Verifier {
    vkey_path: PathBuf,
}

impl Groth16Verifier {
    #[must_use]
    pub fn new(vkey_path: PathBuf) -> Self {
        Self { vkey_path }
    }

    /// Encode a byte slice as a lowercase hex string.
    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parse 320-byte BN254 Groth16 proof into snarkjs JSON format.
    /// Format: pA(64) + pB(128) + pC(64) + stfCommitment(32) + proverSetDigest(32) = 320
    fn proof_to_json(proof_data: &[u8]) -> String {
        // pA: bytes 0..64 (G1 point: 2x32 bytes)
        let pa_x = Self::to_hex(&proof_data[0..32]);
        let pa_y = Self::to_hex(&proof_data[32..64]);
        // pB: bytes 64..192 (G2 point: 2x2x32 bytes)
        let pb_x0 = Self::to_hex(&proof_data[64..96]);
        let pb_x1 = Self::to_hex(&proof_data[96..128]);
        let pb_y0 = Self::to_hex(&proof_data[128..160]);
        let pb_y1 = Self::to_hex(&proof_data[160..192]);
        // pC: bytes 192..256 (G1 point)
        let pc_x = Self::to_hex(&proof_data[192..224]);
        let pc_y = Self::to_hex(&proof_data[224..256]);

        format!(
            r#"{{"pi_a":["0x{pa_x}","0x{pa_y}","1"],"pi_b":[["0x{pb_x0}","0x{pb_x1}"],["0x{pb_y0}","0x{pb_y1}"],["1","0"]],"pi_c":["0x{pc_x}","0x{pc_y}","1"],"protocol":"groth16","curve":"bn128"}}"#
        )
    }

    /// Encode public inputs as a JSON array of hex strings.
    fn public_inputs_to_json(public_inputs: &[[u8; 32]]) -> String {
        let entries: Vec<String> = public_inputs
            .iter()
            .map(|inp| format!("\"0x{}\"", Self::to_hex(inp)))
            .collect();
        format!("[{}]", entries.join(","))
    }
}

impl ProofVerifier for Groth16Verifier {
    fn verify(
        &self,
        proof_data: &[u8],
        public_inputs: &[[u8; 32]],
    ) -> Result<bool, VerificationError> {
        let expected = self.expected_proof_length();
        if proof_data.len() != expected {
            return Err(VerificationError::InvalidLength {
                expected,
                actual: proof_data.len(),
            });
        }

        let proof_json = Self::proof_to_json(proof_data);
        let pub_json = Self::public_inputs_to_json(public_inputs);

        let pid = std::process::id();
        let tmp = std::env::temp_dir();
        let proof_path = tmp.join(format!("worldline_groth16_proof_{pid}.json"));
        let pub_path = tmp.join(format!("worldline_groth16_public_{pid}.json"));

        std::fs::write(&proof_path, proof_json)
            .map_err(|e| VerificationError::BackendError(e.to_string()))?;
        std::fs::write(&pub_path, pub_json)
            .map_err(|e| VerificationError::BackendError(e.to_string()))?;

        let vkey_str = self.vkey_path.to_str().ok_or_else(|| {
            VerificationError::BackendError("vkey path is not valid UTF-8".to_string())
        })?;
        let pub_str = pub_path.to_str().ok_or_else(|| {
            VerificationError::BackendError("temp path is not valid UTF-8".to_string())
        })?;
        let proof_str = proof_path.to_str().ok_or_else(|| {
            VerificationError::BackendError("temp path is not valid UTF-8".to_string())
        })?;

        let output = std::process::Command::new("npx")
            .args(["snarkjs", "groth16", "verify", vkey_str, pub_str, proof_str])
            .output()
            .map_err(|e| VerificationError::BackendError(format!("snarkjs not found: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("OK!") {
            Ok(true)
        } else if output.status.success() {
            Ok(false)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(VerificationError::VerificationFailed {
                reason: stderr.to_string(),
            })
        }
    }

    fn proof_system_id(&self) -> ProofSystemId {
        ProofSystemId::Groth16
    }

    fn expected_proof_length(&self) -> usize {
        320
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_verifier() -> Groth16Verifier {
        Groth16Verifier::new(PathBuf::from(
            "/home/user/project-worldline/circuits/zkeys/worldline_stf_vkey.json",
        ))
    }

    #[test]
    fn rejects_wrong_proof_length() {
        let v = make_verifier();
        let err = v.verify(&[0u8; 100], &[]).unwrap_err();
        assert!(matches!(
            err,
            VerificationError::InvalidLength {
                expected: 320,
                actual: 100
            }
        ));
    }

    #[test]
    fn proof_system_id_is_groth16() {
        let v = make_verifier();
        assert_eq!(v.proof_system_id(), ProofSystemId::Groth16);
    }

    #[test]
    fn expected_length_is_320() {
        let v = make_verifier();
        assert_eq!(v.expected_proof_length(), 320);
    }

    #[test]
    fn proof_to_json_structure() {
        let proof_data = vec![0xabu8; 320];
        let json = Groth16Verifier::proof_to_json(&proof_data);
        assert!(json.contains("\"pi_a\""));
        assert!(json.contains("\"pi_b\""));
        assert!(json.contains("\"pi_c\""));
        assert!(json.contains("\"groth16\""));
        assert!(json.contains("\"bn128\""));
    }

    #[test]
    #[ignore = "requires snarkjs installed"]
    fn verify_real_proof() {
        let v = make_verifier();
        let proof = vec![0u8; 320];
        let _ = v.verify(&proof, &[]);
    }
}
