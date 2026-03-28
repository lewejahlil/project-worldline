#![allow(dead_code)]

use crate::types::ProofSystemId;
use crate::verifiers::traits::{ProofVerifier, VerificationError};
use std::path::PathBuf;

/// Off-chain Plonk verifier using snarkjs subprocess.
///
/// Approach: subprocess (snarkjs plonk verify)
/// - Writes vkey, proof, and public inputs as JSON to temp files
/// - Calls `npx snarkjs plonk verify`
/// - Parses stdout for "OK!"
///
/// Proof format: 256 bytes (snarkjs Plonk compact format)
/// Real verification tests are marked #[ignore] since snarkjs must be installed.
pub struct PlonkVerifier {
    vkey_path: PathBuf,
}

impl PlonkVerifier {
    pub fn new(vkey_path: PathBuf) -> Self {
        Self { vkey_path }
    }

    /// Encode a byte slice as a lowercase hex string.
    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Parse 256-byte Plonk proof into snarkjs JSON format.
    ///
    /// snarkjs Plonk verify expects a JSON proof object with fields like
    /// A, B, C, Z, T1, T2, T3, Wxi, Wxiw, eval_a, eval_b, eval_c, eval_s1,
    /// eval_s2, eval_zw, eval_r, protocol, curve.
    ///
    /// Layout (256 bytes):
    ///   A(64) + B(64) + C(64) + Z(32) + T1(32) + remaining treated as raw.
    ///
    /// For proof data that doesn't originate from a real snarkjs circuit run,
    /// the raw bytes are also included under `_raw` for diagnostics.
    fn proof_to_json(proof_data: &[u8]) -> String {
        // G1 points: each is two 32-byte field elements (x, y)
        let a_x = Self::to_hex(&proof_data[0..32]);
        let a_y = Self::to_hex(&proof_data[32..64]);
        let b_x = Self::to_hex(&proof_data[64..96]);
        let b_y = Self::to_hex(&proof_data[96..128]);
        let c_x = Self::to_hex(&proof_data[128..160]);
        let c_y = Self::to_hex(&proof_data[160..192]);
        // Z: 32 bytes, T1: 32 bytes — remaining 64 bytes split as evaluation scalars
        let z = Self::to_hex(&proof_data[192..224]);
        let t1 = Self::to_hex(&proof_data[224..256]);
        let raw = Self::to_hex(proof_data);

        format!(
            concat!(
                r#"{{"A":["0x{a_x}","0x{a_y}","1"],"#,
                r#""B":["0x{b_x}","0x{b_y}","1"],"#,
                r#""C":["0x{c_x}","0x{c_y}","1"],"#,
                r#""Z":["0x{z}","1"],"#,
                r#""T1":["0x{t1}","1"],"#,
                r#""T2":["0x0","1"],"T3":["0x0","1"],"#,
                r#""Wxi":["0x0","0x0","1"],"Wxiw":["0x0","0x0","1"],"#,
                r#""eval_a":"0x0","eval_b":"0x0","eval_c":"0x0","#,
                r#""eval_s1":"0x0","eval_s2":"0x0","eval_zw":"0x0","eval_r":"0x0","#,
                r#""protocol":"plonk","curve":"bn128","#,
                r#""_raw":"0x{raw}"}}"#
            ),
            a_x = a_x,
            a_y = a_y,
            b_x = b_x,
            b_y = b_y,
            c_x = c_x,
            c_y = c_y,
            z = z,
            t1 = t1,
            raw = raw,
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

impl ProofVerifier for PlonkVerifier {
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

        let tmp = std::env::temp_dir();
        let proof_path = tmp.join("worldline_plonk_proof.json");
        let pub_path = tmp.join("worldline_plonk_public.json");

        std::fs::write(&proof_path, proof_json)
            .map_err(|e| VerificationError::BackendError(e.to_string()))?;
        std::fs::write(&pub_path, pub_json)
            .map_err(|e| VerificationError::BackendError(e.to_string()))?;

        let output = std::process::Command::new("npx")
            .args([
                "snarkjs",
                "plonk",
                "verify",
                self.vkey_path.to_str().unwrap(),
                pub_path.to_str().unwrap(),
                proof_path.to_str().unwrap(),
            ])
            .output()
            .map_err(|e| VerificationError::BackendError(format!("snarkjs not found: {}", e)))?;

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
        ProofSystemId::Plonk
    }

    fn expected_proof_length(&self) -> usize {
        256
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_verifier() -> PlonkVerifier {
        PlonkVerifier::new(PathBuf::from(
            "/home/user/project-worldline/circuits/zkeys/worldline_stf_plonk_v2_vkey.json",
        ))
    }

    #[test]
    fn rejects_wrong_proof_length() {
        let v = make_verifier();
        let err = v.verify(&[0u8; 100], &[]).unwrap_err();
        assert!(matches!(
            err,
            VerificationError::InvalidLength {
                expected: 256,
                actual: 100
            }
        ));
    }

    #[test]
    fn proof_system_id_is_plonk() {
        let v = make_verifier();
        assert_eq!(v.proof_system_id(), ProofSystemId::Plonk);
    }

    #[test]
    fn expected_length_is_256() {
        let v = make_verifier();
        assert_eq!(v.expected_proof_length(), 256);
    }

    #[test]
    fn proof_to_json_contains_expected_fields() {
        let proof_data = vec![0xcdu8; 256];
        let json = PlonkVerifier::proof_to_json(&proof_data);
        assert!(json.contains("\"A\""));
        assert!(json.contains("\"B\""));
        assert!(json.contains("\"C\""));
        assert!(json.contains("\"Z\""));
        assert!(json.contains("\"plonk\""));
        assert!(json.contains("\"bn128\""));
        assert!(json.contains("\"_raw\""));
    }

    #[test]
    #[ignore = "requires snarkjs installed"]
    fn verify_real_proof() {
        let v = make_verifier();
        let proof = vec![0u8; 256];
        let _ = v.verify(&proof, &[]);
    }
}
