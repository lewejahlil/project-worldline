#![allow(dead_code)]

use crate::types::ProofSystemId;
use crate::verifiers::traits::{ProofVerifier, VerificationError};
use std::path::PathBuf;

/// Off-chain Halo2 verifier.
///
/// Approach: native `halo2_proofs` (if dependency available) or subprocess fallback.
///
/// Since `halo2_proofs` requires a git dependency (PSE fork), this implementation
/// provides a subprocess fallback. Real verification tests are marked #[ignore].
///
/// Proof format: 1536 bytes (KZG proof, k=8 BN254)
pub struct Halo2Verifier {
    params_path: PathBuf,
    vkey_path: PathBuf,
}

impl Halo2Verifier {
    #[must_use]
    pub fn new(params_path: PathBuf, vkey_path: PathBuf) -> Self {
        Self {
            params_path,
            vkey_path,
        }
    }

    /// Encode a byte slice as a lowercase hex string.
    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
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

impl ProofVerifier for Halo2Verifier {
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

        // Write proof + public inputs to temp files, call a halo2 verify helper
        let pid = std::process::id();
        let tmp = std::env::temp_dir();
        let proof_path = tmp.join(format!("worldline_halo2_proof_{pid}.bin"));
        let pub_path = tmp.join(format!("worldline_halo2_public_{pid}.json"));

        std::fs::write(&proof_path, proof_data)
            .map_err(|e| VerificationError::BackendError(e.to_string()))?;

        let pub_json = Self::public_inputs_to_json(public_inputs);
        std::fs::write(&pub_path, pub_json)
            .map_err(|e| VerificationError::BackendError(e.to_string()))?;

        let params_str = self.params_path.to_str().ok_or_else(|| {
            VerificationError::BackendError("params path is not valid UTF-8".to_string())
        })?;
        let vkey_str = self.vkey_path.to_str().ok_or_else(|| {
            VerificationError::BackendError("vkey path is not valid UTF-8".to_string())
        })?;
        let proof_str = proof_path.to_str().ok_or_else(|| {
            VerificationError::BackendError("temp path is not valid UTF-8".to_string())
        })?;
        let pub_str = pub_path.to_str().ok_or_else(|| {
            VerificationError::BackendError("temp path is not valid UTF-8".to_string())
        })?;

        // Attempt to call halo2-verify helper binary or script
        let output = std::process::Command::new("cargo")
            .args([
                "run",
                "--bin",
                "halo2-verify",
                "--",
                params_str,
                vkey_str,
                proof_str,
                pub_str,
            ])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                Ok(stdout.trim() == "VALID")
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(VerificationError::VerificationFailed {
                    reason: stderr.to_string(),
                })
            }
            Err(_) => Err(VerificationError::BackendError(
                "halo2 verify helper not available; mark tests as #[ignore]".to_string(),
            )),
        }
    }

    fn proof_system_id(&self) -> ProofSystemId {
        ProofSystemId::Halo2
    }

    fn expected_proof_length(&self) -> usize {
        1536
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_verifier() -> Halo2Verifier {
        Halo2Verifier::new(
            PathBuf::from("/home/user/project-worldline/circuits/zkeys/kzg_params.bin"),
            PathBuf::from(
                "/home/user/project-worldline/circuits/zkeys/worldline_stf_halo2_vkey.bin",
            ),
        )
    }

    #[test]
    fn rejects_wrong_proof_length() {
        let v = make_verifier();
        let err = v.verify(&[0u8; 100], &[]).unwrap_err();
        assert!(matches!(
            err,
            VerificationError::InvalidLength {
                expected: 1536,
                actual: 100
            }
        ));
    }

    #[test]
    fn proof_system_id_is_halo2() {
        let v = make_verifier();
        assert_eq!(v.proof_system_id(), ProofSystemId::Halo2);
    }

    #[test]
    fn expected_length_is_1536() {
        let v = make_verifier();
        assert_eq!(v.expected_proof_length(), 1536);
    }

    #[test]
    #[ignore = "requires halo2-verify helper binary"]
    fn verify_real_proof() {
        let v = make_verifier();
        let proof = vec![0u8; 1536];
        let _ = v.verify(&proof, &[]);
    }
}
