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
/// Proof format: 832 bytes matching PlonkZkAdapter.sol on-chain expectation:
///   uint256[24] proof words (768 bytes) + stfCommitment (32) + proverSetDigest (32)
///
/// The 24 uint256 proof words encode:
///   A      (words  0-1 , bytes   0-63 ): G1 point
///   B      (words  2-3 , bytes  64-127): G1 point
///   C      (words  4-5 , bytes 128-191): G1 point
///   Z      (words  6-7 , bytes 192-255): G1 point
///   T1     (words  8-9 , bytes 256-319): G1 point
///   T2     (words 10-11, bytes 320-383): G1 point
///   T3     (words 12-13, bytes 384-447): G1 point
///   Wxi    (words 14-15, bytes 448-511): G1 point
///   Wxiw   (words 16-17, bytes 512-575): G1 point
///   eval_a (word  18   , bytes 576-607): Fr scalar
///   eval_b (word  19   , bytes 608-639): Fr scalar
///   eval_c (word  20   , bytes 640-671): Fr scalar
///   eval_s1(word  21   , bytes 672-703): Fr scalar
///   eval_s2(word  22   , bytes 704-735): Fr scalar
///   eval_zw(word  23   , bytes 736-767): Fr scalar
///   stfCommitment   (bytes 768-799): uint256
///   proverSetDigest (bytes 800-831): uint256
///
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

    /// Parse 832-byte Plonk proof into snarkjs JSON format.
    ///
    /// The first 768 bytes are the 24 uint256 proof words; the last 64 bytes
    /// are stfCommitment and proverSetDigest (metadata carried alongside).
    fn proof_to_json(proof_data: &[u8]) -> String {
        // G1 points (each: 2 × 32-byte field elements = 64 bytes)
        let a_x = Self::to_hex(&proof_data[0..32]);
        let a_y = Self::to_hex(&proof_data[32..64]);
        let b_x = Self::to_hex(&proof_data[64..96]);
        let b_y = Self::to_hex(&proof_data[96..128]);
        let c_x = Self::to_hex(&proof_data[128..160]);
        let c_y = Self::to_hex(&proof_data[160..192]);
        let z_x = Self::to_hex(&proof_data[192..224]);
        let z_y = Self::to_hex(&proof_data[224..256]);
        let t1_x = Self::to_hex(&proof_data[256..288]);
        let t1_y = Self::to_hex(&proof_data[288..320]);
        let t2_x = Self::to_hex(&proof_data[320..352]);
        let t2_y = Self::to_hex(&proof_data[352..384]);
        let t3_x = Self::to_hex(&proof_data[384..416]);
        let t3_y = Self::to_hex(&proof_data[416..448]);
        let wxi_x = Self::to_hex(&proof_data[448..480]);
        let wxi_y = Self::to_hex(&proof_data[480..512]);
        let wxiw_x = Self::to_hex(&proof_data[512..544]);
        let wxiw_y = Self::to_hex(&proof_data[544..576]);
        // Fr scalars (each: 32 bytes)
        let eval_a = Self::to_hex(&proof_data[576..608]);
        let eval_b = Self::to_hex(&proof_data[608..640]);
        let eval_c = Self::to_hex(&proof_data[640..672]);
        let eval_s1 = Self::to_hex(&proof_data[672..704]);
        let eval_s2 = Self::to_hex(&proof_data[704..736]);
        let eval_zw = Self::to_hex(&proof_data[736..768]);

        format!(
            concat!(
                r#"{{"A":["0x{a_x}","0x{a_y}","1"],"#,
                r#""B":["0x{b_x}","0x{b_y}","1"],"#,
                r#""C":["0x{c_x}","0x{c_y}","1"],"#,
                r#""Z":["0x{z_x}","0x{z_y}","1"],"#,
                r#""T1":["0x{t1_x}","0x{t1_y}","1"],"#,
                r#""T2":["0x{t2_x}","0x{t2_y}","1"],"#,
                r#""T3":["0x{t3_x}","0x{t3_y}","1"],"#,
                r#""Wxi":["0x{wxi_x}","0x{wxi_y}","1"],"#,
                r#""Wxiw":["0x{wxiw_x}","0x{wxiw_y}","1"],"#,
                r#""eval_a":"0x{eval_a}","#,
                r#""eval_b":"0x{eval_b}","#,
                r#""eval_c":"0x{eval_c}","#,
                r#""eval_s1":"0x{eval_s1}","#,
                r#""eval_s2":"0x{eval_s2}","#,
                r#""eval_zw":"0x{eval_zw}","#,
                r#""protocol":"plonk","curve":"bn128"}}"#
            ),
            a_x = a_x,
            a_y = a_y,
            b_x = b_x,
            b_y = b_y,
            c_x = c_x,
            c_y = c_y,
            z_x = z_x,
            z_y = z_y,
            t1_x = t1_x,
            t1_y = t1_y,
            t2_x = t2_x,
            t2_y = t2_y,
            t3_x = t3_x,
            t3_y = t3_y,
            wxi_x = wxi_x,
            wxi_y = wxi_y,
            wxiw_x = wxiw_x,
            wxiw_y = wxiw_y,
            eval_a = eval_a,
            eval_b = eval_b,
            eval_c = eval_c,
            eval_s1 = eval_s1,
            eval_s2 = eval_s2,
            eval_zw = eval_zw,
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

        let pid = std::process::id();
        let tmp = std::env::temp_dir();
        let proof_path = tmp.join(format!("worldline_plonk_proof_{pid}.json"));
        let pub_path = tmp.join(format!("worldline_plonk_public_{pid}.json"));

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
            .args(["snarkjs", "plonk", "verify", vkey_str, pub_str, proof_str])
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
        832
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
                expected: 832,
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
    fn expected_length_is_832() {
        let v = make_verifier();
        assert_eq!(v.expected_proof_length(), 832);
    }

    #[test]
    fn proof_to_json_contains_expected_fields() {
        let proof_data = vec![0xcdu8; 832];
        let json = PlonkVerifier::proof_to_json(&proof_data);
        assert!(json.contains("\"A\""));
        assert!(json.contains("\"B\""));
        assert!(json.contains("\"C\""));
        assert!(json.contains("\"Z\""));
        assert!(json.contains("\"T1\""));
        assert!(json.contains("\"T2\""));
        assert!(json.contains("\"T3\""));
        assert!(json.contains("\"Wxi\""));
        assert!(json.contains("\"Wxiw\""));
        assert!(json.contains("\"eval_a\""));
        assert!(json.contains("\"eval_zw\""));
        assert!(json.contains("\"plonk\""));
        assert!(json.contains("\"bn128\""));
    }

    #[test]
    #[ignore = "requires snarkjs installed"]
    fn verify_real_proof() {
        let v = make_verifier();
        let proof = vec![0u8; 832];
        let _ = v.verify(&proof, &[]);
    }
}
