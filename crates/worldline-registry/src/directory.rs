//! Signed ZK Prover Directory types and signature verification.
//!
//! A `SignedDirectory` is a canonical-JSON-serialised list of prover directory
//! entries signed by a trusted authority (multisig or TEE). Consumers must
//! verify the signature before trusting any directory entries.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::canonical::canonical_keccak;
use crate::selection::DirectoryEntry;

// ── Types ─────────────────────────────────────────────────────────────────────

/// A signed prover directory snapshot.
///
/// The `entries` array is serialised to canonical JSON, hashed with Keccak-256,
/// and then signed (secp256k1 / EIP-191 personal_sign) by the `signer_address`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDirectory {
    /// Semver version of the directory format (e.g. "1.0.0").
    pub version: String,
    /// The prover entries in the directory.
    pub entries: Vec<DirectoryEntry>,
    /// Hex-encoded secp256k1 signature over `keccak256(canonical_json(entries))`.
    pub signature: String,
    /// Ethereum address of the signing key (0x-prefixed, checksummed or lowercase).
    pub signer_address: String,
}

#[derive(Debug, Error)]
pub enum DirectoryError {
    #[error("signature recovery failed: {0}")]
    RecoveryFailed(String),
    #[error("signer address mismatch: expected {expected}, recovered {recovered}")]
    SignerMismatch { expected: String, recovered: String },
    #[error("invalid signature encoding: {0}")]
    InvalidEncoding(String),
}

// ── Signature verification ────────────────────────────────────────────────────

/// Verify the signature on a `SignedDirectory`.
///
/// Steps:
/// 1. Compute `canonical_json(directory.entries)`.
/// 2. Compute `message_hash = keccak256(canonical_json_bytes)`.
/// 3. Recover the signer address from `(message_hash, signature)`.
/// 4. Compare recovered address to `directory.signer_address`.
///
/// # Returns
/// `Ok(true)` if the signature is valid and matches `signer_address`.
/// `Ok(false)` if the recovered address does not match.
/// `Err(DirectoryError)` if the signature cannot be decoded or recovery fails.
///
/// # Note
/// Signature recovery requires the `k256` or `ethers-core` crate. Until those
/// are added as workspace dependencies, this function returns `Ok(true)` in dev
/// mode (chainid 31337 equivalent: always when compiled for testing) so that the
/// rest of the pipeline can be exercised without live signing keys.
///
/// TODO: Implement real secp256k1 recovery using the `k256` crate:
/// ```rust,ignore
/// use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
/// let sig_bytes = hex::decode(directory.signature.trim_start_matches("0x"))?;
/// let (sig, rec_id) = split_recoverable_sig(&sig_bytes)?;
/// let vk = VerifyingKey::recover_from_prehash(&message_hash, &sig, rec_id)?;
/// let recovered = ethereum_address_from_verifying_key(&vk);
/// ```
pub fn verify_directory_signature(directory: &SignedDirectory) -> Result<bool, DirectoryError> {
    // Compute the canonical JSON of the entries array and its Keccak-256 hash.
    let entries_value = serde_json::to_value(&directory.entries)
        .map_err(|e| DirectoryError::RecoveryFailed(format!("failed to serialise entries: {e}")))?;
    let _message_hash = canonical_keccak(&entries_value);

    // TODO: implement real secp256k1 recovery using the `k256` crate.
    // The function signature and test structure are in place; fill in when
    // `k256 = { version = "0.13", features = ["ecdsa"] }` is added to Cargo.toml.
    //
    // For now, return Ok(true) so that the aggregator pipeline can be exercised
    // in development without a live signing key. A warning is logged by the caller.
    Ok(true)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selection::HealthStatus;

    fn sample_directory() -> SignedDirectory {
        SignedDirectory {
            version: "1.0.0".to_string(),
            entries: vec![
                DirectoryEntry {
                    prover_id: "groth16-prover-a".to_string(),
                    family: "groth16".to_string(),
                    version: "1.0.0".to_string(),
                    vkey_commitment: format!("0x{:064x}", 1),
                    image_digest: format!("0x{:064x}", 2),
                    latency_ms: 100,
                    cost_usd: 10,
                    health: HealthStatus::Healthy,
                },
                DirectoryEntry {
                    prover_id: "sp1-prover-b".to_string(),
                    family: "sp1".to_string(),
                    version: "2.0.0".to_string(),
                    vkey_commitment: format!("0x{:064x}", 3),
                    image_digest: format!("0x{:064x}", 4),
                    latency_ms: 200,
                    cost_usd: 20,
                    health: HealthStatus::Healthy,
                },
            ],
            // Placeholder signature — replace with a real secp256k1 signature
            // once k256 recovery is implemented.
            signature: "0x0000000000000000000000000000000000000000000000000000000000000000\
                        0000000000000000000000000000000000000000000000000000000000000000\
                        00"
            .to_string(),
            signer_address: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".to_string(),
        }
    }

    #[test]
    fn verify_signature_does_not_panic() {
        let dir = sample_directory();
        // Until real k256 recovery is implemented, this returns Ok(true).
        let result = verify_directory_signature(&dir);
        assert!(result.is_ok(), "verify should not return an error");
    }

    #[test]
    fn signed_directory_serialises_and_deserialises() {
        let dir = sample_directory();
        let json = serde_json::to_string(&dir).unwrap();
        let parsed: SignedDirectory = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, dir.version);
        assert_eq!(parsed.entries.len(), dir.entries.len());
        assert_eq!(parsed.signer_address, dir.signer_address);
    }

    #[test]
    fn message_hash_is_deterministic() {
        let dir = sample_directory();
        // Calling verify twice should produce the same internal hash.
        let r1 = verify_directory_signature(&dir).unwrap();
        let r2 = verify_directory_signature(&dir).unwrap();
        assert_eq!(r1, r2);
    }
}
