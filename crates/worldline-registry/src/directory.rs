//! Signed ZK Prover Directory types and signature verification.
//!
//! A `SignedDirectory` is a canonical-JSON-serialised list of prover directory
//! entries signed by a trusted authority (multisig or TEE). Consumers must
//! verify the signature before trusting any directory entries.
//!
//! Signature format: EIP-191 `personal_sign` over `keccak256(canonical_json(entries))`.
//! The 65-byte signature is `(r ‖ s ‖ v)` where `v ∈ {0, 1}` (or `{27, 28}`).

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;

use crate::canonical::canonical_keccak;
use crate::selection::DirectoryEntry;

// ── Types ─────────────────────────────────────────────────────────────────────

/// A signed prover directory snapshot.
///
/// The `entries` array is serialised to canonical JSON, hashed with Keccak-256,
/// and then signed (secp256k1 / EIP-191 `personal_sign`) by the `signer_address`.
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

/// Verify the EIP-191 `personal_sign` signature on a [`SignedDirectory`].
///
/// # Algorithm
///
/// 1. Compute `canonical_json(directory.entries)`.
/// 2. Compute `data_hash = keccak256(canonical_json_bytes)`.
/// 3. Compute the EIP-191 digest:
///    `eth_hash = keccak256("\x19Ethereum Signed Message:\n32" ‖ data_hash)`.
/// 4. Decode `directory.signature` from hex into 65 bytes `(r ‖ s ‖ v)`.
/// 5. Recover the secp256k1 [`VerifyingKey`] from `(eth_hash, r, s, v)`.
/// 6. Derive the Ethereum address: last 20 bytes of `keccak256(uncompressed_pubkey[1..])`.
/// 7. Compare (case-insensitive) against `directory.signer_address`.
///
/// # Returns
///
/// * `Ok(true)` — signature is valid and matches `signer_address`.
/// * `Err(DirectoryError::SignerMismatch)` — valid signature, wrong claimed address.
/// * `Err(DirectoryError::InvalidEncoding)` — hex decode failure or wrong length.
/// * `Err(DirectoryError::RecoveryFailed)` — k256 recovery error.
pub fn verify_directory_signature(directory: &SignedDirectory) -> Result<bool, DirectoryError> {
    // Step 1–2: Canonical JSON → Keccak-256 data hash.
    let entries_value = serde_json::to_value(&directory.entries)
        .map_err(|e| DirectoryError::RecoveryFailed(format!("failed to serialise entries: {e}")))?;
    let data_hash = canonical_keccak(&entries_value);

    // Step 3: EIP-191 personal_sign prefix.
    let eth_hash = eip191_hash(&data_hash);

    // Step 4: Decode hex signature → 65 bytes (r[32] ‖ s[32] ‖ v[1]).
    let sig_bytes = hex::decode(directory.signature.trim_start_matches("0x"))
        .map_err(|e| DirectoryError::InvalidEncoding(format!("hex decode failed: {e}")))?;
    if sig_bytes.len() != 65 {
        return Err(DirectoryError::InvalidEncoding(format!(
            "expected 65-byte signature, got {}",
            sig_bytes.len()
        )));
    }

    let (rs_bytes, v_byte) = sig_bytes.split_at(64);
    // v can be 0/1 (raw) or 27/28 (EIP-155 legacy).
    let v = match v_byte[0] {
        0 | 27 => 0u8,
        1 | 28 => 1u8,
        other => {
            return Err(DirectoryError::InvalidEncoding(format!(
                "invalid recovery id byte: {other}"
            )))
        }
    };

    // Step 5: Recover the public key.
    let signature = Signature::from_slice(rs_bytes)
        .map_err(|e| DirectoryError::RecoveryFailed(format!("invalid signature bytes: {e}")))?;
    let recovery_id = RecoveryId::new(v != 0, false);
    let verifying_key = VerifyingKey::recover_from_prehash(&eth_hash, &signature, recovery_id)
        .map_err(|e| DirectoryError::RecoveryFailed(format!("key recovery failed: {e}")))?;

    // Step 6: Derive the Ethereum address from the uncompressed public key.
    let recovered_address = pubkey_to_eth_address(&verifying_key);

    // Step 7: Case-insensitive comparison.
    let expected = directory
        .signer_address
        .trim_start_matches("0x")
        .to_lowercase();
    let recovered = hex::encode(recovered_address);

    if expected != recovered {
        return Err(DirectoryError::SignerMismatch {
            expected: format!("0x{expected}"),
            recovered: format!("0x{recovered}"),
        });
    }

    Ok(true)
}

/// Compute the EIP-191 `personal_sign` hash for a 32-byte message.
///
/// `keccak256("\x19Ethereum Signed Message:\n32" ‖ message)`
fn eip191_hash(message: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"\x19Ethereum Signed Message:\n32");
    hasher.update(message);
    hasher.finalize().into()
}

/// Derive the 20-byte Ethereum address from an secp256k1 [`VerifyingKey`].
///
/// The address is `keccak256(uncompressed_pubkey_bytes[1..])[12..]` — i.e. the
/// last 20 bytes of the Keccak-256 hash of the 64-byte uncompressed public key
/// (with the `0x04` prefix stripped).
fn pubkey_to_eth_address(key: &VerifyingKey) -> [u8; 20] {
    let uncompressed = key.to_encoded_point(false);
    let pubkey_bytes = &uncompressed.as_bytes()[1..]; // strip 0x04 prefix
    let hash: [u8; 32] = Keccak256::digest(pubkey_bytes).into();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selection::HealthStatus;
    use k256::ecdsa::SigningKey;

    /// Build sample directory entries used across tests.
    fn sample_entries() -> Vec<DirectoryEntry> {
        vec![
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
        ]
    }

    /// Create a validly-signed directory from a given signing key and entries.
    fn sign_directory(signing_key: &SigningKey, entries: Vec<DirectoryEntry>) -> SignedDirectory {
        let entries_value = serde_json::to_value(&entries).unwrap();
        let data_hash = canonical_keccak(&entries_value);
        let eth_hash = eip191_hash(&data_hash);

        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&eth_hash)
            .expect("signing should succeed");

        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(&signature.to_bytes());
        sig_bytes.push(recovery_id.to_byte());

        let signer_address = {
            let vk = signing_key.verifying_key();
            let addr = pubkey_to_eth_address(vk);
            format!("0x{}", hex::encode(addr))
        };

        SignedDirectory {
            version: "1.0.0".to_string(),
            entries,
            signature: format!("0x{}", hex::encode(&sig_bytes)),
            signer_address,
        }
    }

    /// Deterministic test signing key (Hardhat account #0 private key).
    fn test_signing_key() -> SigningKey {
        let sk_bytes =
            hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap();
        SigningKey::from_bytes((&sk_bytes[..]).into()).unwrap()
    }

    // ── Preserved existing tests ─────────────────────────────────────────────

    #[test]
    fn signed_directory_serialises_and_deserialises() {
        let sk = test_signing_key();
        let dir = sign_directory(&sk, sample_entries());
        let json = serde_json::to_string(&dir).unwrap();
        let parsed: SignedDirectory = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, dir.version);
        assert_eq!(parsed.entries.len(), dir.entries.len());
        assert_eq!(parsed.signer_address, dir.signer_address);
    }

    #[test]
    fn message_hash_is_deterministic() {
        let sk = test_signing_key();
        let dir = sign_directory(&sk, sample_entries());
        let r1 = verify_directory_signature(&dir).unwrap();
        let r2 = verify_directory_signature(&dir).unwrap();
        assert_eq!(r1, r2);
    }

    // ── New CRI-001 tests ────────────────────────────────────────────────────

    #[test]
    fn valid_eip191_signature_returns_ok_true() {
        let sk = test_signing_key();
        let dir = sign_directory(&sk, sample_entries());
        let result = verify_directory_signature(&dir);
        assert!(result.unwrap(), "valid signature should return Ok(true)");
    }

    #[test]
    fn tampered_entry_after_signing_returns_signer_mismatch() {
        let sk = test_signing_key();
        let mut dir = sign_directory(&sk, sample_entries());
        // Tamper with an entry after signing.
        dir.entries[0].prover_id = "evil-prover".to_string();
        let result = verify_directory_signature(&dir);
        assert!(
            matches!(
                result,
                Err(DirectoryError::SignerMismatch { .. }) | Err(DirectoryError::RecoveryFailed(_))
            ),
            "tampered directory should fail verification, got: {result:?}"
        );
    }

    #[test]
    fn malformed_hex_signature_returns_invalid_encoding() {
        let sk = test_signing_key();
        let mut dir = sign_directory(&sk, sample_entries());
        dir.signature = "0xNOTHEX!!!".to_string();
        let result = verify_directory_signature(&dir);
        assert!(
            matches!(result, Err(DirectoryError::InvalidEncoding(_))),
            "malformed hex should return InvalidEncoding, got: {result:?}"
        );
    }

    #[test]
    fn wrong_length_signature_returns_invalid_encoding() {
        let sk = test_signing_key();
        let mut dir = sign_directory(&sk, sample_entries());
        dir.signature = "0xaabbcc".to_string(); // 3 bytes, not 65
        let result = verify_directory_signature(&dir);
        assert!(
            matches!(result, Err(DirectoryError::InvalidEncoding(_))),
            "short signature should return InvalidEncoding, got: {result:?}"
        );
    }

    #[test]
    fn wrong_signer_address_returns_signer_mismatch() {
        let sk = test_signing_key();
        let mut dir = sign_directory(&sk, sample_entries());
        // Valid signature, but claimed signer is different.
        dir.signer_address = "0x0000000000000000000000000000000000000001".to_string();
        let result = verify_directory_signature(&dir);
        assert!(
            matches!(result, Err(DirectoryError::SignerMismatch { .. })),
            "wrong signer address should return SignerMismatch, got: {result:?}"
        );
    }
}
