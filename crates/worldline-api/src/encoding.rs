//! Calldata encoding for on-chain proof submission.
//!
//! Encodes proof bytes and public inputs into the exact ABI format expected by
//! the Solidity adapter contracts (`Groth16ZkAdapter`, `PlonkZkAdapter`,
//! `Halo2ZkAdapter`) and `WorldlineFinalizer`.
//!
//! # Proof encoding formats
//!
//! | System  | ID | ABI Encoding                                                         | Bytes |
//! |---------|----|----------------------------------------------------------------------|-------|
//! | Groth16 | 1  | `abi.encode(uint256[2], uint256[2][2], uint256[2], uint256, uint256)` | 320   |
//! | Plonk   | 2  | `abi.encode(uint256[24], uint256, uint256)`                           | 832   |
//! | Halo2   | 3  | `abi.encode(bytes, uint256, uint256)`                                | ~2144 |
//!
//! # publicInputs layout (8 words / 256 bytes)
//!
//! | Word | Field                 | Type    |
//! |------|-----------------------|---------|
//! | 0    | stfCommitment         | bytes32 |
//! | 1    | l2Start               | uint256 |
//! | 2    | l2End                 | uint256 |
//! | 3    | outputRoot            | bytes32 |
//! | 4    | l1BlockHash           | bytes32 |
//! | 5    | domainSeparator       | bytes32 |
//! | 6    | windowCloseTimestamp   | uint256 |
//! | 7    | submissionBinding     | bytes32 |
//!
//! Word 7 = `keccak256(abi.encode(words 1–6))`.

use crate::error::EncodingError;
use crate::types::ProofRequest;
use tiny_keccak::{Hasher, Keccak};
use worldline_recursion::ProofSystemId;

/// Expected raw proof byte lengths per proof system.
pub const GROTH16_PROOF_BYTES: usize = 320;
pub const PLONK_PROOF_BYTES: usize = 832;
pub const HALO2_RAW_PROOF_BYTES: usize = 2016;

/// Encode a 32-byte value as a left-padded ABI uint256/bytes32 word.
///
/// For BN254 field elements stored in little-endian, this reverses to big-endian
/// and left-pads to 32 bytes. For values already in big-endian (like keccak output),
/// this is a no-op copy.
fn bytes32_to_abi_word(bytes: &[u8; 32]) -> [u8; 32] {
    *bytes
}

/// Encode a u64 as a 32-byte big-endian ABI uint256 word.
fn u64_to_abi_word(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&value.to_be_bytes());
    word
}

/// Compute keccak256 of the given data.
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

// ── Public Inputs Encoding ───────────────────────────────────────────────────

/// Encode the 256-byte `publicInputs` array for `WorldlineFinalizer`.
///
/// Computes `submissionBinding` (word 7) automatically from words 1–6.
/// The `stf_commitment` parameter should be the Poseidon circuit output
/// (from `PipelineOutput.stf_commitment`).
pub fn encode_public_inputs(
    stf_commitment: &[u8; 32],
    request: &ProofRequest,
) -> Result<Vec<u8>, EncodingError> {
    // Words 1–6 as ABI-encoded
    let w1 = u64_to_abi_word(request.l2_start);
    let w2 = u64_to_abi_word(request.l2_end);
    let w3 = bytes32_to_abi_word(&request.output_root);
    let w4 = bytes32_to_abi_word(&request.l1_block_hash);
    let w5 = bytes32_to_abi_word(&request.domain_separator);
    let w6 = u64_to_abi_word(request.window_close_timestamp);

    // submissionBinding = keccak256(abi.encode(words 1–6))
    // abi.encode concatenates the 6 words (each 32 bytes = 192 bytes total)
    let mut binding_preimage = Vec::with_capacity(192);
    binding_preimage.extend_from_slice(&w1);
    binding_preimage.extend_from_slice(&w2);
    binding_preimage.extend_from_slice(&w3);
    binding_preimage.extend_from_slice(&w4);
    binding_preimage.extend_from_slice(&w5);
    binding_preimage.extend_from_slice(&w6);
    let submission_binding = keccak256(&binding_preimage);

    // Assemble all 8 words
    let mut public_inputs = Vec::with_capacity(256);
    public_inputs.extend_from_slice(&bytes32_to_abi_word(stf_commitment)); // word 0
    public_inputs.extend_from_slice(&w1); // word 1
    public_inputs.extend_from_slice(&w2); // word 2
    public_inputs.extend_from_slice(&w3); // word 3
    public_inputs.extend_from_slice(&w4); // word 4
    public_inputs.extend_from_slice(&w5); // word 5
    public_inputs.extend_from_slice(&w6); // word 6
    public_inputs.extend_from_slice(&submission_binding); // word 7

    if public_inputs.len() != 256 {
        return Err(EncodingError::PublicInputsLengthMismatch(
            public_inputs.len(),
        ));
    }

    Ok(public_inputs)
}

// ── Proof Encoding ───────────────────────────────────────────────────────────

/// ABI-encode a Groth16 proof for `Groth16ZkAdapter.verify()`.
///
/// Input: 320 raw bytes = pi_a(64) + pi_b(128) + pi_c(64) + stfCommitment(32) + proverSetDigest(32).
/// Output: 320 bytes (same layout — Groth16 uses only static ABI types so raw == ABI-encoded).
///
/// The adapter does `abi.decode(proof, (uint256[2], uint256[2][2], uint256[2], uint256, uint256))`.
/// Since all types are static uint256s, ABI encoding is contiguous 32-byte words — identical to raw.
pub fn encode_groth16_proof(raw_proof: &[u8]) -> Result<Vec<u8>, EncodingError> {
    if raw_proof.len() != GROTH16_PROOF_BYTES {
        return Err(EncodingError::ProofLengthMismatch {
            system: ProofSystemId::Groth16,
            expected: GROTH16_PROOF_BYTES,
            actual: raw_proof.len(),
        });
    }
    Ok(raw_proof.to_vec())
}

/// ABI-encode a Plonk proof for `PlonkZkAdapter.verify()`.
///
/// Input: 832 raw bytes = proof_words(768) + stfCommitment(32) + proverSetDigest(32).
/// Output: 832 bytes (same layout — Plonk uses only static ABI types).
///
/// The adapter does `abi.decode(proof, (uint256[24], uint256, uint256))`.
pub fn encode_plonk_proof(raw_proof: &[u8]) -> Result<Vec<u8>, EncodingError> {
    if raw_proof.len() != PLONK_PROOF_BYTES {
        return Err(EncodingError::ProofLengthMismatch {
            system: ProofSystemId::Plonk,
            expected: PLONK_PROOF_BYTES,
            actual: raw_proof.len(),
        });
    }
    Ok(raw_proof.to_vec())
}

/// ABI-encode a Halo2 proof for `Halo2ZkAdapter.verify()`.
///
/// Input: raw KZG proof bytes (~2016 bytes) + stfCommitment(32-byte LE) + proverSetDigest(32-byte LE).
/// These are provided separately because the raw proof does NOT contain the public signals.
///
/// Output: ABI-encoded `(bytes, uint256, uint256)` with dynamic encoding:
///   - Word 0: offset to bytes data (= 0x60 = 96, since 3 head slots)
///   - Word 1: stfCommitment as uint256
///   - Word 2: proverSetDigest as uint256
///   - Word 3: length of bytes
///   - Words 4+: proof bytes padded to 32-byte boundary
///
/// The adapter does `abi.decode(proof, (bytes, uint256, uint256))`.
pub fn encode_halo2_proof(
    raw_proof_bytes: &[u8],
    stf_commitment: &[u8; 32],
    prover_set_digest: &[u8; 32],
) -> Result<Vec<u8>, EncodingError> {
    // ABI encoding for (bytes, uint256, uint256):
    // Head section (3 words):
    //   [0]  offset to bytes data = 0x60 (96 decimal = 3 * 32)
    //   [1]  stfCommitment
    //   [2]  proverSetDigest
    // Data section:
    //   [3]  length of bytes
    //   [4+] bytes data, padded to 32-byte multiple

    let padded_len = raw_proof_bytes.len().div_ceil(32) * 32;
    let total_len = 3 * 32 + 32 + padded_len; // head + length word + padded data

    let mut encoded = Vec::with_capacity(total_len);

    // Offset to bytes data (3 words = 96 bytes)
    encoded.extend_from_slice(&u64_to_abi_word(96));

    // stfCommitment and proverSetDigest
    encoded.extend_from_slice(&bytes32_to_abi_word(stf_commitment));
    encoded.extend_from_slice(&bytes32_to_abi_word(prover_set_digest));

    // Length of bytes
    encoded.extend_from_slice(&u64_to_abi_word(raw_proof_bytes.len() as u64));

    // Bytes data + zero padding
    encoded.extend_from_slice(raw_proof_bytes);
    let padding = padded_len - raw_proof_bytes.len();
    encoded.extend_from_slice(&vec![0u8; padding]);

    Ok(encoded)
}

/// ABI-encode a proof for the given proof system.
///
/// For Groth16 and Plonk, the raw proof bytes already contain stfCommitment and
/// proverSetDigest as the last two 32-byte words.
///
/// For Halo2, the raw proof bytes do NOT contain public signals — they must be
/// provided separately via `stf_commitment` and `prover_set_digest`.
pub fn encode_proof(
    system: ProofSystemId,
    raw_proof: &[u8],
    stf_commitment: &[u8; 32],
    prover_set_digest: &[u8; 32],
) -> Result<Vec<u8>, EncodingError> {
    match system {
        ProofSystemId::Groth16 => encode_groth16_proof(raw_proof),
        ProofSystemId::Plonk => encode_plonk_proof(raw_proof),
        ProofSystemId::Halo2 => encode_halo2_proof(raw_proof, stf_commitment, prover_set_digest),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> ProofRequest {
        ProofRequest {
            pre_state_root: [0u8; 32],
            post_state_root: [0u8; 32],
            batch_commitment: [0u8; 32],
            batch_size: 100,
            requested_systems: vec![1],
            prover_ids: [101, 102, 103],
            proof_system_ids: [1, 2, 3],
            quorum_count: 1,
            l2_start: 0,
            l2_end: 100,
            output_root: [0u8; 32],
            l1_block_hash: [0u8; 32],
            domain_separator: [0xABu8; 32],
            window_close_timestamp: 1700000000,
        }
    }

    #[test]
    fn public_inputs_is_256_bytes() {
        let request = sample_request();
        let stf = [0x42u8; 32];
        let encoded = encode_public_inputs(&stf, &request).unwrap();
        assert_eq!(encoded.len(), 256);
    }

    #[test]
    fn public_inputs_word_0_is_stf_commitment() {
        let request = sample_request();
        let stf = [0x42u8; 32];
        let encoded = encode_public_inputs(&stf, &request).unwrap();
        assert_eq!(&encoded[0..32], &stf);
    }

    #[test]
    fn public_inputs_word_7_is_keccak_of_words_1_through_6() {
        let request = sample_request();
        let stf = [0x42u8; 32];
        let encoded = encode_public_inputs(&stf, &request).unwrap();

        // Extract words 1–6 and compute expected binding
        let words_1_6 = &encoded[32..224]; // words 1-6 = bytes 32..224
        let expected_binding = keccak256(words_1_6);
        let actual_binding = &encoded[224..256]; // word 7

        assert_eq!(actual_binding, &expected_binding);
    }

    #[test]
    fn public_inputs_word_1_is_l2_start() {
        let mut request = sample_request();
        request.l2_start = 42;
        let encoded = encode_public_inputs(&[0u8; 32], &request).unwrap();
        let word1 = &encoded[32..64];
        assert_eq!(word1, &u64_to_abi_word(42));
    }

    #[test]
    fn public_inputs_word_6_is_timestamp() {
        let mut request = sample_request();
        request.window_close_timestamp = 1700000000;
        let encoded = encode_public_inputs(&[0u8; 32], &request).unwrap();
        let word6 = &encoded[192..224];
        assert_eq!(word6, &u64_to_abi_word(1700000000));
    }

    #[test]
    fn groth16_encoding_is_identity() {
        let raw = vec![0xABu8; 320];
        let encoded = encode_groth16_proof(&raw).unwrap();
        assert_eq!(encoded, raw);
    }

    #[test]
    fn groth16_wrong_length_errors() {
        let raw = vec![0u8; 100];
        let err = encode_groth16_proof(&raw).unwrap_err();
        assert!(matches!(err, EncodingError::ProofLengthMismatch { .. }));
    }

    #[test]
    fn plonk_encoding_is_identity() {
        let raw = vec![0xCDu8; 832];
        let encoded = encode_plonk_proof(&raw).unwrap();
        assert_eq!(encoded, raw);
    }

    #[test]
    fn plonk_wrong_length_errors() {
        let raw = vec![0u8; 100];
        let err = encode_plonk_proof(&raw).unwrap_err();
        assert!(matches!(err, EncodingError::ProofLengthMismatch { .. }));
    }

    #[test]
    fn halo2_encoding_has_correct_structure() {
        let raw_proof = vec![0xEFu8; 2016];
        let stf = [0x11u8; 32];
        let psd = [0x22u8; 32];

        let encoded = encode_halo2_proof(&raw_proof, &stf, &psd).unwrap();

        // Word 0: offset = 96 (0x60)
        assert_eq!(&encoded[0..32], &u64_to_abi_word(96));

        // Word 1: stfCommitment
        assert_eq!(&encoded[32..64], &stf);

        // Word 2: proverSetDigest
        assert_eq!(&encoded[64..96], &psd);

        // Word 3: length of bytes = 2016
        assert_eq!(&encoded[96..128], &u64_to_abi_word(2016));

        // Bytes data starts at offset 128
        assert_eq!(&encoded[128..128 + 2016], &raw_proof[..]);

        // 2016 is divisible by 32, so no padding needed
        assert_eq!(encoded.len(), 128 + 2016);
    }

    #[test]
    fn halo2_encoding_pads_to_32_byte_boundary() {
        // Use a proof size that's not a multiple of 32
        let raw_proof = vec![0xEFu8; 1500]; // 1500 mod 32 = 28, needs 4 bytes padding
        let stf = [0x11u8; 32];
        let psd = [0x22u8; 32];

        let encoded = encode_halo2_proof(&raw_proof, &stf, &psd).unwrap();

        let padded_len = 1500_usize.div_ceil(32) * 32; // = 1504
        assert_eq!(encoded.len(), 128 + padded_len);

        // Last 4 bytes should be zero padding
        assert_eq!(&encoded[128 + 1500..], &[0u8; 4]);
    }

    #[test]
    fn encode_proof_dispatches_correctly() {
        let stf = [0x11u8; 32];
        let psd = [0x22u8; 32];

        // Groth16
        let raw = vec![0u8; 320];
        let encoded = encode_proof(ProofSystemId::Groth16, &raw, &stf, &psd).unwrap();
        assert_eq!(encoded.len(), 320);

        // Plonk
        let raw = vec![0u8; 832];
        let encoded = encode_proof(ProofSystemId::Plonk, &raw, &stf, &psd).unwrap();
        assert_eq!(encoded.len(), 832);

        // Halo2
        let raw = vec![0u8; 2016];
        let encoded = encode_proof(ProofSystemId::Halo2, &raw, &stf, &psd).unwrap();
        assert_eq!(encoded.len(), 128 + 2016); // ABI wrapper
    }

    #[test]
    fn submission_binding_changes_with_metadata() {
        let stf = [0u8; 32];
        let req1 = sample_request();
        let mut req2 = sample_request();
        req2.l2_end = 200; // different l2_end

        let enc1 = encode_public_inputs(&stf, &req1).unwrap();
        let enc2 = encode_public_inputs(&stf, &req2).unwrap();

        // Word 7 (submissionBinding) should differ
        assert_ne!(&enc1[224..256], &enc2[224..256]);
        // Word 0 (stfCommitment) should be the same
        assert_eq!(&enc1[0..32], &enc2[0..32]);
    }

    #[test]
    fn proof_request_serde_roundtrip() {
        let request = sample_request();
        let json = serde_json::to_string(&request).unwrap();
        let parsed: ProofRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.l2_start, request.l2_start);
        assert_eq!(parsed.batch_size, request.batch_size);
        assert_eq!(parsed.domain_separator, request.domain_separator);
    }
}
