//! End-to-end integration test: ProvingService -> calldata encoding -> structure validation.
//!
//! Exercises the full Halo2 proving pipeline (native Rust, no snarkjs) and validates
//! the ABI encoding of both publicInputs and the Halo2 proof calldata.

use tiny_keccak::{Hasher, Keccak};
use worldline_api::{
    ProofRequest, ProofResponse, ProofStatus, ProvingService, ServiceConfig,
};

// ── Helpers ─────────────────────────────────────────────────────────────────

fn halo2_config() -> ServiceConfig {
    ServiceConfig {
        groth16: None,
        plonk: None,
        halo2_enabled: true,
        program_vkey: [0xAA; 32],
        policy_hash: [0xBB; 32],
    }
}

fn halo2_request() -> ProofRequest {
    ProofRequest {
        pre_state_root: [0u8; 32],
        post_state_root: [0u8; 32],
        batch_commitment: [0u8; 32],
        batch_size: 100,
        requested_systems: vec![3], // Halo2
        prover_ids: [101, 102, 103],
        proof_system_ids: [1, 2, 3],
        quorum_count: 1,
        l2_start: 0,
        l2_end: 100,
        output_root: [0u8; 32],
        l1_block_hash: [0u8; 32],
        domain_separator: [0xDD; 32],
        window_close_timestamp: 1700000000,
    }
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

/// Read a big-endian u64 from the last 8 bytes of a 32-byte ABI word.
fn word_to_u64(word: &[u8]) -> u64 {
    assert_eq!(word.len(), 32);
    u64::from_be_bytes(word[24..32].try_into().unwrap())
}

/// Run the full pipeline once and return the response.
fn prove_halo2() -> ProofResponse {
    let mut service = ProvingService::new(halo2_config());
    let request = halo2_request();
    service.prove(&request).expect("Halo2 proving should succeed")
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn e2e_prove_completes_with_halo2() {
    let response = prove_halo2();
    assert_eq!(response.status, ProofStatus::Complete);
    assert!(response.proofs[&3].success);
    assert_eq!(response.proofs[&3].proof_length, 1536);
}

#[test]
fn e2e_encoded_public_inputs_is_256_bytes() {
    let response = prove_halo2();
    assert_eq!(
        response.encoded_public_inputs.len(),
        256,
        "publicInputs must be exactly 8 ABI words (256 bytes)"
    );
}

#[test]
fn e2e_public_inputs_word0_is_stf_commitment() {
    let response = prove_halo2();
    let pi = &response.encoded_public_inputs;

    // Word 0 of publicInputs must equal the pipeline's stfCommitment.
    assert_eq!(
        &pi[0..32],
        &response.stf_commitment,
        "word 0 of publicInputs must be the stfCommitment from the pipeline"
    );
    // Also verify it is non-zero (Poseidon output of real inputs).
    assert_ne!(
        response.stf_commitment,
        [0u8; 32],
        "stfCommitment should be non-zero for valid inputs"
    );
}

#[test]
fn e2e_public_inputs_word7_is_keccak_of_words_1_through_6() {
    let response = prove_halo2();
    let pi = &response.encoded_public_inputs;

    // Words 1-6 occupy bytes 32..224.
    let words_1_6 = &pi[32..224];
    let expected_binding = keccak256(words_1_6);
    let actual_binding = &pi[224..256];

    assert_eq!(
        actual_binding, &expected_binding,
        "word 7 (submissionBinding) must equal keccak256(abi.encode(words 1-6))"
    );
}

#[test]
fn e2e_halo2_proof_abi_structure() {
    let response = prove_halo2();
    let encoded = &response.encoded_proofs[&3];
    let calldata = &encoded.calldata;

    // Word 0: offset to dynamic bytes = 96 (0x60), since there are 3 head slots.
    let offset = word_to_u64(&calldata[0..32]);
    assert_eq!(offset, 96, "Halo2 ABI word 0 must be offset = 96 (0x60)");

    // Word 1: stfCommitment.
    assert_eq!(
        &calldata[32..64],
        &response.stf_commitment,
        "Halo2 ABI word 1 must be stfCommitment"
    );

    // Word 2: proverSetDigest.
    assert_eq!(
        &calldata[64..96],
        &response.prover_set_digest,
        "Halo2 ABI word 2 must be proverSetDigest"
    );

    // Word 3: length of raw proof bytes.
    let raw_len = word_to_u64(&calldata[96..128]);
    assert_eq!(
        raw_len, 1536,
        "Halo2 ABI word 3 must indicate raw proof length = 1536"
    );

    // Rest: raw proof bytes padded to 32-byte boundary.
    let proof_data = &calldata[128..128 + 1536];
    assert_eq!(
        proof_data,
        &encoded.raw_proof[..],
        "Halo2 ABI proof data must match raw_proof"
    );

    // 1536 is already 32-byte aligned, so total = 128 (header) + 1536 = 1664.
    assert_eq!(
        calldata.len(),
        128 + 1536,
        "Halo2 ABI total calldata length must be 1664"
    );
}

#[test]
fn e2e_halo2_raw_proof_is_1536_bytes() {
    let response = prove_halo2();
    let encoded = &response.encoded_proofs[&3];
    assert_eq!(
        encoded.raw_proof.len(),
        1536,
        "Halo2 KZG raw proof must be exactly 1536 bytes"
    );
}

#[test]
fn e2e_stf_commitment_in_proof_matches_public_inputs_word0() {
    // This is the on-chain StfMismatch check: the stfCommitment embedded in the
    // proof calldata must match word 0 of publicInputs.
    let response = prove_halo2();
    let pi = &response.encoded_public_inputs;
    let calldata = &response.encoded_proofs[&3].calldata;

    let pi_word0 = &pi[0..32];
    let proof_stf = &calldata[32..64]; // Word 1 of Halo2 ABI = stfCommitment

    assert_eq!(
        pi_word0, proof_stf,
        "stfCommitment in proof calldata must match word 0 of publicInputs (StfMismatch guard)"
    );
}

#[test]
fn e2e_serde_roundtrip_full_response() {
    let response = prove_halo2();

    let json = serde_json::to_string(&response).expect("serialization should succeed");
    let parsed: ProofResponse =
        serde_json::from_str(&json).expect("deserialization should succeed");

    assert_eq!(parsed.status, response.status);
    assert_eq!(parsed.stf_commitment, response.stf_commitment);
    assert_eq!(parsed.prover_set_digest, response.prover_set_digest);
    assert_eq!(parsed.encoded_public_inputs, response.encoded_public_inputs);
    assert_eq!(parsed.program_vkey, response.program_vkey);
    assert_eq!(parsed.policy_hash, response.policy_hash);
    assert_eq!(parsed.proofs.len(), response.proofs.len());
    assert_eq!(parsed.encoded_proofs.len(), response.encoded_proofs.len());

    // Verify the encoded proof bytes survived the roundtrip.
    let original = &response.encoded_proofs[&3];
    let roundtripped = &parsed.encoded_proofs[&3];
    assert_eq!(original.proof_system_id, roundtripped.proof_system_id);
    assert_eq!(original.calldata, roundtripped.calldata);
    assert_eq!(original.raw_proof, roundtripped.raw_proof);
}
