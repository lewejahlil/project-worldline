//! Cross-system tests verifying that the aggregation crate's Poseidon digest
//! computation matches the Halo2 circuit's `compute_public_outputs`.
//!
//! This ensures Rust aggregator ↔ Halo2 circuit ↔ Circom circuit compatibility
//! (all three use circomlib-compatible Poseidon with identical round constants).

use halo2curves::bn256::Fr;
use halo2curves::group::ff::{Field, PrimeField};
use worldline_aggregation::{AggregationStrategy, IndividualProof, ProofAggregator, ProofSystemId};
use worldline_halo2_circuit::{poseidon_compress_3, poseidon_compress_7, WorldlineStfCircuit};

/// Helper: serialize Fr to [u8; 32] little-endian.
fn fr_to_bytes(fr: Fr) -> [u8; 32] {
    fr.to_repr().into()
}

// ---------------------------------------------------------------------------
// Test 1: proverSetDigest from aggregator matches poseidon_compress_7
// ---------------------------------------------------------------------------
#[test]
fn test_prover_set_digest_matches_halo2_poseidon() {
    let prover_ids = [Fr::from(101u64), Fr::from(102u64), Fr::from(103u64)];
    let proof_system_ids = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let quorum_count = Fr::from(3u64);

    // Compute expected digest using the circomlib-compatible Poseidon directly
    let expected = poseidon_compress_7(
        prover_ids[0],
        prover_ids[1],
        prover_ids[2],
        proof_system_ids[0],
        proof_system_ids[1],
        proof_system_ids[2],
        quorum_count,
    );

    // Build an aggregator with matching proofs
    let batch_commitment = [0u8; 32];
    let mut agg = ProofAggregator::new(3, batch_commitment).unwrap();

    agg.add_proof(IndividualProof {
        prover_id: 101,
        proof_system: ProofSystemId::Groth16,
        proof_data: vec![0u8; 320],
        public_inputs: vec![[0u8; 32]],
    })
    .unwrap();

    agg.add_proof(IndividualProof {
        prover_id: 102,
        proof_system: ProofSystemId::Plonk,
        proof_data: vec![0u8; 832],
        public_inputs: vec![[0u8; 32]],
    })
    .unwrap();

    agg.add_proof(IndividualProof {
        prover_id: 103,
        proof_system: ProofSystemId::Halo2,
        proof_data: vec![0u8; 192],
        public_inputs: vec![[0u8; 32]],
    })
    .unwrap();

    let aggregated = agg.aggregate(AggregationStrategy::Independent).unwrap();
    assert_eq!(
        aggregated.prover_set_digest,
        fr_to_bytes(expected),
        "Aggregator prover_set_digest must match circomlib-compatible Poseidon"
    );
}

// ---------------------------------------------------------------------------
// Test 2: stfCommitment from aggregator matches poseidon_compress_3
// ---------------------------------------------------------------------------
#[test]
fn test_stf_commitment_matches_halo2_poseidon() {
    let pre_state_root = Fr::from(1234567890u64);
    let post_state_root = Fr::from(9876543210u64);
    let batch_commitment_fr = Fr::from(5555555555u64);

    let expected = poseidon_compress_3(pre_state_root, post_state_root, batch_commitment_fr);

    let batch_commitment_bytes = fr_to_bytes(batch_commitment_fr);
    let mut agg = ProofAggregator::new(1, batch_commitment_bytes).unwrap();

    // Proof whose public_inputs[0] = preStateRoot, public_inputs[1] = postStateRoot
    agg.add_proof(IndividualProof {
        prover_id: 1,
        proof_system: ProofSystemId::Groth16,
        proof_data: vec![0u8; 320],
        public_inputs: vec![fr_to_bytes(pre_state_root), fr_to_bytes(post_state_root)],
    })
    .unwrap();

    let aggregated = agg.aggregate(AggregationStrategy::Independent).unwrap();
    assert_eq!(
        aggregated.stf_commitment,
        fr_to_bytes(expected),
        "Aggregator stf_commitment must match circomlib-compatible Poseidon"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Full round-trip — aggregator digests match WorldlineStfCircuit::compute_public_outputs
// ---------------------------------------------------------------------------
#[test]
fn test_aggregator_digests_match_circuit_public_outputs() {
    let pre_state_root = Fr::from(1234567890u64);
    let post_state_root = Fr::from(9876543210u64);
    let batch_commitment_fr = Fr::from(5555555555u64);
    let prover_ids = [Fr::from(101u64), Fr::from(102u64), Fr::from(103u64)];
    let proof_system_ids = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let quorum_count = Fr::from(3u64);

    // Compute expected via the Halo2 circuit's public output function
    let (expected_stf, expected_digest) = WorldlineStfCircuit::compute_public_outputs(
        pre_state_root,
        post_state_root,
        batch_commitment_fr,
        prover_ids,
        proof_system_ids,
        quorum_count,
    );

    // Build aggregator with matching inputs
    let batch_commitment_bytes = fr_to_bytes(batch_commitment_fr);
    let mut agg = ProofAggregator::new(3, batch_commitment_bytes).unwrap();

    agg.add_proof(IndividualProof {
        prover_id: 101,
        proof_system: ProofSystemId::Groth16,
        proof_data: vec![0u8; 320],
        public_inputs: vec![fr_to_bytes(pre_state_root), fr_to_bytes(post_state_root)],
    })
    .unwrap();

    agg.add_proof(IndividualProof {
        prover_id: 102,
        proof_system: ProofSystemId::Plonk,
        proof_data: vec![0u8; 832],
        public_inputs: vec![fr_to_bytes(pre_state_root), fr_to_bytes(post_state_root)],
    })
    .unwrap();

    agg.add_proof(IndividualProof {
        prover_id: 103,
        proof_system: ProofSystemId::Halo2,
        proof_data: vec![0u8; 192],
        public_inputs: vec![fr_to_bytes(pre_state_root), fr_to_bytes(post_state_root)],
    })
    .unwrap();

    let aggregated = agg.aggregate(AggregationStrategy::Independent).unwrap();

    assert_eq!(
        aggregated.stf_commitment,
        fr_to_bytes(expected_stf),
        "stf_commitment must match Halo2 circuit compute_public_outputs"
    );
    assert_eq!(
        aggregated.prover_set_digest,
        fr_to_bytes(expected_digest),
        "prover_set_digest must match Halo2 circuit compute_public_outputs"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Poseidon output is non-trivial (not all zeros)
// ---------------------------------------------------------------------------
#[test]
fn test_poseidon_digest_is_nontrivial() {
    let mut agg = ProofAggregator::new(1, [42u8; 32]).unwrap();
    agg.add_proof(IndividualProof {
        prover_id: 1,
        proof_system: ProofSystemId::Groth16,
        proof_data: vec![0u8; 320],
        public_inputs: vec![[1u8; 32]],
    })
    .unwrap();

    let aggregated = agg.aggregate(AggregationStrategy::Independent).unwrap();
    assert_ne!(aggregated.stf_commitment, [0u8; 32]);
    assert_ne!(aggregated.prover_set_digest, [0u8; 32]);
}
