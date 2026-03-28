use worldline_aggregation::{
    AggregationStrategy, IndividualProof, ProofAggregator, ProofSystemId,
};
use worldline_recursion::{RecursionError, RecursionMode, RecursiveVerifier};

fn batch_commitment() -> [u8; 32] {
    [7u8; 32]
}

fn groth16_proof(prover_id: u64) -> IndividualProof {
    IndividualProof {
        prover_id,
        proof_system: ProofSystemId::Groth16,
        proof_data: vec![0u8; 320],
        public_inputs: vec![[1u8; 32]],
    }
}

fn make_aggregated_proof(quorum: u8, count: u64) -> worldline_aggregation::AggregatedProof {
    let mut agg = ProofAggregator::new(quorum, batch_commitment()).unwrap();
    for i in 1..=count {
        agg.add_proof(groth16_proof(i)).unwrap();
    }
    agg.aggregate(AggregationStrategy::Independent).unwrap()
}

// Test 1: Create verifier with max_depth=3 — succeeds
#[test]
fn test_new_max_depth_3_succeeds() {
    let result = RecursiveVerifier::new(3);
    assert!(result.is_ok());
}

// Test 2: Create verifier with max_depth=5 — errors (exceeds cap of 4)
#[test]
fn test_new_max_depth_5_errors() {
    let result = RecursiveVerifier::new(5);
    assert!(matches!(
        result,
        Err(RecursionError::MaxDepthExceeded { max: 4, requested: 5 })
    ));
}

// Test 3: Wrap valid aggregated proof — returns RecursiveProof at depth=1
#[test]
fn test_wrap_valid_aggregated_proof_depth_1() {
    let verifier = RecursiveVerifier::new(4).unwrap();
    let aggregated = make_aggregated_proof(1, 1);
    let result = verifier.wrap(aggregated, RecursionMode::Single);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().recursion_depth, 1);
}

// Test 4: Wrap empty aggregated proof (0 inner proofs) — returns EmptyInnerProof
#[test]
fn test_wrap_empty_aggregated_proof_returns_empty_inner() {
    use worldline_aggregation::AggregatedProof;
    let verifier = RecursiveVerifier::new(4).unwrap();
    let empty = AggregatedProof {
        proofs: vec![],
        quorum_count: 1,
        batch_commitment: batch_commitment(),
        stf_commitment: [1u8; 32],
        prover_set_digest: [2u8; 32],
    };
    let result = verifier.wrap(empty, RecursionMode::Incremental);
    assert!(matches!(result, Err(RecursionError::EmptyInnerProof)));
}

// Test 5: Recurse in Incremental mode — depth increments to 2
#[test]
fn test_recurse_incremental_depth_increments() {
    let verifier = RecursiveVerifier::new(4).unwrap();
    let aggregated = make_aggregated_proof(1, 1);
    let wrapped = verifier.wrap(aggregated, RecursionMode::Incremental).unwrap();
    assert_eq!(wrapped.recursion_depth, 1);
    let recursed = verifier.recurse(wrapped, RecursionMode::Incremental).unwrap();
    assert_eq!(recursed.recursion_depth, 2);
}

// Test 6: Recurse beyond max_depth — returns MaxDepthExceeded
#[test]
fn test_recurse_beyond_max_depth_returns_error() {
    let verifier = RecursiveVerifier::new(2).unwrap();
    let aggregated = make_aggregated_proof(1, 1);
    let mut proof = verifier.wrap(aggregated, RecursionMode::Incremental).unwrap();
    // depth=1, recurse to 2 (ok)
    proof = verifier.recurse(proof, RecursionMode::Incremental).unwrap();
    assert_eq!(proof.recursion_depth, 2);
    // recurse to 3 (exceeds max=2)
    let result = verifier.recurse(proof, RecursionMode::Incremental);
    assert!(matches!(
        result,
        Err(RecursionError::MaxDepthExceeded { max: 2, .. })
    ));
}

// Test 7: Single mode recurse — depth stays at 1
#[test]
fn test_recurse_single_mode_depth_unchanged() {
    let verifier = RecursiveVerifier::new(4).unwrap();
    let aggregated = make_aggregated_proof(1, 1);
    let wrapped = verifier.wrap(aggregated, RecursionMode::Single).unwrap();
    assert_eq!(wrapped.recursion_depth, 1);
    let recursed = verifier.recurse(wrapped, RecursionMode::Single).unwrap();
    assert_eq!(recursed.recursion_depth, 1);
}

// Test 8: verify_structure on valid proof — returns true
#[test]
fn test_verify_structure_valid_proof_returns_true() {
    let verifier = RecursiveVerifier::new(4).unwrap();
    let aggregated = make_aggregated_proof(1, 1);
    let proof = verifier.wrap(aggregated, RecursionMode::Single).unwrap();
    assert!(verifier.verify_structure(&proof));
}

// Test 9: verify_structure on proof with zero verification_key_hash — returns false
#[test]
fn test_verify_structure_zero_vkey_hash_returns_false() {
    use worldline_aggregation::AggregatedProof;
    use worldline_recursion::RecursiveProof;
    let verifier = RecursiveVerifier::new(4).unwrap();
    let bad_proof = RecursiveProof {
        inner_proof: AggregatedProof {
            proofs: vec![groth16_proof(1)],
            quorum_count: 1,
            batch_commitment: batch_commitment(),
            stf_commitment: [0u8; 32],
            prover_set_digest: [1u8; 32],
        },
        recursion_depth: 1,
        outer_proof_data: vec![0u8; 32],
        verification_key_hash: [0u8; 32],
    };
    assert!(!verifier.verify_structure(&bad_proof));
}

// Test 10: Full chain: aggregate 3 proofs → wrap → recurse → verify_structure
#[test]
fn test_full_chain_aggregate_wrap_recurse_verify() {
    let verifier = RecursiveVerifier::new(4).unwrap();
    let aggregated = make_aggregated_proof(2, 3);
    assert_eq!(aggregated.proofs.len(), 3);
    let wrapped = verifier.wrap(aggregated, RecursionMode::Incremental).unwrap();
    assert_eq!(wrapped.recursion_depth, 1);
    let recursed = verifier.recurse(wrapped, RecursionMode::Incremental).unwrap();
    assert_eq!(recursed.recursion_depth, 2);
    assert!(verifier.verify_structure(&recursed));
}
