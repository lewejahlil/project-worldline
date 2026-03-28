use worldline_aggregation::{
    AggregationError, AggregationStrategy, IndividualProof, ProofAggregator, ProofSystemId,
};

fn groth16_proof(prover_id: u64) -> IndividualProof {
    IndividualProof {
        prover_id,
        proof_system: ProofSystemId::Groth16,
        proof_data: vec![0u8; 320],
        public_inputs: vec![[1u8; 32]],
    }
}

fn batch_commitment() -> [u8; 32] {
    [42u8; 32]
}

// Test 1: Create aggregator with quorum=2 — succeeds
#[test]
fn test_new_quorum_2_succeeds() {
    let result = ProofAggregator::new(2, batch_commitment());
    assert!(result.is_ok());
}

// Test 2: Create aggregator with quorum=0 — errors
#[test]
fn test_new_quorum_0_errors() {
    let result = ProofAggregator::new(0, batch_commitment());
    assert!(matches!(
        result,
        Err(AggregationError::InsufficientProofs { required: 0, .. })
    ));
}

// Test 3: Create aggregator with quorum=4 — errors
#[test]
fn test_new_quorum_4_errors() {
    let result = ProofAggregator::new(4, batch_commitment());
    assert!(matches!(
        result,
        Err(AggregationError::InsufficientProofs { required: 4, .. })
    ));
}

// Test 4: Add valid Groth16 proof (320 bytes) — succeeds
#[test]
fn test_add_valid_groth16_proof() {
    let mut agg = ProofAggregator::new(1, batch_commitment()).unwrap();
    let result = agg.add_proof(groth16_proof(1));
    assert!(result.is_ok());
}

// Test 5: Add proof with id=0 — returns InvalidProverId
#[test]
fn test_add_proof_id_zero_returns_invalid_prover_id() {
    let mut agg = ProofAggregator::new(1, batch_commitment()).unwrap();
    let proof = IndividualProof {
        prover_id: 0,
        proof_system: ProofSystemId::Groth16,
        proof_data: vec![0u8; 320],
        public_inputs: vec![],
    };
    let result = agg.add_proof(proof);
    assert!(matches!(result, Err(AggregationError::InvalidProverId)));
}

// Test 6: Add duplicate prover_id — returns DuplicateProver
#[test]
fn test_add_duplicate_prover_id_returns_duplicate_prover() {
    let mut agg = ProofAggregator::new(1, batch_commitment()).unwrap();
    agg.add_proof(groth16_proof(1)).unwrap();
    let result = agg.add_proof(groth16_proof(1));
    assert!(matches!(result, Err(AggregationError::DuplicateProver(1))));
}

// Test 7: Add Groth16 proof with wrong length (128 bytes) — returns InvalidProofData
#[test]
fn test_add_groth16_wrong_length_returns_invalid_proof_data() {
    let mut agg = ProofAggregator::new(1, batch_commitment()).unwrap();
    let proof = IndividualProof {
        prover_id: 1,
        proof_system: ProofSystemId::Groth16,
        proof_data: vec![0u8; 128],
        public_inputs: vec![],
    };
    let result = agg.add_proof(proof);
    assert!(matches!(
        result,
        Err(AggregationError::InvalidProofData { prover_id: 1, .. })
    ));
}

// Test 8: Aggregate with Independent strategy, 3 proofs, quorum=2 — succeeds, AggregatedProof has 3 proofs
#[test]
fn test_aggregate_independent_3_proofs_quorum_2() {
    let mut agg = ProofAggregator::new(2, batch_commitment()).unwrap();
    agg.add_proof(groth16_proof(1)).unwrap();
    agg.add_proof(groth16_proof(2)).unwrap();
    agg.add_proof(groth16_proof(3)).unwrap();
    let result = agg.aggregate(AggregationStrategy::Independent);
    assert!(result.is_ok());
    let aggregated = result.unwrap();
    assert_eq!(aggregated.proofs.len(), 3);
}

// Test 9: Aggregate with quorum=3 but only 2 proofs — returns InsufficientProofs
#[test]
fn test_aggregate_quorum_3_only_2_proofs_returns_insufficient() {
    let mut agg = ProofAggregator::new(3, batch_commitment()).unwrap();
    agg.add_proof(groth16_proof(1)).unwrap();
    agg.add_proof(groth16_proof(2)).unwrap();
    let result = agg.aggregate(AggregationStrategy::Independent);
    assert!(matches!(
        result,
        Err(AggregationError::InsufficientProofs {
            required: 3,
            provided: 2
        })
    ));
}

// Test 10: Aggregate with Sequential strategy, 2 valid proofs, quorum=2 — succeeds
#[test]
fn test_aggregate_sequential_2_valid_proofs_quorum_2() {
    let mut agg = ProofAggregator::new(2, batch_commitment()).unwrap();
    agg.add_proof(groth16_proof(1)).unwrap();
    agg.add_proof(groth16_proof(2)).unwrap();
    let result = agg.aggregate(AggregationStrategy::Sequential);
    assert!(result.is_ok());
}

// Test 11: stf_commitment and prover_set_digest populated in output
#[test]
fn test_stf_commitment_and_prover_set_digest_populated() {
    let mut agg = ProofAggregator::new(2, batch_commitment()).unwrap();
    agg.add_proof(groth16_proof(1)).unwrap();
    agg.add_proof(groth16_proof(2)).unwrap();
    let aggregated = agg.aggregate(AggregationStrategy::Independent).unwrap();
    // stf_commitment and prover_set_digest should not be all-zero
    assert_ne!(aggregated.stf_commitment, [0u8; 32]);
    assert_ne!(aggregated.prover_set_digest, [0u8; 32]);
}

// Test 12: proof_count() and valid_proof_count() return correct values
#[test]
fn test_proof_count_and_valid_proof_count() {
    let mut agg = ProofAggregator::new(1, batch_commitment()).unwrap();
    assert_eq!(agg.proof_count(), 0);
    assert_eq!(agg.valid_proof_count(), 0);
    agg.add_proof(groth16_proof(1)).unwrap();
    assert_eq!(agg.proof_count(), 1);
    assert_eq!(agg.valid_proof_count(), 1);
    agg.add_proof(groth16_proof(2)).unwrap();
    assert_eq!(agg.proof_count(), 2);
    assert_eq!(agg.valid_proof_count(), 2);
}
