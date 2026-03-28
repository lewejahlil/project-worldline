use worldline_aggregation::{
    AggregationError, AggregationStrategy, IndividualProof, MockVerifier, ProofAggregator,
    ProofSystemId, ProofVerifier, VerificationError,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn groth16_proof(prover_id: u64) -> IndividualProof {
    IndividualProof {
        prover_id,
        proof_system: ProofSystemId::Groth16,
        proof_data: vec![0u8; 320],
        public_inputs: vec![[1u8; 32]],
    }
}

fn plonk_proof(prover_id: u64) -> IndividualProof {
    IndividualProof {
        prover_id,
        proof_system: ProofSystemId::Plonk,
        proof_data: vec![0u8; 832],
        public_inputs: vec![[2u8; 32]],
    }
}

fn halo2_proof(prover_id: u64) -> IndividualProof {
    IndividualProof {
        prover_id,
        proof_system: ProofSystemId::Halo2,
        proof_data: vec![0u8; 192],
        public_inputs: vec![[3u8; 32]],
    }
}

fn batch_commitment() -> [u8; 32] {
    [42u8; 32]
}

fn mock_verifier(system_id: ProofSystemId, should_pass: bool) -> Box<dyn ProofVerifier> {
    Box::new(MockVerifier {
        system_id,
        should_pass,
    })
}

// ---------------------------------------------------------------------------
// Test 1: register MockVerifier for all three systems — no error
// ---------------------------------------------------------------------------
#[test]
fn test_register_mock_verifiers_all_systems() {
    let mut agg = ProofAggregator::new(1, batch_commitment()).unwrap();
    agg.register_verifier(mock_verifier(ProofSystemId::Groth16, true));
    agg.register_verifier(mock_verifier(ProofSystemId::Plonk, true));
    agg.register_verifier(mock_verifier(ProofSystemId::Halo2, true));
    // No panic; registration is silent for all three systems.
}

// ---------------------------------------------------------------------------
// Test 2: register same system twice — second silently overwrites the first
// ---------------------------------------------------------------------------
#[test]
fn test_register_duplicate_overwrites() {
    let mut agg = ProofAggregator::new(1, batch_commitment()).unwrap();
    // First: passes
    agg.register_verifier(mock_verifier(ProofSystemId::Groth16, true));
    // Second: fails — overwrites the first
    agg.register_verifier(mock_verifier(ProofSystemId::Groth16, false));

    agg.add_proof(groth16_proof(1)).unwrap();
    let proof = groth16_proof(1);
    // The second verifier (should_pass=false) wins
    let result = agg.verify_proof(&proof).unwrap();
    assert!(!result);
}

// ---------------------------------------------------------------------------
// Test 3: MockVerifier(Groth16, pass=true) — verify_proof on 320-byte proof returns Ok(true)
// ---------------------------------------------------------------------------
#[test]
fn test_verify_valid_groth16_mock_passes() {
    let mut agg = ProofAggregator::new(1, batch_commitment()).unwrap();
    agg.register_verifier(mock_verifier(ProofSystemId::Groth16, true));
    agg.add_proof(groth16_proof(1)).unwrap();

    let proof = groth16_proof(1);
    let result = agg.verify_proof(&proof).unwrap();
    assert!(result);
}

// ---------------------------------------------------------------------------
// Test 4: MockVerifier(Groth16, pass=false) — verify_proof returns Ok(false)
// ---------------------------------------------------------------------------
#[test]
fn test_verify_invalid_proof_mock_fails() {
    let mut agg = ProofAggregator::new(1, batch_commitment()).unwrap();
    agg.register_verifier(mock_verifier(ProofSystemId::Groth16, false));

    let proof = groth16_proof(42);
    let result = agg.verify_proof(&proof).unwrap();
    assert!(!result);
}

// ---------------------------------------------------------------------------
// Test 5: 3 Groth16 proofs, MockVerifier(pass=true), quorum=2 — all 3 pass
// ---------------------------------------------------------------------------
#[test]
fn test_aggregate_3_proofs_all_pass_quorum_2() {
    let mut agg = ProofAggregator::new(2, batch_commitment()).unwrap();
    agg.register_verifier(mock_verifier(ProofSystemId::Groth16, true));
    agg.add_proof(groth16_proof(1)).unwrap();
    agg.add_proof(groth16_proof(2)).unwrap();
    agg.add_proof(groth16_proof(3)).unwrap();

    let result = agg.aggregate(AggregationStrategy::Independent).unwrap();
    // All 3 verified, quorum=2 satisfied
    assert!(result.verified_count >= 2);
    assert_eq!(result.proofs.len(), 3);
}

// ---------------------------------------------------------------------------
// Test 6: 2 Groth16 pass + 1 Halo2 fails — Independent, quorum=2 → QuorumMet (2 verified)
// ---------------------------------------------------------------------------
#[test]
fn test_aggregate_3_proofs_1_fails_quorum_2() {
    let mut agg = ProofAggregator::new(2, batch_commitment()).unwrap();
    agg.register_verifier(mock_verifier(ProofSystemId::Groth16, true));
    agg.register_verifier(mock_verifier(ProofSystemId::Halo2, false));

    agg.add_proof(groth16_proof(1)).unwrap();
    agg.add_proof(groth16_proof(2)).unwrap();
    agg.add_proof(halo2_proof(3)).unwrap();

    let result = agg.aggregate(AggregationStrategy::Independent).unwrap();
    // Groth16 x2 pass, Halo2 x1 fails → verified_count=2, quorum=2 met
    assert_eq!(result.verified_count, 2);
    // Only passing proofs are included
    assert_eq!(result.proofs.len(), 2);
}

// ---------------------------------------------------------------------------
// Test 7: 1 Groth16 pass + 2 Halo2 fail — Independent, quorum=2 → QuorumNotMet
// ---------------------------------------------------------------------------
#[test]
fn test_aggregate_2_fails_quorum_2_returns_quorum_not_met() {
    let mut agg = ProofAggregator::new(2, batch_commitment()).unwrap();
    agg.register_verifier(mock_verifier(ProofSystemId::Groth16, true));
    agg.register_verifier(mock_verifier(ProofSystemId::Halo2, false));

    agg.add_proof(groth16_proof(1)).unwrap();
    agg.add_proof(halo2_proof(2)).unwrap();
    agg.add_proof(halo2_proof(3)).unwrap();

    let err = agg.aggregate(AggregationStrategy::Independent).unwrap_err();
    assert!(matches!(
        err,
        AggregationError::QuorumNotMet {
            required: 2,
            valid: 1
        }
    ));
}

// ---------------------------------------------------------------------------
// Test 8: Independent strategy attempts ALL proofs even when some fail
// ---------------------------------------------------------------------------
#[test]
fn test_independent_strategy_attempts_all_proofs() {
    let mut agg = ProofAggregator::new(2, batch_commitment()).unwrap();
    agg.register_verifier(mock_verifier(ProofSystemId::Groth16, true));
    agg.register_verifier(mock_verifier(ProofSystemId::Halo2, false));

    agg.add_proof(groth16_proof(1)).unwrap();
    agg.add_proof(groth16_proof(2)).unwrap();
    agg.add_proof(halo2_proof(3)).unwrap();

    let result = agg.aggregate(AggregationStrategy::Independent).unwrap();
    // All 3 attempted regardless of failures
    assert_eq!(result.verification_results.len(), 3);
    assert_eq!(result.verified_count, 2);
}

// ---------------------------------------------------------------------------
// Test 9: Sequential strategy stops at first failure
// ---------------------------------------------------------------------------
#[test]
fn test_sequential_strategy_stops_at_first_failure() {
    let mut agg = ProofAggregator::new(1, batch_commitment()).unwrap();
    agg.register_verifier(mock_verifier(ProofSystemId::Groth16, true));
    agg.register_verifier(mock_verifier(ProofSystemId::Halo2, false));

    // Halo2 first — will fail immediately; Groth16 proofs come after but won't be reached
    agg.add_proof(halo2_proof(1)).unwrap();
    agg.add_proof(groth16_proof(2)).unwrap();
    agg.add_proof(groth16_proof(3)).unwrap();

    // quorum=1 but first proof fails → QuorumNotMet
    let err = agg.aggregate(AggregationStrategy::Sequential).unwrap_err();
    assert!(matches!(
        err,
        AggregationError::QuorumNotMet {
            required: 1,
            valid: 0
        }
    ));
}

// ---------------------------------------------------------------------------
// Test 10: verify_proof on unregistered system returns VerifierNotRegistered
// ---------------------------------------------------------------------------
#[test]
fn test_verify_proof_unregistered_system_returns_error() {
    let mut agg = ProofAggregator::new(1, batch_commitment()).unwrap();
    // Only Groth16 registered
    agg.register_verifier(mock_verifier(ProofSystemId::Groth16, true));

    let proof = plonk_proof(1);
    let err = agg.verify_proof(&proof).unwrap_err();
    assert!(matches!(
        err,
        AggregationError::VerifierNotRegistered(ProofSystemId::Plonk)
    ));
}

// ---------------------------------------------------------------------------
// Test 11: verify_all — all three systems pass
// ---------------------------------------------------------------------------
#[test]
fn test_verify_all_all_pass() {
    let mut agg = ProofAggregator::new(1, batch_commitment()).unwrap();
    agg.register_verifier(mock_verifier(ProofSystemId::Groth16, true));
    agg.register_verifier(mock_verifier(ProofSystemId::Plonk, true));
    agg.register_verifier(mock_verifier(ProofSystemId::Halo2, true));

    agg.add_proof(groth16_proof(1)).unwrap();
    agg.add_proof(plonk_proof(2)).unwrap();
    agg.add_proof(halo2_proof(3)).unwrap();

    let report = agg.verify_all().unwrap();
    assert_eq!(report.results.len(), 3);
    assert_eq!(report.verified_count, 3);
    assert!(report.results.iter().all(|(_, _, passed)| *passed));
}

// ---------------------------------------------------------------------------
// Test 12: verify_all — mixed results (Groth16 pass, Halo2 fail)
// ---------------------------------------------------------------------------
#[test]
fn test_verify_all_mixed_results() {
    let mut agg = ProofAggregator::new(1, batch_commitment()).unwrap();
    agg.register_verifier(mock_verifier(ProofSystemId::Groth16, true));
    agg.register_verifier(mock_verifier(ProofSystemId::Halo2, false));

    agg.add_proof(groth16_proof(1)).unwrap();
    agg.add_proof(halo2_proof(2)).unwrap();

    let report = agg.verify_all().unwrap();
    assert_eq!(report.results.len(), 2);
    assert_eq!(report.verified_count, 1);

    let groth16_result = report.results.iter().find(|(id, _, _)| *id == 1).unwrap();
    assert!(groth16_result.2, "Groth16 proof should pass");

    let halo2_result = report.results.iter().find(|(id, _, _)| *id == 2).unwrap();
    assert!(!halo2_result.2, "Halo2 proof should fail");
}

// ---------------------------------------------------------------------------
// Test 13: real Groth16 verification (ignored — requires snarkjs installed)
// ---------------------------------------------------------------------------
#[test]
#[ignore = "requires snarkjs installed and valid verification key"]
fn test_real_groth16_verification_ignored() {
    // This test is intentionally left as a placeholder.
    // In CI with snarkjs available, point to the actual vkey and proof files.
    // e.g.: use worldline_aggregation::verifiers::Groth16Verifier;
    // let verifier = Groth16Verifier::new("circuits/zkeys/state_transition.vkey.json").unwrap();
    // let result = verifier.verify(&proof_data, &public_inputs).unwrap();
    // assert!(result);
}

// ---------------------------------------------------------------------------
// Test 14: real Halo2 verification (ignored — requires halo2-verify helper binary)
// ---------------------------------------------------------------------------
#[test]
#[ignore = "requires halo2-verify helper binary"]
fn test_real_halo2_verification_ignored() {
    // This test is intentionally left as a placeholder.
    // In CI with halo2-verify available, supply a real KZG proof and params.
    // e.g.: use worldline_aggregation::verifiers::Halo2Verifier;
    // let verifier = Halo2Verifier::new("circuits/zkeys/halo2_params.bin").unwrap();
    // let result = verifier.verify(&proof_data, &public_inputs).unwrap();
    // assert!(result);
}

// ---------------------------------------------------------------------------
// Extra: VerificationError type is accessible and behaves correctly
// ---------------------------------------------------------------------------
#[test]
fn test_verification_error_types_accessible() {
    let err = VerificationError::InvalidLength {
        expected: 320,
        actual: 100,
    };
    let msg = err.to_string();
    assert!(msg.contains("320"));
    assert!(msg.contains("100"));

    let err2 = VerificationError::VerificationFailed {
        reason: "bad proof".to_string(),
    };
    assert!(err2.to_string().contains("bad proof"));

    let err3 = VerificationError::BackendError("backend down".to_string());
    assert!(err3.to_string().contains("backend down"));
}
