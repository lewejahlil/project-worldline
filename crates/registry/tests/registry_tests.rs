use worldline_prover_registry::{ProofSystemId, ProverRegistry, RegistryError};

// 1. Register prover with Groth16 — succeeds, active_count=1
#[test]
fn register_groth16_succeeds() {
    let mut reg = ProverRegistry::new();
    reg.register(1, ProofSystemId::Groth16).unwrap();
    assert_eq!(reg.active_count(), 1);
}

// 2. Register prover with Plonk — succeeds, active_count=2
#[test]
fn register_plonk_succeeds() {
    let mut reg = ProverRegistry::new();
    reg.register(1, ProofSystemId::Groth16).unwrap();
    reg.register(2, ProofSystemId::Plonk).unwrap();
    assert_eq!(reg.active_count(), 2);
}

// 3. Register prover with Halo2 — succeeds, active_count=3
#[test]
fn register_halo2_succeeds() {
    let mut reg = ProverRegistry::new();
    reg.register(1, ProofSystemId::Groth16).unwrap();
    reg.register(2, ProofSystemId::Plonk).unwrap();
    reg.register(3, ProofSystemId::Halo2).unwrap();
    assert_eq!(reg.active_count(), 3);
}

// 4. Reject duplicate prover ID — returns ProverAlreadyRegistered
#[test]
fn reject_duplicate_prover_id() {
    let mut reg = ProverRegistry::new();
    reg.register(1, ProofSystemId::Groth16).unwrap();
    let err = reg.register(1, ProofSystemId::Plonk).unwrap_err();
    assert_eq!(err, RegistryError::ProverAlreadyRegistered(1));
}

// 5. Reject prover ID 0 — returns InvalidProverId
#[test]
fn reject_zero_prover_id() {
    let mut reg = ProverRegistry::new();
    let err = reg.register(0, ProofSystemId::Groth16).unwrap_err();
    assert_eq!(err, RegistryError::InvalidProverId);
}

// 6. Deregister prover — active_count decreases, get() still returns record with active=false
#[test]
fn deregister_prover() {
    let mut reg = ProverRegistry::new();
    reg.register(1, ProofSystemId::Groth16).unwrap();
    reg.register(2, ProofSystemId::Plonk).unwrap();
    reg.deregister(1).unwrap();
    assert_eq!(reg.active_count(), 1);
    let record = reg.get(1).expect("record should still exist");
    assert!(!record.active);
}

// 7. Deregister unknown prover — returns ProverNotFound
#[test]
fn deregister_unknown_prover() {
    let mut reg = ProverRegistry::new();
    let err = reg.deregister(99).unwrap_err();
    assert_eq!(err, RegistryError::ProverNotFound(99));
}

// 8. check_quorum(2) with 3 active — succeeds
#[test]
fn check_quorum_sufficient() {
    let mut reg = ProverRegistry::new();
    reg.register(1, ProofSystemId::Groth16).unwrap();
    reg.register(2, ProofSystemId::Plonk).unwrap();
    reg.register(3, ProofSystemId::Halo2).unwrap();
    reg.check_quorum(2).unwrap();
}

// 9. check_quorum(3) with 2 active — returns QuorumNotMet
#[test]
fn check_quorum_not_met() {
    let mut reg = ProverRegistry::new();
    reg.register(1, ProofSystemId::Groth16).unwrap();
    reg.register(2, ProofSystemId::Plonk).unwrap();
    let err = reg.check_quorum(3).unwrap_err();
    assert_eq!(
        err,
        RegistryError::QuorumNotMet {
            required: 3,
            active: 2
        }
    );
}

// 10. check_quorum(0) — returns QuorumOutOfRange
#[test]
fn check_quorum_zero_out_of_range() {
    let reg = ProverRegistry::new();
    let err = reg.check_quorum(0).unwrap_err();
    assert_eq!(err, RegistryError::QuorumOutOfRange(0));
}

// 11. check_quorum(4) — returns QuorumOutOfRange
#[test]
fn check_quorum_four_out_of_range() {
    let reg = ProverRegistry::new();
    let err = reg.check_quorum(4).unwrap_err();
    assert_eq!(err, RegistryError::QuorumOutOfRange(4));
}

// 12. active_provers() returns only active records
#[test]
fn active_provers_returns_only_active() {
    let mut reg = ProverRegistry::new();
    reg.register(1, ProofSystemId::Groth16).unwrap();
    reg.register(2, ProofSystemId::Plonk).unwrap();
    reg.register(3, ProofSystemId::Halo2).unwrap();
    reg.deregister(2).unwrap();
    let active = reg.active_provers();
    assert_eq!(active.len(), 2);
    assert!(active.iter().all(|r| r.active));
    let ids: Vec<u64> = {
        let mut v: Vec<u64> = active.iter().map(|r| r.id).collect();
        v.sort();
        v
    };
    assert_eq!(ids, vec![1, 3]);
}
