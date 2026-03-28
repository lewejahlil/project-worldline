//! Integration tests for the WorldlineSTF Halo2 circuit.
//!
//! These tests exercise the circuit through MockProver (fast) and real
//! proof generation + verification (slow but complete).

use halo2_proofs::{
    dev::MockProver,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2curves::group::ff::Field;
use rand::rngs::OsRng;
use worldline_halo2_circuit::{poseidon_hash_3, poseidon_hash_7, WorldlineStfCircuit, N};

fn valid_inputs() -> (Fr, Fr, Fr, Fr, [Fr; N], [Fr; N], Fr) {
    (
        Fr::from(1234567890u64),
        Fr::from(9876543210u64),
        Fr::from(5555555555u64),
        Fr::from(100u64),
        [Fr::from(101u64), Fr::from(102u64), Fr::from(103u64)],
        [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)],
        Fr::from(3u64),
    )
}

const K: u32 = 8;

// ── MockProver tests ────────────────────────────────────────────────────

#[test]
fn mock_valid_quorum3() {
    let (psr, posr, bc, bs, pids, psids, qc) = valid_inputs();
    let circuit = WorldlineStfCircuit::new(psr, posr, bc, bs, pids, psids, qc);
    let (stf, digest) = WorldlineStfCircuit::compute_public_outputs(psr, posr, bc, pids, psids, qc);
    let prover = MockProver::run(K, &circuit, vec![vec![stf, digest]]).unwrap();
    prover.assert_satisfied();
}

#[test]
fn mock_valid_quorum2() {
    let (psr, posr, bc, bs, pids, psids, _) = valid_inputs();
    let qc = Fr::from(2u64);
    let circuit = WorldlineStfCircuit::new(psr, posr, bc, bs, pids, psids, qc);
    let (stf, digest) = WorldlineStfCircuit::compute_public_outputs(psr, posr, bc, pids, psids, qc);
    let prover = MockProver::run(K, &circuit, vec![vec![stf, digest]]).unwrap();
    prover.assert_satisfied();
}

#[test]
fn mock_invalid_quorum0() {
    let (psr, posr, bc, bs, pids, psids, _) = valid_inputs();
    let qc = Fr::ZERO;
    let circuit = WorldlineStfCircuit::new(psr, posr, bc, bs, pids, psids, qc);
    let (stf, digest) = WorldlineStfCircuit::compute_public_outputs(psr, posr, bc, pids, psids, qc);
    let prover = MockProver::run(K, &circuit, vec![vec![stf, digest]]).unwrap();
    assert!(prover.verify().is_err());
}

#[test]
fn mock_invalid_quorum4() {
    let (psr, posr, bc, bs, pids, psids, _) = valid_inputs();
    let qc = Fr::from(4u64);
    let circuit = WorldlineStfCircuit::new(psr, posr, bc, bs, pids, psids, qc);
    let (stf, digest) = WorldlineStfCircuit::compute_public_outputs(psr, posr, bc, pids, psids, qc);
    let prover = MockProver::run(K, &circuit, vec![vec![stf, digest]]).unwrap();
    assert!(prover.verify().is_err());
}

#[test]
fn mock_invalid_batch_size_0() {
    let (psr, posr, bc, _, pids, psids, qc) = valid_inputs();
    let bs = Fr::ZERO;
    let circuit = WorldlineStfCircuit::new(psr, posr, bc, bs, pids, psids, qc);
    let (stf, digest) = WorldlineStfCircuit::compute_public_outputs(psr, posr, bc, pids, psids, qc);
    let prover = MockProver::run(K, &circuit, vec![vec![stf, digest]]).unwrap();
    assert!(prover.verify().is_err());
}

#[test]
fn mock_invalid_batch_size_1025() {
    let (psr, posr, bc, _, pids, psids, qc) = valid_inputs();
    let bs = Fr::from(1025u64);
    let circuit = WorldlineStfCircuit::new(psr, posr, bc, bs, pids, psids, qc);
    let (stf, digest) = WorldlineStfCircuit::compute_public_outputs(psr, posr, bc, pids, psids, qc);
    let prover = MockProver::run(K, &circuit, vec![vec![stf, digest]]).unwrap();
    assert!(prover.verify().is_err());
}

#[test]
fn mock_invalid_prover_id_zero() {
    let (psr, posr, bc, bs, _, psids, qc) = valid_inputs();
    let pids = [Fr::from(101u64), Fr::ZERO, Fr::from(103u64)];
    let circuit = WorldlineStfCircuit::new(psr, posr, bc, bs, pids, psids, qc);
    let (stf, digest) = WorldlineStfCircuit::compute_public_outputs(psr, posr, bc, pids, psids, qc);
    let prover = MockProver::run(K, &circuit, vec![vec![stf, digest]]).unwrap();
    assert!(prover.verify().is_err());
}

#[test]
fn mock_invalid_psid_4() {
    let (psr, posr, bc, bs, pids, _, qc) = valid_inputs();
    let psids = [Fr::from(1u64), Fr::from(4u64), Fr::from(3u64)];
    let circuit = WorldlineStfCircuit::new(psr, posr, bc, bs, pids, psids, qc);
    let (stf, digest) = WorldlineStfCircuit::compute_public_outputs(psr, posr, bc, pids, psids, qc);
    let prover = MockProver::run(K, &circuit, vec![vec![stf, digest]]).unwrap();
    assert!(prover.verify().is_err());
}

#[test]
fn mock_poseidon_matches_expected() {
    // Verify Poseidon output matches the off-circuit computation
    let (psr, posr, bc, bs, pids, psids, qc) = valid_inputs();
    let stf = poseidon_hash_3(psr, posr, bc);
    let digest = poseidon_hash_7(pids[0], pids[1], pids[2], psids[0], psids[1], psids[2], qc);

    let circuit = WorldlineStfCircuit::new(psr, posr, bc, bs, pids, psids, qc);
    let prover = MockProver::run(K, &circuit, vec![vec![stf, digest]]).unwrap();
    prover.assert_satisfied();
}

// ── Real proof generation + verification ────────────────────────────────

#[test]
fn real_proof_generation_and_verification() {
    let (psr, posr, bc, bs, pids, psids, qc) = valid_inputs();
    let circuit = WorldlineStfCircuit::new(psr, posr, bc, bs, pids, psids, qc);
    let (stf, digest) = WorldlineStfCircuit::compute_public_outputs(psr, posr, bc, pids, psids, qc);

    // Setup: generate KZG parameters
    let params = ParamsKZG::<Bn256>::setup(K, OsRng);

    // Key generation
    let empty_circuit = WorldlineStfCircuit::default();
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should succeed");
    let pk = keygen_pk(&params, vk.clone(), &empty_circuit).expect("keygen_pk should succeed");

    // Create proof
    let instances = [vec![stf, digest]];
    let instances_ref: Vec<&[Fr]> = instances.iter().map(|v| v.as_slice()).collect();

    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[instances_ref.as_slice()],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should succeed");

    let proof_bytes = transcript.finalize();

    // Verify proof
    let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof_bytes.as_slice());
    let strategy = SingleStrategy::new(&params);

    let result = verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
        &params,
        &vk,
        strategy,
        &[instances_ref.as_slice()],
        &mut transcript,
    );

    assert!(result.is_ok(), "Proof verification should succeed");

    // Report proof size
    eprintln!("Halo2 proof size: {} bytes", proof_bytes.len());
}
