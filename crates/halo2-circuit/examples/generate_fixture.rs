//! Generate a deterministic Halo2 proof fixture for integration tests.
//!
//! Outputs a JSON file containing a real KZG proof and its public outputs,
//! suitable for loading in Hardhat and Forge tests that exercise the real
//! Halo2Verifier on-chain.
//!
//! # Determinism
//!
//! Both KZG parameter generation and proof creation use a fixed-seed RNG,
//! ensuring identical output across runs. If the circuit changes, re-run
//! this script to regenerate the fixture.
//!
//! # Usage
//!
//! ```bash
//! cargo run -p worldline-halo2-circuit --example generate_fixture
//! ```

use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk},
    poly::kzg::{commitment::KZGCommitmentScheme, commitment::ParamsKZG, multiopen::ProverSHPLONK},
    transcript::TranscriptWriterBuffer,
};
use halo2_solidity_verifier::Keccak256Transcript;
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2curves::group::ff::PrimeField;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::fs;
use std::path::PathBuf;
use worldline_halo2_circuit::WorldlineStfCircuit;

/// Circuit parameter k — must match generate_verifier.rs and the prover.
const K: u32 = 8;

/// Fixed seed for deterministic KZG parameter generation.
/// Must match generate_verifier.rs so the VK is compatible.
const PARAMS_SEED: u64 = 0;

/// Fixed seed for deterministic proof generation.
const PROOF_SEED: u64 = 42;

/// Convert an Fr field element to a 0x-prefixed big-endian hex string (uint256).
fn fr_to_hex(f: &Fr) -> String {
    let repr = f.to_repr();
    let mut bytes = repr.as_ref().to_vec();
    bytes.reverse();
    format!("0x{}", hex::encode(bytes))
}

fn main() {
    // ── Circuit inputs (canonical test vector shared with Groth16/Plonk) ──
    let pre_state_root = Fr::from(1234567890u64);
    let post_state_root = Fr::from(9876543210u64);
    let batch_commitment = Fr::from(5555555555u64);
    let batch_size = Fr::from(100u64);
    let prover_ids = [Fr::from(101u64), Fr::from(102u64), Fr::from(103u64)];
    let proof_system_ids = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let quorum_count = Fr::from(3u64);

    let circuit = WorldlineStfCircuit::new(
        pre_state_root,
        post_state_root,
        batch_commitment,
        batch_size,
        prover_ids,
        proof_system_ids,
        quorum_count,
    );
    let (stf, digest) = WorldlineStfCircuit::compute_public_outputs(
        pre_state_root,
        post_state_root,
        batch_commitment,
        prover_ids,
        proof_system_ids,
        quorum_count,
    );

    // ── KZG setup (deterministic, same seed as generate_verifier.rs) ─────
    let params_rng = StdRng::seed_from_u64(PARAMS_SEED);
    let params = ParamsKZG::<Bn256>::setup(K, params_rng);

    let empty_circuit = WorldlineStfCircuit::default();
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk");

    // ── Proof generation (deterministic) ─────────────────────────────────
    let instances = [vec![stf, digest]];
    let instances_ref: Vec<&[Fr]> = instances.iter().map(|v| v.as_slice()).collect();

    let proof_rng = StdRng::seed_from_u64(PROOF_SEED);
    let mut transcript = Keccak256Transcript::<G1Affine, Vec<u8>>::init(vec![]);
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[instances_ref.as_slice()],
        proof_rng,
        &mut transcript,
    )
    .expect("proof generation");

    let proof_bytes = transcript.finalize();

    // ── Write fixture JSON ───────────────────────────────────────────────
    let fixture = format!(
        r#"{{
  "proofSystem": "halo2",
  "description": "Deterministic Halo2 KZG proof fixture. Regenerate with: cargo run -p worldline-halo2-circuit --example generate_fixture",
  "circuitParams": {{
    "k": {k},
    "paramsSeed": {params_seed},
    "proofSeed": {proof_seed}
  }},
  "inputs": {{
    "preStateRoot": "{pre_state_root}",
    "postStateRoot": "{post_state_root}",
    "batchCommitment": "{batch_commitment}",
    "batchSize": 100,
    "proverIds": [101, 102, 103],
    "proofSystemIds": [1, 2, 3],
    "quorumCount": 3
  }},
  "publicOutputs": {{
    "stfCommitment": "{stf_commitment}",
    "proverSetDigest": "{prover_set_digest}"
  }},
  "proof": {{
    "rawBytes": "0x{proof_hex}",
    "lengthBytes": {proof_len}
  }}
}}"#,
        k = K,
        params_seed = PARAMS_SEED,
        proof_seed = PROOF_SEED,
        pre_state_root = fr_to_hex(&pre_state_root),
        post_state_root = fr_to_hex(&post_state_root),
        batch_commitment = fr_to_hex(&batch_commitment),
        stf_commitment = fr_to_hex(&stf),
        prover_set_digest = fr_to_hex(&digest),
        proof_hex = hex::encode(&proof_bytes),
        proof_len = proof_bytes.len(),
    );

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test/fixtures/halo2-proof-fixture.json");

    // Ensure fixture directory exists
    if let Some(parent) = fixture_path.parent() {
        fs::create_dir_all(parent).expect("Failed to create fixtures directory");
    }

    fs::write(&fixture_path, &fixture).expect("Failed to write fixture file");

    let canonical = fixture_path
        .canonicalize()
        .unwrap_or_else(|_| fixture_path.clone());
    println!("Fixture written: {}", canonical.display());
    println!("Proof length: {} bytes", proof_bytes.len());
    println!("stfCommitment: {}", fr_to_hex(&stf));
    println!("proverSetDigest: {}", fr_to_hex(&digest));
}
