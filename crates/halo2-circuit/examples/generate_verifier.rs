//! Generate the Halo2 Solidity verifier from the WorldlineSTF circuit.
//!
//! This script generates a production `Halo2Verifier.sol` with embedded verification
//! key constants and real BN254 pairing verification logic, replacing the stub verifier.
//!
//! The generated contract is written to `contracts/src/zk/Halo2Verifier.sol`.
//!
//! # Usage
//!
//! ```bash
//! cargo run -p worldline-halo2-circuit --example generate_verifier
//! ```
//!
//! # Determinism
//!
//! This script uses a fixed-seed RNG for KZG parameter generation, ensuring
//! identical output across runs. If the circuit changes, re-run this script
//! to regenerate the verifier. The committed `Halo2Verifier.sol` must always
//! match the current circuit definition.
//!
//! # Parameters
//!
//! - Circuit: WorldlineSTF (k=8, 256 rows, 2 public instances)
//! - Proof system: KZG on BN254 with SHPLONK (Bdfg21) multi-open
//! - Transcript: Keccak256 (EVM-compatible)

use halo2_proofs::{plonk::keygen_vk, poly::kzg::commitment::ParamsKZG};
use halo2_solidity_verifier::{BatchOpenScheme, SolidityGenerator};
use halo2curves::bn256::Bn256;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::fs;
use std::path::PathBuf;
use worldline_halo2_circuit::WorldlineStfCircuit;

/// Circuit parameter k (log2 of rows). Must match the prover.
const K: u32 = 8;

/// Number of public instances (stfCommitment, proverSetDigest).
const NUM_INSTANCES: usize = 2;

/// Fixed seed for deterministic KZG parameter generation.
/// This is a development ceremony — production deployments require a proper
/// trusted setup ceremony with multiple participants.
const PARAMS_SEED: u64 = 0;

fn main() {
    // Deterministic KZG parameters
    let rng = StdRng::seed_from_u64(PARAMS_SEED);
    let params = ParamsKZG::<Bn256>::setup(K, rng);

    // Generate verification key from the empty circuit
    let empty_circuit = WorldlineStfCircuit::default();
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should succeed");

    // Generate Solidity verifier
    let generator = SolidityGenerator::new(&params, &vk, BatchOpenScheme::Bdfg21, NUM_INSTANCES);
    let solidity_code = generator
        .render()
        .expect("Solidity generation should succeed");

    // Write to contracts/src/zk/Halo2Verifier.sol
    let output_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/src/zk/Halo2Verifier.sol");
    let output_path = output_path.canonicalize().unwrap_or_else(|_| {
        // If the file doesn't exist yet (first generation), use the parent dir
        let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/src/zk");
        let parent = parent.canonicalize().expect("contracts/src/zk/ must exist");
        parent.join("Halo2Verifier.sol")
    });

    fs::write(&output_path, &solidity_code).expect("Failed to write Halo2Verifier.sol");

    println!("Generated: {}", output_path.display());
    println!("Contract size: {} bytes", solidity_code.len());
}
