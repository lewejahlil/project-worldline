//! Generate a Halo2 test proof and print its hex encoding.
//!
//! Usage: cargo run -p worldline-halo2-circuit --example generate_proof

use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk},
    poly::kzg::{commitment::KZGCommitmentScheme, multiopen::ProverSHPLONK},
    poly::kzg::commitment::ParamsKZG,
    transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2curves::group::ff::PrimeField;
use rand::rngs::OsRng;
use worldline_halo2_circuit::WorldlineStfCircuit;

fn main() {
    let pre_state_root = Fr::from(1234567890u64);
    let post_state_root = Fr::from(9876543210u64);
    let batch_commitment = Fr::from(5555555555u64);
    let batch_size = Fr::from(100u64);
    let prover_ids = [Fr::from(101u64), Fr::from(102u64), Fr::from(103u64)];
    let proof_system_ids = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let quorum_count = Fr::from(3u64);

    let circuit = WorldlineStfCircuit::new(
        pre_state_root, post_state_root, batch_commitment, batch_size,
        prover_ids, proof_system_ids, quorum_count,
    );
    let (stf, digest) = WorldlineStfCircuit::compute_public_outputs(
        pre_state_root, post_state_root, batch_commitment,
        prover_ids, proof_system_ids, quorum_count,
    );

    let k = 8u32;
    let params = ParamsKZG::<Bn256>::setup(k, OsRng);
    let empty_circuit = WorldlineStfCircuit::default();
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk");

    let instances = vec![vec![stf, digest]];
    let instances_ref: Vec<&[Fr]> = instances.iter().map(|v| v.as_slice()).collect();

    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
        &params, &pk, &[circuit], &[instances_ref.as_slice()], OsRng, &mut transcript,
    )
    .expect("proof generation");

    let proof_bytes = transcript.finalize();

    // Convert Fr to 32-byte big-endian representation
    fn fr_to_hex(f: &Fr) -> String {
        let repr = f.to_repr();
        // repr is little-endian; reverse for big-endian
        let mut bytes = repr.as_ref().to_vec();
        bytes.reverse();
        format!("0x{}", hex::encode(bytes))
    }

    println!("Proof length: {} bytes", proof_bytes.len());
    println!("Proof hex: 0x{}", hex::encode(&proof_bytes));
    println!("stfCommitment: {}", fr_to_hex(&stf));
    println!("proverSetDigest: {}", fr_to_hex(&digest));
}
