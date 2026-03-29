//! Halo2 inner prover using native Rust `halo2_proofs` (PSE fork, KZG on BN254).
//!
//! Unlike Groth16/Plonk which use snarkjs subprocesses, the Halo2 prover runs
//! entirely in-process via the `worldline-halo2-circuit` crate. This is the
//! most mature proving path — no external dependencies required at runtime.
//!
//! Proof format: variable-length KZG proof bytes (measured at 2016 bytes for k=8,
//! Keccak256 transcript). The adapter envelope adds metadata for on-chain submission.

use crate::prover_traits::{InnerProofOutput, InnerProver, ProverError, StfInputs};
use crate::types::ProofSystemId;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk},
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::ProverSHPLONK,
    },
    transcript::TranscriptWriterBuffer,
};
use halo2_solidity_verifier::Keccak256Transcript;
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2curves::group::ff::PrimeField;
use rand::rngs::OsRng;
use worldline_halo2_circuit::WorldlineStfCircuit;

/// Measured proof byte length for Halo2 KZG proofs with k=8 (Keccak256 transcript).
pub const HALO2_PROOF_BYTES: usize = 2016;

/// Circuit parameter k (log2 of rows). k=8 → 256 rows.
const K: u32 = 8;

/// Halo2 prover with pre-generated KZG parameters and proving key.
pub struct Halo2Prover {
    params: ParamsKZG<Bn256>,
    pk: halo2_proofs::plonk::ProvingKey<G1Affine>,
}

impl Halo2Prover {
    /// Create a new Halo2 prover.
    ///
    /// Generates KZG parameters and proving key from the empty circuit.
    /// This is a one-time setup cost that can be amortized across proofs.
    pub fn new() -> Result<Self, ProverError> {
        let params = ParamsKZG::<Bn256>::setup(K, OsRng);
        let empty_circuit = WorldlineStfCircuit::default();
        let vk = keygen_vk(&params, &empty_circuit)
            .map_err(|e| ProverError::ProofGeneration(format!("keygen_vk: {e}")))?;
        let pk = keygen_pk(&params, vk, &empty_circuit)
            .map_err(|e| ProverError::ProofGeneration(format!("keygen_pk: {e}")))?;
        Ok(Self { params, pk })
    }

    /// Convert `StfInputs` byte arrays to BN254 field elements for the circuit.
    fn inputs_to_circuit(inputs: &StfInputs) -> Result<WorldlineStfCircuit, ProverError> {
        let pre_state_root = bytes_to_fr(&inputs.pre_state_root)?;
        let post_state_root = bytes_to_fr(&inputs.post_state_root)?;
        let batch_commitment = bytes_to_fr(&inputs.batch_commitment)?;
        let batch_size = Fr::from(inputs.batch_size);
        let prover_ids = [
            Fr::from(inputs.prover_ids[0]),
            Fr::from(inputs.prover_ids[1]),
            Fr::from(inputs.prover_ids[2]),
        ];
        let proof_system_ids = [
            Fr::from(inputs.proof_system_ids[0]),
            Fr::from(inputs.proof_system_ids[1]),
            Fr::from(inputs.proof_system_ids[2]),
        ];
        let quorum_count = Fr::from(inputs.quorum_count);

        Ok(WorldlineStfCircuit::new(
            pre_state_root,
            post_state_root,
            batch_commitment,
            batch_size,
            prover_ids,
            proof_system_ids,
            quorum_count,
        ))
    }

    /// Compute public outputs for the given inputs.
    fn compute_public_outputs(inputs: &StfInputs) -> Result<(Fr, Fr), ProverError> {
        let pre = bytes_to_fr(&inputs.pre_state_root)?;
        let post = bytes_to_fr(&inputs.post_state_root)?;
        let batch = bytes_to_fr(&inputs.batch_commitment)?;
        let pids = [
            Fr::from(inputs.prover_ids[0]),
            Fr::from(inputs.prover_ids[1]),
            Fr::from(inputs.prover_ids[2]),
        ];
        let psids = [
            Fr::from(inputs.proof_system_ids[0]),
            Fr::from(inputs.proof_system_ids[1]),
            Fr::from(inputs.proof_system_ids[2]),
        ];
        let qc = Fr::from(inputs.quorum_count);

        Ok(WorldlineStfCircuit::compute_public_outputs(
            pre, post, batch, pids, psids, qc,
        ))
    }
}

/// Convert a 32-byte little-endian array to a BN254 field element.
fn bytes_to_fr(bytes: &[u8; 32]) -> Result<Fr, ProverError> {
    Option::from(Fr::from_repr(*bytes)).ok_or_else(|| {
        ProverError::InvalidInput(format!(
            "bytes do not represent a valid BN254 field element: 0x{}",
            hex::encode(bytes)
        ))
    })
}

impl InnerProver for Halo2Prover {
    fn prove(&self, inputs: &StfInputs) -> Result<InnerProofOutput, ProverError> {
        crate::groth16_prover::validate_stf_inputs(inputs)?;

        let circuit = Self::inputs_to_circuit(inputs)?;
        let (stf_commitment, prover_set_digest) = Self::compute_public_outputs(inputs)?;

        let instances = [vec![stf_commitment, prover_set_digest]];
        let instances_ref: Vec<&[Fr]> = instances.iter().map(|v| v.as_slice()).collect();

        let mut transcript = Keccak256Transcript::<G1Affine, Vec<u8>>::init(vec![]);
        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
            &self.params,
            &self.pk,
            &[circuit],
            &[instances_ref.as_slice()],
            OsRng,
            &mut transcript,
        )
        .map_err(|e| ProverError::ProofGeneration(format!("create_proof: {e}")))?;

        let proof_bytes = transcript.finalize();

        let public_signals = [stf_commitment.to_repr(), prover_set_digest.to_repr()];

        Ok(InnerProofOutput {
            proof_data: proof_bytes,
            public_signals,
            proof_system: ProofSystemId::Halo2,
        })
    }

    fn proof_system_id(&self) -> ProofSystemId {
        ProofSystemId::Halo2
    }

    fn expected_proof_length(&self) -> usize {
        HALO2_PROOF_BYTES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_inputs() -> StfInputs {
        StfInputs {
            pre_state_root: Fr::from(1234567890u64).to_repr(),
            post_state_root: Fr::from(9876543210u64).to_repr(),
            batch_commitment: Fr::from(5555555555u64).to_repr(),
            batch_size: 100,
            prover_ids: [101, 102, 103],
            proof_system_ids: [1, 2, 3],
            quorum_count: 3,
        }
    }

    #[test]
    fn halo2_prove_real() {
        let prover = Halo2Prover::new().unwrap();
        let inputs = test_inputs();
        let output = prover.prove(&inputs).unwrap();

        assert_eq!(output.proof_data.len(), HALO2_PROOF_BYTES);
        assert_eq!(output.proof_system, ProofSystemId::Halo2);

        // Verify public signals match Poseidon computation
        let pre = Fr::from(1234567890u64);
        let post = Fr::from(9876543210u64);
        let batch = Fr::from(5555555555u64);
        let stf = worldline_halo2_circuit::poseidon_compress_3(pre, post, batch);
        assert_eq!(output.public_signals[0], stf.to_repr());

        let digest = worldline_halo2_circuit::poseidon_compress_7(
            Fr::from(101u64),
            Fr::from(102u64),
            Fr::from(103u64),
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(3u64),
        );
        assert_eq!(output.public_signals[1], digest.to_repr());
    }

    #[test]
    fn halo2_prove_boundary_batch_sizes() {
        let prover = Halo2Prover::new().unwrap();

        // batch_size = 1 (minimum)
        let mut inputs = test_inputs();
        inputs.batch_size = 1;
        let output = prover.prove(&inputs).unwrap();
        assert_eq!(output.proof_data.len(), HALO2_PROOF_BYTES);

        // batch_size = 1024 (maximum)
        inputs.batch_size = 1024;
        let output = prover.prove(&inputs).unwrap();
        assert_eq!(output.proof_data.len(), HALO2_PROOF_BYTES);
    }

    #[test]
    fn halo2_rejects_invalid_inputs() {
        let prover = Halo2Prover::new().unwrap();

        // batch_size = 0
        let mut inputs = test_inputs();
        inputs.batch_size = 0;
        assert!(prover.prove(&inputs).is_err());

        // batch_size = 1025
        inputs.batch_size = 1025;
        assert!(prover.prove(&inputs).is_err());

        // prover_id = 0
        inputs.batch_size = 100;
        inputs.prover_ids[1] = 0;
        assert!(prover.prove(&inputs).is_err());
    }

    #[test]
    fn halo2_proof_length_consistent() {
        let prover = Halo2Prover::new().unwrap();

        // Generate two proofs with different inputs and verify same length
        let inputs1 = test_inputs();
        let mut inputs2 = test_inputs();
        inputs2.batch_size = 512;
        inputs2.quorum_count = 1;

        let output1 = prover.prove(&inputs1).unwrap();
        let output2 = prover.prove(&inputs2).unwrap();

        assert_eq!(output1.proof_data.len(), output2.proof_data.len());
        assert_eq!(output1.proof_data.len(), HALO2_PROOF_BYTES);
    }

    /// Three-way consistency: Groth16, Plonk, and Halo2 must produce identical
    /// public signals (stfCommitment, proverSetDigest) for the same STF inputs.
    #[test]
    #[ignore = "requires snarkjs installed and circuit artifacts"]
    fn three_way_cross_prover_consistency() {
        use crate::{Groth16Prover, PlonkProver};
        use std::path::PathBuf;

        let inputs = test_inputs();

        let groth16 = Groth16Prover::new(
            PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../circuits/build/worldline_stf_js/worldline_stf.wasm"
            )),
            PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../circuits/zkeys/worldline_stf_final.zkey"
            )),
        )
        .unwrap();

        let plonk = PlonkProver::new(
            PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../circuits/build/worldline_stf_plonk_js/worldline_stf_plonk.wasm"
            )),
            PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../circuits/zkeys/worldline_stf_plonk_v2.zkey"
            )),
        )
        .unwrap();

        let halo2 = Halo2Prover::new().unwrap();

        let g16_output = groth16.prove(&inputs).unwrap();
        let plonk_output = plonk.prove(&inputs).unwrap();
        let halo2_output = halo2.prove(&inputs).unwrap();

        // stfCommitment must be identical across all three
        assert_eq!(
            g16_output.public_signals[0], plonk_output.public_signals[0],
            "stfCommitment: Groth16 != Plonk"
        );
        assert_eq!(
            g16_output.public_signals[0], halo2_output.public_signals[0],
            "stfCommitment: Groth16 != Halo2"
        );

        // proverSetDigest must be identical across all three
        assert_eq!(
            g16_output.public_signals[1], plonk_output.public_signals[1],
            "proverSetDigest: Groth16 != Plonk"
        );
        assert_eq!(
            g16_output.public_signals[1], halo2_output.public_signals[1],
            "proverSetDigest: Groth16 != Halo2"
        );

        // Proof formats differ
        assert_eq!(g16_output.proof_data.len(), 320);
        assert_eq!(plonk_output.proof_data.len(), 832);
        assert_eq!(halo2_output.proof_data.len(), HALO2_PROOF_BYTES);
    }
}
