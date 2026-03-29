#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSystemId {
    Groth16 = 1,
    Plonk = 2,
    Halo2 = 3,
}

#[derive(Debug, Clone)]
pub struct IndividualProof {
    pub prover_id: u64,
    pub proof_system: ProofSystemId,
    pub proof_data: Vec<u8>,
    pub public_inputs: Vec<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct AggregatedProof {
    pub proofs: Vec<IndividualProof>,
    pub quorum_count: u8,
    pub batch_commitment: [u8; 32],
    pub stf_commitment: [u8; 32],
    pub prover_set_digest: [u8; 32],
    pub verified_count: u8,
    pub verification_results: Vec<(u64, ProofSystemId, bool)>, // (prover_id, system, passed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregationStrategy {
    Independent,
    Sequential,
}

/// Expected proof byte sizes for each proof system (BN254 pairing format).
pub const GROTH16_PROOF_BYTE_SIZE: usize = 320;
pub const PLONK_PROOF_BYTE_SIZE: usize = 832;
pub const HALO2_PROOF_BYTE_SIZE: usize = 2016;

/// Maximum batch size enforced by the STF circuit constraint.
pub const MAX_BATCH_SIZE: u64 = 1024;
