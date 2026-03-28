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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregationStrategy {
    Independent,
    Sequential,
}
