pub use worldline_aggregation::types::{AggregatedProof, ProofSystemId};

#[derive(Debug, Clone)]
pub struct RecursiveProof {
    pub inner_proof: AggregatedProof,
    pub recursion_depth: u8,
    pub outer_proof_data: Vec<u8>,
    pub verification_key_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecursionMode {
    Single,
    Incremental,
}
