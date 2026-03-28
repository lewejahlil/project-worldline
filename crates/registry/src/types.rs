pub type ProverId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProofSystemId {
    Groth16 = 1,
    Plonk = 2,
    Halo2 = 3,
}

#[derive(Debug, Clone)]
pub struct ProverRecord {
    pub id: ProverId,
    pub proof_system: ProofSystemId,
    pub active: bool,
}
