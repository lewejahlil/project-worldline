//! Prover API data model — request/response types for external integration.
//!
//! These types define the contract between Worldline and its consumers.
//! A caller submits a `ProofRequest` and receives a `ProofResponse` containing
//! proof bytes and pre-encoded calldata ready for on-chain submission.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::SystemTime;
// ── Request ──────────────────────────────────────────────────────────────────

/// A proof generation request from an external caller.
///
/// Contains all inputs needed to produce ZK proofs and encode calldata for
/// on-chain submission via `WorldlineFinalizer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRequest {
    // ── STF circuit inputs ───────────────────────────────────────────────
    /// Pre-state root (BN254 field element, 32-byte little-endian).
    #[serde(with = "hex_bytes_32")]
    pub pre_state_root: [u8; 32],
    /// Post-state root (BN254 field element, 32-byte little-endian).
    #[serde(with = "hex_bytes_32")]
    pub post_state_root: [u8; 32],
    /// Batch commitment (BN254 field element, 32-byte little-endian).
    #[serde(with = "hex_bytes_32")]
    pub batch_commitment: [u8; 32],
    /// Batch size (1–1024).
    pub batch_size: u64,

    // ── Prover configuration ─────────────────────────────────────────────
    /// Which proof systems to generate proofs for (1=Groth16, 2=Plonk, 3=Halo2).
    pub requested_systems: Vec<u8>,
    /// Prover IDs (exactly 3, zero-padded if fewer active).
    pub prover_ids: [u64; 3],
    /// Proof system IDs for each prover slot (exactly 3).
    pub proof_system_ids: [u64; 3],
    /// Quorum count (1–3).
    pub quorum_count: u64,

    // ── Submission metadata (publicInputs words 1–6) ─────────────────────
    /// L2 block range start (word 1).
    pub l2_start: u64,
    /// L2 block range end (word 2).
    pub l2_end: u64,
    /// Output root after window execution (word 3).
    #[serde(with = "hex_bytes_32")]
    pub output_root: [u8; 32],
    /// L1 block hash for chain context (word 4).
    #[serde(with = "hex_bytes_32")]
    pub l1_block_hash: [u8; 32],
    /// Domain separator (word 5).
    #[serde(with = "hex_bytes_32")]
    pub domain_separator: [u8; 32],
    /// Window close timestamp in seconds (word 6).
    pub window_close_timestamp: u64,
}

// ── Response ─────────────────────────────────────────────────────────────────

/// The result of proof generation, including pre-encoded calldata.
///
/// Contains everything needed for on-chain submission — callers should not
/// need to understand ABI encoding or compute `submissionBinding` themselves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResponse {
    /// Overall status of the proof generation.
    pub status: ProofStatus,

    /// Per-system proof results (keyed by proof system ID).
    pub proofs: BTreeMap<u8, ProverResult>,

    /// Shared stfCommitment from all inner provers (Poseidon circuit output).
    #[serde(with = "hex_bytes_32")]
    pub stf_commitment: [u8; 32],

    /// Shared proverSetDigest from all inner provers.
    #[serde(with = "hex_bytes_32")]
    pub prover_set_digest: [u8; 32],

    /// Pre-encoded 256-byte `publicInputs` with `submissionBinding` at word 7.
    /// Ready to pass directly to `WorldlineFinalizer.submitZkValidityProof()`.
    #[serde(with = "hex_bytes")]
    pub encoded_public_inputs: Vec<u8>,

    /// Pre-encoded proof calldata per proof system, keyed by `proofSystemId`.
    /// Each value is ABI-encoded in the format the corresponding adapter expects.
    pub encoded_proofs: BTreeMap<u8, EncodedProof>,

    /// Program verification key (pinned in adapter constructors).
    #[serde(with = "hex_bytes_32")]
    pub program_vkey: [u8; 32],

    /// Policy hash (pinned in adapter constructors).
    #[serde(with = "hex_bytes_32")]
    pub policy_hash: [u8; 32],
}

/// ABI-encoded proof bytes for a single proof system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodedProof {
    /// The proof system that produced this proof.
    pub proof_system_id: u8,
    /// ABI-encoded proof bytes matching the adapter's `abi.decode()` format.
    #[serde(with = "hex_bytes")]
    pub calldata: Vec<u8>,
    /// Raw proof bytes before ABI encoding (for inspection).
    #[serde(with = "hex_bytes")]
    pub raw_proof: Vec<u8>,
}

/// Per-prover result within a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverResult {
    /// Proof system that produced (or failed to produce) this proof.
    pub proof_system_id: u8,
    /// Whether this prover succeeded.
    pub success: bool,
    /// Error message if the prover failed (empty on success).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Raw proof byte length (0 on failure).
    pub proof_length: usize,
}

// ── Status types ─────────────────────────────────────────────────────────────

/// Lifecycle state for proof generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofStatus {
    /// Request accepted, not yet started.
    Pending,
    /// Proof generation in progress.
    Proving,
    /// All requested proofs generated successfully.
    Complete,
    /// Some proofs succeeded, others failed (partial success).
    Partial,
    /// All proofs failed.
    Failed,
}

/// Per-prover health signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverHealth {
    /// Which proof system this health report covers.
    pub proof_system_id: u8,
    /// Current availability status.
    pub status: HealthStatus,
    /// Timestamp of the last successful proof (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_proof_at: Option<SystemTime>,
    /// Average proof generation time in milliseconds (if known).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avg_proving_time_ms: Option<u64>,
}

/// Prover availability status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Prover is available and responsive.
    Available,
    /// Prover is available but experiencing degraded performance.
    Degraded,
    /// Prover is not available.
    Unavailable,
}

// ── Hex serde helpers ────────────────────────────────────────────────────────

pub(crate) mod hex_bytes_32 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

pub(crate) mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}
