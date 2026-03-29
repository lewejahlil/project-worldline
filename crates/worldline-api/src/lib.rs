//! Prover API types and calldata encoding for the Worldline multi-ZK-prover system.
//!
//! This crate defines the external integration surface:
//! - [`ProofRequest`] — what a caller provides to request proof generation
//! - [`ProofResponse`] — what they receive, including pre-encoded calldata
//! - [`encoding`] — ABI encoding matching each on-chain adapter contract
//! - [`ApiError`] — typed errors for every failure mode

pub mod encoding;
pub mod error;
pub mod types;

pub use encoding::{
    encode_groth16_proof, encode_halo2_proof, encode_plonk_proof, encode_proof,
    encode_public_inputs,
};
pub use error::{ApiError, EncodingError, ProvingError, ValidationError};
pub use types::{
    EncodedProof, HealthStatus, ProofRequest, ProofResponse, ProofStatus, ProverHealth,
    ProverResult,
};
