//! Typed errors for the worldline-driver library code.
//!
//! Binary entrypoints (`main.rs`) use `anyhow` for ergonomic error context.
//! All library modules use these typed errors instead.

use thiserror::Error;

/// Errors from registry sync operations.
#[derive(Debug, Error)]
pub enum SyncError {
    #[error("failed to fetch registry: {0}")]
    Fetch(String),
    #[error("registry response too large ({size} bytes, max {max})")]
    TooLarge { size: u64, max: u64 },
    #[error("response is not valid UTF-8: {0}")]
    InvalidUtf8(String),
    #[error("failed to parse remote registry JSON: {0}")]
    ParseJson(String),
    #[error("failed to save registry snapshot: {0}")]
    Save(String),
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
}

/// Errors from registry export and plugin check operations.
#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("failed to load registry: {0}")]
    Load(String),
    #[error("failed to serialize compat snapshot: {0}")]
    Serialize(String),
    #[error("plugin not found: {0}")]
    PluginNotFound(String),
}

/// Errors from the aggregator workflow.
#[derive(Debug, Error)]
pub enum AggregatorError {
    #[error("failed to read file {path}: {reason}")]
    FileRead { path: String, reason: String },
    #[error("failed to parse JSON: {0}")]
    ParseJson(String),
    #[error("directory signature verification failed: {0}")]
    SignatureInvalid(String),
    #[error("prover selection failed: {0}")]
    SelectionFailed(String),
    #[error("failed to write manifest: {0}")]
    ManifestWrite(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors from blob encoding/decoding.
#[derive(Debug, Error)]
pub enum BlobError {
    #[error("data too large for single blob: {size} bytes exceeds max {max}")]
    TooLarge { size: usize, max: usize },
    #[error("blob must be exactly {expected} bytes, got {actual}")]
    InvalidBlobSize { expected: usize, actual: usize },
    #[error("field element {index} has non-zero high byte 0x{byte:02x} — may exceed BLS modulus")]
    InvalidFieldElement { index: usize, byte: u8 },
}

/// Errors from proof generation and recursion.
#[derive(Debug, Error)]
pub enum RecursionError {
    #[error("k_in_proof ({k}) exceeds number of requested proof systems ({available})")]
    KExceedsSystems { k: usize, available: usize },
    #[error("k_in_proof ({k}) exceeds max_inner ({max})")]
    KExceedsMax { k: usize, max: usize },
    #[error("pipeline creation failed: {0}")]
    PipelineCreate(String),
    #[error("pipeline execution failed: {0}")]
    PipelineExec(String),
    #[error("prover creation failed: {0}")]
    ProverCreate(String),
}
