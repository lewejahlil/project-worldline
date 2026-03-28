//! Recursion witness scaffolding for the Worldline aggregator.
//!
//! Supports three recursion modes:
//!
//! | Mode                    | Description                                                |
//! |-------------------------|------------------------------------------------------------|
//! | `None`                  | No inner proof recursion; outer proof covers all provers.  |
//! | `SnarkAccumulator`      | Accumulate inner proofs before producing the outer proof.  |
//! | `SnarkMiniVerifier`     | Inline mini-verifier circuit verifies inner proofs.        |
//!
//! See `circuits/recursion/README.md` for detailed trade-offs and activation criteria.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use worldline_registry::selection::ManifestEntry;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Recursion mode as defined in the Worldline policy schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RecursionMode {
    #[default]
    None,
    SnarkAccumulator,
    SnarkMiniVerifier,
}

/// Configuration controlling whether and how inner proofs are recursed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursionConfig {
    pub mode: RecursionMode,
    /// Number of inner proofs to include in the outer proof (0–4 per spec).
    pub k_in_proof: u8,
    /// Upper bound on the number of inner proofs.
    pub max_inner: u8,
}

impl Default for RecursionConfig {
    fn default() -> Self {
        Self {
            mode: RecursionMode::None,
            k_in_proof: 0,
            max_inner: 4,
        }
    }
}

/// A recursion witness built from the selected manifest entries.
///
/// Carries the raw proof bytes from each inner prover (one entry per selected
/// manifest entry up to `k_in_proof`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursionWitness {
    pub mode: RecursionMode,
    pub k_in_proof: u8,
    /// Raw proof bytes per inner prover (length == k_in_proof).
    pub inner_proofs: Vec<Vec<u8>>,
    /// Number of provers that were selected (may be > k_in_proof).
    pub selected_count: u8,
}

// ── build_recursion_witness ───────────────────────────────────────────────────

/// Build a recursion witness from the selected manifest entries.
///
/// # Returns
/// - `Ok(None)` when `config.mode == RecursionMode::None`.
/// - `Ok(Some(witness))` with a structured placeholder when mode is active.
/// - `Err(…)` if configuration constraints are violated.
///
/// # Errors
/// - `k_in_proof > manifest.len()` — cannot request more inner proofs than provers selected.
/// - `k_in_proof > max_inner` — exceeds the configured cap.
///
/// # TODO
/// Actual inner proof collection requires live prover connections. The current
/// implementation returns a structured placeholder (empty proof bytes) so that
/// the rest of the aggregation pipeline can be exercised without live provers.
pub fn build_recursion_witness(
    config: &RecursionConfig,
    manifest: &[ManifestEntry],
) -> Result<Option<RecursionWitness>> {
    if config.mode == RecursionMode::None {
        return Ok(None);
    }

    let k = config.k_in_proof as usize;
    let max = config.max_inner as usize;

    // Validate k_in_proof against manifest length.
    if k > manifest.len() {
        bail!(
            "k_in_proof ({k}) exceeds manifest length ({}) — cannot request more inner proofs \
             than provers selected",
            manifest.len()
        );
    }

    // Validate k_in_proof against max_inner cap.
    if k > max {
        bail!("k_in_proof ({k}) exceeds max_inner ({max}) — configuration constraint violated");
    }

    // PLACEHOLDER: replaced in Phase 1 Chunk 4
    // TODO: Actual inner proof collection from live prover endpoints.
    // In production, this would:
    // 1. Contact each of the first `k_in_proof` prover endpoints.
    // 2. Request a proof for the current window's witness.
    // 3. Collect and validate each proof against the prover's vkey_commitment.
    // For now, return structured placeholder witnesses (empty proof bytes).
    let inner_proofs: Vec<Vec<u8>> = (0..k).map(|_| vec![]).collect();

    Ok(Some(RecursionWitness {
        mode: config.mode.clone(),
        k_in_proof: config.k_in_proof,
        inner_proofs,
        selected_count: manifest.len().min(u8::MAX as usize) as u8,
    }))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest(n: usize) -> Vec<ManifestEntry> {
        (0..n)
            .map(|i| ManifestEntry {
                prover_id: format!("prover-{i}"),
                family: "groth16".to_string(),
                version: "1.0.0".to_string(),
                vkey_commitment: format!("0x{:064x}", i),
                image_digest: format!("0x{:064x}", i + 100),
            })
            .collect()
    }

    #[test]
    fn none_mode_returns_ok_none() {
        let config = RecursionConfig {
            mode: RecursionMode::None,
            k_in_proof: 0,
            max_inner: 4,
        };
        let manifest = sample_manifest(3);
        let result = build_recursion_witness(&config, &manifest).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn k_in_proof_gt_manifest_returns_error() {
        let manifest = sample_manifest(2);
        let config = RecursionConfig {
            mode: RecursionMode::SnarkAccumulator,
            k_in_proof: 3, // > manifest.len() = 2
            max_inner: 4,
        };
        let err = build_recursion_witness(&config, &manifest).unwrap_err();
        assert!(err.to_string().contains("exceeds manifest length"));
    }

    #[test]
    fn k_in_proof_gt_max_inner_returns_error() {
        let manifest = sample_manifest(5);
        let config = RecursionConfig {
            mode: RecursionMode::SnarkMiniVerifier,
            k_in_proof: 5, // > max_inner = 4
            max_inner: 4,
        };
        let err = build_recursion_witness(&config, &manifest).unwrap_err();
        assert!(err.to_string().contains("exceeds max_inner"));
    }

    #[test]
    fn snark_accum_returns_placeholder_witness() {
        let manifest = sample_manifest(3);
        let config = RecursionConfig {
            mode: RecursionMode::SnarkAccumulator,
            k_in_proof: 2,
            max_inner: 4,
        };
        let witness = build_recursion_witness(&config, &manifest)
            .unwrap()
            .expect("should return Some");
        assert_eq!(witness.mode, RecursionMode::SnarkAccumulator);
        assert_eq!(witness.k_in_proof, 2);
        assert_eq!(witness.inner_proofs.len(), 2);
        assert_eq!(witness.selected_count, 3);
    }

    #[test]
    fn witness_serialises_and_deserialises() {
        let manifest = sample_manifest(2);
        let config = RecursionConfig {
            mode: RecursionMode::SnarkMiniVerifier,
            k_in_proof: 1,
            max_inner: 4,
        };
        let witness = build_recursion_witness(&config, &manifest)
            .unwrap()
            .expect("should return Some");
        let json = serde_json::to_string(&witness).unwrap();
        let parsed: RecursionWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.k_in_proof, witness.k_in_proof);
        assert_eq!(parsed.selected_count, witness.selected_count);
    }

    #[test]
    fn zero_k_in_proof_returns_empty_witnesses() {
        let manifest = sample_manifest(3);
        let config = RecursionConfig {
            mode: RecursionMode::SnarkAccumulator,
            k_in_proof: 0,
            max_inner: 4,
        };
        let witness = build_recursion_witness(&config, &manifest)
            .unwrap()
            .expect("should return Some");
        assert_eq!(witness.inner_proofs.len(), 0);
    }
}
