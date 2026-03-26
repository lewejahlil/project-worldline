//! Minimal aggregator workflow.
//!
//! Loads a signed directory + policy, verifies the directory signature, runs
//! deterministic prover selection, computes `policy_hash`, and writes the
//! canonical manifest to disk.

use std::path::PathBuf;

use anyhow::{Context, Result};
use tracing::info;
use worldline_registry::canonical::canonical_keccak;
use worldline_registry::directory::{verify_directory_signature, SignedDirectory};
use worldline_registry::selection::{select, Policy};

// ── Types ─────────────────────────────────────────────────────────────────────

/// Configuration for one aggregator run.
pub struct AggregatorConfig {
    /// Path to the signed directory JSON (conforming to `schemas/directory.schema.json`).
    pub directory_path: PathBuf,
    /// Path to the policy JSON (conforming to `schemas/policy.schema.json`).
    pub policy_path: PathBuf,
    /// Path to the local registry snapshot JSON (used for future cross-checks).
    pub registry_path: PathBuf,
    /// Where to write the canonical manifest output.
    pub output_manifest_path: PathBuf,
}

/// Output of a successful aggregator run.
pub struct AggregatorOutput {
    /// Canonical JSON of the selected manifest.
    pub manifest_json: String,
    /// `keccak256(manifest_json)` — the on-chain `proverSetDigest`.
    pub prover_set_digest: [u8; 32],
    /// `keccak256(canonical_json(policy))` — the on-chain `policyHash`.
    pub policy_hash: [u8; 32],
    /// Number of provers selected.
    pub selected_count: usize,
}

// ── run_aggregator ────────────────────────────────────────────────────────────

/// Execute one aggregator cycle:
///
/// 1. Load and deserialise the signed directory.
/// 2. Verify the directory signature (warn on failure if signature check is stubbed).
/// 3. Load and deserialise the policy.
/// 4. Compute `policy_hash = keccak256(canonical_json(policy))`.
/// 5. Run deterministic prover selection.
/// 6. Write the canonical manifest to `output_manifest_path`.
/// 7. Return [`AggregatorOutput`].
pub fn run_aggregator(config: &AggregatorConfig) -> Result<AggregatorOutput> {
    // ── Step 1: Load directory ────────────────────────────────────────────────
    info!(path = %config.directory_path.display(), "loading signed directory");
    let dir_str = std::fs::read_to_string(&config.directory_path).with_context(|| {
        format!(
            "failed to read directory: {}",
            config.directory_path.display()
        )
    })?;
    let directory: SignedDirectory =
        serde_json::from_str(&dir_str).with_context(|| "failed to parse directory JSON")?;
    info!(
        entries = directory.entries.len(),
        version = %directory.version,
        "loaded directory"
    );

    // ── Step 2: Verify directory signature ───────────────────────────────────
    // The aggregator MUST abort if the directory signature is invalid.
    // An unverified directory could contain attacker-controlled prover entries.
    match verify_directory_signature(&directory) {
        Ok(true) => {
            info!("directory signature verified successfully");
        }
        Ok(false) => {
            // verify_directory_signature() now returns Err on mismatch, so this
            // branch is unreachable. Kept as a defensive guard.
            unreachable!(
                "verify_directory_signature returned Ok(false); \
                 mismatch should produce Err(SignerMismatch)"
            );
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "directory signature verification failed — aborting: {e}"
            ));
        }
    }

    // ── Step 3: Load policy ───────────────────────────────────────────────────
    info!(path = %config.policy_path.display(), "loading policy");
    let policy_str = std::fs::read_to_string(&config.policy_path)
        .with_context(|| format!("failed to read policy: {}", config.policy_path.display()))?;
    let policy_value: serde_json::Value =
        serde_json::from_str(&policy_str).with_context(|| "failed to parse policy JSON")?;
    let policy: Policy = serde_json::from_value(policy_value.clone())
        .with_context(|| "failed to deserialise policy into Policy struct")?;
    info!(
        min_count = policy.min_count,
        min_distinct_families = policy.min_distinct_families,
        "loaded policy"
    );

    // ── Step 4: Compute policy_hash ───────────────────────────────────────────
    let policy_hash = canonical_keccak(&policy_value);
    info!(
        policy_hash = %hex::encode(policy_hash),
        "computed policy_hash"
    );

    // ── Step 5: Run deterministic selection ───────────────────────────────────
    info!("running deterministic prover selection");
    let result = select(&directory.entries, &policy)
        .with_context(|| "prover selection failed — no valid selection satisfies policy")?;
    info!(
        selected = result.selected.len(),
        prover_set_digest = %hex::encode(result.prover_set_digest),
        "selection complete"
    );

    // ── Step 6: Write manifest to disk ────────────────────────────────────────
    if let Some(parent) = config.output_manifest_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create manifest output directory: {}",
                parent.display()
            )
        })?;
    }
    std::fs::write(&config.output_manifest_path, &result.manifest_json).with_context(|| {
        format!(
            "failed to write manifest: {}",
            config.output_manifest_path.display()
        )
    })?;
    info!(
        path = %config.output_manifest_path.display(),
        "manifest written"
    );

    Ok(AggregatorOutput {
        manifest_json: result.manifest_json,
        prover_set_digest: result.prover_set_digest,
        policy_hash,
        selected_count: result.selected.len(),
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
    }

    #[test]
    fn run_aggregator_with_sample_fixtures() {
        let dir = tempdir().unwrap();
        let output_manifest = dir.path().join("manifest.json");

        let config = AggregatorConfig {
            directory_path: fixtures_dir().join("sample-directory.json"),
            policy_path: fixtures_dir().join("sample-policy.json"),
            registry_path: fixtures_dir().join("sample-directory.json"), // not used yet
            output_manifest_path: output_manifest.clone(),
        };

        let result = run_aggregator(&config).unwrap();
        assert!(
            result.selected_count >= 1,
            "at least one prover must be selected"
        );
        assert_ne!(result.prover_set_digest, [0u8; 32]);
        assert_ne!(result.policy_hash, [0u8; 32]);

        // Manifest should be written to disk.
        assert!(output_manifest.exists());
        let manifest_str = std::fs::read_to_string(&output_manifest).unwrap();
        let manifest_json: serde_json::Value = serde_json::from_str(&manifest_str).unwrap();
        assert!(manifest_json.is_array());
    }

    #[test]
    fn policy_hash_is_keccak_of_canonical_policy() {
        let dir = tempdir().unwrap();
        let config = AggregatorConfig {
            directory_path: fixtures_dir().join("sample-directory.json"),
            policy_path: fixtures_dir().join("sample-policy.json"),
            registry_path: fixtures_dir().join("sample-directory.json"),
            output_manifest_path: dir.path().join("manifest.json"),
        };

        let result = run_aggregator(&config).unwrap();

        // Independently compute the policy hash and compare.
        let policy_str =
            std::fs::read_to_string(fixtures_dir().join("sample-policy.json")).unwrap();
        let policy_value: serde_json::Value = serde_json::from_str(&policy_str).unwrap();
        let expected_hash = canonical_keccak(&policy_value);
        assert_eq!(result.policy_hash, expected_hash);
    }
}
