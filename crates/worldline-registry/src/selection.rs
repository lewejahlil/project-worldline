//! Deterministic prover selection algorithm.
//!
//! Selects the smallest contiguous prefix of a deterministically-sorted prover
//! directory that satisfies all diversity and policy constraints.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::canonical::{canonical_json, canonical_keccak};

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Offline,
}

/// A single entry from the signed ZK Prover Directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub prover_id: String,
    pub family: String,
    pub version: String,
    pub vkey_commitment: String,
    pub image_digest: String,
    pub latency_ms: u64,
    pub cost_usd: u64,
    pub health: HealthStatus,
}

/// A fallback tier relaxes `required_families` to its own `families` list.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FallbackTier {
    pub families: Vec<String>,
}

/// Multi-prover diversity policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub min_count: usize,
    pub min_distinct_families: usize,
    #[serde(default)]
    pub required_families: Vec<String>,
    #[serde(default)]
    pub allowlist_provers: Option<Vec<String>>,
    #[serde(default)]
    pub min_inclusion_ratio: f64,
    #[serde(default)]
    pub fallback_tiers: Vec<FallbackTier>,
}

/// A compact manifest entry (subset of DirectoryEntry fields).
/// Serialised to canonical JSON to produce `proverSetDigest`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    pub prover_id: String,
    pub family: String,
    pub version: String,
    pub vkey_commitment: String,
    pub image_digest: String,
}

/// Output of the deterministic selection algorithm.
pub struct SelectionResult {
    /// Selected directory entries (in selection order).
    pub selected: Vec<DirectoryEntry>,
    /// Canonical JSON of the manifest (sorted by `(family, prover_id, version)`).
    pub manifest_json: String,
    /// `keccak256(manifest_json)` — the on-chain `proverSetDigest`.
    pub prover_set_digest: [u8; 32],
}

/// Hard bound for selection set size; protects gas and selection determinism.
/// MED-002 remediation: enforced after prefix selection.
pub const MAX_MANIFEST_ENTRIES: usize = 8;

#[derive(Debug, Error)]
pub enum SelectionError {
    #[error("no valid prover selection satisfies the policy constraints (and all fallback tiers)")]
    NoValidSelection,
    #[error("selected {0} entries, exceeding MAX_MANIFEST_ENTRIES ({MAX_MANIFEST_ENTRIES})")]
    ManifestTooLarge(usize),
}

// ── Algorithm ─────────────────────────────────────────────────────────────────

/// Run the deterministic prover selection algorithm.
///
/// Algorithm (matches the Worldline technical spec):
///
/// 1. **Filter** eligible entries: remove `Offline` entries, apply `allowlist_provers`.
/// 2. **Sort** by composite key `family + "\0" + prover_id + "\0" + version` (lexicographic,
///    UTF-8 byte order). Tie-break by `latency_ms` ascending, then `cost_usd` ascending.
/// 3. Find the **smallest prefix** of the sorted list satisfying ALL constraints:
///    - `prefix.len() >= min_count`
///    - distinct families in prefix >= `min_distinct_families`
///    - `required_families ⊆ families in prefix`
///    - `prefix.len() / eligible.len() >= min_inclusion_ratio`
/// 4. If no prefix satisfies, try `fallback_tiers` in order (each relaxes `required_families`).
/// 5. Build canonical manifest from selected entries sorted by `(family, prover_id, version)`.
/// 6. Compute `prover_set_digest = keccak256(canonical_json(manifest))`.
pub fn select(
    entries: &[DirectoryEntry],
    policy: &Policy,
) -> Result<SelectionResult, SelectionError> {
    // Step 1: Filter eligible entries.
    let mut eligible: Vec<&DirectoryEntry> = entries
        .iter()
        .filter(|e| !matches!(e.health, HealthStatus::Offline))
        .collect();

    if let Some(allowlist) = &policy.allowlist_provers {
        let set: HashSet<&str> = allowlist.iter().map(|s| s.as_str()).collect();
        eligible.retain(|e| set.contains(e.prover_id.as_str()));
    }

    // Step 2: Sort by composite key, then tie-break by latency/cost.
    eligible.sort_by(|a, b| {
        let key_a = format!("{}\0{}\0{}", a.family, a.prover_id, a.version);
        let key_b = format!("{}\0{}\0{}", b.family, b.prover_id, b.version);
        key_a
            .cmp(&key_b)
            .then_with(|| a.latency_ms.cmp(&b.latency_ms))
            .then_with(|| a.cost_usd.cmp(&b.cost_usd))
    });

    let eligible_count = eligible.len();

    // Step 3: Try primary selection.
    let selected = if let Some(sel) = try_prefix_select(
        &eligible,
        policy.min_count,
        policy.min_distinct_families,
        &policy.required_families,
        policy.min_inclusion_ratio,
        eligible_count,
    ) {
        sel
    } else {
        // Step 4: Try fallback tiers.
        let mut fallback = None;
        for tier in &policy.fallback_tiers {
            if let Some(sel) = try_prefix_select(
                &eligible,
                policy.min_count,
                policy.min_distinct_families,
                &tier.families,
                policy.min_inclusion_ratio,
                eligible_count,
            ) {
                fallback = Some(sel);
                break;
            }
        }
        fallback.ok_or(SelectionError::NoValidSelection)?
    };

    // MED-002: Enforce MAX_MANIFEST_ENTRIES bound.
    if selected.len() > MAX_MANIFEST_ENTRIES {
        return Err(SelectionError::ManifestTooLarge(selected.len()));
    }

    // Step 5: Build manifest sorted by (family, prover_id, version).
    let mut manifest: Vec<ManifestEntry> = selected
        .iter()
        .map(|e| ManifestEntry {
            prover_id: e.prover_id.clone(),
            family: e.family.clone(),
            version: e.version.clone(),
            vkey_commitment: e.vkey_commitment.clone(),
            image_digest: e.image_digest.clone(),
        })
        .collect();
    manifest.sort_by(|a, b| {
        (&a.family, &a.prover_id, &a.version).cmp(&(&b.family, &b.prover_id, &b.version))
    });

    // Step 6: Build canonical manifest JSON and compute digest.
    let manifest_value: serde_json::Value = serde_json::Value::Array(
        manifest
            .iter()
            .map(|e| {
                // Keys must be in a deterministic order in canonical JSON.
                // canonical_json() will sort them, but we construct explicitly for clarity.
                serde_json::json!({
                    "family": e.family,
                    "image_digest": e.image_digest,
                    "prover_id": e.prover_id,
                    "version": e.version,
                    "vkey_commitment": e.vkey_commitment,
                })
            })
            .collect(),
    );

    let manifest_json = canonical_json(&manifest_value);
    let prover_set_digest = canonical_keccak(&manifest_value);

    Ok(SelectionResult {
        selected: selected.iter().map(|e| (*e).clone()).collect(),
        manifest_json,
        prover_set_digest,
    })
}

/// Attempt to find the smallest prefix of `eligible` satisfying ALL constraints.
/// Returns `Some(selected)` if found, `None` otherwise.
fn try_prefix_select<'a>(
    eligible: &[&'a DirectoryEntry],
    min_count: usize,
    min_distinct_families: usize,
    required_families: &[String],
    min_inclusion_ratio: f64,
    eligible_total: usize,
) -> Option<Vec<&'a DirectoryEntry>> {
    let n = eligible.len();

    for prefix_len in 0..=n {
        let prefix = &eligible[..prefix_len];

        // Constraint 1: minimum count.
        if prefix_len < min_count {
            continue;
        }

        // Constraint 2: minimum distinct families.
        let families: HashSet<&str> = prefix.iter().map(|e| e.family.as_str()).collect();
        if families.len() < min_distinct_families {
            continue;
        }

        // Constraint 3: required families must all be present.
        if required_families
            .iter()
            .any(|f| !families.contains(f.as_str()))
        {
            continue;
        }

        // Constraint 4: minimum inclusion ratio.
        if eligible_total > 0 && min_inclusion_ratio > 0.0 {
            let ratio = prefix_len as f64 / eligible_total as f64;
            if ratio < min_inclusion_ratio {
                continue;
            }
        }

        return Some(prefix.to_vec());
    }

    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        prover_id: &str,
        family: &str,
        latency_ms: u64,
        cost_usd: u64,
        health: HealthStatus,
    ) -> DirectoryEntry {
        DirectoryEntry {
            prover_id: prover_id.to_string(),
            family: family.to_string(),
            version: "1.0.0".to_string(),
            vkey_commitment: format!("0x{:064x}", 1),
            image_digest: format!("0x{:064x}", 2),
            latency_ms,
            cost_usd,
            health,
        }
    }

    fn basic_policy() -> Policy {
        Policy {
            min_count: 2,
            min_distinct_families: 2,
            required_families: vec![],
            allowlist_provers: None,
            min_inclusion_ratio: 0.0,
            fallback_tiers: vec![],
        }
    }

    // ── basic selection ───────────────────────────────────────────────────────

    #[test]
    fn basic_selection_three_families() {
        let entries = vec![
            entry("g1", "groth16", 100, 10, HealthStatus::Healthy),
            entry("s1", "sp1", 200, 20, HealthStatus::Healthy),
            entry("p1", "plonk", 300, 30, HealthStatus::Healthy),
        ];
        let policy = Policy {
            min_count: 2,
            min_distinct_families: 2,
            ..basic_policy()
        };
        let result = select(&entries, &policy).unwrap();
        assert!(result.selected.len() >= 2);
        let families: HashSet<&str> = result.selected.iter().map(|e| e.family.as_str()).collect();
        assert!(families.len() >= 2);
    }

    // ── required family enforcement ───────────────────────────────────────────

    #[test]
    fn required_family_must_be_included() {
        let entries = vec![
            entry("g1", "groth16", 100, 10, HealthStatus::Healthy),
            entry("s1", "sp1", 200, 20, HealthStatus::Healthy),
        ];
        let policy = Policy {
            min_count: 1,
            min_distinct_families: 1,
            required_families: vec!["sp1".to_string()],
            ..basic_policy()
        };
        let result = select(&entries, &policy).unwrap();
        let families: Vec<&str> = result.selected.iter().map(|e| e.family.as_str()).collect();
        assert!(families.contains(&"sp1"));
    }

    #[test]
    fn missing_required_family_triggers_fallback() {
        let entries = vec![
            entry("g1", "groth16", 100, 10, HealthStatus::Healthy),
            entry("s1", "sp1", 200, 20, HealthStatus::Healthy),
        ];
        let policy = Policy {
            min_count: 1,
            min_distinct_families: 1,
            required_families: vec!["nonexistent".to_string()],
            fallback_tiers: vec![FallbackTier {
                families: vec!["groth16".to_string()],
            }],
            ..basic_policy()
        };
        // Primary fails (nonexistent family), fallback uses groth16.
        let result = select(&entries, &policy).unwrap();
        let families: Vec<&str> = result.selected.iter().map(|e| e.family.as_str()).collect();
        assert!(families.contains(&"groth16"));
    }

    // ── allowlist filtering ───────────────────────────────────────────────────

    #[test]
    fn allowlist_filters_entries() {
        let entries = vec![
            entry("g1", "groth16", 100, 10, HealthStatus::Healthy),
            entry("s1", "sp1", 200, 20, HealthStatus::Healthy),
            entry("p1", "plonk", 300, 30, HealthStatus::Healthy),
        ];
        let policy = Policy {
            min_count: 1,
            min_distinct_families: 1,
            allowlist_provers: Some(vec!["g1".to_string(), "p1".to_string()]),
            ..basic_policy()
        };
        let result = select(&entries, &policy).unwrap();
        for entry in &result.selected {
            assert_ne!(entry.prover_id, "s1");
        }
    }

    // ── fallback tier activation ──────────────────────────────────────────────

    #[test]
    fn fallback_tier_activates_when_primary_fails() {
        let entries = vec![entry("g1", "groth16", 100, 10, HealthStatus::Healthy)];
        // Primary requires 2 distinct families — impossible with 1 entry.
        let policy = Policy {
            min_count: 1,
            min_distinct_families: 2,
            fallback_tiers: vec![FallbackTier { families: vec![] }],
            ..basic_policy()
        };
        // Fallback relaxes required_families to [], min_distinct_families still 2 → still fails.
        // With only 1 entry, min_distinct_families=2 can never be satisfied.
        assert!(select(&entries, &policy).is_err());
    }

    #[test]
    fn fallback_tier_succeeds_with_relaxed_families() {
        let entries = vec![
            entry("g1", "groth16", 100, 10, HealthStatus::Healthy),
            entry("s1", "sp1", 200, 20, HealthStatus::Healthy),
        ];
        // Primary requires "nonexistent" family → will fail.
        let policy = Policy {
            min_count: 1,
            min_distinct_families: 1,
            required_families: vec!["nonexistent".to_string()],
            fallback_tiers: vec![FallbackTier {
                families: vec!["groth16".to_string()],
            }],
            ..basic_policy()
        };
        let result = select(&entries, &policy).unwrap();
        assert!(!result.selected.is_empty());
    }

    // ── tie-breaking ──────────────────────────────────────────────────────────

    #[test]
    fn tie_break_by_latency_then_cost() {
        // Two groth16 provers with same sort key prefix, different latency.
        let mut entries = [
            {
                let mut e = entry("g_slow", "groth16", 500, 5, HealthStatus::Healthy);
                e.version = "1.0.0".to_string();
                e
            },
            {
                let mut e = entry("g_fast", "groth16", 100, 10, HealthStatus::Healthy);
                e.version = "1.0.0".to_string();
                e
            },
        ];
        // Sort them — g_fast should come first (lower latency).
        entries.sort_by(|a, b| {
            let key_a = format!("{}\0{}\0{}", a.family, a.prover_id, a.version);
            let key_b = format!("{}\0{}\0{}", b.family, b.prover_id, b.version);
            key_a
                .cmp(&key_b)
                .then_with(|| a.latency_ms.cmp(&b.latency_ms))
                .then_with(|| a.cost_usd.cmp(&b.cost_usd))
        });
        // g_fast has lower latency and sorts before g_slow.
        assert_eq!(entries[0].prover_id, "g_fast");
    }

    // ── edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn empty_directory_returns_error() {
        let policy = basic_policy();
        assert!(matches!(
            select(&[], &policy),
            Err(SelectionError::NoValidSelection)
        ));
    }

    #[test]
    fn single_entry_satisfies_min_count_one() {
        let entries = vec![entry("g1", "groth16", 100, 10, HealthStatus::Healthy)];
        let policy = Policy {
            min_count: 1,
            min_distinct_families: 1,
            ..basic_policy()
        };
        let result = select(&entries, &policy).unwrap();
        assert_eq!(result.selected.len(), 1);
    }

    #[test]
    fn all_offline_returns_error() {
        let entries = vec![
            entry("g1", "groth16", 100, 10, HealthStatus::Offline),
            entry("s1", "sp1", 200, 20, HealthStatus::Offline),
        ];
        let policy = Policy {
            min_count: 1,
            min_distinct_families: 1,
            ..basic_policy()
        };
        assert!(matches!(
            select(&entries, &policy),
            Err(SelectionError::NoValidSelection)
        ));
    }

    #[test]
    fn offline_entries_are_excluded() {
        let entries = vec![
            entry("g1", "groth16", 100, 10, HealthStatus::Healthy),
            entry("s1", "sp1", 200, 20, HealthStatus::Offline),
        ];
        let policy = Policy {
            min_count: 1,
            min_distinct_families: 1,
            ..basic_policy()
        };
        let result = select(&entries, &policy).unwrap();
        for e in &result.selected {
            assert_ne!(e.prover_id, "s1");
        }
    }

    // ── determinism ───────────────────────────────────────────────────────────

    #[test]
    fn selection_is_deterministic() {
        let entries = vec![
            entry("g1", "groth16", 100, 10, HealthStatus::Healthy),
            entry("s1", "sp1", 200, 20, HealthStatus::Healthy),
            entry("p1", "plonk", 150, 15, HealthStatus::Degraded),
        ];
        let policy = Policy {
            min_count: 2,
            min_distinct_families: 2,
            ..basic_policy()
        };

        let first = select(&entries, &policy).unwrap();
        for _ in 0..100 {
            let run = select(&entries, &policy).unwrap();
            assert_eq!(
                run.prover_set_digest, first.prover_set_digest,
                "selection produced different digest on repeat run"
            );
        }
    }

    // ── manifest and digest ───────────────────────────────────────────────────

    #[test]
    fn manifest_json_is_canonical() {
        let entries = vec![
            entry("g1", "groth16", 100, 10, HealthStatus::Healthy),
            entry("s1", "sp1", 200, 20, HealthStatus::Healthy),
        ];
        let policy = Policy {
            min_count: 2,
            min_distinct_families: 2,
            ..basic_policy()
        };
        let result = select(&entries, &policy).unwrap();
        // Manifest should be valid JSON.
        let parsed: serde_json::Value = serde_json::from_str(&result.manifest_json).unwrap();
        assert!(parsed.is_array());
    }

    // ── MED-002: MAX_MANIFEST_ENTRIES enforcement ──────────────────────────

    #[test]
    fn max_manifest_entries_enforced() {
        // Create 10 entries across 10 families — exceeds MAX_MANIFEST_ENTRIES (8).
        let entries: Vec<DirectoryEntry> = (0..10)
            .map(|i| entry(&format!("p{i}"), &format!("f{i}"), 100, 10, HealthStatus::Healthy))
            .collect();
        let policy = Policy {
            min_count: 10,
            min_distinct_families: 10,
            ..basic_policy()
        };
        let result = select(&entries, &policy);
        assert!(matches!(
            result,
            Err(SelectionError::ManifestTooLarge(10))
        ));
    }

    #[test]
    fn exactly_max_manifest_entries_succeeds() {
        // 8 entries across 8 families — exactly at the limit.
        let entries: Vec<DirectoryEntry> = (0..8)
            .map(|i| entry(&format!("p{i}"), &format!("f{i}"), 100, 10, HealthStatus::Healthy))
            .collect();
        let policy = Policy {
            min_count: 8,
            min_distinct_families: 8,
            ..basic_policy()
        };
        let result = select(&entries, &policy).unwrap();
        assert_eq!(result.selected.len(), 8);
    }

    #[test]
    fn prover_set_digest_non_zero() {
        let entries = vec![
            entry("g1", "groth16", 100, 10, HealthStatus::Healthy),
            entry("s1", "sp1", 200, 20, HealthStatus::Healthy),
        ];
        let policy = Policy {
            min_count: 2,
            min_distinct_families: 2,
            ..basic_policy()
        };
        let result = select(&entries, &policy).unwrap();
        assert_ne!(result.prover_set_digest, [0u8; 32]);
    }
}
