use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use worldline_registry::selection::{select, DirectoryEntry, HealthStatus, Policy};

/// Build a synthetic `DirectoryEntry` consistent with the fixtures used in the test suite.
fn make_entry(i: usize) -> DirectoryEntry {
    let family = match i % 3 {
        0 => "groth16",
        1 => "sp1",
        _ => "plonk",
    };
    DirectoryEntry {
        prover_id: format!("prover-{i:04}"),
        family: family.to_string(),
        version: "1.0.0".to_string(),
        vkey_commitment: format!("0x{:064x}", i),
        image_digest: format!("0x{:064x}", i + 10_000),
        latency_ms: (i as u64 * 37 + 100) % 1_000,
        cost_usd: (i as u64 * 13 + 10) % 100,
        health: HealthStatus::Healthy,
    }
}

/// A policy that selects min(N, 8) provers (capped at MAX_MANIFEST_ENTRIES),
/// requiring at most 3 distinct families (the number of synthetic families).
fn make_policy(n: usize) -> Policy {
    Policy {
        min_count: n.min(8),
        min_distinct_families: (n / 4).clamp(1, 3),
        required_families: vec![],
        allowlist_provers: None,
        min_inclusion_ratio: 0.0,
        fallback_tiers: vec![],
        allow_degraded: false,
    }
}

/// Sweep `select()` throughput with directory sizes N = 2, 4, 8, 16, 32.
///
/// Each benchmark run performs one end-to-end selection:
///   1. Filter eligible entries.
///   2. Deterministic sort.
///   3. Prefix scan satisfying policy constraints.
///   4. Build canonical manifest JSON.
///   5. Compute `prover_set_digest = keccak256(manifest_json)`.
///
/// For N > 8, the policy and directory are sized so that selected entries
/// stay within MAX_MANIFEST_ENTRIES (8). Larger directories still exercise
/// the full filtering and sorting path.
fn bench_aggregation_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregation_throughput");
    for n in [1usize, 2, 4, 8] {
        let entries: Vec<DirectoryEntry> = (0..n).map(make_entry).collect();
        let policy = make_policy(n);
        group.bench_with_input(BenchmarkId::new("select_n_proofs", n), &n, |b, _| {
            b.iter(|| {
                let _ = select(&entries, &policy).expect("selection must succeed");
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_aggregation_throughput);
criterion_main!(benches);
