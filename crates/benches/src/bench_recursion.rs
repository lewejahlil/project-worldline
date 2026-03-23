use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use worldline_driver::recursion::{build_recursion_witness, RecursionConfig, RecursionMode};
use worldline_registry::selection::ManifestEntry;

/// Build a synthetic manifest of `n` entries consistent with those in the test suite.
fn make_manifest(n: usize) -> Vec<ManifestEntry> {
    (0..n)
        .map(|i| ManifestEntry {
            prover_id: format!("prover-{i:04}"),
            family: if i % 2 == 0 {
                "groth16".to_string()
            } else {
                "sp1".to_string()
            },
            version: "1.0.0".to_string(),
            vkey_commitment: format!("0x{:064x}", i),
            image_digest: format!("0x{:064x}", i + 10_000),
        })
        .collect()
}

/// Sweep `build_recursion_witness()` end-to-end latency at recursion depths 1, 2, 4, 8.
///
/// Depth corresponds to `k_in_proof` — the number of inner proofs included in the outer
/// proof. At each depth, the benchmark measures the full witness-building path including
/// entry slicing and structured placeholder construction.
fn bench_recursion_depth(c: &mut Criterion) {
    let mut group = c.benchmark_group("recursion_depth");
    // A manifest large enough to satisfy all tested depths.
    let manifest = make_manifest(32);
    for depth in [1usize, 2, 4, 8] {
        let config = RecursionConfig {
            mode: RecursionMode::SnarkAccumulator,
            k_in_proof: depth as u8,
            max_inner: 16,
        };
        group.bench_with_input(BenchmarkId::new("witness_depth", depth), &depth, |b, _| {
            b.iter(|| {
                let _ = build_recursion_witness(&config, &manifest)
                    .expect("witness build must succeed");
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_recursion_depth);
criterion_main!(benches);
