use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use worldline_registry::canonical::{canonical_json, canonical_keccak};

/// Build a synthetic payload array of `n` manifest-like entries.
fn make_payload(n: usize) -> serde_json::Value {
    let entries: Vec<serde_json::Value> = (0..n)
        .map(|i| {
            serde_json::json!({
                "family": if i % 2 == 0 { "groth16" } else { "sp1" },
                "image_digest": format!("0x{:064x}", i + 10_000),
                "prover_id": format!("prover-{i:04}"),
                "version": "1.0.0",
                "vkey_commitment": format!("0x{:064x}", i),
            })
        })
        .collect();
    serde_json::Value::Array(entries)
}

/// Throughput of `canonical_json()` on payloads of 1, 10, 100, 1000 entries.
///
/// Uses the `canonical.rs` module from `worldline-registry`.
fn bench_canonical_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("canonical_json_serialize");
    for n in [1usize, 10, 100, 1_000] {
        let payload = make_payload(n);
        group.bench_with_input(BenchmarkId::new("entries", n), &n, |b, _| {
            b.iter(|| {
                let _ = canonical_json(&payload);
            });
        });
    }
    group.finish();
}

/// Throughput of `canonical_keccak()` (serialise + hash) on 1, 10, 100, 1000 entries.
fn bench_canonical_keccak(c: &mut Criterion) {
    let mut group = c.benchmark_group("canonical_keccak_hash");
    for n in [1usize, 10, 100, 1_000] {
        let payload = make_payload(n);
        group.bench_with_input(BenchmarkId::new("entries", n), &n, |b, _| {
            b.iter(|| {
                let _ = canonical_keccak(&payload);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_canonical_serialization, bench_canonical_keccak);
criterion_main!(benches);
