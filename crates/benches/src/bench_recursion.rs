use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use worldline_driver::recursion::{
    generate_proofs, ProofGenerationConfig, RecursionConfig, RecursionMode, RequestedSystems,
};

/// Sweep `generate_proofs()` end-to-end latency at recursion depth 1.
///
/// Depth corresponds to `k_in_proof` — the number of inner proofs included in the
/// outer proof. Uses Halo2-only configuration since it is the only proof system
/// available without external subprocess artifacts (snarkjs).
fn bench_recursion_depth(c: &mut Criterion) {
    let mut group = c.benchmark_group("recursion_depth");
    // Only depth=1 is valid with a single Halo2 prover.
    let depth = 1usize;
    let config = ProofGenerationConfig {
        recursion: RecursionConfig {
            mode: RecursionMode::SnarkAccumulator,
            k_in_proof: depth as u8,
            max_inner: 4,
        },
        systems: RequestedSystems {
            groth16: None,
            plonk: None,
            halo2: true,
        },
        pre_state_root: [0u8; 32],
        post_state_root: [0u8; 32],
        batch_commitment: [0u8; 32],
        batch_size: 100,
        prover_ids: [101, 102, 103],
        proof_system_ids: [1, 2, 3],
        quorum_count: 1,
    };
    group.bench_with_input(BenchmarkId::new("witness_depth", depth), &depth, |b, _| {
        b.iter(|| {
            let _ = generate_proofs(&config).expect("proof generation must succeed");
        });
    });
    group.finish();
}

criterion_group!(benches, bench_recursion_depth);
criterion_main!(benches);
