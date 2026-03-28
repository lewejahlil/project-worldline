use criterion::{black_box, criterion_group, criterion_main, Criterion};
use prover_registry::{ProofSystemId, ProverRegistry};

fn setup_registry_3() -> ProverRegistry {
    let mut r = ProverRegistry::new();
    r.register(1, ProofSystemId::Groth16).unwrap();
    r.register(2, ProofSystemId::Plonk).unwrap();
    r.register(3, ProofSystemId::Halo2).unwrap();
    r
}

fn bench_register_prover(c: &mut Criterion) {
    c.bench_function("register_prover", |b| {
        b.iter(|| {
            let mut registry = ProverRegistry::new();
            registry.register(black_box(1), black_box(ProofSystemId::Groth16)).unwrap();
        });
    });
}

fn bench_register_3_provers(c: &mut Criterion) {
    c.bench_function("register_3_provers", |b| {
        b.iter(|| {
            let mut registry = ProverRegistry::new();
            registry.register(1, ProofSystemId::Groth16).unwrap();
            registry.register(2, ProofSystemId::Plonk).unwrap();
            registry.register(3, ProofSystemId::Halo2).unwrap();
        });
    });
}

fn bench_deregister_prover(c: &mut Criterion) {
    c.bench_function("deregister_prover", |b| {
        b.iter_batched(
            setup_registry_3,
            |mut registry| {
                registry.deregister(black_box(2)).unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_check_quorum(c: &mut Criterion) {
    let registry = setup_registry_3();
    c.bench_function("check_quorum", |b| {
        b.iter(|| {
            registry.check_quorum(black_box(2)).unwrap();
        });
    });
}

fn bench_active_provers_lookup(c: &mut Criterion) {
    let registry = setup_registry_3();
    c.bench_function("active_provers_lookup", |b| {
        b.iter(|| {
            let _ = black_box(registry.active_provers());
        });
    });
}

criterion_group!(
    registry_benches,
    bench_register_prover,
    bench_register_3_provers,
    bench_deregister_prover,
    bench_check_quorum,
    bench_active_provers_lookup
);
criterion_main!(registry_benches);
