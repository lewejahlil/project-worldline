use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use worldline_aggregation::{AggregationStrategy, IndividualProof, ProofAggregator, ProofSystemId};
use worldline_recursion::{RecursionMode, RecursiveVerifier};

fn make_groth16_proof() -> IndividualProof {
    IndividualProof {
        prover_id: 1,
        proof_system: ProofSystemId::Groth16,
        proof_data: vec![0u8; 320],
        public_inputs: vec![[0u8; 32]],
    }
}

fn make_plonk_proof() -> IndividualProof {
    IndividualProof {
        prover_id: 2,
        proof_system: ProofSystemId::Plonk,
        proof_data: vec![0u8; 256],
        public_inputs: vec![[0u8; 32]],
    }
}

fn make_halo2_proof() -> IndividualProof {
    IndividualProof {
        prover_id: 3,
        proof_system: ProofSystemId::Halo2,
        proof_data: vec![0u8; 192],
        public_inputs: vec![[0u8; 32]],
    }
}

fn setup_aggregator_3() -> ProofAggregator {
    let mut agg = ProofAggregator::new(2, [0u8; 32]).unwrap();
    agg.add_proof(make_groth16_proof()).unwrap();
    agg.add_proof(make_plonk_proof()).unwrap();
    agg.add_proof(make_halo2_proof()).unwrap();
    agg
}

fn bench_add_single_proof(c: &mut Criterion) {
    c.bench_function("add_single_proof", |b| {
        b.iter_batched(
            || ProofAggregator::new(1, [0u8; 32]).unwrap(),
            |mut agg| {
                agg.add_proof(black_box(make_groth16_proof())).unwrap();
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_add_3_proofs(c: &mut Criterion) {
    c.bench_function("add_3_proofs", |b| {
        b.iter_batched(
            || ProofAggregator::new(2, [0u8; 32]).unwrap(),
            |mut agg| {
                agg.add_proof(make_groth16_proof()).unwrap();
                agg.add_proof(make_plonk_proof()).unwrap();
                agg.add_proof(make_halo2_proof()).unwrap();
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_aggregate_independent(c: &mut Criterion) {
    c.bench_function("aggregate_independent", |b| {
        b.iter_batched(
            setup_aggregator_3,
            |agg| {
                agg.aggregate(black_box(AggregationStrategy::Independent))
                    .unwrap();
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_aggregate_sequential(c: &mut Criterion) {
    c.bench_function("aggregate_sequential", |b| {
        b.iter_batched(
            setup_aggregator_3,
            |agg| {
                agg.aggregate(black_box(AggregationStrategy::Sequential))
                    .unwrap();
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_wrap_recursive(c: &mut Criterion) {
    let verifier = RecursiveVerifier::new(4).unwrap();
    c.bench_function("wrap_recursive", |b| {
        b.iter_batched(
            || {
                setup_aggregator_3()
                    .aggregate(AggregationStrategy::Independent)
                    .unwrap()
            },
            |aggregated| {
                verifier
                    .wrap(black_box(aggregated), RecursionMode::Single)
                    .unwrap();
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_full_pipeline(c: &mut Criterion) {
    let verifier = RecursiveVerifier::new(4).unwrap();
    c.bench_function("full_pipeline", |b| {
        b.iter(|| {
            let mut agg = ProofAggregator::new(2, [0u8; 32]).unwrap();
            agg.add_proof(make_groth16_proof()).unwrap();
            agg.add_proof(make_plonk_proof()).unwrap();
            agg.add_proof(make_halo2_proof()).unwrap();
            let aggregated = agg.aggregate(AggregationStrategy::Independent).unwrap();
            let wrapped = verifier.wrap(aggregated, RecursionMode::Single).unwrap();
            verifier
                .recurse(black_box(wrapped), RecursionMode::Incremental)
                .unwrap();
        });
    });
}

criterion_group!(
    aggregation_benches,
    bench_add_single_proof,
    bench_add_3_proofs,
    bench_aggregate_independent,
    bench_aggregate_sequential,
    bench_wrap_recursive,
    bench_full_pipeline
);
criterion_main!(aggregation_benches);
