use criterion::{criterion_group, criterion_main, Criterion};
use worldline_recursion::prover_traits::StfInputs;
use worldline_recursion::{Halo2Prover, InnerProver};

use halo2curves::bn256::Fr;
use halo2curves::group::ff::PrimeField;

fn test_inputs() -> StfInputs {
    StfInputs {
        pre_state_root: Fr::from(1234567890u64).to_repr(),
        post_state_root: Fr::from(9876543210u64).to_repr(),
        batch_commitment: Fr::from(5555555555u64).to_repr(),
        batch_size: 100,
        prover_ids: [101, 102, 103],
        proof_system_ids: [1, 2, 3],
        quorum_count: 3,
    }
}

/// Benchmark Halo2 inner prover: key generation + proof generation.
///
/// Halo2 is the only prover that runs natively without external binaries.
/// Groth16 and Plonk benchmarks require snarkjs and compiled circuit artifacts.
fn bench_halo2_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("inner_provers");

    // Halo2 setup is expensive (keygen); do it once outside the benchmark loop.
    let prover = Halo2Prover::new().expect("Halo2Prover setup");
    let inputs = test_inputs();

    group.bench_function("halo2_prove", |b| {
        b.iter(|| {
            let _output = prover.prove(&inputs).expect("Halo2 prove");
        });
    });

    group.finish();
}

/// Benchmark Halo2 prover setup (keygen).
fn bench_halo2_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("inner_provers");
    group.sample_size(10); // Keygen is slow; fewer samples.

    group.bench_function("halo2_setup", |b| {
        b.iter(|| {
            let _prover = Halo2Prover::new().expect("Halo2Prover setup");
        });
    });

    group.finish();
}

/// Benchmark the full pipeline with a single Halo2 prover.
fn bench_pipeline_single_halo2(c: &mut Criterion) {
    use worldline_recursion::MultiProverPipeline;

    let mut group = c.benchmark_group("pipeline");

    let inputs = test_inputs();

    group.bench_function("single_halo2", |b| {
        b.iter_batched(
            || {
                let mut pipeline = MultiProverPipeline::new(1, 4).unwrap();
                pipeline.add_prover(Box::new(Halo2Prover::new().unwrap()));
                pipeline
            },
            |pipeline| {
                let _output = pipeline.execute(&inputs).expect("pipeline execute");
            },
            criterion::BatchSize::PerIteration,
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_halo2_prove,
    bench_halo2_setup,
    bench_pipeline_single_halo2
);
criterion_main!(benches);
