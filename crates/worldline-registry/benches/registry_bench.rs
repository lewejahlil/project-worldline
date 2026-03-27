use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use tempfile::tempdir;
use worldline_compat::build_compat_snapshot;
use worldline_registry::{BackendMeta, CircuitMeta, PluginMeta, RegistrySnapshot};

/// Build a registry snapshot with `n` entries for each of circuits, plugins, and backends.
fn make_snapshot(n: usize) -> RegistrySnapshot {
    let mut snap = RegistrySnapshot::default();
    for i in 0..n {
        snap.register_backend(BackendMeta {
            id: format!("backend-{i}"),
            kind: "groth16".to_string(),
            versions: vec!["1.0.0".to_string()],
        })
        .unwrap();
        snap.register_circuit(CircuitMeta {
            id: format!("circuit-{i}"),
            version: "1.0.0".to_string(),
            public_inputs: vec!["x".to_string(), "y".to_string()],
        })
        .unwrap();
        snap.register_plugin(PluginMeta {
            id: format!("plugin-{i}"),
            version: "1.0.0".to_string(),
            backend: format!("backend-{i}"),
        })
        .unwrap();
    }
    snap
}

fn bench_load(c: &mut Criterion) {
    let mut group = c.benchmark_group("load");
    for size in [10usize, 100, 1000, 10000] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let snap = make_snapshot(size);
        worldline_registry::save(&path, &snap).unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| worldline_registry::load(&path).unwrap());
        });
    }
    group.finish();
}

fn bench_save(c: &mut Criterion) {
    let mut group = c.benchmark_group("save");
    for size in [10usize, 100, 1000, 10000] {
        let snap = make_snapshot(size);
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| worldline_registry::save(&path, &snap).unwrap());
        });
    }
    group.finish();
}

fn bench_register_circuit(c: &mut Criterion) {
    c.bench_function("register_circuit/100_existing", |b| {
        b.iter_with_setup(
            || make_snapshot(100),
            |mut snap| {
                snap.register_circuit(CircuitMeta {
                    id: "new-circuit".to_string(),
                    version: "99.0.0".to_string(),
                    public_inputs: vec![],
                })
                .unwrap();
                snap
            },
        );
    });
}

fn bench_register_plugin(c: &mut Criterion) {
    c.bench_function("register_plugin/100_existing", |b| {
        b.iter_with_setup(
            || make_snapshot(100),
            |mut snap| {
                snap.register_plugin(PluginMeta {
                    id: "new-plugin".to_string(),
                    version: "99.0.0".to_string(),
                    backend: "backend-0".to_string(),
                })
                .unwrap();
                snap
            },
        );
    });
}

fn bench_build_compat_snapshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("build_compat_snapshot");
    for size in [10usize, 100, 500] {
        let snap = make_snapshot(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| build_compat_snapshot(&snap));
        });
    }
    group.finish();
}

fn bench_serialization_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization_roundtrip");
    for size in [100usize, 1000, 10000] {
        let snap = make_snapshot(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let json = serde_json::to_string(&snap).unwrap();
                let _: worldline_registry::RegistrySnapshot = serde_json::from_str(&json).unwrap();
            });
        });
    }
    group.finish();
}

fn bench_circuit_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("circuit_lookup");
    for size in [100usize, 1000, 10000] {
        let snap = make_snapshot(size);
        // Look up the last circuit (worst case — linear scan)
        let target_id = format!("circuit-{}", size - 1);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                snap.circuits
                    .iter()
                    .find(|c| c.id == target_id)
                    .expect("circuit not found");
            });
        });
    }
    group.finish();
}

fn bench_snapshot_save_load_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot_roundtrip");
    for size in [100usize, 1000, 10000] {
        let snap = make_snapshot(size);
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                worldline_registry::save(&path, &snap).unwrap();
                worldline_registry::load(&path).unwrap()
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_load,
    bench_save,
    bench_register_circuit,
    bench_register_plugin,
    bench_build_compat_snapshot,
    bench_serialization_roundtrip,
    bench_circuit_lookup,
    bench_snapshot_save_load_roundtrip,
);
criterion_main!(benches);
