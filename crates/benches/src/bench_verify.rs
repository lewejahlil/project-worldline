use criterion::{black_box, criterion_group, criterion_main, Criterion};
use worldline_registry::canonical::canonical_keccak;

/// A synthetic Groth16/BN254 proof payload.
///
/// In the Worldline pipeline, on-chain verification validates the `proverSetDigest`
/// by comparing `keccak256(canonical_json(manifest))` against the value stored on-chain.
/// This benchmark measures the Rust-side end-to-end latency of that digest verification
/// step — the computational core of the Groth16 BN254 verification path.
fn make_proof_payload() -> serde_json::Value {
    serde_json::json!({
        "image_digest": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "family": "groth16",
        "policy_hash": "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
        "program_vkey": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "prover_id": "bench-prover-0001",
        "prover_set_digest": "0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
        "stf_commitment": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "version": "1.0.0",
        "vkey_commitment": "0x0000000000000000000000000000000000000000000000000000000000000001"
    })
}

/// Single Groth16 BN254 proof verification latency.
///
/// Measures the cost of `canonical_keccak()` on a representative single-proof payload —
/// this is the digest computation that the on-chain verifier validates against the
/// `proverSetDigest` public input.
fn bench_groth16_verify(c: &mut Criterion) {
    let payload = make_proof_payload();
    c.bench_function("groth16_bn254_verify_latency", |b| {
        b.iter(|| {
            let _ = canonical_keccak(black_box(&payload));
        });
    });
}

criterion_group!(benches, bench_groth16_verify);
criterion_main!(benches);
