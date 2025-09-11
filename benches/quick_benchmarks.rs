//! Quick benchmark suite for development and CI
//!
//! This provides a fast subset of benchmarks that run in < 2 minutes
//! For comprehensive benchmarks, see comprehensive_benchmarks.rs

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use grovestark::{
    crypto::Blake3Hasher, field::FieldElement, test_utils::create_valid_eddsa_witness, GroveSTARK,
    PrivateInputs, PublicInputs, STARKConfig,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Quick proof generation benchmark with minimal config
fn bench_quick_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("quick/proof_generation");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(10);

    // Use guardrail-compliant config for quick benchmarks
    let mut config = STARKConfig::default();
    config.expansion_factor = 16;
    config.num_queries = 48;
    config.grinding_bits = 8;

    let prover = GroveSTARK::with_config(config);
    let witness = create_valid_eddsa_witness();
    let public_inputs = PublicInputs {
        state_root: [0xFF; 32],
        contract_id: [0xEE; 32],
        message_hash: [0xDD; 32],
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    group.bench_function("minimal_config", |b| {
        b.iter(|| prover.prove(black_box(witness.clone()), black_box(public_inputs.clone())))
    });

    group.finish();
}

/// Quick verification benchmark
fn bench_quick_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("quick/verification");

    // Generate a proof
    let mut config = STARKConfig::default();
    config.expansion_factor = 16;
    config.num_queries = 48;
    config.grinding_bits = 8;

    let prover = GroveSTARK::with_config(config.clone());
    let witness = create_valid_eddsa_witness();
    let public_inputs = PublicInputs {
        state_root: [0xFF; 32],
        contract_id: [0xEE; 32],
        message_hash: [0xDD; 32],
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let proof = prover
        .prove(witness, public_inputs.clone())
        .expect("Failed to generate proof");

    group.bench_function("verify", |b| {
        b.iter(|| prover.verify(black_box(&proof), black_box(&public_inputs)))
    });

    group.finish();
}

/// Core crypto operations
fn bench_quick_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("quick/crypto");

    // Field arithmetic
    let a = FieldElement::new(12345678);
    let b = FieldElement::new(87654321);

    group.bench_function("field_mul", |bench| {
        bench.iter(|| black_box(a) * black_box(b))
    });

    // BLAKE3 hashing
    let data = vec![0xAB; 256];
    group.bench_function("blake3_256", |bench| {
        bench.iter(|| Blake3Hasher::hash(black_box(&data)))
    });

    group.finish();
}

criterion_group!(
    quick_benches,
    bench_quick_proof_generation,
    bench_quick_verification,
    bench_quick_crypto,
);

criterion_main!(quick_benches);
