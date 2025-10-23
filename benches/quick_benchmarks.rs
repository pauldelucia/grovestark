//! Quick benchmark suite for development and CI
//!
//! This provides a fast subset of benchmarks that run in < 2 minutes

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use grovestark::{
    create_witness_from_platform_proofs, crypto::Blake3Hasher, field::FieldElement, GroveSTARK,
    PrivateInputs, PublicInputs, STARKConfig,
};
use serde::Deserialize;
use std::time::Duration;

fn load_fixture_witness() -> (PrivateInputs, PublicInputs) {
    #[derive(Deserialize)]
    struct Ed25519Fix {
        public_key_hex: String,
        signature_r_hex: String,
        signature_s_hex: String,
    }

    #[derive(Deserialize)]
    struct PubInputsFix {
        state_root_hex: String,
        contract_id_hex: String,
        message_hex: String,
        timestamp: u64,
    }

    #[derive(Deserialize)]
    struct PassFix {
        document_json: String,
        document_proof_hex: String,
        key_proof_hex: String,
        public_inputs: PubInputsFix,
        ed25519: Ed25519Fix,
    }

    #[derive(Deserialize)]
    struct Fixtures {
        pass: PassFix,
    }

    fn hex32(s: &str) -> [u8; 32] {
        let bytes = hex::decode(s).expect("Invalid hex");
        assert_eq!(bytes.len(), 32, "expected 32-byte hex");
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    let fixtures: Fixtures =
        serde_json::from_str(include_str!("../tests/fixtures/PASS_AND_FAIL.json")).unwrap();

    let doc_proof = hex::decode(&fixtures.pass.document_proof_hex).unwrap();
    let key_proof = hex::decode(&fixtures.pass.key_proof_hex).unwrap();
    let signature_r = hex32(&fixtures.pass.ed25519.signature_r_hex);
    let signature_s = hex32(&fixtures.pass.ed25519.signature_s_hex);
    let public_key = hex32(&fixtures.pass.ed25519.public_key_hex);
    let message = hex::decode(&fixtures.pass.public_inputs.message_hex).unwrap();

    let witness = create_witness_from_platform_proofs(
        &doc_proof,
        &key_proof,
        fixtures.pass.document_json.as_bytes().to_vec(),
        &public_key,
        &signature_r,
        &signature_s,
        &message,
    )
    .expect("fixture witness");

    let public_inputs = PublicInputs {
        state_root: hex32(&fixtures.pass.public_inputs.state_root_hex),
        contract_id: hex32(&fixtures.pass.public_inputs.contract_id_hex),
        message_hash: hex32(&fixtures.pass.public_inputs.message_hex),
        timestamp: fixtures.pass.public_inputs.timestamp,
    };

    (witness, public_inputs)
}

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
    let (witness, public_inputs) = load_fixture_witness();

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
    let (witness, public_inputs) = load_fixture_witness();

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
