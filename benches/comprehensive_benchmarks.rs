//! Comprehensive GroveSTARK Benchmark Suite
//!
//! This benchmark suite provides complete performance coverage for GroveSTARK,
//! organized into logical modules for production monitoring.
//!
//! ## Benchmark Categories:
//! 1. **End-to-End Performance** - Full proof generation and verification
//! 2. **Core Cryptographic Operations** - EdDSA, BLAKE3, Merkle trees
//! 3. **Component Performance** - Individual phases and operations
//! 4. **Integration Performance** - Ed25519 conversion, parsing, serialization
//! 5. **Scalability Testing** - Document sizes, batch operations, tree depths

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use grovestark::{
    compute_eddsa_hash_h, populate_witness_with_extended, GroveSTARK, MerkleNode, PrivateInputs,
    PublicInputs, STARKConfig,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// WITNESS CREATION UTILITIES
// ============================================================================

/// Create a complete, valid EdDSA witness for benchmarking
fn create_production_witness(doc_size: usize) -> PrivateInputs {
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    // Generate real Ed25519 keypair
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();

    // Create and sign a message
    let message = b"benchmark_challenge_message";
    let signature = signing_key.sign(message);
    let signature_bytes = signature.to_bytes();

    // Extract R and s from signature
    let mut signature_r = [0u8; 32];
    let mut signature_s = [0u8; 32];
    signature_r.copy_from_slice(&signature_bytes[0..32]);
    signature_s.copy_from_slice(&signature_bytes[32..64]);

    let mut witness = PrivateInputs::default();

    // Document and identity data (identity-aware)
    witness.document_cbor = vec![0x42u8; doc_size];
    witness.owner_id = [0x01u8; 32];
    witness.identity_id = witness.owner_id; // bind identity to owner
    witness.doc_root = [0x44u8; 32];
    witness.keys_root = [0x55u8; 32];

    // Merkle paths with varying structure to avoid degeneracy issues (identity-aware)
    witness.owner_id_leaf_to_doc_path = vec![
        MerkleNode {
            hash: [0x02u8; 32],
            is_left: true,
        },
        MerkleNode {
            hash: [0x03u8; 32],
            is_left: false,
        },
    ];
    witness.docroot_to_state_path = vec![MerkleNode {
        hash: [0x04u8; 32],
        is_left: true,
    }];
    witness.key_leaf_to_keysroot_path = vec![MerkleNode {
        hash: [0x05u8; 32],
        is_left: false,
    }];
    witness.identity_leaf_to_state_path = vec![MerkleNode {
        hash: [0x06u8; 32],
        is_left: true,
    }];

    // Set real EdDSA values
    witness.signature_r = signature_r;
    witness.signature_s = signature_s;
    witness.public_key_a = public_key_bytes;

    // Compute proper EdDSA hash h = SHA-512(R || A || M) mod L
    let message = b"benchmark_challenge_message";
    let signature_r = witness.signature_r;
    let public_key_a = witness.public_key_a;

    witness.hash_h = compute_eddsa_hash_h(&signature_r, &public_key_a, message);

    // Extended Edwards coordinates (properly converted)
    let _ = populate_witness_with_extended(&mut witness, &signature_r, &public_key_a, message);

    // Window decompositions (64 4-bit windows each)
    witness.s_windows = (0..64).map(|i| ((i % 16) as u8)).collect();
    witness.h_windows = (0..64).map(|i| (((i + 8) % 16) as u8)).collect();

    witness
}

/// Create witness with specific Merkle path length
fn create_witness_with_path_length(path_length: usize) -> PrivateInputs {
    let mut witness = create_production_witness(100);

    // Create path with alternating structure to avoid degeneracy
    witness.owner_id_leaf_to_doc_path = (0..path_length)
        .map(|i| MerkleNode {
            hash: [(i + 1) as u8; 32],
            is_left: i % 2 == 0,
        })
        .collect();
    witness.docroot_to_state_path = vec![MerkleNode {
        hash: [0xAA; 32],
        is_left: false,
    }];

    witness
}

/// Create variant witness for batch testing
fn create_witness_variant(variant: usize) -> PrivateInputs {
    let mut witness = create_production_witness(100);

    // Vary critical fields to ensure different proofs
    witness.owner_id[0] = variant as u8;
    witness.document_cbor[0] = (variant + 100) as u8;
    witness.signature_s[31] = (variant * 2) as u8;

    witness
}

/// Create production-ready public inputs
fn create_production_public_inputs() -> PublicInputs {
    PublicInputs {
        state_root: [0xFFu8; 32],
        contract_id: [0xEEu8; 32],
        message_hash: [0xDDu8; 32],
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    }
}

// ============================================================================
// 1. END-TO-END PERFORMANCE BENCHMARKS
// ============================================================================

/// Benchmark complete proof generation across document sizes
fn bench_end_to_end_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end/proof_generation");
    group.measurement_time(Duration::from_secs(20)); // Reduced for faster benchmarking
    group.sample_size(10); // Criterion minimum

    let config = STARKConfig::default();
    let prover = GroveSTARK::with_config(config);
    let public_inputs = create_production_public_inputs();

    // Test across realistic document sizes
    for doc_size in [64, 256, 1024, 4096, 16384].iter() {
        let witness = create_production_witness(*doc_size);

        group.bench_with_input(
            BenchmarkId::new("document_size", doc_size),
            doc_size,
            |b, _| {
                b.iter(|| {
                    prover.prove(black_box(witness.clone()), black_box(public_inputs.clone()))
                })
            },
        );
    }

    group.finish();
}

/// Benchmark proof verification performance
fn bench_end_to_end_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end/verification");
    // Reduce sample size for slow verification operations
    group.sample_size(10); // Criterion suggested reducing from 100

    let config = STARKConfig::default();
    let prover = GroveSTARK::with_config(config.clone());

    // Generate valid proof for verification
    let witness = create_production_witness(1024);
    let public_inputs = create_production_public_inputs();
    let valid_proof = prover
        .prove(witness, public_inputs.clone())
        .expect("Failed to generate proof for verification benchmark");

    // Create invalid proof for negative testing
    // Note: Simply corrupting trace_commitment causes deserialization failure (too fast)
    // Instead, corrupt the public outputs to test actual verification logic
    let mut invalid_proof = valid_proof.clone();
    invalid_proof.public_outputs.verified = false; // This will fail in verify_public_outputs()

    // Create mismatched public inputs
    let mut wrong_public_inputs = public_inputs.clone();
    wrong_public_inputs.state_root[0] = wrong_public_inputs.state_root[0].wrapping_add(1);

    group.bench_function("valid_proof_verification", |b| {
        b.iter(|| {
            let result = prover.verify(black_box(&valid_proof), black_box(&public_inputs));
            black_box(result)
        })
    });

    group.bench_function("invalid_proof_verification", |b| {
        b.iter(|| {
            let result = prover.verify(black_box(&invalid_proof), black_box(&public_inputs));
            black_box(result)
        })
    });

    group.bench_function("mismatched_inputs_verification", |b| {
        b.iter(|| {
            let result = prover.verify(black_box(&valid_proof), black_box(&wrong_public_inputs));
            black_box(result)
        })
    });

    group.finish();
}

/// Benchmark batch proof generation
fn bench_end_to_end_batch_proving(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end/batch_proving");
    group.measurement_time(Duration::from_secs(60));
    group.sample_size(10); // Criterion minimum

    let config = STARKConfig::default();
    let prover = GroveSTARK::with_config(config);
    let public_inputs = create_production_public_inputs();

    // Test batch sizes realistic for production
    for batch_size in [1, 2, 4, 8].iter() {
        let witnesses: Vec<_> = (0..*batch_size)
            .map(|i| create_witness_variant(i))
            .collect();

        group.bench_with_input(
            BenchmarkId::new("batch_size", batch_size),
            batch_size,
            |b, _| {
                b.iter(|| {
                    // Use the actual batch proving API
                    prover.prove_batch(
                        black_box(witnesses.clone()),
                        black_box(public_inputs.clone()),
                    )
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// 2. CORE CRYPTOGRAPHIC OPERATIONS
// ============================================================================

/// Benchmark EdDSA scalar multiplication operations
fn bench_crypto_eddsa_operations(c: &mut Criterion) {
    use grovestark::crypto::edwards_arithmetic::Ed25519Constants;
    use grovestark::crypto::scalar_mult_correct;

    let mut group = c.benchmark_group("crypto/eddsa");

    let constants = Ed25519Constants::new();
    let basepoint = scalar_mult_correct::convert_from_extended(&constants.base_point);

    // Benchmark core EdDSA operations
    group.bench_function("scalar_multiplication", |b| {
        let scalar = [0x42u8; 32];
        b.iter(|| {
            scalar_mult_correct::mul_point_by_scalar_le_bytes(
                black_box(&basepoint),
                black_box(&scalar),
            )
        })
    });

    group.bench_function("window_decomposition", |b| {
        let scalar = [0x42u8; 32];
        b.iter(|| scalar_mult_correct::decompose_radix16_windows_from_le_bytes(black_box(&scalar)))
    });

    group.bench_function("eddsa_verify_combine", |b| {
        let s_bytes = [0x42u8; 32];
        let h_bytes = [0x33u8; 32];
        b.iter(|| {
            scalar_mult_correct::eddsa_verify_combine(
                black_box(&s_bytes),
                black_box(&h_bytes),
                black_box(&basepoint),
                black_box(&basepoint),
                black_box(&basepoint),
            )
        })
    });

    group.finish();
}

/// Benchmark BLAKE3 hashing operations
fn bench_crypto_blake3_hashing(c: &mut Criterion) {
    use grovestark::crypto::Blake3Hasher;

    let mut group = c.benchmark_group("crypto/blake3");

    // Test across various data sizes common in GroveSTARK
    for data_size in [32, 64, 128, 256, 512, 1024, 2048, 4096].iter() {
        let data = vec![0xABu8; *data_size];

        group.bench_with_input(
            BenchmarkId::new("hash_size", data_size),
            data_size,
            |b, _| b.iter(|| Blake3Hasher::hash(black_box(&data))),
        );
    }

    group.finish();
}

/// Benchmark Merkle tree operations
fn bench_crypto_merkle_operations(c: &mut Criterion) {
    use grovestark::crypto::{Blake3Hasher, MerkleTree};

    let mut group = c.benchmark_group("crypto/merkle");

    // Test tree construction and proof generation/verification
    for tree_height in [8, 10, 12, 14, 16].iter() {
        let num_leaves = 1usize << tree_height;
        let leaves: Vec<_> = (0..num_leaves)
            .map(|i| {
                let mut data = [0u8; 32];
                data[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                Blake3Hasher::hash(&data)
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("tree_construction", tree_height),
            tree_height,
            |b, _| b.iter(|| MerkleTree::new(black_box(leaves.clone()))),
        );

        if let Ok(tree) = MerkleTree::new(leaves.clone()) {
            group.bench_with_input(
                BenchmarkId::new("proof_generation", tree_height),
                tree_height,
                |b, _| b.iter(|| tree.get_proof(black_box(num_leaves / 2))),
            );

            if let Ok(proof) = tree.get_proof(num_leaves / 2) {
                group.bench_with_input(
                    BenchmarkId::new("proof_verification", tree_height),
                    tree_height,
                    |b, _| b.iter(|| MerkleTree::verify_proof(black_box(&proof))),
                );
            }
        }
    }

    group.finish();
}

/// Benchmark field arithmetic operations
fn bench_crypto_field_arithmetic(c: &mut Criterion) {
    use grovestark::field::FieldElement;

    let mut group = c.benchmark_group("crypto/field_arithmetic");

    let a = FieldElement::new(12345678);
    let b = FieldElement::new(87654321);
    let c_elem = FieldElement::new(555666777);

    group.bench_function("addition", |bench| {
        bench.iter(|| black_box(a) + black_box(b))
    });

    group.bench_function("subtraction", |bench| {
        bench.iter(|| black_box(a) - black_box(b))
    });

    group.bench_function("multiplication", |bench| {
        bench.iter(|| black_box(a) * black_box(b))
    });

    group.bench_function("division", |bench| {
        bench.iter(|| black_box(a) / black_box(b))
    });

    group.bench_function("exponentiation", |bench| {
        bench.iter(|| black_box(a).pow(black_box(123u64)))
    });

    group.bench_function("batch_operations", |bench| {
        bench.iter(|| {
            let result = black_box(a) * black_box(b) + black_box(c_elem);
            result.pow(black_box(5u64))
        })
    });

    group.finish();
}

// ============================================================================
// 3. COMPONENT PERFORMANCE BENCHMARKS
// ============================================================================

/// Benchmark individual STARK operations  
fn bench_components_stark_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("components/stark_operations");

    let config = STARKConfig::default();
    let witness = create_production_witness(1024);
    let public_inputs = create_production_public_inputs();

    // Benchmark full STARK proof generation (the most important metric)
    group.bench_function("stark_proof_generation", |b| {
        b.iter(|| {
            grovestark::stark_winterfell::generate_proof(
                black_box(&witness),
                black_box(&public_inputs),
                black_box(&config),
            )
        })
    });

    group.finish();
}

/// Benchmark trace generation performance
fn bench_components_trace_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("components/trace_generation");

    let config = STARKConfig::default();

    // Test trace generation with different witness sizes
    for doc_size in [256, 1024, 4096].iter() {
        let witness = create_production_witness(*doc_size);
        let public_inputs = create_production_public_inputs();

        group.bench_with_input(
            BenchmarkId::new("witness_size", doc_size),
            doc_size,
            |b, _| {
                b.iter(|| {
                    // This internally generates the execution trace
                    grovestark::stark_winterfell::generate_proof(
                        black_box(&witness),
                        black_box(&public_inputs),
                        black_box(&config),
                    )
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// 4. INTEGRATION PERFORMANCE BENCHMARKS
// ============================================================================

/// Benchmark Ed25519 point conversion operations
fn bench_integration_ed25519_conversion(c: &mut Criterion) {
    use grovestark::{compressed_to_extended, populate_witness_with_extended};

    let mut group = c.benchmark_group("integration/ed25519_conversion");

    // Test with identity point for consistency
    let mut compressed_r = [0u8; 32];
    compressed_r[0] = 1;
    let mut compressed_a = [0u8; 32];
    compressed_a[0] = 1;
    let message = b"benchmark message";

    group.bench_function("point_decompression", |b| {
        b.iter(|| compressed_to_extended(black_box(&compressed_r)))
    });

    group.bench_function("witness_population", |b| {
        b.iter(|| {
            let mut witness = PrivateInputs::default();
            populate_witness_with_extended(
                black_box(&mut witness),
                black_box(&compressed_r),
                black_box(&compressed_a),
                black_box(message),
            )
        })
    });

    group.bench_function("hash_h_computation", |b| {
        b.iter(|| {
            compute_eddsa_hash_h(
                black_box(&compressed_r),
                black_box(&compressed_a),
                black_box(message),
            )
        })
    });

    group.finish();
}

/// Benchmark GroveDB proof parsing
fn bench_integration_grovedb_parsing(c: &mut Criterion) {
    use grovestark::parse_grovedb_proof;

    let mut group = c.benchmark_group("integration/grovedb_parsing");

    // Create mock GroveDB proof data
    let mock_proof = create_mock_grovedb_proof(10);

    group.bench_function("proof_parsing", |b| {
        b.iter(|| parse_grovedb_proof(black_box(&mock_proof)))
    });

    group.finish();
}

/// Create mock GroveDB proof for parsing benchmarks
fn create_mock_grovedb_proof(num_nodes: usize) -> Vec<u8> {
    let mut proof = Vec::new();

    // State root (32 bytes)
    proof.extend_from_slice(&[0xFFu8; 32]);

    // Proof length placeholder (4 bytes)
    let proof_data_start = proof.len() + 4;
    proof.extend_from_slice(&[0u8; 4]);

    // Mock Merk operations
    for i in 0..num_nodes {
        proof.push(0x01); // Push operation
        proof.extend_from_slice(&[(i as u8); 32]); // Hash
    }

    // Update proof length
    let proof_data_len = proof.len() - proof_data_start;
    let len_bytes = (proof_data_len as u32).to_le_bytes();
    proof[proof_data_start - 4..proof_data_start].copy_from_slice(&len_bytes);

    proof
}

/// Benchmark proof serialization and deserialization
fn bench_integration_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("integration/serialization");

    // Generate a proof for serialization testing
    let config = STARKConfig::default();
    let prover = GroveSTARK::with_config(config);
    let witness = create_production_witness(1024);
    let public_inputs = create_production_public_inputs();

    let proof = prover
        .prove(witness, public_inputs)
        .expect("Failed to generate proof for serialization benchmark");

    group.bench_function("proof_serialization", |b| {
        b.iter(|| bincode1::serialize(black_box(&proof)))
    });

    let serialized = bincode1::serialize(&proof).unwrap();

    group.bench_function("proof_deserialization", |b| {
        b.iter(|| bincode1::deserialize::<grovestark::STARKProof>(black_box(&serialized)))
    });

    group.finish();
}

// ============================================================================
// 5. SCALABILITY TESTING BENCHMARKS
// ============================================================================

/// Benchmark impact of different STARK config parameters on performance
fn bench_scalability_config_parameters(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalability/config_parameters");
    group.measurement_time(Duration::from_secs(20));
    group.sample_size(10); // Criterion minimum

    // Use smaller witness for config parameter testing
    let witness = create_production_witness(256);
    let public_inputs = create_production_public_inputs();

    // Allow weak params for exploratory scaling
    std::env::set_var("GS_ALLOW_WEAK_PARAMS", "1");
    // Test 1: Vary expansion factor (affects proof size and security)
    // Only test with smaller values for practical benchmarking
    println!("\nTesting expansion factor impact...");
    for expansion_factor in [2, 4].iter() {
        let mut config = STARKConfig::default();
        config.expansion_factor = *expansion_factor;
        config.grinding_bits = 10; // Reduce for faster benchmarking
        let prover = GroveSTARK::with_config(config);

        group.bench_with_input(
            BenchmarkId::new("expansion_factor", expansion_factor),
            expansion_factor,
            |b, _| {
                b.iter(|| {
                    prover.prove(black_box(witness.clone()), black_box(public_inputs.clone()))
                })
            },
        );
    }

    // Test 2: Vary number of queries (affects soundness and proof size)
    println!("\nTesting query count impact...");
    for num_queries in [10, 15].iter() {
        let mut config = STARKConfig::default();
        config.num_queries = *num_queries;
        config.grinding_bits = 10; // Reduce for faster benchmarking
        let prover = GroveSTARK::with_config(config);

        group.bench_with_input(
            BenchmarkId::new("num_queries", num_queries),
            num_queries,
            |b, _| {
                b.iter(|| {
                    prover.prove(black_box(witness.clone()), black_box(public_inputs.clone()))
                })
            },
        );
    }

    // Test 3: Vary folding factor (affects FRI rounds and proof size)
    println!("\nTesting folding factor impact...");
    for folding_factor in [2, 4].iter() {
        let mut config = STARKConfig::default();
        config.folding_factor = *folding_factor;
        config.grinding_bits = 10; // Reduce for faster benchmarking
        let prover = GroveSTARK::with_config(config);

        group.bench_with_input(
            BenchmarkId::new("folding_factor", folding_factor),
            folding_factor,
            |b, _| {
                b.iter(|| {
                    prover.prove(black_box(witness.clone()), black_box(public_inputs.clone()))
                })
            },
        );
    }

    // Test 4: Vary grinding bits (affects PoW difficulty and proving time)
    println!("\nTesting grinding bits impact...");
    for grinding_bits in [8, 12, 16].iter() {
        let mut config = STARKConfig::default();
        config.grinding_bits = *grinding_bits;
        let prover = GroveSTARK::with_config(config);

        group.bench_with_input(
            BenchmarkId::new("grinding_bits", grinding_bits),
            grinding_bits,
            |b, _| {
                b.iter(|| {
                    prover.prove(black_box(witness.clone()), black_box(public_inputs.clone()))
                })
            },
        );
    }

    group.finish();
}

/// Benchmark optimal vs suboptimal configurations
fn bench_scalability_config_profiles(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalability/config_profiles");
    group.measurement_time(Duration::from_secs(20));
    group.sample_size(10); // Criterion minimum

    // Use smaller witness for practical benchmarking
    let witness = create_production_witness(256);
    let public_inputs = create_production_public_inputs();

    // Allow weak params in this profile section too
    std::env::set_var("GS_ALLOW_WEAK_PARAMS", "1");
    // Profile 1: Fast proving (lower security)
    let mut fast_config = STARKConfig::default();
    fast_config.expansion_factor = 2;
    fast_config.num_queries = 10;
    fast_config.folding_factor = 8;
    fast_config.grinding_bits = 8;

    // Profile 2: Balanced (default)
    let balanced_config = STARKConfig::default();

    // Profile 3: High security (slower but reduced for benchmarking)
    let mut secure_config = STARKConfig::default();
    secure_config.expansion_factor = 16; // Reduced from 16
    secure_config.num_queries = 25; // Reduced from 30
    secure_config.folding_factor = 2;
    secure_config.grinding_bits = 20; // Reduced from 24

    // Profile 4: Small proof size optimized
    let mut small_proof_config = STARKConfig::default();
    small_proof_config.expansion_factor = 4;
    small_proof_config.num_queries = 15;
    small_proof_config.folding_factor = 8;
    small_proof_config.grinding_bits = 16;

    for (name, config) in [
        ("fast_proving", fast_config),
        ("balanced", balanced_config),
        ("high_security", secure_config),
        ("small_proof", small_proof_config),
    ]
    .iter()
    {
        let prover = GroveSTARK::with_config(config.clone());

        group.bench_with_input(BenchmarkId::new("profile", name), name, |b, _| {
            b.iter(|| prover.prove(black_box(witness.clone()), black_box(public_inputs.clone())))
        });
    }

    group.finish();
}

/// Benchmark scalability across Merkle tree depths
fn bench_scalability_merkle_depth(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalability/merkle_depth");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10); // Criterion minimum

    let config = STARKConfig::default();
    let prover = GroveSTARK::with_config(config);
    let public_inputs = create_production_public_inputs();

    // Test impact of Merkle path length on proving time
    for path_length in [5, 10, 15, 20, 25, 30].iter() {
        let witness = create_witness_with_path_length(*path_length);

        group.bench_with_input(
            BenchmarkId::new("path_length", path_length),
            path_length,
            |b, _| {
                b.iter(|| {
                    prover.prove(black_box(witness.clone()), black_box(public_inputs.clone()))
                })
            },
        );
    }

    group.finish();
}

/// Benchmark memory usage patterns across document sizes
fn bench_scalability_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalability/memory_usage");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10); // Criterion minimum

    let config = STARKConfig::default();
    let prover = GroveSTARK::with_config(config);
    let public_inputs = create_production_public_inputs();

    // Test memory scaling with large documents
    for doc_size in [1024, 4096, 16384, 65536, 262144].iter() {
        let witness = create_production_witness(*doc_size);

        group.bench_with_input(
            BenchmarkId::new("document_size_kb", doc_size / 1024),
            doc_size,
            |b, _| {
                b.iter(|| {
                    prover.prove(black_box(witness.clone()), black_box(public_inputs.clone()))
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// BENCHMARK GROUPS ORGANIZATION
// ============================================================================

/// Benchmark verification performance with different configs
fn bench_verification_config_impact(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end/verification_configs");
    group.sample_size(10);

    let witness = create_production_witness(256);
    let public_inputs = create_production_public_inputs();

    // Test verification time with different security parameters
    let configs = vec![
        ("minimal_security", {
            let mut cfg = STARKConfig::default();
            cfg.num_queries = 10; // Minimum
            cfg.expansion_factor = 2; // Minimum
            cfg.grinding_bits = 8; // Low PoW
            cfg
        }),
        ("balanced", {
            let mut cfg = STARKConfig::default();
            cfg.num_queries = 15;
            cfg.expansion_factor = 4;
            cfg.grinding_bits = 12;
            cfg
        }),
        ("production", STARKConfig::default()),
    ];

    for (name, config) in configs {
        // Generate proof with this config
        let prover = GroveSTARK::with_config(config.clone());
        let proof = prover
            .prove(witness.clone(), public_inputs.clone())
            .expect("Failed to generate proof");

        // Benchmark verification
        group.bench_function(name, |b| {
            b.iter(|| prover.verify(black_box(&proof), black_box(&public_inputs)))
        });
    }

    group.finish();
}

criterion_group!(
    end_to_end_benches,
    bench_end_to_end_proof_generation,
    bench_end_to_end_verification,
    bench_verification_config_impact,
    bench_end_to_end_batch_proving,
);

criterion_group!(
    crypto_benches,
    bench_crypto_eddsa_operations,
    bench_crypto_blake3_hashing,
    bench_crypto_merkle_operations,
    bench_crypto_field_arithmetic,
);

criterion_group!(
    component_benches,
    bench_components_stark_operations,
    bench_components_trace_generation,
);

criterion_group!(
    integration_benches,
    bench_integration_ed25519_conversion,
    bench_integration_grovedb_parsing,
    bench_integration_serialization,
);

criterion_group!(
    scalability_benches,
    bench_scalability_config_parameters,
    bench_scalability_config_profiles,
    bench_scalability_merkle_depth,
    bench_scalability_memory_usage,
);

// Quick benchmarks for CI/development (< 5 minutes)
criterion_group!(
    quick_benches,
    bench_crypto_field_arithmetic,
    bench_crypto_blake3_hashing,
    bench_integration_ed25519_conversion,
);

// Full benchmark suite (may take 30-60 minutes)
criterion_main!(
    end_to_end_benches,
    crypto_benches,
    component_benches,
    integration_benches,
    scalability_benches,
);

// To run quick benchmarks only:
// cargo bench --features bench -- quick_benches
//
// To run specific groups:
// cargo bench --features bench -- crypto_benches
// cargo bench --features bench -- end_to_end_benches
//
// To run a specific benchmark:
// cargo bench --features bench -- "field_arithmetic/addition"
