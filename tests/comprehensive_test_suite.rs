//! Comprehensive test suite for production readiness
//!
//! This test suite validates all components of the GroveSTARK system
//! ensuring 100% production readiness with no placeholders.

use grovestark::crypto::ed25519::decompress::augment_witness_with_extended;
use grovestark::crypto::{Blake3Hasher, HybridVerifier, PrivacyLevel};
use grovestark::error_handling::{
    CircuitBreaker, CircuitBreakerConfig, RetryConfig, RetryExecutor,
};
use grovestark::phases::eddsa::witness_augmentation::augment_eddsa_witness;
use grovestark::{GroveSTARK, MerkleNode, PrivateInputs, PublicInputs, STARKConfig, STARKProof};
use std::time::{Duration, Instant};

/// Test configuration for all tests
/// Uses reduced security parameters for faster testing
fn test_config() -> STARKConfig {
    // Allow weaker parameters for test speed
    std::env::set_var("GS_ALLOW_WEAK_PARAMS", "1");
    std::env::set_var("FAST_TESTS", "1");
    STARKConfig {
        field_bits: 64,
        expansion_factor: 8,
        num_queries: 10, // Minimum for tests (production: 30)
        folding_factor: 4,
        grinding_bits: 8,          // Much faster for testing (production: 24)
        trace_length: 65536, // Required for all phases (BLAKE3: 3584, Merkle: 16384, EdDSA: 32768)
        num_trace_columns: 104, // Must match production setting
        max_remainder_degree: 255, // Must be one less than power of two
        security_level: 128,
    }
}

/// Generate valid test witness
fn generate_test_witness() -> (PrivateInputs, PublicInputs) {
    // Use valid EdDSA test data that verifies correctly (freshly generated)
    let signature_r = [
        0x18, 0xac, 0x08, 0x19, 0x28, 0xc3, 0x9a, 0xee, 0x8f, 0xa5, 0x29, 0x91, 0x6c, 0x07, 0x71,
        0x9f, 0xaa, 0x53, 0x4b, 0xdd, 0x32, 0x90, 0x38, 0xac, 0x6b, 0x4c, 0x59, 0xe6, 0x92, 0xc5,
        0x92, 0xed,
    ];

    let signature_s = [
        0xde, 0x69, 0x45, 0xb4, 0x55, 0xb7, 0x4c, 0xa9, 0x9a, 0x25, 0xd2, 0xf6, 0x63, 0x50, 0x0f,
        0xfd, 0xa4, 0x9c, 0xe0, 0x11, 0x65, 0x07, 0x49, 0xb8, 0xed, 0xcd, 0x29, 0x72, 0x94, 0x46,
        0x3b, 0x0e,
    ];

    let public_key_a = [
        0xbf, 0xe8, 0xd2, 0xb0, 0x16, 0xbf, 0x3f, 0x02, 0xb2, 0x51, 0x33, 0xe8, 0x5d, 0xe5, 0xef,
        0xf0, 0xb7, 0xe2, 0xfb, 0x00, 0x27, 0x76, 0xba, 0x46, 0x5a, 0xd8, 0xf9, 0x2a, 0xce, 0x35,
        0x33, 0xae,
    ];

    // Hash h = SHA-512(R || A || M) mod L (properly reduced)
    let hash_h = [
        0xef, 0x15, 0xc6, 0xba, 0x64, 0x5a, 0x12, 0x23, 0xdf, 0x69, 0x9b, 0xc7, 0x99, 0x39, 0xc5,
        0x8b, 0xd3, 0x67, 0x5c, 0x78, 0xa7, 0x1d, 0x2f, 0x2c, 0x7c, 0xc8, 0xcc, 0x40, 0x71, 0x13,
        0xcd, 0x0e,
    ];

    let private_key = [
        0xdd, 0xbd, 0xd9, 0xbc, 0x9e, 0x20, 0x44, 0x9e, 0x5f, 0x4c, 0x7b, 0x5d, 0x07, 0x05, 0x95,
        0x13, 0xd7, 0xdf, 0x77, 0xb1, 0x9b, 0xf4, 0xca, 0xc2, 0x2b, 0x06, 0x0b, 0xc2, 0xa2, 0x74,
        0x96, 0xcd,
    ];

    let message_hash = [0xBB; 32];

    let mut witness = PrivateInputs {
        document_cbor: b"test_document_data_12345".to_vec(),
        owner_id: *b"test_owner_id_67890_dash_platfor", // Exactly 32 bytes
        // Identity-aware fields
        doc_root: [0x44; 32],
        keys_root: [0x55; 32],
        owner_id_leaf_to_doc_path: vec![
            MerkleNode {
                hash: [0x11; 32],
                is_left: true,
            },
            MerkleNode {
                hash: [0x22; 32],
                is_left: false,
            },
            MerkleNode {
                hash: [0x33; 32],
                is_left: true,
            },
        ],
        docroot_to_state_path: vec![MerkleNode {
            hash: [0x66; 32],
            is_left: true,
        }],
        key_leaf_to_keysroot_path: vec![
            MerkleNode {
                hash: [0x44; 32],
                is_left: false,
            },
            MerkleNode {
                hash: [0x55; 32],
                is_left: true,
            },
        ],
        identity_leaf_to_state_path: vec![MerkleNode {
            hash: [0x77; 32],
            is_left: false,
        }],
        identity_id: *b"test_owner_id_67890_dash_platfor", // Must match owner_id
        private_key,
        signature_r,
        signature_s,
        public_key_a,
        pubkey_a_compressed: public_key_a,
        key_usage_tag: *b"sig:ed25519:v1\0\0",
        hash_h,
        ..Default::default()
    };

    // Augment with decompressed extended coordinates
    let _ = augment_witness_with_extended(
        &signature_r,
        &public_key_a,
        &mut witness.r_extended_x,
        &mut witness.r_extended_y,
        &mut witness.r_extended_z,
        &mut witness.r_extended_t,
        &mut witness.a_extended_x,
        &mut witness.a_extended_y,
        &mut witness.a_extended_z,
        &mut witness.a_extended_t,
    );

    let public = PublicInputs {
        state_root: [0x99; 32],
        contract_id: [0xAA; 32],
        message_hash,
        timestamp: 1700000000, // More recent timestamp
    };

    // Augment with scalar decomposition and other fields
    let augmented_witness =
        augment_eddsa_witness(&witness, &public).expect("Failed to augment EdDSA witness");

    (augmented_witness, public)
}

#[test]
fn test_end_to_end_proof_generation_and_verification() {
    let config = test_config();
    let stark = GroveSTARK::with_config(config.clone());
    let (witness, public) = generate_test_witness();

    // Generate proof
    let proof = stark.prove(witness, public.clone()).unwrap();

    // Verify proof
    let result = stark.verify(&proof, &public).unwrap();

    assert!(result, "Proof verification should succeed");
}

#[test]
fn test_proof_serialization_and_deserialization() {
    let config = test_config();
    let stark = GroveSTARK::with_config(config);
    let (witness, public) = generate_test_witness();

    // Generate proof
    let proof = stark.prove(witness, public).unwrap();

    // Serialize
    let serialized = bincode1::serialize(&proof).unwrap();
    assert!(
        !serialized.is_empty(),
        "Serialized proof should not be empty"
    );

    // Deserialize
    let deserialized: STARKProof = bincode1::deserialize(&serialized).unwrap();

    // Check fields match
    assert_eq!(proof.trace_commitment, deserialized.trace_commitment);
    assert_eq!(proof.pow_nonce, deserialized.pow_nonce);
}

#[test]
fn test_invalid_proof_rejection() {
    let config = test_config();
    let stark = GroveSTARK::with_config(config.clone());
    let (witness, public) = generate_test_witness();

    // Generate valid proof
    let mut proof = stark.prove(witness, public.clone()).unwrap();

    // Tamper with proof
    proof.pow_nonce = proof.pow_nonce.wrapping_add(1);

    // Verification should fail
    let verifier = GroveSTARK::with_config(config);
    let result = verifier.verify(&proof, &public);

    // Should either fail or return false
    match result {
        Ok(false) => {} // Expected
        Err(_) => {}    // Also acceptable
        Ok(true) => panic!("Tampered proof should not verify"),
    }
}

#[test]
fn test_merkle_proof_verification() {
    use grovestark::crypto::merkle::MerkleTree;

    let leaves = vec![[0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32]];

    let tree = MerkleTree::new(leaves.clone()).unwrap();
    let root = tree.root();

    // Get proof for leaf at index 2
    let proof = tree.get_proof(2).unwrap();

    // Verify proof
    assert_eq!(proof.leaf, leaves[2]);
    assert_eq!(proof.root, root);
    assert!(MerkleTree::verify_proof(&proof));
}

#[test]
fn test_blake3_hashing() {
    let data = b"test data for blake3 hashing";
    let hash = Blake3Hasher::hash(data);

    // Hash should be deterministic
    let hash2 = Blake3Hasher::hash(data);
    assert_eq!(hash, hash2, "Hash should be deterministic");

    // Different data should produce different hash
    let hash3 = Blake3Hasher::hash(b"different data");
    assert_ne!(hash, hash3, "Different data should produce different hash");
}

#[test]
fn test_hybrid_verification_with_privacy_levels() {
    let (witness, public) = generate_test_witness();

    // Test Standard privacy level
    let proof_standard =
        HybridVerifier::prove_ownership(&witness, &public, PrivacyLevel::Standard).unwrap();

    assert_eq!(proof_standard.privacy_level, PrivacyLevel::Standard);
    assert!(proof_standard.signature_component.ring_signature.is_none());

    // Test Minimal privacy level
    let proof_minimal =
        HybridVerifier::prove_ownership(&witness, &public, PrivacyLevel::Minimal).unwrap();

    assert_eq!(proof_minimal.privacy_level, PrivacyLevel::Minimal);
}

#[test]
fn test_grovedb_proof_parsing() {
    // Use real fixture and production parser to assert deterministic parsing
    let proof_path =
        "tests/fixtures/document_proof_B5XLy3cUDayaqZmcGaWb98PEAUguGHiHSU5DxiKrHBj3.bin";
    let proof_data = std::fs::read(proof_path).expect("Failed to read document proof fixture");
    let nodes = grovestark::parse_grovedb_proof(&proof_data).expect("Proof parse failed");
    assert!(!nodes.is_empty());
}

#[test]
fn test_error_handling_with_retry() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = counter.clone();

    let config = RetryConfig {
        max_attempts: 3,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_secs(1),
        backoff_multiplier: 2.0,
        jitter_factor: 0.0,
    };

    let executor = RetryExecutor::new(config);

    let result = executor.execute(move || {
        let count = counter_clone.fetch_add(1, Ordering::SeqCst);
        if count < 2 {
            Err(grovestark::error::Error::NetworkError(
                "Simulated failure".into(),
            ))
        } else {
            Ok(42)
        }
    });

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);
    assert_eq!(counter.load(Ordering::SeqCst), 3);
}

#[test]
fn test_circuit_breaker() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        reset_timeout: Duration::from_millis(50),
        success_threshold: 1,
    };

    let breaker = CircuitBreaker::new(config);

    // Cause failures to open circuit
    let _ = breaker.call(|| Err::<(), _>(grovestark::error::Error::NetworkError("Error".into())));
    let _ = breaker.call(|| Err::<(), _>(grovestark::error::Error::NetworkError("Error".into())));

    // Circuit should be open
    let result = breaker.call(|| Ok(42));
    assert!(result.is_err());

    // Wait for reset
    std::thread::sleep(Duration::from_millis(100));

    // Should work now
    let result = breaker.call(|| Ok(42));
    assert!(result.is_ok());
}

#[test]
fn test_constant_time_operations() {
    use grovestark::crypto::constant_time::{ct_compare, ConstantTimeField};
    use grovestark::field::FieldElement;

    // Test constant-time comparison
    let a = [0x42u8; 32];
    let b = [0x42u8; 32];
    let c = [0x43u8; 32];

    assert!(ct_compare(&a, &b));
    assert!(!ct_compare(&a, &c));

    // Test constant-time field operations
    let f1 = FieldElement::new(100);
    let f2 = FieldElement::new(200);

    let sum = ConstantTimeField::add(f1, f2);
    assert_eq!(sum, FieldElement::new(300));

    let selected = ConstantTimeField::select(true, f1, f2);
    assert_eq!(selected, f1);
}

#[test]
fn test_ring_signature_generation_and_verification() {
    use ed25519_dalek::SigningKey;
    use grovestark::crypto::ring_signature::RingSigner;
    use rand::rngs::OsRng;

    // Create ring members
    let mut ring = Vec::new();
    let mut private_keys = Vec::new();

    let mut rng = OsRng;
    for _ in 0..3 {
        let key = SigningKey::generate(&mut rng);
        ring.push(key.verifying_key());
        private_keys.push(key);
    }

    // Sign with member 1
    let message = b"test message for ring signature";
    let signature = RingSigner::sign(ring.clone(), 1, &private_keys[1], message).unwrap();

    // Verify
    assert!(RingSigner::verify(&signature, message).unwrap());

    // Wrong message should fail
    assert!(!RingSigner::verify(&signature, b"wrong message").unwrap());
}

#[test]
fn test_fri_protocol() {
    use grovestark::field::FieldElement;
    use grovestark::prover::fri::{FRIConfig, FRIProver, FRIVerifier};

    let config = FRIConfig {
        expansion_factor: 8,
        num_queries: 10,
        folding_factor: 2,
        max_remainder_degree: 64,
    };

    let domain_size = 256;
    let prover = FRIProver::new(config.clone(), domain_size);
    let verifier = FRIVerifier::new(config, domain_size);

    // Create test polynomial
    let polynomial: Vec<FieldElement> = (0..128).map(|i| FieldElement::new(i as u64)).collect();

    // Generate commitment
    let commitment = prover.prove(&polynomial).unwrap();

    // Generate queries
    let seed = [0x42u8; 32];
    let queries = prover.generate_queries(&commitment, &seed).unwrap();

    // Verify
    assert!(verifier.verify(&commitment, &queries).unwrap());
}

#[test]
fn test_batch_proving() {
    let config = test_config();
    let stark = GroveSTARK::with_config(config);

    // Generate multiple witnesses
    let mut witnesses = Vec::new();
    for i in 0..3 {
        let mut witness = generate_test_witness().0;
        witness.document_cbor.push(i as u8);
        witnesses.push(witness);
    }

    let public = generate_test_witness().1;

    // Batch prove
    let batch_proof = stark.prove_batch(witnesses, public).unwrap();

    assert!(!batch_proof.individual_proofs.is_empty());
    assert_eq!(batch_proof.individual_proofs.len(), 3);
}

#[test]
fn test_performance_benchmark() {
    let config = test_config();
    let stark = GroveSTARK::with_config(config.clone());
    let (witness, public) = generate_test_witness();

    // Benchmark proof generation
    let start = Instant::now();
    let proof = stark.prove(witness, public.clone()).unwrap();
    let proving_time = start.elapsed();

    println!("Proof generation time: {:?}", proving_time);
    let perf_limit = std::env::var("GS_PERF_LIMIT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(600);
    assert!(
        proving_time < Duration::from_secs(perf_limit),
        "Proof generation should be reasonably fast (under {} seconds)",
        perf_limit
    );

    // Benchmark verification
    let verifier = GroveSTARK::with_config(config);
    let start = Instant::now();
    let result = verifier.verify(&proof, &public).unwrap();
    let verification_time = start.elapsed();

    println!("Verification time: {:?}", verification_time);
    assert!(result);
    let verify_limit = std::env::var("GS_VERIFY_LIMIT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(15);
    assert!(
        verification_time < Duration::from_secs(verify_limit),
        "Verification should be reasonably fast (under {} seconds)",
        verify_limit
    );
}

#[test]
fn test_memory_safety() {
    use grovestark::crypto::constant_time::SecureMemory;

    // Test secure memory zeroing
    let mut sensitive_data = vec![0x42u8; 32];
    SecureMemory::zeroize(&mut sensitive_data);
    assert_eq!(sensitive_data, vec![0u8; 32]);

    // Test secure comparison
    let a = [0x11u8; 32];
    let b = [0x11u8; 32];
    assert!(SecureMemory::compare(&a, &b));
}

/// Integration test that simulates a complete workflow
#[test]
fn test_complete_workflow_integration() {
    // 1. Initialize system
    let config = test_config();
    let stark = GroveSTARK::with_config(config.clone());

    // 2. Create witness using test data
    let (witness, public) = generate_test_witness();

    // 3. Generate proof
    let proof = stark.prove(witness, public.clone()).unwrap();

    // 4. Serialize for transmission
    let serialized = bincode1::serialize(&proof).unwrap();
    assert!(serialized.len() > 100, "Proof should have substantial size");

    // 5. Deserialize on verifier side
    let received_proof: STARKProof = bincode1::deserialize(&serialized).unwrap();

    // 6. Verify proof
    let verifier = GroveSTARK::with_config(config);
    let valid = verifier.verify(&received_proof, &public).unwrap();

    assert!(valid, "Complete workflow should succeed");
}
