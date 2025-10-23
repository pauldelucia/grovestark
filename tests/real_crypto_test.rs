use grovestark::prover::GroveSTARK;
use grovestark::test_utils::create_valid_eddsa_witness_with_key;
use grovestark::types::{PublicInputs, STARKConfig};
// use grovestark::verifier::Verifier;

#[test]
fn test_real_blake3_operations() {
    // Test BLAKE3 hashing using the blake3 crate directly
    use blake3::Hasher;

    // Test vectors from BLAKE3 spec
    let input = b"hello world";
    let expected_hex = "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24";

    let mut hasher = Hasher::new();
    hasher.update(input);
    let hash = hasher.finalize();

    let result_hex = hex::encode(hash.as_bytes());
    assert_eq!(result_hex, expected_hex);

    println!("✅ BLAKE3 hashing works correctly");
}

#[test]
fn test_real_eddsa_signing() {
    use ed25519_dalek::{Signer, SigningKey, Verifier as EdVerifier};
    use rand::rngs::OsRng;

    // Generate Ed25519 keypair
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let message = b"Test message for EdDSA";

    // Sign message
    let signature = signing_key.sign(message);

    // Verify signature
    match verifying_key.verify(message, &signature) {
        Ok(()) => {
            println!("✅ EdDSA signing and verification works!");
            let sig_bytes = signature.to_bytes();
            println!("  Signature R: {:02x?}...", &sig_bytes[..8]);
            println!("  Signature s: {:02x?}...", &sig_bytes[32..40]);
        }
        Err(e) => panic!("EdDSA verification failed: {}", e),
    }
}

#[test]
fn test_real_stark_proof_generation() {
    // Use smaller parameters for testing
    let mut config = STARKConfig::default();
    config.expansion_factor = 16;
    config.num_queries = 48;
    config.folding_factor = 4;
    config.grinding_bits = 4; // Reduced from 20 for faster testing
    config.trace_length = 65536; // Required for all phases

    // Create witness with valid EdDSA signature
    let (witness, _private_key) = create_valid_eddsa_witness_with_key();

    let public = PublicInputs {
        state_root: [0x99; 32],
        contract_id: [0x88; 32],
        message_hash: [0x77; 32],
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let grove_stark = GroveSTARK::with_config(config.clone());

    println!("Generating STARK proof (this may take a moment)...");
    let proof = grove_stark.prove(witness, public.clone()).unwrap();

    // Verify proof is not placeholder
    assert!(
        proof.trace_commitment.len() >= 32,
        "Trace commitment should be substantial"
    );

    // The proof should have real FRI data
    assert!(
        proof.fri_proof.final_polynomial.len() > 100,
        "Should have real FRI proof data"
    );

    println!("✅ Real STARK proof generation works!");
    println!(
        "  Proof size: {} bytes",
        proof.fri_proof.final_polynomial.len()
    );
    println!("  PoW nonce: {}", proof.pow_nonce);

    // Test verification
    println!("Verifying STARK proof...");
    // Use GroveSTARK::verify
    let is_valid = grove_stark.verify(&proof, &public).unwrap();
    assert!(is_valid, "Proof should verify");

    println!("✅ STARK proof verification works!");
}
