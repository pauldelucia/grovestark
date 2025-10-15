use grovestark::ed25519_helpers::create_witness_from_platform_proofs;
/// Test proof generation with real testnet data
/// This test uses actual testnet proofs and generates a full STARK proof
use grovestark::{GroveSTARK, PublicInputs, STARKConfig};

#[test]
fn test_proof_generation_with_real_testnet_data() {
    println!("\n🚀 Testing STARK Proof Generation with Real Testnet Data");
    println!("=======================================================\n");

    // Load unified PASS_AND_FAIL fixtures for real testnet-like data
    #[derive(serde::Deserialize)]
    struct Ed25519Fix {
        public_key_hex: String,
        signature_r_hex: String,
        signature_s_hex: String,
        private_key_hex: String,
    }
    #[derive(serde::Deserialize)]
    struct PubInputsFix {
        state_root_hex: String,
        contract_id_hex: String,
        message_hex: String,
        timestamp: u64,
    }
    #[derive(serde::Deserialize)]
    struct PassFix {
        document_json: String,
        document_proof_hex: String,
        key_proof_hex: String,
        public_inputs: PubInputsFix,
        ed25519: Ed25519Fix,
    }
    #[derive(serde::Deserialize)]
    struct Fixtures {
        pass: PassFix,
    }
    fn hex32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }
    let fixtures: Fixtures =
        serde_json::from_str(include_str!("fixtures/PASS_AND_FAIL.json")).unwrap();
    let document_proof =
        hex::decode(&fixtures.pass.document_proof_hex).expect("decode document proof");
    let key_proof = hex::decode(&fixtures.pass.key_proof_hex).expect("decode key proof");
    let public_key = hex32(&fixtures.pass.ed25519.public_key_hex);
    let signature_r = hex32(&fixtures.pass.ed25519.signature_r_hex);
    let signature_s = hex32(&fixtures.pass.ed25519.signature_s_hex);
    let private_key = hex32(&fixtures.pass.ed25519.private_key_hex);
    let message = hex::decode(&fixtures.pass.public_inputs.message_hex).unwrap();

    println!("Creating witness from platform proofs...");

    // Create witness using the platform proofs API
    let witness_result = create_witness_from_platform_proofs(
        &document_proof,
        &key_proof,
        fixtures.pass.document_json.as_bytes().to_vec(),
        &public_key,
        &signature_r,
        &signature_s,
        &message,
        &private_key,
    );

    let witness = match witness_result {
        Ok(w) => {
            println!("✅ Witness created successfully");
            w
        }
        Err(e) => {
            println!("❌ Failed to create witness: {:?}", e);
            panic!("Witness creation failed");
        }
    };

    // Create public inputs
    let public_inputs = PublicInputs {
        state_root: hex32(&fixtures.pass.public_inputs.state_root_hex),
        contract_id: hex32(&fixtures.pass.public_inputs.contract_id_hex),
        message_hash: hex32(&fixtures.pass.public_inputs.message_hex),
        timestamp: fixtures.pass.public_inputs.timestamp,
    };

    // Configure prover for fast testing
    std::env::set_var("GS_ALLOW_WEAK_PARAMS", "1");
    std::env::set_var("FAST_TESTS", "1");
    let mut config = STARKConfig::default();
    config.grinding_bits = 8; // low but compatible
    config.num_queries = 10; // faster for test

    println!("\nConfiguring STARK prover:");
    println!("  - Grinding bits: {}", config.grinding_bits);
    println!("  - Num queries: {}", config.num_queries);
    println!("  - Trace length: {}", config.trace_length);
    println!("  - Expansion factor: {}", config.expansion_factor);

    let prover = GroveSTARK::with_config(config);

    // Check Rayon parallelization
    println!("\nChecking parallelization:");
    println!("  - Rayon threads: {}", rayon::current_num_threads());
    println!("  - CPU count: {}", num_cpus::get());

    // Time the proof generation
    println!("\n🔨 Generating STARK proof...");
    let start = std::time::Instant::now();

    let proof = match prover.prove(witness, public_inputs.clone()) {
        Ok(p) => {
            let elapsed = start.elapsed();
            println!("✅ Proof generated in {:.2}s", elapsed.as_secs_f32());
            p
        }
        Err(e) => {
            println!("❌ Proof generation failed: {:?}", e);
            panic!("Proof generation failed");
        }
    };

    // Verify the proof
    println!("\n🔍 Verifying proof...");
    match prover.verify(&proof, &public_inputs) {
        Ok(true) => println!("✅ Proof verified successfully!"),
        Ok(false) => panic!("❌ Proof verification failed"),
        Err(e) => panic!("❌ Verification error: {:?}", e),
    }

    // Print proof statistics
    let proof_bytes = bincode1::serialize(&proof).unwrap();
    println!("\n📊 Proof Statistics:");
    println!("  - Proof size: {} bytes", proof_bytes.len());
    println!(
        "  - Security level: {}",
        proof.public_outputs.key_security_level
    );
    println!("  - PoW nonce: {}", proof.pow_nonce);

    println!("\n🎉 Test completed successfully!");
}

/// Create a mock document proof for testing
fn create_mock_document_proof(owner_id: &[u8]) -> Vec<u8> {
    let mut proof = Vec::new();

    // Mock proof structure (simplified)
    // State root (32 bytes)
    proof.extend_from_slice(&[1u8; 32]);

    // Proof data length (4 bytes)
    proof.extend_from_slice(&100u32.to_le_bytes());

    // Mock Merkle operations
    proof.push(0x01); // Push operation
    proof.extend_from_slice(owner_id); // Owner ID as leaf

    proof.push(0x10); // KVHash operation
    proof.extend_from_slice(&[2u8; 32]); // Mock key
    proof.extend_from_slice(&[3u8; 32]); // Mock value hash

    proof.push(0x02); // Parent operation
    proof.extend_from_slice(&[4u8; 32]); // Mock parent hash

    proof
}

/// Create a mock key proof for testing
fn create_mock_key_proof(identity_id: &[u8]) -> Vec<u8> {
    let mut proof = Vec::new();

    // Mock proof structure (simplified)
    // State root (32 bytes)
    proof.extend_from_slice(&[1u8; 32]);

    // Proof data length (4 bytes)
    proof.extend_from_slice(&100u32.to_le_bytes());

    // Mock Merkle operations for identity
    proof.push(0x01); // Push operation
    proof.extend_from_slice(identity_id); // Identity ID as leaf

    proof.push(0x11); // KVValueHash operation
    proof.extend_from_slice(&[5u8; 32]); // Mock key hash
    proof.extend_from_slice(&[6u8; 32]); // Mock value

    proof.push(0x03); // Child operation
    proof.extend_from_slice(&[7u8; 32]); // Mock child hash

    proof
}

#[test]
fn test_proof_generation_performance() {
    println!("\n⚡ Performance Test: STARK Proof Generation");
    println!("==========================================\n");

    // Run with different configurations to test performance
    let configs = vec![
        (4, 10, "Minimal (testing)"),
        (8, 15, "Low security"),
        (16, 20, "Medium security"),
    ];

    for (grinding_bits, num_queries, label) in configs {
        println!("Testing {} configuration:", label);
        println!("  - Grinding bits: {}", grinding_bits);
        println!("  - Num queries: {}", num_queries);

        let mut config = STARKConfig::default();
        config.grinding_bits = grinding_bits;
        config.num_queries = num_queries;

        let prover = GroveSTARK::with_config(config);

        // Create a simple witness (matching IDs)
        let witness = create_simple_witness();
        let public_inputs = PublicInputs {
            state_root: [10u8; 32],
            contract_id: [11u8; 32],
            message_hash: [12u8; 32],
            timestamp: 1700000000,
        };

        let start = std::time::Instant::now();
        match prover.prove(witness, public_inputs) {
            Ok(_) => {
                let elapsed = start.elapsed();
                println!("  ✅ Generated in {:.2}s\n", elapsed.as_secs_f32());
            }
            Err(e) => {
                println!("  ❌ Failed: {:?}\n", e);
            }
        }
    }
}

fn create_simple_witness() -> grovestark::PrivateInputs {
    use grovestark::{MerkleNode, PrivateInputs};

    let matching_id = [42u8; 32];

    PrivateInputs {
        // Document side
        doc_root: [7u8; 32],
        owner_id: matching_id.clone(),
        owner_id_leaf_to_doc_path: vec![MerkleNode {
            hash: [2u8; 32],
            is_left: true,
        }],
        docroot_to_state_path: vec![MerkleNode {
            hash: [3u8; 32],
            is_left: false,
        }],

        // Identity side - MUST match owner_id
        identity_id: matching_id.clone(),
        keys_root: [4u8; 32],
        identity_leaf_to_state_path: vec![MerkleNode {
            hash: [5u8; 32],
            is_left: true,
        }],

        // EdDSA fields
        key_usage_tag: *b"sig:ed25519:v1\0\0",
        pubkey_a_compressed: [
            0xbf, 0xe8, 0xd2, 0xb0, 0x16, 0xbf, 0x3f, 0x02, 0xb2, 0x51, 0x33, 0xe8, 0x5d, 0xe5,
            0xef, 0xf0, 0xb7, 0xe2, 0xfb, 0x00, 0x27, 0x76, 0xba, 0x46, 0x5a, 0xd8, 0xf9, 0x2a,
            0xce, 0x35, 0x33, 0xae,
        ],
        key_leaf_to_keysroot_path: vec![MerkleNode {
            hash: [6u8; 32],
            is_left: false,
        }],

        signature_r: [1u8; 32],
        signature_s: [2u8; 32],

        // Document CBOR - ensure non-empty
        document_cbor: vec![1, 2, 3, 4, 5],
        private_key: [3u8; 32],
        public_key_a: [4u8; 32],
        hash_h: [5u8; 32],

        ..Default::default()
    }
}
