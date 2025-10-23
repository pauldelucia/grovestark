/// Production proof generation and verification test
use grovestark::{GroveSTARK, PublicInputs, STARKConfig};

// Shared fixture loader (copied from integration_test.rs)
fn load_pass_fixture() -> (grovestark::PrivateInputs, PublicInputs) {
    #[derive(serde::Deserialize)]
    struct Ed25519Fix {
        public_key_hex: String,
        signature_r_hex: String,
        signature_s_hex: String,
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
        let v = hex::decode(s).expect("hex32 decode");
        assert_eq!(v.len(), 32);
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }

    let fixtures: Fixtures =
        serde_json::from_str(include_str!("fixtures/PASS_AND_FAIL.json")).unwrap();

    let doc_proof = hex::decode(&fixtures.pass.document_proof_hex).expect("decode document proof");
    let key_proof = hex::decode(&fixtures.pass.key_proof_hex).expect("decode key proof");
    let sig_r = hex32(&fixtures.pass.ed25519.signature_r_hex);
    let sig_s = hex32(&fixtures.pass.ed25519.signature_s_hex);
    let pubkey = hex32(&fixtures.pass.ed25519.public_key_hex);
    let msg = hex::decode(&fixtures.pass.public_inputs.message_hex).unwrap();

    let witness = grovestark::create_witness_from_platform_proofs(
        &doc_proof,
        &key_proof,
        fixtures.pass.document_json.as_bytes().to_vec(),
        &pubkey,
        &sig_r,
        &sig_s,
        &msg,
    )
    .expect("fixture witness build");

    let public_inputs = PublicInputs {
        state_root: hex32(&fixtures.pass.public_inputs.state_root_hex),
        contract_id: hex32(&fixtures.pass.public_inputs.contract_id_hex),
        message_hash: hex32(&fixtures.pass.public_inputs.message_hex),
        timestamp: fixtures.pass.public_inputs.timestamp,
    };

    (witness, public_inputs)
}

#[test]
fn test_production_proof() {
    println!("\n🔧 Testing Production Proof Generation and Verification");
    println!("========================================================");

    // Load a valid witness with real Merkle paths and EdDSA from fixtures
    let (witness, public_inputs) = load_pass_fixture();

    // Configure for production parameters
    let mut config = STARKConfig::default();
    config.expansion_factor = 16; // Production minimum
    config.grinding_bits = 16; // Moderate PoW (production would use 20-24)
    config.num_queries = 48; // Production security minimum
    config.folding_factor = 4; // Standard

    println!("Configuration:");
    println!("  - Expansion factor: {}", config.expansion_factor);
    println!("  - Grinding bits: {}", config.grinding_bits);
    println!("  - Num queries: {}", config.num_queries);
    println!("  - Trace length: {}", config.trace_length);

    // Create prover
    let prover = GroveSTARK::with_config(config);

    // Public inputs already sourced from fixtures

    // Generate proof
    println!("\n⚙️ Generating STARK proof...");
    let start = std::time::Instant::now();

    match prover.prove(witness, public_inputs.clone()) {
        Ok(proof) => {
            let gen_time = start.elapsed();
            println!("✅ Proof generated successfully!");
            println!("   Generation time: {:.2}s", gen_time.as_secs_f32());

            // Check proof size
            let proof_bytes = bincode1::serialize(&proof).unwrap();
            println!("   Proof size: {} KB", proof_bytes.len() / 1024);

            // Verify proof
            println!("\n🔍 Verifying proof...");
            let verify_start = std::time::Instant::now();

            match prover.verify(&proof, &public_inputs) {
                Ok(true) => {
                    let verify_time = verify_start.elapsed();
                    println!("✅ Proof verified successfully!");
                    println!("   Verification time: {:.3}ms", verify_time.as_millis());

                    // Check public outputs
                    println!("\n📊 Public outputs:");
                    println!("   EdDSA verified: {}", proof.public_outputs.verified);
                    println!(
                        "   Key security level: {}",
                        proof.public_outputs.key_security_level
                    );
                    println!("   PoW nonce: {}", proof.pow_nonce);

                    assert!(
                        proof.public_outputs.verified,
                        "EdDSA verification must pass"
                    );

                    println!("\n🎉 SUCCESS: Production proof generation and verification works!");
                }
                Ok(false) => {
                    panic!("❌ Proof verification returned false");
                }
                Err(e) => {
                    panic!("❌ Proof verification failed: {}", e);
                }
            }
        }
        Err(e) => {
            panic!("❌ Proof generation failed: {}", e);
        }
    }
}
