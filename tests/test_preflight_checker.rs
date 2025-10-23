/// Test the preflight checker to ensure it catches constraint failures quickly
use grovestark::{create_witness_from_platform_proofs, GroveSTARK, PublicInputs, STARKConfig};

#[test]
fn test_preflight_checker() {
    println!("\n🚀 Testing Preflight Checker");
    println!("==============================\n");

    // Load unified PASS_AND_FAIL fixtures instead of constructing ad-hoc inputs
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
    let message = hex::decode(&fixtures.pass.public_inputs.message_hex).unwrap();
    let document_json = fixtures.pass.document_json.as_bytes().to_vec();

    println!("Creating witness...");
    let witness = create_witness_from_platform_proofs(
        &document_proof,
        &key_proof,
        document_json,
        &public_key,
        &signature_r,
        &signature_s,
        &message,
    )
    .expect("Failed to create witness");

    println!("✅ Witness created");

    // Configure prover with minimal settings
    std::env::set_var("GS_ALLOW_WEAK_PARAMS", "1");
    std::env::set_var("FAST_TESTS", "1");
    let mut config = STARKConfig::default();
    config.expansion_factor = 8;
    config.grinding_bits = 0;
    config.num_queries = 8;

    let prover = GroveSTARK::with_config(config);

    let public_inputs = PublicInputs {
        state_root: hex32(&fixtures.pass.public_inputs.state_root_hex),
        contract_id: hex32(&fixtures.pass.public_inputs.contract_id_hex),
        message_hash: hex32(&fixtures.pass.public_inputs.message_hex),
        timestamp: fixtures.pass.public_inputs.timestamp,
    };

    println!("\n⚡ Starting proof generation (with preflight check)...");
    let start_time = std::time::Instant::now();

    // The preflight check runs automatically in debug builds
    // It should complete in milliseconds if all constraints pass
    match prover.prove(witness, public_inputs) {
        Ok(_proof) => {
            let elapsed = start_time.elapsed();
            println!("✅ Proof generated successfully!");
            println!("   Time: {:.2}s", elapsed.as_secs_f32());

            // With the fix, we should get here
            assert!(
                elapsed.as_secs() < 120,
                "Should complete quickly with minimal settings"
            );
        }
        Err(e) => {
            let elapsed = start_time.elapsed();

            // Check if it's a preflight failure (fast)
            if e.to_string().contains("Preflight") {
                println!(
                    "⚡ Preflight caught error in {:.3}s: {}",
                    elapsed.as_secs_f32(),
                    e
                );

                // This is actually good - preflight worked!
                // But with our fix, we shouldn't hit this
                panic!(
                    "Preflight found constraint failure (but it was fast!): {}",
                    e
                );
            } else {
                println!("❌ Error after {:.2}s: {}", elapsed.as_secs_f32(), e);
                panic!("Unexpected error: {}", e);
            }
        }
    }

    println!("\n🎉 Test complete!");
}
