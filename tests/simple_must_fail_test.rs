use grovestark::utils::TestUtils;
use grovestark::*;

#[test]
fn test_must_fail_simple() {
    println!("🔍 Simple must-fail test with feature enabled");

    // Create minimal valid witness
    let witness = TestUtils::create_test_witness();

    // Use strong parameters for FRI
    let config = STARKConfig {
        expansion_factor: 16,
        grinding_bits: 16,
        num_queries: 64,
        folding_factor: 4,
        ..Default::default()
    };

    let prover = GroveSTARK::with_config(config);
    let public_inputs = PublicInputs {
        state_root: [10u8; 32],
        contract_id: [11u8; 32],
        message_hash: [12u8; 32],
        timestamp: 1700000000,
    };

    // This should fail with must_fail feature
    #[cfg(feature = "must_fail_test")]
    {
        println!("⚠️  Must-fail feature is ACTIVE - proof should fail verification");
        match prover.prove(witness, public_inputs.clone()) {
            Ok(proof) => {
                println!("📝 Proof generated with must-fail constraint");
                match prover.verify(&proof, &public_inputs) {
                    Ok(true) => {
                        panic!("❌ CRITICAL: Must-fail proof verified as VALID!");
                    }
                    Ok(false) => {
                        println!("✅ GOOD: Must-fail proof was rejected");
                    }
                    Err(e) => {
                        println!("✅ GOOD: Verification failed with error: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("✅ GOOD: Proof generation failed with must-fail: {}", e);
            }
        }
    }

    #[cfg(not(feature = "must_fail_test"))]
    {
        println!("Must-fail feature not active, skipping test");
    }
}
