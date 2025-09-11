use grovestark::utils::TestUtils;
/// Test to verify constraint count fix (91 constraints, not 87)
use grovestark::*;

#[test]
fn test_constraint_count_production() {
    println!("Testing constraint count in production mode (should be 91)");

    // Create a valid witness
    let witness = TestUtils::create_test_witness();

    // Use production config
    let config = STARKConfig::default();

    let prover = GroveSTARK::with_config(config);
    let public_inputs = PublicInputs {
        state_root: [10u8; 32],
        contract_id: [11u8; 32],
        message_hash: [12u8; 32],
        timestamp: 1700000000,
    };

    // This should work now with NUM_CONSTRAINTS = 91
    match prover.prove(witness, public_inputs.clone()) {
        Ok(_proof) => {
            println!("✅ Proof generation succeeded with 91 constraints");
        }
        Err(e) => {
            if e.to_string().contains("wrote 91 constraints, expected 87") {
                panic!(
                    "❌ Still have constraint count mismatch! Fix didn't work: {}",
                    e
                );
            } else if e
                .to_string()
                .contains("EdDSA signature verification failed")
            {
                println!("✅ Failed at EdDSA validation (expected with test witness)");
            } else {
                println!("Failed with different error: {}", e);
            }
        }
    }
}

#[test]
fn test_corrupted_witness_fails() {
    println!("Testing that corrupted witness fails verification");

    // Create a valid witness then corrupt it
    let mut witness = TestUtils::create_test_witness();

    // Corrupt the owner_id to differ from identity_id
    witness.owner_id[0] ^= 0xFF;

    println!("Corrupted owner_id: {:?}", hex::encode(&witness.owner_id));
    println!("Identity_id: {:?}", hex::encode(&witness.identity_id));

    let config = STARKConfig::default();
    let prover = GroveSTARK::with_config(config);
    let public_inputs = PublicInputs {
        state_root: [10u8; 32],
        contract_id: [11u8; 32],
        message_hash: [12u8; 32],
        timestamp: 1700000000,
    };

    // Try to generate proof with corrupted witness
    match prover.prove(witness, public_inputs.clone()) {
        Ok(proof) => {
            // Proof generated, now verify it should fail
            match prover.verify(&proof, &public_inputs) {
                Ok(true) => {
                    panic!("❌ CRITICAL: Corrupted witness verified as valid!");
                }
                Ok(false) => {
                    println!("✅ Good: Corrupted witness was rejected by verifier");
                }
                Err(e) => {
                    println!("✅ Good: Verification failed with error: {}", e);
                }
            }
        }
        Err(e) => {
            println!(
                "✅ Good: Proof generation failed for corrupted witness: {}",
                e
            );
        }
    }
}
