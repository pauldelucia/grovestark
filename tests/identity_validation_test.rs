use grovestark::utils::TestUtils;
/// Test to verify that identity validation is working correctly
/// This test ensures that a proof with mismatched owner/identity FAILS verification
use grovestark::*;

#[test]
fn test_mismatched_identity_must_fail() {
    println!("Testing that mismatched owner/identity fails verification");

    // Start with a valid witness from TestUtils
    let mut witness = TestUtils::create_test_witness();

    // Now corrupt it by changing the identity_id to not match owner_id
    // This simulates an attacker trying to prove ownership with wrong identity
    witness.owner_id = [1u8; 32]; // Document owned by identity "1111..."
    witness.identity_id = [2u8; 32]; // Key belongs to identity "2222..."

    println!("Owner ID: {}", hex::encode(&witness.owner_id));
    println!("Identity ID: {}", hex::encode(&witness.identity_id));
    println!("IDs are different - proof should fail!");

    // Use production config
    let config = STARKConfig::default();
    let prover = GroveSTARK::with_config(config);

    let public_inputs = PublicInputs {
        state_root: [10u8; 32],
        contract_id: [11u8; 32],
        message_hash: [12u8; 32],
        timestamp: 1700000000,
    };

    // Try to generate proof with mismatched IDs
    match prover.prove(witness, public_inputs.clone()) {
        Ok(proof) => {
            println!("⚠️ Proof generated with mismatched IDs, now verifying...");

            // This MUST fail verification
            match prover.verify(&proof, &public_inputs) {
                Ok(true) => {
                    panic!("❌ CRITICAL SECURITY VULNERABILITY: Mismatched owner/identity passed verification!");
                }
                Ok(false) => {
                    println!("✅ Good: Verification correctly rejected mismatched IDs");
                }
                Err(e) => {
                    println!("✅ Good: Verification failed with error: {}", e);
                }
            }
        }
        Err(e) => {
            // Check what kind of error we got
            let err_str = e.to_string();
            if err_str.contains("DIFF") || err_str.contains("identity") || err_str.contains("owner")
            {
                println!("✅ Good: Proof generation failed due to ID mismatch: {}", e);
            } else {
                println!("Proof generation failed with different error: {}", e);
            }
        }
    }
}

#[test]
fn test_identity_extraction_offset_issue() {
    println!("Testing potential identity extraction offset issue");

    // This test demonstrates the risk of using hardcoded offsets
    // The identity_id extraction uses offset 740, which could be manipulated

    // The real issue is that we can't directly test the extraction function
    // as it's private, but we can demonstrate the risk through the
    // validation bypass test below

    println!("⚠️ Identity extraction uses hardcoded offset 740");
    println!("This could be exploited if proof structure changes or is manipulated");
}

#[test]
fn test_validation_bypass_vulnerability() {
    use grovestark::ed25519_helpers::create_witness_from_platform_proofs;

    println!("Testing potential validation bypass vulnerability");

    // Create mock proofs where the identity_id at the hardcoded offset
    // matches the document owner, but it's not the real identity

    // Mock document with owner "Alice"
    let alice_id = [170u8; 32]; // 0xAA repeated
    let document_json = format!(
        r#"{{"$ownerId": "{}"}}"#,
        bs58::encode(&alice_id).into_string()
    );

    // Mock key proof that belongs to "Bob" but has "Alice" at offset 740
    let mut key_proof = vec![0u8; 2000];
    // Place Alice's ID at the extraction offset even though this is Bob's key
    key_proof[740..772].copy_from_slice(&alice_id);

    // Mock document proof
    let document_proof = vec![0u8; 1000];

    // Create witness using no_validation (simulating attacker)
    let witness_result = create_witness_from_platform_proofs(
        &document_proof,
        &key_proof,
        document_json.as_bytes().to_vec(),
        &[0u8; 32], // public key
        &[0u8; 32], // signature_r
        &[0u8; 32], // signature_s
        &[0u8; 32], // message
        &[0u8; 32], // private key
    );

    match witness_result {
        Ok(witness) => {
            println!("Witness created:");
            println!("  owner_id: {}", hex::encode(&witness.owner_id));
            println!("  identity_id: {}", hex::encode(&witness.identity_id));

            if witness.owner_id == witness.identity_id {
                println!("⚠️ WARNING: IDs match even though key doesn't belong to document owner!");
                println!("This could allow bypass of ownership validation!");
            }
        }
        Err(e) => {
            println!("Witness creation failed: {}", e);
        }
    }
}
