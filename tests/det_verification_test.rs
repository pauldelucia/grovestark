// Test using exact data from Dash Evo Tool logs
use grovestark::{GroveSTARK, STARKConfig};

#[test]
fn test_det_proof_generation_and_verification() {
    // Exact data from DET_LOGS.md

    // Create mock proof bytes (since DET generates the proof successfully)
    // The issue is with verification, not generation
    let mock_proof = create_mock_proof_from_det_data();

    // Create verifier with same config
    let mut config = STARKConfig::default();
    config.grinding_bits = 24; // Production setting from DET
    let verifier = GroveSTARK::with_config(config);

    // Create public inputs from DET data
    let public_inputs = grovestark::PublicInputs {
        state_root: hex_to_array32(
            "008d01fce11e3abd185f55b42a07a5ede936c985f5eadacef172de2906eb76f2",
        ),
        contract_id: hex_to_array32(
            "57e5c248f52c7d15857a3af8525749caced7b8399c0ed3221c36480263702306",
        ),
        message_hash: hex_to_array32(
            "01ca07150c4795325ab8e5a19864b9a276bc6f8d9dc59d6f194e9318ff310a45",
        ),
        timestamp: 0, // Not used
    };

    println!("Testing verification with DET data...");
    println!("State root: {:?}", hex::encode(&public_inputs.state_root));
    println!("Contract ID: {:?}", hex::encode(&public_inputs.contract_id));
    println!(
        "Message hash: {:?}",
        hex::encode(&public_inputs.message_hash)
    );

    // Test verification
    match verifier.verify(&mock_proof, &public_inputs) {
        Ok(result) => {
            println!("Verification result: {}", result);
            if !result {
                println!("❌ Verification failed - checking why...");

                // Check individual components
                if !mock_proof.public_outputs.verified {
                    println!("  - EdDSA signature verification: FAILED");
                } else {
                    println!("  - EdDSA signature verification: OK");
                }

                if mock_proof.public_outputs.key_security_level > 3 {
                    println!(
                        "  - Key security level: {} (invalid)",
                        mock_proof.public_outputs.key_security_level
                    );
                } else {
                    println!(
                        "  - Key security level: {} (OK)",
                        mock_proof.public_outputs.key_security_level
                    );
                }

                // Check proof commitment
                if mock_proof.public_outputs.proof_commitment == [0u8; 32] {
                    println!("  - Proof commitment: empty");
                } else {
                    println!(
                        "  - Proof commitment: {:?}",
                        hex::encode(&mock_proof.public_outputs.proof_commitment)
                    );
                }
            }
        }
        Err(e) => {
            println!("❌ Verification error: {:?}", e);

            // Analyze the error
            let error_str = e.to_string();
            if error_str.contains("Public outputs indicate verification failed") {
                println!("  Issue: EdDSA signature verification failed during proof generation");
                println!("  This means the signature components don't verify correctly");
            } else if error_str.contains("Insufficient proof of work") {
                println!("  Issue: Proof of work validation failed");
            } else if error_str.contains("Proof too small") || error_str.contains("Proof too large")
            {
                println!("  Issue: Proof size validation failed");
            } else {
                println!("  Unexpected error type");
            }
        }
    }
}

fn create_mock_proof_from_det_data() -> grovestark::STARKProof {
    // Create a mock proof that simulates what DET would generate
    // The key is that DET says proof generation succeeds, so public_outputs.verified should be true

    grovestark::STARKProof {
        trace_commitment: vec![1u8; 32],
        constraint_commitment: vec![2u8; 32],
        fri_proof: grovestark::types::FRIProof {
            query_rounds: vec![],
            final_polynomial: vec![0u8; 100_000], // Simulate a real proof size
            proof_of_work: 0,
        },
        pow_nonce: compute_pow_nonce(),
        public_inputs: grovestark::PublicInputs {
            state_root: hex_to_array32(
                "008d01fce11e3abd185f55b42a07a5ede936c985f5eadacef172de2906eb76f2",
            ),
            contract_id: hex_to_array32(
                "57e5c248f52c7d15857a3af8525749caced7b8399c0ed3221c36480263702306",
            ),
            message_hash: hex_to_array32(
                "01ca07150c4795325ab8e5a19864b9a276bc6f8d9dc59d6f194e9318ff310a45",
            ),
            timestamp: 0,
        },
        public_outputs: grovestark::PublicOutputs {
            verified: true, // DET says proof generation succeeds, so EdDSA must have verified
            key_security_level: 4, // From DET logs: Key ID: 4
            proof_commitment: [3u8; 32],
        },
    }
}

fn compute_pow_nonce() -> u64 {
    // Compute a valid proof-of-work nonce for the mock proof
    use grovestark::crypto::Blake3Hasher;

    let trace_commitment = vec![1u8; 32];
    let constraint_commitment = vec![2u8; 32];
    let grinding_bits = 24;

    let challenge =
        Blake3Hasher::hash(&[&trace_commitment[..], &constraint_commitment[..]].concat());

    // Find a nonce that satisfies the proof-of-work requirement
    for nonce in 0u64..u64::MAX {
        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&nonce.to_le_bytes());

        let pow_hash = Blake3Hasher::hash(&[&challenge[..], &nonce_bytes[..]].concat());

        let leading_zeros = pow_hash.iter().take_while(|&&b| b == 0).count() * 8;
        let first_nonzero = pow_hash.iter().find(|&&b| b != 0).unwrap_or(&0);
        let additional_zeros = first_nonzero.leading_zeros() as usize;
        let total_zeros = leading_zeros + additional_zeros;

        if total_zeros >= grinding_bits {
            return nonce;
        }
    }

    0 // Fallback
}

fn hex_to_array32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("Invalid hex string");
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes[0..32]);
    array
}
