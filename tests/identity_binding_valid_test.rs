use grovestark::{GroveSTARK, MerkleNode, PrivateInputs, PublicInputs, STARKConfig};

#[test]
fn test_valid_proof_with_matching_ids() {
    println!("\n🔓 Testing Valid Proof Generation with Matching IDs");
    println!("==================================================");

    // Create a simple witness with matching owner_id and identity_id
    let matching_id = [42u8; 32];

    let witness = PrivateInputs {
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

        // Use valid EdDSA test data
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

        // EdDSA signature
        signature_r: [
            0x18, 0xac, 0x08, 0x19, 0x28, 0xc3, 0x9a, 0xee, 0x8f, 0xa5, 0x29, 0x91, 0x6c, 0x07,
            0x71, 0x9f, 0xaa, 0x53, 0x4b, 0xdd, 0x32, 0x90, 0x38, 0xac, 0x6b, 0x4c, 0x59, 0xe6,
            0x92, 0xc5, 0x92, 0xed,
        ],
        signature_s: [
            0xde, 0x69, 0x45, 0xb4, 0x55, 0xb7, 0x4c, 0xa9, 0x9a, 0x25, 0xd2, 0xf6, 0x63, 0x50,
            0x0f, 0xfd, 0xa4, 0x9c, 0xe0, 0x11, 0x65, 0x07, 0x49, 0xb8, 0xed, 0xcd, 0x29, 0x72,
            0x94, 0x46, 0x3b, 0x0e,
        ],

        // Document CBOR - ensure non-empty
        document_cbor: vec![1, 2, 3, 4, 5],
        private_key: [
            0xdd, 0xbd, 0xd9, 0xbc, 0x9e, 0x20, 0x44, 0x9e, 0x5f, 0x4c, 0x7b, 0x5d, 0x07, 0x05,
            0x95, 0x13, 0xd7, 0xdf, 0x77, 0xb1, 0x9b, 0xf4, 0xca, 0xc2, 0x2b, 0x06, 0x0b, 0xc2,
            0xa2, 0x74, 0x96, 0xcd,
        ],
        public_key_a: [
            0xbf, 0xe8, 0xd2, 0xb0, 0x16, 0xbf, 0x3f, 0x02, 0xb2, 0x51, 0x33, 0xe8, 0x5d, 0xe5,
            0xef, 0xf0, 0xb7, 0xe2, 0xfb, 0x00, 0x27, 0x76, 0xba, 0x46, 0x5a, 0xd8, 0xf9, 0x2a,
            0xce, 0x35, 0x33, 0xae,
        ],
        hash_h: [
            0xef, 0x15, 0xc6, 0xba, 0x64, 0x5a, 0x12, 0x23, 0xdf, 0x69, 0x9b, 0xc7, 0x99, 0x39,
            0xc5, 0x8b, 0xd3, 0x67, 0x5c, 0x78, 0xa7, 0x1d, 0x2f, 0x2c, 0x7c, 0xc8, 0xcc, 0x40,
            0x71, 0x13, 0xcd, 0x0e,
        ],
        ..Default::default()
    };

    // Augment witness with extended coordinates
    use grovestark::crypto::ed25519::decompress::augment_witness_with_extended;
    use grovestark::phases::eddsa::witness_augmentation::augment_eddsa_witness;

    let mut augmented_witness = witness.clone();
    let _ = augment_witness_with_extended(
        &witness.signature_r,
        &witness.public_key_a,
        &mut augmented_witness.r_extended_x,
        &mut augmented_witness.r_extended_y,
        &mut augmented_witness.r_extended_z,
        &mut augmented_witness.r_extended_t,
        &mut augmented_witness.a_extended_x,
        &mut augmented_witness.a_extended_y,
        &mut augmented_witness.a_extended_z,
        &mut augmented_witness.a_extended_t,
    );

    let public_inputs = PublicInputs {
        state_root: [10u8; 32],
        contract_id: [11u8; 32],
        message_hash: [10u8; 32],
        timestamp: 1699999999,
    };

    let final_witness = augment_eddsa_witness(&augmented_witness, &public_inputs)
        .expect("Failed to augment EdDSA witness");

    // Create prover with test config
    let mut config = STARKConfig::default();
    config.grinding_bits = 2; // Low for testing
    let prover = GroveSTARK::with_config(config);

    println!("\nStep 1: Attempting proof generation with matching IDs...");
    println!("  Owner ID:    {:?}", hex::encode(&matching_id));
    println!("  Identity ID: {:?}", hex::encode(&matching_id));
    println!("  Expected: DIFF columns should all be 0, proof should succeed");

    // This should succeed since owner_id == identity_id
    match prover.prove(final_witness, public_inputs.clone()) {
        Ok(proof) => {
            println!("\n✅ SUCCESS: Proof generated with matching IDs!");
            println!(
                "  Proof size: {} bytes",
                bincode1::serialize(&proof).unwrap().len()
            );

            // Verify the proof
            match prover.verify(&proof, &public_inputs) {
                Ok(true) => println!("✅ Proof verification succeeded!"),
                Ok(false) => panic!("❌ Proof verification failed!"),
                Err(e) => panic!("❌ Proof verification error: {}", e),
            }
        }
        Err(e) => {
            panic!(
                "❌ UNEXPECTED: Proof generation failed with matching IDs!\n  Error: {}",
                e
            );
        }
    }

    println!("\n🎉 Test passed: Valid proofs can be generated when owner_id == identity_id");
}
