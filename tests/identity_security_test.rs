//! Test that the identity binding security fix actually works

use grovestark::{create_witness_from_platform_proofs, MerkleNode, PrivateInputs, PublicInputs};

#[test]
fn test_mismatched_owner_identity_fails() {
    // Create a witness with mismatched owner_id and identity_id
    let mut witness = PrivateInputs::default();

    // Set up document side
    witness.doc_root = [1u8; 32];
    witness.owner_id = [2u8; 32]; // Owner is ID 2
    witness.owner_id_leaf_to_doc_path = vec![MerkleNode {
        hash: [3u8; 32],
        is_left: true,
    }];
    witness.docroot_to_state_path = vec![MerkleNode {
        hash: [4u8; 32],
        is_left: false,
    }];

    // Set up identity side with DIFFERENT ID
    witness.identity_id = [5u8; 32]; // Identity is ID 5 (NOT matching owner!)
    witness.keys_root = [6u8; 32];
    witness.identity_leaf_to_state_path = vec![MerkleNode {
        hash: [7u8; 32],
        is_left: true,
    }];

    // Set up key membership
    witness.key_usage_tag = *b"sig:ed25519:v1\0\0";
    witness.pubkey_a_compressed = [8u8; 32];
    witness.key_leaf_to_keysroot_path = vec![MerkleNode {
        hash: [9u8; 32],
        is_left: false,
    }];

    // Set up EdDSA signature (dummy values for test)
    witness.signature_r = [10u8; 32];
    witness.signature_s = [11u8; 32];
    witness.public_key_a = [8u8; 32]; // Same as pubkey_a_compressed
    witness.hash_h = [12u8; 32];

    // Set up extended coordinates (dummy values)
    witness.r_extended_x = [0u8; 32];
    witness.r_extended_y = [10u8; 32];
    witness.r_extended_z = {
        let mut z = [0u8; 32];
        z[0] = 1;
        z
    };
    witness.r_extended_t = [0u8; 32];
    witness.a_extended_x = [0u8; 32];
    witness.a_extended_y = [8u8; 32];
    witness.a_extended_z = {
        let mut z = [0u8; 32];
        z[0] = 1;
        z
    };
    witness.a_extended_t = [0u8; 32];

    // Set scalar windows
    witness.s_windows = vec![0u8; 64];
    witness.h_windows = vec![0u8; 64];

    let public_inputs = PublicInputs {
        state_root: [100u8; 32],
        contract_id: [101u8; 32],
        message_hash: [102u8; 32],
        timestamp: 1234567890,
    };

    // Identity-aware validation should detect the mismatch and fail
    let result = grovestark::validation::validate_identity_witness(&witness);
    assert!(
        result.is_err(),
        "Should fail with mismatched owner_id and identity_id"
    );

    if let Err(e) = result {
        let error_msg = format!("{}", e);
        assert!(
            error_msg.contains("Owner ID must match Identity ID"),
            "Error should mention ID mismatch, got: {}",
            error_msg
        );
    }
}

#[test]
fn test_matched_owner_identity_passes() {
    // Create a witness with matching owner_id and identity_id
    let mut witness = PrivateInputs::default();

    // Set up document side
    witness.doc_root = [1u8; 32];
    witness.owner_id = [2u8; 32]; // Owner is ID 2
    witness.owner_id_leaf_to_doc_path = vec![MerkleNode {
        hash: [3u8; 32],
        is_left: true,
    }];
    witness.docroot_to_state_path = vec![MerkleNode {
        hash: [4u8; 32],
        is_left: false,
    }];

    // Set up identity side with MATCHING ID
    witness.identity_id = [2u8; 32]; // Identity is ALSO ID 2 (matching owner!)
    witness.keys_root = [6u8; 32];
    witness.identity_leaf_to_state_path = vec![MerkleNode {
        hash: [7u8; 32],
        is_left: true,
    }];

    // Set up key membership
    witness.key_usage_tag = *b"sig:ed25519:v1\0\0";
    witness.pubkey_a_compressed = [8u8; 32];
    witness.key_leaf_to_keysroot_path = vec![MerkleNode {
        hash: [9u8; 32],
        is_left: false,
    }];

    // Identity-aware validation should accept matching IDs
    let result = grovestark::validation::validate_identity_witness(&witness);
    assert!(
        result.is_ok(),
        "Should pass with matching owner_id and identity_id"
    );
}

#[test]
fn test_integration_with_sdk_proofs() {
    // Use real fixture proofs and platform integration path
    let document_proof = std::fs::read(
        "tests/fixtures/document_proof_B5XLy3cUDayaqZmcGaWb98PEAUguGHiHSU5DxiKrHBj3.bin",
    )
    .expect("read document proof");
    let identity_proof = std::fs::read(
        "tests/fixtures/identity_proof_FQ4waDowFQXD4tJPKQM1114VSr5f8s3qAc5bT8FJkT49.bin",
    )
    .expect("read identity proof");

    // Derive owner_id by extracting identity_id from the key proof and encoding to JSON
    let identity_id = grovestark::parser::grovedb_executor::extract_closest_identity_id_from_key_proof(
        &identity_proof,
    )
    .expect("extract identity id from proof");
    let owner_b58 = bs58::encode(identity_id).into_string();
    let document_json = serde_json::json!({"$ownerId": owner_b58}).to_string().into_bytes();

    let signature_r = [50u8; 32];
    let signature_s = [51u8; 32];
    let public_key = [52u8; 32];
    let message = b"test message";
    let private_key = [53u8; 32];

    let result = create_witness_from_platform_proofs(
        &document_proof,
        &identity_proof,
        document_json,
        &public_key,
        &signature_r,
        &signature_s,
        message,
        &private_key,
    );

    assert!(result.is_ok(), "Should create witness successfully");
    let witness = result.unwrap();

    // Verify that identity_id was set to match owner_id
    assert_eq!(
        witness.owner_id, witness.identity_id,
        "identity_id should equal owner_id for valid proof"
    );
    assert_eq!(
        witness.owner_id, identity_id,
        "owner_id should be set correctly"
    );
}
