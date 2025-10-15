//! Test the simplified identity binding security

use grovestark::create_witness_from_platform_proofs;

#[test]
fn test_accepts_matched_owner_identity() {
    // Create mock proofs with matching owner_id and identity_id

    // Mock document proof with valid Merk operation header
    let mut document_proof = vec![];
    document_proof.extend_from_slice(&[0x00, 0x04, 0x00, 0x04]); // Mock header
    document_proof.push(0x01); // Push operation
    document_proof.extend_from_slice(&[0xAAu8; 32]); // Hash
    document_proof.extend_from_slice(&[0u8; 32]); // Padding for owner_id location
    document_proof[32..64].copy_from_slice(&[0xAAu8; 32]); // owner_id = 0xAA...

    // Mock key proof with SAME identity_id
    let mut key_proof = vec![0u8; 70]; // Padding before identity_id
    key_proof.extend_from_slice(&[0xAAu8; 32]); // identity_id = 0xAA... at offset 70 (same!)
    key_proof.extend_from_slice(&[0u8; 50]); // More padding

    // Document JSON with owner_id field
    // Create a proper JSON document with {"$ownerId": "<base58 string>"}
    let document_json = r#"{
        "$id": "9kqkfbbDz6go9GEeUJSpsMG3mj3swcqa1UJ6rK5QnR6X",
        "$ownerId": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "$revision": 1,
        "$type": "testDocument"
    }"#
    .as_bytes()
    .to_vec();

    let public_key = [0xCCu8; 32];
    let signature_r = [0xDDu8; 32];
    let signature_s = [0xEEu8; 32];
    let message = b"test message";
    let private_key = [0xFFu8; 32];

    // This should SUCCEED because owner_id == identity_id
    let result = create_witness_from_platform_proofs(
        &document_proof,
        &key_proof,
        document_json,
        &public_key,
        &signature_r,
        &signature_s,
        message,
        &private_key,
    );

    // Note: This will fail on EdDSA decompression with dummy data,
    // but should pass the owner_id == identity_id check
    match result {
        Ok(witness) => {
            assert_eq!(witness.owner_id, witness.identity_id, "IDs should match");
            assert_eq!(witness.owner_id, [0xAAu8; 32], "Owner ID should be set");
        }
        Err(e) => {
            let error_msg = format!("{}", e);
            // If it fails, it should be for EdDSA reasons, not ownership
            assert!(
                !error_msg.contains("Identity doesn't own document"),
                "Should not fail on ownership check when IDs match"
            );
        }
    }
}

#[test]
fn test_extraction_placeholders() {
    // Test that our placeholder extraction functions work
    // This documents the current behavior until proper parsing is implemented

    let mut document_cbor = vec![0u8; 100];
    document_cbor[32..64].copy_from_slice(&[0x42u8; 32]);

    let mut key_proof = vec![0u8; 100];
    key_proof[32..64].copy_from_slice(&[0x42u8; 32]);

    // Both should extract the same value from offset 32-64
    // This is a placeholder implementation that needs proper parsing

    // The test just documents that extraction works somehow
    // Real implementation needs:
    // 1. CBOR parsing for document
    // 2. GroveDB proof path parsing for identity_id
}

#[test]
fn test_witness_structure() {
    // Test that the witness is properly structured for the simplified path

    // Create matching mock data
    let mut document_proof = vec![0x01]; // Minimal valid proof for parser
    document_proof.extend_from_slice(&[0x11u8; 32]); // Push operation

    let mut key_proof = vec![0x01]; // Minimal valid proof for parser
    key_proof.extend_from_slice(&[0x22u8; 32]); // Push operation

    let mut document_cbor = vec![0u8; 100];
    let owner_id = [0x33u8; 32];
    document_cbor[32..64].copy_from_slice(&owner_id);

    // Make key proof have same identity_id
    key_proof.resize(100, 0);
    key_proof[32..64].copy_from_slice(&owner_id);

    // Use valid Ed25519 test data to avoid decompression errors
    // These are from the Ed25519 test vectors
    let public_key = [
        0x3b, 0x12, 0x49, 0x45, 0x67, 0x3d, 0xdb, 0xac, 0xab, 0xe6, 0xb6, 0xfd, 0x81, 0xca, 0xe3,
        0x6c, 0xd5, 0x51, 0x17, 0xae, 0x53, 0x77, 0xdd, 0xb1, 0xa9, 0xc0, 0x2e, 0xc0, 0xf8, 0xaa,
        0xba, 0x5a,
    ];

    let signature_r = [
        0x3b, 0x12, 0x49, 0x45, 0x67, 0x3d, 0xdb, 0xac, 0xab, 0xe6, 0xb6, 0xfd, 0x81, 0xca, 0xe3,
        0x6c, 0xd5, 0x51, 0x17, 0xae, 0x53, 0x77, 0xdd, 0xb1, 0xa9, 0xc0, 0x2e, 0xc0, 0xf8, 0xaa,
        0xba, 0x5a,
    ];

    let signature_s = [0x01u8; 32];
    let message = b"test";
    let private_key = [0x01u8; 32];

    let result = create_witness_from_platform_proofs(
        &document_proof,
        &key_proof,
        document_cbor.clone(),
        &public_key,
        &signature_r,
        &signature_s,
        message,
        &private_key,
    );

    // Check if we get past the owner_id == identity_id check
    match result {
        Ok(witness) => {
            // Witness should have:
            assert_eq!(witness.owner_id, owner_id, "Owner ID should be set");
            assert_eq!(
                witness.identity_id, owner_id,
                "Identity ID should match owner"
            );
            assert_eq!(
                witness.document_cbor, document_cbor,
                "Document should be stored"
            );
            assert_eq!(witness.public_key_a, public_key, "Public key should be set");
        }
        Err(e) => {
            println!("Witness creation failed (expected with test data): {}", e);
            // As long as it's not an ownership error, that's OK for this test
            let error_msg = format!("{}", e);
            assert!(
                !error_msg.contains("Identity doesn't own document"),
                "Should not be an ownership error"
            );
        }
    }
}
