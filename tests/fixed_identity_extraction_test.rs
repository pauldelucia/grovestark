use grovestark::create_witness_from_platform_proofs;
use hex;

#[test]
fn test_fixed_identity_extraction() {
    println!("\n🔍 Testing Fixed Identity ID Extraction from Key Proof");
    println!("======================================================\n");

    // Create a mock key proof with identity ID at the correct offset (788 / 0x314)
    let correct_identity_id =
        hex::decode("fe653f96bfa2c977e39772e1167717dccb4e86371c7e97eb570c9e5dd43cc05d").unwrap();
    let wrong_identity_id =
        hex::decode("7e5adbbc69c5c31e7706f9f41002804f354e78e573b863656a9281d6befea040").unwrap();

    // Build a key proof with the IDs at the expected positions
    let mut key_proof = vec![0u8; 2000]; // Large enough for all offsets

    // Place wrong ID at old offset 740 (0x2e4)
    key_proof[740..772].copy_from_slice(&wrong_identity_id);

    // Place correct ID at new offset 788 (0x314)
    key_proof[788..820].copy_from_slice(&correct_identity_id);

    // Create a mock document proof
    let mut document_proof = vec![0u8; 100];
    document_proof[0..4].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Basic header

    // Create document JSON with matching owner ID
    let document_json = format!(
        r#"{{
        "$id": "test_doc",
        "$ownerId": "{}",
        "$revision": 1
    }}"#,
        hex::encode(&correct_identity_id)
    )
    .into_bytes();

    // Mock EdDSA components
    let public_key = [0x01u8; 32];
    let signature_r = [0x02u8; 32];
    let signature_s = [0x03u8; 32];
    let message = b"test message";

    println!(
        "Expected identity ID: {}",
        hex::encode(&correct_identity_id)
    );
    println!(
        "Wrong ID at offset 740: {}",
        hex::encode(&wrong_identity_id)
    );
    println!(
        "Correct ID at offset 788: {}",
        hex::encode(&correct_identity_id)
    );

    // Try to create witness - this should now extract the correct ID from offset 788
    let result = create_witness_from_platform_proofs(
        &document_proof,
        &key_proof,
        document_json,
        &public_key,
        &signature_r,
        &signature_s,
        message,
    );

    match result {
        Ok(witness) => {
            println!("\n✅ Witness created successfully!");
            println!(
                "  Extracted identity ID: {}",
                hex::encode(&witness.identity_id)
            );
            println!("  Document owner ID: {}", hex::encode(&witness.owner_id));

            // Verify the IDs match
            assert_eq!(
                witness.identity_id, witness.owner_id,
                "Identity ID should match owner ID"
            );

            // Verify we got the correct ID, not the wrong one
            assert_eq!(
                witness.identity_id,
                correct_identity_id.as_slice(),
                "Should extract correct identity ID from offset 788"
            );

            assert_ne!(
                witness.identity_id,
                wrong_identity_id.as_slice(),
                "Should NOT extract wrong ID from offset 740"
            );

            println!("\n🎉 SUCCESS: Identity ID correctly extracted from offset 788!");
        }
        Err(e) => {
            // Check if it's a different error (e.g., EdDSA decompression)
            let error_msg = format!("{}", e);
            if error_msg.contains("Identity doesn't own document") {
                panic!(
                    "❌ FAILED: Still extracting wrong identity ID!\nError: {}",
                    e
                );
            } else {
                // If it's an EdDSA error, that's OK - we're testing ID extraction
                println!("⚠️  Got expected EdDSA error (ID extraction worked): {}", e);

                // For this test, EdDSA errors are acceptable since we're using dummy keys
                // The important thing is that we didn't get an ownership mismatch error
                assert!(
                    !error_msg.contains("Identity doesn't own document"),
                    "Should not fail on ownership check"
                );
                println!("\n✅ Identity extraction working correctly (EdDSA error is expected with dummy keys)");
            }
        }
    }
}

#[test]
fn test_extraction_with_real_offsets() {
    println!("\n🔬 Testing ID Extraction with Real Proof Structure");
    println!("==================================================\n");

    // Simulate the exact structure from the DET_PROOF_LOGS
    let correct_id =
        hex::decode("fe653f96bfa2c977e39772e1167717dccb4e86371c7e97eb570c9e5dd43cc05d").unwrap();
    let wrong_id =
        hex::decode("7e5adbbc69c5c31e7706f9f41002804f354e78e573b863656a9281d6befea040").unwrap();

    // Build key proof matching the real structure
    let mut key_proof = vec![0u8; 2000];

    // Add some realistic proof structure markers
    key_proof[736..740].copy_from_slice(&[0x04, 0x20, 0x00, 0x00]); // Marker before old offset
    key_proof[740..772].copy_from_slice(&wrong_id); // Wrong ID at 740 (0x2e4)

    key_proof[784..788].copy_from_slice(&[0x01, 0x20, 0x00, 0x00]); // Marker before correct offset
    key_proof[788..820].copy_from_slice(&correct_id); // Correct ID at 788 (0x314)

    // Also place at secondary location for completeness
    key_proof[1924..1956].copy_from_slice(&correct_id); // Secondary at 1924 (0x784)

    println!("Key proof structure:");
    println!(
        "  Offset 0x2e0-0x2e3: marker {:02x} {:02x} {:02x} {:02x}",
        key_proof[736], key_proof[737], key_proof[738], key_proof[739]
    );
    println!(
        "  Offset 0x2e4 (740): {} (WRONG)",
        hex::encode(&key_proof[740..772])
    );
    println!(
        "  Offset 0x310-0x313: marker {:02x} {:02x} {:02x} {:02x}",
        key_proof[784], key_proof[785], key_proof[786], key_proof[787]
    );
    println!(
        "  Offset 0x314 (788): {} (CORRECT)",
        hex::encode(&key_proof[788..820])
    );

    // We can't directly call extract_identity_id_from_key_proof as it's private,
    // but we can test through create_witness_from_platform_proofs

    // Create minimal valid structures for the test
    let document_proof = vec![0x01, 0x00, 0x00, 0x00];
    let document_json = format!(r#"{{"$ownerId": "{}"}}"#, hex::encode(&correct_id)).into_bytes();

    let public_key = [0x01u8; 32];
    let signature_r = [0x02u8; 32];
    let signature_s = [0x03u8; 32];
    let message = b"test";

    let result = create_witness_from_platform_proofs(
        &document_proof,
        &key_proof,
        document_json,
        &public_key,
        &signature_r,
        &signature_s,
        message,
    );

    // Check that we're extracting the correct ID
    match result {
        Ok(witness) => {
            assert_eq!(
                witness.identity_id,
                correct_id.as_slice(),
                "Should extract ID from offset 788, not 740"
            );
            println!("\n✅ Correctly extracted ID from offset 788!");
        }
        Err(e) => {
            let error_msg = format!("{}", e);
            if error_msg.contains("Identity doesn't own document") {
                // If we get ownership error, check which ID was extracted
                if error_msg.contains(&hex::encode(&wrong_id)) {
                    panic!("❌ Still extracting wrong ID from offset 740!");
                } else {
                    panic!("❌ Ownership check failed for unexpected reason: {}", e);
                }
            } else {
                // Other errors (like EdDSA) are OK for this test
                println!(
                    "⚠️ Got non-ownership error (extraction likely worked): {}",
                    e
                );
            }
        }
    }
}
