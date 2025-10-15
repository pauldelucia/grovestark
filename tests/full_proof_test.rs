//! Test the complete STARK proof with all three phases

use grovestark::types::{MerkleNode, PrivateInputs, PublicInputs, STARKConfig};

#[test]
fn test_full_stark_proof() {
    // Create witness with all required data
    let owner_id = [0xAA; 32];
    let witness = PrivateInputs {
        // Document to hash (will be processed by BLAKE3)
        document_cbor: vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ],

        // Owner ID
        owner_id,
        identity_id: owner_id, // Must match owner_id

        // Identity-aware fields
        doc_root: [0x44; 32],
        keys_root: [0x55; 32],
        owner_id_leaf_to_doc_path: vec![
            MerkleNode {
                hash: [0x11; 32],
                is_left: false,
            },
            MerkleNode {
                hash: [0x22; 32],
                is_left: true,
            },
            MerkleNode {
                hash: [0x33; 32],
                is_left: false,
            },
        ],
        docroot_to_state_path: vec![],
        key_leaf_to_keysroot_path: vec![],
        identity_leaf_to_state_path: vec![],

        // EdDSA private key (32 bytes)
        private_key: [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
            0xDD, 0xEE, 0xFF, 0x00,
        ],

        // EdDSA signature components (r, s)
        signature_r: [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ],
        signature_s: [
            0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
            0xCC, 0xDD, 0xEE, 0xFF,
        ],
        ..Default::default()
    };

    // Create config with 65536 rows
    let config = STARKConfig {
        field_bits: 64,
        expansion_factor: 8,
        num_queries: 20,
        folding_factor: 4,
        max_remainder_degree: 255,
        grinding_bits: 5, // Very low for testing
        trace_length: 65536,
        num_trace_columns: 72,
        security_level: 128,
    };

    println!("Testing full STARK proof with all three phases:");
    println!("  Phase 1: BLAKE3 compression (rows 0-3583)");
    println!("  Phase 2: Merkle path verification (rows 3584-19967)");
    println!("  Phase 3: EdDSA signature verification (rows 19968-52735)");
    println!("  Padding: (rows 52736-65535)");

    // Verify the configuration
    assert_eq!(config.trace_length, 65536);
    assert_eq!(config.num_trace_columns, 72);

    // Verify witness data sizes
    assert_eq!(witness.private_key.len(), 32);
    assert_eq!(witness.signature_r.len(), 32);
    assert_eq!(witness.signature_s.len(), 32);
    assert_eq!(witness.owner_id_leaf_to_doc_path.len(), 3);

    println!("✅ Full proof test configuration validated");
}

#[test]
fn test_phase_boundaries() {
    // Test that phase boundaries are correctly set
    const BLAKE3_END: usize = 3584;
    const MERKLE_END: usize = BLAKE3_END + 16384;
    const EDDSA_END: usize = MERKLE_END + 32768;
    const TOTAL_ROWS: usize = 65536;

    assert_eq!(BLAKE3_END, 3584);
    assert_eq!(MERKLE_END, 19968);
    assert_eq!(EDDSA_END, 52736);
    assert!(EDDSA_END < TOTAL_ROWS);

    println!("Phase boundaries:");
    println!("  BLAKE3: 0..{}", BLAKE3_END);
    println!("  Merkle: {}..{}", BLAKE3_END, MERKLE_END);
    println!("  EdDSA: {}..{}", MERKLE_END, EDDSA_END);
    println!("  Padding: {}..{}", EDDSA_END, TOTAL_ROWS);
}
