use grovestark::crypto::ed25519::decompress::augment_witness_with_extended;
use grovestark::phases::eddsa::witness_augmentation::augment_eddsa_witness;
use grovestark::types::{MerkleNode, PrivateInputs, PublicInputs};

/// Create a valid EdDSA witness with proper extended coordinates
pub fn create_valid_eddsa_witness_with_decompression() -> PrivateInputs {
    // Use the valid test data from eddsa_test_data.rs
    let signature_r = [
        0xcc, 0xbe, 0x0e, 0x07, 0x1b, 0x3d, 0x98, 0x78, 0x56, 0x37, 0x2d, 0x16, 0x9d, 0x38, 0x5e,
        0xfa, 0x38, 0x4a, 0xa9, 0xc5, 0x15, 0x8a, 0xf3, 0x4e, 0xc8, 0x77, 0x09, 0xe8, 0xd9, 0x60,
        0x44, 0xa1,
    ];

    let signature_s = [
        0xc0, 0x5d, 0xa5, 0x15, 0x1f, 0x1e, 0xdc, 0xd5, 0xfd, 0x35, 0xa4, 0x24, 0xb5, 0xb3, 0x31,
        0xb2, 0xc7, 0xe0, 0x42, 0xae, 0x05, 0xf2, 0x1d, 0x5b, 0xb5, 0x66, 0xd4, 0xf9, 0x5a, 0x82,
        0xdc, 0x06,
    ];

    let public_key_a = [
        0x5a, 0xef, 0x23, 0x2b, 0x7f, 0x89, 0xde, 0x68, 0x4d, 0x2d, 0xe7, 0x54, 0x66, 0xbf, 0xa5,
        0xfb, 0xed, 0xed, 0x58, 0xb4, 0x15, 0x26, 0x13, 0xe6, 0xe7, 0x15, 0x92, 0x9d, 0x39, 0x11,
        0x40, 0x85,
    ];

    let hash_h = [
        0x6a, 0x10, 0x42, 0x3c, 0x2b, 0x7f, 0xe7, 0x13, 0xcb, 0x5b, 0x01, 0x04, 0x86, 0x87, 0x13,
        0xe0, 0xc2, 0x18, 0xbd, 0x21, 0x10, 0xff, 0x34, 0xcd, 0x16, 0x2c, 0x19, 0x65, 0x2e, 0xf3,
        0x85, 0xdf,
    ];

    let private_key = [
        0x90, 0xb3, 0x78, 0x10, 0xa3, 0xe2, 0x42, 0xfa, 0x3a, 0xe2, 0xbe, 0xa4, 0x42, 0x66, 0xbc,
        0x42, 0xe1, 0x94, 0x78, 0xad, 0xb3, 0x6c, 0xda, 0xb1, 0x93, 0x0c, 0xb3, 0xb4, 0xb8, 0x3a,
        0x23, 0x07,
    ];

    let owner_id = {
        let mut id = [0u8; 32];
        id[0] = 5;
        id[1] = 6;
        id[2] = 7;
        id[3] = 8;
        id
    };

    let mut witness = PrivateInputs {
        signature_r,
        signature_s,
        public_key_a,
        hash_h,
        private_key,
        document_cbor: vec![1, 2, 3, 4],
        owner_id,
        identity_id: owner_id, // Must match owner_id

        // Identity-aware fields
        doc_root: [0x44; 32],
        keys_root: [0x55; 32],
        owner_id_leaf_to_doc_path: vec![
            MerkleNode {
                hash: [0u8; 32],
                is_left: true,
            },
            MerkleNode {
                hash: [1u8; 32],
                is_left: false,
            },
        ],
        docroot_to_state_path: vec![],
        key_leaf_to_keysroot_path: vec![
            MerkleNode {
                hash: [2u8; 32],
                is_left: false,
            },
            MerkleNode {
                hash: [3u8; 32],
                is_left: true,
            },
        ],
        identity_leaf_to_state_path: vec![],
        ..Default::default()
    };

    // Augment with decompressed extended coordinates
    let _ = augment_witness_with_extended(
        &signature_r,
        &public_key_a,
        &mut witness.r_extended_x,
        &mut witness.r_extended_y,
        &mut witness.r_extended_z,
        &mut witness.r_extended_t,
        &mut witness.a_extended_x,
        &mut witness.a_extended_y,
        &mut witness.a_extended_z,
        &mut witness.a_extended_t,
    );

    augment_eddsa_witness(&witness).expect("Failed to augment witness")
}
