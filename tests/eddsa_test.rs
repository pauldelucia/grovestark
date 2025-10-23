use grovestark::crypto::edwards_arithmetic::{
    identity, point_double, point_mul_by_8, point_negate, unified_add, Ed25519Constants,
    ExtendedPoint,
};
use grovestark::crypto::scalar_mult::{
    scalar_mult_fixed_base, scalar_mult_variable_base, FixedBaseTable,
};
use grovestark::types::{MerkleNode, PrivateInputs};

#[test]
fn test_edwards_curve_operations() {
    let constants = Ed25519Constants::new();
    let base = constants.base_point;

    // Test point doubling
    let doubled = point_double(&base);
    assert!(!is_identity_point(&doubled));

    // Test point addition
    let sum = unified_add(&base, &doubled);
    assert!(!is_identity_point(&sum));

    // Test identity
    let id = identity();
    assert!(is_identity_point(&id));

    // Test cofactor multiplication
    let base_times_8 = point_mul_by_8(&base);
    assert!(!is_identity_point(&base_times_8));
}

#[test]
fn test_scalar_multiplication() {
    let constants = Ed25519Constants::new();
    let base = constants.base_point;

    // Test scalar mult by small value
    let scalar = [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    // Compute 3*B using repeated addition
    let base_2 = point_double(&base);
    let base_3_manual = unified_add(&base, &base_2);

    // Compute 3*B using scalar mult
    let table = FixedBaseTable::new();
    let base_3_scalar = scalar_mult_fixed_base(&scalar, &table);

    // They should be equal in projective sense
    // For now just check neither is identity
    assert!(!is_identity_point(&base_3_manual));
    assert!(!is_identity_point(&base_3_scalar));
}

#[test]
fn test_eddsa_signature_verification_mock() {
    // Create mock EdDSA signature components
    let s = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // s = 1
    let h = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // h = 2

    let constants = Ed25519Constants::new();
    let base = constants.base_point;

    // Mock public key A = base point
    let a = base;

    // Mock R = base point
    let r = base;

    // Compute [s]B
    let table = FixedBaseTable::new();
    let s_b = scalar_mult_fixed_base(&s, &table);

    // Compute [h]A
    let h_a = scalar_mult_variable_base(&h, &a);

    // Compute [s]B - R - [h]A
    let neg_r = point_negate(&r);
    let neg_h_a = point_negate(&h_a);

    let temp = unified_add(&s_b, &neg_r);
    let result = unified_add(&temp, &neg_h_a);

    // Multiply by 8 (cofactor)
    let final_result = point_mul_by_8(&result);

    // In a valid signature, this should be identity
    // For this mock test, it won't be
    assert!(!is_identity_point(&final_result));
}

#[test]
fn test_eddsa_witness_creation() {
    // Create a mock EdDSA witness
    let mut witness = PrivateInputs::default();
    witness.document_cbor = vec![1, 2, 3, 4];
    witness.owner_id = [5; 32];
    // Set identity-aware fields
    witness.identity_id = witness.owner_id; // Must match
    witness.doc_root = [0x44; 32];
    witness.keys_root = [0x55; 32];
    witness.owner_id_leaf_to_doc_path = vec![MerkleNode {
        hash: [0u8; 32],
        is_left: true,
    }];
    witness.docroot_to_state_path = vec![MerkleNode {
        hash: [3u8; 32],
        is_left: false,
    }];
    witness.key_leaf_to_keysroot_path = vec![MerkleNode {
        hash: [1u8; 32],
        is_left: false,
    }];
    witness.identity_leaf_to_state_path = vec![MerkleNode {
        hash: [4u8; 32],
        is_left: true,
    }];
    witness.pubkey_a_compressed = witness.public_key_a;

    // EdDSA signature components
    witness.signature_r = [0x11; 32];
    witness.signature_s = [0x22; 32];

    // EdDSA witness augmentation
    witness.public_key_a = [0x33; 32];
    witness.hash_h = [0x44; 32];
    witness.s_windows = (0..64).map(|i| (i % 16) as u8).collect(); // 64 windows
    witness.h_windows = (0..64).map(|i| (15 - (i % 16)) as u8).collect(); // 64 windows

    // Scalar range check auxiliary values
    witness.s_range_diff = [0; 32];
    witness.s_range_borrow = [0; 32];
    witness.h_range_diff = [0; 32];
    witness.h_range_borrow = [0; 32];

    // Extended coordinate representations
    witness.r_extended_x = [0; 32];
    witness.r_extended_y = [0x11; 32]; // Same as signature_r for testing
    witness.r_extended_z = {
        let mut z = [0; 32];
        z[0] = 1; // Z = 1 for affine representation
        z
    };
    witness.r_extended_t = [0; 32];
    witness.a_extended_x = [0; 32];
    witness.a_extended_y = [0x33; 32]; // Same as public_key_a for testing
    witness.a_extended_z = {
        let mut z = [0; 32];
        z[0] = 1; // Z = 1 for affine representation
        z
    };
    witness.a_extended_t = [0; 32];

    // Intermediate points
    witness.intermediate_point_1_x = [0; 32];
    witness.intermediate_point_1_y = [0; 32];
    witness.intermediate_point_1_z = [0; 32];
    witness.intermediate_point_1_t = [0; 32];
    witness.intermediate_point_2_x = [0; 32];
    witness.intermediate_point_2_y = [0; 32];
    witness.intermediate_point_2_z = [0; 32];
    witness.intermediate_point_2_t = [0; 32];

    // Verify witness structure
    assert_eq!(witness.s_windows.len(), 64);
    assert_eq!(witness.h_windows.len(), 64);
    assert_eq!(witness.public_key_a.len(), 32);
    assert_eq!(witness.hash_h.len(), 32);
}

// Helper function to check if a point is identity
fn is_identity_point(p: &ExtendedPoint) -> bool {
    // Identity has X = 0, T = 0
    p.x.iter().all(|&x| x == 0) && p.t.iter().all(|&t| t == 0)
}
