//! EdDSA witness augmentation utilities
//!
//! Provides functions to augment EdDSA witness data with computed intermediate values
//! needed for constraint evaluation, following the researcher's requirements.

use crate::crypto::scalar_mult::FixedBaseTable;
use crate::error::Result;
use crate::phases::eddsa::scalar_range::compute_scalar_borrow_chain;
use crate::types::PrivateInputs;

/// Augment EdDSA witness with computed intermediate values
/// This is the researcher's requirement #9 - witness augmentation for EdDSA
pub fn augment_eddsa_witness(base: &PrivateInputs) -> Result<PrivateInputs> {
    let mut augmented = base.clone();

    // 1. Decompose scalars s and h into 4-bit windows (64 windows each)
    let s_scalar = bytes_to_limbs(&base.signature_s);
    let h_scalar = bytes_to_limbs(&base.hash_h);

    augmented.s_windows = decompose_scalar_to_windows(&s_scalar);
    augmented.h_windows = decompose_scalar_to_windows(&h_scalar);

    // 2. Compute scalar range check auxiliary values
    // Convert to u16 limbs for borrow chain computation
    let s_scalar_u16 = u64_limbs_to_u16(&s_scalar);
    let h_scalar_u16 = u64_limbs_to_u16(&h_scalar);
    let (s_diff, s_borrow) = compute_scalar_borrow_chain(&s_scalar_u16);
    let (h_diff, h_borrow) = compute_scalar_borrow_chain(&h_scalar_u16);

    // Store these for auxiliary trace generation
    augmented.s_range_diff = limbs_to_bytes_u16(&s_diff);
    augmented.s_range_borrow = limbs_to_bytes_u16(&s_borrow);
    augmented.h_range_diff = limbs_to_bytes_u16(&h_diff);
    augmented.h_range_borrow = limbs_to_bytes_u16(&h_borrow);

    // Debug: Check if range check data is non-zero
    eprintln!("[AUGMENT] s_borrow[0..4] = {:?}", &s_borrow[0..4]);
    eprintln!("[AUGMENT] s_diff[0..4] = {:?}", &s_diff[0..4]);

    // 3. Decompress R and A points from compressed form
    use crate::crypto::point_decompression::decompress_ed25519_point;

    let r_ext_point = decompress_ed25519_point(&base.signature_r)?;
    let a_ext_point = decompress_ed25519_point(&base.public_key_a)?;

    // Convert to ExtendedPoint format
    let r_point: crate::crypto::edwards_arithmetic::ExtendedPoint = r_ext_point.into();
    let a_point: crate::crypto::edwards_arithmetic::ExtendedPoint = a_ext_point.into();

    // 4. Store extended coordinate representations
    augmented.r_extended_x = limbs_to_bytes(&r_point.x);
    augmented.r_extended_y = limbs_to_bytes(&r_point.y);
    augmented.r_extended_z = limbs_to_bytes(&r_point.z);
    augmented.r_extended_t = limbs_to_bytes(&r_point.t);

    augmented.a_extended_x = limbs_to_bytes(&a_point.x);
    augmented.a_extended_y = limbs_to_bytes(&a_point.y);
    augmented.a_extended_z = limbs_to_bytes(&a_point.z);
    augmented.a_extended_t = limbs_to_bytes(&a_point.t);

    // 5. Precompute fixed-base table lookups for [s]B
    // This helps constraint verification by providing expected intermediate points
    let fixed_table = FixedBaseTable::new();
    let mut intermediate_points = Vec::new();

    for (window_idx, &window_value) in augmented.s_windows.iter().enumerate() {
        if window_idx < 64 {
            let table_point = fixed_table.lookup(window_idx, window_value);
            intermediate_points.push((
                limbs_to_bytes(&table_point.x),
                limbs_to_bytes(&table_point.y),
                limbs_to_bytes(&table_point.z),
                limbs_to_bytes(&table_point.t),
            ));
        }
    }

    // Store first few intermediate points (storage limited)
    if !intermediate_points.is_empty() {
        augmented.intermediate_point_1_x = intermediate_points[0].0;
        augmented.intermediate_point_1_y = intermediate_points[0].1;
        augmented.intermediate_point_1_z = intermediate_points[0].2;
        augmented.intermediate_point_1_t = intermediate_points[0].3;
    }

    if intermediate_points.len() > 1 {
        augmented.intermediate_point_2_x = intermediate_points[1].0;
        augmented.intermediate_point_2_y = intermediate_points[1].1;
        augmented.intermediate_point_2_z = intermediate_points[1].2;
        augmented.intermediate_point_2_t = intermediate_points[1].3;
    }

    Ok(augmented)
}

/// Create a placeholder witness with augmented values for testing
#[cfg(test)]
pub fn create_placeholder_eddsa_witness() -> Result<PrivateInputs> {
    // Use valid Ed25519 test vectors from RFC 8032
    // These are from test vector 1 (empty message)
    let signature_r =
        hex::decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155")
            .unwrap()
            .try_into()
            .unwrap();
    let signature_s =
        hex::decode("5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
            .unwrap()
            .try_into()
            .unwrap();
    let public_key_a =
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .unwrap()
            .try_into()
            .unwrap();

    // Compute proper hash h = SHA-512(R || A || M) mod L
    use crate::crypto::field_conversion::compute_challenge_scalar;
    let hash_h = compute_challenge_scalar(&signature_r, &public_key_a, b"");

    let mut base_witness = PrivateInputs::default();
    base_witness.signature_r = signature_r;
    base_witness.signature_s = signature_s;
    base_witness.public_key_a = public_key_a;
    base_witness.hash_h = hash_h;
    base_witness.document_cbor = b"test_document".to_vec();
    base_witness.owner_id = [5u8; 32];
    base_witness.identity_id = base_witness.owner_id;
    base_witness.doc_root = [0x44; 32];
    base_witness.keys_root = [0x55; 32];
    base_witness.private_key = [6u8; 32];

    augment_eddsa_witness(&base_witness)
}

/// Convert 32-byte array to 16 limbs of 16-bit values
fn bytes_to_limbs(bytes: &[u8; 32]) -> [u64; 16] {
    let mut limbs = [0u64; 16];
    for i in 0..16 {
        let low = bytes[i * 2] as u64;
        let high = bytes[i * 2 + 1] as u64;
        limbs[i] = low | (high << 8);
    }
    limbs
}

/// Convert 16 limbs of 16-bit values to 32-byte array
fn limbs_to_bytes(limbs: &[u64; 16]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..16 {
        bytes[i * 2] = (limbs[i] & 0xFF) as u8;
        bytes[i * 2 + 1] = ((limbs[i] >> 8) & 0xFF) as u8;
    }
    bytes
}

/// Convert u16 limbs to bytes (for range check results)
fn limbs_to_bytes_u16(limbs: &[u16; 16]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..16 {
        bytes[i * 2] = (limbs[i] & 0xFF) as u8;
        bytes[i * 2 + 1] = (limbs[i] >> 8) as u8;
    }
    bytes
}

/// Decompose scalar into 64 4-bit windows
fn decompose_scalar_to_windows(scalar: &[u64; 16]) -> Vec<u8> {
    let mut windows = Vec::with_capacity(64);

    // Convert to bytes first
    let mut bytes = [0u8; 32];
    for i in 0..16 {
        bytes[i * 2] = (scalar[i] & 0xFF) as u8;
        bytes[i * 2 + 1] = ((scalar[i] >> 8) & 0xFF) as u8;
    }

    // Extract 4-bit windows (little-endian)
    for byte_idx in 0..32 {
        let byte = bytes[byte_idx];
        windows.push(byte & 0xF); // Low nibble
        windows.push((byte >> 4) & 0xF); // High nibble
    }

    windows
}

/// Convert u64 limbs to u16 limbs
fn u64_limbs_to_u16(limbs_64: &[u64; 16]) -> [u16; 16] {
    let mut limbs_16 = [0u16; 16];
    for i in 0..16 {
        limbs_16[i] = (limbs_64[i] & 0xFFFF) as u16;
    }
    limbs_16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_witness_augmentation() {
        let witness = create_placeholder_eddsa_witness().unwrap();

        // Check that windows were generated
        assert!(witness.s_windows.len() > 0);
        assert!(witness.h_windows.len() > 0);

        // Check that all augmented fields are initialized
        assert_ne!(witness.r_extended_x, [0u8; 32]);
        assert_ne!(witness.r_extended_y, [0u8; 32]);
        assert_ne!(witness.r_extended_z, [0u8; 32]);
        assert_ne!(witness.r_extended_t, [0u8; 32]);
    }

    #[test]
    fn test_bytes_limbs_conversion() {
        let bytes = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let limbs = bytes_to_limbs(&bytes);
        let converted_back = limbs_to_bytes(&limbs);

        assert_eq!(bytes, converted_back);
    }

    #[test]
    fn test_scalar_range_augmentation() {
        let base_witness = PrivateInputs::default();
        let augmented = augment_eddsa_witness(&base_witness).unwrap();

        // Range check auxiliary values should be computed
        // For default witness (all zeros), range check should show s < L
        assert!(augmented.s_range_borrow != [0u8; 32] || augmented.s_range_diff != [0u8; 32]);
    }
}
