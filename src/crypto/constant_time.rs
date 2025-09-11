//! Constant-time cryptographic operations for timing attack resistance
//!
//! This module provides constant-time implementations of sensitive operations
//! to prevent timing side-channel attacks.

use crate::field::FieldElement;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Constant-time comparison of byte arrays
pub fn ct_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.ct_eq(b).into()
}

/// Constant-time selection between two values
pub fn ct_select<T: ConditionallySelectable>(condition: bool, a: &T, b: &T) -> T {
    T::conditional_select(b, a, Choice::from(condition as u8))
}

// EdDSA is the only active signature scheme.

/// Constant-time field operations
pub struct ConstantTimeField;

impl ConstantTimeField {
    /// Add two field elements in constant time
    pub fn add(a: FieldElement, b: FieldElement) -> FieldElement {
        // Field addition is already constant-time
        a + b
    }

    /// Multiply two field elements in constant time
    pub fn mul(a: FieldElement, b: FieldElement) -> FieldElement {
        // Field multiplication is already constant-time
        a * b
    }

    /// Compare two field elements in constant time
    pub fn compare(a: FieldElement, b: FieldElement) -> bool {
        let a_bytes = a.to_bytes();
        let b_bytes = b.to_bytes();

        a_bytes.ct_eq(&b_bytes).into()
    }

    /// Conditional selection of field elements
    pub fn select(condition: bool, a: FieldElement, b: FieldElement) -> FieldElement {
        let choice = Choice::from(condition as u8);
        let a_val = a.as_u64();
        let b_val = b.as_u64();

        let result = u64::conditional_select(&b_val, &a_val, choice);
        FieldElement::new(result)
    }
}

/// Constant-time Merkle tree operations
pub struct ConstantTimeMerkle;

impl ConstantTimeMerkle {
    /// Verify a Merkle proof in constant time
    pub fn verify_proof(leaf: &[u8; 32], path: &[(Vec<u8>, bool)], root: &[u8; 32]) -> bool {
        use crate::crypto::Blake3Hasher;

        let mut current = *leaf;

        for (sibling, is_left) in path {
            if sibling.len() != 32 {
                return false;
            }

            let mut sibling_array = [0u8; 32];
            sibling_array.copy_from_slice(sibling);

            // Use constant-time selection for ordering
            let (left, right) = Self::ct_order_hashes(&current, &sibling_array, *is_left);

            // Combine and hash
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&left);
            combined[32..].copy_from_slice(&right);

            current = Blake3Hasher::hash(&combined);
        }

        ct_compare(&current, root)
    }

    /// Order two hashes in constant time based on position
    fn ct_order_hashes(
        hash1: &[u8; 32],
        hash2: &[u8; 32],
        hash1_is_left: bool,
    ) -> ([u8; 32], [u8; 32]) {
        let choice = Choice::from(hash1_is_left as u8);

        let mut left = [0u8; 32];
        let mut right = [0u8; 32];

        for i in 0..32 {
            left[i] = u8::conditional_select(&hash2[i], &hash1[i], choice);
            right[i] = u8::conditional_select(&hash1[i], &hash2[i], choice);
        }

        (left, right)
    }
}

/// Constant-time memory operations
pub struct SecureMemory;

impl SecureMemory {
    /// Securely clear sensitive memory
    pub fn zeroize(data: &mut [u8]) {
        use zeroize::Zeroize;
        data.zeroize();
    }

    /// Constant-time memory comparison
    pub fn compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for i in 0..a.len() {
            result |= a[i] ^ b[i];
        }

        result == 0
    }

    /// Constant-time copy
    pub fn copy(dest: &mut [u8], src: &[u8]) {
        if dest.len() != src.len() {
            return;
        }
        dest.copy_from_slice(src);
    }
}

/// Timing-safe random number generation
pub struct SecureRandom;

impl SecureRandom {
    /// Generate cryptographically secure random bytes
    pub fn random_bytes(length: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut bytes = vec![0u8; length];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    /// Generate a random field element
    pub fn random_field_element() -> FieldElement {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        FieldElement::new(rng.gen())
    }

    // Scalar helpers not needed here
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_compare() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let c = [2u8; 32];

        assert!(ct_compare(&a, &b));
        assert!(!ct_compare(&a, &c));
    }

    #[test]
    fn test_constant_time_select() {
        let a = 42u64;
        let b = 100u64;

        assert_eq!(u64::conditional_select(&b, &a, Choice::from(1)), 42);
        assert_eq!(u64::conditional_select(&b, &a, Choice::from(0)), 100);
    }

    #[test]
    fn test_constant_time_field_ops() {
        let a = FieldElement::new(42);
        let b = FieldElement::new(100);

        let sum = ConstantTimeField::add(a, b);
        assert_eq!(sum, FieldElement::new(142));

        let selected = ConstantTimeField::select(true, a, b);
        assert_eq!(selected, a);

        let selected = ConstantTimeField::select(false, a, b);
        assert_eq!(selected, b);
    }

    #[test]
    fn test_secure_memory() {
        let mut data = vec![0x42u8; 32];
        SecureMemory::zeroize(&mut data);
        assert_eq!(data, vec![0u8; 32]);

        let a = [1u8; 32];
        let b = [1u8; 32];
        assert!(SecureMemory::compare(&a, &b));
    }

    #[test]
    fn test_secure_random() {
        let bytes1 = SecureRandom::random_bytes(32);
        let bytes2 = SecureRandom::random_bytes(32);

        // Should be different (with overwhelming probability)
        assert_ne!(bytes1, bytes2);

        let field1 = SecureRandom::random_field_element();
        let field2 = SecureRandom::random_field_element();

        // Should be different
        assert_ne!(field1, field2);
    }
}
