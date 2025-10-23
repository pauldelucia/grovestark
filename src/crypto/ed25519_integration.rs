/// Integration with ed25519-dalek library for witness generation
///
/// This module provides the interface to ed25519-dalek for:
/// - Key generation and validation
/// - Signature generation and verification
/// - Point decompression
/// - Scalar operations
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};

use crate::error::{Error, Result};
use crate::types::PrivateInputs;

/// Generate an EdDSA signature using ed25519-dalek
pub fn sign_message(
    private_key: &[u8; 32],
    message: &[u8],
) -> Result<(
    [u8; 32], // R (first 32 bytes of signature)
    [u8; 32], // s (last 32 bytes of signature)
)> {
    // Create signing key from private key bytes
    let signing_key = SigningKey::from_bytes(private_key);

    // Sign the message
    let signature = signing_key.sign(message);
    let sig_bytes = signature.to_bytes();

    // Split into R and s components
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig_bytes[0..32]);
    s.copy_from_slice(&sig_bytes[32..64]);

    Ok((r, s))
}

/// Verify an EdDSA signature using ed25519-dalek
pub fn verify_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature_r: &[u8; 32],
    signature_s: &[u8; 32],
) -> Result<bool> {
    // Reconstruct the signature
    let mut sig_bytes = [0u8; 64];
    sig_bytes[0..32].copy_from_slice(signature_r);
    sig_bytes[32..64].copy_from_slice(signature_s);

    let signature = Signature::from_bytes(&sig_bytes);

    // Create verifying key from public key bytes
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| Error::InvalidInput(format!("Invalid public key: {}", e)))?;

    // Verify the signature
    Ok(verifying_key.verify(message, &signature).is_ok())
}

/// Compute h = SHA-512(R || A || M) mod L using ed25519-dalek
///
/// This properly reduces the hash modulo the group order L
pub fn compute_challenge_scalar(r: &[u8; 32], a: &[u8; 32], m: &[u8]) -> [u8; 32] {
    // Compute SHA-512(R || A || M)
    let mut hasher = Sha512::new();
    hasher.update(r);
    hasher.update(a);
    hasher.update(m);
    let hash = hasher.finalize();

    // Use curve25519-dalek's scalar reduction
    let mut hash_bytes = [0u8; 64];
    hash_bytes.copy_from_slice(&hash);

    // Reduce modulo L using curve25519-dalek's implementation
    let scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&hash_bytes);

    let mut result = [0u8; 32];
    result.copy_from_slice(scalar.as_bytes());
    result
}

/// Derive public key from private key using ed25519-dalek
pub fn derive_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    let signing_key = SigningKey::from_bytes(private_key);
    let verifying_key = signing_key.verifying_key();
    *verifying_key.as_bytes()
}

/// Augment witness with ed25519-dalek computed values
pub fn augment_witness_with_eddsa(
    witness: &mut PrivateInputs,
    private_key: &[u8; 32],
    message: &[u8],
) -> Result<()> {
    // Derive public key from supplied private key
    witness.public_key_a = derive_public_key(private_key);

    // Sign the message to get R and s
    let (r, s) = sign_message(private_key, message)?;
    witness.signature_r = r;
    witness.signature_s = s;

    // Compute challenge scalar h = SHA-512(R || A || M) mod L
    witness.hash_h = compute_challenge_scalar(&witness.signature_r, &witness.public_key_a, message);

    // Decompose scalars into 4-bit windows for scalar multiplication
    decompose_scalar_windows(&witness.signature_s, &mut witness.s_windows);
    decompose_scalar_windows(&witness.hash_h, &mut witness.h_windows);

    Ok(())
}

/// Decompose a scalar into 4-bit windows for windowed scalar multiplication
fn decompose_scalar_windows(scalar: &[u8; 32], windows: &mut Vec<u8>) {
    windows.clear();

    // Each byte contains two 4-bit windows
    for byte in scalar.iter() {
        windows.push(byte & 0x0F); // Low nibble
        windows.push((byte >> 4) & 0x0F); // High nibble
    }
}

/// Convert ed25519-dalek point to our ExtendedPoint representation
pub fn dalek_to_extended_point(
    compressed: &[u8; 32],
) -> Result<crate::crypto::edwards_arithmetic::ExtendedPoint> {
    // Use curve25519-dalek to decompress the point
    let compressed_point = curve25519_dalek::edwards::CompressedEdwardsY(*compressed);
    let _point = compressed_point
        .decompress()
        .ok_or_else(|| Error::InvalidInput("Failed to decompress point".into()))?;

    // Convert to our ExtendedPoint representation
    // Note: This requires converting between field representations
    // For now, return a placeholder - will be properly implemented
    // when we fully integrate the library

    Ok(crate::crypto::edwards_arithmetic::ExtendedPoint {
        x: [0u64; 16],
        y: [0u64; 16],
        z: [1u64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        t: [0u64; 16],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let private_key = [1u8; 32];
        let message = b"test message";

        // Derive public key
        let public_key = derive_public_key(&private_key);

        // Sign message
        let (r, s) = sign_message(&private_key, message).unwrap();

        // Verify signature
        let valid = verify_signature(&public_key, message, &r, &s).unwrap();
        assert!(valid);

        // Invalid signature should fail
        let mut bad_r = r;
        bad_r[0] ^= 1;
        let invalid = verify_signature(&public_key, message, &bad_r, &s).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_challenge_scalar_computation() {
        let r = [1u8; 32];
        let a = [2u8; 32];
        let m = b"message";

        let h = compute_challenge_scalar(&r, &a, m);

        // Should be deterministic
        let h2 = compute_challenge_scalar(&r, &a, m);
        assert_eq!(h, h2);

        // Different inputs should give different results
        let h3 = compute_challenge_scalar(&r, &a, b"different");
        assert_ne!(h, h3);
    }

    #[test]
    fn test_witness_augmentation() {
        let mut witness = PrivateInputs::default();
        let message = b"test message for signing";
        let private_key = [42u8; 32];

        augment_witness_with_eddsa(&mut witness, &private_key, message).unwrap();

        // Should have populated all EdDSA fields
        assert_ne!(witness.public_key_a, [0u8; 32]);
        assert_ne!(witness.signature_r, [0u8; 32]);
        assert_ne!(witness.signature_s, [0u8; 32]);
        assert_ne!(witness.hash_h, [0u8; 32]);
        assert_eq!(witness.s_windows.len(), 64); // 32 bytes * 2 windows per byte
        assert_eq!(witness.h_windows.len(), 64);
    }
}
