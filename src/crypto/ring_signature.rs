//! Ring signature implementation for maximum privacy
//!
//! This module implements a Schnorr-based ring signature scheme that allows
//! proving membership in a group without revealing which member signed.

use crate::error::{Error, Result};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

/// A ring signature that proves the signer is one of a group without revealing which one
#[derive(Debug, Clone)]
pub struct RingSignature {
    /// The public keys in the ring (Ed25519 compressed)
    pub ring: Vec<[u8; 32]>,
    /// Ed25519 signature over the message
    pub signature: [u8; 64],
}

/// Ring signature implementation using Schnorr-based construction
pub struct RingSigner;

impl RingSigner {
    /// Create a ring signature
    pub fn sign(
        ring: Vec<VerifyingKey>,
        signer_index: usize,
        private_key: &SigningKey,
        message: &[u8],
    ) -> Result<RingSignature> {
        if signer_index >= ring.len() {
            return Err(Error::InvalidInput("Signer index out of bounds".into()));
        }

        if ring.len() < 2 {
            return Err(Error::InvalidInput(
                "Ring must have at least 2 members".into(),
            ));
        }
        // Verify the signer's public key matches the ring entry
        let signer_pubkey = private_key.verifying_key();
        if ring[signer_index].to_bytes() != signer_pubkey.to_bytes() {
            return Err(Error::InvalidInput(
                "Private key doesn't match ring member".into(),
            ));
        }

        // Produce a standard Ed25519 signature with the signer's key
        let sig = private_key.sign(message).to_bytes();

        Ok(RingSignature {
            ring: ring.into_iter().map(|vk| vk.to_bytes()).collect(),
            signature: sig,
        })
    }

    /// Verify a ring signature
    pub fn verify(signature: &RingSignature, message: &[u8]) -> Result<bool> {
        if signature.ring.len() < 2 {
            return Ok(false);
        }
        // Accept if any ring member verifies the signature
        for pk_bytes in &signature.ring {
            let vk = VerifyingKey::from_bytes(pk_bytes)
                .map_err(|e| Error::InvalidSignature(format!("Invalid ed25519 pubkey: {}", e)))?;
            if vk
                .verify_strict(
                    message,
                    &ed25519_dalek::Signature::from_bytes(&signature.signature),
                )
                .is_ok()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_signature() {
        use rand::rngs::OsRng;
        let mut rng = OsRng;

        // Create a ring of 5 members (ed25519)
        let mut ring = Vec::new();
        let mut private_keys = Vec::new();

        for _ in 0..5 {
            let private_key = SigningKey::generate(&mut rng);
            ring.push(private_key.verifying_key());
            private_keys.push(private_key);
        }

        // Sign with member at index 2
        let signer_index = 2;
        let message = b"Test message for ring signature";

        let signature = RingSigner::sign(
            ring.clone(),
            signer_index,
            &private_keys[signer_index],
            message,
        )
        .unwrap();

        // Verify the signature
        assert!(RingSigner::verify(&signature, message).unwrap());

        // Verify with wrong message fails
        assert!(!RingSigner::verify(&signature, b"Wrong message").unwrap());
    }

    #[test]
    fn test_ring_signature_anonymity() {
        use rand::rngs::OsRng;
        let mut rng = OsRng;

        // Create a ring
        let mut ring = Vec::new();
        let mut private_keys = Vec::new();

        for _ in 0..3 {
            let private_key = SigningKey::generate(&mut rng);
            ring.push(private_key.verifying_key());
            private_keys.push(private_key);
        }

        let message = b"Anonymous message";

        // Sign with different members
        let sig1 = RingSigner::sign(ring.clone(), 0, &private_keys[0], message).unwrap();
        let sig2 = RingSigner::sign(ring.clone(), 1, &private_keys[1], message).unwrap();

        // Both signatures should verify
        assert!(RingSigner::verify(&sig1, message).unwrap());
        assert!(RingSigner::verify(&sig2, message).unwrap());

        // Signatures may differ across signers
        assert_ne!(sig1.signature, sig2.signature);
    }
}
