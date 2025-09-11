// Test utilities for generating valid EdDSA signatures

use crate::types::{MerkleNode, PrivateInputs};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;

/// Create a witness with a valid EdDSA signature
pub fn create_valid_eddsa_witness() -> PrivateInputs {
    // Generate a real Ed25519 keypair
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();
    let private_key_bytes = signing_key.to_bytes();

    // Create a message to sign
    let message = b"GroveSTARK test message";

    // Sign the message
    let signature = signing_key.sign(message);
    let signature_bytes = signature.to_bytes();

    // Extract R and s from the signature
    let mut signature_r = [0u8; 32];
    let mut signature_s = [0u8; 32];
    signature_r.copy_from_slice(&signature_bytes[0..32]);
    signature_s.copy_from_slice(&signature_bytes[32..64]);

    // Compute hash_h = SHA-512(R || A || M) mod L
    let hash_h = crate::compute_eddsa_hash_h(&signature_r, &public_key_bytes, message);

    // Create identity-aware witness
    let mut witness = PrivateInputs {
        document_cbor: vec![0x01, 0x02, 0x03],
        // Identity/doc roots and IDs
        owner_id: [0x11; 32],
        identity_id: [0x11; 32],
        doc_root: [0x44; 32],
        keys_root: [0x55; 32],
        // Merkle paths (minimal)
        owner_id_leaf_to_doc_path: vec![MerkleNode {
            hash: [0x22; 32],
            is_left: true,
        }],
        docroot_to_state_path: vec![MerkleNode {
            hash: [0x66; 32],
            is_left: false,
        }],
        identity_leaf_to_state_path: vec![MerkleNode {
            hash: [0x77; 32],
            is_left: true,
        }],
        key_leaf_to_keysroot_path: vec![MerkleNode {
            hash: [0x33; 32],
            is_left: false,
        }],
        // EdDSA
        private_key: private_key_bytes,
        signature_r,
        signature_s,
        public_key_a: public_key_bytes,
        pubkey_a_compressed: public_key_bytes,
        hash_h,
        ..Default::default()
    };

    // Populate extended coordinates
    crate::populate_witness_with_extended(&mut witness, &signature_r, &public_key_bytes, message)
        .expect("Failed to populate extended coordinates");

    witness
}
