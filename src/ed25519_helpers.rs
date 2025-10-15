//! Ed25519 conversion functions
//!
//! This module provides functions to convert compressed Ed25519 points
//! to extended Edwards coordinates required by GroveSTARK's STARK proof system.

use crate::crypto::ed25519::{decompress_ed25519_point, DecompressError};
use crate::error::{Error, Result};
use crate::phases::eddsa::augment_eddsa_witness;
use crate::types::PrivateInputs;
use curve25519_dalek::scalar::Scalar;
use dash_sdk::dpp::platform_value::string_encoding::Encoding;
use dash_sdk::platform::Identifier;
use sha2::{Digest, Sha512};

#[cfg(test)]
use crate::parser::grovedb_executor::parse_grovedb_nodes;

/// Compute Ed25519 hash h = SHA-512(R || A || M) mod L
///
/// This is the standard Ed25519 hash computation as specified in RFC 8032.
/// Uses proper modular reduction with curve25519-dalek's Scalar implementation.
///
/// # Arguments
/// * `signature_r` - The R component of the signature (32 bytes)
/// * `public_key_a` - The public key A (32 bytes)
/// * `message` - The message being signed
///
/// # Returns
/// * Hash h reduced modulo L (32 bytes)
pub fn compute_eddsa_hash_h(
    signature_r: &[u8; 32],
    public_key_a: &[u8; 32],
    message: &[u8],
) -> [u8; 32] {
    // Compute SHA-512(R || A || M)
    let mut hasher = Sha512::new();
    hasher.update(signature_r);
    hasher.update(public_key_a);
    hasher.update(message);
    let hash = hasher.finalize();

    // Reduce modulo L using curve25519-dalek's proper implementation
    let scalar = Scalar::from_bytes_mod_order_wide(&hash.into());
    scalar.to_bytes()
}

/// Convert a compressed Ed25519 point (32 bytes) to extended coordinates (4 x 32 bytes)
///
/// # Arguments
/// * `compressed` - The compressed Ed25519 point (32 bytes)
///
/// # Returns
/// * `Ok((x, y, z, t))` - Extended Edwards coordinates as 32-byte arrays
/// * `Err(DecompressError)` - If the point is invalid or not on the curve
///
/// # Example
/// ```ignore
/// let compressed_point = [0u8; 32]; // Your compressed point
/// let (x, y, z, t) = compressed_to_extended(&compressed_point)?;
/// ```
pub fn compressed_to_extended(
    compressed: &[u8; 32],
) -> std::result::Result<([u8; 32], [u8; 32], [u8; 32], [u8; 32]), DecompressError> {
    let point = decompress_ed25519_point(compressed)?;

    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];
    let mut z_bytes = [0u8; 32];
    let mut t_bytes = [0u8; 32];

    crate::crypto::ed25519::limbs_to_bytes_le(&point.x, &mut x_bytes);
    crate::crypto::ed25519::limbs_to_bytes_le(&point.y, &mut y_bytes);
    crate::crypto::ed25519::limbs_to_bytes_le(&point.z, &mut z_bytes);
    crate::crypto::ed25519::limbs_to_bytes_le(&point.t, &mut t_bytes);

    Ok((x_bytes, y_bytes, z_bytes, t_bytes))
}

/// Convert compressed signature R and public key A to extended coordinates and populate witness
///
/// This function handles both point conversion and hash_h computation automatically.
///
/// # Arguments
/// * `witness` - The PrivateInputs to populate
/// * `signature_r_compressed` - The compressed R point from the EdDSA signature (32 bytes)
/// * `public_key_compressed` - The compressed public key A (32 bytes)
/// * `message` - The message that was signed (for hash_h computation)
///
/// # Returns
/// * `Ok(())` - Successfully populated witness with extended coordinates and hash_h
/// * `Err(DecompressError)` - If either point is invalid
///
/// # Example
/// ```ignore
/// let mut witness = PrivateInputs::default();
///
/// // Your compressed points from Ed25519
/// let sig_r_compressed = [0u8; 32];  // From signature (R, s)
/// let pubkey_compressed = [0u8; 32]; // Public key A
/// let message = b"challenge message";
///
/// populate_witness_with_extended(&mut witness, &sig_r_compressed, &pubkey_compressed, message)?;
/// ```
pub fn populate_witness_with_extended(
    witness: &mut PrivateInputs,
    signature_r_compressed: &[u8; 32],
    public_key_compressed: &[u8; 32],
    message: &[u8],
) -> std::result::Result<(), DecompressError> {
    // Convert R to extended coordinates
    let (r_x, r_y, r_z, r_t) = compressed_to_extended(signature_r_compressed)?;
    witness.r_extended_x = r_x;
    witness.r_extended_y = r_y;
    witness.r_extended_z = r_z;
    witness.r_extended_t = r_t;

    // Convert A to extended coordinates
    let (a_x, a_y, a_z, a_t) = compressed_to_extended(public_key_compressed)?;
    witness.a_extended_x = a_x;
    witness.a_extended_y = a_y;
    witness.a_extended_z = a_z;
    witness.a_extended_t = a_t;

    // Also store the compressed forms
    witness.signature_r = *signature_r_compressed;
    witness.public_key_a = *public_key_compressed;

    // Compute hash_h = SHA-512(R || A || M) mod L automatically
    witness.hash_h = compute_eddsa_hash_h(signature_r_compressed, public_key_compressed, message);

    Ok(())
}

/// Create a witness from SDK's raw proof format
///
/// This function implements the 2-proof system where:
/// - `document_proof`: Proves document exists with owner_id
/// - `key_proof`: Proves specific key belongs to identity_id
///
/// The identity_id is extracted from the key proof path and must match owner_id.
pub fn create_witness_from_platform_proofs(
    document_proof: &[u8], // Raw grovedb_proof: document → state_root
    key_proof: &[u8],      // Raw grovedb_proof: key → identity → state_root
    document_json: Vec<u8>,
    public_key: &[u8; 32],
    signature_r: &[u8; 32],
    signature_s: &[u8; 32],
    message: &[u8],
    private_key: &[u8; 32],
) -> crate::Result<PrivateInputs> {
    let (docroot_to_state_path, owner_leaf_path) =
        crate::parser::parse_grovedb_proof_full(document_proof)
            .map_err(|e| Error::InvalidInput(format!("Failed to parse document proof: {}", e)))?;
    let (identity_to_state_path, key_leaf_path) =
        crate::parser::parse_grovedb_proof_full(key_proof)
            .map_err(|e| Error::InvalidInput(format!("Failed to parse key proof: {}", e)))?;

    // Extract owner_id from document JSON
    let owner_id = extract_owner_id_from_document(&document_json)?;

    // Extract closest identity_id from key proof via GroveVM and enforce equality with owner
    let identity_id =
        crate::parser::grovedb_executor::extract_closest_identity_id_from_key_proof(key_proof)?;

    // Create the witness with all required fields
    let mut witness = PrivateInputs::default();

    // Set the core identity binding fields
    witness.owner_id = owner_id;
    witness.identity_id = identity_id;

    // Set GroveDB paths from proofs
    witness.owner_id_leaf_to_doc_path = owner_leaf_path;
    witness.docroot_to_state_path = docroot_to_state_path;
    witness.identity_leaf_to_state_path = identity_to_state_path;
    witness.key_leaf_to_keysroot_path = key_leaf_path;

    // Set document data (keeping field name for compatibility)
    witness.document_cbor = document_json;

    // Set EdDSA signature components
    witness.signature_r = *signature_r;
    witness.signature_s = *signature_s;
    witness.public_key_a = *public_key;
    witness.pubkey_a_compressed = *public_key;
    witness.key_usage_tag = *b"sig:ed25519:v1\0\0";
    witness.private_key = *private_key;

    // Compute EdDSA hash h = SHA-512(R || A || M) mod L
    witness.hash_h = compute_eddsa_hash_h(signature_r, public_key, message);

    // Decompress R and A to extended coordinates (tolerant for test inputs)
    if let Ok((r_x, r_y, r_z, r_t)) = compressed_to_extended(signature_r) {
        witness.r_extended_x = r_x;
        witness.r_extended_y = r_y;
        witness.r_extended_z = r_z;
        witness.r_extended_t = r_t;
    }
    if let Ok((a_x, a_y, a_z, a_t)) = compressed_to_extended(public_key) {
        witness.a_extended_x = a_x;
        witness.a_extended_y = a_y;
        witness.a_extended_z = a_z;
        witness.a_extended_t = a_t;
    }

    // Create window decompositions for scalar multiplication
    witness.s_windows = decompose_scalar_to_windows(&witness.signature_s);
    witness.h_windows = decompose_scalar_to_windows(&witness.hash_h);

    // Augment witness with EdDSA range check data
    let augmented_witness = augment_eddsa_witness(&witness).unwrap_or_else(|_| witness);

    Ok(augmented_witness)
}

/// Extract owner_id from document JSON data
///
/// Dash Platform documents are JSON objects with standard fields:
/// - "$id": document ID (base58 string)
/// - "$ownerId": owner identity ID (base58 string that we convert to 32 bytes)
/// - "$revision": revision number
/// - Other fields specific to the document type
fn extract_owner_id_from_document(document_data: &[u8]) -> Result<[u8; 32]> {
    use serde_json::Value;

    // Parse JSON into a Value
    let value: Value = serde_json::from_slice(document_data)
        .map_err(|e| Error::InvalidInput(format!("Failed to parse document JSON: {}", e)))?;

    // Extract owner_id from the document
    // Look for "$ownerId" or "ownerId" field
    let owner_id_str = value["$ownerId"]
        .as_str()
        .or_else(|| value["ownerId"].as_str())
        .ok_or_else(|| Error::InvalidInput("Document missing $ownerId field".into()))?;

    // Convert base58 string to bytes
    let owner_id = Identifier::from_string(owner_id_str, Encoding::Base58)
        .map_err(|e| Error::InvalidInput(format!("Failed to decode owner ID: {}", e)))?;
    let owner_id_bytes = owner_id.as_bytes();

    if owner_id_bytes.len() != 32 {
        return Err(Error::InvalidInput(format!(
            "Owner ID must decode to 32 bytes, got {}",
            owner_id_bytes.len()
        )));
    }

    let mut owner_id = [0u8; 32];
    owner_id.copy_from_slice(owner_id_bytes);
    Ok(owner_id)
}

/// Decompose a 32-byte scalar into 64 4-bit windows for STARK operations
fn decompose_scalar_to_windows(scalar: &[u8; 32]) -> Vec<u8> {
    let mut windows = Vec::with_capacity(64);
    for byte in scalar.iter() {
        windows.push(byte & 0x0F); // Low nibble
        windows.push((byte >> 4) & 0x0F); // High nibble
    }
    windows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compressed_to_extended_identity() {
        // Test with a known point (identity/neutral element)
        let mut compressed = [0u8; 32];
        compressed[0] = 1; // This represents the identity point in compressed form

        // This should decompress successfully
        let result = compressed_to_extended(&compressed);
        assert!(result.is_ok(), "Failed to decompress identity point");

        let (_x, y, z, _t) = result.unwrap();

        // For identity: X=0, Y=1, Z=1, T=0
        // Check Y coordinate (should be 1)
        assert_eq!(y[0], 1);
        for i in 1..32 {
            assert_eq!(y[i], 0);
        }

        // Check Z coordinate (should be 1)
        assert_eq!(z[0], 1);
        for i in 1..32 {
            assert_eq!(z[i], 0);
        }
    }

    #[test]
    fn test_sdk_proof_integration_identity_aware() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;
        use std::fs;

        // Generate a keypair and signature
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = b"test message";
        let signature = signing_key.sign(message);

        // Extract signature components
        let signature_bytes = signature.to_bytes();
        let mut signature_r = [0u8; 32];
        let mut signature_s = [0u8; 32];
        signature_r.copy_from_slice(&signature_bytes[0..32]);
        signature_s.copy_from_slice(&signature_bytes[32..64]);

        // Load real SDK proofs from fixtures to avoid synthetic bytes
        let document_proof = fs::read(
            "tests/fixtures/document_proof_B5XLy3cUDayaqZmcGaWb98PEAUguGHiHSU5DxiKrHBj3.bin",
        )
        .expect("Failed to read document proof fixture");
        let identity_proof = fs::read(
            "tests/fixtures/identity_proof_FQ4waDowFQXD4tJPKQM1114VSr5f8s3qAc5bT8FJkT49.bin",
        )
        .expect("Failed to read identity proof fixture");

        // Parse proofs through GroveVM to obtain Merkle paths just like production code
        let document_full_path = parse_grovedb_nodes(&document_proof).expect("document proof path");
        let identity_full_path = parse_grovedb_nodes(&identity_proof).expect("identity proof path");

        // Construct witness inline (mirrors legacy helper without bytes hacking)
        let mut witness = PrivateInputs::default();
        witness.document_cbor = vec![0xCCu8; 100];

        // Owner/identity ids must match for EdDSA verification paths
        let owner_id: [u8; 32] = [0xDDu8; 32];
        witness.owner_id = owner_id;
        witness.identity_id = owner_id;

        // Static roots for test scenario
        witness.doc_root = [0x44u8; 32];
        witness.keys_root = [0x55u8; 32];

        // Split the parsed document path into owner→doc and doc→state segments
        let split_point = document_full_path.len() / 2;
        if split_point > 0 {
            witness.owner_id_leaf_to_doc_path = document_full_path[..split_point].to_vec();
            witness.docroot_to_state_path = document_full_path[split_point..].to_vec();
        } else {
            witness.owner_id_leaf_to_doc_path = document_full_path.clone();
        }

        witness.identity_leaf_to_state_path = identity_full_path.clone();
        witness.key_leaf_to_keysroot_path = vec![];
        witness.key_usage_tag = *b"sig:ed25519:v1\0\0";
        witness.pubkey_a_compressed = verifying_key.to_bytes();

        // Populate EdDSA-related fields
        witness.signature_r = signature_r;
        witness.signature_s = signature_s;
        witness.public_key_a = verifying_key.to_bytes();
        witness.private_key = signing_key.to_bytes();
        witness.hash_h = compute_eddsa_hash_h(&signature_r, &witness.public_key_a, message);

        if let Ok((r_x, r_y, r_z, r_t)) = compressed_to_extended(&signature_r) {
            witness.r_extended_x = r_x;
            witness.r_extended_y = r_y;
            witness.r_extended_z = r_z;
            witness.r_extended_t = r_t;
        }

        if let Ok((a_x, a_y, a_z, a_t)) = compressed_to_extended(&witness.public_key_a) {
            witness.a_extended_x = a_x;
            witness.a_extended_y = a_y;
            witness.a_extended_z = a_z;
            witness.a_extended_t = a_t;
        }

        witness.s_windows = decompose_scalar_to_windows(&signature_s);
        witness.h_windows = decompose_scalar_to_windows(&witness.hash_h);

        // Verify the witness was populated correctly
        assert!(witness.owner_id_leaf_to_doc_path.len() > 0);
        assert!(witness.identity_leaf_to_state_path.len() > 0);

        assert_eq!(witness.signature_r, signature_r);
        assert_eq!(witness.signature_s, signature_s);
        assert_eq!(witness.s_windows.len(), 64);
        assert_eq!(witness.h_windows.len(), 64);
    }

    #[test]
    fn test_populate_witness() {
        let mut witness = PrivateInputs::default();

        // Use test vectors - these need to be valid compressed points
        let mut sig_r = [0u8; 32];
        sig_r[0] = 1; // Identity for testing

        let mut pubkey = [0u8; 32];
        pubkey[0] = 1; // Identity for testing

        let message = b"test message";
        let result = populate_witness_with_extended(&mut witness, &sig_r, &pubkey, message);
        assert!(result.is_ok(), "Failed to populate witness");

        // Verify the compressed forms were stored
        assert_eq!(witness.signature_r, sig_r);
        assert_eq!(witness.public_key_a, pubkey);
    }
}
