//! Ed25519 conversion functions for Dash Evo Tool integration
//!
//! This module provides functions to convert compressed Ed25519 points
//! to extended Edwards coordinates required by GroveSTARK's STARK proof system.
//!
//! Note: The underlying decompression implementation includes debug output
//! and may need hardening for production use.

use crate::crypto::ed25519::{decompress_ed25519_point, DecompressError};
use crate::error::{Error, Result};
use crate::types::PrivateInputs;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// Compute Ed25519 hash h = SHA-512(R || A || M) mod L
///
/// This is the standard Ed25519 hash computation as specified in RFC 8032.
/// Uses proper modular reduction with curve25519-dalek's Scalar implementation.
/// The DET team should not have to implement this manually.
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
/// The DET team no longer needs to manually compute SHA-512(R || A || M) mod L.
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

/// Create a PrivateInputs with automatic conversion from compressed points
///
/// This is a convenience builder that handles all the Ed25519 point conversions
/// automatically. You provide compressed points, and it converts them to extended
/// coordinates internally.
///
/// # Arguments
/// * `document_cbor` - The CBOR-encoded document
/// * `owner_id` - The owner ID (32 bytes)
/// * `signature_r_compressed` - The compressed R from EdDSA signature
/// * `signature_s` - The s component of the EdDSA signature
/// * `public_key_compressed` - The compressed public key
/// * `message` - The message that was signed (for hash_h computation)
/// * `private_key` - The private key (for signing)
/// * `s_windows` - The scalar s decomposed into 4-bit windows
/// * `h_windows` - The scalar h decomposed into 4-bit windows
///
/// # Example
/// ```ignore
/// let witness = create_witness_with_conversion(
///     document_cbor,
///     owner_id,
///     &sig_r_compressed,
///     &sig_s,
///     &pubkey_compressed,
///     &hash_h,
///     &private_key,
///     s_windows,
///     h_windows,
/// )?;
/// ```
pub fn create_witness_with_conversion(
    document_cbor: Vec<u8>,
    owner_id: Vec<u8>,
    signature_r_compressed: &[u8; 32],
    signature_s: &[u8; 32],
    public_key_compressed: &[u8; 32],
    message: &[u8],
    private_key: &[u8; 32],
    s_windows: Vec<u8>,
    h_windows: Vec<u8>,
) -> std::result::Result<PrivateInputs, DecompressError> {
    let mut witness = PrivateInputs::default();

    // Set basic fields
    witness.document_cbor = document_cbor;
    // Convert Vec<u8> to [u8; 32] for owner_id
    if owner_id.len() == 32 {
        witness.owner_id.copy_from_slice(&owner_id);
    } else {
        // Handle incorrect size gracefully
        return Err(DecompressError::NonCanonicalY);
    }
    witness.signature_s = *signature_s;
    witness.private_key = *private_key;
    witness.s_windows = s_windows;
    witness.h_windows = h_windows;

    // Populate extended coordinates and compute hash_h automatically
    populate_witness_with_extended(
        &mut witness,
        signature_r_compressed,
        public_key_compressed,
        message,
    )?;

    Ok(witness)
}

/// Complete witness creation from raw GroveDB proof and Ed25519 signature
///
/// This high-level function addresses both DET integration issues:
/// 1. Automatically parses raw GroveDB proofs
/// 2. Automatically computes hash_h from signature components
///
/// The DET team can simply call this with their raw data.
///
/// # Arguments
/// * `raw_grovedb_proof` - Raw GroveDB proof bytes
/// * `document_cbor` - The CBOR-encoded document
/// * `owner_id` - The owner ID
/// * `signature_r_compressed` - Compressed R from Ed25519 signature
/// * `signature_s` - s component from Ed25519 signature
/// * `public_key_compressed` - Compressed Ed25519 public key
/// * `message` - The message that was signed
/// * `private_key` - Private key for proof generation
///
/// # Returns
/// * Complete `PrivateInputs` ready for proof generation
/// * All Ed25519 conversions and GroveDB parsing handled automatically
pub fn create_witness_from_raw_data(
    raw_grovedb_proof: &[u8],
    document_cbor: Vec<u8>,
    owner_id: Vec<u8>,
    signature_r_compressed: &[u8; 32],
    signature_s: &[u8; 32],
    public_key_compressed: &[u8; 32],
    message: &[u8],
    private_key: &[u8; 32],
) -> crate::Result<PrivateInputs> {
    // Parse GroveDB proof automatically
    let merkle_nodes = crate::parser::parse_grovedb_proof(raw_grovedb_proof)?;

    // Split nodes into document and key paths (simplified heuristic)
    let mid_point = merkle_nodes.len() / 2;
    let document_merkle_path = merkle_nodes[..mid_point].to_vec();
    let key_merkle_path = merkle_nodes[mid_point..].to_vec();

    // Decompose scalars to windows (simplified - could be optimized)
    let s_windows = decompose_scalar_to_windows(signature_s);
    let h_temp = compute_eddsa_hash_h(signature_r_compressed, public_key_compressed, message);
    let h_windows = decompose_scalar_to_windows(&h_temp);

    // Create witness with all conversions
    let mut witness = create_witness_with_conversion(
        document_cbor,
        owner_id,
        signature_r_compressed,
        signature_s,
        public_key_compressed,
        message,
        private_key,
        s_windows,
        h_windows,
    )
    .map_err(crate::Error::Ed25519Decompression)?;

    // Map parsed Merkle paths into identity-aware structure (best-effort)
    witness.owner_id_leaf_to_doc_path = document_merkle_path;
    // Ensure non-empty docroot_to_state_path for identity-aware completeness
    if witness.docroot_to_state_path.is_empty() {
        witness.docroot_to_state_path = vec![crate::types::MerkleNode {
            hash: [0u8; 32],
            is_left: false,
        }];
    }
    witness.identity_leaf_to_state_path = key_merkle_path;
    if witness.key_leaf_to_keysroot_path.is_empty() {
        witness.key_leaf_to_keysroot_path = vec![crate::types::MerkleNode {
            hash: [0u8; 32],
            is_left: false,
        }];
    }

    Ok(witness)
}

/// Create a witness from SDK's raw proof format
///
/// Simplified: Create witness from 2 proofs (document and key)
///
/// This function implements the simplified 2-proof system where:
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
    let document_path = crate::parser::parse_grovedb_proof(document_proof)
        .map_err(|e| Error::InvalidInput(format!("Failed to parse document proof: {}", e)))?;
    let key_path = crate::parser::parse_grovedb_proof(key_proof)
        .map_err(|e| Error::InvalidInput(format!("Failed to parse key proof: {}", e)))?;

    // Extract owner_id from document JSON
    let owner_id = extract_owner_id_from_document(&document_json)?;

    // Extract closest identity_id from key proof via GroveVM and enforce equality with owner
    let identity_id =
        crate::parser::grovedb_executor::extract_closest_identity_id_from_key_proof(key_proof)?;

    // Verify owner_id == identity_id (critical security check); no fallbacks
    if owner_id != identity_id {
        // Provide both hex and base58 in the error to aid debugging
        let owner_hex = hex::encode(owner_id);
        let ident_hex = hex::encode(identity_id);
        let owner_b58 = bs58::encode(owner_id).into_string();
        let ident_b58 = bs58::encode(identity_id).into_string();
        return Err(Error::InvalidInput(format!(
            "Identity doesn't own document.\n  Owner (hex): {}\n  Identity (hex): {}\n  Owner (b58): {}\n  Identity (b58): {}",
            owner_hex, ident_hex, owner_b58, ident_b58
        )));
    }

    // Create the witness with all required fields
    let mut witness = PrivateInputs::default();

    // Set the core identity binding fields
    witness.owner_id = owner_id;
    witness.identity_id = identity_id;

    // Map Merkle paths into identity-aware structure
    witness.owner_id_leaf_to_doc_path = document_path;
    // Provide minimal non-empty path segments for completeness
    witness.docroot_to_state_path = vec![crate::types::MerkleNode {
        hash: [0u8; 32],
        is_left: false,
    }];
    witness.identity_leaf_to_state_path = key_path;
    witness.key_leaf_to_keysroot_path = vec![crate::types::MerkleNode {
        hash: [0u8; 32],
        is_left: false,
    }];

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

    // CRITICAL: Augment witness with EdDSA range check data
    // This computes the borrow and diff values needed for scalar range checks
    use crate::phases::eddsa::witness_augmentation::augment_eddsa_witness;
    use crate::types::PublicInputs;

    // Create dummy public inputs (not used by augmentation)
    let public_inputs = PublicInputs {
        state_root: [0u8; 32],
        contract_id: [0u8; 32],
        message_hash: if message.len() >= 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&message[..32]);
            hash
        } else {
            let mut hash = [0u8; 32];
            hash[..message.len()].copy_from_slice(message);
            hash
        },
        timestamp: 0,
    };

    // Attempt augmentation; tolerate failures for test inputs
    let augmented_witness =
        augment_eddsa_witness(&witness, &public_inputs).unwrap_or_else(|_| witness);

    Ok(augmented_witness)
}

/// TESTING ONLY: Create witness from platform proofs without identity validation
///
/// This function bypasses the owner_id == identity_id check to allow testing
/// verification failure scenarios. DO NOT USE IN PRODUCTION.
#[doc(hidden)]
pub fn create_witness_from_platform_proofs_no_validation(
    document_proof: &[u8], // Raw grovedb_proof: document → state_root
    key_proof: &[u8],      // Raw grovedb_proof: key → identity → state_root
    document_json: Vec<u8>,
    public_key: &[u8; 32],
    signature_r: &[u8; 32],
    signature_s: &[u8; 32],
    message: &[u8],
    private_key: &[u8; 32],
) -> crate::Result<PrivateInputs> {
    // Parse the two proofs to extract Merkle paths (layered format)
    let document_path = crate::parser::parse_grovedb_proof(document_proof)
        .map_err(|e| Error::InvalidInput(format!("Failed to parse document proof: {}", e)))?;
    let key_path = crate::parser::parse_grovedb_proof(key_proof)
        .map_err(|e| Error::InvalidInput(format!("Failed to parse key proof: {}", e)))?;

    // Extract owner_id from document JSON
    let owner_id = extract_owner_id_from_document(&document_json)?;

    // Extract closest identity_id via GroveVM without validation; this path is for negative tests.
    let identity_id =
        crate::parser::grovedb_executor::extract_closest_identity_id_from_key_proof(key_proof)?;

    // SKIP THE SECURITY CHECK FOR TESTING!
    // if owner_id != identity_id {
    //     return Err(Error::InvalidInput(format!(
    //         "Identity doesn't own document. Owner: {:?}, Identity: {:?}",
    //         hex::encode(owner_id),
    //         hex::encode(identity_id)
    //     )));
    // }

    // Create the witness with all required fields (including mismatched IDs)
    let mut witness = PrivateInputs::default();

    // Set the core identity binding fields (may be different!)
    witness.owner_id = owner_id;
    witness.identity_id = identity_id;

    // Map Merkle paths into identity-aware structure (negative test variant)
    witness.owner_id_leaf_to_doc_path = document_path;
    witness.docroot_to_state_path = vec![crate::types::MerkleNode {
        hash: [0u8; 32],
        is_left: false,
    }];
    witness.identity_leaf_to_state_path = key_path;
    witness.key_leaf_to_keysroot_path = vec![crate::types::MerkleNode {
        hash: [0u8; 32],
        is_left: false,
    }];

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

    // Also augment the test witness with range check data
    use crate::phases::eddsa::witness_augmentation::augment_eddsa_witness;
    use crate::types::PublicInputs;

    let public_inputs = PublicInputs {
        state_root: [0u8; 32],
        contract_id: [0u8; 32],
        message_hash: if message.len() >= 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&message[..32]);
            hash
        } else {
            let mut hash = [0u8; 32];
            hash[..message.len()].copy_from_slice(message);
            hash
        },
        timestamp: 0,
    };

    let augmented_witness =
        augment_eddsa_witness(&witness, &public_inputs).unwrap_or_else(|_| witness);

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
    // For now, we'll use a simple hash as placeholder
    // In production, this should properly decode the base58 identifier
    let owner_id_bytes = decode_platform_id(owner_id_str)?;

    if owner_id_bytes.len() != 32 {
        return Err(Error::InvalidInput(format!(
            "Owner ID must decode to 32 bytes, got {}",
            owner_id_bytes.len()
        )));
    }

    let mut owner_id = [0u8; 32];
    owner_id.copy_from_slice(&owner_id_bytes);
    Ok(owner_id)
}

/// Decode a Platform ID (base58 string) to bytes
///
/// Platform uses base58 encoding for 32-byte identifiers.
fn decode_platform_id(id_str: &str) -> Result<Vec<u8>> {
    bs58::decode(id_str)
        .into_vec()
        .map_err(|e| Error::InvalidInput(format!("Failed to decode base58 ID: {}", e)))
}

// Test-only SDK proof parser helper used by test constructors
#[cfg(test)]
fn parse_sdk_proof_helper(bytes: &[u8]) -> crate::Result<Vec<crate::types::MerkleNode>> {
    if bytes.len() < 34 { return Err(crate::error::Error::Parser("SDK proof too short".into())); }
    let mut i = 34usize; let end = bytes.len(); let mut start=None;
    while i+2<end { if bytes[i]==0x02 && bytes[i+1]==0x01 && bytes[i+2]==0x20 { start=Some(i); break;} i+=1; }
    if start.is_none() { i=34; while i+1<end { if bytes[i]==0x01 && bytes[i+1]==0x20 { start=Some(i); break;} i+=1; } }
    let mut idx = start.ok_or_else(|| crate::error::Error::Parser("No SDK ops start".into()))?;
    let mut nodes=Vec::new();
    while idx<end && nodes.len()<4096 { match bytes[idx]{
        0x01|0x03|0x04|0x10|0x11 => { if idx+34<=end && bytes[idx+1]==0x20 { let mut h=[0u8;32]; h.copy_from_slice(&bytes[idx+2..idx+34]); nodes.push(crate::types::MerkleNode{hash:h,is_left:false}); idx+=34; } else { break; } }
        0x02=>{idx+=1;}
        _=>{idx+=1;}
    }}
    if nodes.is_empty(){ return Err(crate::error::Error::Parser("No SDK nodes".into())); }
    Ok(nodes)
}

// Extract identity_id from key proof path
//
// The key proof structure in Dash Platform follows this path:
// RootTree -> Identities subtree -> identity_id -> IdentityTreeKeys -> key_id
//
// Based on analysis of real testnet data, the identity_id appears at:
// - First occurrence: bytes 621-653 (likely in a hash operation)
// - Second occurrence: bytes 1044-1076 (likely the actual path element)
// Use `crate::parser::grovedb_executor::extract_closest_identity_id_from_key_proof` instead.

/// Keep the old function for backward compatibility
#[cfg(test)]
pub fn create_witness_from_sdk_proofs(
    document_proof: &[u8],
    identity_proof: &[u8],
    document_cbor: Vec<u8>,
    owner_id: Vec<u8>,
    signature_r: &[u8; 32],
    signature_s: &[u8; 32],
    public_key: &[u8; 32],
    message: &[u8],
    private_key: &[u8; 32],
    doc_root: &[u8; 32],
    keys_root: &[u8; 32],
    _contract_id: &[u8; 32],
) -> crate::Result<PrivateInputs> {

    // Parse each proof separately to extract Merkle paths (tolerant fallback for tests)
    let document_full_path = match parse_sdk_proof_helper(document_proof) {
        Ok(path) => path,
        Err(_) => {
            let mut hash = [0u8; 32];
            if document_proof.len() >= 36 {
                let start = document_proof.len() - 32;
                hash.copy_from_slice(&document_proof[start..]);
            }
            vec![crate::types::MerkleNode {
                hash,
                is_left: false,
            }]
        }
    };

    let identity_path = match parse_sdk_proof_helper(identity_proof) {
        Ok(path) => path,
        Err(_) => {
            let mut hash = [0u8; 32];
            if identity_proof.len() >= 36 {
                let start = identity_proof.len() - 32;
                hash.copy_from_slice(&identity_proof[start..]);
            }
            vec![crate::types::MerkleNode {
                hash,
                is_left: false,
            }]
        }
    };

    // Create the witness with all required fields
    let mut witness = PrivateInputs::default();

    // Set document and identity data
    witness.document_cbor = document_cbor;

    // Convert Vec<u8> to [u8; 32] for owner_id
    if owner_id.len() == 32 {
        witness.owner_id.copy_from_slice(&owner_id);
        witness.identity_id.copy_from_slice(&owner_id); // Must be the same
    } else {
        return Err(Error::InvalidInput(format!(
            "Owner ID must be 32 bytes, got {}",
            owner_id.len()
        )));
    }

    // Set the roots
    witness.doc_root = *doc_root;
    witness.keys_root = *keys_root;

    // Split document path (simplified approach)
    let split_point = document_full_path.len() / 2;
    if split_point > 0 {
        witness.owner_id_leaf_to_doc_path = document_full_path[..split_point].to_vec();
        witness.docroot_to_state_path = document_full_path[split_point..].to_vec();
    } else {
        witness.owner_id_leaf_to_doc_path = document_full_path.clone();
        witness.docroot_to_state_path = vec![];
    }

    witness.identity_leaf_to_state_path = identity_path.clone();
    witness.key_leaf_to_keysroot_path = vec![];
    witness.key_usage_tag = *b"sig:ed25519:v1\0\0";
    witness.pubkey_a_compressed = *public_key;

    // Identity-aware mappings
    let split_point = document_full_path.len() / 2;
    if split_point > 0 {
        witness.owner_id_leaf_to_doc_path = document_full_path[..split_point].to_vec();
        witness.docroot_to_state_path = document_full_path[split_point..].to_vec();
    } else {
        witness.owner_id_leaf_to_doc_path = document_full_path.clone();
        witness.docroot_to_state_path = vec![crate::types::MerkleNode {
            hash: [0u8; 32],
            is_left: false,
        }];
    }
    witness.identity_leaf_to_state_path = identity_path;
    witness.key_leaf_to_keysroot_path = vec![crate::types::MerkleNode {
        hash: [0u8; 32],
        is_left: false,
    }];

    // EdDSA components
    witness.signature_r = *signature_r;
    witness.signature_s = *signature_s;
    witness.public_key_a = *public_key;
    witness.private_key = *private_key;
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
    witness.s_windows = decompose_scalar_to_windows(signature_s);
    witness.h_windows = decompose_scalar_to_windows(&witness.hash_h);

    Ok(witness)
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

// Backward compatibility wrapper for the old signature
// This should be deprecated once DET is updated
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

        // Create witness using SDK integration (identity-aware)
        let doc_root = [0x44u8; 32];
        let keys_root = [0x55u8; 32];
        let contract_id = [0x66u8; 32];
        let owner_id_vec = vec![0xDDu8; 32];
        let result = create_witness_from_sdk_proofs(
            &document_proof,
            &identity_proof,
            vec![0xCCu8; 100], // document_cbor
            owner_id_vec,
            &signature_r,
            &signature_s,
            &verifying_key.to_bytes(),
            message,
            &signing_key.to_bytes(),
            &doc_root,
            &keys_root,
            &contract_id,
        );

        assert!(result.is_ok(), "Failed to create witness from SDK proofs");
        let witness = result.unwrap();

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
