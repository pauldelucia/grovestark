//! Identity-aware commitment functions for zero-knowledge ownership proofs
//!
//! This module implements the commitment functions needed for the identity-binding
//! solution that proves document ownership through identity verification.

use blake3;

/// Domain-separated tag for owner_id leaf commitments
const OWNER_ID_LEAF_TAG: &[u8] = b"doc/owner_id:v1";

/// Domain-separated tag for identity leaf payloads
const IDENTITY_LEAF_TAG: &[u8] = b"id/leaf:v1";

/// Domain-separated tag for key leaf payloads
const KEY_LEAF_TAG: &[u8] = b"id/key:v1";

/// Domain-separated tag for EdDSA message hashing
const EDDSA_MSG_TAG: &[u8] = b"grove/eddsa/msg_hash:v1";

/// Merkle leaf node prefix (0x00)
const MERKLE_LEAF_PREFIX: u8 = 0x00;

/// Merkle inner node prefix (0x01)
const MERKLE_INNER_PREFIX: u8 = 0x01;

/// Compute the owner_id leaf commitment
///
/// This binds the owner_id to a specific contract to ensure document and identity
/// are under the same contract (Pattern B from the spec).
///
/// # Arguments
/// * `contract_id` - The 32-byte contract identifier
/// * `owner_id` - The 32-byte owner identity ID
///
/// # Returns
/// The 32-byte BLAKE3 hash of the tagged payload
pub fn owner_id_leaf(contract_id: &[u8; 32], owner_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(OWNER_ID_LEAF_TAG);
    hasher.update(contract_id);
    hasher.update(owner_id);
    *hasher.finalize().as_bytes()
}

/// Build the identity leaf payload
///
/// This creates the payload that binds an identity to a contract and its key set.
///
/// # Arguments
/// * `contract_id` - The 32-byte contract identifier
/// * `identity_id` - The 32-byte identity identifier
/// * `keys_root` - The 32-byte root of the identity's key set Merkle tree
///
/// # Returns
/// The concatenated payload bytes
pub fn identity_leaf_payload(
    contract_id: &[u8; 32],
    identity_id: &[u8; 32],
    keys_root: &[u8; 32],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(IDENTITY_LEAF_TAG.len() + 96);
    payload.extend_from_slice(IDENTITY_LEAF_TAG);
    payload.extend_from_slice(contract_id);
    payload.extend_from_slice(identity_id);
    payload.extend_from_slice(keys_root);
    payload
}

/// Compute the identity leaf node hash
///
/// # Arguments
/// * `payload` - The identity leaf payload from `identity_leaf_payload()`
///
/// # Returns
/// The 32-byte Merkle leaf node hash
pub fn identity_leaf_node(payload: &[u8]) -> [u8; 32] {
    H_leaf(&blake3::hash(payload).into())
}

/// Build the key leaf payload
///
/// This creates the payload for a key in the identity's key set.
///
/// # Arguments
/// * `key_usage_tag` - The 16-byte usage tag (e.g., "sig:ed25519:v1\0\0")
/// * `pubkey_a_compressed` - The 32-byte Ed25519 compressed public key
///
/// # Returns
/// The concatenated payload bytes
pub fn key_leaf_payload(key_usage_tag: &[u8; 16], pubkey_a_compressed: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(KEY_LEAF_TAG.len() + 48);
    payload.extend_from_slice(KEY_LEAF_TAG);
    payload.extend_from_slice(key_usage_tag);
    payload.extend_from_slice(pubkey_a_compressed);
    payload
}

/// Compute the key leaf node hash
///
/// # Arguments
/// * `payload` - The key leaf payload from `key_leaf_payload()`
///
/// # Returns
/// The 32-byte Merkle leaf node hash
pub fn key_leaf_node(payload: &[u8]) -> [u8; 32] {
    H_leaf(&blake3::hash(payload).into())
}

/// Compute a Merkle leaf node hash
///
/// This applies the leaf domain separation (0x00 prefix) and hashes the payload.
///
/// # Arguments
/// * `payload` - The leaf payload bytes
///
/// # Returns
/// The 32-byte Merkle leaf node hash
#[allow(non_snake_case)]
pub fn H_leaf(payload: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[MERKLE_LEAF_PREFIX]);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

/// Compute a Merkle inner node hash
///
/// This applies the inner node domain separation (0x01 prefix) and hashes
/// the concatenation of left and right children.
///
/// # Arguments
/// * `left` - The 32-byte left child hash
/// * `right` - The 32-byte right child hash
///
/// # Returns
/// The 32-byte Merkle inner node hash
#[allow(non_snake_case)]
pub fn H_inner(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[MERKLE_INNER_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Compute the EdDSA challenge hash with domain separation
///
/// This computes h = SHA-512(R || A || tag || msg_hash) mod L
/// Note: The mod L operation is handled by the EdDSA module.
///
/// # Arguments
/// * `r` - The 32-byte R point (compressed)
/// * `a` - The 32-byte A public key (compressed)
/// * `msg_hash` - The 32-byte message hash
///
/// # Returns
/// The 64-byte SHA-512 hash (caller must reduce mod L)
pub fn eddsa_challenge(r: &[u8; 32], a: &[u8; 32], msg_hash: &[u8; 32]) -> [u8; 64] {
    use sha2::{Digest, Sha512};

    let mut hasher = Sha512::new();
    hasher.update(r);
    hasher.update(a);
    hasher.update(EDDSA_MSG_TAG);
    hasher.update(msg_hash);

    let result = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

/// Get the default key usage tag for Ed25519 signatures
pub fn default_key_usage_tag() -> [u8; 16] {
    *b"sig:ed25519:v1\0\0"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_owner_id_leaf() {
        let contract_id = [1u8; 32];
        let owner_id = [2u8; 32];
        let leaf = owner_id_leaf(&contract_id, &owner_id);

        // Should be deterministic
        let leaf2 = owner_id_leaf(&contract_id, &owner_id);
        assert_eq!(leaf, leaf2);

        // Different inputs should give different outputs
        let different_owner = [3u8; 32];
        let leaf3 = owner_id_leaf(&contract_id, &different_owner);
        assert_ne!(leaf, leaf3);
    }

    #[test]
    fn test_identity_leaf_payload() {
        let contract_id = [1u8; 32];
        let identity_id = [2u8; 32];
        let keys_root = [3u8; 32];

        let payload = identity_leaf_payload(&contract_id, &identity_id, &keys_root);

        // Check length: tag (11) + contract (32) + identity (32) + keys_root (32)
        assert_eq!(payload.len(), IDENTITY_LEAF_TAG.len() + 96);

        // Check structure
        assert_eq!(&payload[..IDENTITY_LEAF_TAG.len()], IDENTITY_LEAF_TAG);
        assert_eq!(
            &payload[IDENTITY_LEAF_TAG.len()..IDENTITY_LEAF_TAG.len() + 32],
            &contract_id
        );
    }

    #[test]
    fn test_key_leaf_payload() {
        let key_usage_tag = default_key_usage_tag();
        let pubkey = [4u8; 32];

        let payload = key_leaf_payload(&key_usage_tag, &pubkey);

        // Check length: tag (10) + usage (16) + pubkey (32)
        assert_eq!(payload.len(), KEY_LEAF_TAG.len() + 48);

        // Check structure
        assert_eq!(&payload[..KEY_LEAF_TAG.len()], KEY_LEAF_TAG);
    }

    #[test]
    fn test_merkle_hashing() {
        let left = [1u8; 32];
        let right = [2u8; 32];

        // Inner nodes should be deterministic
        let inner1 = H_inner(&left, &right);
        let inner2 = H_inner(&left, &right);
        assert_eq!(inner1, inner2);

        // Order matters
        let inner_reversed = H_inner(&right, &left);
        assert_ne!(inner1, inner_reversed);

        // Leaf hashing
        let leaf = H_leaf(&left);
        assert_ne!(leaf, left); // Should be different due to domain separation
    }

    #[test]
    fn test_default_key_usage_tag() {
        let tag = default_key_usage_tag();
        assert_eq!(tag.len(), 16);
        assert_eq!(&tag[..14], b"sig:ed25519:v1");
        assert_eq!(&tag[14..], b"\0\0");
    }
}
