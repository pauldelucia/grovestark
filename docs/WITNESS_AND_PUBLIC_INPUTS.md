# Witness & Public Inputs

This document describes the data model (`src/types.rs`) and how it binds into the circuit.

## PublicInputs

- `state_root: [u8; 32]`: binds to a specific Dash Platform block/epoch state root
- `contract_id: [u8; 32]`: binds to a specific data contract
- `message_hash: [u8; 32]`: 32-byte challenge used by Ed25519 verification
- `timestamp: u64`: accepted by the API (reserved, not enforced in-circuit)

These are committed inside the proof and validated by boundary assertions and constraints.

## PrivateInputs (Witness)

Document side (hidden):
- `doc_root: [u8; 32]`: document Merkle root
- `owner_id: [u8; 32]`: extracted from document; must equal identity ID
- `owner_id_leaf_to_doc_path: Vec<MerkleNode>`: Merkle path from owner leaf to `doc_root`
- `docroot_to_state_path: Vec<MerkleNode>`: Merkle path from `doc_root` to `state_root`

Identity side (hidden):
- `identity_id: [u8; 32]`: must equal `owner_id`
- `keys_root: [u8; 32]`: root of identity’s key-set Merkle tree
- `identity_leaf_to_state_path: Vec<MerkleNode>`: path from identity leaf to `state_root`

Key membership:
- `key_usage_tag: [u8; 16]`: usage/type tag for the key (e.g., `sig:ed25519:v1\0`)
- `pubkey_a_compressed: [u8; 32]`: Ed25519 compressed public key
- `key_leaf_to_keysroot_path: Vec<MerkleNode>`: path from key leaf to `keys_root`

EdDSA artifacts:
- `signature_r: [u8; 32]`, `signature_s: [u8; 32]`
- `public_key_a: [u8; 32]` (alias)
- `hash_h: [u8; 32]`: `SHA-512(R||A||M) mod L` (can be derived by helpers)
- `s_windows`, `h_windows`: 64 4-bit windows for scalar mult

Extended coordinates and intermediates:
- `r_extended_*`, `a_extended_*`: extended Edwards coordinates for `R` and `A`
- `intermediate_point_*`: intermediate points for scalar multiplication consistency checks

Integration helpers:
- `grovedb_proof: Vec<u8>`: raw GroveDB layered proof
- `document_cbor: Vec<u8>`: document bytes for public output commitment

## Validation

- `validate_witness` enforces non-empty critical fields (document, keys, signature components)
- `validate_identity_witness` enforces `owner_id == identity_id` and presence of all Merkle paths (can be relaxed in tests via `GS_RELAX_ID_VALIDATION`)
- `validate_and_lock_public_inputs` applies format checks and computes a binding commitment for `PublicInputs`

## Building Witnesses

Helpers in `src/ed25519_helpers.rs` provide convenient constructors:
- `create_witness_from_platform_proofs(...)`: from Platform proofs, document JSON/CBOR, `(R,S)`, `A`, and `message` bytes
- `create_witness_with_conversion(...)`: handles point decompression and extended coordinate population
- `populate_witness_with_extended(...)`: populate extended coordinate fields if only compressed points are available
- `compressed_to_extended(...)`: convert compressed Ed25519 points to extended limbs

The circuit expects `message_hash` as the 32-byte challenge. Construct it from a canonical application-domain message and pass it via `PublicInputs`.
