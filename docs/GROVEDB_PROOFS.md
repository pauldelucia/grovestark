# GroveDB Proofs Deep Dive

This document explains how layered GroveDB proofs are handled, parsed, and bound to the STARK constraints.

## Inputs & Parsing

- Raw proof bytes are accepted via witness field `grovedb_proof`.
- `src/parser/` provides:
  - `proof_decoder.rs`: decodes raw DET/SDK proof formats into intermediate operations
  - `proof_extractor.rs`: utilities to extract sibling lists and closest identity IDs
  - `grovedb_executor.rs`: executes parsed operations into a Merkle tree state model and yields `MerkleNode` sequences

Key entry points:
- `parse_grovedb_nodes(proof_bytes)` → `Vec<MerkleNode>` for Merkle path windows
- `parse_proof_operations(...)` / `execute_proof(...)` implement a small interpreter to derive state transitions from the proof

## Binding to the Circuit

- Merkle nodes are fed into the witness vectors:
  - `owner_id_leaf_to_doc_path`
  - `docroot_to_state_path`
  - `identity_leaf_to_state_path`
  - `key_leaf_to_keysroot_path`
- Main segment Merkle constraints verify hash recomputation with left/right flags using BLAKE3.
- GroveVM (aux segment) models the stack-machine execution used during parsing/push-tape so that the exact windows used by the main segment are deterministically produced from `grovedb_proof`.

## Document & Identity Binding

- The circuit binds that `owner_id == identity_id` via boundary assertions.
- `doc_root` and `keys_root` are connected to the public `state_root` through separate Merkle paths.
- The key membership path proves that the supplied Ed25519 public key `A` is included under the identity’s key set with the correct `key_usage_tag`.

## Public Commitment

- The prover computes a public `proof_commitment` (see `src/prover/mod.rs`) as a BLAKE3 hash of:
  - `document_cbor || owner_id || state_root`
- This commitment is part of `PublicOutputs` and is verified in the host-side verification logic before delegating to Winterfell’s verification.

