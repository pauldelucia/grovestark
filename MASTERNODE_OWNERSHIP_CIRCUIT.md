GroveSTARK Circuit 2 — Masternode Ownership (Owner Control + Operator Eligibility)

Goal
Prove: “I control the masternode OWNER key at a specific Platform state (state_root), and the linked OPERATOR key is present and not disabled,” without revealing which masternode.

Active/Eligible Definition
“Active” here means eligible/able to participate now: the key exists in state and is not disabled. It does not mean “currently selected in a validator set.”

Public Inputs
- state_root (aka app_hash): Platform state commitment for the chosen height/epoch.
- message_hash: 32‑byte challenge hash. The signed challenge must commit to freshness (epoch/height, timestamp, nonce, context). Height itself need not be a separate public input if it’s inside the challenge.

Private Witness
Owner key membership (A):
- GroveDB membership proof for the owner key leaf under Identities/<owner_identity_id>/IdentityKeys/<owner_key_id>, up to state_root.
- Leaf value bytes: serialized IdentityPublicKey for the owner key (as stored by Drive/DPP).
- Owner secp256k1 public key bytes (provided by prover; used to verify signature and HASH160 binding).
- ECDSA signature (r, s) over message_hash.

Operator key membership (B):
- GroveDB membership proof for the operator key leaf under Identities/<operator_identity_id>/IdentityKeys/<bls_key_id>, up to state_root.
- Leaf value bytes: serialized IdentityPublicKey for the operator BLS key (compressed 48‑byte pubkey in data field).

Derived/Checked Values (in‑circuit):
- owner_identity_id = proTxHash (extracted from proof path A segment).
- operator_identity_id (extracted from proof path B segment).
- operator_identity_id must equal SHA256(proTxHash || bls_operator_pubkey_bytes) per DPP.

Core Constraints
Merkle binding (both proofs):
- Recompute leaf hashes from the exact serialized key bytes (byte‑accurate to Drive/Merk) and ascend via sibling hashes/left‑right flags to the same public state_root.

Owner key semantics (ECDSA_HASH160):
- Parse the leaf value as IdentityPublicKey; enforce:
  - key_type == ECDSA_HASH160 (20‑byte data), purpose == OWNER, disabled == 0.
- Compute HASH160(secp256k1_pubkey_bytes) = RIPEMD‑160(SHA‑256(pubkey)) and constrain it equal to the 20‑byte data parsed from the leaf.
- Verify ECDSA(secp256k1) signature (r, s) against message_hash under the supplied pubkey.

Operator key semantics (BLS12_381):
- Parse the leaf value as IdentityPublicKey; enforce:
  - key_type == BLS12_381 (48‑byte compressed), purpose == SYSTEM, disabled == 0.
- Extract the 48‑byte compressed BLS pubkey bytes (as stored) for identity linkage.

Identity linkage (deterministic):
- Extract owner_identity_id = proTxHash from path A.
- Extract operator_identity_id from path B.
- Constrain operator_identity_id == SHA256(proTxHash || bls_operator_pubkey_bytes).

Freshness binding:
- Require message_hash to be derived from a domain‑separated challenge committing to epoch/height, timestamp, nonce, and app context (verifier supplies the challenge; details in Protocol Flow).

Protocol Flow
Verifier:
- Chooses a height/epoch and generates a fresh random challenge/nonce.
- Fetches state_root (app_hash) for that height.
- Verifies the ZK proof against {state_root, message_hash}.

Prover:
- Builds canonical challenge C = H(domain_sep || state_root_or_epoch || timestamp || nonce || app_context) and sets message_hash = first_32_bytes(H(C)).
- Signs message_hash with their secp256k1 owner key (ECDSA (r, s)).
- Fetches two GroveDB key proofs: (A) owner key under owner_identity_id, (B) operator BLS key under operator_identity_id. Proofs must include leaf values.
- Preprocesses proofs into sibling hashes and direction bits; extracts leaf value bytes and identity IDs from paths.
- Produces the ZK proof with public inputs {state_root, message_hash}.

Witness Format (conceptual)
- Proof A: path nodes, leaf bytes (IdentityPublicKey), owner_identity_id (from path segment), owner_key_id.
- Proof B: path nodes, leaf bytes (IdentityPublicKey), operator_identity_id (from path segment), bls_key_id.
- Owner pubkey bytes (secp256k1), signature (r, s).
- No owner/operator metadata (type/purpose/disabled) is accepted from the prover; all are parsed from the leaf bytes.

Implementation Pieces
Circuit gadgets:
- Grove leaf/node hashing identical to Drive/Merk (byte‑accurate; include leaf/inner prefixes as used on chain).
- IdentityPublicKey parser for the on‑disk serialization (lengths, key_type, purpose, security_level if present, disabled, data bytes).
- Hash primitives: SHA‑256, RIPEMD‑160, HASH160(pubkey) and SHA‑256(proTxHash || bls_pubkey).
- ECDSA(secp256k1) verification over a 32‑byte message_hash.

Witness preprocessor:
- Convert layered GroveDB proofs into arrays of sibling hashes and direction bits.
- Extract leaf value bytes exactly as stored (no re‑encoding) and path segments for identity IDs.
- Validate pubkey encoding agreement: the prover must supply the same pubkey byte form (compressed/uncompressed) whose HASH160 equals the stored 20‑byte data.

SDK/API helpers:
- Get state_root (app_hash) at a given height/epoch.
- Fetch key proofs by identity_id + key_id (owner and operator), returning proofs with leaf values.
- Optional one‑shot helper to fetch and normalize both proofs for the circuit.

Security & Privacy
- Zero‑knowledge: only state_root and message_hash are public. Identities, keys, signature, path indices, and which leaves are used remain hidden.
- Soundness: proofs are tied to the committed state (state_root) and to the verifier’s challenge; replay across states/challenges is prevented.
- Single source of truth: key_type/purpose/disabled/data are parsed from proof leaf bytes; the prover cannot spoof them. The only supplied key material is the owner secp256k1 pubkey, which is bound by HASH160 equality and used for signature verification.

Notes & Edge Cases
- Owner pubkey bytes must match the encoding used to compute the HASH160 stored on chain (commonly 33‑byte compressed). Mismatched encoding yields a HASH160 inequality and fails.
- Operator key verification is not required; the operator BLS key is parsed to enforce policy (type/purpose/disabled) and to derive operator_identity_id via SHA‑256.
- If Platform adds additional key policies (e.g., security level), parse and enforce them as needed.

Statement Summary
There exist identities (owner = proTxHash, operator = SHA256(proTxHash || bls_pubkey)) in Platform state_root such that:
- The owner identity includes an enabled ECDSA_HASH160 OWNER key with data == HASH160(owner_pubkey).
- The operator identity includes an enabled BLS12_381 SYSTEM key whose bytes derive the operator identity as specified.
- The prover knows owner_pubkey and a valid ECDSA signature (r, s) over message_hash under that pubkey.
All while keeping identities, keys, paths, and signatures private.
