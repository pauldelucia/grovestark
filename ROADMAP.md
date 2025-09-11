# GroveSTARK Ownership Proof — Spec & Roadmap

This document specifies the target behavior and a cleanup roadmap for the GroveSTARK prover so users can prove they own a document in a specific contract at a specific state (block) without revealing identity, document contents, or private keys.

## Goal (What Users Get)

- Proves: “This document exists in contract `contract_id` under Platform state `state_root`, and the document’s owner controls a key that signed a fresh challenge (`message_hash`).”
- Reveals only: `state_root`, `contract_id`, `message_hash`, `timestamp` (all public inputs).
- Keeps private: identity, Merkle paths, document contents, keys, and all trace internals.

## Public Inputs (Verifier Sees)

- `state_root: [u8; 32]` — Platform state root (binds proof to a specific block/epoch).
- `contract_id: [u8; 32]` — Scopes the claim to a contract.
- `message_hash: [u8; 32]` — Hash of a fresh challenge (see “Challenge Binding”).
- `timestamp: u64` — Context/freshness (optionally bound inside the challenge too).

## Private Inputs (Witness)

- Merkle paths for document and identity/key membership (kept private):
  - `owner_id_leaf_to_doc_path`, `docroot_to_state_path`.
  - `identity_leaf_to_state_path`, `key_leaf_to_keysroot_path`.
- Identity/key data: `owner_id`, `identity_id`, `keys_root`.
- EdDSA: `(R, S)` and `A` (public key) used inside the circuit’s signature check.
- Document bytes (e.g., `document_cbor`) — not disclosed, only used as inputs to intermediate hashing/constraints when needed.

Note: The current code includes `private_key` in the witness; the circuit does not depend on it. See “API Refinements”.

## What the Circuit Verifies

1. Document existence under `state_root`: Merkle recomputation from leaves to root equals the public `state_root`.
2. Identity binding: The document’s `owner_id` equals the `identity_id` tied to the key (private equality enforced at a join row).
3. Key ownership: There exists a key in that identity’s key set.
4. Signature validity: The Ed25519 verification relation holds for `(R, S, A, message_hash)`.

## Challenge Binding (Freshness, Anti‑Replay, Contract/State Scope)

To ensure “control at a specific time/state” and prevent replay/linkability:

- Define a canonical challenge bytestring `C`:
  - `C = H( domain_sep || contract_id || state_root || block_height_or_epoch || timestamp || nonce || app_context )`.
- Produce `message_hash = first_32_bytes( H(C) )` (or a 32‑byte message derived from `C`).
- Sign `C` off‑circuit to produce `(R, S)` under key `A`.
- Pass `(R, S, A)` and `message_hash` into the proof (as part of the witness/public inputs).

Effects:
- Binds the proof to `contract_id` and `state_root` for that block.
- Freshness via `timestamp` and `nonce` (verifier enforces window/replay policy).
- Minimizes linkability: use a per‑session random `nonce` in `C`.

## Recommended Verifier Policy

- Accept proof only if:
  - `state_root` is from a known/acceptable block height or epoch.
  - `timestamp` in `C` is recent, and `nonce` hasn’t been seen before.
  - `contract_id` matches the scope expected by the application.

## API Refinements (Proposed)

1. Make `private_key` optional in the witness:
   - Remove “Private key cannot be zero” from `validate_witness` (keep only for hybrid-feature flows, if any).
   - Rely on the existence of `(R, S, A)` and the EdDSA verification inside the proof.

2. Add a canonical “challenge builder” helper:
   - `build_challenge(contract_id, state_root, block_or_epoch, timestamp, nonce, context) -> [u8; 32]`.
   - Caller uses this to generate `message_hash` and `(R, S)` before building the witness.

3. Remove the “hybrid” wrapper altogether:
   - Delete `src/crypto/hybrid_verification.rs` and any wrappers that only existed to support it.
   - The core ZK proof binds to a canonical in‑circuit challenge; no separate off‑circuit signature layer is needed.

## Clean‑Up & Hardening Roadmap

Phase 1 — Minimal, Safe Core (short)
- [ ] Remove `private_key` requirement in `validate_witness` and witness builders.
- [ ] Add challenge builder helper and thread it into tests/examples.
- [ ] Ensure all tests that previously used ad‑hoc proofs now use `PASS_AND_FAIL.json` fixtures.
- [ ] Remove hybrid-related files and references.
- [ ] Reduce debug logs in hot paths; keep `wf_dbg` gated.

Phase 2 — Public API & Docs (short)
- [ ] Public API doc: “What to provide” (proof inputs) and “What is proven”.
- [ ] Sample code: challenge construction and client‑side signing.
- [ ] Verifier policy doc: acceptable `state_root`/epoch, freshness window, nonce replay cache.

Phase 3 — Circuit & AIR polish (medium)
- [ ] Keep aux transition degrees at realistic bounds (current cap: 8), revisit if constraints evolve.
- [ ] Lock boundary assertions to trace subgroup only (no coset/domain offset math) — already done.
- [ ] Ensure EdDSA selector boundary and identity equality limb assertions are minimal and robust.

Phase 4 — Codebase Hygiene (medium)
- [ ] Delete unused mock proof builders, hybrid code, and old test scaffolding.
- [ ] Consolidate performance tests; remove duplicate variants.
- [ ] Move heavy real‑data tests behind `--release` gating (already done for most).
- [ ] Keep debug OOD probes under a feature flag only.

Phase 5 — Optional Enhancements (later)
- [ ] Add a structured “epoch id” public input distinct from raw `state_root` (if product requires).
- [ ] Add an optional revocation/expiry check (app‑level) based on block height.
- [ ] Consider alternative hash domain separation for challenge if cross‑app usage is planned.

## Next Circuits (near term)

Circuit 2 — Document Type Binding (low–moderate)
- Add public input `doc_type_commitment: [u8; 32]`.
- Parse GroveDB ops to extract the doc_type path segment; assert equality to `doc_type_commitment` at Merkle end.
- Proves: “Document of type `doc_type` exists under `contract_id` at `state_root`, owner==identity, signature on fresh challenge.”

Circuit 3 — Document Commitment Binding (low)
- Add public input `document_commitment` (e.g., saltedDomainHash from Platform schema).
- Assert that the document leaf/tag used in the path equals `document_commitment`.
- Establishes a stable commitment to private document bytes without disclosure.

## Long‑Term Product Ideas (community & growth)

1) ZK Login + Token/Role Gating
- Use core proof + doc_type binding to gate access, without revealing identity/doc.
- Bind challenge to `(contract_id, state_root/epoch, timestamp, nonce)`; apps verify offline.

2) Private Airdrops / Coupons / One‑time Claims
- Add a nullifier gadget (e.g., `H(identity_secret, event_id)`) tied to the challenge; register nullifiers to prevent double claims.
- Simple Dash Platform “nullifier registry” contract stores nullifiers per event.

3) Event Tickets & Anonymous Check‑In
- Tickets as docs; prove valid ticket ownership with one‑time nullifier at check‑in.
- Optional revocation list for stolen tickets.

4) Credential Gating (KYC‑lite) with Selective Disclosure
- Bind a boolean field commitment (e.g., `is_over_18`, `residency`) to a public input.
- Issuer stores verified attribute docs; users prove the flag without revealing identity or doc.

5) DAO Private Voting / Snapshot Proof (advanced)
- Private voting with nullifiers and optional token‑weighted ballots.
- Requires tally backend and careful epoch binding.

6) Cross‑Chain Bridges (advanced)
- Prove “lock doc” exists at `state_root`; verify root via a light‑client/oracle on the destination chain; mint wrapped assets.

## Platform Integration Notes

- Nullifier registry: a simple data contract keyed by `(event_id, nullifier)` to prevent duplicates.
- Token/role doc types: standardize or publish reference contracts for common gating scenarios.
- Expose/standardize block height or an epoch id associated with each `state_root` to simplify verifier UX.

## Security Notes & Common Pitfalls

- Replay/linkability: Always include a random `nonce` and current timestamp in the challenge; enforce replay cache/in‑window on the verifier.
- Contract scoping: Include `contract_id` in the challenge; check it in the verifier context.
- State scoping: Verify `state_root` corresponds to the intended block height/epoch; challenge should include the epoch id for clarity.
- Key rotation: Proofs are valid for the state encoded by `state_root`. For current status, require a fresh `state_root`.
- Private key safety: The private key never enters the STARK trace; the proof only relies on `(R, S, A, message_hash)` inside the circuit.

## User‑Facing Summary

“GroveSTARK lets you prove you own a Platform document under a specific contract and state root, and that your key signed a fresh challenge — without revealing your identity, your document, your Merkle paths, or your key. Anyone can verify the proof offline using just the block’s state root, the contract id, and your challenge hash.”
