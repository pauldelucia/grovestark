# GroveSTARK Technical Overview

This document dives into the architecture, core phases, constraint layout, and proof system parameters used by GroveSTARK beyond the high-level README.

## Architecture

- Execution is organized into three main phases over a single STARK trace:
  - BLAKE3 hashing windows and nibble lanes
  - Merkle path verification with lane packing
  - EdDSA verification and GroveVM helpers (in the auxiliary segment)
- Backed by Winterfell 0.13.1 with BLAKE3-256 as the hash (via `winterfell::crypto`), Goldilocks base field (`winterfell::math::fields::f64::BaseElement`), and standard FRI-based low-degree testing.
- The code is grouped by function:
  - `src/stark_winterfell.rs`: end-to-end prover/verifier wiring against Winterfell (trace construction, AIR wiring, options, and verification glue).
  - `src/air/`: high-level constraints that bind identity and phase selectors.
  - `src/phases/`: phase-specific trace builders and constraints: `blake3`, `merkle`, `eddsa`, and `grovevm`.
  - `src/crypto/`: in-circuit primitives (BLAKE3 operations and constraints, Edwards arithmetic, Ed25519 helpers, constant-time utilities, and Merkle helpers).
  - `src/parser/`: GroveDB proof parsing and execution utilities to derive Merkle nodes/operations from layered proofs.
  - `src/prover/`: `GroveSTARK` API, public-output computation, basic PoW commitment, and batch helper.
  - `src/validation/`: guardrails for inputs and configuration.

## Trace Layout

All indices below refer to main/aux segments in `src/stark_winterfell.rs`.

- Main trace width: 132 columns
- Auxiliary trace width: 119 columns
- Total width: 251 (< 255 limit)
- Phase lengths (rows):
  - `BLAKE3_LEN = 3584`
  - `MERKLE_LEN = 16384`
  - `EDDSA_LEN = 32768`

Main segment packs BLAKE3 message nibbles, Merkle staging/control, selectors, and reserved lanes. EdDSA extended coordinates and GroveVM stack live in the auxiliary segment to keep the main segment compact and to isolate constraints by phase.

## Constraint System

- Constraint ranges (`LAYOUT`) in the main segment:
  - `0..15`: BLAKE3 constraints (split commit)
  - `15..21`: Merkle constraints (flags + packed lanes)
  - `21..22`: `SEL_FINAL` constraint used to bind phase endpoints
- Auxiliary segment currently hosts 11 GroveVM constraints for a simple stack machine used during proof parsing and witness preparation.
- Phase isolation is accomplished via selector gates and row-window checks; assertions pin phase counts and isolation to the expected ranges.

### BLAKE3

- Custom message-column mapping and nibble-lane packing to reduce bandwidth.
- Deterministic lane-packing scalar `gamma` derived from AIR parameters; enforced to avoid degenerate values.
- In-circuit operations: `g`, `round`, `compress`, plus helpers for multi-input hashing.

### Merkle Verification

- Uses BLAKE3 for parent hashing with left/right flags.
- Message view (`MsgView`) multiplexes message sources between document hashing and Merkle windows depending on the active phase gate.
- Lane packing aggregates nibbles into packed lanes to reduce the number of explicit constraints while keeping binding strong.

### EdDSA (Ed25519)

- Verification is split:
  - Off-circuit/auxiliary: scalar decompositions and extended coordinate witnesses (`R`, `A`, intermediate points) are provided or derived via helpers in `ed25519_helpers.rs`.
  - In-circuit: constraints bind the scalar multiplication consistency, range checks, and final group relation. Some heavy relations are delegated to auxiliary columns to keep the main AIR compact.
- The circuit verifies `(R,S)` against a 32-byte `message_hash` supplied as a public input.

## Public and Private Bindings

- Public inputs (`src/types.rs`):
  - `state_root`, `contract_id`, `message_hash` (32 bytes each)
  - `timestamp` is currently unused by the circuit but retained for forward compatibility.
- Private inputs carry:
  - Document-side roots and Merkle paths
  - Identity-side roots and key membership paths
  - Ed25519 artifacts (`R`, `S`, `A`) plus extended coordinates and auxiliary windows for scalar multiplication
  - Optional GroveDB proof bytes and document CBOR for integration.
- Boundary assertions bind owner and identity IDs and enforce that the key belongs to the identity that owns the document under the provided `state_root`.

## Winterfell Options and Guardrails

- `STARKConfig` defaults (non-test builds):
  - `expansion_factor = 16`
  - `num_queries = 48`
  - `folding_factor = 4`
  - `grinding_bits = 24`
  - `trace_length = 65536`
- Validation enforces guardrails at runtime unless `GS_ALLOW_WEAK_PARAMS=1` is set.
- Proof-of-work: a small leading-zero requirement over a commitment to the trace and constraint commitments; configured via `grinding_bits`.

## GroveDB Proofs and GroveVM

- Layered GroveDB proofs are parsed under `src/parser/` into operations (`Op`) and sibling hashes (`MerkleNode`).
- GroveVM (aux segment) executes a minimal stack machine to model proof execution, push intermediate hashes, and expose the correct Merkle windows to the main segment.
- This separation keeps parsing complexity out of the main AIR while preserving a tight binding between parsed data and constraints.

## Logging and Debugging

- `hotlog!` macro can be enabled with the `hotlog` feature to emit detailed step logs in hot paths.
- Optional `wf_dbg` feature gates additional Winterfell debug logging around OOD/CE paths.
- Feature `quiet_eval` suppresses verbose constraint-evaluation logging.

## Security Notes (technical)

- Identity binding is enforced via boundary assertions and phase-join selectors — not via ad-hoc host checks.
- Avoid reducing `expansion_factor`, `num_queries`, or `grinding_bits` in production. Test/bench flows can relax via env vars as documented.

