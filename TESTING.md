Testing GroveSTARK
===================

This repo includes end‑to‑end and component tests covering proof parsing, witness building, Merkle verification, EdDSA integration, and the full STARK pipeline. Tests rely on reproducible fixtures.

Run Tests
---------

- Full suite (recommended):
  - `cargo test --release -q`

- Common targets:
  - CI suite: `cargo test --release -q --test ci_test_suite -- --nocapture`
  - Comprehensive: `cargo test --release -q --test comprehensive_test_suite -- --nocapture`
  - Preflight: `cargo test --release -q --test test_preflight_checker -- --nocapture`
  - Testnet: `cargo test --release -q --test testnet_proof_generation_test -- --nocapture`
  - Simple testnet: `cargo test --release -q --test testnet_proof_simple -- --nocapture`
  - Verification rejection: `cargo test --release -q --test verification_rejection_test -- --nocapture`

Fixtures
--------

- Location: `tests/fixtures/`
  - `PASS_AND_FAIL.json`: unified pass/fail fixture set used across tests.
  - `document_proof_*.bin`: GroveDB document proof (layered format).
  - `identity_proof_*.bin`: GroveDB key/identity proof (layered format).
  - `proof_metadata_*.json`: minimal metadata for the above.

Parameters & Env Flags
----------------------

- Production guardrails (enforced in release):
  - expansion_factor ≥ 16, num_queries ≥ 48, folding_factor ≥ 4.

- Local/development flags (for tests that opt into reduced configs):
  - `FAST_TESTS=1` — enables compact configs where supported.
  - `GS_ALLOW_WEAK_PARAMS=1` — bypass guardrails for tests using smaller params.
  - `GS_RELAX_ID_VALIDATION=1` — allow building mismatched owner/identity witnesses for negative tests (identity binding still enforced in‑circuit at prove/verify).

- Performance tuning in tests:
  - `GS_PERF_LIMIT_SECS` — adjust proof‑time assertion windows.
  - `GS_VERIFY_LIMIT_SECS` — adjust verification‑time assertion windows.

Canonical Challenge (What to Sign)
----------------------------------

Tests that simulate user flows bind freshness and scope using a canonical challenge. The recommended pattern is:

`C = H(domain_sep || contract_id || state_root || block_height_or_epoch || timestamp || nonce || app_context)`

Then derive `message_hash = first_32_bytes(H(C))`. Provide `(R,S,A)` for `C` in the witness; pass `message_hash` as a public input. This prevents replay and binds to the intended contract/state.

Notes
-----

- Many heavy tests are release‑only or optimized for release; expect `--release` to be required.
- The old “hybrid” wrapper is removed; all tests rely on the in‑circuit challenge.
- EdDSA (Ed25519) is the only active signature scheme; identity‑aware Merkle paths are the default.
