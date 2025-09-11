# Development Guide

This guide covers environment setup, running, logging, features, and test knobs used throughout the repo.

## Setup

- Install Rust (1.77+ recommended) and Cargo
- Build: `cargo build --release`
- Run tests (release recommended for heavy tests): `cargo test --release -q`
- Run examples: `cargo run --example proof_demo --release`

## Parameters & Guardrails

- Defaults (non-test builds): `expansion_factor=16`, `num_queries=48`, `folding_factor=4`, `grinding_bits=24`, `trace_length=65536`
- Guardrails are enforced by `validate_config` unless `GS_ALLOW_WEAK_PARAMS=1`.
- For fast CI or local iteration:
  - `FAST_TESTS=1`: use lighter params in hybrid verifier paths
  - `GS_ALLOW_WEAK_PARAMS=1`: bypass guardrails when running reduced configs

## Useful Env Vars

- Soundness/size:
  - `GS_ALLOW_WEAK_PARAMS=1`
  - `FAST_TESTS=1`
  - `GS_EXPANSION_FACTOR`, `GS_NUM_QUERIES`, `GS_GRINDING_BITS` (used by probe tools)
- Trace/diagnostics (expert):
  - `VALIDATE_TRACE=1`, `GS_ISOLATE_OOD=1`
  - `GS_ENABLE_C6=1`, `GS_LANE_PROBE=...`
  - `GS_B3_ONLY_IDX=...`, `GS_B3_ENABLE_INDICES=...`
- Input validation:
  - `GS_RELAX_ID_VALIDATION=1` (for negative tests only)
- Logging:
  - `RUST_LOG=info` (or `debug`) with `env_logger`/`tracing-subscriber`

## Cargo Features

- `bench`: enable Criterion benchmarks
- Debugging/testing toggles:
  - `short_trace`, `skip_eddsa`, `quiet_eval`, `hotlog`, `panic_in_transition`, `must_fail_test`, `fri_only_must_fail`, `wf_dbg`, `validate_trace`

Enable features with `--features "feature1,feature2"`.

## Running Targeted Tests

- Full suite (quiet): `cargo test --release -q`
- Single test target: `cargo test --release -q --test ci_test_suite -- --nocapture`
- Selected benches:
  - `cargo bench --bench quick_benchmarks --features bench`
  - `cargo bench --bench comprehensive_benchmarks --features bench`

## Integration Tips

- Public inputs bind proofs to a specific `state_root`, `contract_id`, and `message_hash` (32-byte challenge).
- Build a canonical application message `C` and derive `message_hash = first_32_bytes(H(C))`. Sign `C` off-circuit.
- Use `ed25519_helpers` to generate the witness from Platform proofs and Ed25519 data, ensuring extended coordinates and windows are populated consistently.

