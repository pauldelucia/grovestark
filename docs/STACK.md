# Stack & Dependencies

This document enumerates core dependencies, their roles, and key internal modules.

## Languages & Tooling

- Rust 1.77+ (2021 edition)
- Cargo for build, test, and benches

## Core Libraries

- Winterfell 0.13.1: STARK prover/verifier, FRI, commitment scheme, Goldilocks field
- `blake3`: hashing library for off-circuit and some helpers
- `sha2`: used in Ed25519 helper flow to compute `h = SHA-512(R || A || M) mod L` where appropriate
- `ed25519-dalek`, `curve25519-dalek`: reference arithmetic and integration helpers (also in dev-deps for testing paths)
- `serde`, `serde_json`, `bincode`, `bincode1`: serialization of proofs and fixtures
- `grovedb`, `grovedb-merk`, `grovedb-costs`: proof decoding and integration with GroveDB formats
- `rayon`, `num_cpus`: parallelism hints for heavy paths
- `tracing`, `tracing-subscriber`, `env_logger`, `log`: structured and leveled logging

## Internal Modules

- `src/stark_winterfell.rs`: adapter around Winterfell (trace/AIR/options/proof verify)
- `src/air/`: identity/selector constraints and counts
- `src/phases/`: phase builders for blake3, merkle, eddsa, grovevm
- `src/crypto/`: in-circuit primitives for BLAKE3 and Ed25519 arithmetic, scalar mult, decompression
- `src/parser/`: parse layered GroveDB proofs to `Op` sequences and sibling lists
- `src/prover/`: `GroveSTARK` API, batch proving helper, proof-of-work binding
- `src/validation/`: config and input guardrails

## Features (Cargo)

- `bench`: enable Criterion benches
- `tripwire`, `tripwire_perf`, `validate_trace`: debug/testing toggles
- `short_trace`: use 16384 rows instead of 65536 (faster debugging)
- `skip_eddsa`: bypass EdDSA to debug Merkle/BLAKE3 phases
- `quiet_eval`: reduce constraint-eval logging noise
- `hotlog`: enable `hotlog!` macro for hot-path logs
- `panic_in_transition`, `must_fail_test`, `fri_only_must_fail`, `wf_dbg`: test/debug behavior probes

## Environment Variables

- `GS_ALLOW_WEAK_PARAMS=1`: bypass production guardrails for tests/benches
- `FAST_TESTS=1`: select lighter-but-compatible params in hybrid verifier paths
- `GS_RELAX_ID_VALIDATION=1`: relax identity vs owner equality in specific negative tests
- `GS_EXPANSION_FACTOR`, `GS_NUM_QUERIES`, `GS_GRINDING_BITS`: override parameters in probe tools
- `GS_ENABLE_C6`, `GS_ISOLATE_OOD`, `GS_LANE_PROBE`, `GS_B3_ONLY_IDX`, `GS_B3_ENABLE_INDICES`: expert diagnostics around constraint evaluation and BLAKE3 indices (see `src/stark_winterfell.rs`)
- `VALIDATE_TRACE=1`: enable extra trace validation checks in verifier paths
- Standard `RUST_LOG` controls logging when used with `env_logger`/`tracing-subscriber`

