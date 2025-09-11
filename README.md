# GroveSTARK

Zero‑knowledge STARK proofs for Dash Platform GroveDB: prove you own a document in a specific contract at a specific block height — without revealing identity or document contents.

**WARNING:** This is a research project. It has not been audited and may contain bugs and security flaws. This implementation is NOT ready for production use.

## Overview

GroveSTARK generates Winterfell‑based STARK proofs that bind to:
- a Dash Platform `state_root` (block/epoch),
- a `contract_id`, and
- a fresh challenge `message_hash` (timestamp + nonce recommended).

The circuit privately checks:
- your document (with ownerId) exists under the public `state_root`,
- the identity in the document owns a key,
- the document’s ownerId equals the identity id, and
- the Ed25519 signature `(R,S)` verifies against the challenge `message_hash` (under key `A`).

Hybrid/signature wrappers are not required — the circuit itself enforces freshness and scope via the in‑circuit challenge.

## Features

- Zero‑knowledge document ownership proof under a specific `state_root` and `contract_id`.
- Private identity binding (ownerId == identityId) without revealing either.
- Ed25519 signature verification on a public 32‑byte challenge (`message_hash`).
- Optimized Merkle/BLAKE3 windows, release‑grade parameters via Winterfell 0.13.1.
- Batch proving helper for multiple documents.

## Parameters & Guardrails

- Production minimums (release builds):
  - expansion_factor ≥ 16
  - num_queries ≥ 48
  - folding_factor ≥ 4
- For development/tests you can set `GS_ALLOW_WEAK_PARAMS=1` and/or use `FAST_TESTS=1` where appropriate.

## Install / Build / Test

Build:
```bash
cargo build --release
```

Run tests (many heavy tests expect release):
```bash
cargo test --release -q
```

Examples:
```bash
cargo run --example proof_demo --release
```

## Usage

### Quick Start (Fixture‑based)

```rust
use grovestark::{GroveSTARK, PublicInputs, STARKConfig, create_witness_from_platform_proofs};

// 1) Load Platform proofs + EdDSA data from your app (here we use test fixtures)
let fixtures: serde_json::Value = serde_json::from_str(include_str!("tests/fixtures/PASS_AND_FAIL.json")).unwrap();
let doc_proof = hex::decode(fixtures["pass"]["document_proof_hex"].as_str().unwrap()).unwrap();
let key_proof = hex::decode(fixtures["pass"]["key_proof_hex"].as_str().unwrap()).unwrap();
let pubkey = hex::decode(fixtures["pass"]["ed25519"]["public_key_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
let sig_r = hex::decode(fixtures["pass"]["ed25519"]["signature_r_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
let sig_s = hex::decode(fixtures["pass"]["ed25519"]["signature_s_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
let message = hex::decode(fixtures["pass"]["public_inputs"]["message_hex"].as_str().unwrap()).unwrap();
let document_json = fixtures["pass"]["document_json"].as_str().unwrap().as_bytes().to_vec();

// 2) Build the witness from Platform proofs
let witness = create_witness_from_platform_proofs(
    &doc_proof, &key_proof, document_json, &pubkey, &sig_r, &sig_s, &message,
    &hex::decode(fixtures["pass"]["ed25519"]["private_key_hex"].as_str().unwrap()).unwrap().try_into().unwrap(),
).expect("witness");

// 3) Public inputs (bind to state_root, contract_id, challenge hash, timestamp)
let public_inputs = PublicInputs {
    state_root: hex::decode(fixtures["pass"]["public_inputs"]["state_root_hex"].as_str().unwrap()).unwrap().try_into().unwrap(),
    contract_id: hex::decode(fixtures["pass"]["public_inputs"]["contract_id_hex"].as_str().unwrap()).unwrap().try_into().unwrap(),
    message_hash: hex::decode(fixtures["pass"]["public_inputs"]["message_hex"].as_str().unwrap()).unwrap().try_into().unwrap(),
    timestamp: fixtures["pass"]["public_inputs"]["timestamp"].as_u64().unwrap(),
};

// 4) Prove and verify
let config = STARKConfig::default(); // release guardrails apply in production
let prover = GroveSTARK::with_config(config);
let proof = prover.prove(witness, public_inputs.clone()).expect("prove");
let ok = prover.verify(&proof, &public_inputs).expect("verify");
assert!(ok);
```

### What to Sign (Challenge)

To prevent replay and bind scope, build a canonical challenge and derive `message_hash`:

`C = H(domain_sep || contract_id || state_root || block_height_or_epoch || timestamp || nonce || app_context)`

Then `message_hash = first_32_bytes(H(C))`. Sign `C` off‑circuit to get `(R,S)`; pass `(R,S,A,message_hash)` into the witness/public inputs.

### Batch Proving (optional helper)

You can generate proofs for multiple witnesses and receive a `BatchProof` with a binding commitment. (Aggregation/recursion are future work.)

## Architecture (high level)

- `air/` — constraints (Merkle/BLAKE3/EdDSA + identity binding).
- `crypto/` — primitives (BLAKE3, Ed25519 helpers), no hybrid wrapper.
- `parser/` — GroveDB layered proof parsing for Merkle paths.
- `prover/` — proof generation (Winterfell 0.13.1), batch helper.
- `utils/` — helper functions.

## Further Reading

- docs/TECH_OVERVIEW.md — trace, constraints, and phase design
- docs/STACK.md — dependencies, features, and env vars
- docs/WITNESS_AND_PUBLIC_INPUTS.md — data model and validation
- docs/GROVEDB_PROOFS.md — GroveDB proof parsing/binding
- docs/DEVELOPMENT.md — parameters, features, logging, and testing

## Testing

Common commands:
```bash
# Full suite (release recommended for heavy tests)
cargo test --release -q

# Run a single test target
cargo test --release -q --test ci_test_suite -- --nocapture
```

## Benchmarks

```bash
cargo bench --bench quick_benchmarks --features bench
cargo bench --bench comprehensive_benchmarks --features bench
```

## Security Notes

- Zero‑knowledge: identity, document contents, Merkle paths, and private key are never revealed.
- Bind proofs to a specific block/epoch via `state_root`.
- Use a canonical signed challenge (timestamp + nonce) to prevent replay and linkability.
- Production guardrails enforce sufficient blowup/queries in release.

## Roadmap

See `ROADMAP.md` for the current spec, next circuits (document type & document commitment binding), and long‑term product ideas (ZK login, private airdrops, tickets, credential gating, etc.).

## License

MIT

## Contributing

Contributions are welcome! Please run tests in release and add/adjust tests for any new functionality.
