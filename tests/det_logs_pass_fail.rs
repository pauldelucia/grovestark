use grovestark::{create_witness_from_platform_proofs, GroveSTARK, PublicInputs, STARKConfig};
use serde::Deserialize;

fn hex32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("hex32 decode");
    assert_eq!(v.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn default_fast_config() -> STARKConfig {
    // Allow weaker params for faster CI-style tests
    std::env::set_var("GS_ALLOW_WEAK_PARAMS", "1");
    std::env::set_var("FAST_TESTS", "1");
    std::env::set_var("GS_RELAX_ID_VALIDATION", "1");
    let mut cfg = STARKConfig::default();
    cfg.grinding_bits = 0;
    cfg.num_queries = 8;
    cfg.expansion_factor = 16;
    cfg
}

#[derive(Deserialize)]
struct Ed25519Fix {
    public_key_hex: String,
    signature_r_hex: String,
    signature_s_hex: String,
    private_key_hex: String,
}

#[derive(Deserialize)]
struct PubInputsFix {
    state_root_hex: String,
    contract_id_hex: String,
    message_hex: String,
    timestamp: u64,
}

#[derive(Deserialize)]
struct PassFix {
    document_json: String,
    document_proof_hex: String,
    key_proof_hex: String,
    public_inputs: PubInputsFix,
    ed25519: Ed25519Fix,
}

#[derive(Deserialize)]
struct FailFix {
    key_proof_hex_fail: String,
}

#[derive(Deserialize)]
struct Fixtures {
    pass: PassFix,
    fail: FailFix,
}

#[test]
fn det_logs_pass_case_verifies() {
    // Load fixtures
    let fixtures: Fixtures =
        serde_json::from_str(include_str!("fixtures/PASS_AND_FAIL.json")).unwrap();

    // Decode proofs
    let doc_proof = hex::decode(&fixtures.pass.document_proof_hex).expect("decode document proof");
    let key_proof = hex::decode(&fixtures.pass.key_proof_hex).expect("decode key proof (pass)");

    // Decode EdDSA components
    let sig_r_vec = hex::decode(&fixtures.pass.ed25519.signature_r_hex).unwrap();
    let sig_s_vec = hex::decode(&fixtures.pass.ed25519.signature_s_hex).unwrap();
    let pubkey_vec = hex::decode(&fixtures.pass.ed25519.public_key_hex).unwrap();
    let msg_vec = hex::decode(&fixtures.pass.public_inputs.message_hex).unwrap();
    let privkey_vec = hex::decode(&fixtures.pass.ed25519.private_key_hex).unwrap();

    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    let mut pubkey = [0u8; 32];
    let mut privkey = [0u8; 32];
    sig_r.copy_from_slice(&sig_r_vec);
    sig_s.copy_from_slice(&sig_s_vec);
    pubkey.copy_from_slice(&pubkey_vec);
    privkey.copy_from_slice(&privkey_vec);

    // Build witness (validated path; enforces owner == identity via GroveVM)
    let witness = create_witness_from_platform_proofs(
        &doc_proof,
        &key_proof,
        fixtures.pass.document_json.as_bytes().to_vec(),
        &pubkey,
        &sig_r,
        &sig_s,
        &msg_vec,
        &privkey,
    )
    .expect("witness build (pass)");

    // Public inputs from logs
    let public = PublicInputs {
        state_root: hex32(&fixtures.pass.public_inputs.state_root_hex),
        contract_id: hex32(&fixtures.pass.public_inputs.contract_id_hex),
        message_hash: hex32(&fixtures.pass.public_inputs.message_hex),
        timestamp: fixtures.pass.public_inputs.timestamp,
    };

    let prover = GroveSTARK::with_config(default_fast_config());
    let proof = prover
        .prove(witness.clone(), public.clone())
        .expect("prove(pass)");
    let ok = prover
        .verify(&proof, &public)
        .expect("verify(pass) errored");
    assert!(ok, "pass case should verify");
}

#[test]
fn det_logs_fail_case_rejects() {
    // Load fixtures
    let fixtures: Fixtures =
        serde_json::from_str(include_str!("fixtures/PASS_AND_FAIL.json")).unwrap();

    // Same document proof and JSON; identity mismatch via different key proof
    let doc_proof = hex::decode(&fixtures.pass.document_proof_hex).expect("decode document proof");
    let key_proof_fail =
        hex::decode(&fixtures.fail.key_proof_hex_fail).expect("decode key proof (fail)");

    // EdDSA components (reuse pass case)
    let sig_r = hex32(&fixtures.pass.ed25519.signature_r_hex);
    let sig_s = hex32(&fixtures.pass.ed25519.signature_s_hex);
    let pubkey = hex32(&fixtures.pass.ed25519.public_key_hex);
    let msg = hex::decode(&fixtures.pass.public_inputs.message_hex).unwrap();
    let privkey = hex32(&fixtures.pass.ed25519.private_key_hex);

    // Build witness using the no-validation path to allow mismatched identity
    let witness = create_witness_from_platform_proofs(
        &doc_proof,
        &key_proof_fail,
        fixtures.pass.document_json.as_bytes().to_vec(),
        &pubkey,
        &sig_r,
        &sig_s,
        &msg,
        &privkey,
    )
    .expect("witness build (fail)");

    // Public inputs from logs
    let public = PublicInputs {
        state_root: hex32(&fixtures.pass.public_inputs.state_root_hex),
        contract_id: hex32(&fixtures.pass.public_inputs.contract_id_hex),
        message_hash: hex32(&fixtures.pass.public_inputs.message_hex),
        timestamp: fixtures.pass.public_inputs.timestamp,
    };

    let prover = GroveSTARK::with_config(default_fast_config());
    let proof = prover
        .prove(witness.clone(), public.clone())
        .expect("prove(fail)");
    let ok = prover
        .verify(&proof, &public)
        .expect("verify(fail) errored");
    assert!(!ok, "fail case should not verify");
}
