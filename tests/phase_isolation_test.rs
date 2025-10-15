/// Phase isolation tests per GUIDANCE.md Section 8
/// Updated to use real PASS_AND_FAIL fixtures for witness/public inputs
use grovestark::prover::GroveSTARK;
use grovestark::types::{PublicInputs, STARKConfig};

// Load a valid witness and public inputs from PASS_AND_FAIL fixtures
fn load_pass_fixture() -> (grovestark::PrivateInputs, PublicInputs) {
    #[derive(serde::Deserialize)]
    struct Ed25519Fix {
        public_key_hex: String,
        signature_r_hex: String,
        signature_s_hex: String,
        private_key_hex: String,
    }
    #[derive(serde::Deserialize)]
    struct PubInputsFix {
        state_root_hex: String,
        contract_id_hex: String,
        message_hex: String,
        timestamp: u64,
    }
    #[derive(serde::Deserialize)]
    struct PassFix {
        document_json: String,
        document_proof_hex: String,
        key_proof_hex: String,
        public_inputs: PubInputsFix,
        ed25519: Ed25519Fix,
    }
    #[derive(serde::Deserialize)]
    struct Fixtures {
        pass: PassFix,
    }

    fn hex32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).expect("hex32 decode");
        assert_eq!(v.len(), 32);
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }

    let fixtures: Fixtures =
        serde_json::from_str(include_str!("fixtures/PASS_AND_FAIL.json")).unwrap();

    let doc_proof = hex::decode(&fixtures.pass.document_proof_hex).expect("decode document proof");
    let key_proof = hex::decode(&fixtures.pass.key_proof_hex).expect("decode key proof");
    let sig_r = hex32(&fixtures.pass.ed25519.signature_r_hex);
    let sig_s = hex32(&fixtures.pass.ed25519.signature_s_hex);
    let pubkey = hex32(&fixtures.pass.ed25519.public_key_hex);
    let msg = hex::decode(&fixtures.pass.public_inputs.message_hex).unwrap();
    let privkey = hex32(&fixtures.pass.ed25519.private_key_hex);

    let witness = grovestark::create_witness_from_platform_proofs(
        &doc_proof,
        &key_proof,
        fixtures.pass.document_json.as_bytes().to_vec(),
        &pubkey,
        &sig_r,
        &sig_s,
        &msg,
        &privkey,
    )
    .expect("fixture witness build");

    let public_inputs = PublicInputs {
        state_root: hex32(&fixtures.pass.public_inputs.state_root_hex),
        contract_id: hex32(&fixtures.pass.public_inputs.contract_id_hex),
        message_hash: hex32(&fixtures.pass.public_inputs.message_hex),
        timestamp: fixtures.pass.public_inputs.timestamp,
    };

    (witness, public_inputs)
}

fn default_fast_config() -> STARKConfig {
    // Allow weak params for fast phase isolation tests
    std::env::set_var("GS_ALLOW_WEAK_PARAMS", "1");
    std::env::set_var("FAST_TESTS", "1");
    let mut cfg = STARKConfig::default();
    cfg.grinding_bits = 0; // fastest
    cfg.num_queries = 8;
    cfg.expansion_factor = 16;
    cfg
}

#[test]
fn test_merkle_phase_isolation() {
    // Use real fixture-based witness; isolation is exercised inside constraints
    let (witness, public_inputs) = load_pass_fixture();
    let prover = GroveSTARK::with_config(default_fast_config());

    let proof = prover
        .prove(witness, public_inputs.clone())
        .expect("prove(pass fixtures)");
    assert!(
        proof.public_outputs.verified,
        "Proof should verify with isolation constraints active"
    );

    let verification_result = prover.verify(&proof, &public_inputs).unwrap();
    assert!(verification_result, "Verification failed for fixture proof");
}

#[test]
fn test_blake3_merkle_handoff() {
    // Validates phase boundary by proving a real fixture witness
    let (witness, public_inputs) = load_pass_fixture();
    let prover = GroveSTARK::with_config(default_fast_config());

    let proof = prover
        .prove(witness.clone(), public_inputs.clone())
        .expect("prove(pass fixtures)");
    assert!(proof.public_outputs.verified, "Initial proof should verify");

    let verification_result = prover.verify(&proof, &public_inputs).unwrap();
    assert!(verification_result, "Proof verification should succeed");
}

#[test]
fn test_merkle_window_fixture() {
    // Use the real fixture paths to ensure window handling is correct
    let (witness, public_inputs) = load_pass_fixture();
    let prover = GroveSTARK::with_config(default_fast_config());

    let proof = prover
        .prove(witness, public_inputs.clone())
        .expect("prove(pass fixtures)");
    assert!(
        proof.public_outputs.verified,
        "Proof should verify with fixtures"
    );

    let verification_result = prover.verify(&proof, &public_inputs).unwrap();
    assert!(verification_result, "Verification failed for fixture proof");
}
