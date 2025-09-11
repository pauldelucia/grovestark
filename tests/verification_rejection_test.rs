//! Verification rejection tests using real fixtures

use grovestark::{
    create_witness_from_platform_proofs, create_witness_from_platform_proofs_no_validation,
    GroveSTARK, PublicInputs, STARKConfig,
};

#[test]
fn test_verification_rejects_mismatched_identity() {
    println!("\n🧪 Testing Verification Rejection with Mismatched Identity");
    println!("=======================================================");

    #[derive(serde::Deserialize)]
    struct Ed25519Fix { public_key_hex: String, signature_r_hex: String, signature_s_hex: String, private_key_hex: String }
    #[derive(serde::Deserialize)]
    struct PubInputsFix { state_root_hex: String, contract_id_hex: String, message_hex: String, timestamp: u64 }
    #[derive(serde::Deserialize)]
    struct PassFix { document_json: String, document_proof_hex: String, key_proof_hex: String, public_inputs: PubInputsFix, ed25519: Ed25519Fix }
    #[derive(serde::Deserialize)]
    struct FailFix { key_proof_hex_fail: String }
    #[derive(serde::Deserialize)]
    struct Fixtures { pass: PassFix, fail: FailFix }
    fn hex32(s: &str) -> [u8; 32] { let v = hex::decode(s).unwrap(); let mut out=[0u8;32]; out.copy_from_slice(&v); out }

    let fixtures: Fixtures = serde_json::from_str(include_str!("fixtures/PASS_AND_FAIL.json")).unwrap();
    let doc_proof = hex::decode(&fixtures.pass.document_proof_hex).unwrap();
    let mismatched_key_proof = hex::decode(&fixtures.fail.key_proof_hex_fail).unwrap();
    let pub_key = hex32(&fixtures.pass.ed25519.public_key_hex);
    let sig_r = hex32(&fixtures.pass.ed25519.signature_r_hex);
    let sig_s = hex32(&fixtures.pass.ed25519.signature_s_hex);
    let priv_key = hex32(&fixtures.pass.ed25519.private_key_hex);
    let message = hex::decode(&fixtures.pass.public_inputs.message_hex).unwrap();

    // Build witness with mismatched owner/identity (no validation)
    let witness = create_witness_from_platform_proofs_no_validation(
        &doc_proof,
        &mismatched_key_proof,
        fixtures.pass.document_json.as_bytes().to_vec(),
        &pub_key,
        &sig_r,
        &sig_s,
        &message,
        &priv_key,
    )
    .expect("no-validation witness");

    // Prover should reject or verify should fail
    let mut config = STARKConfig::default();
    config.grinding_bits = 8;
    config.num_queries = 48;
    let prover = GroveSTARK::with_config(config);
    let public_inputs = PublicInputs {
        state_root: hex32(&fixtures.pass.public_inputs.state_root_hex),
        contract_id: hex32(&fixtures.pass.public_inputs.contract_id_hex),
        message_hash: hex32(&fixtures.pass.public_inputs.message_hex),
        timestamp: fixtures.pass.public_inputs.timestamp,
    };
    match prover.prove(witness, public_inputs.clone()) {
        Err(_) => { /* acceptable */ }
        Ok(proof) => {
            let ok = prover.verify(&proof, &public_inputs).unwrap_or(false);
            assert!(!ok, "Mismatched identity should not verify");
        }
    }
}

#[test]
fn test_matching_identity_should_work() {
    println!("\n✅ Testing Valid Case: Matching Identity");
    println!("=======================================\n");

    #[derive(serde::Deserialize)]
    struct Ed25519Fix { public_key_hex: String, signature_r_hex: String, signature_s_hex: String, private_key_hex: String }
    #[derive(serde::Deserialize)]
    struct PubInputsFix { state_root_hex: String, contract_id_hex: String, message_hex: String, timestamp: u64 }
    #[derive(serde::Deserialize)]
    struct PassFix { document_json: String, document_proof_hex: String, key_proof_hex: String, public_inputs: PubInputsFix, ed25519: Ed25519Fix }
    #[derive(serde::Deserialize)]
    struct Fixtures { pass: PassFix }
    fn hex32(s: &str) -> [u8; 32] { let v = hex::decode(s).unwrap(); let mut out=[0u8;32]; out.copy_from_slice(&v); out }

    let fixtures: Fixtures = serde_json::from_str(include_str!("fixtures/PASS_AND_FAIL.json")).unwrap();
    let doc_proof = hex::decode(&fixtures.pass.document_proof_hex).unwrap();
    let key_proof = hex::decode(&fixtures.pass.key_proof_hex).unwrap();
    let pub_key = hex32(&fixtures.pass.ed25519.public_key_hex);
    let sig_r = hex32(&fixtures.pass.ed25519.signature_r_hex);
    let sig_s = hex32(&fixtures.pass.ed25519.signature_s_hex);
    let priv_key = hex32(&fixtures.pass.ed25519.private_key_hex);
    let message = hex::decode(&fixtures.pass.public_inputs.message_hex).unwrap();

    let witness = create_witness_from_platform_proofs(
        &doc_proof,
        &key_proof,
        fixtures.pass.document_json.as_bytes().to_vec(),
        &pub_key,
        &sig_r,
        &sig_s,
        &message,
        &priv_key,
    )
    .expect("fixture witness build");

    let mut config = STARKConfig::default();
    config.grinding_bits = 8;
    config.num_queries = 48;
    let prover = GroveSTARK::with_config(config);
    let public_inputs = PublicInputs {
        state_root: hex32(&fixtures.pass.public_inputs.state_root_hex),
        contract_id: hex32(&fixtures.pass.public_inputs.contract_id_hex),
        message_hash: hex32(&fixtures.pass.public_inputs.message_hex),
        timestamp: fixtures.pass.public_inputs.timestamp,
    };
    let proof = prover.prove(witness, public_inputs.clone()).expect("prove(pass)");
    let ok = prover.verify(&proof, &public_inputs).unwrap_or(false);
    assert!(ok, "Matching identity should verify");
}

