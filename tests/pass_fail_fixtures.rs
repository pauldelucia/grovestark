use grovestark::{create_witness_from_platform_proofs, GroveSTARK, PublicInputs, STARKConfig};

fn hex32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("hex32 decode");
    assert_eq!(v.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn default_fast_config() -> STARKConfig {
    std::env::set_var("GS_ALLOW_WEAK_PARAMS", "1");
    std::env::set_var("FAST_TESTS", "1");
    let mut cfg = STARKConfig::default();
    cfg.grinding_bits = 0;
    cfg.num_queries = 8;
    cfg.expansion_factor = 16;
    cfg
}

#[test]
fn test_fixture_end_to_end_valid() {
    #[derive(serde::Deserialize)]
    struct Ed25519Fix {
        public_key_hex: String,
        signature_r_hex: String,
        signature_s_hex: String,
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

    let fixtures: Fixtures =
        serde_json::from_str(include_str!("fixtures/PASS_AND_FAIL.json")).unwrap();
    let document_proof =
        hex::decode(&fixtures.pass.document_proof_hex).expect("Invalid document proof hex");
    let key_proof = hex::decode(&fixtures.pass.key_proof_hex).expect("Invalid key proof hex");

    let sig_r = hex32(&fixtures.pass.ed25519.signature_r_hex);
    let sig_s = hex32(&fixtures.pass.ed25519.signature_s_hex);
    let pub_key = hex32(&fixtures.pass.ed25519.public_key_hex);
    let msg = hex::decode(&fixtures.pass.public_inputs.message_hex).unwrap();

    let witness = create_witness_from_platform_proofs(
        &document_proof,
        &key_proof,
        fixtures.pass.document_json.as_bytes().to_vec(),
        &pub_key,
        &sig_r,
        &sig_s,
        &msg,
    )
    .expect("validated witness");

    let public_inputs = PublicInputs {
        state_root: hex32(&fixtures.pass.public_inputs.state_root_hex),
        contract_id: hex32(&fixtures.pass.public_inputs.contract_id_hex),
        message_hash: hex32(&fixtures.pass.public_inputs.message_hex),
        timestamp: fixtures.pass.public_inputs.timestamp,
    };

    let prover = GroveSTARK::with_config(default_fast_config());
    let proof = prover
        .prove(witness.clone(), public_inputs.clone())
        .expect("prover(prove)");
    let ok = prover
        .verify(&proof, &public_inputs)
        .expect("prover(verify)");
    assert!(ok, "Valid fixture witness should verify");
}

#[test]
fn test_fixture_end_to_end_invalid() {
    #[derive(serde::Deserialize)]
    struct Ed25519Fix {
        public_key_hex: String,
        signature_r_hex: String,
        signature_s_hex: String,
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
        public_inputs: PubInputsFix,
        ed25519: Ed25519Fix,
    }
    #[derive(serde::Deserialize)]
    struct FailFix {
        key_proof_hex_fail: String,
    }
    #[derive(serde::Deserialize)]
    struct Fixtures {
        pass: PassFix,
        fail: FailFix,
    }

    let fixtures: Fixtures =
        serde_json::from_str(include_str!("fixtures/PASS_AND_FAIL.json")).unwrap();
    let document_proof =
        hex::decode(&fixtures.pass.document_proof_hex).expect("Invalid document proof hex");
    let mismatched_key_proof =
        hex::decode(&fixtures.fail.key_proof_hex_fail).expect("Invalid mismatched key proof hex");

    let sig_r = hex32(&fixtures.pass.ed25519.signature_r_hex);
    let sig_s = hex32(&fixtures.pass.ed25519.signature_s_hex);
    let pub_key = hex32(&fixtures.pass.ed25519.public_key_hex);
    let msg = hex::decode(&fixtures.pass.public_inputs.message_hex).unwrap();

    // Build using no-validation path to proceed with negative test
    let witness = create_witness_from_platform_proofs(
        &document_proof,
        &mismatched_key_proof,
        fixtures.pass.document_json.as_bytes().to_vec(),
        &pub_key,
        &sig_r,
        &sig_s,
        &msg,
    )
    .expect("no-validation witness");

    let public_inputs = PublicInputs {
        state_root: hex32(&fixtures.pass.public_inputs.state_root_hex),
        contract_id: hex32(&fixtures.pass.public_inputs.contract_id_hex),
        message_hash: hex32(&fixtures.pass.public_inputs.message_hex),
        timestamp: fixtures.pass.public_inputs.timestamp,
    };

    let prover = GroveSTARK::with_config(default_fast_config());
    match prover.prove(witness.clone(), public_inputs.clone()) {
        Err(_) => { /* Prove-time rejection acceptable */ }
        Ok(proof) => match prover.verify(&proof, &public_inputs) {
            Ok(valid) => assert!(!valid, "Invalid proof should not verify"),
            Err(_) => { /* Verify-time error acceptable */ }
        },
    }
}
