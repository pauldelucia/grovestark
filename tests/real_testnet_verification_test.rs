use grovestark::{GroveSTARK, PublicInputs, STARKConfig};

// Use PASS_AND_FAIL fixtures to create a valid witness and inputs
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

#[test]
fn test_real_testnet_proof_verification() {
    println!("Testing real testnet proof generation and verification (fixtures)...");

    let (witness, public_inputs) = load_pass_fixture();

    // Generate proof with default config
    let prover = GroveSTARK::with_config(STARKConfig::default());

    let proof = prover
        .prove(witness, public_inputs.clone())
        .expect("proof generation from fixtures");
    assert!(proof.public_outputs.verified, "EdDSA must verify");

    let result = prover.verify(&proof, &public_inputs).unwrap();
    assert!(result, "Fixture proof should verify");
}

#[test]
fn test_real_testnet_witness_creation() {
    println!("Testing witness creation from fixtures...");
    let (witness, _pi) = load_pass_fixture();

    // Basic sanity checks
    assert_eq!(witness.owner_id, witness.identity_id, "IDs must match");
    assert_ne!(witness.signature_r, [0u8; 32]);
    assert_ne!(witness.signature_s, [0u8; 32]);
    assert_ne!(witness.public_key_a, [0u8; 32]);
    assert!(!witness.document_cbor.is_empty());
}
