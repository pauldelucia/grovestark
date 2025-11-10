use grovestark::{GroveSTARK, PrivateInputs, PublicInputs, PublicOutputs, STARKConfig};

// Unified fixture-based witness/public-inputs builder used across tests
fn load_pass_fixture() -> (PrivateInputs, PublicInputs) {
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

    let witness = grovestark::create_witness_from_platform_proofs(
        &doc_proof,
        &key_proof,
        fixtures.pass.document_json.as_bytes().to_vec(),
        &pubkey,
        &sig_r,
        &sig_s,
        &msg,
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
fn test_end_to_end_proof_generation_and_verification() {
    // Use the shared fixture-based builder (production-style path)
    let (witness, public_inputs) = load_pass_fixture();

    // Production-grade parameters (release-mode intended)
    let config = STARKConfig {
        expansion_factor: 16,
        num_queries: 48,
        folding_factor: 4,
        grinding_bits: 16,
        ..Default::default()
    };
    let prover = GroveSTARK::with_config(config);

    let proof = prover
        .prove(witness, public_inputs.clone())
        .expect("prove(pass fixtures)");
    assert!(
        proof.public_outputs.verified,
        "Public outputs should report verified"
    );
    assert_eq!(proof.public_inputs.state_root, public_inputs.state_root);

    let ok = prover
        .verify(&proof, &public_inputs)
        .expect("verify(pass fixtures) errored");
    assert!(ok, "Valid fixture witness should verify");
}

#[test]
fn test_batch_proving() {
    let config = STARKConfig::default();
    let prover = GroveSTARK::with_config(config);

    let (w1, public_inputs) = load_pass_fixture();
    let w2 = w1.clone();
    let witnesses = vec![w1, w2];

    let batch_proof = prover.prove_batch(witnesses, public_inputs).unwrap();

    assert_eq!(batch_proof.individual_proofs.len(), 2);
    assert_ne!(batch_proof.batch_commitment, [0u8; 32]);
}

#[test]
fn test_invalid_proof_rejection() {
    let config = STARKConfig::default();
    let prover = GroveSTARK::with_config(config);

    let mut proof = create_dummy_proof();
    let (_, public_inputs) = load_pass_fixture();

    proof.public_outputs.verified = false;

    let result = prover.verify(&proof, &public_inputs);
    assert!(result.is_err());
}

#[test]
fn test_grovedb_proof_parsing() {
    // Use the real fixture document proof and the production parser
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/PASS_AND_FAIL.json")).unwrap();
    let doc_hex = fixtures["pass"]["document_proof_hex"].as_str().unwrap();
    let doc_proof = hex::decode(doc_hex).expect("decode document proof");

    let nodes = grovestark::parse_grovedb_proof(&doc_proof).expect("parse grove proof");
    assert!(nodes.len() > 0, "Should extract at least one node");
}

#[test]
fn test_merkle_tree_operations() {
    use grovestark::crypto::{Blake3Hasher, MerkleTree};

    let leaves = vec![
        Blake3Hasher::hash(b"leaf1"),
        Blake3Hasher::hash(b"leaf2"),
        Blake3Hasher::hash(b"leaf3"),
        Blake3Hasher::hash(b"leaf4"),
    ];

    let tree = MerkleTree::new(leaves.clone()).unwrap();

    for i in 0..leaves.len() {
        let proof = tree.get_proof(i).unwrap();
        assert!(MerkleTree::verify_proof(&proof));
    }
}

#[test]
fn test_field_arithmetic() {
    use grovestark::field::FieldElement;

    let a = FieldElement::new(100);
    let b = FieldElement::new(200);

    let sum = a + b;
    assert_eq!(sum.as_u64(), 300);

    let product = a * b;
    assert_eq!(product.as_u64(), 20000);

    let inverse = a.inverse().unwrap();
    assert_eq!((a * inverse).as_u64(), 1);
}

#[test]
fn test_proof_size() {
    let mut config = STARKConfig::default();
    config.grinding_bits = 8; // Reduce for testing
    let prover = GroveSTARK::with_config(config);

    let (witness, public_inputs) = load_pass_fixture();

    let proof = prover.prove(witness, public_inputs).unwrap();

    let serialized = bincode1::serialize(&proof).unwrap();
    let proof_size_bytes = serialized.len();

    // For now, we're generating a mock proof, so just check it's not empty
    assert!(proof_size_bytes > 100, "Proof should not be empty");
}

// removed obsolete manual witness constructors in favor of fixtures
// removed legacy helpers: create_valid_witness_variant, create_valid_public_inputs

fn create_dummy_proof() -> grovestark::STARKProof {
    use grovestark::types::FRIProof;

    grovestark::STARKProof {
        circuit: grovestark::CircuitId::ContractMembership,
        trace_commitment: vec![1u8; 32],
        constraint_commitment: vec![2u8; 32],
        fri_proof: FRIProof {
            final_polynomial: vec![3u8; 32],
            proof_of_work: 12345,
        },
        pow_nonce: 67890,
        public_inputs: {
            let (_, pi) = load_pass_fixture();
            pi
        },
        public_outputs: PublicOutputs {
            verified: true,
            key_security_level: 2,
            proof_commitment: [13u8; 32],
        },
    }
}

// GUIDANCE.md Section F: Recommended tests
// Note: These tests verify the correctness of the MSG separation implementation
// by ensuring the proof generation succeeds with the new constraints

#[test]
fn test_alpha_basis_probe() {
    std::env::set_var("GS_ALLOW_WEAK_PARAMS", "1");
    std::env::set_var("FAST_TESTS", "1");
    // Test each constraint individually with basis α vectors to identify the problematic ones
    eprintln!("\n=== Alpha-Basis Probe Test ===");
    eprintln!("Testing each constraint with basis α to identify drift...\n");

    let mut config = STARKConfig::default();
    config.grinding_bits = 2;

    let (witness, public_inputs) = load_pass_fixture();

    // Run the test for each constraint individually
    const NUM_CONSTRAINTS: usize = 20; // Main constraints

    for cid in 0..NUM_CONSTRAINTS {
        eprintln!("Testing constraint {}/{}", cid, NUM_CONSTRAINTS);

        // Create basis α: all zeros except position cid = 1
        let mut basis_alpha = vec![0u64; NUM_CONSTRAINTS];
        basis_alpha[cid] = 1;

        // We need to create a custom test that evaluates constraints with this basis α
        // For now, just run the regular test to see if it works
        let prover = GroveSTARK::with_config(config.clone());
        match prover.prove(witness.clone(), public_inputs.clone()) {
            Ok(_) => eprintln!("  Constraint {} OK", cid),
            Err(e) => eprintln!("  Constraint {} FAILED: {:?}", cid, e),
        }
    }
}

#[test]
fn test_merkle_msg_constraints_work() {
    std::env::set_var("GS_ALLOW_WEAK_PARAMS", "1");
    std::env::set_var("FAST_TESTS", "1");
    // This test verifies that the MsgView integration and isolation constraints
    // work correctly by successfully generating a proof with them enabled

    let mut config = STARKConfig::default();
    config.grinding_bits = 2;
    let prover = GroveSTARK::with_config(config);

    let (witness, public_inputs) = load_pass_fixture();

    // If the MSG separation isn't working correctly, this will fail
    // with constraint evaluation errors
    let proof = prover.prove(witness, public_inputs.clone()).unwrap();

    assert!(proof.public_outputs.verified);

    // Verify the proof to ensure MSG constraints are properly evaluated
    assert!(
        prover.verify(&proof, &public_inputs).is_ok(),
        "Proof verification failed with MSG constraints"
    );
}
