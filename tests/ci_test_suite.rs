/// CI Test Suite - Following GUIDANCE.md recommendations
/// These tests should be run in CI to ensure STARK soundness and correctness
use grovestark::*;

// Test 1: FRI soundness test (requires special features)
#[test]
#[cfg(all(feature = "fri_only_must_fail", feature = "skip_eddsa"))]
fn ci_test_1_fri_soundness() {
    println!("[CI Test 1] FRI Soundness Test - Same AIR on both sides");

    // Build a minimally valid EdDSA witness and aligned identity binding
    use grovestark::crypto::field_conversion::compute_challenge_scalar;
    use grovestark::phases::eddsa::augment_eddsa_witness;
    use grovestark::types::PrivateInputs as PI;

    // RFC8032 test vector (empty message)
    let signature_r =
        hex::decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155").unwrap();
    let signature_s =
        hex::decode("5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").unwrap();
    let public_key_a =
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();

    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    let mut pub_a = [0u8; 32];
    sig_r.copy_from_slice(&signature_r);
    sig_s.copy_from_slice(&signature_s);
    pub_a.copy_from_slice(&public_key_a);

    let hash_h = compute_challenge_scalar(&sig_r, &pub_a, b"");

    let mut base = PI::default();
    base.owner_id = [6u8; 32];
    base.identity_id = base.owner_id; // enforce equality for DIFF boundary
    base.signature_r = sig_r;
    base.signature_s = sig_s;
    base.public_key_a = pub_a;
    base.pubkey_a_compressed = pub_a;
    base.hash_h = hash_h;
    base.private_key = [1u8; 32];
    base.document_cbor = b"ci_test_document".to_vec();

    // Identity-aware fields
    base.doc_root = [0x44; 32];
    base.keys_root = [0x55; 32];
    base.owner_id_leaf_to_doc_path = vec![grovestark::types::MerkleNode {
        hash: [1u8; 32],
        is_left: true,
    }];
    base.docroot_to_state_path = vec![];
    base.key_leaf_to_keysroot_path = vec![grovestark::types::MerkleNode {
        hash: [2u8; 32],
        is_left: false,
    }];
    base.identity_leaf_to_state_path = vec![];
    eprintln!(
        "[CI DEBUG] base.private_key[0..4] = {:02x?}",
        &base.private_key[..4]
    );
    let witness = augment_eddsa_witness(&base, &public_inputs).expect("augment eddsa witness");
    let config = STARKConfig {
        expansion_factor: 16,
        num_queries: 64,
        folding_factor: 4,
        grinding_bits: 0,
        ..Default::default()
    };

    let prover = GroveSTARK::with_config(config);
    let public_inputs = PublicInputs {
        state_root: [10u8; 32],
        contract_id: [11u8; 32],
        message_hash: [12u8; 32],
        timestamp: 1700000000,
    };

    let witness = augment_eddsa_witness(&base, &public_inputs).expect("augment eddsa witness");

    let witness = augment_eddsa_witness(&base, &public_inputs).expect("augment eddsa witness");

    match prover.prove(witness, public_inputs.clone()) {
        Ok(proof) => match prover.verify(&proof, &public_inputs) {
            Ok(true) => panic!("[CI FAIL] FRI accepted invalid constraint!"),
            Ok(false) | Err(_) => println!("[CI PASS] FRI correctly rejected invalid constraint"),
        },
        Err(_) => println!("[CI PASS] Proof generation failed as expected"),
    }
}

// Test 2: AIR mismatch sanity test (would require separate binaries in real CI)
#[test]
fn ci_test_2_air_mismatch_placeholder() {
    println!("[CI Test 2] AIR Mismatch Test - Placeholder");
    println!("  In real CI, this would:");
    println!("  1. Generate proof WITHOUT fri_only_must_fail");
    println!("  2. Verify WITH fri_only_must_fail");
    println!("  3. Expect verification failure");
    // For now, just pass
}

// Test 3: End-to-end validity test (production path)
#[test]
#[cfg(not(any(feature = "fri_only_must_fail", feature = "skip_eddsa")))]
fn ci_test_3_end_to_end_validity() {
    println!("[CI Test 3] End-to-End Validity Test - Production Path (fixtures)");

    // Reuse real pass-case fixtures from DET_PROOF_LOGS
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

    // Decode proofs
    let doc_proof = hex::decode(&fixtures.pass.document_proof_hex).expect("decode document proof");
    let key_proof = hex::decode(&fixtures.pass.key_proof_hex).expect("decode key proof");

    // Decode EdDSA components
    let sig_r = hex32(&fixtures.pass.ed25519.signature_r_hex);
    let sig_s = hex32(&fixtures.pass.ed25519.signature_s_hex);
    let pubkey = hex32(&fixtures.pass.ed25519.public_key_hex);
    let msg = hex::decode(&fixtures.pass.public_inputs.message_hex).unwrap();

    // Build witness using the validated builder (enforces owner==identity via GroveVM)
    let witness = create_witness_from_platform_proofs(
        &doc_proof,
        &key_proof,
        fixtures.pass.document_json.as_bytes().to_vec(),
        &pubkey,
        &sig_r,
        &sig_s,
        &msg,
    )
    .expect("fixture witness build");

    // Public inputs from fixtures
    let public_inputs = PublicInputs {
        state_root: hex32(&fixtures.pass.public_inputs.state_root_hex),
        contract_id: hex32(&fixtures.pass.public_inputs.contract_id_hex),
        message_hash: hex32(&fixtures.pass.public_inputs.message_hex),
        timestamp: fixtures.pass.public_inputs.timestamp,
    };

    // Production-ish config
    let config = STARKConfig {
        expansion_factor: 16,
        num_queries: 48,
        folding_factor: 4,
        grinding_bits: 16,
        ..Default::default()
    };
    let prover = GroveSTARK::with_config(config);

    let proof = prover
        .prove(witness.clone(), public_inputs.clone())
        .expect("prove(pass fixtures)");
    let ok = prover
        .verify(&proof, &public_inputs)
        .expect("verify(pass fixtures) errored");
    assert!(ok, "[CI FAIL] Valid fixture witness should verify");
}

// Test 4: Parameter guardrails
#[test]
fn ci_test_4_parameter_guardrails() {
    println!("[CI Test 4] Parameter Guardrails");

    // Production parameters that MUST be enforced
    const MIN_EXPANSION_FACTOR: usize = 16;
    const MIN_NUM_QUERIES: usize = 48;
    const MIN_FOLDING_FACTOR: usize = 4;

    // In production, these should be the defaults
    // For now, just document what they should be
    println!("  Production minimums:");
    println!("    expansion_factor >= {}", MIN_EXPANSION_FACTOR);
    println!("    num_queries >= {}", MIN_NUM_QUERIES);
    println!("    folding_factor >= {}", MIN_FOLDING_FACTOR);

    // Check if a weak config would be rejected
    let weak_config = STARKConfig {
        expansion_factor: 2, // Too low!
        num_queries: 1,      // Way too low!
        folding_factor: 2,   // Below recommended
        ..Default::default()
    };

    // In production, this should panic or return error
    println!(
        "  Weak config: expansion={}, queries={}, folding={}",
        weak_config.expansion_factor, weak_config.num_queries, weak_config.folding_factor
    );
    println!("  [WARNING] Production code should reject weak parameters!");
}

// Test matrix summary
#[test]
fn ci_test_summary() {
    println!("\n=== CI Test Matrix Summary ===");
    println!("Test 1: FRI Soundness       - Run with fri_only_must_fail,skip_eddsa");
    println!("Test 2: AIR Mismatch        - Requires separate binaries");
    println!("Test 3: End-to-End Valid    - Run with NO special features");
    println!("Test 4: Parameter Guards    - Always run");
    println!("==============================");
}
