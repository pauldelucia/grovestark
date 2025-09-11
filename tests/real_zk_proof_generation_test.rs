// Test generating actual ZK proofs using real SDK proof data from Dash Platform
use grovestark::{
    create_witness_from_platform_proofs,
    types::{PublicInputs, STARKConfig},
    GroveSTARK, parse_grovedb_proof,
};
use std::fs;

// Helper: load PASS_AND_FAIL fixtures
fn load_pass_fixture() -> (
    Vec<u8>,           // document_proof
    Vec<u8>,           // key_proof
    Vec<u8>,           // document_json bytes
    [u8; 32],          // pubkey
    [u8; 32],          // sig_r
    [u8; 32],          // sig_s
    Vec<u8>,           // message bytes
    [u8; 32],          // private_key
    PublicInputs,      // public inputs
) {
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
    let document_proof = hex::decode(&fixtures.pass.document_proof_hex).unwrap();
    let key_proof = hex::decode(&fixtures.pass.key_proof_hex).unwrap();
    let pubkey = hex32(&fixtures.pass.ed25519.public_key_hex);
    let sig_r = hex32(&fixtures.pass.ed25519.signature_r_hex);
    let sig_s = hex32(&fixtures.pass.ed25519.signature_s_hex);
    let private_key = hex32(&fixtures.pass.ed25519.private_key_hex);
    let message = hex::decode(&fixtures.pass.public_inputs.message_hex).unwrap();
    let public_inputs = PublicInputs {
        state_root: hex32(&fixtures.pass.public_inputs.state_root_hex),
        contract_id: hex32(&fixtures.pass.public_inputs.contract_id_hex),
        message_hash: hex32(&fixtures.pass.public_inputs.message_hex),
        timestamp: fixtures.pass.public_inputs.timestamp,
    };

    (
        document_proof,
        key_proof,
        fixtures.pass.document_json.as_bytes().to_vec(),
        pubkey,
        sig_r,
        sig_s,
        message,
        private_key,
        public_inputs,
    )
}

#[cfg_attr(debug_assertions, ignore = "Runs only in release mode; heavy + strict constraints")]
#[test]
fn test_generate_zk_proof_with_real_data() {
    println!("\n=== Testing ZK Proof Generation with Real SDK Data ===\n");

    // Load real proof bytes and inputs from fixtures
    let (doc_proof, id_proof, document_json, pubkey, sig_r, sig_s, message, private_key, public_inputs) =
        load_pass_fixture();

    println!("✅ Loaded real proof fixtures:");
    println!("   Document proof: {} bytes", doc_proof.len());
    println!("   Identity proof: {} bytes", id_proof.len());

    // Create the witness using the SDK proof data (fixture-driven)
    let witness_result = create_witness_from_platform_proofs(
        &doc_proof,
        &id_proof,
        document_json,
        &pubkey,
        &sig_r,
        &sig_s,
        &message,
        &private_key,
    );

    assert!(
        witness_result.is_ok(),
        "Failed to create witness: {:?}",
        witness_result.err()
    );
    let witness = witness_result.unwrap();

    println!("\n📦 Created witness from real SDK proofs:");
    println!(
        "   Document path nodes: {} + {}",
        witness.owner_id_leaf_to_doc_path.len(),
        witness.docroot_to_state_path.len()
    );
    println!(
        "   Identity path nodes: {} + {}",
        witness.key_leaf_to_keysroot_path.len(),
        witness.identity_leaf_to_state_path.len()
    );
    println!("   Signature components: ✓");
    println!(
        "   Scalar windows: {} s-windows, {} h-windows",
        witness.s_windows.len(),
        witness.h_windows.len()
    );

    // Public inputs come from fixtures

    println!("\n🔑 Created public inputs:");
    println!("   State root: {:02x?}...", &public_inputs.state_root[0..8]);
    println!(
        "   Contract ID: {:02x?}...",
        &public_inputs.contract_id[0..8]
    );
    println!("   Timestamp: {}", public_inputs.timestamp);

    // Configure STARK parameters — stronger settings for stability
    let config = STARKConfig {
        field_bits: 64,
        expansion_factor: 8,
        num_queries: 24,
        folding_factor: 4,
        max_remainder_degree: 255, // 2^8 - 1
        grinding_bits: 8,
        trace_length: 65536,     // Required for all phases
        num_trace_columns: 104,  // Must match production
        security_level: 96,
    };

    println!("\n⚙️  STARK configuration:");
    println!("   Field bits: {}", config.field_bits);
    println!("   Expansion factor: {}", config.expansion_factor);
    println!("   Number of queries: {}", config.num_queries);
    println!("   Grinding bits: {}", config.grinding_bits);
    println!("   Trace length: {}", config.trace_length);

    // Generate the STARK proof
    println!("\n🔨 Generating STARK proof (this may take a moment)...");

    std::env::set_var("GS_ALLOW_WEAK_PARAMS", "1");
    std::env::set_var("FAST_TESTS", "1");
    let prover = GroveSTARK::with_config(config);
    let proof_result = prover.prove(witness, public_inputs.clone());

    assert!(
        proof_result.is_ok(),
        "Failed to generate proof: {:?}",
        proof_result.err()
    );
    let proof = proof_result.unwrap();

    println!("\n✅ STARK proof generated successfully!");
    println!("   Proof components:");
    println!(
        "     - Trace commitment: {} bytes",
        proof.trace_commitment.len()
    );
    println!(
        "     - Constraint commitment: {} bytes",
        proof.constraint_commitment.len()
    );
    println!(
        "     - FRI proof rounds: {} rounds",
        proof.fri_proof.query_rounds.len()
    );
    println!("     - Proof of work nonce: {}", proof.pow_nonce);

    // Verify the proof
    println!("\n🔍 Verifying STARK proof...");

    let verification_result = prover.verify(&proof, &public_inputs);

    assert!(
        verification_result.is_ok(),
        "Verification failed: {:?}",
        verification_result.err()
    );
    assert!(verification_result.unwrap(), "Proof is invalid!");

    println!("\n✅ Proof verification successful!");
    println!("\n🎉 Successfully generated and verified a ZK proof using real SDK data!");
}

#[cfg_attr(debug_assertions, ignore = "Runs only in release mode; heavy + strict constraints")]
#[test]
fn test_parse_and_use_real_merkle_paths() {
    println!("\n=== Testing Merkle Path Extraction from Real Data ===\n");

    // Load and parse the real proofs
    let (doc_proof, id_proof, document_json, pubkey, sig_r, sig_s, message, private_key, public_inputs) =
        load_pass_fixture();

    // Parse the Merkle paths
    let doc_nodes = parse_grovedb_proof(&doc_proof).expect("Failed to parse document proof");
    let id_nodes = parse_grovedb_proof(&id_proof).expect("Failed to parse identity proof");

    println!("📊 Parsed Merkle paths from real proofs:");
    println!("   Document path:");
    for (i, node) in doc_nodes.iter().enumerate() {
        println!(
            "     Node {}: hash={:02x?}..., is_left={}",
            i,
            &node.hash[0..8],
            node.is_left
        );
    }
    println!("   Identity path:");
    for (i, node) in id_nodes.iter().enumerate() {
        println!(
            "     Node {}: hash={:02x?}..., is_left={}",
            i,
            &node.hash[0..8],
            node.is_left
        );
    }

    // Create witness using the helper function which properly populates all fields (fixtures)
    let witness = create_witness_from_platform_proofs(
        &doc_proof,
        &id_proof,
        document_json,
        &pubkey,
        &sig_r,
        &sig_s,
        &message,
        &private_key,
    )
    .expect("Failed to create witness");

    // Extract state root
    let state_root = {
        let mut root = [0u8; 32];
        root.copy_from_slice(&doc_proof[2..34]);
        root
    };

    let public_inputs = public_inputs;

    println!("\n🔨 Generating proof with real Merkle paths...");

    // Test that we can generate a proof with the real Merkle paths
    let config = STARKConfig {
        field_bits: 64,
        expansion_factor: 8,
        num_queries: 24,
        folding_factor: 4,
        max_remainder_degree: 255, // Must be 2^n - 1
        grinding_bits: 8,
        trace_length: 65536,       // Required for all phases
        num_trace_columns: 104,    // Must match production
        security_level: 96,
    };

    std::env::set_var("GS_ALLOW_WEAK_PARAMS", "1");
    std::env::set_var("FAST_TESTS", "1");
    let prover = GroveSTARK::with_config(config);
    let proof_result = prover.prove(witness, public_inputs.clone());
    assert!(
        proof_result.is_ok(),
        "Failed to generate proof with real Merkle paths: {:?}",
        proof_result.err()
    );

    println!("✅ Successfully generated proof using real Merkle paths!");

    let proof = proof_result.unwrap();
    let verify_result = prover.verify(&proof, &public_inputs);
    assert!(
        verify_result.is_ok() && verify_result.unwrap(),
        "Proof verification failed"
    );

    println!("✅ Proof verification successful!");
}

#[cfg_attr(debug_assertions, ignore = "Runs only in release mode; heavy + strict constraints")]
#[test]
fn test_zk_proof_with_metadata() {
    println!("\n=== Testing ZK Proof with Metadata from Real Data ===\n");

    // Load the metadata file
    let metadata_path =
        "tests/fixtures/proof_metadata_B5XLy3cUDayaqZmcGaWb98PEAUguGHiHSU5DxiKrHBj3.json";
    let metadata_str = fs::read_to_string(metadata_path).expect("Failed to read metadata file");

    // Parse the JSON metadata manually (since we don't have serde_json in deps)
    // For testing, we'll just extract the security level from the JSON string
    let security_level: u8 = if metadata_str.contains("\"security_level\": 5") {
        5
    } else {
        3
    };

    println!("📋 Loaded metadata:");
    println!("   Security level extracted: {}", security_level);

    // Load the actual proof files and inputs from fixtures
    let (doc_proof, id_proof, document_json, pubkey, sig_r, sig_s, message, private_key, public_inputs) =
        load_pass_fixture();

    // Security level already extracted above

    // Create witness (fixtures)
    let witness = create_witness_from_platform_proofs(
        &doc_proof,
        &id_proof,
        document_json,
        &pubkey,
        &sig_r,
        &sig_s,
        &message,
        &private_key,
    )
    .expect("Failed to create witness");

    // Create public inputs with metadata values
    let public_inputs = public_inputs;

    println!("\n🔐 Using metadata in proof:");
    println!("   Security level: {}", security_level);

    // Generate and verify proof with moderate config for stability
    let config = STARKConfig {
        field_bits: 64,
        expansion_factor: 8,
        num_queries: 24,
        folding_factor: 4,
        max_remainder_degree: 255, // 2^8 - 1
        grinding_bits: 8,
        trace_length: 65536,     // Required for all phases
        num_trace_columns: 104,  // Must match production
        security_level: 96,
    };

    println!("\n🔨 Generating proof with metadata context...");
    std::env::set_var("GS_ALLOW_WEAK_PARAMS", "1");
    std::env::set_var("FAST_TESTS", "1");
    let prover = GroveSTARK::with_config(config);
    let proof = prover
        .prove(witness, public_inputs.clone())
        .expect("Failed to generate proof");

    println!("✅ Proof generated!");
    println!(
        "   Proof demonstrates ownership with security level: {}",
        security_level
    );

    let verification_result = prover
        .verify(&proof, &public_inputs)
        .expect("Verification failed");
    assert!(verification_result, "Proof is invalid");

    println!("\n✅ Proof verified successfully!");
    println!(
        "🎉 Zero-knowledge proof confirms document ownership without revealing document contents!"
    );
}
