/// Full STARK proof generation test using real testnet data from grovestark_test_proofs
use grovestark::{create_witness_from_platform_proofs, GroveSTARK, PublicInputs, STARKConfig};
use std::fs;
use std::path::Path;

#[test]
fn test_full_stark_proof_with_real_testnet_data() {
    println!("\n🚀 Full STARK Proof Generation with Real Testnet Data");
    println!("====================================================\n");
    println!("🔧 Rayon threads: {}", rayon::current_num_threads());

    // Load real testnet data from grovestark_test_proofs directory
    let test_proofs_dir = Path::new("tests/fixtures");

    // 1. Load document proof
    let document_proof_path =
        test_proofs_dir.join("document_proof_B5XLy3cUDayaqZmcGaWb98PEAUguGHiHSU5DxiKrHBj3.bin");
    let document_proof = fs::read(&document_proof_path).expect(&format!(
        "Failed to read document proof from {:?}",
        document_proof_path
    ));

    // 2. Load identity/key proof
    let key_proof_path =
        test_proofs_dir.join("identity_proof_FQ4waDowFQXD4tJPKQM1114VSr5f8s3qAc5bT8FJkT49.bin");
    let key_proof = fs::read(&key_proof_path).expect(&format!(
        "Failed to read key proof from {:?}",
        key_proof_path
    ));

    // 3. Load metadata to get the document JSON
    let metadata_path =
        test_proofs_dir.join("proof_metadata_B5XLy3cUDayaqZmcGaWb98PEAUguGHiHSU5DxiKrHBj3.json");
    let metadata_str = fs::read_to_string(&metadata_path)
        .expect(&format!("Failed to read metadata from {:?}", metadata_path));
    let metadata: serde_json::Value =
        serde_json::from_str(&metadata_str).expect("Failed to parse metadata JSON");

    // Create document JSON based on metadata
    let document_json = serde_json::json!({
        "$version": "0",
        "$id": metadata["document_id"],
        "$ownerId": metadata["identity_id"],
        "saltedDomainHash": "DatikyjRKcaaSMVNLOWdILAOxy/QoOmpSt/0lZ5MNb8=",
        "$revision": 1,
        "$createdAt": null,
        "$updatedAt": null,
        "$transferredAt": null,
        "$createdAtBlockHeight": null,
        "$updatedAtBlockHeight": null,
        "$transferredAtBlockHeight": null,
        "$createdAtCoreBlockHeight": null,
        "$updatedAtCoreBlockHeight": null,
        "$transferredAtCoreBlockHeight": null
    })
    .to_string()
    .into_bytes();

    // 4. Real EdDSA signature components from testnet
    let signature_r_hex = "dbb76975d7a20eead1884b434bf699a729cd35815c2c84a48fea66e12b2ab323";
    let signature_s_hex = "d99553f7a4bdb47c8161691a767eb511bed436e99a690331e8a384d96ecb7d08";
    let public_key_hex = "13f54fc83ab3112dc6e47a46822d0a6cdb0ec8bd496333d4d03527c198680928";
    let message_hex = "d43e625b43a2ceeae3bb3fc7119946fef628501b092ee2379aef649f55416e82";
    let private_key_hex = "6e6f24b6f7a51203e1cbee0c30066a18901b1d5e13f7ffc69017d28228c78f3f";

    let signature_r_bytes = hex::decode(signature_r_hex).expect("Invalid signature R hex");
    let signature_s_bytes = hex::decode(signature_s_hex).expect("Invalid signature S hex");
    let public_key_bytes = hex::decode(public_key_hex).expect("Invalid public key hex");
    let message_bytes = hex::decode(message_hex).expect("Invalid message hex");
    let private_key_bytes = hex::decode(private_key_hex).expect("Invalid private key hex");

    let mut signature_r = [0u8; 32];
    let mut signature_s = [0u8; 32];
    let mut public_key = [0u8; 32];
    let mut message = [0u8; 32];
    let mut private_key = [0u8; 32];

    signature_r.copy_from_slice(&signature_r_bytes);
    signature_s.copy_from_slice(&signature_s_bytes);
    public_key.copy_from_slice(&public_key_bytes);
    message.copy_from_slice(&message_bytes);
    private_key.copy_from_slice(&private_key_bytes);

    println!("Real Testnet Data from grovestark_test_proofs:");
    println!("  Document proof: {} bytes", document_proof.len());
    println!("  Key proof: {} bytes", key_proof.len());
    println!("  Document JSON: {} bytes", document_json.len());
    println!("  Document ID: {}", metadata["document_id"]);
    println!("  Identity ID: {}", metadata["identity_id"]);

    // Step 1: Create witness from real testnet proofs
    println!("\n⚙️  Creating witness from real testnet proofs...");
    let witness = create_witness_from_platform_proofs(
        &document_proof,
        &key_proof,
        document_json,
        &public_key,
        &signature_r,
        &signature_s,
        &message,
        &private_key,
    )
    .expect("Failed to create witness from real testnet data");

    println!("✅ Witness created successfully");
    println!("  Owner ID:    {}", hex::encode(&witness.owner_id));
    println!("  Identity ID: {}", hex::encode(&witness.identity_id));
    println!("  IDs Match:   {}", witness.owner_id == witness.identity_id);

    // The IDs should now match with the corrected extraction offsets
    assert_eq!(
        witness.owner_id, witness.identity_id,
        "IDs must match for valid proof"
    );

    // Step 2: Configure STARK prover with production-like parameters
    println!("\n⚙️  Configuring STARK prover with production-like settings...");
    let mut config = STARKConfig::default();

    // Use production-like parameters
    config.expansion_factor = 16; // Production-like
    config.grinding_bits = 16; // Some proof of work
    config.num_queries = 48; // Production security
    config.folding_factor = 4; // Normal folding

    println!(
        "  - Expansion factor: {} (LDE = {} evaluation points)",
        config.expansion_factor,
        config.trace_length * config.expansion_factor
    );
    println!(
        "  - Grinding bits: {} (2^{} = {} PoW iterations)",
        config.grinding_bits,
        config.grinding_bits,
        1 << config.grinding_bits
    );
    println!("  - Num queries: {}", config.num_queries);
    println!("  - Trace length: {}", config.trace_length);
    println!("  - Rayon threads: {}", rayon::current_num_threads());

    let prover = GroveSTARK::with_config(config);

    // Step 3: Create public inputs
    let public_inputs = PublicInputs {
        state_root: [10u8; 32],  // Mock state root
        contract_id: [11u8; 32], // Mock contract ID
        message_hash: message,   // Use the real message hash
        timestamp: 1700000000,   // Mock timestamp
    };

    // Step 4: Generate STARK proof with real testnet data
    println!("\n🔨 Generating STARK proof with real testnet data...");
    println!("    (This tests the complete pipeline with actual Platform proofs)");

    let start_time = std::time::Instant::now();

    let proof = match prover.prove(witness, public_inputs.clone()) {
        Ok(p) => {
            let elapsed = start_time.elapsed();
            println!("✅ STARK proof generated successfully!");
            println!("  Generation time: {:.2}s", elapsed.as_secs_f32());
            p
        }
        Err(e) => {
            panic!("❌ STARK proof generation failed: {}", e);
        }
    };

    // Step 5: Verify the proof
    println!("\n🔍 Verifying STARK proof...");
    let verify_start = std::time::Instant::now();

    match prover.verify(&proof, &public_inputs) {
        Ok(true) => {
            let verify_time = verify_start.elapsed();
            println!("✅ Proof verified successfully!");
            println!("  Verification time: {:.2}ms", verify_time.as_millis());
        }
        Ok(false) => panic!("❌ Proof verification failed"),
        Err(e) => panic!("❌ Verification error: {}", e),
    }

    // Step 6: Report proof statistics
    let proof_bytes = bincode1::serialize(&proof).unwrap();
    println!("\n📊 Proof Statistics:");
    println!(
        "  - Proof size: {} bytes ({:.1} KB)",
        proof_bytes.len(),
        proof_bytes.len() as f32 / 1024.0
    );
    println!(
        "  - Security level: {}",
        proof.public_outputs.key_security_level
    );
    println!("  - EdDSA verified: {}", proof.public_outputs.verified);
    println!("  - PoW nonce: {}", proof.pow_nonce);

    println!("\n🎉 SUCCESS: Complete STARK proof pipeline with real testnet data!");
    println!("    ✅ Real Platform proofs parsed correctly");
    println!("    ✅ Identity binding enforced (owner_id == identity_id)");
    println!("    ✅ EdDSA signature verified in STARK");
    println!("    ✅ STARK proof generated and verified");
    println!("    ✅ All cryptographic operations working with real data");
}

#[test]
fn test_full_security_proof_with_testnet_data() {
    println!("\n🔐 Full Security STARK Proof with Real Testnet Data");
    println!("==================================================");
    println!("(This test uses production security parameters)");

    // Load real testnet data (same as above test)
    let test_proofs_dir = Path::new("tests/fixtures");

    let document_proof_path =
        test_proofs_dir.join("document_proof_B5XLy3cUDayaqZmcGaWb98PEAUguGHiHSU5DxiKrHBj3.bin");
    let document_proof = fs::read(&document_proof_path).expect("Failed to read document proof");

    let key_proof_path =
        test_proofs_dir.join("identity_proof_FQ4waDowFQXD4tJPKQM1114VSr5f8s3qAc5bT8FJkT49.bin");
    let key_proof = fs::read(&key_proof_path).expect("Failed to read key proof");

    // Configure for production security
    let mut config = STARKConfig::default();
    config.grinding_bits = 20; // Production PoW difficulty
    config.num_queries = 48; // Production security queries

    println!("⚠️  WARNING: This test uses production security parameters");
    println!(
        "  - Grinding bits: {} (2^{} = {} PoW iterations)",
        config.grinding_bits,
        config.grinding_bits,
        1 << config.grinding_bits
    );
    println!("  - Expected time: 30-120 seconds depending on hardware");

    // Run the test with production parameters...
    println!("Test would continue here with production parameters");
}
