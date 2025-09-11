/// Simple test with real testnet data
use grovestark::{create_witness_from_platform_proofs, GroveSTARK, PublicInputs, STARKConfig};
use std::fs;
use std::path::Path;

#[test]
fn test_testnet_proof_generation() {
    println!("\n🚀 Testing STARK Proof with Real Testnet Data");

    // Load test files
    let test_dir = Path::new("tests/fixtures");
    let doc_proof =
        fs::read(test_dir.join("document_proof_B5XLy3cUDayaqZmcGaWb98PEAUguGHiHSU5DxiKrHBj3.bin"))
            .expect("Failed to read document proof");
    let key_proof =
        fs::read(test_dir.join("identity_proof_FQ4waDowFQXD4tJPKQM1114VSr5f8s3qAc5bT8FJkT49.bin"))
            .expect("Failed to read key proof");

    // Load metadata
    let metadata: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(
            test_dir.join("proof_metadata_B5XLy3cUDayaqZmcGaWb98PEAUguGHiHSU5DxiKrHBj3.json"),
        )
        .expect("Failed to read metadata"),
    )
    .expect("Failed to parse metadata");

    // Create document JSON
    let doc_json = serde_json::json!({
        "$version": "0",
        "$id": metadata["document_id"],
        "$ownerId": metadata["identity_id"],
        "saltedDomainHash": "DatikyjRKcaaSMVNLOWdILAOxy/QoOmpSt/0lZ5MNb8=",
        "$revision": 1
    })
    .to_string()
    .into_bytes();

    // EdDSA components
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    let mut pubkey = [0u8; 32];
    let mut msg = [0u8; 32];
    let mut privkey = [0u8; 32];

    sig_r.copy_from_slice(
        &hex::decode("dbb76975d7a20eead1884b434bf699a729cd35815c2c84a48fea66e12b2ab323").unwrap(),
    );
    sig_s.copy_from_slice(
        &hex::decode("d99553f7a4bdb47c8161691a767eb511bed436e99a690331e8a384d96ecb7d08").unwrap(),
    );
    pubkey.copy_from_slice(
        &hex::decode("13f54fc83ab3112dc6e47a46822d0a6cdb0ec8bd496333d4d03527c198680928").unwrap(),
    );
    msg.copy_from_slice(
        &hex::decode("d43e625b43a2ceeae3bb3fc7119946fef628501b092ee2379aef649f55416e82").unwrap(),
    );
    privkey.copy_from_slice(
        &hex::decode("6e6f24b6f7a51203e1cbee0c30066a18901b1d5e13f7ffc69017d28228c78f3f").unwrap(),
    );

    println!("Creating witness...");
    let witness = create_witness_from_platform_proofs(
        &doc_proof, &key_proof, doc_json, &pubkey, &sig_r, &sig_s, &msg, &privkey,
    )
    .expect("Failed to create witness");

    println!("✅ Witness created");
    assert_eq!(witness.owner_id, witness.identity_id, "IDs must match");

    // Create prover with production-minimum queries for Winterfell 0.13.1
    let mut config = STARKConfig::default();
    config.grinding_bits = 12; // Light PoW
    config.num_queries = 48; // Production minimum

    let prover = GroveSTARK::with_config(config);

    let public_inputs = PublicInputs {
        state_root: [10u8; 32],
        contract_id: [11u8; 32],
        message_hash: msg,
        timestamp: 1700000000,
    };

    println!("Generating proof...");
    let start = std::time::Instant::now();

    match prover.prove(witness, public_inputs.clone()) {
        Ok(proof) => {
            println!(
                "✅ Proof generated in {:.2}s",
                start.elapsed().as_secs_f32()
            );

            // Verify
            match prover.verify(&proof, &public_inputs) {
                Ok(true) => println!("✅ Proof verified!"),
                Ok(false) => panic!("Proof invalid"),
                Err(e) => panic!("Verification error: {}", e),
            }

            println!("\n🎉 SUCCESS: Column ordering fix works with real testnet data!");
        }
        Err(e) => panic!("Proof generation failed: {}", e),
    }
}
