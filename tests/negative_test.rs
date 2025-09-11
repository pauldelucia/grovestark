/// Negative test - verify that corrupted witness fails
use grovestark::{create_witness_from_platform_proofs, GroveSTARK, PublicInputs, STARKConfig};
use std::fs;
use std::path::Path;

#[test]
fn test_corrupted_witness_fails_verification() {
    println!("\n❌ Negative Test: Corrupted witness should produce invalid proof");

    // Load real testnet data
    let test_proofs_dir = Path::new("tests/fixtures");
    let document_proof_path =
        test_proofs_dir.join("document_proof_B5XLy3cUDayaqZmcGaWb98PEAUguGHiHSU5DxiKrHBj3.bin");
    let document_proof = fs::read(&document_proof_path).unwrap();

    let key_proof_path =
        test_proofs_dir.join("identity_proof_FQ4waDowFQXD4tJPKQM1114VSr5f8s3qAc5bT8FJkT49.bin");
    let key_proof = fs::read(&key_proof_path).unwrap();

    let metadata_path =
        test_proofs_dir.join("proof_metadata_B5XLy3cUDayaqZmcGaWb98PEAUguGHiHSU5DxiKrHBj3.json");
    let metadata_str = fs::read_to_string(&metadata_path).unwrap();
    let metadata: serde_json::Value = serde_json::from_str(&metadata_str).unwrap();

    let document_json = serde_json::json!({
        "$version": "0",
        "$id": metadata["document_id"],
        "$ownerId": metadata["identity_id"],
        "saltedDomainHash": "DatikyjRKcaaSMVNLOWdILAOxy/QoOmpSt/0lZ5MNb8=",
        "$revision": 1,
    })
    .to_string()
    .into_bytes();

    // Real EdDSA signature components
    let signature_r =
        hex::decode("dbb76975d7a20eead1884b434bf699a729cd35815c2c84a48fea66e12b2ab323").unwrap();
    let signature_s =
        hex::decode("d99553f7a4bdb47c8161691a767eb511bed436e99a690331e8a384d96ecb7d08").unwrap();
    let public_key =
        hex::decode("13f54fc83ab3112dc6e47a46822d0a6cdb0ec8bd496333d4d03527c198680928").unwrap();
    let message =
        hex::decode("d43e625b43a2ceeae3bb3fc7119946fef628501b092ee2379aef649f55416e82").unwrap();
    let private_key =
        hex::decode("6e6f24b6f7a51203e1cbee0c30066a18901b1d5e13f7ffc69017d28228c78f3f").unwrap();

    // Convert to fixed-size arrays
    let mut public_key_arr = [0u8; 32];
    let mut signature_r_arr = [0u8; 32];
    let mut signature_s_arr = [0u8; 32];
    let mut message_arr = [0u8; 32];
    let mut private_key_arr = [0u8; 32];

    public_key_arr.copy_from_slice(&public_key[..32]);
    signature_r_arr.copy_from_slice(&signature_r[..32]);
    signature_s_arr.copy_from_slice(&signature_s[..32]);
    message_arr.copy_from_slice(&message[..32]);
    private_key_arr.copy_from_slice(&private_key[..32]);

    // Create witness
    let mut witness = create_witness_from_platform_proofs(
        &document_proof,
        &key_proof,
        document_json,
        &public_key_arr,
        &signature_r_arr,
        &signature_s_arr,
        &message_arr,
        &private_key_arr,
    )
    .unwrap();

    println!("Original owner_id: {:?}", hex::encode(&witness.owner_id));

    // CORRUPT THE WITNESS - flip a byte in owner_id
    witness.owner_id[0] ^= 0xFF;
    println!("Corrupted owner_id: {:?}", hex::encode(&witness.owner_id));
    println!(
        "Identity_id unchanged: {:?}",
        hex::encode(&witness.identity_id)
    );
    println!("IDs now DIFFERENT - should fail DIFF assertion!");

    // Try to generate proof with corrupted witness
    // GUIDANCE.md: Increased expansion_factor and num_queries for proper soundness
    let config = STARKConfig {
        expansion_factor: 16, // Keep 16x for strong LDE
        grinding_bits: 16,    // Optional PoW
        num_queries: 64,      // CRITICAL: Increased from 1->48->64 for stronger FRI soundness
        folding_factor: 4,    // Increased from 2 to 4 as recommended
        ..Default::default()
    };

    let prover = GroveSTARK::with_config(config);
    let public_inputs = PublicInputs {
        state_root: [10u8; 32],
        contract_id: [11u8; 32],
        message_hash: message_arr,
        timestamp: 1700000000,
    };

    // Generate proof with corrupted witness (prover may reject outright)
    match prover.prove(witness, public_inputs.clone()) {
        Ok(proof) => {
            println!("⚠️  Proof generated with corrupted witness!");
            // Now try to verify - this should FAIL
            match prover.verify(&proof, &public_inputs) {
                Ok(true) => {
                    panic!(
                        "❌ CRITICAL: Proof with corrupted witness verified as VALID! This should not happen!"
                    );
                }
                Ok(false) => {
                    println!("✅ Good: Proof with corrupted witness was rejected by verifier");
                }
                Err(e) => {
                    println!("✅ Good: Proof verification failed with error: {}", e);
                }
            }
        }
        Err(e) => {
            println!(
                "✅ Prover correctly rejected corrupted/mismatched identity during proof generation: {}",
                e
            );
        }
    }
}
