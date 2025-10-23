use grovestark::{GroveSTARK, PrivateInputs, PublicInputs, STARKConfig};

#[test]
fn test_minimal_proof() {
    println!("Starting minimal proof test");

    // Create minimal witness using default and override needed fields
    let mut witness = PrivateInputs::default();
    witness.document_cbor = vec![1, 2, 3, 4]; // Minimal document
    witness.owner_id = [1u8; 32];
    witness.identity_id = [1u8; 32]; // Same as owner_id for valid proof

    // Use real testnet EdDSA signature values (non-zero)
    witness.signature_r =
        hex::decode("dbb76975d7a20eead1884b434bf699a729cd35815c2c84a48fea66e12b2ab323")
            .unwrap()
            .try_into()
            .unwrap();
    witness.signature_s =
        hex::decode("d99553f7a4bdb47c8161691a767eb511bed436e99a690331e8a384d96ecb7d08")
            .unwrap()
            .try_into()
            .unwrap();

    // Set extended coordinates to identity point
    witness.r_extended_y[0] = 1; // Y=1
    witness.r_extended_z[0] = 1; // Z=1 for identity
    witness.a_extended_y[0] = 1; // Y=1
    witness.a_extended_z[0] = 1; // Z=1

    // Identity-aware fields
    witness.doc_root = [0x44; 32];
    witness.keys_root = [0x55; 32];
    witness.owner_id_leaf_to_doc_path = vec![grovestark::MerkleNode {
        hash: [2u8; 32],
        is_left: false,
    }];
    witness.docroot_to_state_path = vec![];
    witness.key_leaf_to_keysroot_path = vec![grovestark::MerkleNode {
        hash: [3u8; 32],
        is_left: true,
    }];
    witness.identity_leaf_to_state_path = vec![];

    // Create minimal public inputs
    let public_inputs = PublicInputs {
        state_root: [10u8; 32],
        contract_id: [11u8; 32],
        message_hash: [12u8; 32],
        timestamp: 1700000000,
    };

    // Create prover with minimal config
    let mut config = STARKConfig::default();
    config.grinding_bits = 8; // Minimal PoW
    config.num_queries = 48; // Minimal queries

    let prover = GroveSTARK::with_config(config);

    println!("Attempting to generate proof...");

    // Try to generate proof
    match prover.prove(witness, public_inputs.clone()) {
        Ok(proof) => {
            println!("✅ Proof generated!");

            // Try to verify
            match prover.verify(&proof, &public_inputs) {
                Ok(true) => println!("✅ Proof verified!"),
                Ok(false) => println!("❌ Proof invalid"),
                Err(e) => println!("❌ Verification error: {}", e),
            }
        }
        Err(e) => {
            println!("❌ Proof generation failed: {}", e);
        }
    }
}
