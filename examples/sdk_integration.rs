//! Example demonstrating SDK integration with separate document and identity proofs
//!
//! This example shows how to use GroveSTARK with raw proofs from the Dash SDK,
//! where document and identity proofs are provided separately.

use grovestark::{create_witness_from_platform_proofs, GroveSTARK, PublicInputs, STARKConfig};
use hex;
use serde::Deserialize;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 GroveSTARK SDK Integration Example");
    println!("=====================================\n");

    // Step 1: Load real fixture data (mirrors integration tests)
    println!("Step 1: Loading proofs from PASS_AND_FAIL fixtures...");

    #[derive(Deserialize)]
    struct Ed25519Fix {
        public_key_hex: String,
        signature_r_hex: String,
        signature_s_hex: String,
    }

    #[derive(Deserialize)]
    struct PubInputsFix {
        state_root_hex: String,
        contract_id_hex: String,
        message_hex: String,
        timestamp: u64,
    }

    #[derive(Deserialize)]
    struct PassFix {
        document_json: String,
        document_proof_hex: String,
        key_proof_hex: String,
        public_inputs: PubInputsFix,
        ed25519: Ed25519Fix,
    }

    #[derive(Deserialize)]
    struct Fixtures {
        pass: PassFix,
    }

    fn hex32(s: &str) -> [u8; 32] {
        let bytes = hex::decode(s).expect("Invalid hex");
        assert_eq!(bytes.len(), 32, "expected 32-byte hex");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    }

    let fixtures: Fixtures =
        serde_json::from_str(include_str!("../tests/fixtures/PASS_AND_FAIL.json"))?;

    let doc_proof = hex::decode(&fixtures.pass.document_proof_hex)?;
    let key_proof = hex::decode(&fixtures.pass.key_proof_hex)?;
    let sig_r = hex32(&fixtures.pass.ed25519.signature_r_hex);
    let sig_s = hex32(&fixtures.pass.ed25519.signature_s_hex);
    let public_key = hex32(&fixtures.pass.ed25519.public_key_hex);
    let message = hex::decode(&fixtures.pass.public_inputs.message_hex)?;

    println!("  ✓ Loaded document proof ({} bytes)", doc_proof.len());
    println!("  ✓ Loaded identity proof ({} bytes)", key_proof.len());

    // Step 2: Create witness using real proofs
    println!("\nStep 2: Creating witness from fixture proofs...");

    let witness = create_witness_from_platform_proofs(
        &doc_proof,
        &key_proof,
        fixtures.pass.document_json.as_bytes().to_vec(),
        &public_key,
        &sig_r,
        &sig_s,
        &message,
    )?;

    println!("  ✓ Created witness with:");
    println!(
        "    - Document path: {} + {} nodes",
        witness.owner_id_leaf_to_doc_path.len(),
        witness.docroot_to_state_path.len()
    );
    println!(
        "    - Identity path: {} + {} nodes",
        witness.key_leaf_to_keysroot_path.len(),
        witness.identity_leaf_to_state_path.len()
    );
    println!("    - EdDSA components populated");

    // Step 4: Generate STARK proof
    println!("\nStep 4: Generating STARK proof...");

    let config = STARKConfig::default();
    let prover = GroveSTARK::with_config(config);

    let public_inputs = PublicInputs {
        state_root: hex32(&fixtures.pass.public_inputs.state_root_hex),
        contract_id: hex32(&fixtures.pass.public_inputs.contract_id_hex),
        message_hash: hex32(&fixtures.pass.public_inputs.message_hex),
        timestamp: fixtures.pass.public_inputs.timestamp,
    };

    println!("  ⏳ This may take a moment...");
    let proof = prover.prove(witness, public_inputs.clone())?;

    println!("  ✓ Generated STARK proof");
    println!(
        "    - Proof size: {} bytes",
        proof.fri_proof.final_polynomial.len()
    );
    println!("    - PoW nonce: {}", proof.pow_nonce);

    // Step 5: Verify the proof
    println!("\nStep 5: Verifying STARK proof...");

    let is_valid = prover.verify(&proof, &public_inputs)?;

    if is_valid {
        println!("  ✅ Proof verified successfully!");
    } else {
        println!("  ❌ Proof verification failed");
    }

    println!("\n🎉 SDK Integration Complete!");
    println!("\nSummary:");
    println!("--------");
    println!("This example demonstrated how to:");
    println!("1. Accept separate document and identity proofs");
    println!("2. Parse GroveDB layered proofs");
    println!("3. Create a complete witness for STARK proving");
    println!("4. Generate and verify the zero-knowledge proof");

    Ok(())
}
