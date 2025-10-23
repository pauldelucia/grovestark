//! Example demonstrating SDK integration with separate document and identity proofs
//!
//! This example shows how to use GroveSTARK with raw proofs from the Dash SDK,
//! where document and identity proofs are provided separately.

use ed25519_dalek::{Signer, SigningKey};
use grovestark::{create_witness_from_platform_proofs, GroveSTARK, PublicInputs, STARKConfig};
use rand::rngs::OsRng;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 GroveSTARK SDK Integration Example");
    println!("=====================================\n");

    // Step 1: Generate Ed25519 keypair and signature (normally from SDK)
    println!("Step 1: Generating EdDSA signature...");
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let message = b"Document ownership challenge";
    let signature = signing_key.sign(message);

    let signature_bytes = signature.to_bytes();
    let mut signature_r = [0u8; 32];
    let mut signature_s = [0u8; 32];
    signature_r.copy_from_slice(&signature_bytes[0..32]);
    signature_s.copy_from_slice(&signature_bytes[32..64]);

    println!("  ✓ Generated Ed25519 signature");

    // Step 2: Create mock SDK proofs (in production, these come from SDK)
    println!("\nStep 2: Creating mock SDK proofs...");

    // Document proof: Raw Merk operations
    // Format: [op_code, data...]
    // 0x01 = Push, 0x02 = Parent, 0x03 = Child
    let mut document_proof = Vec::new();
    // First node: Push hash + Parent (left sibling)
    document_proof.push(0x01); // Push operation
    document_proof.extend_from_slice(&[0x11u8; 32]); // Hash
    document_proof.push(0x02); // Parent operation
                               // Second node: Push hash only (right sibling)
    document_proof.push(0x01); // Push operation
    document_proof.extend_from_slice(&[0x22u8; 32]); // Hash

    // Identity proof: Raw Merk operations
    let mut identity_proof = Vec::new();
    // Single node: Push hash (right sibling)
    identity_proof.push(0x01); // Push operation
    identity_proof.extend_from_slice(&[0x33u8; 32]); // Hash

    println!(
        "  ✓ Created document proof ({} bytes)",
        document_proof.len()
    );
    println!(
        "  ✓ Created identity proof ({} bytes)",
        identity_proof.len()
    );

    // Step 3: Create witness using SDK integration function
    println!("\nStep 3: Creating witness from SDK proofs...");

    // Additional required values for the simplified 2-proof path
    let public_key_bytes = verifying_key.to_bytes();

    let witness = create_witness_from_platform_proofs(
        &document_proof,
        &identity_proof,
        vec![0xDDu8; 100], // Document JSON/CBOR data
        &public_key_bytes,
        &signature_r,
        &signature_s,
        message,
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
        state_root: [0xFFu8; 32],
        contract_id: [0xAAu8; 32],
        message_hash: [0xBBu8; 32],
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
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
