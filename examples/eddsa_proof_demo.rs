//! Demonstration of EdDSA signature verification in STARK proofs
//!
//! This example shows how GroveSTARK proves ownership of a document
//! using Ed25519 signature verification within a STARK proof.
//!
//! Run with: cargo run --release --example eddsa_proof_demo

use ed25519_dalek::{Signer, SigningKey, Verifier as DalekVerifier};
use grovestark::{compute_eddsa_hash_h, populate_witness_with_extended};
use grovestark::{GroveSTARK, MerkleNode, PrivateInputs, PublicInputs, STARKConfig};
use rand::rngs::OsRng;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║     GroveSTARK: EdDSA Signature Verification in STARKs      ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();

    // Step 1: Generate Ed25519 keypair and signature
    println!("🔑 Step 1: Generating Ed25519 keypair and signature...");

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();

    // Message to sign (simulating document hash)
    let message = b"GroveDB document commitment";

    // Sign the message
    let signature = signing_key.sign(message);
    let signature_bytes = signature.to_bytes();

    // Verify with ed25519-dalek first
    match verifying_key.verify(message, &signature) {
        Ok(()) => println!("   ✅ Ed25519 signature valid (ed25519-dalek)"),
        Err(e) => {
            println!("   ❌ Ed25519 signature invalid: {}", e);
            return Err(e.into());
        }
    }

    // Extract R and s from signature
    let mut signature_r = [0u8; 32];
    let mut signature_s = [0u8; 32];
    signature_r.copy_from_slice(&signature_bytes[0..32]);
    signature_s.copy_from_slice(&signature_bytes[32..64]);

    println!("   Public key:  0x{:02x}...", public_key_bytes[0]);
    println!("   Signature R: 0x{:02x}...", signature_r[0]);
    println!("   Signature s: 0x{:02x}...", signature_s[0]);
    println!();

    // Step 2: Create witness with EdDSA signature
    println!("📝 Step 2: Creating STARK witness with EdDSA signature...");

    // Compute hash_h = SHA-512(R || A || M) mod L
    let hash_h = compute_eddsa_hash_h(&signature_r, &public_key_bytes, message);

    // Create witness (identity-aware Merkle fields)
    let mut witness = PrivateInputs {
        // Identity & document
        owner_id: [0x42; 32],
        identity_id: [0x42; 32],
        doc_root: [0x10; 32],
        keys_root: [0x99; 32],
        document_cbor: vec![0xa1, 0x61, 0x78, 0x01], // {x:1} minimal CBOR
        // Merkle paths
        owner_id_leaf_to_doc_path: vec![
            MerkleNode {
                hash: [0x11; 32],
                is_left: true,
            },
            MerkleNode {
                hash: [0x22; 32],
                is_left: false,
            },
        ],
        docroot_to_state_path: vec![MerkleNode {
            hash: [0xaa; 32],
            is_left: true,
        }],
        identity_leaf_to_state_path: vec![MerkleNode {
            hash: [0xbb; 32],
            is_left: false,
        }],
        key_leaf_to_keysroot_path: vec![MerkleNode {
            hash: [0x33; 32],
            is_left: true,
        }],
        // EdDSA
        signature_r,
        signature_s,
        public_key_a: public_key_bytes,
        pubkey_a_compressed: public_key_bytes,
        hash_h,
        ..Default::default()
    };

    // Populate extended coordinates for EdDSA verification
    populate_witness_with_extended(&mut witness, &signature_r, &public_key_bytes, message)?;

    println!("   ✅ Witness created with EdDSA extended coordinates");
    println!("   Owner ID set; identity_id matches owner_id");
    println!(
        "   Merkle paths: owner->doc={}, doc->state={}, identity->state={}, key->keys_root={}",
        witness.owner_id_leaf_to_doc_path.len(),
        witness.docroot_to_state_path.len(),
        witness.identity_leaf_to_state_path.len(),
        witness.key_leaf_to_keysroot_path.len()
    );
    println!();

    // Step 3: Create public inputs
    println!("🌍 Step 3: Setting public inputs...");
    let public_inputs = PublicInputs {
        state_root: [0xaa; 32],
        contract_id: [0xbb; 32],
        message_hash: {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(blake3::hash(message).as_bytes());
            hash
        },
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };
    println!("   State root: 0xaa...");
    println!("   Contract ID: 0xbb...");
    println!(
        "   Message hash: 0x{:02x}...",
        public_inputs.message_hash[0]
    );
    println!();

    // Step 4: Configure and run STARK prover
    println!("🚀 Step 4: Generating STARK proof with EdDSA verification...");

    let config = STARKConfig::default();
    println!("   Configuration:");
    println!("     - Field: Goldilocks (64-bit)");
    println!(
        "     - Trace: {} rows × {} columns",
        config.trace_length, config.num_trace_columns
    );
    println!("     - Security: ~{} bits", config.security_level);

    let prover = GroveSTARK::with_config(config);

    println!("   Phases:");
    println!("     1. BLAKE3 hashing (~2730 steps)");
    println!("     2. Merkle path verification (~2730 steps)");
    println!("     3. EdDSA signature verification (~32768 steps)");
    println!("       - Computing [s]B (scalar multiplication)");
    println!("       - Computing [h]A (scalar multiplication)");
    println!("       - Verifying [s]B - [h]A - R = O (identity)");

    let start = Instant::now();
    let proof = prover.prove(witness, public_inputs.clone())?;
    let prove_time = start.elapsed();

    println!("   ✅ Proof generated in {:.2}s", prove_time.as_secs_f64());

    // Get proof size
    let proof_bytes = bincode1::serialize(&proof)?;
    println!("   Proof size: {} KB", proof_bytes.len() / 1024);
    println!();

    // Step 5: Verify the STARK proof
    println!("🔍 Step 5: Verifying STARK proof...");

    let start = Instant::now();
    let is_valid = prover.verify(&proof, &public_inputs)?;
    let verify_time = start.elapsed();

    if is_valid {
        println!("   ✅ STARK proof VALID! EdDSA signature verified within STARK.");
        println!("   Verification time: {:.3}ms", verify_time.as_millis());
    } else {
        println!("   ❌ STARK proof INVALID!");
        return Err("STARK proof verification failed".into());
    }
    println!();

    // Summary
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║                    EdDSA STARK Summary                      ║");
    println!("╠════════════════════════════════════════════════════════════╣");
    println!("║ Signature scheme:      Ed25519 (EdDSA)                      ║");
    println!(
        "║ Proof generation:      {:>37} ║",
        format!("{:.2}s", prove_time.as_secs_f64())
    );
    println!(
        "║ Proof verification:    {:>37} ║",
        format!("{:.3}ms", verify_time.as_millis())
    );
    println!(
        "║ Proof size:            {:>37} ║",
        format!("{} KB", proof_bytes.len() / 1024)
    );
    println!("║ Result:                ✅ Ownership proven with EdDSA       ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    println!("🎉 EdDSA signature successfully verified within STARK proof!");

    Ok(())
}
