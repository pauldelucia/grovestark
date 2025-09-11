//! Demonstration of STARK proof generation and verification with benchmarks
//!
//! Run with: cargo run --release --example proof_demo

use grovestark::test_utils::create_valid_eddsa_witness;
use grovestark::{GroveSTARK, PublicInputs, STARKConfig};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║       GroveSTARK: Proof Generation & Verification Demo      ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();

    // Step 1: Create witness with valid EdDSA signature
    println!("📝 Step 1: Creating witness data with valid EdDSA signature...");
    let witness = create_valid_eddsa_witness();
    println!("   ✅ Witness created with valid Ed25519 signature");
    println!("   Document: {} bytes", witness.document_cbor.len());
    println!(
        "   Merkle paths: {} + {} document nodes, {} + {} key nodes",
        witness.owner_id_leaf_to_doc_path.len(),
        witness.docroot_to_state_path.len(),
        witness.key_leaf_to_keysroot_path.len(),
        witness.identity_leaf_to_state_path.len()
    );
    println!();

    // Step 2: Configure STARK parameters
    println!("⚙️  Step 2: Configuring STARK parameters...");
    let config = STARKConfig::default();
    println!("   Trace length: {} rows", config.trace_length);
    println!("   Field: Goldilocks (64-bit)");
    println!("   Expansion factor: {}x", config.expansion_factor);
    println!("   Number of queries: {}", config.num_queries);
    println!(
        "   Grinding bits: {} (PoW difficulty)",
        config.grinding_bits
    );
    println!();

    // Step 3: Create public inputs
    println!("🔐 Step 3: Setting public inputs...");
    let public_inputs = PublicInputs {
        state_root: [0xaa; 32],
        contract_id: [0xbb; 32],
        message_hash: [0xcc; 32],
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };
    println!("   State root: 0xaa...");
    println!("   Contract ID: 0xbb...");
    println!("   Timestamp: {}", public_inputs.timestamp);
    println!();

    // Step 4: Generate STARK proof
    println!("🚀 Step 4: Generating STARK proof...");
    println!("   Building execution trace...");
    println!("   Computing constraints...");
    println!("   Running FRI protocol...");

    let prover = GroveSTARK::with_config(config);
    let start = Instant::now();
    let proof = prover.prove(witness, public_inputs.clone())?;
    let prove_time = start.elapsed();

    println!("   ✅ Proof generated in {:.2}s", prove_time.as_secs_f64());

    // Get proof statistics
    let proof_bytes = bincode1::serialize(&proof)?;
    println!();
    println!("📊 Proof Statistics:");
    println!("   Total size: {} KB", proof_bytes.len() / 1024);
    println!("   Query rounds: {}", proof.fri_proof.query_rounds.len());
    println!(
        "   Final polynomial degree: {}",
        proof.fri_proof.final_polynomial.len()
    );
    println!();

    // Step 5: Verify the proof
    println!("🔍 Step 5: Verifying STARK proof...");
    let start = Instant::now();
    let is_valid = prover.verify(&proof, &public_inputs)?;
    let verify_time = start.elapsed();

    if is_valid {
        println!("   ✅ Proof VERIFIED in {:.3}ms", verify_time.as_millis());
    } else {
        println!("   ❌ Proof verification FAILED!");
        return Err("Proof verification failed".into());
    }
    println!();

    // Summary
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║                         SUMMARY                             ║");
    println!("╠════════════════════════════════════════════════════════════╣");
    println!(
        "║ Proof generation time: {:>36} ║",
        format!("{:.2}s", prove_time.as_secs_f64())
    );
    println!(
        "║ Verification time:     {:>36} ║",
        format!("{:.3}ms", verify_time.as_millis())
    );
    println!(
        "║ Proof size:            {:>36} ║",
        format!("{} KB", proof_bytes.len() / 1024)
    );
    println!("║ Security level:        {:>36} ║", "~100 bits");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    println!("🎉 Demo completed successfully!");

    Ok(())
}
