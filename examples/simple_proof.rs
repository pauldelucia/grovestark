//! Simple example of STARK proof generation and verification
//!
//! Run with: cargo run --release --example simple_proof

use grovestark::test_utils::create_valid_eddsa_witness;
use grovestark::{GroveSTARK, PublicInputs, STARKConfig};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Simple GroveSTARK Example");
    println!("=========================\n");

    // Create witness with valid EdDSA signature
    println!("Creating witness with valid EdDSA signature...");
    let witness = create_valid_eddsa_witness();
    println!("✓ Witness created");

    // Create public inputs
    let public_inputs = PublicInputs {
        state_root: [0xaa; 32],
        contract_id: [0xbb; 32],
        message_hash: [0xcc; 32],
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };

    // Use default configuration
    let config = STARKConfig::default();
    println!("\nConfiguration:");
    println!("  Trace length: {}", config.trace_length);
    println!("  Field bits: {}", config.field_bits);
    println!("  Expansion factor: {}", config.expansion_factor);
    println!("  Number of queries: {}", config.num_queries);

    // Generate proof
    println!("\nGenerating STARK proof...");
    let start = std::time::Instant::now();

    let prover = GroveSTARK::with_config(config);
    let proof = prover.prove(witness, public_inputs.clone())?;

    let elapsed = start.elapsed();
    println!("✓ Proof generated in {:.2}s", elapsed.as_secs_f64());

    // Get proof size
    let proof_bytes = bincode1::serialize(&proof)?;
    println!("  Proof size: {} KB", proof_bytes.len() / 1024);

    // Verify proof
    println!("\nVerifying proof...");
    let start = std::time::Instant::now();

    let is_valid = prover.verify(&proof, &public_inputs)?;

    let elapsed = start.elapsed();

    if is_valid {
        println!(
            "✓ Proof is VALID! (verified in {:.3}ms)",
            elapsed.as_millis()
        );
    } else {
        println!("✗ Proof is INVALID!");
        return Err("Proof verification failed".into());
    }

    println!("\n🎉 Success! GroveSTARK proof generation and verification complete.");

    Ok(())
}
