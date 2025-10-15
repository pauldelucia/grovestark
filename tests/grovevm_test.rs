//! Tests for GroveVM integration

use grovestark::phases::grovevm::types::{hash_to_limbs, limbs_to_hash};
use grovestark::phases::grovevm::{GroveVMTraceBuilder, Op};

#[test]
fn test_grovevm_simple_proof() {
    println!("\n=== Testing GroveVM with Simple Proof ===");

    // Create a simple proof: push two hashes and parent them
    let mut proof_bytes = Vec::new();
    proof_bytes.push(0x00); // Version
    proof_bytes.extend_from_slice(&[0xAA; 32]); // Root hash (placeholder)
    proof_bytes.push(0x01); // PushHash
    proof_bytes.extend_from_slice(&[0x11; 32]); // First hash
    proof_bytes.push(0x01); // PushHash
    proof_bytes.extend_from_slice(&[0x22; 32]); // Second hash
    proof_bytes.push(0x10); // Parent operation

    // Parse the proof
    let (ops, tape) = GroveVMTraceBuilder::parse_grovevm_ops_from_proof(&proof_bytes)
        .expect("Failed to parse proof");

    assert_eq!(ops.len(), 3);
    assert_eq!(ops[0], Op::PushHash);
    assert_eq!(ops[1], Op::PushHash);
    assert_eq!(ops[2], Op::Parent);

    assert_eq!(tape.len(), 2);
    assert_eq!(tape[0], [0x11; 32]);
    assert_eq!(tape[1], [0x22; 32]);

    // Build trace
    let mut builder = GroveVMTraceBuilder::new(ops, tape, 256);
    let trace = builder.build_trace().expect("Failed to build trace");

    println!(
        "✅ Successfully built GroveVM trace with {} columns and {} rows",
        trace.num_cols(),
        trace.num_rows()
    );

    // Verify the trace has expected structure
    use grovestark::phases::grovevm::types::{OP_PUSH_H, SP};
    use winterfell::math::fields::f64::BaseElement;
    use winterfell::math::FieldElement;

    // First operation should be PushHash; SP recorded after op = 1
    assert_eq!(trace.get(OP_PUSH_H, 0), BaseElement::ONE);
    assert_eq!(trace.get(SP, 0), BaseElement::ONE);

    // Second operation should be PushHash; SP recorded after op = 2
    assert_eq!(trace.get(OP_PUSH_H, 1), BaseElement::ONE);
    assert_eq!(trace.get(SP, 1), BaseElement::new(2));

    // Third operation should be Parent; SP recorded after op = 1
    assert_eq!(
        trace.get(grovestark::phases::grovevm::types::OP_PARENT, 2),
        BaseElement::ONE
    );
    assert_eq!(trace.get(SP, 2), BaseElement::ONE);

    println!("✅ Trace structure verified correctly");
}

#[test]
fn test_grovevm_hash_limb_conversion() {
    // Test hash to limbs and back conversion
    let original_hash = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
        0xDE, 0xF0,
    ];

    let limbs = hash_to_limbs(&original_hash);
    let recovered_hash = limbs_to_hash(&limbs);

    assert_eq!(original_hash, recovered_hash);
    println!("✅ Hash to limbs conversion works correctly");
}

#[test]
fn test_grovevm_child_operation() {
    println!("\n=== Testing GroveVM Child Operation ===");

    // Create proof with Child operation (swapped order)
    let mut proof_bytes = Vec::new();
    proof_bytes.push(0x00); // Version
    proof_bytes.extend_from_slice(&[0xAA; 32]); // Root hash
    proof_bytes.push(0x01); // PushHash
    proof_bytes.extend_from_slice(&[0x11; 32]); // First hash
    proof_bytes.push(0x02); // PushKvHash (different type)
    proof_bytes.extend_from_slice(&[0x22; 32]); // Second hash
    proof_bytes.push(0x11); // Child operation (swapped order)

    let (ops, tape) = GroveVMTraceBuilder::parse_grovevm_ops_from_proof(&proof_bytes)
        .expect("Failed to parse proof");

    assert_eq!(ops.len(), 3);
    assert_eq!(ops[0], Op::PushHash);
    assert_eq!(ops[1], Op::PushKvHash);
    assert_eq!(ops[2], Op::Child);

    // Build and verify trace
    let mut builder = GroveVMTraceBuilder::new(ops, tape, 256);
    let trace = builder.build_trace().expect("Failed to build trace");

    println!("✅ Child operation trace built successfully");

    // Verify Child operation encoding
    use grovestark::phases::grovevm::types::{OP_CHILD, OP_PUSH_KV};
    use winterfell::math::fields::f64::BaseElement;
    use winterfell::math::FieldElement;

    assert_eq!(trace.get(OP_PUSH_KV, 1), BaseElement::ONE);
    assert_eq!(trace.get(OP_CHILD, 2), BaseElement::ONE);

    println!("✅ Child operation verified correctly");
}

#[test]
fn test_grovevm_stack_depth() {
    use grovestark::phases::grovevm::types::D_MAX;

    println!("\n=== Testing GroveVM Stack Depth Limit ===");
    println!("Maximum stack depth: {}", D_MAX);

    // Create proof that would exceed stack depth
    let mut proof_bytes = Vec::new();
    proof_bytes.push(0x00); // Version
    proof_bytes.extend_from_slice(&[0xAA; 32]); // Root hash

    // Push D_MAX items (should succeed)
    for i in 0..D_MAX {
        proof_bytes.push(0x01); // PushHash
        proof_bytes.extend_from_slice(&[(i as u8); 32]); // Unique hash for each
    }

    let (ops, tape) = GroveVMTraceBuilder::parse_grovevm_ops_from_proof(&proof_bytes)
        .expect("Failed to parse proof");

    assert_eq!(ops.len(), D_MAX);
    assert_eq!(tape.len(), D_MAX);

    // Build trace - should succeed with D_MAX items
    let mut builder = GroveVMTraceBuilder::new(ops, tape, 256);
    let _trace = builder.build_trace().expect("Should handle D_MAX items");

    println!("✅ Stack handles {} items correctly", D_MAX);

    // Now test exceeding the limit
    let mut proof_bytes_overflow = proof_bytes.clone();
    proof_bytes_overflow.push(0x01); // One more PushHash
    proof_bytes_overflow.extend_from_slice(&[0xFF; 32]);

    let (ops_overflow, tape_overflow) =
        GroveVMTraceBuilder::parse_grovevm_ops_from_proof(&proof_bytes_overflow)
            .expect("Failed to parse proof");

    assert_eq!(ops_overflow.len(), D_MAX + 1);

    // This should fail when executing
    let mut builder_overflow = GroveVMTraceBuilder::new(ops_overflow, tape_overflow, 256);
    let result = builder_overflow.build_trace();

    assert!(result.is_err(), "Should fail when exceeding stack depth");
    println!("✅ Stack overflow detected correctly");
}
