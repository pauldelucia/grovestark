//! GroveVM trace builder

use winterfell::math::fields::f64::BaseElement;
use winterfell::math::FieldElement;
use winterfell::matrix::ColMatrix;

use crate::phases::grovevm::types::*;

/// GroveVM trace builder for auxiliary segment
pub struct GroveVMTraceBuilder {
    state: GroveVMState,
    trace_length: usize,
}

impl GroveVMTraceBuilder {
    /// Create a new trace builder from operations and push tape
    pub fn new(operations: Vec<Op>, push_tape: Vec<[u8; 32]>, trace_length: usize) -> Self {
        Self {
            state: GroveVMState::new(operations, push_tape),
            trace_length,
        }
    }

    /// Build the auxiliary trace for GroveVM execution
    pub fn build_trace(&mut self) -> Result<ColMatrix<BaseElement>, String> {
        // Initialize auxiliary trace matrix
        let mut columns = vec![vec![BaseElement::ZERO; self.trace_length]; GROVEVM_AUX_WIDTH];

        // Track current operation index
        let mut op_idx = 0;

        // Execute operations and fill trace
        for step in 0..self.trace_length {
            // Check if we have more operations to execute
            if op_idx < self.state.operations.len() {
                let op = self.state.operations[op_idx];

                // Set opcode one-hot encoding
                match op {
                    Op::PushHash => columns[OP_PUSH_H][step] = BaseElement::ONE,
                    Op::PushKvHash => columns[OP_PUSH_KV][step] = BaseElement::ONE,
                    Op::Parent => columns[OP_PARENT][step] = BaseElement::ONE,
                    Op::Child => columns[OP_CHILD][step] = BaseElement::ONE,
                }

                // Execute the operation, then record control columns reflecting the transition

                // For push operations, copy hash to push_hash columns
                if matches!(op, Op::PushHash | Op::PushKvHash) {
                    if self.state.tp < self.state.push_tape.len() {
                        let hash = &self.state.push_tape[self.state.tp];
                        let limbs = hash_to_limbs(hash);

                        for (i, &limb) in limbs.iter().enumerate() {
                            columns[PUSH_HASH_START + i][step] = BaseElement::new(limb as u64);
                        }
                    }
                }

                if let Err(e) = self.state.execute_op(op) {
                    return Err(format!("Op execution failed at step {}: {}", step, e));
                }

                // Set control columns after operation to reflect tp/sp transitions
                columns[SP][step] = BaseElement::new(self.state.sp as u64);
                columns[TP][step] = BaseElement::new(self.state.tp as u64);

                // Write stack state after operation
                for slot in 0..D_MAX {
                    let hash = &self.state.stack[slot];
                    let limbs = hash_to_limbs(hash);

                    for (limb_idx, &limb) in limbs.iter().enumerate() {
                        let col_idx = STACK_START + slot * LIMBS_PER_HASH + limb_idx;
                        columns[col_idx][step] = BaseElement::new(limb as u64);
                    }
                }

                op_idx += 1;
            } else {
                // Padding rows - maintain final state
                // CRITICAL: Set all opcode columns to 0 (no operation)
                columns[OP_PUSH_H][step] = BaseElement::ZERO;
                columns[OP_PUSH_KV][step] = BaseElement::ZERO;
                columns[OP_PARENT][step] = BaseElement::ZERO;
                columns[OP_CHILD][step] = BaseElement::ZERO;

                // Use the current state values (after all operations executed)
                columns[SP][step] = BaseElement::new(self.state.sp as u64);
                columns[TP][step] = BaseElement::new(self.state.tp as u64);

                // Clear push_hash columns in padding
                for i in PUSH_HASH_START..PUSH_HASH_END {
                    columns[i][step] = BaseElement::ZERO;
                }

                // Copy current stack state
                for slot in 0..D_MAX {
                    let hash = &self.state.stack[slot];
                    let limbs = hash_to_limbs(hash);

                    for (limb_idx, &limb) in limbs.iter().enumerate() {
                        let col_idx = STACK_START + slot * LIMBS_PER_HASH + limb_idx;
                        columns[col_idx][step] = BaseElement::new(limb as u64);
                    }
                }
            }
        }

        // Convert to ColMatrix
        Ok(ColMatrix::new(columns))
    }

    /// Parse proof to GroveVM operations and push tape (internal GroveVM helper)
    /// Supports both simple and multi-layer proofs. Renamed to avoid confusion with
    /// the global parser API in `parser/mod.rs`.
    pub fn parse_grovevm_ops_from_proof(
        proof_bytes: &[u8],
    ) -> Result<(Vec<Op>, Vec<[u8; 32]>), String> {
        use crate::phases::grovevm::proof_parser::{flatten_proof, parse_grovedb_proof_multilayer};

        // Try parsing as multi-layer proof first
        match parse_grovedb_proof_multilayer(proof_bytes) {
            Ok(multilayer_proof) => {
                // If we have lower layers, flatten the proof
                if !multilayer_proof.lower_layers.is_empty() {
                    Ok(flatten_proof(&multilayer_proof))
                } else {
                    // Just root layer
                    Ok((multilayer_proof.root_operations, multilayer_proof.root_tape))
                }
            }
            Err(_) => {
                // Fall back to simple parsing for backward compatibility
                Self::parse_grovevm_proof_simple(proof_bytes)
            }
        }
    }

    /// Simple proof parser for backward compatibility
    fn parse_grovevm_proof_simple(proof_bytes: &[u8]) -> Result<(Vec<Op>, Vec<[u8; 32]>), String> {
        let mut ops = Vec::new();
        let mut push_tape = Vec::new();

        // Skip version byte and root hash (1 + 32 = 33 bytes)
        if proof_bytes.len() < 33 {
            return Err("Proof too short".into());
        }

        let mut cursor = 33;

        while cursor < proof_bytes.len() {
            let op_byte = proof_bytes[cursor];

            match Op::from_byte(op_byte) {
                Some(Op::PushHash | Op::PushKvHash) => {
                    // Push operations include a 32-byte hash
                    if cursor + 33 > proof_bytes.len() {
                        return Err("Incomplete push operation".into());
                    }

                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&proof_bytes[cursor + 1..cursor + 33]);

                    ops.push(Op::from_byte(op_byte).unwrap());
                    push_tape.push(hash);
                    cursor += 33;
                }
                Some(Op::Parent | Op::Child) => {
                    ops.push(Op::from_byte(op_byte).unwrap());
                    cursor += 1;
                }
                None => {
                    // Skip unknown operation codes
                    cursor += 1;
                }
            }
        }

        Ok((ops, push_tape))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_push_parent() {
        // Create simple proof: push two hashes and parent them
        let ops = vec![Op::PushHash, Op::PushHash, Op::Parent];
        let tape = vec![[1u8; 32], [2u8; 32]];

        let mut builder = GroveVMTraceBuilder::new(ops, tape, 256);
        let trace = builder.build_trace().expect("Failed to build trace");

        // Check trace dimensions
        assert_eq!(trace.num_cols(), GROVEVM_AUX_WIDTH);
        assert_eq!(trace.num_rows(), 256);

        // Verify first operation is PushHash
        assert_eq!(trace.get(OP_PUSH_H, 0), BaseElement::ONE);
        // SP is recorded after executing the op
        assert_eq!(trace.get(SP, 0), BaseElement::ONE); // SP becomes 1 after first push

        // Verify second operation is PushHash
        assert_eq!(trace.get(OP_PUSH_H, 1), BaseElement::ONE);
        assert_eq!(trace.get(SP, 1), BaseElement::new(2)); // SP incremented to 2 after second push

        // Verify third operation is Parent
        assert_eq!(trace.get(OP_PARENT, 2), BaseElement::ONE);
        assert_eq!(trace.get(SP, 2), BaseElement::ONE); // SP becomes 1 after parent (two pops, one push)

        // After Parent, SP should be 1 (two pops, one push)
        // Check in padding rows
        assert_eq!(trace.get(SP, 3), BaseElement::ONE);
    }

    #[test]
    fn test_parse_grovevm_ops_from_proof() {
        // Create a mock proof with known structure
        let mut proof = vec![0x00]; // Version
        proof.extend_from_slice(&[0xAAu8; 32]); // Root hash
        proof.push(0x01); // PushHash
        proof.extend_from_slice(&[0xBBu8; 32]); // Hash data
        proof.push(0x02); // PushKvHash
        proof.extend_from_slice(&[0xCCu8; 32]); // Hash data
        proof.push(0x10); // Parent

        let (ops, tape) = GroveVMTraceBuilder::parse_grovevm_ops_from_proof(&proof)
            .expect("Failed to parse proof");

        assert_eq!(ops.len(), 3);
        assert_eq!(ops[0], Op::PushHash);
        assert_eq!(ops[1], Op::PushKvHash);
        assert_eq!(ops[2], Op::Parent);

        assert_eq!(tape.len(), 2);
        assert_eq!(tape[0], [0xBBu8; 32]);
        assert_eq!(tape[1], [0xCCu8; 32]);
    }
}
