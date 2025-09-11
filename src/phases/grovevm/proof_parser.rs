//! GroveDB multi-layer proof parser
//!
//! Handles the complex layered structure of GroveDB proofs where
//! the root layer operations reference lower layers for actual data.

use crate::phases::grovevm::types::Op;
use std::collections::BTreeMap;

/// Represents a complete GroveDB proof with layers
#[derive(Debug, Clone)]
pub struct GroveDBProof {
    pub version: u8,
    pub root_hash: [u8; 32],
    pub root_operations: Vec<Op>,
    pub root_tape: Vec<[u8; 32]>,
    pub lower_layers: BTreeMap<Vec<u8>, LayerProof>,
}

/// A single layer in the proof structure
#[derive(Debug, Clone)]
pub struct LayerProof {
    pub operations: Vec<Op>,
    pub tape: Vec<[u8; 32]>,
}

/// Parse a complete GroveDB proof with multi-layer support
pub fn parse_grovedb_proof_multilayer(proof_bytes: &[u8]) -> Result<GroveDBProof, String> {
    if proof_bytes.len() < 33 {
        return Err("Proof too short for header".into());
    }

    let version = proof_bytes[0];
    let mut root_hash = [0u8; 32];
    root_hash.copy_from_slice(&proof_bytes[1..33]);

    let mut cursor = 33;
    let mut root_operations = Vec::new();
    let mut root_tape = Vec::new();
    let mut lower_layers = BTreeMap::new();

    // State for tracking when we transition to lower layers
    let mut in_lower_layer = false;
    let mut current_layer_key = Vec::new();
    let mut current_layer_ops = Vec::new();
    let mut current_layer_tape = Vec::new();

    while cursor < proof_bytes.len() {
        let op_byte = proof_bytes[cursor];

        match op_byte {
            0x01 | 0x02 => {
                // Push operations (Hash or KVHash)
                if cursor + 33 > proof_bytes.len() {
                    break; // Incomplete push
                }

                let mut hash = [0u8; 32];
                hash.copy_from_slice(&proof_bytes[cursor + 1..cursor + 33]);

                let op = Op::from_byte(op_byte).unwrap();

                if in_lower_layer {
                    current_layer_ops.push(op);
                    current_layer_tape.push(hash);
                } else {
                    root_operations.push(op);
                    root_tape.push(hash);
                }

                cursor += 33;
            }
            0x10 | 0x11 => {
                // Parent or Child operations
                let op = Op::from_byte(op_byte).unwrap();

                if in_lower_layer {
                    current_layer_ops.push(op);
                } else {
                    root_operations.push(op);
                }

                cursor += 1;
            }
            0x12 => {
                // Layer boundary marker (custom for GroveDB)
                // Indicates start of a lower layer proof
                if cursor + 1 >= proof_bytes.len() {
                    break;
                }

                // Read layer key length
                let key_len = proof_bytes[cursor + 1] as usize;
                if cursor + 2 + key_len > proof_bytes.len() {
                    break;
                }

                // Save previous layer if we were in one
                if in_lower_layer && !current_layer_key.is_empty() {
                    lower_layers.insert(
                        current_layer_key.clone(),
                        LayerProof {
                            operations: current_layer_ops.clone(),
                            tape: current_layer_tape.clone(),
                        },
                    );
                    current_layer_ops.clear();
                    current_layer_tape.clear();
                }

                // Start new layer
                current_layer_key = proof_bytes[cursor + 2..cursor + 2 + key_len].to_vec();
                in_lower_layer = true;
                cursor += 2 + key_len;
            }
            0x13 => {
                // End of layer marker
                if in_lower_layer && !current_layer_key.is_empty() {
                    lower_layers.insert(
                        current_layer_key.clone(),
                        LayerProof {
                            operations: current_layer_ops.clone(),
                            tape: current_layer_tape.clone(),
                        },
                    );
                    current_layer_ops.clear();
                    current_layer_tape.clear();
                    current_layer_key.clear();
                    in_lower_layer = false;
                }
                cursor += 1;
            }
            _ => {
                // Unknown operation or data
                cursor += 1;
            }
        }
    }

    // Save final layer if still in one
    if in_lower_layer && !current_layer_key.is_empty() {
        lower_layers.insert(
            current_layer_key,
            LayerProof {
                operations: current_layer_ops,
                tape: current_layer_tape,
            },
        );
    }

    Ok(GroveDBProof {
        version,
        root_hash,
        root_operations,
        root_tape,
        lower_layers,
    })
}

/// Execute a multi-layer proof to compute the final root
pub fn execute_multilayer_proof(proof: &GroveDBProof) -> Result<[u8; 32], String> {
    use crate::phases::grovevm::types::GroveVMState;

    // First execute all lower layers to get their roots
    let mut layer_roots: BTreeMap<Vec<u8>, [u8; 32]> = BTreeMap::new();

    for (key, layer) in &proof.lower_layers {
        let mut state = GroveVMState::new(layer.operations.clone(), layer.tape.clone());

        // Execute all operations in the layer
        for op in &layer.operations {
            state.execute_op(*op)?;
        }

        // Get the root of this layer
        if let Some(root) = state.get_root() {
            layer_roots.insert(key.clone(), root);
        } else {
            return Err(format!("Layer {:?} did not produce single root", key));
        }
    }

    // Now execute root layer, substituting layer references with their computed roots
    // This requires modifying the tape to include layer roots where referenced
    let mut modified_tape = proof.root_tape.clone();

    // In a real implementation, we'd need to identify which tape entries
    // are layer references and substitute them. For now, we'll append layer roots.
    for (_key, root) in layer_roots {
        modified_tape.push(root);
    }

    let mut root_state = GroveVMState::new(proof.root_operations.clone(), modified_tape);

    // Execute root layer operations
    for op in &proof.root_operations {
        root_state.execute_op(*op)?;
    }

    // Get final root
    root_state
        .get_root()
        .ok_or("Root layer did not produce single root".into())
}

/// Flatten a multi-layer proof into a single sequence of operations
/// This is useful for testing and debugging
pub fn flatten_proof(proof: &GroveDBProof) -> (Vec<Op>, Vec<[u8; 32]>) {
    let mut all_ops = Vec::new();
    let mut all_tape = Vec::new();

    // Add all lower layer operations first
    for (_key, layer) in &proof.lower_layers {
        all_ops.extend(&layer.operations);
        all_tape.extend(&layer.tape);
    }

    // Then add root layer operations
    all_ops.extend(&proof.root_operations);
    all_tape.extend(&proof.root_tape);

    (all_ops, all_tape)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multilayer_proof_parsing() {
        // Create a proof with layers
        let mut proof_bytes = Vec::new();
        proof_bytes.push(0x00); // Version
        proof_bytes.extend_from_slice(&[0xAA; 32]); // Root hash

        // Root layer operations
        proof_bytes.push(0x01); // PushHash
        proof_bytes.extend_from_slice(&[0x11; 32]);

        // Layer boundary
        proof_bytes.push(0x12); // Layer start marker
        proof_bytes.push(0x04); // Key length
        proof_bytes.extend_from_slice(b"key1"); // Layer key

        // Lower layer operations
        proof_bytes.push(0x01); // PushHash
        proof_bytes.extend_from_slice(&[0x22; 32]);
        proof_bytes.push(0x01); // PushHash
        proof_bytes.extend_from_slice(&[0x33; 32]);
        proof_bytes.push(0x10); // Parent

        proof_bytes.push(0x13); // End of layer

        let proof = parse_grovedb_proof_multilayer(&proof_bytes).expect("Failed to parse");

        assert_eq!(proof.root_operations.len(), 1);
        assert_eq!(proof.lower_layers.len(), 1);

        let layer = proof
            .lower_layers
            .get(b"key1".as_slice())
            .expect("Layer not found");
        assert_eq!(layer.operations.len(), 3);
        assert_eq!(layer.tape.len(), 2);
    }

    #[test]
    fn test_multilayer_execution() {
        // Create a simple two-layer proof
        let proof = GroveDBProof {
            version: 0,
            root_hash: [0xAA; 32],
            root_operations: vec![Op::PushHash, Op::PushHash, Op::Parent],
            root_tape: vec![[0x11; 32], [0x22; 32]],
            lower_layers: {
                let mut layers = BTreeMap::new();
                layers.insert(
                    b"sublayer".to_vec(),
                    LayerProof {
                        operations: vec![Op::PushHash, Op::PushHash, Op::Child],
                        tape: vec![[0x33; 32], [0x44; 32]],
                    },
                );
                layers
            },
        };

        let root = execute_multilayer_proof(&proof).expect("Failed to execute");

        // Root should be non-zero
        assert_ne!(root, [0u8; 32]);
    }
}
