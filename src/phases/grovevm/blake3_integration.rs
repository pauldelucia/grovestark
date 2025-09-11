//! BLAKE3 integration for GroveVM Parent/Child operations
//!
//! This module handles routing stack data to BLAKE3 for hash computation
//! when Parent or Child operations are executed.

use crate::phases::grovevm::types::*;
use winterfell::math::fields::f64::BaseElement;
use winterfell::math::FieldElement;

/// Phase identifier for GroveVM operations that need BLAKE3
pub const GROVEVM_BLAKE3_PHASE: usize = 65000; // Near end of trace

/// Route GroveVM stack data to BLAKE3 message columns for Parent/Child operations
pub fn route_grovevm_to_blake3(
    main_columns: &mut [Vec<BaseElement>],
    aux_columns: &[Vec<BaseElement>],
    step: usize,
) {
    // Check if we're in a GroveVM Parent/Child operation
    // Read opcode from auxiliary trace
    if aux_columns.len() <= 64 + OP_PARENT {
        return; // No GroveVM columns
    }

    let is_parent = aux_columns[64 + OP_PARENT][step];
    let is_child = aux_columns[64 + OP_CHILD][step];

    if is_parent == BaseElement::ZERO && is_child == BaseElement::ZERO {
        return; // Not a merge operation
    }

    // Get stack pointer (would need proper extraction in production)
    // For now, assume we can determine SP from context
    let sp = 2usize; // Placeholder - would extract from aux_columns[64 + SP][step]

    if sp < 2 {
        return; // Not enough items on stack
    }

    // Calculate indices for top two stack items
    let left_base = 64 + STACK_START + (sp - 2) * LIMBS_PER_HASH;
    let right_base = 64 + STACK_START + (sp - 1) * LIMBS_PER_HASH;

    // Check bounds
    if right_base + LIMBS_PER_HASH > aux_columns.len() {
        return;
    }

    // Route to BLAKE3 message columns (MSG0-MSG15)
    const MSG_BASE: usize = 16; // MSG0 column index

    // Determine ordering based on operation type
    let swap = is_child != BaseElement::ZERO;

    // Copy left hash (8 u32 limbs) to MSG0-MSG7
    for i in 0..8 {
        let left_limb = aux_columns[left_base + i][step];
        let right_limb = aux_columns[right_base + i][step];

        if swap {
            // Child: swap order (right, left)
            main_columns[MSG_BASE + i][step] = right_limb;
            main_columns[MSG_BASE + 8 + i][step] = left_limb;
        } else {
            // Parent: normal order (left, right)
            main_columns[MSG_BASE + i][step] = left_limb;
            main_columns[MSG_BASE + 8 + i][step] = right_limb;
        }
    }

    // Trigger BLAKE3 computation by setting appropriate control flag
    // This would be handled by the phase selector in production
}

/// Compute BLAKE3 hash for GroveVM Parent/Child operation
/// Returns the hash result as 8 u32 limbs
pub fn compute_grovevm_blake3(
    left_hash: &[u32; 8],
    right_hash: &[u32; 8],
    is_child: bool,
) -> [u32; 8] {
    // Convert limbs back to bytes
    let mut left_bytes = [0u8; 32];
    let mut right_bytes = [0u8; 32];

    for i in 0..8 {
        let left_le = left_hash[i].to_le_bytes();
        let right_le = right_hash[i].to_le_bytes();
        left_bytes[i * 4..(i + 1) * 4].copy_from_slice(&left_le);
        right_bytes[i * 4..(i + 1) * 4].copy_from_slice(&right_le);
    }

    // Concatenate in correct order
    let concat = if is_child {
        [right_bytes, left_bytes].concat()
    } else {
        [left_bytes, right_bytes].concat()
    };

    // Compute BLAKE3 hash
    let hash = blake3::hash(&concat);
    let hash_bytes = hash.as_bytes();

    // Convert back to limbs
    let mut result = [0u32; 8];
    for i in 0..8 {
        result[i] = u32::from_le_bytes([
            hash_bytes[i * 4],
            hash_bytes[i * 4 + 1],
            hash_bytes[i * 4 + 2],
            hash_bytes[i * 4 + 3],
        ]);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_parent_child_difference() {
        let left = [0x11111111u32; 8];
        let right = [0x22222222u32; 8];

        let parent_hash = compute_grovevm_blake3(&left, &right, false);
        let child_hash = compute_grovevm_blake3(&left, &right, true);

        // Parent and Child should produce different hashes due to order
        assert_ne!(parent_hash, child_hash);
    }

    #[test]
    fn test_blake3_child_is_swapped_parent() {
        let left = [0x11111111u32; 8];
        let right = [0x22222222u32; 8];

        // Child(left, right) should equal Parent(right, left)
        let child_hash = compute_grovevm_blake3(&left, &right, true);
        let swapped_parent = compute_grovevm_blake3(&right, &left, false);

        assert_eq!(child_hash, swapped_parent);
    }
}
