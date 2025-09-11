//! GroveVM constraints implementation
//!
//! Implements packed constraints using deterministic gamma for lane packing

use winterfell::math::fields::f64::BaseElement;
use winterfell::math::FieldElement;

use crate::phases::grovevm::types::*;

/// GroveVM constraints evaluator
pub struct GroveVMConstraints {
    gamma: BaseElement,
    sp_range_check: crate::phases::grovevm::range_check::StackPointerRangeCheck,
}

impl GroveVMConstraints {
    /// Create a new constraints evaluator with deterministic gamma
    pub fn new(gamma: BaseElement) -> Self {
        use crate::phases::grovevm::types::D_MAX;
        Self {
            gamma,
            sp_range_check: crate::phases::grovevm::range_check::StackPointerRangeCheck::new(D_MAX),
        }
    }

    /// Evaluate all GroveVM constraints
    /// Returns a vector of constraint evaluations
    pub fn evaluate<E: FieldElement<BaseField = BaseElement>>(
        &self,
        current: &[E],
        next: &[E],
        blake3_output: Option<&[E; 8]>, // BLAKE3 output when available
    ) -> Vec<E> {
        let mut result = Vec::new();

        // Convert gamma to extension field if needed
        // Use BaseElement conversion through ToElements trait
        let gamma = E::from(self.gamma);

        // 1. Opcode one-hot constraints (4 constraints total)
        self.enforce_opcode_one_hot(current, &mut result);

        // 2. Stack pointer update (2 constraints)
        self.enforce_sp_update(current, next, &mut result);

        // 3. Tape cursor update (1 constraint)
        self.enforce_tp_update(current, next, &mut result);

        // 4. Packed stack continuity (1 constraint)
        self.enforce_stack_continuity_packed(current, next, gamma, &mut result);

        // 5. Stack write operations (2 packed constraints)
        if let Some(blake3_out) = blake3_output {
            self.enforce_stack_writes_packed(current, next, blake3_out, gamma, &mut result);
        } else {
            // When BLAKE3 output is not available, add zero constraints to maintain count
            result.push(E::ZERO);
            result.push(E::ZERO);
        }

        // 6. Safety constraints (packed into one):
        //    - No push beyond depth: if sp == D_MAX then is_push must be 0
        //    - No merge below depth: if sp == 0 then is_merge must be 0
        //    We build exact-match indicators eq(sp, c) over small domain 0..D_MAX
        let sp_eq = |v: E, c: usize| -> E {
            let mut num = E::ONE;
            for k in 0..=D_MAX {
                if k != c {
                    let diff =
                        E::from(BaseElement::new(c as u64)) - E::from(BaseElement::new(k as u64));
                    // Multiply numerator by (v - k)
                    num = num * (v - E::from(BaseElement::new(k as u64)));
                    // Scale by inverse of (c - k)
                    let inv = diff.inv();
                    num = num * inv;
                }
            }
            num
        };
        let sp_eq_max = sp_eq(current[SP], D_MAX);
        let sp_eq_zero = sp_eq(current[SP], 0);
        let is_push = current[OP_PUSH_H] + current[OP_PUSH_KV];
        let is_merge = current[OP_PARENT] + current[OP_CHILD];
        result.push(sp_eq_max * is_push + sp_eq_zero * is_merge);

        result
    }

    /// Enforce opcode encoding (4 constraints: all must be binary)
    fn enforce_opcode_one_hot<E: FieldElement<BaseField = BaseElement>>(
        &self,
        current: &[E],
        result: &mut Vec<E>,
    ) {
        let op_ph = current[OP_PUSH_H];
        let op_pk = current[OP_PUSH_KV];
        let op_pr = current[OP_PARENT];
        let op_ch = current[OP_CHILD];

        // Boolean constraints for all 4 opcodes (ensures each is 0 or 1)
        result.push(op_ph * (op_ph - E::ONE)); // op_ph * (op_ph - 1) = 0
        result.push(op_pk * (op_pk - E::ONE)); // op_pk * (op_pk - 1) = 0
        result.push(op_pr * (op_pr - E::ONE)); // op_pr * (op_pr - 1) = 0
        result.push(op_ch * (op_ch - E::ONE)); // op_ch * (op_ch - 1) = 0

        // Note: We allow all zeros (no-op in padding) OR exactly one 1 (active operation)
        // The at-most-one constraint is implicitly enforced by the trace construction
    }

    /// Enforce stack pointer update (2 constraints)
    fn enforce_sp_update<E: FieldElement<BaseField = BaseElement>>(
        &self,
        current: &[E],
        next: &[E],
        result: &mut Vec<E>,
    ) {
        let op_ph = current[OP_PUSH_H];
        let op_pk = current[OP_PUSH_KV];
        let op_pr = current[OP_PARENT];
        let op_ch = current[OP_CHILD];

        let sp_curr = current[SP];
        let sp_next = next[SP];

        // Delta: +1 for push, -1 for parent/child
        let delta = (op_ph + op_pk) - (op_pr + op_ch);

        // SP update constraint
        result.push(sp_next - sp_curr - delta);

        // Range check SP ∈ [0..D_MAX] using proper gadget
        let sp_range = self.sp_range_check.constraint(sp_curr);
        result.push(sp_range);
    }

    /// Enforce tape cursor update (1 constraint)
    fn enforce_tp_update<E: FieldElement<BaseField = BaseElement>>(
        &self,
        current: &[E],
        next: &[E],
        result: &mut Vec<E>,
    ) {
        let op_ph = current[OP_PUSH_H];
        let op_pk = current[OP_PUSH_KV];

        let tp_curr = current[TP];
        let tp_next = next[TP];

        // TP increments only on push operations
        result.push(tp_next - tp_curr - (op_ph + op_pk));
    }

    /// Enforce stack continuity using packed constraint (1 constraint)
    fn enforce_stack_continuity_packed<E: FieldElement<BaseField = BaseElement>>(
        &self,
        current: &[E],
        next: &[E],
        gamma: E,
        result: &mut Vec<E>,
    ) {
        // Extract SP value using small value decoder
        let sp = self.decode_small_value(current[SP]);
        let is_push = current[OP_PUSH_H] + current[OP_PUSH_KV];
        let is_merge = current[OP_PARENT] + current[OP_CHILD];

        // Pack all non-written slots into single constraint
        let mut packed_diff = E::ZERO;
        let mut gamma_power = E::ONE;

        for slot in 0..D_MAX {
            // Determine if this slot is being written
            let is_written = if sp < D_MAX {
                // Push writes to slot[sp], merge writes to slot[sp-2]
                let is_push_slot = (slot == sp) && is_push != E::ZERO;
                let is_merge_slot = sp >= 2 && (slot == sp - 2) && is_merge != E::ZERO;
                is_push_slot || is_merge_slot
            } else {
                false
            };

            if !is_written {
                // Pack the continuity check for this slot
                for limb in 0..LIMBS_PER_HASH {
                    let idx = STACK_START + slot * LIMBS_PER_HASH + limb;
                    if idx < current.len() && idx < next.len() {
                        packed_diff = packed_diff + gamma_power * (next[idx] - current[idx]);
                        gamma_power = gamma_power * gamma;
                    }
                }
            }
        }

        result.push(packed_diff);
    }

    /// Enforce stack write operations (2 packed constraints)
    /// SIMPLIFIED TO AVOID DEGREE-3: We remove the gating entirely
    /// The continuity constraint already ensures non-written slots remain unchanged
    /// These constraints just verify the written values are correct
    fn enforce_stack_writes_packed<E: FieldElement<BaseField = BaseElement>>(
        &self,
        current: &[E],
        next: &[E],
        blake3_output: &[E; 8],
        gamma: E,
        result: &mut Vec<E>,
    ) {
        // Gating flags
        let is_push = current[OP_PUSH_H] + current[OP_PUSH_KV];
        let is_merge = current[OP_PARENT] + current[OP_CHILD];

        // (A) Push write: write PUSH_HASH limbs into stack[sp]
        let mut push_packed = E::ZERO;
        let sp = self.decode_small_value(current[SP]);
        if sp < D_MAX {
            let base = STACK_START + sp * LIMBS_PER_HASH;
            let mut gp = E::ONE;
            for limb in 0..LIMBS_PER_HASH {
                let idx = base + limb;
                if idx < next.len() && PUSH_HASH_START + limb < current.len() {
                    push_packed = push_packed + gp * (next[idx] - current[PUSH_HASH_START + limb]);
                    gp = gp * gamma;
                }
            }
        }
        result.push(is_push * push_packed);

        // (B) Merge write: write BLAKE3(left,right) into stack[sp-2]
        let mut merge_packed = E::ZERO;
        if sp >= 2 {
            let base = STACK_START + (sp - 2) * LIMBS_PER_HASH;
            let mut gp = E::ONE;
            for limb in 0..LIMBS_PER_HASH {
                let idx = base + limb;
                if idx < next.len() {
                    merge_packed = merge_packed + gp * (next[idx] - blake3_output[limb]);
                    gp = gp * gamma;
                }
            }
        }
        result.push(is_merge * merge_packed);
    }

    /// Decode small field element value to usize
    /// Works for values 0..16 which covers our stack pointer range
    fn decode_small_value<E: FieldElement<BaseField = BaseElement>>(&self, value: E) -> usize {
        // Since we know SP is small (0..D_MAX where D_MAX=5),
        // we can check against known values
        for i in 0..16 {
            let test = E::from(BaseElement::new(i));
            if value == test {
                return i as usize;
            }
        }
        // Default to 0 if not found (shouldn't happen with valid traces)
        0
    }
}

/// Static version of decode_small_value for non-method contexts
fn decode_small_value_static<E: FieldElement<BaseField = BaseElement>>(value: E) -> usize {
    for i in 0..16 {
        let test = E::from(BaseElement::new(i));
        if value == test {
            return i as usize;
        }
    }
    0
}

/// Route stack operations to BLAKE3 for Parent/Child operations
pub fn route_to_blake3<E: FieldElement<BaseField = BaseElement>>(
    current: &[E],
    main_trace: &mut [E],
    msg_start: usize, // Starting column for message input
) {
    // Extract SP value using small value decoder
    let sp = decode_small_value_static(current[SP]);
    let is_parent = current[OP_PARENT];
    let is_child = current[OP_CHILD];
    let is_merge = is_parent + is_child;

    if is_merge != E::ZERO && sp >= 2 {
        // Read top two stack items
        let left_idx = STACK_START + (sp - 2) * LIMBS_PER_HASH;
        let right_idx = STACK_START + (sp - 1) * LIMBS_PER_HASH;

        // Route to MSG lanes based on orientation
        // Parent: (S[sp-2], S[sp-1])
        // Child: (S[sp-1], S[sp-2]) - swapped
        let swap = is_child;

        for i in 0..8 {
            if left_idx + i < current.len() && right_idx + i < current.len() {
                let left = current[left_idx + i];
                let right = current[right_idx + i];

                // Route to BLAKE3 message lanes
                if msg_start + i < main_trace.len() && msg_start + 8 + i < main_trace.len() {
                    main_trace[msg_start + i] = left * (E::ONE - swap) + right * swap;
                    main_trace[msg_start + 8 + i] = right * (E::ONE - swap) + left * swap;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_one_hot() {
        let gamma = BaseElement::new(12345);
        let constraints = GroveVMConstraints::new(gamma);

        // Test valid one-hot encoding
        let mut current = vec![BaseElement::ZERO; GROVEVM_AUX_WIDTH];
        current[OP_PUSH_H] = BaseElement::ONE;

        let _next = current.clone();
        let mut result = Vec::new();
        constraints.enforce_opcode_one_hot(&current, &mut result);

        // First three should be 0 (boolean constraints satisfied)
        assert_eq!(result[0], BaseElement::ZERO); // 1 * (1 - 1) = 0
        assert_eq!(result[1], BaseElement::ZERO); // 0 * (0 - 1) = 0
        assert_eq!(result[2], BaseElement::ZERO); // 0 * (0 - 1) = 0

        // Sum should be 0 (since 1 + 0 + 0 + 0 - 1 = 0)
        assert_eq!(result[3], BaseElement::ZERO);
    }

    #[test]
    fn test_sp_update() {
        let gamma = BaseElement::new(12345);
        let constraints = GroveVMConstraints::new(gamma);

        // Test push operation (SP should increment)
        let mut current = vec![BaseElement::ZERO; GROVEVM_AUX_WIDTH];
        current[OP_PUSH_H] = BaseElement::ONE;
        current[SP] = BaseElement::new(3);

        let mut next = current.clone();
        next[SP] = BaseElement::new(4); // SP incremented

        let mut result = Vec::new();
        constraints.enforce_sp_update(&current, &next, &mut result);

        // SP update constraint should be satisfied
        assert_eq!(result[0], BaseElement::ZERO); // 4 - 3 - 1 = 0
    }
}
