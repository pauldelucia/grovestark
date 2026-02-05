//! GroveVM constraints implementation
//!
//! Implements packed constraints using deterministic gamma for lane packing.
//! All stack index selection uses algebraic Lagrange indicators (sp_eq)
//! instead of non-algebraic decode_small_value.

use winterfell::math::fields::f64::BaseElement;
use winterfell::math::FieldElement;

use crate::phases::grovevm::types::*;

/// Algebraic Lagrange indicator: returns 1 when `v == c`, 0 when `v ∈ {0..D_MAX}\{c}`.
/// Degree = D_MAX (= 5).
fn sp_eq<E: FieldElement<BaseField = BaseElement>>(v: E, c: usize) -> E {
    let mut num = E::ONE;
    for k in 0..=D_MAX {
        if k != c {
            let diff = E::from(BaseElement::new(c as u64)) - E::from(BaseElement::new(k as u64));
            num = num * (v - E::from(BaseElement::new(k as u64)));
            let inv = diff.inv();
            num = num * inv;
        }
    }
    num
}

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
    /// Returns a vector of 12 constraint evaluations
    pub fn evaluate<E: FieldElement<BaseField = BaseElement>>(
        &self,
        current: &[E],
        next: &[E],
        blake3_output: Option<&[E; 8]>, // BLAKE3 output when available
    ) -> Vec<E> {
        let mut result = Vec::new();

        let gamma = E::from(self.gamma);

        // 1. Opcode one-hot constraints (5 constraints: 4 booleanity + 1 at-most-one)
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
            result.push(E::ZERO);
            result.push(E::ZERO);
        }

        // 6. Safety constraints (packed into one):
        //    - No push beyond depth: if sp == D_MAX then is_push must be 0
        //    - No merge below depth: if sp == 0 then is_merge must be 0
        let sp_eq_max = sp_eq(current[SP], D_MAX);
        let sp_eq_zero = sp_eq(current[SP], 0);
        let is_push = current[OP_PUSH_H] + current[OP_PUSH_KV];
        let is_merge = current[OP_PARENT] + current[OP_CHILD];
        result.push(sp_eq_max * is_push + sp_eq_zero * is_merge);

        result
    }

    /// Enforce opcode encoding (5 constraints: 4 binary + 1 at-most-one)
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
        result.push(op_ph * (op_ph - E::ONE));
        result.push(op_pk * (op_pk - E::ONE));
        result.push(op_pr * (op_pr - E::ONE));
        result.push(op_ch * (op_ch - E::ONE));

        // At-most-one constraint: sum ∈ {0, 1}
        let sum = op_ph + op_pk + op_pr + op_ch;
        result.push(sum * (sum - E::ONE));
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

        result.push(tp_next - tp_curr - (op_ph + op_pk));
    }

    /// Enforce stack continuity using algebraic packed constraint (1 constraint)
    ///
    /// For each slot, compute `is_written = is_push * sp_eq(sp, slot) + is_merge * sp_eq(sp, slot+2)`,
    /// then pack `(1 - is_written) * (next[idx] - current[idx])` with gamma.
    fn enforce_stack_continuity_packed<E: FieldElement<BaseField = BaseElement>>(
        &self,
        current: &[E],
        next: &[E],
        gamma: E,
        result: &mut Vec<E>,
    ) {
        let sp_val = current[SP];
        let is_push = current[OP_PUSH_H] + current[OP_PUSH_KV];
        let is_merge = current[OP_PARENT] + current[OP_CHILD];

        let mut packed_diff = E::ZERO;
        let mut gamma_power = E::ONE;

        for slot in 0..D_MAX {
            // Algebraically determine if this slot is being written:
            // Push writes to slot[sp], so is_written_by_push = is_push * sp_eq(sp, slot)
            let is_push_target = is_push * sp_eq(sp_val, slot);

            // Merge writes to slot[sp-2], so is_written_by_merge = is_merge * sp_eq(sp, slot+2)
            // sp_eq(sp, slot+2) is well-defined for slot+2 <= D_MAX
            let is_merge_target = if slot + 2 <= D_MAX {
                is_merge * sp_eq(sp_val, slot + 2)
            } else {
                E::ZERO
            };

            let is_written = is_push_target + is_merge_target;

            // Pack the continuity check: (1 - is_written) * (next - current) for each limb
            for limb in 0..LIMBS_PER_HASH {
                let idx = STACK_START + slot * LIMBS_PER_HASH + limb;
                if idx < current.len() && idx < next.len() {
                    packed_diff = packed_diff
                        + gamma_power * (E::ONE - is_written) * (next[idx] - current[idx]);
                    gamma_power = gamma_power * gamma;
                }
            }
        }

        result.push(packed_diff);
    }

    /// Enforce stack write operations using algebraic selection (2 packed constraints)
    fn enforce_stack_writes_packed<E: FieldElement<BaseField = BaseElement>>(
        &self,
        current: &[E],
        next: &[E],
        blake3_output: &[E; 8],
        gamma: E,
        result: &mut Vec<E>,
    ) {
        let sp_val = current[SP];
        let is_push = current[OP_PUSH_H] + current[OP_PUSH_KV];
        let is_merge = current[OP_PARENT] + current[OP_CHILD];

        // (A) Push write: write PUSH_HASH limbs into stack[sp]
        // Use algebraic selection: sum over all possible slots, gated by sp_eq
        let mut push_packed = E::ZERO;
        let mut gp = E::ONE;
        for limb in 0..LIMBS_PER_HASH {
            // For each limb, compute the algebraically selected next value
            let mut selected_next = E::ZERO;
            for slot in 0..D_MAX {
                let idx = STACK_START + slot * LIMBS_PER_HASH + limb;
                if idx < next.len() {
                    selected_next += sp_eq(sp_val, slot) * next[idx];
                }
            }
            if PUSH_HASH_START + limb < current.len() {
                push_packed += gp * (selected_next - current[PUSH_HASH_START + limb]);
            }
            gp = gp * gamma;
        }
        result.push(is_push * push_packed);

        // (B) Merge write: write BLAKE3(left,right) into stack[sp-2]
        // Use algebraic selection: sum over all possible slots, gated by sp_eq(sp, slot+2)
        let mut merge_packed = E::ZERO;
        let mut gp = E::ONE;
        for limb in 0..LIMBS_PER_HASH {
            let mut selected_next = E::ZERO;
            for slot in 0..D_MAX {
                if slot + 2 <= D_MAX {
                    let idx = STACK_START + slot * LIMBS_PER_HASH + limb;
                    if idx < next.len() {
                        selected_next += sp_eq(sp_val, slot + 2) * next[idx];
                    }
                }
            }
            merge_packed += gp * (selected_next - blake3_output[limb]);
            gp = gp * gamma;
        }
        result.push(is_merge * merge_packed);
    }
}

/// Route stack operations to BLAKE3 for Parent/Child operations.
/// Note: route_to_blake3 is used at trace generation time (not constraint evaluation)
/// so non-algebraic decode is acceptable here.
pub fn route_to_blake3<E: FieldElement<BaseField = BaseElement>>(
    current: &[E],
    main_trace: &mut [E],
    msg_start: usize,
) {
    // Extract SP value (trace-time only, non-algebraic is fine)
    let sp = {
        let mut found = 0usize;
        for i in 0..16 {
            if current[SP] == E::from(BaseElement::new(i as u64)) {
                found = i;
                break;
            }
        }
        found
    };
    let is_parent = current[OP_PARENT];
    let is_child = current[OP_CHILD];
    let is_merge = is_parent + is_child;

    if is_merge != E::ZERO && sp >= 2 {
        let left_idx = STACK_START + (sp - 2) * LIMBS_PER_HASH;
        let right_idx = STACK_START + (sp - 1) * LIMBS_PER_HASH;

        let swap = is_child;

        for i in 0..8 {
            if left_idx + i < current.len() && right_idx + i < current.len() {
                let left = current[left_idx + i];
                let right = current[right_idx + i];

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

        // First four should be 0 (boolean constraints satisfied)
        assert_eq!(result[0], BaseElement::ZERO); // 1 * (1 - 1) = 0
        assert_eq!(result[1], BaseElement::ZERO); // 0 * (0 - 1) = 0
        assert_eq!(result[2], BaseElement::ZERO); // 0 * (0 - 1) = 0
        assert_eq!(result[3], BaseElement::ZERO); // 0 * (0 - 1) = 0

        // At-most-one: sum=1, 1*(1-1)=0
        assert_eq!(result[4], BaseElement::ZERO);
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
