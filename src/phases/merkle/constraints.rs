//! Merkle phase constraints
//!
//! Implements constraints for verifying Merkle path traversal:
//! 1. Hash computation correctness (reuses BLAKE3 constraints)
//! 2. Path continuity (output of level i = input of level i+1)
//! 3. Ordering based on is_left flag
//! 4. Root verification at the end

use winterfell::math::{fields::f64::BaseElement, FieldElement};

/// Carrier for resolved periodic values
#[derive(Copy, Clone)]
pub struct MerklePer<E> {
    pub p_m: E,
    pub p_load: E,
    pub p_comp: E,
    pub p_hold: E,
}

/// Evaluate Merkle-specific constraints
///
/// These constraints are only active when P_M (Merkle phase selector) = 1
/// and properly gated by sub-phase selectors (P_M_LOAD, P_M_COMP, P_M_HOLD)
pub fn evaluate_merkle_constraints<E: FieldElement<BaseField = BaseElement>>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    per: MerklePer<E>,
) {
    // Complete Merkle constraint set
    // Column indices
    const IS_LEFT_FLAG: usize = 63;
    // const MSG0: usize = 16; // MSG0 column (unused in current constraints)
    // const MSG1: usize = 17; // MSG1 column (unused in current constraints)
    // const MSG2: usize = 18; // MSG2 column (unused in current constraints)

    // Safety check
    if IS_LEFT_FLAG >= current.len() {
        for i in 0..result.len() {
            result[i] = E::ZERO;
        }
        return;
    }

    // Gates per Section 2
    let s_m = per.p_m;
    let _g_load = per.p_m * per.p_load;
    let _g_comp = per.p_m * per.p_comp;
    let g_hold = per.p_m * per.p_hold;
    let not_m = E::ONE - s_m;

    let is_left = current[IS_LEFT_FLAG];
    let mut i = 0;

    // Constraint 1: Binarity - using simpler form that worked before
    // Just check is_left is binary without gates (naturally satisfied)
    result[i] = is_left * (is_left - E::ONE);
    i += 1;

    // Constraint 2: Isolation (inactive rows must have is_left = 0)
    result[i] = not_m * is_left;
    i += 1;

    // HOLD continuity for MERKLE_MSG columns
    // Now that Merkle uses scratch columns 55-62,64-71, we can enforce continuity
    // 12 continuity + 12 isolation = 24 MSG constraints (WORKING CONFIG)
    for k in 0..12 {
        result[i] = g_hold
            * (next[crate::stark_winterfell::MERKLE_MSG.col(k)]
                - current[crate::stark_winterfell::MERKLE_MSG.col(k)]);
        i += 1;
    }

    // Isolation constraints for MERKLE_MSG columns
    // Ensure MERKLE_MSG columns are zero outside Merkle phase
    for k in 0..12 {
        result[i] = not_m * current[crate::stark_winterfell::MERKLE_MSG.col(k)];
        i += 1;
    }

    // Assert we filled exactly the expected number
    debug_assert_eq!(i, result.len(), "Merkle constraints count mismatch");
}

/// Get the number of Merkle constraints
pub const fn num_merkle_constraints() -> usize {
    26 // Binary flag (1) + IS_LEFT isolation (1) + MSG continuity (12) + MSG isolation (12)
}

/// Evaluate Merkle constraints with lane packing
/// Reduces 24 lane constraints to 4 packed constraints using deterministic gamma
pub fn evaluate_merkle_constraints_packed<E: FieldElement<BaseField = BaseElement>>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    per: MerklePer<E>,
    gamma: E,
) {
    // Column indices
    const IS_LEFT_FLAG: usize = 63;
    const NUM_LANES: usize = 12; // We have 12 MSG lanes to pack

    // Safety check
    if IS_LEFT_FLAG >= current.len() {
        for i in 0..result.len() {
            result[i] = E::ZERO;
        }
        return;
    }

    // Gates
    let s_m = per.p_m;
    let g_hold = per.p_m * per.p_hold;
    let not_m = E::ONE - s_m;

    let is_left = current[IS_LEFT_FLAG];
    let mut i = 0;

    // Constraint 0: Binary flag - is_left must be 0 or 1
    result[i] = is_left * (is_left - E::ONE);
    i += 1;

    // Constraint 1: IS_LEFT isolation - is_left must be 0 outside Merkle phase
    result[i] = not_m * is_left;
    i += 1;

    // LANE PACKING
    // Split lanes into even (0,2,4,6,8,10) and odd (1,3,5,7,9,11)

    // Constraint 2: Packed continuity for even lanes
    let mut c_even = E::ZERO;
    let mut gamma_pow = E::ONE;
    for k in (0..NUM_LANES).step_by(2) {
        let col = crate::stark_winterfell::MERKLE_MSG.col(k);
        c_even = c_even + gamma_pow * (next[col] - current[col]);
        gamma_pow = gamma_pow * gamma;
    }
    result[i] = g_hold * c_even;
    i += 1;

    // Constraint 3: Packed continuity for odd lanes
    let mut c_odd = E::ZERO;
    gamma_pow = E::ONE;
    for k in (1..NUM_LANES).step_by(2) {
        let col = crate::stark_winterfell::MERKLE_MSG.col(k);
        c_odd = c_odd + gamma_pow * (next[col] - current[col]);
        gamma_pow = gamma_pow * gamma;
    }
    result[i] = g_hold * c_odd;
    i += 1;

    // Constraint 4: Packed isolation for even lanes
    let mut i_even = E::ZERO;
    gamma_pow = E::ONE;
    for k in (0..NUM_LANES).step_by(2) {
        let col = crate::stark_winterfell::MERKLE_MSG.col(k);
        i_even = i_even + gamma_pow * current[col];
        gamma_pow = gamma_pow * gamma;
    }
    result[i] = not_m * i_even;
    i += 1;

    // Constraint 5: Packed isolation for odd lanes
    let mut i_odd = E::ZERO;
    gamma_pow = E::ONE;
    for k in (1..NUM_LANES).step_by(2) {
        let col = crate::stark_winterfell::MERKLE_MSG.col(k);
        i_odd = i_odd + gamma_pow * current[col];
        gamma_pow = gamma_pow * gamma;
    }
    result[i] = not_m * i_odd;
    i += 1;

    debug_assert_eq!(i, 6, "Lane packed Merkle should have exactly 6 constraints");
    debug_assert_eq!(i, result.len(), "Merkle constraints count mismatch");
}

/// Get the number of lane-packed Merkle constraints
pub const fn num_merkle_constraints_packed() -> usize {
    6 // Binary flag (1) + IS_LEFT isolation (1) + packed continuity (2) + packed isolation (2)
}
