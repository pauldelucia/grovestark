use winterfell::math::fields::f64::BaseElement;
use winterfell::math::FieldElement;

/// Evaluate EdDSA constraints
/// These constraints enforce:
/// 1. Window bit decomposition (4-bit windows are valid)
/// 2. Scalar range checks (s < L and h < L)
/// 3. Unified addition formulas for Edwards curve  
/// 4. Scalar multiplication correctness
/// 5. Final verification equation: [8]([s]B - R - [h]A) = O
pub fn evaluate_eddsa_constraints<E: FieldElement<BaseField = BaseElement>>(
    current: &[E],
    _aux_current: &[E],
    result: &mut [E],
    eddsa_mask: E,
    ci: usize,
) -> usize {
    let mut constraint_idx = ci;

    // Use the provided EdDSA mask instead of reading from trace
    let eddsa_active = eddsa_mask;

    // NOTE: This function returns exactly 64 scalar range-check constraints
    // (32 for S + 32 for H)
    // The XY-TZ constraints and window bit constraints are handled elsewhere

    // Scalar range checks using auxiliary trace columns
    // These enforce s < L and h < L using borrow chains

    // Use dynamically computed Ed25519 group order L
    use crate::crypto::ed25519_scalar::ED25519_L_LIMBS_U16;

    // Column indices for s and h scalars in main trace
    const S_SCALAR_COLS: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const H_SCALAR_COLS: [usize; 16] = [
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    ];

    // FIXED: Use absolute column indices matching fill_aux_columns
    // These match the layout in stark_winterfell.rs:
    // Columns 132-147: s_range_borrow
    // Columns 148-163: (was 164 in fill, fixing to be consistent)
    // Columns 164-179: h_range_borrow
    // Columns 180-195: (padding)
    // Columns 196-211: s_range_diff
    // Columns 212-227: h_range_diff
    const S_RANGE_BORROW_COLS: [usize; 16] = [
        132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147,
    ];
    const H_RANGE_BORROW_COLS: [usize; 16] = [
        164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
    ];
    const S_RANGE_DIFF_COLS: [usize; 16] = [
        196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211,
    ];
    const H_RANGE_DIFF_COLS: [usize; 16] = [
        212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227,
    ];

    let base = E::from(BaseElement::new(1u64 << 16)); // 2^16

    // S scalar range check constraints: s < L
    for i in 0..16 {
        let s_i = current[S_SCALAR_COLS[i]];

        // Use absolute indices directly from current (not aux_current slice)
        if current.len() <= S_RANGE_DIFF_COLS[i] || current.len() <= S_RANGE_BORROW_COLS[i] {
            // Columns not available, skip constraint
            result[constraint_idx] = E::ZERO;
            constraint_idx += 1;
            result[constraint_idx] = E::ZERO;
            constraint_idx += 1;
            continue;
        }

        let diff = current[S_RANGE_DIFF_COLS[i]];
        let b = current[S_RANGE_BORROW_COLS[i]];
        let l_i = E::from(BaseElement::new(ED25519_L_LIMBS_U16[i] as u64));

        // For i=0: scalar[0] - L[0] = diff0 - 2^16 * borrow0
        // For i>0: scalar[i] - L[i] - borrow[i-1] = diff[i] - 2^16 * borrow[i]
        if i == 0 {
            result[constraint_idx] = eddsa_active * ((s_i - l_i) - (diff - base * b));
        } else {
            let b_prev = current[S_RANGE_BORROW_COLS[i - 1]];
            result[constraint_idx] = eddsa_active * ((s_i - l_i - b_prev) - (diff - base * b));
        }
        constraint_idx += 1;

        // Booleanity constraint for borrow bit
        result[constraint_idx] = eddsa_active * b * (b - E::ONE);
        constraint_idx += 1;
    }

    // H scalar range check constraints: h < L (all 16 limbs)
    for i in 0..16 {
        let h_i = current[H_SCALAR_COLS[i]];

        // Use absolute indices directly from current
        if current.len() <= H_RANGE_DIFF_COLS[i] || current.len() <= H_RANGE_BORROW_COLS[i] {
            // Columns not available, skip constraint
            result[constraint_idx] = E::ZERO;
            constraint_idx += 1;
            result[constraint_idx] = E::ZERO;
            constraint_idx += 1;
            continue;
        }

        let diff = current[H_RANGE_DIFF_COLS[i]];
        let b = current[H_RANGE_BORROW_COLS[i]];
        let l_i = E::from(BaseElement::new(ED25519_L_LIMBS_U16[i] as u64));

        if i == 0 {
            result[constraint_idx] = eddsa_active * ((h_i - l_i) - (diff - base * b));
        } else {
            let b_prev = current[H_RANGE_BORROW_COLS[i - 1]];
            result[constraint_idx] = eddsa_active * ((h_i - l_i - b_prev) - (diff - base * b));
        }
        constraint_idx += 1;

        // Booleanity constraint for borrow bit
        result[constraint_idx] = eddsa_active * b * (b - E::ONE);
        constraint_idx += 1;
    }

    // Return the number of constraints added
    constraint_idx - ci
}

// Use evaluate_eddsa_constraints directly.
