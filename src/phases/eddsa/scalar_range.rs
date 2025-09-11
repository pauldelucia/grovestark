//! Scalar range check for EdDSA
//!
//! Ensures that scalars s and h are less than the Ed25519 group order L
//! uses a borrow-chain pattern for modular range checks.

use winterfell::math::fields::f64::BaseElement;
use winterfell::math::FieldElement;

use crate::crypto::ed25519_scalar::ED25519_L_LIMBS_U16;

// Re-export for backward compatibility
pub fn ed25519_group_order() -> [u16; 16] {
    *ED25519_L_LIMBS_U16
}

// Keep the old constant name for compatibility but use the dynamic version
pub const ED25519_GROUP_ORDER: [u16; 16] = [0; 16]; // This will be replaced at runtime

/// Helper function to compute borrow chain for scalar < L
/// Returns (difference, borrow_out) where difference = scalar - L with borrows
pub fn compute_scalar_borrow_chain(scalar: &[u16; 16]) -> ([u16; 16], [u16; 16]) {
    const BASE16: i32 = 1 << 16;
    let mut diff = [0u16; 16];
    let mut borrow = [0u16; 16];
    let mut borrow_in: i32 = 0;

    let l = *ED25519_L_LIMBS_U16;

    for i in 0..16 {
        let t = scalar[i] as i32 - l[i] as i32 - borrow_in;
        if t >= 0 {
            diff[i] = t as u16;
            borrow[i] = 0;
            borrow_in = 0;
        } else {
            diff[i] = (t + BASE16) as u16;
            borrow[i] = 1;
            borrow_in = 1;
        }
    }

    (diff, borrow)
}

/// Generate constraints for scalar range check: scalar < L
/// Uses a borrow-chain pattern with the Ed25519 group order
pub fn generate_scalar_range_constraints<E: FieldElement<BaseField = BaseElement>>(
    result: &mut [E],
    constraint_offset: usize,
    scalar_cols: &[usize; 16], // Column indices for scalar limbs
    diff_cols: &[usize; 16],   // Auxiliary columns for difference limbs
    borrow_cols: &[usize; 16], // Auxiliary columns for borrow chain
    current_row: &[E],         // Current row values from evaluation frame
    gate: E,                   // Phase gate (only active during EdDSA)
) -> usize {
    let mut ci = constraint_offset;
    let base = E::from(65536u32); // 2^16

    // Ed25519 group order L in field elements
    let l = *ED25519_L_LIMBS_U16;
    let l_limbs: [E; 16] = [
        E::from(BaseElement::new(l[0] as u64)),
        E::from(BaseElement::new(l[1] as u64)),
        E::from(BaseElement::new(l[2] as u64)),
        E::from(BaseElement::new(l[3] as u64)),
        E::from(BaseElement::new(l[4] as u64)),
        E::from(BaseElement::new(l[5] as u64)),
        E::from(BaseElement::new(l[6] as u64)),
        E::from(BaseElement::new(l[7] as u64)),
        E::from(BaseElement::new(l[8] as u64)),
        E::from(BaseElement::new(l[9] as u64)),
        E::from(BaseElement::new(l[10] as u64)),
        E::from(BaseElement::new(l[11] as u64)),
        E::from(BaseElement::new(l[12] as u64)),
        E::from(BaseElement::new(l[13] as u64)),
        E::from(BaseElement::new(l[14] as u64)),
        E::from(BaseElement::new(l[15] as u64)),
    ];

    // i = 0: scalar[0] - L[0] - 0 = diff[0] - base * borrow[0]
    {
        let scalar0 = current_row[scalar_cols[0]];
        let diff0 = current_row[diff_cols[0]];
        let borrow0 = current_row[borrow_cols[0]];

        result[ci] = gate * ((scalar0 - l_limbs[0]) - (diff0 - base * borrow0));
        ci += 1;

        // Booleanity of borrow[0]
        result[ci] = gate * borrow0 * (borrow0 - E::ONE);
        ci += 1;
    }

    // i = 1..15: scalar[i] - L[i] - borrow[i-1] = diff[i] - base * borrow[i]
    for i in 1..16 {
        let scalar_i = current_row[scalar_cols[i]];
        let diff_i = current_row[diff_cols[i]];
        let borrow_i = current_row[borrow_cols[i]];
        let borrow_prev = current_row[borrow_cols[i - 1]];

        result[ci] = gate * ((scalar_i - l_limbs[i] - borrow_prev) - (diff_i - base * borrow_i));
        ci += 1;

        // Booleanity of borrow[i]
        result[ci] = gate * borrow_i * (borrow_i - E::ONE);
        ci += 1;
    }

    // Final borrow must be 1 (proving scalar < L): borrow[15] == 1
    let borrow_last = current_row[borrow_cols[15]];
    result[ci] = gate * (borrow_last - E::ONE);
    ci += 1;

    ci - constraint_offset
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_borrow_chain() {
        // Test with scalar = L - 1 (should be valid)
        let mut scalar = *ED25519_L_LIMBS_U16;
        scalar[0] -= 1; // Make it L - 1

        let (diff, borrow) = compute_scalar_borrow_chain(&scalar);

        // Final borrow should be 1 (proving scalar < L)
        assert_eq!(borrow[15], 1);

        // For scalar = L - 1, diff should be [0xFFFF, 0xFFFF, ..., 0x0FFF]
        assert_eq!(diff[0], 0xFFFF);
    }

    #[test]
    fn test_scalar_at_limit() {
        // Test with scalar = L (should fail - not less than L)
        let scalar = *ED25519_L_LIMBS_U16;

        let (diff, borrow) = compute_scalar_borrow_chain(&scalar);

        // Final borrow should be 0 (proving scalar >= L)
        assert_eq!(borrow[15], 0);

        // Difference should be exactly 0
        for i in 0..16 {
            assert_eq!(diff[i], 0);
        }
    }

    #[test]
    fn test_small_scalar() {
        // Test with small scalar (definitely < L)
        let mut scalar = [0u16; 16];
        scalar[0] = 42; // Small scalar

        let (_diff, borrow) = compute_scalar_borrow_chain(&scalar);

        // Final borrow should be 1 (proving scalar < L)
        assert_eq!(borrow[15], 1);
    }
}
