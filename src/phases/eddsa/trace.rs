use crate::crypto::edwards_arithmetic::ExtendedPoint;
use winterfell::math::fields::f64::BaseElement;

// Column assignments for EdDSA phase - must fit within 72 columns!
// We'll reuse columns during different phases since they don't overlap in time

// Scalars s and h (stored once, reused throughout)
pub const S_SCALAR_COLS: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
pub const H_SCALAR_COLS: [usize; 16] = [
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];

// Control columns
pub const WINDOW_BITS_COL: usize = 32; // Current window value (0-15)
pub const WINDOW_INDEX_COL: usize = 33; // Which window we're processing (0-63)
pub const PHASE_SELECTOR_COL: usize = 34; // 0=sB, 1=hA, 2=combine, 3=x8

// Extended point accumulator - MOVED TO AUXILIARY SECTION (132+) TO AVOID CONFLICTS
// These now use the same indices as X_COLS and Y_COLS in stark_winterfell.rs
pub const ACCUMULATOR_X_COLS: [usize; 16] = [
    132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147,
];
pub const ACCUMULATOR_Y_COLS: [usize; 16] = [
    148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163,
];
// Z and T coordinates will be stored in auxiliary trace
// Following researcher's recommendation: main trace for X,Y; aux trace for Z,T
pub const AUX_Z_COLS: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
pub const AUX_T_COLS: [usize; 16] = [
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];

// Binary decomposition for 4-bit windows (researcher's recommendation)
pub const WINDOW_BIT0_COL: usize = 68; // b0 (LSB)
pub const WINDOW_BIT1_COL: usize = 69; // b1
pub const WINDOW_BIT2_COL: usize = 70; // b2
pub const WINDOW_BIT3_COL: usize = 71; // b3 (MSB)

// For R and A points, we'll store them in the accumulator columns when needed
// Since we process sequentially, we don't need all points simultaneously
pub const R_POINT_X_COLS: [usize; 16] = ACCUMULATOR_X_COLS;
pub const R_POINT_Y_COLS: [usize; 16] = ACCUMULATOR_Y_COLS;
pub const A_POINT_X_COLS: [usize; 16] = ACCUMULATOR_X_COLS;
pub const A_POINT_Y_COLS: [usize; 16] = ACCUMULATOR_Y_COLS;

// Helper function to convert bytes to 16-bit limbs
pub fn bytes_to_limbs(bytes: &[u8; 32]) -> [u64; 16] {
    let mut limbs = [0u64; 16];
    for i in 0..16 {
        let low = bytes[i * 2] as u64;
        let high = bytes[i * 2 + 1] as u64;
        limbs[i] = low | (high << 8);
    }
    limbs
}

// Helper function to store an extended point
// Per GUIDANCE.md: ALL EdDSA coordinates (X,Y,Z,T) are in auxiliary segment
// This function is now a no-op for the main trace
pub fn store_extended_point(_trace: &mut [Vec<BaseElement>], _row: usize, _point: &ExtendedPoint) {
    // Do nothing - EdDSA coordinates are stored separately and written to auxiliary trace
    // The actual coordinates are collected in EddsaAuxStorage during fill_eddsa_phase_with_aux
}
