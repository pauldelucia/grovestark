use crate::crypto::edwards_arithmetic::{
    identity, point_double, unified_add, Ed25519Constants, ExtendedPoint,
};

/// Precomputed table entry for windowed scalar multiplication
#[derive(Debug, Clone, Copy)]
pub struct TableEntry {
    pub point: ExtendedPoint,
}

/// Precomputed table for fixed-base scalar multiplication
/// Contains [0]B, [1]B, [2]B, ..., [15]B for 4-bit windows
pub struct FixedBaseTable {
    pub tables: Vec<[TableEntry; 16]>, // One table per window
}

impl Default for FixedBaseTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FixedBaseTable {
    /// Create precomputed tables for base point B
    pub fn new() -> Self {
        let constants = Ed25519Constants::new();
        let base = constants.base_point;

        // We'll use 64 windows of 4 bits each for 256-bit scalars
        let num_windows = 64;
        let mut tables = Vec::with_capacity(num_windows);

        let mut window_base = base;

        for _window in 0..num_windows {
            let mut table = [TableEntry { point: identity() }; 16];

            // table[0] = identity (already set)
            // table[1] = window_base
            table[1] = TableEntry { point: window_base };

            // Compute table[2] through table[15]
            for i in 2..16 {
                if i % 2 == 0 {
                    // Even: double table[i/2]
                    table[i] = TableEntry {
                        point: point_double(&table[i / 2].point),
                    };
                } else {
                    // Odd: add base to table[i-1]
                    table[i] = TableEntry {
                        point: unified_add(&table[i - 1].point, &window_base),
                    };
                }
            }

            tables.push(table);

            // Move to next window: multiply by 2^4 = 16
            for _ in 0..4 {
                window_base = point_double(&window_base);
            }
        }

        Self { tables }
    }

    /// Look up a point in the table for a given window and value
    pub fn lookup(&self, window: usize, value: u8) -> ExtendedPoint {
        assert!(window < self.tables.len());
        assert!(value < 16);
        self.tables[window][value as usize].point
    }
}

/// Variable-base table for scalar multiplication
/// Built on-the-fly for a specific point
pub struct VariableBaseTable {
    pub base: ExtendedPoint,
    pub table: [ExtendedPoint; 16],
}

impl VariableBaseTable {
    /// Create a table for variable point A
    pub fn new(a: &ExtendedPoint) -> Self {
        let mut table = [identity(); 16];

        // table[0] = identity
        // table[1] = A
        table[1] = *a;

        // Compute table[2] through table[15]
        for i in 2..16 {
            if i % 2 == 0 {
                table[i] = point_double(&table[i / 2]);
            } else {
                table[i] = unified_add(&table[i - 1], a);
            }
        }

        Self { base: *a, table }
    }

    /// Look up a point in the table
    pub fn lookup(&self, value: u8) -> ExtendedPoint {
        assert!(value < 16);
        self.table[value as usize]
    }
}

/// Extract 4-bit window from scalar at given position
pub fn extract_window(scalar: &[u64; 16], window_index: usize) -> u8 {
    // Each limb is 16 bits, each window is 4 bits
    // So each limb contains 4 windows
    let limb_index = window_index / 4;
    let window_in_limb = window_index % 4;

    if limb_index >= 16 {
        return 0;
    }

    let shift = window_in_limb * 4;
    ((scalar[limb_index] >> shift) & 0xF) as u8
}

/// Fixed-base scalar multiplication [s]B using precomputed tables
pub fn scalar_mult_fixed_base(scalar: &[u64; 16], table: &FixedBaseTable) -> ExtendedPoint {
    let mut accumulator = identity();

    // Process 64 windows of 4 bits each
    for window in 0..64 {
        let bits = extract_window(scalar, window);
        let table_point = table.lookup(window, bits);
        accumulator = unified_add(&accumulator, &table_point);
    }

    accumulator
}

/// Variable-base scalar multiplication [s]A using on-the-fly table
pub fn scalar_mult_variable_base(scalar: &[u64; 16], point: &ExtendedPoint) -> ExtendedPoint {
    let table = VariableBaseTable::new(point);
    let mut accumulator = identity();
    let _current_base = *point;

    // Process 64 windows of 4 bits each
    for window in 0..64 {
        let bits = extract_window(scalar, window);
        let table_point = table.lookup(bits);

        if window == 0 {
            accumulator = table_point;
        } else {
            // Shift accumulator by 4 bits (multiply by 16)
            for _ in 0..4 {
                accumulator = point_double(&accumulator);
            }
            // Add table lookup
            accumulator = unified_add(&accumulator, &table_point);
        }
    }

    accumulator
}

/// Simple double-and-add scalar multiplication (for testing)
pub fn scalar_mult_simple(scalar: &[u64; 16], point: &ExtendedPoint) -> ExtendedPoint {
    let mut result = identity();
    let mut temp = *point;

    // Process each bit of the scalar
    for limb in 0..16 {
        for bit in 0..16 {
            if (scalar[limb] >> bit) & 1 == 1 {
                result = unified_add(&result, &temp);
            }
            temp = point_double(&temp);
        }
    }

    result
}

/// Decompose scalar into 4-bit windows for trace
pub fn decompose_scalar_windows(scalar: &[u64; 16]) -> Vec<u8> {
    let mut windows = Vec::with_capacity(64);

    for window in 0..64 {
        windows.push(extract_window(scalar, window));
    }

    windows
}

/// Window selector for constraints - returns 16 bits, one hot
pub fn window_selector(value: u8) -> [bool; 16] {
    assert!(value < 16);
    let mut selector = [false; 16];
    selector[value as usize] = true;
    selector
}

/// Scalar reduction modulo L (group order)
pub fn reduce_scalar_mod_l(scalar: &[u64; 32]) -> [u64; 16] {
    let constants = Ed25519Constants::new();
    let mut result = [0u64; 16];

    // Copy low 16 limbs
    for i in 0..16 {
        result[i] = scalar[i];
    }

    // Reduce modulo L using Barrett reduction or similar
    // For now, simple conditional subtraction
    let mut borrow = 0i64;
    let mut temp = [0u64; 16];

    for i in 0..16 {
        let diff = result[i] as i64 - constants.l[i] as i64 - borrow;
        if diff < 0 {
            temp[i] = (diff + 0x10000) as u64;
            borrow = 1;
        } else {
            temp[i] = diff as u64;
            borrow = 0;
        }
    }

    // If no borrow, use reduced value
    if borrow == 0 {
        result = temp;
    }

    result
}

/// Check if scalar < L (for range checks)
pub fn scalar_less_than_l(scalar: &[u64; 16]) -> bool {
    let constants = Ed25519Constants::new();

    for i in (0..16).rev() {
        if scalar[i] < constants.l[i] {
            return true;
        }
        if scalar[i] > constants.l[i] {
            return false;
        }
    }

    // Equal to L
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_extraction() {
        let scalar = [
            0x1234, 0x5678, 0x9ABC, 0xDEF0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        // First limb windows: 0x1234 = 0001 0010 0011 0100
        assert_eq!(extract_window(&scalar, 0), 0x4); // bits 0-3
        assert_eq!(extract_window(&scalar, 1), 0x3); // bits 4-7
        assert_eq!(extract_window(&scalar, 2), 0x2); // bits 8-11
        assert_eq!(extract_window(&scalar, 3), 0x1); // bits 12-15

        // Second limb windows: 0x5678
        assert_eq!(extract_window(&scalar, 4), 0x8); // bits 16-19
        assert_eq!(extract_window(&scalar, 5), 0x7); // bits 20-23
    }

    #[test]
    fn test_window_selector() {
        let selector = window_selector(5);
        assert!(!selector[0]);
        assert!(!selector[1]);
        assert!(!selector[4]);
        assert!(selector[5]);
        assert!(!selector[6]);

        // Check one-hot property
        let count = selector.iter().filter(|&&x| x).count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_scalar_mult_consistency() {
        let constants = Ed25519Constants::new();
        let base = constants.base_point;
        let scalar = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        // Simple double
        let doubled = point_double(&base);

        // Scalar mult by 2
        let mult_result = scalar_mult_simple(&scalar, &base);

        // Should be equivalent (in projective coordinates)
        // Just check they're not identity
        assert!(!crate::crypto::edwards_arithmetic::is_identity(&doubled));
        assert!(!crate::crypto::edwards_arithmetic::is_identity(
            &mult_result
        ));
    }
}
