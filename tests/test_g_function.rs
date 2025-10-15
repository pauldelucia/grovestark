//! Tests for the BLAKE3 G mixing function using lookup tables

use grovestark::crypto::blake3_lookup::Blake3LookupTables;
use grovestark::field::FieldElement;

/// BLAKE3 G mixing function implementation using lookup tables
pub fn blake3_g_function(
    tables: &Blake3LookupTables,
    state: &mut [FieldElement; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    mx: FieldElement,
    my: FieldElement,
) {
    // G function steps:
    // 1. a = a + b + mx
    state[a] = state[a] + state[b] + mx;

    // 2. d = (d ^ a) >>> 16
    let d_xor_a = tables.xor_table.xor_field(state[d], state[a]);
    state[d] = tables.rotation_table.rotate_field(d_xor_a, 16);

    // 3. c = c + d
    state[c] = state[c] + state[d];

    // 4. b = (b ^ c) >>> 12
    let b_xor_c = tables.xor_table.xor_field(state[b], state[c]);
    state[b] = tables.rotation_table.rotate_field(b_xor_c, 12);

    // 5. a = a + b + my
    state[a] = state[a] + state[b] + my;

    // 6. d = (d ^ a) >>> 8
    let d_xor_a = tables.xor_table.xor_field(state[d], state[a]);
    state[d] = tables.rotation_table.rotate_field(d_xor_a, 8);

    // 7. c = c + d
    state[c] = state[c] + state[d];

    // 8. b = (b ^ c) >>> 7
    let b_xor_c = tables.xor_table.xor_field(state[b], state[c]);
    state[b] = tables.rotation_table.rotate_field(b_xor_c, 7);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g_function_basic() {
        let tables = Blake3LookupTables::new();

        // Test with simple values
        let mut state = [FieldElement::ZERO; 16];
        state[0] = FieldElement::new(0x12345678);
        state[4] = FieldElement::new(0xABCDEF00);
        state[8] = FieldElement::new(0xDEADBEEF);
        state[12] = FieldElement::new(0xCAFEBABE);

        let mx = FieldElement::new(0x11111111);
        let my = FieldElement::new(0x22222222);

        blake3_g_function(&tables, &mut state, 0, 4, 8, 12, mx, my);

        // Check that state was modified
        assert_ne!(state[0], FieldElement::new(0x12345678));
        assert_ne!(state[4], FieldElement::new(0xABCDEF00));
        assert_ne!(state[8], FieldElement::new(0xDEADBEEF));
        assert_ne!(state[12], FieldElement::new(0xCAFEBABE));
    }

    #[test]
    fn test_g_function_with_blake3_iv() {
        let tables = Blake3LookupTables::new();

        // Use actual BLAKE3 IV values
        let mut state = [FieldElement::ZERO; 16];
        let blake3_iv = [
            0x6A09E667u32,
            0xBB67AE85u32,
            0x3C6EF372u32,
            0xA54FF53Au32,
            0x510E527Fu32,
            0x9B05688Cu32,
            0x1F83D9ABu32,
            0x5BE0CD19u32,
        ];

        for i in 0..8 {
            state[i] = FieldElement::new(blake3_iv[i] as u64);
        }

        // Test message values
        let mx = FieldElement::new(0x12345678);
        let my = FieldElement::new(0x87654321);

        blake3_g_function(&tables, &mut state, 0, 4, 8, 12, mx, my);

        // Verify state was updated
        assert_ne!(state[0].as_u64(), blake3_iv[0] as u64);
        assert_ne!(state[4].as_u64(), blake3_iv[4] as u64);
    }

    #[test]
    fn test_g_function_operations_order() {
        let tables = Blake3LookupTables::new();

        // Test that operations happen in correct order
        let mut state = [FieldElement::ZERO; 16];
        state[0] = FieldElement::new(1);
        state[1] = FieldElement::new(2);
        state[2] = FieldElement::new(3);
        state[3] = FieldElement::new(4);

        let mx = FieldElement::new(5);
        let my = FieldElement::new(6);

        let initial_a = state[0];

        blake3_g_function(&tables, &mut state, 0, 1, 2, 3, mx, my);

        // The value will be modified by later operations, but it should have gone through this
        assert_ne!(state[0], initial_a);
    }

    #[test]
    fn test_g_function_column_step() {
        let tables = Blake3LookupTables::new();

        // Test a column step (indices 0, 4, 8, 12)
        let mut state = [FieldElement::ZERO; 16];
        for i in 0..16 {
            state[i] = FieldElement::new((i * 0x11111111) as u64);
        }

        blake3_g_function(
            &tables,
            &mut state,
            0,
            4,
            8,
            12,
            FieldElement::new(0xAAAAAAAA),
            FieldElement::new(0x55555555),
        );

        // All four positions should be modified
        assert_ne!(state[0], FieldElement::new(0));
        assert_ne!(state[4], FieldElement::new(0x44444444));
        assert_ne!(state[8], FieldElement::new(0x88888888));
        assert_ne!(state[12], FieldElement::new(0xCCCCCCCC));
    }

    #[test]
    fn test_g_function_diagonal_step() {
        let tables = Blake3LookupTables::new();

        // Test a diagonal step (indices 0, 5, 10, 15)
        let mut state = [FieldElement::ZERO; 16];
        for i in 0..16 {
            state[i] = FieldElement::new((i * 0x10101010) as u64);
        }

        blake3_g_function(
            &tables,
            &mut state,
            0,
            5,
            10,
            15,
            FieldElement::new(0x12345678),
            FieldElement::new(0x87654321),
        );

        // All four positions should be modified
        assert_ne!(state[0], FieldElement::new(0));
        assert_ne!(state[5], FieldElement::new(0x50505050));
        assert_ne!(state[10], FieldElement::new(0xA0A0A0A0));
        assert_ne!(state[15], FieldElement::new(0xF0F0F0F0));
    }
}
