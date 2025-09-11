use grovestark::field::FieldElement;

/// XOR lookup table for 8-bit values
/// xor_table[a][b] = a XOR b for all possible 8-bit values
pub struct XorLookupTable {
    table: Vec<Vec<u8>>,
}

impl XorLookupTable {
    /// Create a new XOR lookup table for 8-bit values
    pub fn new() -> Self {
        let mut table = vec![vec![0u8; 256]; 256];

        // Precompute all possible XOR combinations
        for a in 0..256 {
            for b in 0..256 {
                table[a][b] = (a as u8) ^ (b as u8);
            }
        }

        Self { table }
    }

    /// Lookup XOR of two 8-bit values
    pub fn xor_8bit(&self, a: u8, b: u8) -> u8 {
        self.table[a as usize][b as usize]
    }

    /// XOR two 32-bit values using 8-bit lookups
    pub fn xor_32bit(&self, a: u32, b: u32) -> u32 {
        let a_bytes = a.to_le_bytes();
        let b_bytes = b.to_le_bytes();

        let result_bytes = [
            self.xor_8bit(a_bytes[0], b_bytes[0]),
            self.xor_8bit(a_bytes[1], b_bytes[1]),
            self.xor_8bit(a_bytes[2], b_bytes[2]),
            self.xor_8bit(a_bytes[3], b_bytes[3]),
        ];

        u32::from_le_bytes(result_bytes)
    }

    /// XOR two field elements representing 32-bit values
    pub fn xor_field(&self, a: FieldElement, b: FieldElement) -> FieldElement {
        // Extract the lower 32 bits from field elements
        let a_u32 = (a.as_u64() & 0xFFFFFFFF) as u32;
        let b_u32 = (b.as_u64() & 0xFFFFFFFF) as u32;

        let result = self.xor_32bit(a_u32, b_u32);
        FieldElement::new(result as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_lookup_table_creation() {
        let table = XorLookupTable::new();

        // Test some known XOR values
        assert_eq!(table.xor_8bit(0x00, 0x00), 0x00);
        assert_eq!(table.xor_8bit(0xFF, 0xFF), 0x00);
        assert_eq!(table.xor_8bit(0xAA, 0x55), 0xFF);
        assert_eq!(table.xor_8bit(0x12, 0x34), 0x26);
    }

    #[test]
    fn test_xor_8bit_comprehensive() {
        let table = XorLookupTable::new();

        // Test XOR properties
        for a in 0..=255u8 {
            // Identity: a XOR 0 = a
            assert_eq!(table.xor_8bit(a, 0), a);

            // Self-inverse: a XOR a = 0
            assert_eq!(table.xor_8bit(a, a), 0);

            // Commutative: a XOR b = b XOR a
            for b in 0..=255u8 {
                assert_eq!(table.xor_8bit(a, b), table.xor_8bit(b, a));
            }
        }
    }

    #[test]
    fn test_xor_32bit() {
        let table = XorLookupTable::new();

        // Test known 32-bit XOR values
        assert_eq!(table.xor_32bit(0x00000000, 0x00000000), 0x00000000);
        assert_eq!(table.xor_32bit(0xFFFFFFFF, 0xFFFFFFFF), 0x00000000);
        assert_eq!(table.xor_32bit(0x12345678, 0x87654321), 0x95511559);

        // Test XOR properties for 32-bit
        let test_values = [0x00000000, 0xFFFFFFFF, 0x12345678, 0xDEADBEEF, 0xCAFEBABE];

        for &a in &test_values {
            // Identity
            assert_eq!(table.xor_32bit(a, 0), a);

            // Self-inverse
            assert_eq!(table.xor_32bit(a, a), 0);

            // Commutative
            for &b in &test_values {
                assert_eq!(table.xor_32bit(a, b), table.xor_32bit(b, a));
            }
        }
    }

    #[test]
    fn test_xor_field_elements() {
        let table = XorLookupTable::new();

        // Test XOR of field elements representing 32-bit values
        let a = FieldElement::new(0x12345678);
        let b = FieldElement::new(0x87654321);
        let result = table.xor_field(a, b);

        assert_eq!(result.as_u64(), 0x95511559);

        // Test with maximum 32-bit value
        let max_32 = FieldElement::new(0xFFFFFFFF);
        let zero = FieldElement::new(0);

        assert_eq!(table.xor_field(max_32, max_32), zero);
        assert_eq!(table.xor_field(max_32, zero), max_32);
    }

    #[test]
    fn test_xor_associative() {
        let table = XorLookupTable::new();

        // Test associative property: (a XOR b) XOR c = a XOR (b XOR c)
        let test_values = [0x12345678, 0xABCDEF00, 0x11111111];

        let left = table.xor_32bit(
            table.xor_32bit(test_values[0], test_values[1]),
            test_values[2],
        );

        let right = table.xor_32bit(
            test_values[0],
            table.xor_32bit(test_values[1], test_values[2]),
        );

        assert_eq!(left, right);
    }

    #[test]
    fn test_xor_blake3_constants() {
        let table = XorLookupTable::new();

        // Test with actual BLAKE3 IV constants
        let blake3_iv = [
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
            0x5BE0CD19,
        ];

        // XOR first two IV values (used in BLAKE3 G function)
        let result = table.xor_32bit(blake3_iv[0], blake3_iv[1]);
        assert_eq!(result, 0xD16E48E2); // Correct XOR: 0x6A09E667 ^ 0xBB67AE85
    }
}

fn main() {
    println!("XOR Lookup Table Tests");
    println!("======================");

    let table = XorLookupTable::new();

    // Demonstrate basic XOR
    let a = 0x12345678u32;
    let b = 0xABCDEF00u32;
    let result = table.xor_32bit(a, b);

    println!("0x{:08X} XOR 0x{:08X} = 0x{:08X}", a, b, result);

    // Verify with native XOR
    let native_result = a ^ b;
    println!("Native XOR result:     0x{:08X}", native_result);
    println!("Match: {}", result == native_result);
}
