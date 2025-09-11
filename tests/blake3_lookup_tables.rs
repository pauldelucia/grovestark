//! Test suite for BLAKE3 implementation using lookup tables

mod test_blake3_complete;
mod test_g_function;

use grovestark::crypto::blake3_lookup::{Blake3LookupTables, RotationTable, XorLookupTable};
use grovestark::field::FieldElement;

#[test]
fn test_xor_lookup_basic() {
    let table = XorLookupTable::new();

    // Test basic XOR properties
    assert_eq!(table.xor_8bit(0x00, 0x00), 0x00);
    assert_eq!(table.xor_8bit(0xFF, 0xFF), 0x00);
    assert_eq!(table.xor_8bit(0xAA, 0x55), 0xFF);
}

#[test]
fn test_xor_32bit_values() {
    let table = XorLookupTable::new();

    // Test 32-bit XOR matches native implementation
    let test_cases = [
        (0x12345678u32, 0x87654321u32, 0x95511559u32),
        (0xDEADBEEF, 0xCAFEBABE, 0x14530451),
        (0xFFFFFFFF, 0x00000000, 0xFFFFFFFF),
    ];

    for (a, b, expected) in test_cases {
        let result = table.xor_32bit(a, b);
        assert_eq!(result, expected, "XOR({:08X}, {:08X}) failed", a, b);

        // Verify against native XOR
        assert_eq!(result, a ^ b);
    }
}

#[test]
fn test_xor_field_elements() {
    let table = XorLookupTable::new();

    let a = FieldElement::new(0x12345678);
    let b = FieldElement::new(0x87654321);
    let result = table.xor_field(a, b);

    // Should match 32-bit XOR
    assert_eq!(result.as_u64(), 0x95511559);
}

#[test]
fn test_rotation_amounts() {
    let table = RotationTable::new();

    // Test BLAKE3's specific rotation amounts
    let x = 0x12345678u32;

    // 16-bit rotation
    assert_eq!(table.rotate_right(x, 16), 0x56781234);

    // 12-bit rotation
    assert_eq!(table.rotate_right(x, 12), 0x67812345);

    // 8-bit rotation
    assert_eq!(table.rotate_right(x, 8), 0x78123456);

    // 7-bit rotation
    assert_eq!(table.rotate_right(x, 7), 0xF02468AC);
}

#[test]
fn test_rotation_field_elements() {
    let table = RotationTable::new();

    let x = FieldElement::new(0x12345678);

    // Test all BLAKE3 rotation amounts
    let r16 = table.rotate_field(x, 16);
    let r12 = table.rotate_field(x, 12);
    let r8 = table.rotate_field(x, 8);
    let r7 = table.rotate_field(x, 7);

    assert_eq!(r16.as_u64(), 0x56781234);
    assert_eq!(r12.as_u64(), 0x67812345);
    assert_eq!(r8.as_u64(), 0x78123456);
    assert_eq!(r7.as_u64(), 0xF02468AC);
}

#[test]
fn test_xor_properties() {
    let table = XorLookupTable::new();

    // Test mathematical properties of XOR
    let values = [0x12345678u32, 0xABCDEF00, 0xDEADBEEF];

    for &a in &values {
        // Identity: a XOR 0 = a
        assert_eq!(table.xor_32bit(a, 0), a);

        // Self-inverse: a XOR a = 0
        assert_eq!(table.xor_32bit(a, a), 0);

        for &b in &values {
            // Commutative: a XOR b = b XOR a
            assert_eq!(table.xor_32bit(a, b), table.xor_32bit(b, a));

            for &c in &values {
                // Associative: (a XOR b) XOR c = a XOR (b XOR c)
                let left = table.xor_32bit(table.xor_32bit(a, b), c);
                let right = table.xor_32bit(a, table.xor_32bit(b, c));
                assert_eq!(left, right);
            }
        }
    }
}

#[test]
fn test_combined_tables() {
    let tables = Blake3LookupTables::new();

    // Test that combined tables work together
    let a = FieldElement::new(0x12345678);
    let b = FieldElement::new(0xABCDEF00);

    // XOR then rotate (common pattern in BLAKE3)
    let xored = tables.xor_table.xor_field(a, b);
    let rotated = tables.rotation_table.rotate_field(xored, 16);

    // Verify the operations
    let expected_xor = 0x12345678u32 ^ 0xABCDEF00;
    let expected_rotate = expected_xor.rotate_right(16);

    assert_eq!(rotated.as_u64(), expected_rotate as u64);
}

#[test]
fn test_lookup_table_size() {
    let tables = Blake3LookupTables::new();

    // XOR table should be 256x256 = 64KB
    assert_eq!(tables.xor_table.size_bytes(), 65536);

    println!(
        "Total lookup table size: {} bytes",
        tables.total_size_bytes()
    );
}
