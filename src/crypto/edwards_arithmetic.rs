use crate::error::Result;

// Ed25519 field prime p = 2^255 - 19 in 16-bit limbs (little-endian)
const ED25519_FIELD_PRIME: [u64; 16] = [
    0xFFED, // p[0] = 65516 (2^16 - 19)
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // p[1..7] = 2^16 - 1
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // p[8..14] = 2^16 - 1
    0x7FFF, // p[15] = 32767 (2^15 - 1, top bit clear for 255 bits total)
];

/// Extended Edwards coordinates for Ed25519
/// Represents a point (X:Y:Z:T) where x = X/Z, y = Y/Z, xy = T/Z
#[derive(Debug, Clone, Copy)]
pub struct ExtendedPoint {
    pub x: [u64; 16], // X coordinate in 16-bit limbs
    pub y: [u64; 16], // Y coordinate in 16-bit limbs
    pub z: [u64; 16], // Z coordinate in 16-bit limbs
    pub t: [u64; 16], // T coordinate in 16-bit limbs
}

/// Ed25519 curve constants
pub struct Ed25519Constants {
    /// Edwards curve parameter d = -121665/121666 mod p
    pub d: [u64; 16],
    /// 2*d for unified addition formula
    pub d2: [u64; 16],
    /// Prime modulus p = 2^255 - 19
    pub p: [u64; 16],
    /// Group order L = 2^252 + 27742317777372353535851937790883648493
    pub l: [u64; 16],
    /// Base point B
    pub base_point: ExtendedPoint,
}

impl Default for Ed25519Constants {
    fn default() -> Self {
        Self::new()
    }
}

impl Ed25519Constants {
    pub fn new() -> Self {
        // p = 2^255 - 19 in 16-bit limbs
        let mut p = [0u64; 16];
        p[0] = 0xFFED; // -19 mod 2^16
        for i in 1..15 {
            p[i] = 0xFFFF;
        }
        p[15] = 0x7FFF; // 2^255 - 1 highest bit

        // d = -121665/121666 mod p
        // This is approximately 37095705934669439343138083508754565189542113879843219016388785533085940283555
        let d = [
            0x78A3, 0x1359, 0x4DCA, 0x75EB, 0xD8AB, 0x4141, 0x0A4D, 0x0070, 0xE898, 0x7779, 0x4079,
            0x8CC7, 0xFE73, 0x2B6F, 0x6CEE, 0x5203,
        ];

        // 2*d
        let mut d2 = [0u64; 16];
        let mut carry = 0u64;
        for i in 0..16 {
            let sum = d[i] * 2 + carry;
            d2[i] = sum & 0xFFFF;
            carry = sum >> 16;
        }

        // L = 2^252 + 27742317777372353535851937790883648493
        let l = [
            0x5CF5, 0xD3ED, 0xF5D3, 0x8631, 0xEDED, 0xEDED, 0xEDED, 0xEDED, 0xEDED, 0xEDED, 0xEDED,
            0xEDED, 0xEDED, 0xEDED, 0xEDED, 0x7FFF,
        ];

        // Base point B (generator) in extended coordinates
        // x = 15112221349535400772501151409588531511454012693041857206046113283949847762202
        // y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
        let base_point = ExtendedPoint {
            x: [
                0xD51A, 0x8F25, 0x2D60, 0xC956, 0xA7B2, 0x9525, 0xC760, 0x692C, 0xDC5C, 0xFDD6,
                0xE231, 0xC0A4, 0x53FE, 0xCD6E, 0x36D3, 0x2169,
            ],
            y: [
                0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
            ],
            z: [
                0x0001, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            ],
            t: [
                // Corrected T = X*Y (since Z=1)
                0xdda3, 0xa5b7, 0x8ab3, 0x6dde, 0x52f5, 0x7751, 0x9f80, 0x20f0, 0xe37d, 0x64ab,
                0x4e8e, 0x66ea, 0x7665, 0xd78b, 0x5f0f, 0x6787,
            ],
        };

        Self {
            d,
            d2,
            p,
            l,
            base_point,
        }
    }
}

/// Modular reduction of a 32-limb product to 16 limbs mod p = 2^255 - 19
pub fn reduce_mod_p(product: &[u64; 32]) -> [u64; 16] {
    let mut result = [0u64; 16];
    let mut temp = [0u64; 32];

    // Copy product
    for i in 0..32 {
        temp[i] = product[i];
    }

    // Reduce using p = 2^255 - 19
    // Everything above bit 255 gets multiplied by 19 and added to the low part
    let mut carry = 0u64;

    // First reduction pass
    for i in 0..16 {
        let mut sum = temp[i] + carry;

        // Add contribution from high limbs multiplied by 19
        if i < 15 {
            sum += temp[i + 16] * 19;
        } else {
            // Special case for highest limb: only bits above 255
            let high_bits = temp[31] >> 15; // Bits 255 and above
            sum += high_bits * 19;
        }

        result[i] = sum & 0xFFFF;
        carry = sum >> 16;
    }

    // Second reduction pass if needed
    if carry > 0 || result[15] >= 0x8000 {
        let mut borrow = 0i64;
        for i in 0..16 {
            let diff = result[i] as i64 - Ed25519Constants::new().p[i] as i64 - borrow;
            if diff < 0 {
                result[i] = (diff + 0x10000) as u64;
                borrow = 1;
            } else {
                result[i] = diff as u64;
                borrow = 0;
            }
        }
    }

    result
}

/// Unified addition formula for extended Edwards coordinates
/// No case splits, no divisions - works for all inputs including doubling
pub fn unified_add(p1: &ExtendedPoint, p2: &ExtendedPoint) -> ExtendedPoint {
    let constants = Ed25519Constants::new();

    // Temporary storage for intermediate values
    let mut temp_a = [0u64; 32];
    let mut temp_b = [0u64; 32];
    let mut temp_c = [0u64; 32];
    let mut temp_d = [0u64; 32];

    // A = (Y1 - X1) * (Y2 - X2)
    let y1_minus_x1 = sub_mod_p(&p1.y, &p1.x);
    let y2_minus_x2 = sub_mod_p(&p2.y, &p2.x);
    mul_limbs(&y1_minus_x1, &y2_minus_x2, &mut temp_a);
    let a = reduce_mod_p(&temp_a);

    // B = (Y1 + X1) * (Y2 + X2)
    let y1_plus_x1 = add_mod_p(&p1.y, &p1.x);
    let y2_plus_x2 = add_mod_p(&p2.y, &p2.x);
    mul_limbs(&y1_plus_x1, &y2_plus_x2, &mut temp_b);
    let b = reduce_mod_p(&temp_b);

    // C = T1 * 2d * T2
    let mut t1_2d = [0u64; 32];
    mul_limbs(&p1.t, &constants.d2, &mut t1_2d);
    let t1_2d_reduced = reduce_mod_p(&t1_2d);
    mul_limbs(&t1_2d_reduced, &p2.t, &mut temp_c);
    let c = reduce_mod_p(&temp_c);

    // D = Z1 * 2 * Z2
    let z1_2 = double_mod_p(&p1.z);
    mul_limbs(&z1_2, &p2.z, &mut temp_d);
    let d = reduce_mod_p(&temp_d);

    // E = B - A
    let e = sub_mod_p(&b, &a);

    // F = D - C
    let f = sub_mod_p(&d, &c);

    // G = D + C
    let g = add_mod_p(&d, &c);

    // H = B + A
    let h = add_mod_p(&b, &a);

    // X3 = E * F
    let mut x3_temp = [0u64; 32];
    mul_limbs(&e, &f, &mut x3_temp);
    let x3 = reduce_mod_p(&x3_temp);

    // Y3 = G * H
    let mut y3_temp = [0u64; 32];
    mul_limbs(&g, &h, &mut y3_temp);
    let y3 = reduce_mod_p(&y3_temp);

    // Z3 = F * G
    let mut z3_temp = [0u64; 32];
    mul_limbs(&f, &g, &mut z3_temp);
    let z3 = reduce_mod_p(&z3_temp);

    // T3 = E * H
    let mut t3_temp = [0u64; 32];
    mul_limbs(&e, &h, &mut t3_temp);
    let t3 = reduce_mod_p(&t3_temp);

    ExtendedPoint {
        x: x3,
        y: y3,
        z: z3,
        t: t3,
    }
}

/// Point doubling (just calls unified_add with same point)
pub fn point_double(p: &ExtendedPoint) -> ExtendedPoint {
    unified_add(p, p)
}

/// Point negation: (X:Y:Z:T) -> (-X:Y:Z:-T)
pub fn point_negate(p: &ExtendedPoint) -> ExtendedPoint {
    let _constants = Ed25519Constants::new();

    ExtendedPoint {
        x: sub_mod_p(&[0; 16], &p.x),
        y: p.y,
        z: p.z,
        t: sub_mod_p(&[0; 16], &p.t),
    }
}

/// Multiply point by 8 (cofactor clearing)
pub fn point_mul_by_8(p: &ExtendedPoint) -> ExtendedPoint {
    let p2 = point_double(p);
    let p4 = point_double(&p2);
    point_double(&p4)
}

/// Add two 16-limb numbers mod p
pub fn add_mod_p(a: &[u64; 16], b: &[u64; 16]) -> [u64; 16] {
    let constants = Ed25519Constants::new();
    let mut result = [0u64; 16];
    let mut carry = 0u64;

    for i in 0..16 {
        let sum = a[i] + b[i] + carry;
        result[i] = sum & 0xFFFF;
        carry = sum >> 16;
    }

    // Reduce if >= p
    if carry > 0 || is_gte(&result, &constants.p) {
        let mut borrow = 0i64;
        for i in 0..16 {
            let diff = result[i] as i64 - constants.p[i] as i64 - borrow;
            if diff < 0 {
                result[i] = (diff + 0x10000) as u64;
                borrow = 1;
            } else {
                result[i] = diff as u64;
                borrow = 0;
            }
        }
    }

    result
}

/// Subtract two 16-limb numbers mod p
pub fn sub_mod_p(a: &[u64; 16], b: &[u64; 16]) -> [u64; 16] {
    let constants = Ed25519Constants::new();
    let mut result = [0u64; 16];
    let mut borrow = 0i64;

    for i in 0..16 {
        let diff = a[i] as i64 - b[i] as i64 - borrow;
        if diff < 0 {
            result[i] = (diff + 0x10000) as u64;
            borrow = 1;
        } else {
            result[i] = diff as u64;
            borrow = 0;
        }
    }

    // If we borrowed, add p
    if borrow != 0 {
        let mut carry = 0u64;
        for i in 0..16 {
            let sum = result[i] + constants.p[i] + carry;
            result[i] = sum & 0xFFFF;
            carry = sum >> 16;
        }
    }

    result
}

/// Double a 16-limb number mod p
pub fn double_mod_p(a: &[u64; 16]) -> [u64; 16] {
    add_mod_p(a, a)
}

/// Multiply two 16-limb numbers to get 32-limb product
pub fn mul_limbs(a: &[u64; 16], b: &[u64; 16], result: &mut [u64; 32]) {
    // Clear result
    for i in 0..32 {
        result[i] = 0;
    }

    // Schoolbook multiplication
    for i in 0..16 {
        let mut carry = 0u64;
        for j in 0..16 {
            let prod = a[i] * b[j] + result[i + j] + carry;
            result[i + j] = prod & 0xFFFF;
            carry = prod >> 16;
        }
        result[i + 16] = carry;
    }
}

/// Check if a >= b
fn is_gte(a: &[u64; 16], b: &[u64; 16]) -> bool {
    for i in (0..16).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

/// Convert affine point to extended coordinates
pub fn affine_to_extended(x: &[u64; 16], y: &[u64; 16]) -> ExtendedPoint {
    let mut t_temp = [0u64; 32];
    mul_limbs(x, y, &mut t_temp);
    let t = reduce_mod_p(&t_temp);

    ExtendedPoint {
        x: *x,
        y: *y,
        z: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        t,
    }
}

/// Field multiplication in Ed25519 field
fn field_multiply(a: &[u64; 16], b: &[u64; 16]) -> [u64; 16] {
    // Schoolbook multiplication followed by modular reduction
    let mut product = [0u128; 32];

    // Multiply
    for i in 0..16 {
        for j in 0..16 {
            product[i + j] += (a[i] as u128) * (b[j] as u128);
        }
    }

    // Reduce modulo p = 2^255 - 19
    // We use the fact that 2^255 ≡ 19 (mod p)
    for i in (16..32).rev() {
        let carry = product[i] * 19;
        product[i - 16] += carry;
        product[i] = 0;
    }

    // Handle carries and final reduction
    let mut result = [0u64; 16];
    let mut carry = 0u128;

    for i in 0..16 {
        let sum = product[i] + carry;
        result[i] = (sum & 0xFFFF) as u64;
        carry = sum >> 16;
    }

    // Final reduction if result >= p
    if is_greater_or_equal(&result, &ED25519_FIELD_PRIME) {
        subtract_field(&result, &ED25519_FIELD_PRIME)
    } else {
        result
    }
}

/// Field inversion using Fermat's little theorem: a^-1 = a^(p-2) mod p
fn field_invert(a: &[u64; 16]) -> Result<[u64; 16]> {
    // p - 2 for Ed25519 field
    let exp_p_minus_2: [u64; 16] = [
        0xFFEB, // (2^255 - 19) - 2 = 2^255 - 21
        0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
        0xFFFF, 0xFFFF, 0xFFFF, 0x7FFF,
    ];

    Ok(field_power(a, &exp_p_minus_2))
}

/// Modular exponentiation using square-and-multiply
fn field_power(base: &[u64; 16], exp: &[u64; 16]) -> [u64; 16] {
    let mut result = [0u64; 16];
    result[0] = 1; // Initialize to 1

    let mut current_base = *base;

    // Process each bit of the exponent
    for &exp_limb in exp.iter() {
        for bit_pos in 0..16 {
            if (exp_limb >> bit_pos) & 1 == 1 {
                result = field_multiply(&result, &current_base);
            }
            current_base = field_multiply(&current_base, &current_base);
        }
    }

    result
}

/// Check if a >= b (both in field representation)
fn is_greater_or_equal(a: &[u64; 16], b: &[u64; 16]) -> bool {
    for i in (0..16).rev() {
        if a[i] > b[i] {
            return true;
        } else if a[i] < b[i] {
            return false;
        }
    }
    true // Equal case
}

/// Subtract b from a in field representation (assumes a >= b)
fn subtract_field(a: &[u64; 16], b: &[u64; 16]) -> [u64; 16] {
    let mut result = [0u64; 16];
    let mut borrow = 0u64;

    for i in 0..16 {
        let diff = (a[i] as i64) - (b[i] as i64) - (borrow as i64);
        if diff >= 0 {
            result[i] = diff as u64;
            borrow = 0;
        } else {
            result[i] = (diff + 65536) as u64;
            borrow = 1;
        }
    }

    result
}

/// Decompress Ed25519 point from compressed y-coordinate
pub fn decompress_point(y_compressed: &[u8; 32]) -> Result<ExtendedPoint> {
    // Extract y coordinate (first 255 bits)
    let mut y = [0u64; 16];
    for i in 0..16 {
        let low = y_compressed[i * 2] as u64;
        let high = y_compressed[i * 2 + 1] as u64;
        y[i] = low | (high << 8);
    }

    // Clear the sign bit (bit 255) and extract it
    let sign_bit = (y_compressed[31] & 0x80) != 0;
    y[15] &= 0x7FFF;

    // Compute x from curve equation: x^2 = (y^2 - 1) / (d * y^2 + 1)
    // where d = -121665/121666 for Ed25519

    // First compute y^2
    let y_squared = field_multiply(&y, &y);

    // Compute y^2 - 1
    let mut y_squared_minus_1 = y_squared;
    if y_squared_minus_1[0] == 0 {
        // Handle underflow
        y_squared_minus_1[0] = ED25519_FIELD_PRIME[0] - 1;
        for i in 1..16 {
            if y_squared_minus_1[i] == 0 {
                y_squared_minus_1[i] = ED25519_FIELD_PRIME[i] - 1;
            } else {
                y_squared_minus_1[i] -= 1;
                break;
            }
        }
    } else {
        y_squared_minus_1[0] -= 1;
    }

    // Ed25519 d parameter = -121665/121666 mod p
    // This is a complex computation, for now use the known constant
    let d: [u64; 16] = [
        0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70,
        0x00,
    ];

    // Compute d * y^2
    let d_y_squared = field_multiply(&d, &y_squared);

    // Compute d * y^2 + 1
    let mut denominator = d_y_squared;
    denominator[0] += 1;
    if denominator[0] >= 65536 {
        // Handle carry
        denominator[0] -= 65536;
        for i in 1..16 {
            denominator[i] += 1;
            if denominator[i] < 65536 {
                break;
            }
            denominator[i] -= 65536;
        }
    }

    // Compute x^2 = (y^2 - 1) / (d * y^2 + 1) = (y^2 - 1) * (d * y^2 + 1)^-1
    let denom_inv = field_invert(&denominator)?;
    let x_squared = field_multiply(&y_squared_minus_1, &denom_inv);

    // Compute square root of x_squared
    let x = field_sqrt(&x_squared)?;

    // Apply sign bit
    let final_x = if sign_bit != ((x[0] & 1) == 1) {
        subtract_field(&ED25519_FIELD_PRIME, &x)
    } else {
        x
    };

    // Convert to extended coordinates
    Ok(affine_to_extended(&final_x, &y))
}

/// Check if two field elements are equal
fn field_equal(a: &[u64; 16], b: &[u64; 16]) -> bool {
    a.iter().zip(b.iter()).all(|(&x, &y)| x == y)
}

/// Convert extended point to affine coordinates (for final output)
pub fn extended_to_affine(p: &ExtendedPoint) -> Result<([u64; 16], [u64; 16])> {
    // Compute Z^-1 mod p using Fermat's little theorem: z^-1 = z^(p-2) mod p
    // where p = 2^255 - 19 for Ed25519
    let z_inv = field_invert(&p.z)?;

    // Convert to affine: (x/z, y/z)
    let affine_x = field_multiply(&p.x, &z_inv);
    let affine_y = field_multiply(&p.y, &z_inv);

    Ok((affine_x, affine_y))
}

/// Identity element in extended coordinates
pub fn identity() -> ExtendedPoint {
    ExtendedPoint {
        x: [0; 16],
        y: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        z: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        t: [0; 16],
    }
}

/// Check if point is identity (legacy - kept for compatibility)
pub fn is_identity(p: &ExtendedPoint) -> bool {
    // Identity has X = 0, Y = Z (any non-zero), T = 0
    p.x.iter().all(|&x| x == 0) && p.t.iter().all(|&t| t == 0)
}

/// Is projective-identity? On Edwards extended, any (0:λ:λ:0) with λ != 0 is identity.
/// We check X = 0, T = 0, Y == Z, and Y (==Z) is nonzero (mod p).
pub fn is_identity_projective(p: &ExtendedPoint) -> bool {
    // Check X = 0
    let x_is_zero = p.x.iter().all(|&x| x == 0);

    // Check T = 0
    let t_is_zero = p.t.iter().all(|&t| t == 0);

    // Check Y == Z by comparing all limbs
    let y_eq_z = p.y.iter().zip(p.z.iter()).all(|(&y, &z)| y == z);

    // Check Y is nonzero (at least one limb is non-zero)
    let y_is_nonzero = p.y.iter().any(|&y| y != 0);

    x_is_zero && t_is_zero && y_eq_z && y_is_nonzero
}

/// Normalize the projective identity representative (0:λ:λ:0) to canonical (0:1:1:0).
/// Call this only if `is_identity_projective(p)` returned true.
pub fn normalize_identity_in_place(p: &mut ExtendedPoint) {
    // X=0, T=0 by assumption; set Y=1, Z=1 canonically
    p.x = [0; 16];
    p.t = [0; 16];
    p.y = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    p.z = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
}

// Public field operation functions for use by other modules
pub fn field_add(a: &[u64; 16], b: &[u64; 16]) -> [u64; 16] {
    add_mod_p(a, b)
}

pub fn field_sub(a: &[u64; 16], b: &[u64; 16]) -> [u64; 16] {
    sub_mod_p(a, b)
}

pub fn field_mul(a: &[u64; 16], b: &[u64; 16]) -> [u64; 16] {
    field_multiply(a, b)
}

pub fn field_div(a: &[u64; 16], b: &[u64; 16]) -> Result<[u64; 16]> {
    let b_inv = field_invert(b)?;
    Ok(field_multiply(a, &b_inv))
}

pub fn field_square(a: &[u64; 16]) -> [u64; 16] {
    field_multiply(a, a)
}

pub fn field_sqrt(a: &[u64; 16]) -> Result<[u64; 16]> {
    // For Ed25519 field p = 2^255 - 19, we can use the fact that p ≡ 5 (mod 8)
    // So sqrt(a) = a^((p+3)/8) if a^((p-1)/2) = 1, else a^((p+3)/8) * sqrt(-1)

    // Exponent (p+3)/8 for Ed25519
    let exp_p_plus_3_div_8: [u64; 16] = [
        0xFFFE, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
        0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x0FFF,
    ];

    let candidate = field_power(a, &exp_p_plus_3_div_8);

    // Check if candidate^2 == a
    let candidate_squared = field_multiply(&candidate, &candidate);
    if field_equal(&candidate_squared, a) {
        Ok(candidate)
    } else {
        // Try candidate * sqrt(-1)
        // sqrt(-1) in Ed25519 field is 2^((p-1)/4)
        let sqrt_minus_1: [u64; 16] = [
            0x61b2, 0x7dca, 0x7a7e, 0x0a2d, 0x3c39, 0x1a5d, 0x4c3b, 0x1c7a, 0x1b6e, 0x7f24, 0x5f25,
            0x5c1f, 0x7a7a, 0x7e7e, 0x7e7e, 0x7e7e,
        ];

        let final_candidate = field_multiply(&candidate, &sqrt_minus_1);
        let final_squared = field_multiply(&final_candidate, &final_candidate);

        if field_equal(&final_squared, a) {
            Ok(final_candidate)
        } else {
            Err(crate::error::Error::InvalidInput(
                "No square root exists".into(),
            ))
        }
    }
}

pub fn field_negate(a: &[u64; 16]) -> [u64; 16] {
    sub_mod_p(&ED25519_FIELD_PRIME, a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_point_operations() {
        let constants = Ed25519Constants::new();
        let base = constants.base_point;

        // Test doubling
        let doubled = point_double(&base);
        assert!(!is_identity(&doubled));

        // Test addition
        let sum = unified_add(&base, &doubled);
        assert!(!is_identity(&sum));

        // Test identity
        let id = identity();
        assert!(is_identity(&id));

        // Test adding identity
        let base_plus_id = unified_add(&base, &id);
        // Should not be identity (it's the base point)
        assert!(!is_identity(&base_plus_id));
    }

    #[test]
    fn test_modular_arithmetic() {
        let a = [0xFFFF; 16];
        let b = [0x0001, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let sum = add_mod_p(&a, &b);
        let diff = sub_mod_p(&a, &b);

        // Basic sanity checks
        assert!(sum[0] != a[0] || sum[1] != a[1]);
        assert!(diff[0] != a[0] || diff[1] != a[1]);
    }
}
