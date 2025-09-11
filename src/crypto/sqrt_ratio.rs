// Bullet-proof sqrt_ratio implementation for Ed25519 field
use crate::crypto::fe25519_digits as fe;
use fe::Limbs16;

fn pow_le(mut base: Limbs16, exp_le: &[u8]) -> Limbs16 {
    let mut res = fe::one();
    for &byte in exp_le {
        for i in 0..8 {
            if ((byte >> i) & 1) == 1 {
                res = fe::mul(&res, &base);
            }
            base = fe::sqr(&base);
        }
    }
    res
}

// (p-5)/8 = 2^252 - 3
#[allow(dead_code)]
fn exp_p_minus_5_div_8_le() -> Vec<u8> {
    use num_bigint::BigUint;
    use num_traits::One;
    let mut e: BigUint = BigUint::one() << 252;
    e -= BigUint::from(3u32);
    e.to_bytes_le()
}

// (p-1)/4 = 2^253 - 5
#[allow(dead_code)]
fn exp_p_minus_1_div_4_le() -> Vec<u8> {
    use num_bigint::BigUint;
    use num_traits::One;
    let mut e: BigUint = BigUint::one() << 253;
    e -= BigUint::from(5u32);
    e.to_bytes_le()
}

// sqrt(-1) mod p - computed as 2^((p-1)/4) for p ≡ 5 (mod 8)
fn sqrt_m1_const() -> Limbs16 {
    // Computed as 2^(2^253 - 5) which gives sqrt(-1) for Ed25519 field
    // This value satisfies i^2 ≡ -1 (mod p)
    [
        0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099,
        0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83,
    ]
}

/// Returns (is_square, sqrt(u/v)). If false, the return value is zero.
/// Implements the correct algorithm for p ≡ 5 (mod 8) fields like Ed25519
pub fn sqrt_ratio_i(u: &Limbs16, v: &Limbs16) -> (bool, Limbs16) {
    // Special case: if v = 0, then u/v is undefined
    let v_is_zero = {
        let mut v_can = *v;
        fe::canonicalize(&mut v_can);
        v_can == fe::zero()
    };
    if v_is_zero {
        return (false, fe::zero());
    }

    // Special case: if u = 0, then sqrt(u/v) = 0
    let u_is_zero = {
        let mut u_can = *u;
        fe::canonicalize(&mut u_can);
        u_can == fe::zero()
    };
    if u_is_zero {
        return (true, fe::zero());
    }

    // For p ≡ 5 (mod 8), we use the following algorithm:
    // Let w = u * v^3. Then w^((p-5)/8) gives us a candidate.
    // r = u * v^3 * (u * v^7)^((p-5)/8) is the standard formula.

    // First compute v^(-1) so we can work with u/v directly
    let v_inv = field_invert(v);
    let ratio = fe::mul(u, &v_inv); // ratio = u/v

    // Now compute sqrt(ratio) using the standard algorithm for p ≡ 5 (mod 8)
    let (exists, mut sqrt_ratio) = sqrt_p5mod8(&ratio);

    if !exists {
        return (false, fe::zero());
    }

    // Verify our result: sqrt_ratio^2 should equal ratio
    let check = fe::sqr(&sqrt_ratio);
    let mut ratio_can = ratio;
    let mut check_can = check;
    fe::canonicalize(&mut ratio_can);
    fe::canonicalize(&mut check_can);

    if !fe::ct_eq(&check_can, &ratio_can) {
        // Try the other square root (negate it)
        sqrt_ratio = fe::neg(&sqrt_ratio);
        let check2 = fe::sqr(&sqrt_ratio);
        let mut check2_can = check2;
        fe::canonicalize(&mut check2_can);

        if !fe::ct_eq(&check2_can, &ratio_can) {
            return (false, fe::zero()); // Neither root works
        }
    }

    (true, sqrt_ratio)
}

/// Compute modular inverse using Fermat's little theorem: a^(p-2) mod p
fn field_invert(a: &Limbs16) -> Limbs16 {
    // For p = 2^255 - 19, compute a^(2^255 - 21)
    // We can reuse our exponentiation: (2^255 - 21) = (2^252 - 3) * 8 + 3
    // But it's easier to just compute a^(p-2) directly

    use num_bigint::BigUint;
    use num_traits::One;

    // p - 2 = 2^255 - 21
    let mut exp: BigUint = BigUint::one() << 255;
    exp -= BigUint::from(21u32);

    pow_le(*a, &exp.to_bytes_le())
}

/// Compute square root for p ≡ 5 (mod 8) field using standard algorithm
fn sqrt_p5mod8(a: &Limbs16) -> (bool, Limbs16) {
    // For p ≡ 5 (mod 8), we compute r = a^((p+3)/8)
    // Then check if r^2 = a or r^2 = -a

    use num_bigint::BigUint;
    use num_traits::One;

    // (p + 3) / 8 = (2^255 - 19 + 3) / 8 = (2^255 - 16) / 8 = 2^252 - 2
    let mut exp: BigUint = BigUint::one() << 252;
    exp -= BigUint::from(2u32);

    let r = pow_le(*a, &exp.to_bytes_le());
    let r_squared = fe::sqr(&r);

    // Check if r^2 = a
    let mut a_can = *a;
    let mut r_sq_can = r_squared;
    fe::canonicalize(&mut a_can);
    fe::canonicalize(&mut r_sq_can);

    if fe::ct_eq(&r_sq_can, &a_can) {
        return (true, r);
    }

    // Check if r^2 = -a (then multiply by sqrt(-1))
    let neg_a = fe::neg(&a_can);
    let mut neg_a_can = neg_a;
    fe::canonicalize(&mut neg_a_can);

    if fe::ct_eq(&r_sq_can, &neg_a_can) {
        let sqrt_neg1 = sqrt_m1_const();
        let result = fe::mul(&r, &sqrt_neg1);
        return (true, result);
    }

    // No square root exists
    (false, fe::zero())
}

// Wrapper for backwards compatibility with existing code
pub fn recover_x_from_y(y: &Limbs16, x_sign: u16, d: &Limbs16) -> Result<Limbs16, &'static str> {
    // X from: x^2 = (y^2 - 1) / (d*y^2 + 1)
    let y2 = fe::sqr(y);
    let u = fe::sub(&y2, &fe::one());
    let dy2 = fe::mul(d, &y2);
    let v = fe::add(&dy2, &fe::one());

    let (ok, mut x) = sqrt_ratio_i(&u, &v);
    if !ok {
        return Err("no square root");
    }

    // fix sign
    if (x[0] & 1) != (x_sign & 1) {
        x = fe::neg(&x);
    }

    Ok(x)
}

// Keep old function name for compatibility
pub fn sqrt_ratio_m1(u: &Limbs16, v: &Limbs16) -> (bool, Limbs16) {
    sqrt_ratio_i(u, v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqrt_minus_one_is_not_pm_one_and_squares_to_minus_one() {
        let one = fe::one();
        let neg_one = fe::neg(&one);

        let (ok, i) = sqrt_ratio_i(&neg_one, &one); // sqrt(-1/1)
        assert!(ok, "sqrt(-1) should exist in p ≡ 5 mod 8");

        // i^2 == -1
        let i2 = fe::mul(&i, &i);
        assert!(fe::ct_eq(&i2, &neg_one), "i^2 must be -1");

        // i != 1 and i != -1
        assert!(!fe::ct_eq(&i, &one), "sqrt(-1) must not be +1");
        assert!(!fe::ct_eq(&i, &neg_one), "sqrt(-1) must not be -1");
    }

    #[test]
    fn test_sqrt_ratio_basic() {
        // Test sqrt(4/1) = 2
        let four = fe::from_u32(4);
        let one = fe::one();
        let (ok, x) = sqrt_ratio_i(&four, &one);
        assert!(ok);
        let xsq = fe::sqr(&x);
        assert!(fe::ct_eq(&xsq, &four));
    }

    #[test]
    fn sqrt_minus_one_squares_to_minus_one() {
        let i = sqrt_m1_const();
        let i_squared = fe::sqr(&i);
        // i_squared should be -1 mod p
        let minus_one = fe::neg(&fe::one());
        assert!(fe::ct_eq(&i_squared, &minus_one));
    }

    #[test]
    fn test_sqrt_ratio_compatibility() {
        // Test sqrt(1/1) = 1
        let (exists, result) = sqrt_ratio_m1(&fe::one(), &fe::one());
        assert!(exists);
        assert_eq!(result, fe::one());

        // Test sqrt(4/1) = 2
        let two = fe::add(&fe::one(), &fe::one());
        let four = fe::sqr(&two);
        let (exists, result) = sqrt_ratio_m1(&four, &fe::one());
        assert!(exists);
        // Result should be either 2 or -2 mod p
        let result_squared = fe::sqr(&result);
        assert!(fe::ct_eq(&result_squared, &four));
    }
}
