// 16 limbs, each 16 bits, little-endian: limb 0 is least significant.
// All functions expect inputs already reduced to < 2^256 (e.g., mul's raw product folded).

pub type Limbs16 = [u16; 16];

#[inline]
pub fn zero() -> Limbs16 {
    [0; 16]
}
#[inline]
pub fn one() -> Limbs16 {
    let mut o = [0; 16];
    o[0] = 1;
    o
}

#[inline]
pub fn from_u32(x: u32) -> Limbs16 {
    let mut out = [0u16; 16];
    out[0] = (x & 0xffff) as u16;
    out[1] = (x >> 16) as u16;
    out
}

// 2^255 - 19 in 16×16-bit LE "shape": only limb15 must be 15-bit.
// You do NOT need full p digits to subtract; we implement canonicalize() explicitly.
#[inline]
fn ge_p(a: &Limbs16) -> bool {
    // Compare a to p: a >= p ?
    // p has limbs [0xffff; 0..14], limb15 = 0x7fff - 18? No: p is "2^255-19".
    // Canonicalization below handles the compare without explicit P table:
    // Trick: compute a' = a with limb15 masked; if limb15 had bit15 set we already fold it.
    // After canonicalize(), a is < 2^255; then a >= p iff a >= (0x...ffff, 0x7fff-19carry), but easiest is:
    // convert to BigUint only here if you prefer; we avoid that — we implement a ≥ p by testing (a+19) ≥ 2^255
    // which is equivalent after masking.
    let mut carry = 19u32; // add 19 to a and see if bit255 sets
    for i in 0..15 {
        let t = a[i] as u32 + carry;
        carry = t >> 16;
    }
    // apply to limb15 (15-bit)
    let t15 = (a[15] as u32) + carry;
    // if t15 >= 1<<15, (a+19) crossed 2^255 → a >= p
    (t15 >> 15) != 0
}

#[inline]
pub fn canonicalize(x: &mut Limbs16) {
    // 1) push limb15 bit15 (if any) down via +19 into limb0
    let hi = (x[15] as u32) >> 15;
    x[15] &= 0x7fff;
    if hi != 0 {
        let mut c = hi * 19;
        for i in 0..16 {
            let t = x[i] as u32 + c;
            x[i] = (t & 0xffff) as u16;
            c = t >> 16;
            if c == 0 {
                break;
            }
        }
        // limb15 might have re-overflowed via carry chain; mask again
        x[15] &= 0x7fff;
    }
    // 2) final conditional subtract of p
    if ge_p(x) {
        // subtract p == (2^255 - 19): same as "x = x + 19; clear bit255".
        // Implement as: x = x - p  <=> x = x + 19 and then clear bit255 (we know it is set).
        // We'll do straightforward borrow subtraction by 0xffff..,0x7fff, then plus 19 is already accounted by ge_p test.
        // Simpler: do x = x + 19, then clear limb15's bit15 again (guaranteed set).
        let mut c = 19u32;
        for i in 0..16 {
            let t = x[i] as u32 + c;
            x[i] = (t & 0xffff) as u16;
            c = t >> 16;
        }
        // Now clear bit255 (limb15 bit15) once
        x[15] &= 0x7fff;
    }
}

#[inline]
pub fn add(a: &Limbs16, b: &Limbs16) -> Limbs16 {
    let mut out = [0u16; 16];
    let mut c = 0u32;
    for i in 0..16 {
        let t = a[i] as u32 + b[i] as u32 + c;
        out[i] = (t & 0xffff) as u16;
        c = t >> 16;
    }
    // fold 2^256 via 2 * 2^255 ≡ 38
    if c != 0 {
        let t0 = out[0] as u32 + 38 * c;
        out[0] = (t0 & 0xffff) as u16;
        let mut cc = t0 >> 16;
        for i in 1..16 {
            if cc == 0 {
                break;
            }
            let ti = out[i] as u32 + cc;
            out[i] = (ti & 0xffff) as u16;
            cc = ti >> 16;
        }
    }
    canonicalize(&mut out);
    out
}

#[inline]
pub fn sub(a: &Limbs16, b: &Limbs16) -> Limbs16 {
    // a - b mod p
    let mut out = [0u16; 16];
    let mut borrow = 0i32;
    for i in 0..16 {
        let t = a[i] as i32 - b[i] as i32 - borrow;
        if t < 0 {
            out[i] = (t + 0x1_0000) as u16;
            borrow = 1;
        } else {
            out[i] = t as u16;
            borrow = 0;
        }
    }
    // if borrowed, add p to get the proper positive representation
    if borrow != 0 {
        let mut c = 0u32;
        for i in 0..16 {
            let t = out[i] as u32 + P[i] as u32 + c;
            out[i] = (t & 0xffff) as u16;
            c = t >> 16;
        }
    }
    canonicalize(&mut out);
    out
}

pub fn mul(a: &Limbs16, b: &Limbs16) -> Limbs16 {
    let mut prod = [0u64; 32];
    for i in 0..16 {
        let ai = a[i] as u64;
        for j in 0..16 {
            prod[i + j] = prod[i + j].wrapping_add(ai * (b[j] as u64));
        }
    }
    // fold high 16 limbs using 2^256 ≡ 38
    for k in 16..32 {
        let add = prod[k] * 38;
        prod[k - 16] = prod[k - 16].wrapping_add(add);
        prod[k] = 0;
    }
    // base-2^16 reduction
    let mut out = [0u16; 16];
    let mut c = 0u64;
    for i in 0..16 {
        let t = prod[i] + c;
        out[i] = (t & 0xffff) as u16;
        c = t >> 16;
    }
    // any remaining carry folds again by 38
    if c != 0 {
        let t0 = out[0] as u32 + (c as u32) * 38;
        out[0] = (t0 & 0xffff) as u16;
        let mut cc = t0 >> 16;
        for i in 1..16 {
            if cc == 0 {
                break;
            }
            let ti = out[i] as u32 + cc;
            out[i] = (ti & 0xffff) as u16;
            cc = ti >> 16;
        }
    }
    canonicalize(&mut out);
    out
}

#[inline]
pub fn sqr(a: &Limbs16) -> Limbs16 {
    mul(a, a)
}

#[inline]
pub fn neg(a: &Limbs16) -> Limbs16 {
    sub(&zero(), a)
}

#[inline]
pub fn ct_eq(a: &Limbs16, b: &Limbs16) -> bool {
    let mut aa = *a;
    let mut bb = *b;
    canonicalize(&mut aa);
    canonicalize(&mut bb);
    // constant-ish eq over limbs
    let mut acc = 0u16;
    for i in 0..16 {
        acc |= aa[i] ^ bb[i];
    }
    acc == 0
}

// Field inversion using Fermat's little theorem: a^(p-2) mod p
pub fn invert(a: &Limbs16) -> Limbs16 {
    use num_bigint::BigUint;
    use num_traits::One;
    // p-2 = (1<<255) - 21
    let mut exp: BigUint = BigUint::one() << 255;
    exp -= BigUint::from(21u32);
    pow_le(a, &exp.to_bytes_le())
}

fn pow_le(a: &Limbs16, exp_le: &[u8]) -> Limbs16 {
    let mut base = *a;
    let mut res = one();
    for &byte in exp_le {
        for i in 0..8 {
            if (byte >> i) & 1 == 1 {
                res = mul(&res, &base);
            }
            base = sqr(&base);
        }
    }
    res
}

// Backwards compatibility with old API
pub fn normalize(x: &mut Limbs16) {
    canonicalize(x);
}

// Compatibility functions from old API
const P: Limbs16 = [
    0xffed, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0x7fff, // 2^255-19 in 16-bit LE
];

#[inline]
#[allow(dead_code)]
fn lt(a: &Limbs16, b: &Limbs16) -> bool {
    for i in (0..16).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

#[inline]
#[allow(dead_code)]
fn ge(a: &Limbs16, b: &Limbs16) -> bool {
    !lt(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_arithmetic() {
        // Test that 1 + 1 = 2
        let two = add(&one(), &one());
        assert_eq!(two[0], 2);
        for i in 1..16 {
            assert_eq!(two[i], 0);
        }

        // Test that p + 1 = 1 (mod p)
        let p_plus_1 = add(&P, &one());
        assert_eq!(p_plus_1, one());

        // Test that 0 - 1 = p - 1 (mod p)
        let minus_one = sub(&zero(), &one());
        let mut expected = P;
        expected[0] -= 1; // p - 1
        assert_eq!(minus_one, expected);
    }

    #[test]
    fn test_multiplication() {
        // Test that 2 * 3 = 6
        let two = add(&one(), &one());
        let three = add(&two, &one());
        let six = mul(&two, &three);
        assert_eq!(six[0], 6);
        for i in 1..16 {
            assert_eq!(six[i], 0);
        }
    }
}
