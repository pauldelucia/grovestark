//! Ed25519 point decompression -> extended coordinates (X:Y:Z:T)
//! - Field: 2^255 - 19 using 16×16-bit limbs, little-endian
//! - Output: X,Y,Z,T as [u16; 16]; Z = 1, T = X*Y
//! - Algorithm: x^2 = (y^2 - 1) / (d*y^2 + 1), with sqrt via sqrt_ratio_i.
//! - Assumes fe25519_digits provides basic field ops.

use crate::crypto::fe25519_digits as fe;

pub type Limbs16 = [u16; 16];

#[derive(Clone, Copy, Debug)]
pub struct ExtPointLimbs {
    pub x: Limbs16,
    pub y: Limbs16,
    pub z: Limbs16,
    pub t: Limbs16,
}

#[derive(Debug)]
pub enum DecompressError {
    NonCanonicalY,
    NoSquareRoot,
}

impl std::fmt::Display for DecompressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecompressError::NonCanonicalY => write!(f, "Non-canonical Y coordinate"),
            DecompressError::NoSquareRoot => {
                write!(f, "No valid square root exists for X coordinate")
            }
        }
    }
}

impl std::error::Error for DecompressError {}

/// d = -121665/121666 (mod p) computed once and cached.
fn edwards_d() -> Limbs16 {
    // The correct d constant from curve25519-dalek (in little-endian 16-bit limbs)
    // This is d = -121665/121666 mod p
    [
        0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079,
        0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203,
    ]
}

/// Return sqrt(-1) mod p (unique choice used by dalek).
/// This is the canonical square root of -1 in the field.
fn sqrt_m1_const() -> Limbs16 {
    // Computed as 2^(2^253 - 5) which gives sqrt(-1) for Ed25519 field
    // This value satisfies i^2 ≡ -1 (mod p)
    [
        0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099,
        0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83,
    ]
}

/// Return a^((p-5)/8) where p = 2^255-19, so (p-5)/8 = 2^252 - 3.
/// This is the classic "22523" chain from curve25519-dalek, adapted to Limbs16.
fn pow_2_252m3(a: &Limbs16) -> Limbs16 {
    // This chain computes a^(2^252 - 3).
    // Variable names follow dalek's pattern (t0,t1,t2,t3).
    let mut t0 = fe::sqr(a); // a^2
    let mut t1 = fe::sqr(&t0); // a^4
    t1 = fe::sqr(&t1); // a^8
    t1 = fe::mul(a, &t1); // a^9
    t0 = fe::mul(&t0, &t1); // a^11
    let mut t2 = fe::sqr(&t0); // a^22
    t1 = fe::mul(&t1, &t2); // a^31 = a^(2^5 - 1)

    t2 = fe::sqr(&t1);
    for _ in 1..5 {
        t2 = fe::sqr(&t2);
    } // a^(2^10 - 2^5)
    t1 = fe::mul(&t2, &t1); // a^(2^10 - 1)

    t2 = fe::sqr(&t1);
    for _ in 1..10 {
        t2 = fe::sqr(&t2);
    } // a^(2^20 - 2^10)
    t2 = fe::mul(&t2, &t1); // a^(2^20 - 1)

    let mut t3 = fe::sqr(&t2);
    for _ in 1..20 {
        t3 = fe::sqr(&t3);
    } // a^(2^40 - 2^20)
    t2 = fe::mul(&t3, &t2); // a^(2^40 - 1)

    t3 = fe::sqr(&t2);
    for _ in 1..10 {
        t3 = fe::sqr(&t3);
    } // a^(2^50 - 2^10)
    t1 = fe::mul(&t3, &t1); // a^(2^50 - 1)

    t3 = fe::sqr(&t1);
    for _ in 1..50 {
        t3 = fe::sqr(&t3);
    } // a^(2^100 - 2^50)
    t2 = fe::mul(&t3, &t1); // a^(2^100 - 1)

    t3 = fe::sqr(&t2);
    for _ in 1..100 {
        t3 = fe::sqr(&t3);
    } // a^(2^200 - 2^100)
    t2 = fe::mul(&t3, &t2); // a^(2^200 - 1)

    t3 = fe::sqr(&t2);
    for _ in 1..50 {
        t3 = fe::sqr(&t3);
    } // a^(2^250 - 2^50)
    t1 = fe::mul(&t3, &t1); // a^(2^250 - 1)

    t1 = fe::sqr(&t1); // a^(2^251 - 2)
    t1 = fe::sqr(&t1); // a^(2^252 - 4)
    fe::mul(&t1, a) // a^(2^252 - 3)
}

// sqrt_ratio_i is now imported from crate::crypto::sqrt_ratio

/// Return true if limbs encode an odd integer (LSB=1).
#[inline]
fn is_odd(x: &Limbs16) -> bool {
    (x[0] & 1) == 1
}

/// Parse compressed 32 bytes into (y_limbs, x_sign_bit).
#[inline]
fn parse_compressed_y(bytes: &[u8; 32]) -> (Limbs16, u16) {
    let sign = (bytes[31] >> 7) as u16;
    let mut y_bytes = *bytes;
    y_bytes[31] &= 0x7F;

    let mut y = [0u16; 16];
    for i in 0..16 {
        y[i] = (y_bytes[2 * i] as u16) | ((y_bytes[2 * i + 1] as u16) << 8);
    }
    fe::canonicalize(&mut y);
    (y, sign)
}

/// y must be canonical (< p). We already masked the top bit; still reject y >= p.
#[inline]
fn reject_non_canonical_y(y: &Limbs16) -> bool {
    // Check if y >= p by testing (y+19) >= 2^255
    let mut carry = 19u32;
    for i in 0..15 {
        let t = y[i] as u32 + carry;
        carry = t >> 16;
    }
    let t15 = (y[15] as u32) + carry;
    (t15 >> 15) != 0 // true if y >= p => reject
}

/// Extended Edwards decompression: (X:Y:Z:T), with Z=1, T=X·Y
pub fn decompress_ed25519_point(compressed: &[u8; 32]) -> Result<ExtPointLimbs, DecompressError> {
    let (y, sign) = parse_compressed_y(compressed);
    if reject_non_canonical_y(&y) {
        return Err(DecompressError::NonCanonicalY);
    }

    // x^2 = (y^2 - 1) / (d*y^2 + 1)
    let d = edwards_d();
    let y2 = fe::sqr(&y);
    let u = fe::sub(&y2, &fe::one());
    let dy2 = fe::mul(&d, &y2);
    let v = fe::add(&dy2, &fe::one());

    // Use the sqrt_ratio_i from our sqrt_ratio module instead
    let (ok, mut x) = crate::crypto::sqrt_ratio::sqrt_ratio_i(&u, &v);
    if !ok {
        return Err(DecompressError::NoSquareRoot);
    }

    // Fix parity: if x parity != sign_bit, negate x.
    if (is_odd(&x) as u16) != sign {
        x = fe::neg(&x);
    }

    let z = fe::one();
    let t = fe::mul(&x, &y);

    // Verify the decompressed point is on the curve
    if !on_curve(&x, &y, &z) {
        return Err(DecompressError::NoSquareRoot);
    }

    // Verify T·Z = X·Y invariant
    if !tz_eq_xy(&t, &z, &x, &y) {
        return Err(DecompressError::NoSquareRoot);
    }

    Ok(ExtPointLimbs { x, y, z, t })
}

/// Check curve equation in projective form:
/// -X^2 Z^2 + Y^2 Z^2 = Z^4 + d X^2 Y^2
#[inline]
fn on_curve(x: &Limbs16, y: &Limbs16, z: &Limbs16) -> bool {
    let d = edwards_d();
    let x2 = fe::sqr(x);
    let y2 = fe::sqr(y);
    let z2 = fe::sqr(z);
    let z4 = fe::sqr(&z2);

    let lhs = fe::add(&fe::mul(&y2, &z2), &fe::neg(&fe::mul(&x2, &z2)));
    let rhs = fe::add(&z4, &fe::mul(&d, &fe::mul(&x2, &y2)));

    let mut a = lhs;
    fe::canonicalize(&mut a);
    let mut b = rhs;
    fe::canonicalize(&mut b);
    fe::ct_eq(&a, &b)
}

/// Check T·Z == X·Y
#[inline]
fn tz_eq_xy(t: &Limbs16, z: &Limbs16, x: &Limbs16, y: &Limbs16) -> bool {
    let tz = fe::mul(t, z);
    let xy = fe::mul(x, y);
    let mut a = tz;
    fe::canonicalize(&mut a);
    let mut b = xy;
    fe::canonicalize(&mut b);
    fe::ct_eq(&a, &b)
}

/// Public helper: decompress and return limbs for trace/witness.
pub fn decompress_to_extended_limbs(
    compressed: &[u8; 32],
) -> Result<(Limbs16, Limbs16, Limbs16, Limbs16), DecompressError> {
    let p = decompress_ed25519_point(compressed)?;
    Ok((p.x, p.y, p.z, p.t))
}

/// Convenience for witness augmentation. Populates your `PrivateInputs` fields.
#[allow(dead_code)]
pub fn augment_witness_with_extended(
    sig_r: &[u8; 32],
    pubkey_a: &[u8; 32],
    out_r_x: &mut [u8; 32],
    out_r_y: &mut [u8; 32],
    out_r_z: &mut [u8; 32],
    out_r_t: &mut [u8; 32],
    out_a_x: &mut [u8; 32],
    out_a_y: &mut [u8; 32],
    out_a_z: &mut [u8; 32],
    out_a_t: &mut [u8; 32],
) -> Result<(), DecompressError> {
    let (rx, ry, rz, rt) = decompress_to_extended_limbs(sig_r)?;
    let (ax, ay, az, at) = decompress_to_extended_limbs(pubkey_a)?;

    limbs_to_bytes_le(&rx, out_r_x);
    limbs_to_bytes_le(&ry, out_r_y);
    limbs_to_bytes_le(&rz, out_r_z);
    limbs_to_bytes_le(&rt, out_r_t);

    limbs_to_bytes_le(&ax, out_a_x);
    limbs_to_bytes_le(&ay, out_a_y);
    limbs_to_bytes_le(&az, out_a_z);
    limbs_to_bytes_le(&at, out_a_t);
    Ok(())
}

/// Serialize limbs -> 32 little-endian bytes.
#[inline]
pub fn limbs_to_bytes_le(x: &Limbs16, out: &mut [u8; 32]) {
    for i in 0..16 {
        out[2 * i] = (x[i] & 0x00FF) as u8;
        out[2 * i + 1] = (x[i] >> 8) as u8;
    }
}

/// ***************
/// *  Inversion  *
/// ***************
/// If your crate already exposes `fe::inv`, delete this function and use that.
/// This version reuses the 2^252-3 chain: a^{-1} = a^{p-2} = a^{(2^255-21)} = (a^{2^252-3}) * a^(-?)* …
/// Instead, we use a standard trick: a^{-1} = (a^{2^252-3}) * (a^3) via identities.
/// Here we follow the same approach as dalek: inv(z) = z^(p-2) using the same pow chain macro-pattern.
#[allow(dead_code)]
fn inv(a: &Limbs16) -> Limbs16 {
    // a^(p-2) = a^(2^255-21) = (a^(2^252-3)) * (a^(-?)) * …; the canonical dalek chain:
    // Just reuse pow_2_252m3 for b = a^(2^252 - 3), then:
    // a^(p-2) = b * (a^2)    because: (2^252 - 3) + 2 = 2^252 - 1; then square 3 times:
    // ((2^252 - 1) * 2^3) = 2^255 - 8; multiply by a^{-13}?  — to avoid mistakes, use dalek chain directly:

    // Adapted from dalek: inv(z) = z^(p-2)
    let z2 = fe::sqr(a); // 2
    let z9 = fe::mul(&fe::sqr(&fe::sqr(&fe::sqr(&z2))), a); // 9
    let z11 = fe::mul(&z9, &z2); // 11
    let z2_5_0 = fe::mul(&fe::sqr(&z11), &z9); // 31
                                               // Compute z^(2^10 - 2^0)
    let mut t = z2_5_0;
    for _ in 0..5 {
        t = fe::sqr(&t);
    }
    let z2_10_0 = fe::mul(&t, &z2_5_0);
    // z^(2^20 - 2^0)
    t = z2_10_0;
    for _ in 0..10 {
        t = fe::sqr(&t);
    }
    let z2_20_0 = fe::mul(&t, &z2_10_0);
    // z^(2^40 - 2^0)
    t = z2_20_0;
    for _ in 0..20 {
        t = fe::sqr(&t);
    }
    let z2_40_0 = fe::mul(&t, &z2_20_0);
    // z^(2^50 - 2^0)
    t = z2_40_0;
    for _ in 0..10 {
        t = fe::sqr(&t);
    }
    let z2_50_0 = fe::mul(&t, &z2_10_0);
    // z^(2^100 - 2^0)
    t = z2_50_0;
    for _ in 0..50 {
        t = fe::sqr(&t);
    }
    let z2_100_0 = fe::mul(&t, &z2_50_0);
    // z^(2^200 - 2^0)
    t = z2_100_0;
    for _ in 0..100 {
        t = fe::sqr(&t);
    }
    let z2_200_0 = fe::mul(&t, &z2_100_0);
    // z^(2^250 - 2^0)
    t = z2_200_0;
    for _ in 0..50 {
        t = fe::sqr(&t);
    }
    let z2_250_0 = fe::mul(&t, &z2_50_0);
    // z^(2^255 - 2^5) = (2^250 - 1) << 5
    t = z2_250_0;
    for _ in 0..5 {
        t = fe::sqr(&t);
    }
    // multiply by z^11 -> 2^255 - 2^5 + 11 = 2^255 - 21
    fe::mul(&t, &z11)
}
