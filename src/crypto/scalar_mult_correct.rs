// Correct 4-bit window scalar multiplication for Ed25519
// Based on REPORT.md implementation

use crate::crypto::fe25519_digits as fe;

#[derive(Clone, Copy, Debug)]
pub struct ExtPoint {
    pub x: [u16; 16],
    pub y: [u16; 16],
    pub z: [u16; 16],
    pub t: [u16; 16],
}

// Helpers
#[inline]
fn zero() -> [u16; 16] {
    [0; 16]
}

#[inline]
fn one() -> [u16; 16] {
    let mut result = [0; 16];
    result[0] = 1;
    result
}

// Correct Edwards extended add (a = -1)
#[inline]
pub fn ed_add(p: &ExtPoint, q: &ExtPoint) -> ExtPoint {
    #[cfg(debug_assertions)]
    {
        assert_invariants("add.in.p", p);
        assert_invariants("add.in.q", q);
    }
    // A = (Y1 - X1) * (Y2 - X2)
    let y1_minus_x1 = fe::sub(&p.y, &p.x);
    let y2_minus_x2 = fe::sub(&q.y, &q.x);
    let a = fe::mul(&y1_minus_x1, &y2_minus_x2);

    // B = (Y1 + X1) * (Y2 + X2)
    let y1_plus_x1 = fe::add(&p.y, &p.x);
    let y2_plus_x2 = fe::add(&q.y, &q.x);
    let b = fe::mul(&y1_plus_x1, &y2_plus_x2);

    // C = 2 * d * T1 * T2
    let d = edwards_d();
    let two = fe::add(&one(), &one());
    let dt1 = fe::mul(&d, &p.t);
    let dt1t2 = fe::mul(&dt1, &q.t);
    let c = fe::mul(&two, &dt1t2);

    // D = 2 * Z1 * Z2
    let z1z2 = fe::mul(&p.z, &q.z);
    let d_big = fe::mul(&two, &z1z2);

    // E = B - A
    let e = fe::sub(&b, &a);
    // F = D - C
    let f = fe::sub(&d_big, &c);
    // G = D + C
    let g = fe::add(&d_big, &c);
    // H = B + A
    let h = fe::add(&b, &a);

    // X3 = E * F
    let x3 = fe::mul(&e, &f);
    // Y3 = G * H
    let y3 = fe::mul(&g, &h);
    // T3 = E * H
    let t3 = fe::mul(&e, &h);
    // Z3 = F * G
    let z3 = fe::mul(&f, &g);

    let mut x3_canon = x3;
    let mut y3_canon = y3;
    let mut z3_canon = z3;
    let mut t3_canon = t3;

    // Canonicalize outputs to avoid tiny non-canonical mismatches
    fe::canonicalize(&mut x3_canon);
    fe::canonicalize(&mut y3_canon);
    fe::canonicalize(&mut z3_canon);
    fe::canonicalize(&mut t3_canon);

    let result = ExtPoint {
        x: x3_canon,
        y: y3_canon,
        z: z3_canon,
        t: t3_canon,
    };

    #[cfg(debug_assertions)]
    {
        assert_invariants("add.out", &result);
    }

    result
}

#[inline]
pub fn ed_double(p: &ExtPoint) -> ExtPoint {
    #[cfg(debug_assertions)]
    {
        assert_invariants("double.in", p);
    }
    // a = -1
    let a_x2 = fe::sqr(&p.x); // A = X1^2
    let b_y2 = fe::sqr(&p.y); // B = Y1^2
    let z2 = fe::sqr(&p.z); // Z1^2
    let two = fe::add(&one(), &one());
    let c_2z2 = fe::mul(&two, &z2); // C = 2*Z1^2
    let d_negx2 = fe::neg(&a_x2); // D = -A

    // E = (X1+Y1)^2 - A - B
    let x_plus_y = fe::add(&p.x, &p.y);
    let e_tmp = fe::sqr(&x_plus_y);
    let e_minus_a = fe::sub(&e_tmp, &a_x2);
    let e = fe::sub(&e_minus_a, &b_y2);

    let g = fe::add(&d_negx2, &b_y2); // G = D + B
    let f = fe::sub(&g, &c_2z2); // F = G - C
    let h = fe::sub(&d_negx2, &b_y2); // H = D - B

    let x3 = fe::mul(&e, &f); // X3 = E * F
    let y3 = fe::mul(&g, &h); // Y3 = G * H
    let t3 = fe::mul(&e, &h); // T3 = E * H
    let z3 = fe::mul(&f, &g); // Z3 = F * G

    let mut x3_canon = x3;
    let mut y3_canon = y3;
    let mut z3_canon = z3;
    let mut t3_canon = t3;

    // Canonicalize outputs to avoid tiny non-canonical mismatches
    fe::canonicalize(&mut x3_canon);
    fe::canonicalize(&mut y3_canon);
    fe::canonicalize(&mut z3_canon);
    fe::canonicalize(&mut t3_canon);

    let result = ExtPoint {
        x: x3_canon,
        y: y3_canon,
        z: z3_canon,
        t: t3_canon,
    };

    #[cfg(debug_assertions)]
    {
        assert_invariants("double.out", &result);
    }

    result
}

#[inline]
pub fn ed_identity() -> ExtPoint {
    ExtPoint {
        x: zero(),
        y: one(),
        z: one(),
        t: zero(),
    }
}

#[inline]
pub fn ed_neg(p: &ExtPoint) -> ExtPoint {
    // Negation on Edwards: (-X, Y, Z, -T)
    ExtPoint {
        x: fe::neg(&p.x),
        y: p.y,
        z: p.z,
        t: fe::neg(&p.t),
    }
}

// Helper to create field element from u32
#[inline]
fn fe_from_u32(v: u32) -> [u16; 16] {
    let mut out = [0u16; 16];
    out[0] = (v & 0xffff) as u16;
    out[1] = (v >> 16) as u16;
    out
}

// Get Edwards d constant - compute programmatically
fn edwards_d() -> [u16; 16] {
    // d = -121665/121666 mod p for Ed25519
    let n = fe_from_u32(121665);
    let den = fe_from_u32(121666);
    let den_inv = fe::invert(&den); // Field inversion
    let d = fe::mul(&fe::neg(&n), &den_inv);
    let mut can = d;
    fe::canonicalize(&mut can);
    can
}

// Correct window decomposition (radix-16, little-endian)
#[inline]
pub fn decompose_radix16_windows_from_le_bytes(s: &[u8; 32]) -> [u8; 64] {
    let mut w = [0u8; 64];
    for i in 0..32 {
        let b = s[i];
        w[2 * i] = b & 0x0f;
        w[2 * i + 1] = (b >> 4) & 0x0f;
    }
    w
}

// From 16 little-endian u16 limbs (common format)
#[inline]
pub fn decompose_radix16_windows_from_limbs16_le(limbs: &[u16; 16]) -> [u8; 64] {
    let mut w = [0u8; 64];
    for i in 0..16 {
        let li = limbs[i];
        w[4 * i] = (li & 0x000f) as u8;
        w[4 * i + 1] = ((li >> 4) & 0x000f) as u8;
        w[4 * i + 2] = ((li >> 8) & 0x000f) as u8;
        w[4 * i + 3] = ((li >> 12) & 0x000f) as u8;
    }
    w
}

// Build table [0P .. 15P]
#[inline]
pub fn table_0_to_15(point: &ExtPoint) -> [ExtPoint; 16] {
    let mut tbl = [ed_identity(); 16];
    tbl[0] = ed_identity();
    tbl[1] = *point;

    for k in 2..16 {
        // tbl[k] = tbl[k-1] + P
        tbl[k] = ed_add(&tbl[k - 1], point);
    }
    tbl
}

// Core 4-bit window scalar mult (MSW→LSW)
pub fn scalar_mul_4bit_windows(point: &ExtPoint, scalar_nibbles: &[u8; 64]) -> ExtPoint {
    // Precompute 0..15 * P
    let tbl = table_0_to_15(point);

    // Accumulator starts at identity
    let mut acc = ed_identity();

    // Process from most-significant window down to least-significant
    for wi in (0..64).rev() {
        // 4 doublings
        acc = ed_double(&acc);
        acc = ed_double(&acc);
        acc = ed_double(&acc);
        acc = ed_double(&acc);

        let d = scalar_nibbles[wi] as usize; // 0..15
        if d != 0 {
            acc = ed_add(&acc, &tbl[d]);
        }
    }
    acc
}

// From 32 scalar bytes (little-endian)
pub fn mul_point_by_scalar_le_bytes(point: &ExtPoint, scalar_le: &[u8; 32]) -> ExtPoint {
    let nibbles = decompose_radix16_windows_from_le_bytes(scalar_le);
    scalar_mul_4bit_windows(point, &nibbles)
}

// From 16 u16 limbs (little-endian)
pub fn mul_point_by_scalar_limbs16(point: &ExtPoint, limbs: &[u16; 16]) -> ExtPoint {
    let nibbles = decompose_radix16_windows_from_limbs16_le(limbs);
    scalar_mul_4bit_windows(point, &nibbles)
}

// Check projective identity
#[inline]
pub fn is_identity_projective(p: &ExtPoint) -> bool {
    // (0 : λ : λ : 0), λ != 0
    let x0 = p.x.iter().all(|&x| x == 0);
    let t0 = p.t.iter().all(|&t| t == 0);
    let y_eq_z = p.y.iter().zip(p.z.iter()).all(|(&y, &z)| y == z);
    let y_nz = p.y.iter().any(|&y| y != 0);
    x0 && t0 && y_eq_z && y_nz
}

#[inline]
pub fn normalize_identity_in_place(p: &mut ExtPoint) {
    p.x = zero();
    p.t = zero();
    p.y = one();
    p.z = one();
}

// Convert from our ExtendedPoint format to this module's ExtPoint
pub fn convert_from_extended(p: &crate::crypto::edwards_arithmetic::ExtendedPoint) -> ExtPoint {
    let mut x = [0u16; 16];
    let mut y = [0u16; 16];
    let mut z = [0u16; 16];
    let mut t = [0u16; 16];

    for i in 0..16 {
        x[i] = p.x[i] as u16;
        y[i] = p.y[i] as u16;
        z[i] = p.z[i] as u16;
        t[i] = p.t[i] as u16;
    }

    ExtPoint { x, y, z, t }
}

// Convert back to ExtendedPoint format
pub fn convert_to_extended(p: &ExtPoint) -> crate::crypto::edwards_arithmetic::ExtendedPoint {
    let mut x = [0u64; 16];
    let mut y = [0u64; 16];
    let mut z = [0u64; 16];
    let mut t = [0u64; 16];

    for i in 0..16 {
        x[i] = p.x[i] as u64;
        y[i] = p.y[i] as u64;
        z[i] = p.z[i] as u64;
        t[i] = p.t[i] as u64;
    }

    crate::crypto::edwards_arithmetic::ExtendedPoint { x, y, z, t }
}

// End-to-end combine for EdDSA verification
pub fn eddsa_verify_combine(
    s_le: &[u8; 32],
    h_le: &[u8; 32],
    r_ext: &ExtPoint,
    a_ext: &ExtPoint,
    basepoint_ext: &ExtPoint,
) -> ExtPoint {
    // [s]B and [h]A
    let sB = mul_point_by_scalar_le_bytes(basepoint_ext, s_le);
    let hA = mul_point_by_scalar_le_bytes(a_ext, h_le);

    // Combine: sB - R - hA = sB + (-R) + (-hA)
    let minus_r = ed_neg(r_ext);
    let minus_hA = ed_neg(&hA);

    let p1 = ed_add(&sB, &minus_r);
    let mut final_p = ed_add(&p1, &minus_hA);

    // No cofactor clearing needed for EdDSA verification
    if is_identity_projective(&final_p) {
        normalize_identity_in_place(&mut final_p);
    }

    final_p
}

// Helper functions for invariant checking
#[inline]
pub fn fe_eq(a: &[u16; 16], b: &[u16; 16]) -> bool {
    let mut aa = *a;
    let mut bb = *b;
    fe::canonicalize(&mut aa);
    fe::canonicalize(&mut bb);
    aa == bb
}

#[inline]
pub fn assert_invariants(tag: &str, p: &ExtPoint) {
    // (I1) T·Z == X·Y
    let tz = fe::mul(&p.t, &p.z);
    let xy = fe::mul(&p.x, &p.y);
    assert!(fe_eq(&tz, &xy), "{tag}: T·Z != X·Y (I1 failed)");

    // (I2) Y² − X² == Z² + d·T²
    let y2 = fe::sqr(&p.y);
    let x2 = fe::sqr(&p.x);
    let z2 = fe::sqr(&p.z);
    let t2 = fe::sqr(&p.t);
    let lhs = fe::sub(&y2, &x2);
    let rhs = fe::add(&z2, &fe::mul(&edwards_d(), &t2));
    assert!(fe_eq(&lhs, &rhs), "{tag}: Y²−X² != Z² + d·T² (I2 failed)");
}

// Diagnostic function for P + (-P)
pub fn diag_p_plus_negp(p: &ExtPoint) {
    let q = ed_neg(p);
    let r = ed_add(p, &q);

    // X and T should be zero
    let zero = [0u16; 16];
    assert!(fe_eq(&r.x, &zero), "P+(-P): X != 0");
    assert!(fe_eq(&r.t, &zero), "P+(-P): T != 0");

    // Y should equal Z (this is the critical check)
    assert!(fe_eq(&r.y, &r.z), "P+(-P): Y != Z (means H != F)");

    // Print diagnostic info
    let y2 = fe::sqr(&p.y);
    let x2 = fe::sqr(&p.x);
    let z2 = fe::sqr(&p.z);
    let t2 = fe::sqr(&p.t);
    let h = fe::add(&y2, &fe::neg(&x2)); // Note: 2 cancels later
    let f = fe::add(&z2, &fe::mul(&edwards_d(), &t2));
    let diff = fe::sub(&h, &f);
    eprintln!("(H-F) should be 0, got {:04x?}", &diff[..8]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_and_doublings_are_consistent() {
        // Scalar = 1 → result must equal P
        let p = ExtPoint {
            x: [
                0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6,
                0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169,
            ],
            y: [
                0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
            ],
            z: one(),
            t: [
                0xdda3, 0xa5b7, 0x8ab3, 0x6dde, 0x52f5, 0x7751, 0x9f80, 0x20f0, 0xe37d, 0x64ab,
                0x4e8e, 0x66ea, 0x7665, 0xd78b, 0x5f0f, 0x6787,
            ],
        };

        let mut s = [0u8; 32];
        s[0] = 1;
        let q = mul_point_by_scalar_le_bytes(&p, &s);

        // Check projective equality via cross-multiplication
        let xz = fe::mul(&p.x, &q.z);
        let zx = fe::mul(&q.x, &p.z);
        let yz = fe::mul(&p.y, &q.z);
        let zy = fe::mul(&q.y, &p.z);

        // They should be equal
        assert_eq!(xz, zx);
        assert_eq!(yz, zy);
    }

    #[test]
    fn mul_then_add_inverse_is_identity() {
        // Base point - corrected values
        let p = ExtPoint {
            x: [
                0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6,
                0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169,
            ],
            y: [
                0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
            ],
            z: one(),
            t: [
                0xdda3, 0xa5b7, 0x8ab3, 0x6dde, 0x52f5, 0x7751, 0x9f80, 0x20f0, 0xe37d, 0x64ab,
                0x4e8e, 0x66ea, 0x7665, 0xd78b, 0x5f0f, 0x6787,
            ],
        };

        // First check invariants on base point
        assert_invariants("base_point", &p);

        // Test P + (-P) directly
        diag_p_plus_negp(&p);

        // Also test with scalar multiplication
        let mut k = [0u8; 32];
        k[0] = 13; // small but non-trivial
        let q = mul_point_by_scalar_le_bytes(&p, &k);
        let mq = ed_neg(&q);
        let r = ed_add(&q, &mq);

        assert!(is_identity_projective(&r));
    }
}
