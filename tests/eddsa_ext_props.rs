use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{rngs::StdRng, RngCore, SeedableRng};

use grovestark::compressed_to_extended;
use grovestark::crypto::fe25519_digits as fe;
use grovestark::crypto::point_decompression::edwards_d;
use grovestark::crypto::scalar_mult_correct::{ed_add, ed_neg, ExtPoint};

fn limbs_from_le(bytes: &[u8; 32]) -> [u16; 16] {
    let mut out = [0u16; 16];
    for i in 0..16 {
        out[i] = (bytes[2 * i] as u16) | ((bytes[2 * i + 1] as u16) << 8);
    }
    out
}

fn ct_true(b: bool) {
    assert!(b);
}

fn check_invariants(p: &ExtPoint) {
    // I1: T*Z == X*Y
    let tz = fe::mul(&p.t, &p.z);
    let xy = fe::mul(&p.x, &p.y);
    ct_true(fe::ct_eq(&tz, &xy));

    // I2: Y^2 - X^2 == Z^2 + d*T^2
    let y2 = fe::sqr(&p.y);
    let x2 = fe::sqr(&p.x);
    let lhs = fe::sub(&y2, &x2);

    let z2 = fe::sqr(&p.z);
    let d = edwards_d();
    let dt2 = fe::mul(&d, &fe::sqr(&p.t));
    let rhs = fe::add(&z2, &dt2);

    ct_true(fe::ct_eq(&lhs, &rhs));
}

// A tiny helper to turn dalek point into your ExtPoint with Z=1, T=X*Y
fn to_extpoint_from_dalek(p: &EdwardsPoint) -> ExtPoint {
    // Decompress from dalek's compressed form to stay consistent with your path:
    let enc = p.compress().to_bytes();
    let (x_bytes, y_bytes, z_bytes, t_bytes) = compressed_to_extended(&enc).expect("decompress");

    // Convert bytes back to limbs
    let x = limbs_from_le(&x_bytes);
    let y = limbs_from_le(&y_bytes);
    let z = limbs_from_le(&z_bytes);
    let t = limbs_from_le(&t_bytes);

    ExtPoint { x, y, z, t }
}

#[test]
fn ed_neg_add_identity() {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    for _ in 0..200 {
        let mut scalar_bytes = [0u8; 32];
        rng.fill_bytes(&mut scalar_bytes);
        let s = Scalar::from_bytes_mod_order(scalar_bytes);
        let p = &s * &EdwardsPoint::default(); // some generator (dalek's default is basepoint)
        let p = to_extpoint_from_dalek(&p);
        let m = ed_neg(&p);
        let o = ed_add(&p, &m);

        // Projective identity: X=0, T=0, Y==Z != 0
        let x_zero = fe::ct_eq(&o.x, &fe::zero());
        let t_zero = fe::ct_eq(&o.t, &fe::zero());
        assert!(x_zero && t_zero, "X or T not zero in P+(-P)");

        let yz_eq = fe::ct_eq(&o.y, &o.z);
        assert!(yz_eq, "Y != Z in identity");

        let y_nonzero = !fe::ct_eq(&o.y, &fe::zero());
        assert!(y_nonzero, "Y=Z=0 (invalid identity)");
    }
}

#[test]
fn dalek_roundtrip_invariants() {
    let mut rng = StdRng::seed_from_u64(1337);
    for _ in 0..200 {
        let mut scalar_bytes = [0u8; 32];
        rng.fill_bytes(&mut scalar_bytes);
        let s = Scalar::from_bytes_mod_order(scalar_bytes);
        let p = &s * &EdwardsPoint::default();
        let p = to_extpoint_from_dalek(&p);
        check_invariants(&p);
    }
}
