use crate::crypto::fe25519_digits as fe;
use crate::crypto::sqrt_ratio::sqrt_ratio_i;
use crate::error::{Error, Result};
use fe::Limbs16;

// Extended point representation with 16-bit limbs
#[derive(Clone, Debug)]
pub struct ExtPoint {
    pub x: Limbs16,
    pub y: Limbs16,
    pub z: Limbs16,
    pub t: Limbs16,
}

fn inv(a: &Limbs16) -> Limbs16 {
    // a^(p-2) with LE bits
    use num_bigint::BigUint;
    use num_traits::One;
    let mut e: BigUint = BigUint::one() << 255;
    e -= BigUint::from(21u32); // p-2
                               // pow
    let mut base = *a;
    let mut res = fe::one();
    for byte in e.to_bytes_le() {
        for i in 0..8 {
            if ((byte >> i) & 1) == 1 {
                res = fe::mul(&res, &base);
            }
            base = fe::sqr(&base);
        }
    }
    res
}

fn field_const_from_ratio(num: u32, den: u32) -> Limbs16 {
    let n = fe::from_u32(num);
    let d = fe::from_u32(den);
    fe::mul(&fe::neg(&n), &inv(&d)) // -num * den^{-1} mod p
}

pub fn edwards_d() -> Limbs16 {
    // d = -121665/121666 mod p
    field_const_from_ratio(121665, 121666)
}

pub fn decompress_ed25519_point(y_compressed: &[u8; 32]) -> Result<ExtPoint> {
    // 1) extract sign and y
    let mut bytes = *y_compressed;
    let x_sign = (bytes[31] >> 7) as u16;
    bytes[31] &= 0x7f;
    let mut y = [0u16; 16];
    for i in 0..16 {
        y[i] = (bytes[2 * i] as u16) | ((bytes[2 * i + 1] as u16) << 8);
    }
    fe::canonicalize(&mut y);

    // Reject non-canonical encodings of Y (>= p)
    if ge_p(&y) {
        return Err(Error::InvalidPoint("non-canonical Y".into()));
    }

    // 2) X from: x^2 = (y^2 - 1) / (d*y^2 + 1)
    let d = edwards_d();
    let y2 = fe::sqr(&y);
    let u = fe::sub(&y2, &fe::one());
    let dy2 = fe::mul(&d, &y2);
    let v = fe::add(&dy2, &fe::one());

    let (ok, mut x) = sqrt_ratio_i(&u, &v);
    if !ok {
        return Err(Error::InvalidPoint("no square root".into()));
    }

    // 3) fix sign - canonicalize x before reading parity
    fe::canonicalize(&mut x);
    if (x[0] & 1) != (x_sign & 1) {
        x = fe::neg(&x);
    }

    // 4) build extended point (affine → extended)
    let z = fe::one();
    let t = fe::mul(&x, &y);
    Ok(ExtPoint { x, y, z, t })
}

// Add ge_p function to satisfy the compiler
fn ge_p(a: &Limbs16) -> bool {
    let mut carry = 19u32;
    for i in 0..15 {
        let t = a[i] as u32 + carry;
        carry = t >> 16;
    }
    let t15 = (a[15] as u32) + carry;
    (t15 >> 15) != 0
}

// Convert ExtPoint to crate's ExtendedPoint format (with u64 limbs)
impl From<ExtPoint> for crate::crypto::edwards_arithmetic::ExtendedPoint {
    fn from(p: ExtPoint) -> Self {
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
}

/// Compress an extended point to Ed25519 format (32 bytes)
pub fn compress_ed25519_point(point: &ExtPoint) -> [u8; 32] {
    // Convert to affine coordinates if needed (x = X/Z, y = Y/Z)
    let z_inv = fe::invert(&point.z);
    let x_affine = fe::mul(&point.x, &z_inv);
    let y_affine = fe::mul(&point.y, &z_inv);

    // Convert y to bytes
    let mut compressed = [0u8; 32];
    for i in 0..16 {
        compressed[2 * i] = (y_affine[i] & 0xFF) as u8;
        compressed[2 * i + 1] = ((y_affine[i] >> 8) & 0xFF) as u8;
    }

    // Set sign bit based on x coordinate's parity
    if x_affine[0] & 1 == 1 {
        compressed[31] |= 0x80;
    }

    compressed
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn decompress_rfc8032_pk_vector_1() {
        // A (RFC 8032, test 1)
        let pk = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&pk);
        let ext = decompress_ed25519_point(&arr).expect("decompress must succeed");
        assert_eq!(ext.z, fe::one());
        assert!(fe::ct_eq(&ext.t, &fe::mul(&ext.x, &ext.y)));
        assert_eq!(ext.x[0] & 1, ((pk[31] >> 7) as u16) & 1);
    }

    #[test]
    fn test_decompress_basepoint() {
        // Ed25519 basepoint in compressed form
        let basepoint_compressed =
            hex::decode("5866666666666666666666666666666666666666666666666666666666666666")
                .unwrap();
        let mut compressed = [0u8; 32];
        compressed.copy_from_slice(&basepoint_compressed);

        let point = decompress_ed25519_point(&compressed).unwrap();

        // Verify Z = 1 and T = X*Y
        assert_eq!(point.z, fe::one());
        assert_eq!(point.t, fe::mul(&point.x, &point.y));
    }

    #[test]
    fn test_decompress_rfc8032_r_point() {
        // R point from RFC 8032 test vector 1 signature
        let r_compressed =
            hex::decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155")
                .unwrap();
        let mut compressed = [0u8; 32];
        compressed.copy_from_slice(&r_compressed);

        let point = decompress_ed25519_point(&compressed).unwrap();

        // Verify Z = 1 and T = X*Y
        assert_eq!(point.z, fe::one());
        assert_eq!(point.t, fe::mul(&point.x, &point.y));
    }

    #[test]
    fn test_round_trip_compression() {
        // Test round-trip: decompress -> compress should yield same result
        let original =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        let mut compressed = [0u8; 32];
        compressed.copy_from_slice(&original);

        let point = decompress_ed25519_point(&compressed).unwrap();
        let recompressed = compress_ed25519_point(&point);

        assert_eq!(compressed, recompressed);
    }
}
