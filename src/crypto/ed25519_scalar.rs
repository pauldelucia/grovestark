// SHA-512 to scalar mod L reduction for Ed25519

use once_cell::sync::Lazy;

pub static ED25519_L_LIMBS_U16: Lazy<[u16; 16]> = Lazy::new(|| {
    use num_bigint::BigUint;
    const L_DEC: &str =
        "7237005577332262213973186563042994240857116359379907606001950938285454250989";
    let l = BigUint::parse_bytes(L_DEC.as_bytes(), 10).unwrap();
    let le = l.to_bytes_le();
    let mut limbs = [0u16; 16];
    for i in 0..16 {
        let lo = *le.get(2 * i).unwrap_or(&0);
        let hi = *le.get(2 * i + 1).unwrap_or(&0);
        limbs[i] = (lo as u16) | ((hi as u16) << 8);
    }
    limbs
});

pub fn reduce_sha512_mod_l(digest64: &[u8; 64]) -> [u8; 32] {
    use num_bigint::BigUint;
    const L_DEC: &str =
        "7237005577332262213973186563042994240857116359379907606001950938285454250989";
    let l = BigUint::parse_bytes(L_DEC.as_bytes(), 10).unwrap();
    let n = BigUint::from_bytes_le(digest64);
    let r = n % l;
    let mut out = [0u8; 32];
    let rb = r.to_bytes_le();
    out[..rb.len().min(32)].copy_from_slice(&rb[..rb.len().min(32)]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use num_bigint::BigUint;

    #[test]
    fn test_reduce_sha512_mod_l() {
        // Test with a known SHA-512 output from RFC 8032 test vector 1
        // This is SHA-512(R || A || "") where R and A are from the test vector
        let hash_hex = "86eabc8e4c96193d290504e7c600df6cf8d8256131ec2c138a3e7e162e5254040ef15bdc988a22c7207411377c33f2ac09b1e86a046234283768ee7ba03c0e9f";
        let hash_bytes = hex::decode(hash_hex).unwrap();
        let mut hash_array = [0u8; 64];
        hash_array.copy_from_slice(&hash_bytes);

        // Note: The hash is given in big-endian hex, but we need to interpret it as little-endian for Ed25519
        // So we reverse it
        hash_array.reverse();

        let reduced = reduce_sha512_mod_l(&hash_array);

        // The result should be a valid 32-byte scalar < L
        // We can verify it's non-zero and within range
        assert!(
            reduced.iter().any(|&b| b != 0),
            "Reduced scalar should not be zero"
        );

        // Verify it's less than L by converting back to BigUint
        let reduced_bigint = BigUint::from_bytes_le(&reduced);
        const L_DEC: &str =
            "7237005577332262213973186563042994240857116359379907606001950938285454250989";
        let l = BigUint::parse_bytes(L_DEC.as_bytes(), 10).unwrap();
        assert!(reduced_bigint < l, "Reduced scalar should be less than L");
    }

    #[test]
    fn test_reduce_identity() {
        // Test that reducing a value less than L returns the same value
        let mut small_value = [0u8; 64];
        small_value[0] = 1; // Set to 1

        let reduced = reduce_sha512_mod_l(&small_value);

        // Should be [1, 0, 0, ..., 0]
        assert_eq!(reduced[0], 1);
        for i in 1..32 {
            assert_eq!(reduced[i], 0);
        }
    }

    #[test]
    fn test_reduce_large_value() {
        // Test with a value larger than L
        let large_value = [0xff; 64]; // All 0xFF bytes

        let reduced = reduce_sha512_mod_l(&large_value);

        // Result should be less than L
        let reduced_bigint = BigUint::from_bytes_le(&reduced);
        const L_DEC: &str =
            "7237005577332262213973186563042994240857116359379907606001950938285454250989";
        let l = BigUint::parse_bytes(L_DEC.as_bytes(), 10).unwrap();
        assert!(reduced_bigint < l, "Reduced scalar should be less than L");
    }
}
