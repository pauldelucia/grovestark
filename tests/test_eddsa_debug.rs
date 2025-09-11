use num_bigint::BigUint;

fn main() {
    // H = SHA-512(R || A || "") from RFC 8032 test vector 1
    let hash_hex = "2771062b6b536fe7ffbdda0320c3827b035df10d284df3f08222f04dbca7a4c20ef15bdc988a22c7207411377c33f2ac09b1e86a046234283768ee7ba03c0e9f";
    let hash = hex::decode(hash_hex).unwrap();

    // L = 2^252 + 27742317777372353535851937790883648493
    let l = BigUint::parse_bytes(
        b"7237005577332262213973186563042994240857116359379907606001950938285454250989",
        10,
    )
    .unwrap();

    // Convert hash to big integer (little-endian)
    let hash_int = BigUint::from_bytes_le(&hash);

    // Reduce modulo L
    let reduced = hash_int % l;

    // Convert back to bytes (little-endian)
    let reduced_bytes = reduced.to_bytes_le();

    println!("Reduced bytes (hex): {}", hex::encode(&reduced_bytes));

    // Convert to 16-bit limbs
    let mut limbs = [0u64; 16];
    for i in 0..16.min(reduced_bytes.len() / 2) {
        let low = reduced_bytes.get(i * 2).copied().unwrap_or(0) as u64;
        let high = reduced_bytes.get(i * 2 + 1).copied().unwrap_or(0) as u64;
        limbs[i] = low | (high << 8);
    }

    println!("Limbs: {:x?}", limbs);
}
