use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};

fn main() {
    // Generate a new Ed25519 key pair
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    // Get the keys as bytes
    let private_key_bytes = signing_key.to_bytes();
    let public_key_bytes = verifying_key.to_bytes();

    println!("=== Generated Ed25519 Key Pair ===");
    println!("Private key (32 bytes):");
    print_as_rust_array(&private_key_bytes, "PRIVATE_KEY");
    println!();

    println!("Public key (32 bytes - compressed):");
    print_as_rust_array(&public_key_bytes, "PUBLIC_KEY");
    println!();

    // Create a test message
    let message = b"Test message for GroveSTARK EdDSA verification";
    let message_hash = Sha512::digest(message);
    let mut message_32 = [0u8; 32];
    message_32.copy_from_slice(&message_hash[..32]);

    println!("Message hash (32 bytes):");
    print_as_rust_array(&message_32, "MESSAGE_HASH");
    println!();

    // Sign the message
    let signature = signing_key.sign(message);
    let signature_bytes = signature.to_bytes();

    // Extract R and s from signature (first 32 bytes is R, last 32 is s)
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature_bytes[..32]);
    s_bytes.copy_from_slice(&signature_bytes[32..]);

    println!("=== Signature Components ===");
    println!("R point (32 bytes - compressed):");
    print_as_rust_array(&r_bytes, "SIGNATURE_R");
    println!();

    println!("s scalar (32 bytes):");
    print_as_rust_array(&s_bytes, "SIGNATURE_S");
    println!();

    // Compute h = SHA-512(R || A || M) mod L
    // Note: ed25519-dalek does this internally, but we need it for our STARK
    let mut hasher = Sha512::new();
    hasher.update(r_bytes);
    hasher.update(public_key_bytes);
    hasher.update(message);
    let h_full = hasher.finalize();

    // Reduce h modulo L (group order)
    // For simplicity, we'll use the first 32 bytes as an approximation
    // In production, this should be properly reduced mod L
    let mut h_bytes = [0u8; 32];
    h_bytes.copy_from_slice(&h_full[..32]);

    println!("Hash h (32 bytes - SHA-512(R || A || M) truncated):");
    print_as_rust_array(&h_bytes, "HASH_H");
    println!();

    // For extended coordinates, we'd need to decompress the points
    // This requires Edwards curve arithmetic
    println!("\n=== Extended Coordinates (Placeholder) ===");
    println!("// Note: These would need proper Edwards curve decompression");
    println!("// For now, using identity-like values for testing");

    // R extended (would need proper decompression)
    println!("pub const R_EXTENDED_X: [u8; 32] = [0; 32];");
    println!("pub const R_EXTENDED_Y: [u8; 32] = R_BYTES; // Same as compressed");
    println!("pub const R_EXTENDED_Z: [u8; 32] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];");
    println!("pub const R_EXTENDED_T: [u8; 32] = [0; 32];");

    println!();

    // A extended (would need proper decompression)
    println!("pub const A_EXTENDED_X: [u8; 32] = [0; 32];");
    println!("pub const A_EXTENDED_Y: [u8; 32] = PUBLIC_KEY; // Same as compressed");
    println!("pub const A_EXTENDED_Z: [u8; 32] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];");
    println!("pub const A_EXTENDED_T: [u8; 32] = [0; 32];");

    // Verify the signature
    println!("\n=== Verification ===");
    match verifying_key.verify_strict(message, &signature) {
        Ok(_) => println!("✓ Signature is valid!"),
        Err(e) => println!("✗ Signature verification failed: {:?}", e),
    }
}

fn print_as_rust_array(bytes: &[u8], name: &str) {
    print!("pub const {}: [u8; {}] = [", name, bytes.len());
    for (i, byte) in bytes.iter().enumerate() {
        if i % 8 == 0 {
            print!("\n    ");
        }
        print!("0x{:02x}", byte);
        if i < bytes.len() - 1 {
            print!(", ");
        }
    }
    println!("\n];");
}
