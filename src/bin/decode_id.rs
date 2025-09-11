fn main() {
    let id_str = "FQ4waDowFQXD4tJPKQM1114VSr5f8s3qAc5bT8FJkT49";
    let decoded = bs58::decode(id_str).into_vec().unwrap();
    println!("Base58 \"{}\" decodes to:", id_str);
    println!("  Hex: {}", hex::encode(&decoded));
    println!("  Length: {} bytes", decoded.len());
}
