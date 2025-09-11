use grovestark::parser::parse_grovedb_proof;
use hex;

fn load_fixture_doc_proof() -> Vec<u8> {
    #[derive(serde::Deserialize)]
    struct Fixtures { pass: PassFix }
    #[derive(serde::Deserialize)]
    struct PassFix { document_proof_hex: String }
    let fixtures: Fixtures = serde_json::from_str(include_str!("fixtures/PASS_AND_FAIL.json")).unwrap();
    hex::decode(&fixtures.pass.document_proof_hex).expect("decode document proof")
}

#[test]
fn test_parse_real_grovedb_proof() {
    // Use the real fixture document proof (layered format)
    let doc_proof = load_fixture_doc_proof();

    println!("Parsing document proof of {} bytes", doc_proof.len());

    // Look for Op::Push(Node::Hash) operations (0x01 followed by 32 bytes)
    let mut pos = 33; // Skip version + state root
    let mut found_ops = Vec::new();

    while pos < doc_proof.len() - 32 {
        if doc_proof[pos] == 0x01 {
            // Potential hash node
            println!("Found 0x01 at position {}", pos);
            if pos + 32 < doc_proof.len() {
                let hash_bytes = &doc_proof[pos + 1..pos + 33];
                println!("  Hash: {:02x?}", &hash_bytes[0..8]);
                found_ops.push(pos);
            }
        } else if doc_proof[pos] == 0x10 {
            println!("Found Op::Parent at position {}", pos);
            found_ops.push(pos);
        } else if doc_proof[pos] == 0x11 {
            println!("Found Op::Child at position {}", pos);
            found_ops.push(pos);
        }
        pos += 1;
    }

    println!("\nFound {} potential operations", found_ops.len());

    // Try our parser on the full layered proof
    let result = parse_grovedb_proof(&doc_proof);
    assert!(result.is_ok(), "Failed to parse proof: {:?}", result.err());

    let nodes = result.unwrap();
    println!("\nExtracted {} nodes from proof", nodes.len());

    for (i, node) in nodes.iter().enumerate() {
        println!(
            "Node {}: is_left={}, hash={:02x?}",
            i,
            node.is_left,
            &node.hash[0..8]
        );
    }
}

#[test]
fn test_find_proof_operations() {
    // Let's analyze the proof structure more carefully
    let doc_proof_hex = "008d01df2b7bb6e932d43346b57bee9e4294556918af5e88191d2da318ce6ab7ff2dc904014000240201205bb4077299c35f3d25823bac24779abe40e3e0ff4d76104b5b6a074687142a4800e1087bd1e12d3e63369913b0a6a96d6ad9b7934dd71f51b8abf1a840282d009d10013d0791d300d9b21bbf5c93758a411d27f7b61fb3307d4ba6d43ad78fdf8d646911";

    let doc_proof = hex::decode(doc_proof_hex).expect("Failed to decode hex");

    println!("Proof analysis:");
    println!("  Total length: {} bytes", doc_proof.len());
    println!("  Version byte: 0x{:02x}", doc_proof[0]);
    println!("  State root: {:02x?}", &doc_proof[1..33]);

    // Look for specific patterns
    println!("\nSearching for operation codes:");

    for i in 33..doc_proof.len() {
        match doc_proof[i] {
            0x01 => {
                if i + 32 < doc_proof.len() {
                    println!(
                        "  [{}] 0x01 (Push Hash) - next 32: {:02x?}...",
                        i,
                        &doc_proof[i + 1..i + 9]
                    );
                }
            }
            0x02 => println!("  [{}] 0x02 (Push KVHash)", i),
            0x03 => println!("  [{}] 0x03 (Push KV)", i),
            0x10 => println!("  [{}] 0x10 (Parent)", i),
            0x11 => println!("  [{}] 0x11 (Child)", i),
            _ => {}
        }
    }
}
