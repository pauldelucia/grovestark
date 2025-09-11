use grovestark::parser::proof_extractor::{
    decode_merk_proof, extract_merkle_path_from_ops, MerkNode, MerkOp,
};
use hex;

#[test]
fn test_proof_parsing_with_is_left() {
    // This is the document proof from DET_PROOF_LOGS.md
    let doc_proof_hex = "008d01df2b7bb6e932d43346b57bee9e4294556918af5e88191d2da318ce6ab7ff2dc904014000240201205bb4077299c35f3d25823bac24779abe40e3e0ff4d76104b5b6a074687142a4800e1087bd1e12d3e63369913b0a6a96d6ad9b7934dd71f51b8abf1a840282d009d10013d0791d300d9b21bbf5c93758a411d27f7b61fb3307d4ba6d43ad78fdf8d646911010140fb028b01985931c823f722968e943c663da32f74a00e06a9ae866c44ae85544cef7dc799028e1c0b2fe4c55e4891e72047aa134b49121e86b7816bdebc8ddb10b0c5d7126010019cc5eef8f284be5cbcb4c60e102ed80f8c65c1a698a9f2b2ecf9ad288887afa602472cdee36f03a9548b6173d20a323d6f5f82a722d1ad05b34f189c5c6b25294a1001487e98039043f388830ad9b5ceba0ea2caea90b5f22678b332f54fe3f4af804f02c7a957db2518ce3845b356d4c8d87c48054d17aa63a1987468bbf384be708da210012839d58ef9dbe5703ddd9cfce05a5aee2bdf385a07a603037ac3a0d58540080402fcf9335072821922004e4315b5be2f3e2695e6f740dae8d0bc74a038cad05d1b1001c3c8105c9628031a3758be7afc04d51a9633c9e4df061000332e1244f95ae3fe029bd9cb9ddceaa2b83e6243731ac1d5a35a5ca52f7a606b45561bc0160b55e89c10023a3aa08eafdcb1f910ccf1e6e46330b46d007cb38899b534ab8c08c5c6426c5b042057e5c248f52c7d15857a3af8525749caced7b8399c0ed3221c3648026370230600050201010100260c03151892264960e70272b6667ce8717902c5e69af0c9953a5653bf53826411023cf0248f9997b40fe5b248d9ff068d151c14e328dcf3c21cbeb14fcf0e753c4f10018016c1dd0bf2b28fdc06b415e03b6ac2a489e6eccb28eb5bc38f13f0a2c7beda1111026153686780ee38204610d502f16bce91b9620ca3fb9be9a773115f05be005f7910015399c590d2cb9599905a82ddeb23344aed92f910d8bea4832608dee794c22005111111111102f5a40b154096932fa4f0f0a0058553d8e34dadbb5536d789ab8d8da8be8fffc3100113fa02c86f511b00bf7faaee9fbd14a54b6a33b25fb7d7f7861bd3df4ac9321511012057e5c248f52c7d15857a3af8525749caced7b8399c0ed3221c364802637023064f012dc2833acd51e23e40ad7ab1e2abbd0745a54c13b265a1cd46bf0f88d03d87860401010008020104626c6f6200d84dd6907e1c4977368d8b652259e86c2926689f42a045fe7a22027d76d2a302100101013c0404626c6f62001402011073616c746564446f6d61696e4861736800a9cf0b4fd9197d1e18977c30cbf3f032ddfd1d9c5bd9b0f78484dbfd29a130340104626c6f626b040100002402012057840ab06c0d15a5542aedf4e3df9bd854835ce24a4139e65f4b63764864890c002c04e9dff2e94ee7064bd870bbf0eac280822ac8cbb7bf920568ff785289f97002884ca74cafb81cdfbb72b67d205279dfe83e59d244695b99f9e27dfa8cf43e9210010100af032057840ab06c0d15a5542aedf4e3df9bd854835ce24a4139e65f4b63764864890c008b00640157840ab06c0d15a5542aedf4e3df9bd854835ce24a4139e65f4b63764864890cfe653f96bfa2c977e39772e1167717dccb4e86371c7e97eb570c9e5dd43cc05d010000747616d18ba23f832de0139829ac5b4ba8ab1273f1b5c9ae9a1b2aa30434f79f012302fe653f96bfa2c977e39772e1167717dccb4e86371c7e97eb570c9e5dd43cc05d25830001";

    let doc_proof = hex::decode(doc_proof_hex).expect("Failed to decode hex");

    // Find where Merk operations start (around position 109)
    let mut merk_start = None;
    for i in 100..doc_proof.len().min(150) {
        // Look for Merk operation codes (0x01-0x13)
        if doc_proof[i] <= 0x13 && doc_proof[i] > 0 {
            // Check if it looks like a valid operation sequence
            if i + 32 < doc_proof.len() {
                merk_start = Some(i);
                break;
            }
        }
    }

    if let Some(start) = merk_start {
        println!("Found Merk operations starting at position {}", start);
        let merk_data = &doc_proof[start..];

        // Try to decode operations
        match decode_merk_proof(merk_data) {
            Ok(ops) => {
                println!("\nDecoded {} operations:", ops.len());

                // Show first 10 operations in detail
                for (i, op) in ops.iter().enumerate().take(10) {
                    match op {
                        MerkOp::Push(node) => match node {
                            MerkNode::Hash(h) => {
                                println!(
                                    "  {}: Push(Hash({:02x}{:02x}{:02x}{:02x}...))",
                                    i, h[0], h[1], h[2], h[3]
                                );
                            }
                            MerkNode::KVHash(h) => {
                                println!(
                                    "  {}: Push(KVHash({:02x}{:02x}{:02x}{:02x}...))",
                                    i, h[0], h[1], h[2], h[3]
                                );
                            }
                            _ => println!("  {}: Push(other node type)", i),
                        },
                        MerkOp::PushInverted(node) => match node {
                            MerkNode::Hash(h) => {
                                println!(
                                    "  {}: PushInverted(Hash({:02x}{:02x}{:02x}{:02x}...))",
                                    i, h[0], h[1], h[2], h[3]
                                );
                            }
                            _ => println!("  {}: PushInverted(other node type)", i),
                        },
                        MerkOp::Parent => println!("  {}: Parent", i),
                        MerkOp::Child => println!("  {}: Child", i),
                        MerkOp::ParentInverted => println!("  {}: ParentInverted", i),
                        MerkOp::ChildInverted => println!("  {}: ChildInverted", i),
                    }
                }

                // Extract Merkle path
                let path = extract_merkle_path_from_ops(&ops);
                println!("\nExtracted Merkle path with {} nodes:", path.len());

                // Show the is_left flags
                let left_count = path.iter().filter(|(is_left, _)| *is_left).count();
                let right_count = path.len() - left_count;

                println!(
                    "  {} left siblings, {} right siblings",
                    left_count, right_count
                );

                // Show first few nodes with their is_left flags
                for (i, (is_left, hash)) in path.iter().enumerate().take(5) {
                    println!(
                        "  Node {}: is_left={}, hash={:02x}{:02x}{:02x}{:02x}...",
                        i, is_left, hash[0], hash[1], hash[2], hash[3]
                    );
                }
            }
            Err(e) => {
                println!("\nFailed to decode: {:?}", e);

                // Show the bytes around the failure point
                println!("\nFirst 50 bytes of Merk data:");
                for (i, byte) in merk_data.iter().enumerate().take(50) {
                    if i % 16 == 0 {
                        println!();
                        print!("{:04x}: ", start + i);
                    }
                    print!("{:02x} ", byte);
                }
                println!();
            }
        }
    } else {
        println!("Could not find Merk operations in proof");
    }
}
