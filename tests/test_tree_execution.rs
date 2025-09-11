use grovestark::parser::grovedb_executor::{
    execute_proof, extract_sibling_hashes, parse_proof_operations,
};
use hex;

#[test]
fn test_execute_proof_operations() {
    // Simple proof with a few operations to test execution
    let doc_proof_hex = "008d01df2b7bb6e932d43346b57bee9e4294556918af5e88191d2da318ce6ab7ff2dc904014000240201205bb4077299c35f3d25823bac24779abe40e3e0ff4d76104b5b6a074687142a4800e1087bd1e12d3e63369913b0a6a96d6ad9b7934dd71f51b8abf1a840282d009d10013d0791d300d9b21bbf5c93758a411d27f7b61fb3307d4ba6d43ad78fdf8d646911";

    let doc_proof = hex::decode(doc_proof_hex).expect("Failed to decode hex");

    // Parse operations
    let operations = parse_proof_operations(&doc_proof).expect("Failed to parse operations");
    println!("Parsed {} operations", operations.len());

    // Try to execute them
    match execute_proof(operations.clone()) {
        Ok(tree) => {
            println!("Successfully built tree!");
            // Tree was built successfully
        }
        Err(e) => {
            println!("Failed to execute proof: {:?}", e);
            // Let's try with just the first few operations
            if operations.len() > 3 {
                let subset = operations[0..3].to_vec();
                println!("Trying with first 3 operations");
                match execute_proof(subset) {
                    Ok(_) => println!("Subset execution succeeded"),
                    Err(e2) => println!("Subset also failed: {:?}", e2),
                }
            }
        }
    }
}

#[test]
fn test_simple_proof_execution() {
    use grovestark::parser::grovedb_executor::{execute_proof, Node, Op};

    // Create a simple proof sequence
    let operations = vec![
        Op::Push(Node::Hash([1u8; 32])),
        Op::Push(Node::Hash([2u8; 32])),
        Op::Parent, // Combine them
    ];

    match execute_proof(operations) {
        Ok(tree) => {
            println!("Simple proof execution succeeded");
            assert!(tree.left.is_some(), "Tree should have left child");
        }
        Err(e) => {
            panic!("Simple proof execution failed: {:?}", e);
        }
    }
}

#[test]
fn test_complex_proof_execution() {
    use grovestark::parser::grovedb_executor::{execute_proof, Node, Op};

    // Create a more complex proof sequence
    let operations = vec![
        Op::Push(Node::Hash([1u8; 32])),
        Op::Push(Node::Hash([2u8; 32])),
        Op::Parent, // Combine 1 and 2
        Op::Push(Node::Hash([3u8; 32])),
        Op::Child, // Add 3 as child
    ];

    match execute_proof(operations) {
        Ok(tree) => {
            println!("Complex proof execution succeeded");
            assert!(
                tree.left.is_some() || tree.right.is_some(),
                "Tree should have children"
            );
        }
        Err(e) => {
            panic!("Complex proof execution failed: {:?}", e);
        }
    }
}
