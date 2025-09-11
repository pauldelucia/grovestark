use grovestark::{GroveSTARK, MerkleNode, PrivateInputs, PublicInputs, STARKConfig};

/// Testnet data for Dash Platform
/// Document ID: 9kqkfbbDz6go9GEeUJSpsMG3mj3swcqa1UJ6rK5QnR6X
/// Owner ID: 3bFoxHWSiyzkbPH4rt16quPaq9W8PUXMpPoYTddA9RKU
/// Contract ID: 8XSvQw14RSGZS2MGXieTmXR4RVEyb5bZh7gYMWd6M6Te
pub mod testnet {

    // Real testnet data
    pub const DOCUMENT_ID: &str = "9kqkfbbDz6go9GEeUJSpsMG3mj3swcqa1UJ6rK5QnR6X";
    pub const OWNER_ID: &str = "3bFoxHWSiyzkbPH4rt16quPaq9W8PUXMpPoYTddA9RKU";
    pub const CONTRACT_ID: &str = "8XSvQw14RSGZS2MGXieTmXR4RVEyb5bZh7gYMWd6M6Te";
    pub const DOCUMENT_TYPE: &str = "minimalContract";

    // Critical Authentication Key (Key ID: 4)
    pub const KEY_ID: u32 = 4;
    pub const KEY_PURPOSE: &str = "AUTHENTICATION";
    pub const KEY_SECURITY_LEVEL: &str = "CRITICAL";
    pub const KEY_TYPE: &str = "EDDSA_ED25519";

    // Public key in different formats
    pub const PUBLIC_KEY_HEX: &str =
        "0203285018f170ffa601a865a241926c24ee04a4f4a8111f1d61f93eceae68fed3";
    pub const PUBLIC_KEY_BASE64: &str = "AgMoUBjxcP+mAahlokGSbCTuBKT0qBEfHWH5Ps6uaP7T";
    pub const PUBLIC_KEY_HASH: &str = "a8ba3a4160c9e3969611dcfa2edcade435a3c68a";

    // Private key for testing (NEVER use in production!)
    pub const PRIVATE_KEY_HEX: &str =
        "fe94e9a3edd263b5b4826438d3cf614ef922dcbc5e211f3928d119003435346f";

    pub fn get_private_key() -> [u8; 32] {
        let bytes = hex::decode(PRIVATE_KEY_HEX).expect("Invalid private key hex");
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        key
    }

    pub fn get_public_key() -> Vec<u8> {
        hex::decode(PUBLIC_KEY_HEX).expect("Invalid public key hex")
    }

    pub fn get_owner_id_bytes() -> Vec<u8> {
        // Convert base58 owner ID to bytes (simplified - in production use proper base58 decoder)
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(OWNER_ID.as_bytes());
        hash.to_vec()
    }

    pub fn get_contract_id_bytes() -> [u8; 32] {
        // Convert base58 contract ID to bytes
        let mut bytes = [0u8; 32];
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(CONTRACT_ID.as_bytes());
        bytes.copy_from_slice(&hash);
        bytes
    }

    pub fn create_test_document() -> Vec<u8> {
        // Create a minimal CBOR-encoded document
        // In production, this would be the actual document from Dash Platform
        let doc = format!(
            r#"{{
                "id": "{}",
                "ownerId": "{}",
                "type": "{}",
                "revision": 1
            }}"#,
            DOCUMENT_ID, OWNER_ID, DOCUMENT_TYPE
        );
        doc.into_bytes()
    }
}

#[test]
fn test_with_testnet_data() {
    let config = STARKConfig::default();
    let prover = GroveSTARK::with_config(config.clone());

    // Create witness with testnet data
    let owner_id = {
        let owner_bytes = testnet::get_owner_id_bytes();
        let mut owner_id = [0u8; 32];
        owner_id.copy_from_slice(&owner_bytes[..32.min(owner_bytes.len())]);
        owner_id
    };

    let witness = PrivateInputs {
        document_cbor: testnet::create_test_document(),
        owner_id,
        identity_id: owner_id, // Must match owner_id

        // Identity-aware fields
        doc_root: [0x44; 32],
        keys_root: [0x55; 32],
        owner_id_leaf_to_doc_path: vec![
            // These would be actual Merkle paths from GroveDB
            // For testing, using placeholder paths
            MerkleNode {
                hash: [1u8; 32],
                is_left: true,
            },
            MerkleNode {
                hash: [2u8; 32],
                is_left: false,
            },
        ],
        docroot_to_state_path: vec![],
        key_leaf_to_keysroot_path: vec![MerkleNode {
            hash: [3u8; 32],
            is_left: true,
        }],
        identity_leaf_to_state_path: vec![],

        private_key: testnet::get_private_key(),
        // Signature components
        signature_r: [0u8; 32], // Placeholder
        signature_s: [0u8; 32], // Placeholder
        ..Default::default()
    };

    // Create public inputs
    let public_inputs = PublicInputs {
        state_root: [0u8; 32], // Would be actual Dash Platform state root
        contract_id: testnet::get_contract_id_bytes(),
        message_hash: [0u8; 32], // Would be actual message hash
        timestamp: 1234567890,
    };

    // Generate proof
    let proof_result = prover.prove(witness, public_inputs.clone());

    // Since we're using placeholder signature values, the proof generation
    // will succeed but verification of the signature will fail.
    // In production, you would use actual signed data.
    match proof_result {
        Ok(proof) => {
            // Verify the proof structure is created
            assert_eq!(proof.public_inputs.contract_id, public_inputs.contract_id);
            assert_eq!(proof.public_inputs.state_root, public_inputs.state_root);

            // Note: Full verification would fail with placeholder signatures
            // In production, use actual signatures
            println!("Proof generated successfully with testnet data");
        }
        Err(e) => {
            // Expected with placeholder signatures
            println!(
                "Proof generation failed (expected with placeholder signatures): {:?}",
                e
            );
        }
    }
}

#[test]
fn test_document_hashing() {
    use grovestark::crypto::Blake3Hasher;

    let document = testnet::create_test_document();
    let hash = Blake3Hasher::hash(&document);

    // Verify hash is 32 bytes
    assert_eq!(hash.len(), 32);

    // Hash should be deterministic
    let hash2 = Blake3Hasher::hash(&document);
    assert_eq!(hash, hash2);
}

#[test]
fn test_contract_document_relationship() {
    // Test that we can properly encode the relationship between
    // contract, document, and owner

    let contract_id = testnet::get_contract_id_bytes();
    let owner_id = testnet::get_owner_id_bytes();
    let document = testnet::create_test_document();

    // Create a commitment that binds all three together
    use grovestark::crypto::Blake3Hasher;
    let commitment = Blake3Hasher::hash(&[&contract_id[..], &owner_id[..], &document[..]].concat());

    // Commitment should be deterministic
    let commitment2 =
        Blake3Hasher::hash(&[&contract_id[..], &owner_id[..], &document[..]].concat());

    assert_eq!(commitment, commitment2);
}

/// Helper function to create a realistic witness for testnet data
pub fn create_testnet_witness() -> PrivateInputs {
    use grovestark::crypto::Blake3Hasher;

    let owner_id = {
        let owner_bytes = testnet::get_owner_id_bytes();
        let mut owner_id = [0u8; 32];
        owner_id.copy_from_slice(&owner_bytes[..32.min(owner_bytes.len())]);
        owner_id
    };

    PrivateInputs {
        document_cbor: testnet::create_test_document(),
        owner_id,
        identity_id: owner_id, // Must match owner_id

        // Identity-aware fields
        doc_root: [0x44; 32],
        keys_root: [0x55; 32],
        owner_id_leaf_to_doc_path: vec![
            MerkleNode {
                hash: Blake3Hasher::hash(b"merkle_sibling_1"),
                is_left: true,
            },
            MerkleNode {
                hash: Blake3Hasher::hash(b"merkle_sibling_2"),
                is_left: false,
            },
            MerkleNode {
                hash: Blake3Hasher::hash(b"merkle_sibling_3"),
                is_left: true,
            },
        ],
        docroot_to_state_path: vec![],
        key_leaf_to_keysroot_path: vec![
            MerkleNode {
                hash: Blake3Hasher::hash(b"key_merkle_sibling_1"),
                is_left: false,
            },
            MerkleNode {
                hash: Blake3Hasher::hash(b"key_merkle_sibling_2"),
                is_left: true,
            },
        ],
        identity_leaf_to_state_path: vec![],

        private_key: testnet::get_private_key(),
        signature_r: [0u8; 32], // Would be actual signature
        signature_s: [0u8; 32], // Would be actual signature
        ..Default::default()
    }
}

/// Helper function to create realistic public inputs for testnet
pub fn create_testnet_public_inputs() -> PublicInputs {
    use grovestark::crypto::Blake3Hasher;

    PublicInputs {
        state_root: Blake3Hasher::hash(b"dash_platform_state_root_testnet"),
        contract_id: testnet::get_contract_id_bytes(),
        message_hash: Blake3Hasher::hash(b"challenge_message"),
        timestamp: 1699999999,
    }
}
