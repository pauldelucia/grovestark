use grovestark::{
    test_utils::create_valid_eddsa_witness, GroveSTARK, MerkleNode, PrivateInputs, PublicInputs,
    STARKConfig,
};

fn id_from_b58(s: &str) -> [u8; 32] {
    let bytes = bs58::decode(s).into_vec().expect("base58 decode failed");
    assert_eq!(bytes.len(), 32, "decoded ID must be 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn make_identity_aware(mut w: PrivateInputs) -> PrivateInputs {
    // Populate identity-aware fields so the identity-aware Merkle path is used.
    // Use 1 dummy node per path; the implementation forces the final root to public input.
    w.doc_root = [1u8; 32];
    w.keys_root = [2u8; 32];
    w.owner_id_leaf_to_doc_path = vec![MerkleNode {
        hash: [3u8; 32],
        is_left: true,
    }];
    w.docroot_to_state_path = vec![MerkleNode {
        hash: [4u8; 32],
        is_left: false,
    }];
    w.identity_leaf_to_state_path = vec![MerkleNode {
        hash: [5u8; 32],
        is_left: true,
    }];
    w.key_leaf_to_keysroot_path = vec![MerkleNode {
        hash: [6u8; 32],
        is_left: false,
    }];
    // Ensure identity-aware path sees a non-zero public key
    if w.pubkey_a_compressed == [0u8; 32] {
        w.pubkey_a_compressed = w.public_key_a;
    }
    w
}

#[test]
fn test_logs_valid_then_invalid() {
    // Allow weak params for this fast-running test
    std::env::set_var("GS_ALLOW_WEAK_PARAMS", "1");
    std::env::set_var("FAST_TESTS", "1");
    // IDs taken from DET_PROOF_LOGS.md (owner that appears in the logs) and a mismatched identity.
    // Owner (base58): J846nouwbX2LYoyfWGC4LdYoYKKsKpjTnQFQaNZKDWRS
    // Mismatched identity (base58): kapC1fvHPhkg5i2ARyEpoDyGzyFZzQK4S7XnBhBki93
    let owner_id_b58 = "J846nouwbX2LYoyfWGC4LdYoYKKsKpjTnQFQaNZKDWRS";
    let mismatch_id_b58 = "kapC1fvHPhkg5i2ARyEpoDyGzyFZzQK4S7XnBhBki93";

    let owner_id = id_from_b58(owner_id_b58);
    let mismatch_id = id_from_b58(mismatch_id_b58);

    // Public inputs (state_root is arbitrary but non-placeholder to exercise boundary assertions)
    let public_inputs = PublicInputs {
        state_root: [0xAA; 32],
        contract_id: [0xBB; 32],
        message_hash: [0xCC; 32],
        timestamp: 1_700_000_000,
    };

    // Use fast test defaults (cfg(test) already lightens config)
    let mut config = STARKConfig::default();
    config.grinding_bits = 0;
    config.num_queries = 8;
    config.expansion_factor = 16;
    let prover = GroveSTARK::with_config(config);

    // 1) Valid: owner == identity → should verify
    let mut w_ok = create_valid_eddsa_witness();
    w_ok.owner_id = owner_id;
    w_ok.identity_id = owner_id;
    let w_ok = make_identity_aware(w_ok);

    let proof_ok = prover
        .prove(w_ok, public_inputs.clone())
        .expect("failed to generate valid proof");
    let verified_ok = prover
        .verify(&proof_ok, &public_inputs)
        .expect("verification errored for valid proof");
    assert!(verified_ok, "valid proof did not verify");

    // 2) Invalid: owner != identity → should fail verification
    // Build a non-identity-aware witness to bypass prevalidation,
    // and rely on DIFF boundary assertions to catch the mismatch.
    let mut w_bad = create_valid_eddsa_witness();
    w_bad.owner_id = owner_id;
    w_bad.identity_id = mismatch_id;
    // Force Merkle path by clearing identity-aware fields
    w_bad.doc_root = [0u8; 32];
    w_bad.keys_root = [0u8; 32];
    w_bad.owner_id_leaf_to_doc_path.clear();
    w_bad.docroot_to_state_path.clear();
    w_bad.identity_leaf_to_state_path.clear();
    w_bad.key_leaf_to_keysroot_path.clear();

    // Use placeholder state root (0x0A repeated) so Merkle boundary is skipped
    let public_inputs_loose = PublicInputs {
        state_root: [0x0A; 32],
        ..public_inputs
    };

    match prover.prove(w_bad, public_inputs_loose.clone()) {
        Ok(proof_bad) => {
            let verified_bad = prover
                .verify(&proof_bad, &public_inputs_loose)
                .expect("verification errored for mismatched IDs");
            assert!(!verified_bad, "mismatched IDs proof incorrectly verified");
        }
        Err(e) => {
            // Prover may reject mismatched identity during witness validation; accept this outcome
            println!(
                "✅ Prover correctly rejected mismatched identity during proof generation: {}",
                e
            );
        }
    }
}
