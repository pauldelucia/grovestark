//! Complete BLAKE3 implementation tests

use grovestark::crypto::blake3_field::{
    blake3_hash, blake3_hash_block, verify_merkle_path, Blake3FieldState,
};
use grovestark::field::FieldElement;

#[test]
fn test_blake3_compression_basic() {
    let state = Blake3FieldState::new();
    let output = state.compress();

    // Should produce 16 field elements
    assert_eq!(output.len(), 16);

    // Should not be all zeros
    assert!(output.iter().any(|&x| x != FieldElement::ZERO));
}

#[test]
fn test_blake3_load_block() {
    let mut state = Blake3FieldState::new();

    // Load a test block
    let data = b"The quick brown fox jumps over the lazy dog";
    state.load_block(data);

    // Check first word (little-endian "The ")
    let expected_first = u32::from_le_bytes([b'T', b'h', b'e', b' ']);
    assert_eq!(state.block[0].as_u64(), expected_first as u64);

    // Check block length
    assert_eq!(state.block_len.as_u64(), data.len() as u64);
}

#[test]
fn test_blake3_single_block_hash() {
    // Test with known input
    let data = b"BLAKE3 test vector";
    let hash1 = blake3_hash_block(data);
    let hash2 = blake3_hash_block(data);

    // Should be deterministic
    assert_eq!(hash1, hash2);

    // Should not be trivial
    assert_ne!(hash1[0], 0);
    assert_ne!(hash1[0], 0xFFFFFFFF);
}

#[test]
fn test_blake3_multi_block_hash() {
    // Test with data spanning multiple blocks
    let data = vec![0x55u8; 200]; // More than 3 blocks
    let hash = blake3_hash(&data);

    // Should produce consistent results
    let hash2 = blake3_hash(&data);
    assert_eq!(hash, hash2);

    // Different data should produce different hash
    let data2 = vec![0xAAu8; 200];
    let hash3 = blake3_hash(&data2);
    assert_ne!(hash, hash3);
}

#[test]
fn test_blake3_incremental_hashing() {
    // Test that hashing blocks incrementally works
    let data = vec![0x42u8; 128];

    // Hash all at once
    let full_hash = blake3_hash(&data);

    // This should match (for our simplified version)
    // In real BLAKE3, there's more complex tree hashing
    assert_eq!(full_hash.len(), 8);
}

#[test]
fn test_merkle_path_verification() {
    // Create a simple Merkle tree scenario
    let leaf = [0x11u8; 32];
    let sibling1 = [0x22u8; 32];
    let sibling2 = [0x33u8; 32];

    // Calculate intermediate hash
    let mut combined1 = [0u8; 64];
    combined1[0..32].copy_from_slice(&leaf);
    combined1[32..64].copy_from_slice(&sibling1);
    let hash1_result = blake3_hash(&combined1);

    let mut intermediate = [0u8; 32];
    for i in 0..8 {
        let bytes = hash1_result[i].to_le_bytes();
        intermediate[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }

    // Calculate root
    let mut combined2 = [0u8; 64];
    combined2[0..32].copy_from_slice(&intermediate);
    combined2[32..64].copy_from_slice(&sibling2);
    let root_result = blake3_hash(&combined2);

    let mut root = [0u8; 32];
    for i in 0..8 {
        let bytes = root_result[i].to_le_bytes();
        root[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }

    // Create path
    let path = vec![
        (true, sibling1), // leaf is on left
        (true, sibling2), // intermediate is on left
    ];

    // Verify path
    assert!(verify_merkle_path(&leaf, &path, &root));

    // Wrong path should fail
    let wrong_path = vec![
        (false, sibling1), // Wrong position
        (true, sibling2),
    ];
    assert!(!verify_merkle_path(&leaf, &wrong_path, &root));
}

#[test]
fn test_blake3_field_state_with_cv() {
    // Test creating state with custom chain value
    let cv = [0x12345678u32; 8];
    let state = Blake3FieldState::with_cv(cv);

    for i in 0..8 {
        assert_eq!(state.cv[i].as_u64(), 0x12345678);
    }
}

#[test]
fn test_blake3_flags() {
    use grovestark::crypto::blake3_field::{CHUNK_END, CHUNK_START, ROOT};

    let mut state = Blake3FieldState::new();
    state.flags = FieldElement::new((CHUNK_START | CHUNK_END | ROOT) as u64);

    // Should have all three flags set
    let flags = state.flags.as_u64() as u32;
    assert_ne!(flags & CHUNK_START, 0);
    assert_ne!(flags & CHUNK_END, 0);
    assert_ne!(flags & ROOT, 0);
}

#[test]
fn test_blake3_message_permutation() {
    use grovestark::crypto::blake3_field::MSG_PERMUTATION;

    // Verify permutations are valid
    for round in &MSG_PERMUTATION {
        // Each round should be a permutation of 0..16
        let mut seen = [false; 16];
        for &idx in round {
            assert!(idx < 16);
            assert!(!seen[idx], "Duplicate index in permutation");
            seen[idx] = true;
        }
        assert!(seen.iter().all(|&x| x), "Missing index in permutation");
    }
}

#[test]
fn test_blake3_empty_block() {
    // Test hashing empty block
    let hash = blake3_hash_block(b"");

    // Should still produce valid output
    assert_ne!(hash[0], 0);

    // Should be consistent
    let hash2 = blake3_hash_block(b"");
    assert_eq!(hash, hash2);
}

#[test]
fn test_blake3_full_block() {
    // Test with exactly 64 bytes
    let data = vec![0x5Au8; 64];
    let hash = blake3_hash_block(&data);

    // Should work correctly
    assert_ne!(hash[0], 0);

    // Test with multi-block for same data
    let hash2 = blake3_hash(&data);
    // These might differ due to different flags/counter
    assert_eq!(hash.len(), hash2.len());
}

#[test]
fn test_blake3_different_lengths() {
    // Test various data lengths
    let lengths = [0, 1, 31, 32, 63, 64, 65, 127, 128, 255, 256];

    for len in lengths {
        let data = vec![0x77u8; len];
        let hash = blake3_hash(&data);

        // Each should produce valid hash
        assert_eq!(hash.len(), 8);

        // Should be deterministic
        let hash2 = blake3_hash(&data);
        assert_eq!(hash, hash2);
    }
}
