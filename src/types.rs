use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateInputs {
    // === Document side (hidden doc_root) ===
    /// Document Merkle root (hidden from verifier)
    pub doc_root: [u8; 32],
    /// Owner ID extracted from document (32 bytes)
    pub owner_id: [u8; 32],
    /// Merkle path from owner_id leaf to doc_root
    pub owner_id_leaf_to_doc_path: Vec<MerkleNode>,
    /// Merkle path from doc_root to state_root
    pub docroot_to_state_path: Vec<MerkleNode>,

    // === Identity side (hidden identity) ===
    /// Identity ID (must equal owner_id for valid proof)
    pub identity_id: [u8; 32],
    /// Root of the identity's key set Merkle tree
    pub keys_root: [u8; 32],
    /// Merkle path from identity leaf to state_root
    pub identity_leaf_to_state_path: Vec<MerkleNode>,

    // === Key set membership ===
    /// Key usage tag (e.g., "sig:ed25519:v1\0")
    pub key_usage_tag: [u8; 16],
    /// Ed25519 compressed public key from identity's key set
    pub pubkey_a_compressed: [u8; 32],
    /// Merkle path from key leaf to keys_root
    pub key_leaf_to_keysroot_path: Vec<MerkleNode>,

    // === EdDSA signature ===
    /// EdDSA signature R point (32 bytes, compressed)
    pub signature_r: [u8; 32],
    /// EdDSA signature s scalar (32 bytes)
    pub signature_s: [u8; 32],

    // === GroveDB proof data ===
    /// Raw GroveDB proof bytes for GroveVM execution (optional)
    #[serde(default)]
    pub grovedb_proof: Vec<u8>,

    /// Document CBOR
    #[serde(default)]
    pub document_cbor: Vec<u8>,
    // === EdDSA Witness Augmentation ===
    /// Public key A (alias for pubkey_a_compressed for compatibility)
    #[serde(default)]
    pub public_key_a: [u8; 32],
    /// Hash h = H(R || A || M) mod L (32 bytes)
    /// For now provided as witness, later computed via SHA-512
    #[serde(default)]
    pub hash_h: [u8; 32],
    /// Decomposed windows of s for scalar mult (64 4-bit values)
    #[serde(default)]
    pub s_windows: Vec<u8>,
    /// Decomposed windows of h for scalar mult (64 4-bit values)
    #[serde(default)]
    pub h_windows: Vec<u8>,

    // === Scalar Range Check Auxiliary Values ===
    /// Difference s - L for range check (32 bytes)
    #[serde(default)]
    pub s_range_diff: [u8; 32],
    /// Borrow chain for s < L range check (32 bytes)
    #[serde(default)]
    pub s_range_borrow: [u8; 32],
    /// Difference h - L for range check (32 bytes)
    #[serde(default)]
    pub h_range_diff: [u8; 32],
    /// Borrow chain for h < L range check (32 bytes)
    #[serde(default)]
    pub h_range_borrow: [u8; 32],

    // === Extended Coordinate Representations ===
    /// R point extended X coordinate (32 bytes)
    #[serde(default)]
    pub r_extended_x: [u8; 32],
    /// R point extended Y coordinate (32 bytes)
    #[serde(default)]
    pub r_extended_y: [u8; 32],
    /// R point extended Z coordinate (32 bytes)
    #[serde(default)]
    pub r_extended_z: [u8; 32],
    /// R point extended T coordinate (32 bytes)
    #[serde(default)]
    pub r_extended_t: [u8; 32],
    /// A point extended X coordinate (32 bytes)
    #[serde(default)]
    pub a_extended_x: [u8; 32],
    /// A point extended Y coordinate (32 bytes)
    #[serde(default)]
    pub a_extended_y: [u8; 32],
    /// A point extended Z coordinate (32 bytes)
    #[serde(default)]
    pub a_extended_z: [u8; 32],
    /// A point extended T coordinate (32 bytes)
    #[serde(default)]
    pub a_extended_t: [u8; 32],

    // === Intermediate Points for Scalar Multiplication ===
    /// First intermediate point X coordinate (32 bytes)
    #[serde(default)]
    pub intermediate_point_1_x: [u8; 32],
    /// First intermediate point Y coordinate (32 bytes)
    #[serde(default)]
    pub intermediate_point_1_y: [u8; 32],
    /// First intermediate point Z coordinate (32 bytes)
    #[serde(default)]
    pub intermediate_point_1_z: [u8; 32],
    /// First intermediate point T coordinate (32 bytes)
    #[serde(default)]
    pub intermediate_point_1_t: [u8; 32],
    /// Second intermediate point X coordinate (32 bytes)
    #[serde(default)]
    pub intermediate_point_2_x: [u8; 32],
    /// Second intermediate point Y coordinate (32 bytes)
    #[serde(default)]
    pub intermediate_point_2_y: [u8; 32],
    /// Second intermediate point Z coordinate (32 bytes)
    #[serde(default)]
    pub intermediate_point_2_z: [u8; 32],
    /// Second intermediate point T coordinate (32 bytes)
    #[serde(default)]
    pub intermediate_point_2_t: [u8; 32],
}

impl Default for PrivateInputs {
    fn default() -> Self {
        Self {
            // Document side
            doc_root: [0u8; 32],
            owner_id: [0u8; 32],
            owner_id_leaf_to_doc_path: Vec::new(),
            docroot_to_state_path: Vec::new(),
            // Identity side
            identity_id: [0u8; 32],
            keys_root: [0u8; 32],
            identity_leaf_to_state_path: Vec::new(),
            // Key set membership
            key_usage_tag: *b"sig:ed25519:v1\0\0",
            pubkey_a_compressed: [0u8; 32],
            key_leaf_to_keysroot_path: Vec::new(),
            // EdDSA signature
            signature_r: [0u8; 32],
            signature_s: [0u8; 32],
            // GroveDB proof
            grovedb_proof: Vec::new(),
            document_cbor: Vec::new(),
            public_key_a: [0u8; 32],
            hash_h: [0u8; 32],
            s_windows: vec![0u8; 64],
            h_windows: vec![0u8; 64],
            // Scalar range check auxiliary values
            s_range_diff: [0u8; 32],
            s_range_borrow: [0u8; 32],
            h_range_diff: [0u8; 32],
            h_range_borrow: [0u8; 32],
            // Extended coordinate representations
            r_extended_x: [0u8; 32],
            r_extended_y: [0u8; 32],
            r_extended_z: [0u8; 32],
            r_extended_t: [0u8; 32],
            a_extended_x: [0u8; 32],
            a_extended_y: [0u8; 32],
            a_extended_z: [0u8; 32],
            a_extended_t: [0u8; 32],
            // Intermediate points
            intermediate_point_1_x: [0u8; 32],
            intermediate_point_1_y: [0u8; 32],
            intermediate_point_1_z: [0u8; 32],
            intermediate_point_1_t: [0u8; 32],
            intermediate_point_2_x: [0u8; 32],
            intermediate_point_2_y: [0u8; 32],
            intermediate_point_2_z: [0u8; 32],
            intermediate_point_2_t: [0u8; 32],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    pub hash: [u8; 32],
    pub is_left: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    pub state_root: [u8; 32],
    pub contract_id: [u8; 32],
    pub message_hash: [u8; 32],
    /// Timestamp (deprecated, not used in ZK proof)
    #[serde(default)]
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicOutputs {
    pub verified: bool,
    pub key_security_level: u8,
    pub proof_commitment: [u8; 32],
    // Identity binding is enforced cryptographically via boundary assertions
    // No need to expose owner_id and identity_id here
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct STARKProof {
    pub trace_commitment: Vec<u8>,
    pub constraint_commitment: Vec<u8>,
    pub fri_proof: FRIProof,
    pub pow_nonce: u64,
    pub public_inputs: PublicInputs,
    pub public_outputs: PublicOutputs,
}

/// FRI proof structure
///
/// Note: This structure serves as a compatibility layer between our API
/// and Winterfell's internal proof format. The complete STARK proof from
/// Winterfell is stored in `final_polynomial` for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FRIProof {
    /// Contains the complete Winterfell STARK proof bytes
    pub final_polynomial: Vec<u8>,
    /// Proof of work nonce for additional security
    pub proof_of_work: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryRound {
    pub leaf_index: usize,
    pub authentication_paths: Vec<Vec<[u8; 32]>>,
    pub evaluations: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProof {
    pub individual_proofs: Vec<STARKProof>,
    pub batch_commitment: [u8; 32],
    pub aggregated_proof: Option<STARKProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct STARKConfig {
    pub field_bits: usize,
    pub expansion_factor: usize,
    pub num_queries: usize,
    pub folding_factor: usize,
    pub max_remainder_degree: usize,
    pub grinding_bits: usize,
    pub num_trace_columns: usize,
    pub trace_length: usize,
    pub security_level: usize,
}

impl Default for STARKConfig {
    fn default() -> Self {
        // Defaults are environment-sensitive: speed up tests while keeping
        // production builds on stronger parameters.
        //
        // To override in tests without changing code, you can also set:
        //   FAST_TESTS=1  (honored by various fast-path guards)
        // for even faster runs when needed.
        #[cfg(test)]
        {
            // Test-friendly defaults (fast): minimal grinding and fewer queries
            Self {
                field_bits: 64,
                expansion_factor: 8,
                num_queries: 8,
                folding_factor: 4,
                max_remainder_degree: 255,
                grinding_bits: 0,
                num_trace_columns: 104,
                trace_length: 65536,
                security_level: 80,
            }
        }
        #[cfg(not(test))]
        {
            // Production defaults per GUIDANCE.md recommendations
            Self {
                field_bits: 64,
                expansion_factor: 16,      // stronger FRI soundness
                num_queries: 48,           // 48-64 recommended
                folding_factor: 4,         // perf/soundness sweet spot
                max_remainder_degree: 255, // one less than a power of two
                grinding_bits: 24,         // PoW ~2^24
                num_trace_columns: 104,
                trace_length: 65536,
                security_level: 128,
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParsedProof {
    pub state_root: [u8; 32],
    pub document_path: Vec<MerkleNode>,
    pub key_path: Vec<MerkleNode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkOp {
    Push([u8; 32]),
    Parent,
    Child([u8; 32]),
    Hash([u8; 32]), // 0x04 - Hash operation from SDK
    KVHash([u8; 32]),
    KVValueHash([u8; 32]),
}

#[derive(Debug, Clone)]
pub struct ExecutionTrace {
    pub columns: Vec<Vec<u64>>,
    pub width: usize,
    pub length: usize,
}

impl ExecutionTrace {
    pub fn new(width: usize, length: usize) -> Self {
        let columns = vec![vec![0u64; length]; width];
        Self {
            columns,
            width,
            length,
        }
    }

    pub fn set(&mut self, column: usize, row: usize, value: u64) {
        self.columns[column][row] = value;
    }

    pub fn get(&self, column: usize, row: usize) -> u64 {
        self.columns[column][row]
    }
}

#[derive(Debug, Clone)]
pub struct LookupTables {
    pub xor_8bit: Vec<Vec<u8>>,
    pub rotation: Vec<Vec<u32>>,
    pub add_carry: Vec<Vec<u8>>,
}

impl Default for LookupTables {
    fn default() -> Self {
        Self::new()
    }
}

impl LookupTables {
    pub fn new() -> Self {
        let mut xor_8bit = vec![vec![0u8; 256]; 256];
        for (i, xor_row) in xor_8bit.iter_mut().enumerate().take(256) {
            for (j, cell) in xor_row.iter_mut().enumerate().take(256) {
                *cell = (i ^ j) as u8;
            }
        }

        let mut rotation = vec![vec![0u32; 32]; 32];
        for (value, rot_row) in rotation.iter_mut().enumerate().take(32) {
            for (shift, cell) in rot_row.iter_mut().enumerate().take(32) {
                *cell = (value as u32).rotate_right(shift as u32);
            }
        }

        let mut add_carry = vec![vec![0u8; 256]; 256];
        for (i, add_row) in add_carry.iter_mut().enumerate().take(256) {
            for (j, cell) in add_row.iter_mut().enumerate().take(256) {
                *cell = ((i + j) >> 8) as u8;
            }
        }

        Self {
            xor_8bit,
            rotation,
            add_carry,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TraceRow {
    pub blake3_state: [u32; 16],
    pub merkle_current: [u8; 32],
    pub merkle_sibling: [u8; 32],
    pub operation_selector: u32,
    pub auxiliary: [u32; 7],
}
