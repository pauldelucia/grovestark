//! GroveVM types and constants

use winterfell::math::fields::f64::BaseElement;

// ===== Column Layout for GroveVM Auxiliary Trace =====
// Per GROVEVM_IMPLEMENTATION_PLAN.md

// Opcode one-hot encoding (4 columns)
pub const OP_PUSH_H: usize = 0; // Push hash
pub const OP_PUSH_KV: usize = 1; // Push KV hash
pub const OP_PARENT: usize = 2; // Parent operation
pub const OP_CHILD: usize = 3; // Child operation

// Control columns
pub const SP: usize = 4; // Stack pointer [0..D_MAX]
pub const TP: usize = 5; // Tape cursor

// Push tape input (8 u32 limbs for hash)
pub const PUSH_HASH_START: usize = 6;
pub const PUSH_HASH_END: usize = 14; // 6..14 = 8 limbs

// Stack configuration
pub const STACK_START: usize = 14;
pub const D_MAX: usize = 5; // Reduced stack depth to fit in 255 column limit
pub const LIMBS_PER_HASH: usize = 8; // 8 u32 limbs = 256 bits

// Total auxiliary columns for GroveVM
pub const GROVEVM_AUX_WIDTH: usize = STACK_START + (D_MAX * LIMBS_PER_HASH); // 14 + (5 * 8) = 54

// ===== Operation Types =====
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    PushHash,   // 0x01 - Push hash to stack
    PushKvHash, // 0x02 - Push KV hash to stack
    Parent,     // 0x10 - Parent operation (merge top 2 as left child)
    Child,      // 0x11 - Child operation (merge top 2 as right child)
}

impl Op {
    /// Parse operation code from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Op::PushHash),
            0x02 => Some(Op::PushKvHash),
            0x10 => Some(Op::Parent),
            0x11 => Some(Op::Child),
            _ => None,
        }
    }

    /// Get the opcode byte value
    pub fn to_byte(&self) -> u8 {
        match self {
            Op::PushHash => 0x01,
            Op::PushKvHash => 0x02,
            Op::Parent => 0x10,
            Op::Child => 0x11,
        }
    }
}

// ===== Stack State =====
#[derive(Debug, Clone)]
pub struct GroveVMState {
    pub stack: Vec<[u8; 32]>,     // Stack of 32-byte hashes
    pub sp: usize,                // Stack pointer
    pub tp: usize,                // Tape pointer
    pub operations: Vec<Op>,      // Operations to execute
    pub push_tape: Vec<[u8; 32]>, // Hashes to push (from proof)
}

impl Default for GroveVMState {
    fn default() -> Self {
        Self {
            stack: vec![[0u8; 32]; D_MAX],
            sp: 0,
            tp: 0,
            operations: Vec::new(),
            push_tape: Vec::new(),
        }
    }
}

impl GroveVMState {
    /// Create a new GroveVM state from operations and push tape
    pub fn new(operations: Vec<Op>, push_tape: Vec<[u8; 32]>) -> Self {
        Self {
            stack: vec![[0u8; 32]; D_MAX],
            sp: 0,
            tp: 0,
            operations,
            push_tape,
        }
    }

    /// Execute one operation
    pub fn execute_op(&mut self, op: Op) -> Result<(), String> {
        match op {
            Op::PushHash | Op::PushKvHash => {
                if self.sp >= D_MAX {
                    return Err("Stack overflow".into());
                }
                if self.tp >= self.push_tape.len() {
                    return Err("Tape underflow".into());
                }

                self.stack[self.sp] = self.push_tape[self.tp];
                self.sp += 1;
                self.tp += 1;
                Ok(())
            }
            Op::Parent | Op::Child => {
                if self.sp < 2 {
                    return Err("Stack underflow".into());
                }

                let left = self.stack[self.sp - 2];
                let right = self.stack[self.sp - 1];

                // Compute BLAKE3 hash of concatenation
                let concat = if op == Op::Child {
                    [right, left].concat()
                } else {
                    [left, right].concat()
                };

                let result = blake3::hash(&concat);
                self.stack[self.sp - 2] = result.into();
                self.sp -= 1;
                Ok(())
            }
        }
    }

    /// Get the final stack root (should be single element)
    pub fn get_root(&self) -> Option<[u8; 32]> {
        if self.sp == 1 {
            Some(self.stack[0])
        } else {
            None
        }
    }
}

// ===== Helper Functions =====

/// Convert a 32-byte hash to 8 u32 limbs (little-endian)
pub fn hash_to_limbs(hash: &[u8; 32]) -> [u32; 8] {
    let mut limbs = [0u32; 8];
    for (i, chunk) in hash.chunks(4).enumerate() {
        limbs[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    limbs
}

/// Convert 8 u32 limbs back to a 32-byte hash
pub fn limbs_to_hash(limbs: &[u32; 8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    for (i, &limb) in limbs.iter().enumerate() {
        let bytes = limb.to_le_bytes();
        hash[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }
    hash
}

/// Convert limbs to BaseElement array
pub fn limbs_to_elements(limbs: &[u32; 8]) -> [BaseElement; 8] {
    use winterfell::math::FieldElement;
    let mut elements = [BaseElement::ZERO; 8];
    for (i, &limb) in limbs.iter().enumerate() {
        elements[i] = BaseElement::new(limb as u64);
    }
    elements
}

/// Compute deterministic gamma for lane packing
/// Per GROVEVM_IMPLEMENTATION_PLAN.md
pub fn compute_deterministic_gamma(
    domain_size: usize,
    lde_factor: usize,
    ce_factor: usize,
    root: &[u8; 32],
) -> BaseElement {
    use blake3::Hasher;

    let mut hasher = Hasher::new();
    hasher.update(&domain_size.to_le_bytes());
    hasher.update(&lde_factor.to_le_bytes());
    hasher.update(&ce_factor.to_le_bytes());
    hasher.update(b"GroveVM_v1"); // AIR fingerprint
    hasher.update(root);

    let hash = hasher.finalize();
    // Convert to field element (reduce modulo field prime)
    // Take first 8 bytes and interpret as u64
    let value = u64::from_le_bytes([
        hash.as_bytes()[0],
        hash.as_bytes()[1],
        hash.as_bytes()[2],
        hash.as_bytes()[3],
        hash.as_bytes()[4],
        hash.as_bytes()[5],
        hash.as_bytes()[6],
        hash.as_bytes()[7],
    ]);

    // Goldilocks field modulus is 2^64 - 2^32 + 1
    // Since value < 2^64, we just need to ensure it's not exactly 2^64 - 2^32 + 1
    BaseElement::new(value)
}
