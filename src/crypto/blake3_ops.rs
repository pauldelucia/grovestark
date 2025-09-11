use crate::field::{FieldElement, FieldOperations};
use blake3;

pub const BLAKE3_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

pub const BLAKE3_MSG_PERMUTATION: [usize; 16] =
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[derive(Debug, Clone)]
pub struct Blake3State {
    pub h: [u32; 8],
    pub v: [u32; 16],
    pub t: u64,
    pub b: u64,
    pub f: bool,
}

impl Default for Blake3State {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake3State {
    pub fn new() -> Self {
        Self {
            h: BLAKE3_IV,
            v: [0u32; 16],
            t: 0,
            b: 0,
            f: false,
        }
    }

    pub fn init_chunk(&mut self, chunk_index: u64, flags: u32) {
        self.h = BLAKE3_IV;
        self.t = 0;
        self.b = 0;
        self.f = false;

        self.h[0] ^= flags;
        if chunk_index > 0 {
            self.h[1] ^= chunk_index as u32;
            self.h[2] ^= (chunk_index >> 32) as u32;
        }
    }

    pub fn g(&mut self, a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
        self.v[a] = FieldOperations::add_mod32(self.v[a], FieldOperations::add_mod32(self.v[b], x));
        self.v[d] = FieldOperations::rotr(FieldOperations::xor(self.v[d], self.v[a]), 16);

        self.v[c] = FieldOperations::add_mod32(self.v[c], self.v[d]);
        self.v[b] = FieldOperations::rotr(FieldOperations::xor(self.v[b], self.v[c]), 12);

        self.v[a] = FieldOperations::add_mod32(self.v[a], FieldOperations::add_mod32(self.v[b], y));
        self.v[d] = FieldOperations::rotr(FieldOperations::xor(self.v[d], self.v[a]), 8);

        self.v[c] = FieldOperations::add_mod32(self.v[c], self.v[d]);
        self.v[b] = FieldOperations::rotr(FieldOperations::xor(self.v[b], self.v[c]), 7);
    }

    pub fn round(&mut self, m: &[u32; 16], r: usize) {
        let s = &BLAKE3_MSG_PERMUTATION;
        let idx = |i: usize| s[(r * 16 + i) % 16];

        self.g(0, 4, 8, 12, m[idx(0)], m[idx(1)]);
        self.g(1, 5, 9, 13, m[idx(2)], m[idx(3)]);
        self.g(2, 6, 10, 14, m[idx(4)], m[idx(5)]);
        self.g(3, 7, 11, 15, m[idx(6)], m[idx(7)]);

        self.g(0, 5, 10, 15, m[idx(8)], m[idx(9)]);
        self.g(1, 6, 11, 12, m[idx(10)], m[idx(11)]);
        self.g(2, 7, 8, 13, m[idx(12)], m[idx(13)]);
        self.g(3, 4, 9, 14, m[idx(14)], m[idx(15)]);
    }

    pub fn compress(&mut self, block: &[u8; 64], block_len: u8, flags: u32) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        for (i, &iv) in BLAKE3_IV.iter().enumerate().take(8) {
            self.v[i] = self.h[i];
            self.v[i + 8] = iv;
        }

        self.v[12] ^= self.t as u32;
        self.v[13] ^= (self.t >> 32) as u32;
        self.v[14] ^= block_len as u32;
        self.v[15] ^= flags;

        for r in 0..7 {
            self.round(&m, r);
        }

        for i in 0..8 {
            self.h[i] = FieldOperations::xor(self.h[i], self.v[i]);
            self.h[i] = FieldOperations::xor(self.h[i], self.v[i + 8]);
        }
    }
}

pub struct Blake3Hasher;

impl Blake3Hasher {
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let hash = blake3::hash(data);
        *hash.as_bytes()
    }

    pub fn hash_concat(left: &[u8], right: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(left);
        hasher.update(right);
        let hash = hasher.finalize();
        *hash.as_bytes()
    }

    pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
        let hasher = blake3::Hasher::new_keyed(key);
        let mut h = hasher.clone();
        h.update(data);
        let hash = h.finalize();
        *hash.as_bytes()
    }

    pub fn derive_key(context: &str, key_material: &[u8]) -> [u8; 32] {
        let hasher = blake3::Hasher::new_derive_key(context);
        let mut h = hasher.clone();
        h.update(key_material);
        let hash = h.finalize();
        *hash.as_bytes()
    }

    pub fn hash_to_field(data: &[u8]) -> FieldElement {
        let hash = Self::hash(data);
        FieldElement::from_bytes(&hash[..8])
    }

    pub fn multi_hash(inputs: &[&[u8]]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        for input in inputs {
            hasher.update(input);
        }
        let hash = hasher.finalize();
        *hash.as_bytes()
    }
}

pub struct Blake3Constraints;

impl Blake3Constraints {
    #[allow(clippy::too_many_arguments)]
    pub fn g_constraints(
        v_curr: &[FieldElement; 16],
        v_next: &[FieldElement; 16],
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        x: FieldElement,
        _y: FieldElement,
    ) -> Vec<FieldElement> {
        let mut constraints = Vec::new();

        let v_a_1 = v_curr[a] + v_curr[b] + x;
        constraints.push(v_next[a] - v_a_1);

        let v_d_1_xor = v_curr[d] + v_next[a];
        let v_d_1 = FieldElement::new(FieldOperations::rotr(v_d_1_xor.as_u64() as u32, 16) as u64);
        constraints.push(v_next[d] - v_d_1);

        let v_c_1 = v_curr[c] + v_next[d];
        constraints.push(v_next[c] - v_c_1);

        let v_b_1_xor = v_curr[b] + v_next[c];
        let v_b_1 = FieldElement::new(FieldOperations::rotr(v_b_1_xor.as_u64() as u32, 12) as u64);
        constraints.push(v_next[b] - v_b_1);

        constraints
    }

    pub fn round_constraints(
        state_curr: &Blake3State,
        state_next: &Blake3State,
        message: &[FieldElement; 16],
        round: usize,
    ) -> Vec<FieldElement> {
        let mut constraints = Vec::new();

        let v_curr: [FieldElement; 16] = state_curr
            .v
            .iter()
            .map(|&x| FieldElement::new(x as u64))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let v_next: [FieldElement; 16] = state_next
            .v
            .iter()
            .map(|&x| FieldElement::new(x as u64))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let s = &BLAKE3_MSG_PERMUTATION;
        let idx = |i: usize| s[(round * 16 + i) % 16];

        constraints.extend(Self::g_constraints(
            &v_curr,
            &v_next,
            0,
            4,
            8,
            12,
            message[idx(0)],
            message[idx(1)],
        ));
        constraints.extend(Self::g_constraints(
            &v_curr,
            &v_next,
            1,
            5,
            9,
            13,
            message[idx(2)],
            message[idx(3)],
        ));
        constraints.extend(Self::g_constraints(
            &v_curr,
            &v_next,
            2,
            6,
            10,
            14,
            message[idx(4)],
            message[idx(5)],
        ));
        constraints.extend(Self::g_constraints(
            &v_curr,
            &v_next,
            3,
            7,
            11,
            15,
            message[idx(6)],
            message[idx(7)],
        ));

        constraints
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hash() {
        let data = b"hello world";
        let hash = Blake3Hasher::hash(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_blake3_concat() {
        let left = b"hello";
        let right = b"world";
        let hash = Blake3Hasher::hash_concat(left, right);

        let mut combined = Vec::new();
        combined.extend_from_slice(left);
        combined.extend_from_slice(right);
        let expected = Blake3Hasher::hash(&combined);

        assert_eq!(hash, expected);
    }

    #[test]
    fn test_blake3_to_field() {
        let data = b"test data";
        let field_elem = Blake3Hasher::hash_to_field(data);
        assert!(field_elem.as_u64() > 0);
    }
}
