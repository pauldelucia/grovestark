use crate::crypto::blake3_ops::Blake3Hasher;
use crate::error::{Error, Result};
use crate::field::FieldElement;
use crate::types::MerkleNode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
    nodes: Vec<Vec<[u8; 32]>>,
    height: usize,
}

impl MerkleTree {
    pub fn new(leaves: Vec<[u8; 32]>) -> Result<Self> {
        if leaves.is_empty() {
            return Err(Error::MerkleTree(
                "Cannot create tree with no leaves".into(),
            ));
        }

        let mut padded_leaves = leaves.clone();
        let next_power_of_two = padded_leaves.len().next_power_of_two();

        while padded_leaves.len() < next_power_of_two {
            padded_leaves.push([0u8; 32]);
        }

        let height = (next_power_of_two as f64).log2() as usize;
        let mut nodes = vec![padded_leaves.clone()];

        for level in 0..height {
            let current_level = &nodes[level];
            let mut next_level = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    [0u8; 32]
                };

                let parent = Blake3Hasher::hash_concat(&left, &right);
                next_level.push(parent);
            }

            nodes.push(next_level);
        }

        Ok(Self {
            leaves: padded_leaves,
            nodes,
            height,
        })
    }

    pub fn root(&self) -> [u8; 32] {
        if self.height == 0 {
            self.leaves[0]
        } else {
            self.nodes[self.height][0]
        }
    }

    pub fn get_proof(&self, leaf_index: usize) -> Result<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return Err(Error::MerkleTree("Leaf index out of bounds".into()));
        }

        let mut path = Vec::new();
        let mut index = leaf_index;

        for level in 0..self.height {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            let sibling = if sibling_index < self.nodes[level].len() {
                self.nodes[level][sibling_index]
            } else {
                [0u8; 32]
            };

            path.push(MerkleNode {
                hash: sibling,
                is_left: index % 2 == 1,
            });

            index /= 2;
        }

        Ok(MerkleProof {
            leaf: self.leaves[leaf_index],
            path,
            root: self.root(),
        })
    }

    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut current = proof.leaf;

        for node in &proof.path {
            current = if node.is_left {
                Blake3Hasher::hash_concat(&node.hash, &current)
            } else {
                Blake3Hasher::hash_concat(&current, &node.hash)
            };
        }

        current == proof.root
    }

    pub fn batch_proof(&self, indices: &[usize]) -> Result<BatchMerkleProof> {
        let mut proofs = Vec::new();

        for &index in indices {
            proofs.push(self.get_proof(index)?);
        }

        Ok(BatchMerkleProof {
            proofs,
            root: self.root(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf: [u8; 32],
    pub path: Vec<MerkleNode>,
    pub root: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchMerkleProof {
    pub proofs: Vec<MerkleProof>,
    pub root: [u8; 32],
}

pub struct MerkleConstraints;

impl MerkleConstraints {
    pub fn step_constraint(
        leaf: &[FieldElement; 32],
        sibling: &[FieldElement; 32],
        is_left: bool,
        parent: &[FieldElement; 32],
    ) -> Vec<FieldElement> {
        let mut constraints = Vec::new();

        let computed = if is_left {
            Self::hash_constraint(sibling, leaf)
        } else {
            Self::hash_constraint(leaf, sibling)
        };

        for i in 0..32 {
            constraints.push(parent[i] - computed[i]);
        }

        constraints
    }

    pub fn hash_constraint(
        left: &[FieldElement; 32],
        right: &[FieldElement; 32],
    ) -> [FieldElement; 32] {
        let mut left_bytes = [0u8; 32];
        let mut right_bytes = [0u8; 32];

        for i in 0..32 {
            left_bytes[i] = left[i].as_u64() as u8;
            right_bytes[i] = right[i].as_u64() as u8;
        }

        let hash = Blake3Hasher::hash_concat(&left_bytes, &right_bytes);

        let mut result = [FieldElement::ZERO; 32];
        for i in 0..32 {
            result[i] = FieldElement::new(hash[i] as u64);
        }

        result
    }

    pub fn path_constraints(
        leaf: &[FieldElement; 32],
        path: &[(MerkleNode, bool)],
        root: &[FieldElement; 32],
    ) -> Vec<FieldElement> {
        let mut constraints = Vec::new();
        let mut current = *leaf;

        for (node, is_current_left) in path {
            let sibling: [FieldElement; 32] = node
                .hash
                .iter()
                .map(|&b| FieldElement::new(b as u64))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            let parent = if *is_current_left {
                Self::hash_constraint(&current, &sibling)
            } else {
                Self::hash_constraint(&sibling, &current)
            };

            current = parent;
        }

        for i in 0..32 {
            constraints.push(root[i] - current[i]);
        }

        constraints
    }
}

pub struct CompressedMerkleProof {
    pub leaf_indices: Vec<u32>,
    pub hashes: Vec<[u8; 32]>,
    pub directions: Vec<bool>,
}

impl CompressedMerkleProof {
    pub fn from_proofs(proofs: &[MerkleProof]) -> Self {
        let mut leaf_indices = Vec::new();
        let mut hashes = Vec::new();
        let mut directions = Vec::new();
        let mut seen_hashes = std::collections::HashSet::new();

        for (idx, proof) in proofs.iter().enumerate() {
            leaf_indices.push(idx as u32);

            for node in &proof.path {
                if seen_hashes.insert(node.hash) {
                    hashes.push(node.hash);
                }
                directions.push(node.is_left);
            }
        }

        Self {
            leaf_indices,
            hashes,
            directions,
        }
    }

    pub fn size_bytes(&self) -> usize {
        self.leaf_indices.len() * 4 + self.hashes.len() * 32 + self.directions.len().div_ceil(8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_creation() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves).unwrap();
        assert_eq!(tree.height, 2);
        assert_eq!(tree.leaves.len(), 4);
    }

    #[test]
    fn test_merkle_proof_verification() {
        let leaves = vec![
            Blake3Hasher::hash(b"leaf1"),
            Blake3Hasher::hash(b"leaf2"),
            Blake3Hasher::hash(b"leaf3"),
            Blake3Hasher::hash(b"leaf4"),
        ];

        let tree = MerkleTree::new(leaves.clone()).unwrap();

        for i in 0..leaves.len() {
            let proof = tree.get_proof(i).unwrap();
            assert!(MerkleTree::verify_proof(&proof));
            assert_eq!(proof.leaf, leaves[i]);
            assert_eq!(proof.root, tree.root());
        }
    }

    #[test]
    fn test_batch_proof() {
        let leaves = vec![
            Blake3Hasher::hash(b"a"),
            Blake3Hasher::hash(b"b"),
            Blake3Hasher::hash(b"c"),
            Blake3Hasher::hash(b"d"),
            Blake3Hasher::hash(b"e"),
            Blake3Hasher::hash(b"f"),
            Blake3Hasher::hash(b"g"),
            Blake3Hasher::hash(b"h"),
        ];

        let tree = MerkleTree::new(leaves).unwrap();
        let batch_proof = tree.batch_proof(&[0, 3, 7]).unwrap();

        assert_eq!(batch_proof.proofs.len(), 3);
        for proof in &batch_proof.proofs {
            assert!(MerkleTree::verify_proof(proof));
        }
    }
}
