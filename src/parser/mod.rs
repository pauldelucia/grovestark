pub mod grovedb_executor;
pub mod proof_decoder;
pub mod proof_extractor;

use crate::error::{Error, Result};
use crate::types::{MerkleNode, ParsedProof};
use bincode;
use grovedb_costs::OperationCost;

/// Parse a GroveDB proof and extract Merkle nodes (GroveDBProof via bincode v2, big-endian)
pub fn parse_grovedb_proof(raw_proof: &[u8]) -> Result<Vec<MerkleNode>> {
    let (doc_path, key_path) = parse_grovedb_proof_full(raw_proof)?;
    let mut nodes = doc_path;
    nodes.extend(key_path);
    Ok(nodes)
}

/// Parse GroveDB proof using the new extractor for full Merkle path extraction
pub fn parse_grovedb_proof_full(raw_proof: &[u8]) -> Result<(Vec<MerkleNode>, Vec<MerkleNode>)> {
    // Decode layered GroveDB proof via bincode v2 (big-endian, no limit)
    let cfg = bincode::config::standard()
        .with_big_endian()
        .with_no_limit();
    let grovedb_proof: grovedb::operations::proof::GroveDBProof =
        bincode::decode_from_slice(raw_proof, cfg)
            .map_err(|e| Error::Parser(format!("Layered decode failed (bincode2): {}", e)))?
            .0;

    // Collect merk_proof slices per layer
    fn collect_layers(
        layer: &grovedb::operations::proof::LayerProof,
        path: &mut Vec<Vec<u8>>,
        out: &mut Vec<(Vec<Vec<u8>>, Vec<u8>)>,
    ) {
        out.push((path.clone(), layer.merk_proof.clone()));
        for (k, v) in &layer.lower_layers {
            path.push(k.clone());
            collect_layers(v, path, out);
            path.pop();
        }
    }

    let mut layers: Vec<(Vec<Vec<u8>>, Vec<u8>)> = Vec::new();
    match &grovedb_proof {
        grovedb::operations::proof::GroveDBProof::V0(v0) => {
            let mut path = Vec::new();
            collect_layers(&v0.root_layer, &mut path, &mut layers);
        }
    }

    // Helper to convert Merk Ops to MerkleNode path
    fn path_from_ops(ops: &[grovedb_merk::proofs::Op]) -> Vec<MerkleNode> {
        #[derive(Clone, Debug)]
        struct Item {
            contains_leaf: bool,
            hash: Option<[u8; 32]>,
        }
        fn push_item(stack: &mut Vec<Item>, node: &grovedb_merk::proofs::Node) {
            let contains_leaf = matches!(
                node,
                grovedb_merk::proofs::Node::KV(_, _)
                    | grovedb_merk::proofs::Node::KVHash(_)
                    | grovedb_merk::proofs::Node::KVDigest(_, _)
                    | grovedb_merk::proofs::Node::KVValueHash(_, _, _)
                    | grovedb_merk::proofs::Node::KVValueHashFeatureType(_, _, _, _)
                    | grovedb_merk::proofs::Node::KVRefValueHash(_, _, _)
            );
            let hash = if let grovedb_merk::proofs::Node::Hash(h) = node {
                Some(*h)
            } else {
                None
            };
            stack.push(Item {
                contains_leaf,
                hash,
            });
        }
        fn combine(stack: &mut Vec<Item>, left_is_child: bool, path: &mut Vec<MerkleNode>) {
            if stack.len() < 2 {
                return;
            }
            let top = stack.pop().unwrap();
            let next = stack.pop().unwrap();
            let (parent, child, attaches_left) = if left_is_child {
                (top, next, true)
            } else {
                (next, top, false)
            };
            if child.contains_leaf && !parent.contains_leaf {
                if let Some(sib_hash) = parent.hash {
                    let is_left = !attaches_left;
                    path.push(MerkleNode {
                        hash: sib_hash,
                        is_left,
                    });
                }
            } else if parent.contains_leaf && !child.contains_leaf {
                if let Some(sib_hash) = child.hash {
                    let is_left = attaches_left;
                    path.push(MerkleNode {
                        hash: sib_hash,
                        is_left,
                    });
                }
            }
            stack.push(Item {
                contains_leaf: parent.contains_leaf || child.contains_leaf,
                hash: None,
            });
        }
        let mut stack: Vec<Item> = Vec::new();
        let mut path: Vec<MerkleNode> = Vec::new();
        for op in ops {
            match op {
                grovedb_merk::proofs::Op::Push(node)
                | grovedb_merk::proofs::Op::PushInverted(node) => {
                    push_item(&mut stack, node);
                }
                grovedb_merk::proofs::Op::Parent => combine(&mut stack, true, &mut path),
                grovedb_merk::proofs::Op::Child => combine(&mut stack, false, &mut path),
                grovedb_merk::proofs::Op::ParentInverted => combine(&mut stack, false, &mut path),
                grovedb_merk::proofs::Op::ChildInverted => combine(&mut stack, true, &mut path),
            }
        }
        path
    }

    // Root layer (empty path vec) is the document path; first lower layer (if any) as key path
    let mut document_path = Vec::new();
    let mut key_path = Vec::new();
    for (layer_path_keys, merk_proof) in layers {
        let ops: Vec<_> = grovedb_merk::proofs::Decoder::new(&merk_proof)
            .filter_map(|r| r.ok())
            .collect();
        let nodes = path_from_ops(&ops);
        if layer_path_keys.is_empty() {
            document_path = nodes;
        } else if key_path.is_empty() {
            key_path = nodes;
        }
    }

    Ok((document_path, key_path))
}

/// Decode layered proof and return (document_path, key_path, state_root).
/// Note: For layered proofs, the state root is not embedded explicitly in the envelope.
/// Computing it requires full tree hashing. For now, this returns zeroed state_root
/// as a placeholder; callers relying on state_root should obtain it from the external context.
#[allow(dead_code)]
fn parse_grovedb_proof_with_root(
    raw_proof: &[u8],
) -> Result<(Vec<MerkleNode>, Vec<MerkleNode>, [u8; 32])> {
    // Decode layered proof first
    let cfg = bincode::config::standard()
        .with_big_endian()
        .with_no_limit();
    let grovedb_proof: grovedb::operations::proof::GroveDBProof =
        bincode::decode_from_slice(raw_proof, cfg)
            .map_err(|e| Error::Parser(format!("Layered decode failed (bincode2): {}", e)))?
            .0;

    // Collect ops for the root layer to recompute root hash
    let root_ops: Vec<grovedb_merk::proofs::Op> = match &grovedb_proof {
        grovedb::operations::proof::GroveDBProof::V0(v0) => {
            grovedb_merk::proofs::Decoder::new(&v0.root_layer.merk_proof)
                .filter_map(|r| r.ok())
                .collect()
        }
    };

    // Recompute root using Merk's hash functions
    fn recompute_root_from_ops(ops: &[grovedb_merk::proofs::Op]) -> [u8; 32] {
        use grovedb_merk::proofs::Node as MNode;
        use grovedb_merk::tree::{
            combine_hash, kv_digest_to_kv_hash, kv_hash, node_hash, value_hash,
        };

        #[derive(Clone)]
        struct Item {
            node: MNode,
            left: Option<[u8; 32]>,
            right: Option<[u8; 32]>,
        }

        fn compute_node_kv_hash(node: &MNode, cost: &mut OperationCost) -> [u8; 32] {
            match node {
                MNode::KV(key, value) | MNode::KVCount(key, value, _) => {
                    kv_hash(key.as_slice(), value.as_slice()).unwrap_add_cost(cost)
                }
                MNode::KVHash(kv) | MNode::KVHashCount(kv, _) => *kv,
                MNode::KVDigest(key, value_hash) | MNode::KVDigestCount(key, value_hash, _) => {
                    kv_digest_to_kv_hash(key.as_slice(), value_hash).unwrap_add_cost(cost)
                }
                MNode::KVValueHash(key, _value, value_hash)
                | MNode::KVValueHashFeatureType(key, _value, value_hash, _) => {
                    kv_digest_to_kv_hash(key.as_slice(), value_hash).unwrap_add_cost(cost)
                }
                MNode::KVRefValueHash(key, referenced_value, node_value_hash)
                | MNode::KVRefValueHashCount(key, referenced_value, node_value_hash, _) => {
                    let referenced_value_hash =
                        value_hash(referenced_value.as_slice()).unwrap_add_cost(cost);
                    let combined =
                        combine_hash(node_value_hash, &referenced_value_hash).unwrap_add_cost(cost);
                    kv_digest_to_kv_hash(key.as_slice(), &combined).unwrap_add_cost(cost)
                }
                MNode::Hash(h) => *h, // treat as complete node hash
            }
        }

        fn compute_item_hash(it: &Item, cost: &mut OperationCost) -> [u8; 32] {
            match &it.node {
                MNode::Hash(h) => *h,
                _ => {
                    let kvh = compute_node_kv_hash(&it.node, cost);
                    let left = it.left.unwrap_or([0u8; 32]);
                    let right = it.right.unwrap_or([0u8; 32]);
                    node_hash(&kvh, &left, &right).unwrap_add_cost(cost)
                }
            }
        }

        let mut cost = OperationCost::default();
        let mut stack: Vec<Item> = Vec::new();
        for op in ops {
            match op {
                grovedb_merk::proofs::Op::Push(n) | grovedb_merk::proofs::Op::PushInverted(n) => {
                    stack.push(Item {
                        node: n.clone(),
                        left: None,
                        right: None,
                    });
                }
                grovedb_merk::proofs::Op::Parent => {
                    // pop parent (top), child (next), attach child as left
                    if stack.len() >= 2 {
                        let mut parent = stack.pop().unwrap();
                        let child = stack.pop().unwrap();
                        let ch = compute_item_hash(&child, &mut cost);
                        parent.left = Some(ch);
                        stack.push(parent);
                    }
                }
                grovedb_merk::proofs::Op::Child => {
                    // pop child (top), parent (next), attach as right
                    if stack.len() >= 2 {
                        let child = stack.pop().unwrap();
                        let mut parent = stack.pop().unwrap();
                        let ch = compute_item_hash(&child, &mut cost);
                        parent.right = Some(ch);
                        stack.push(parent);
                    }
                }
                grovedb_merk::proofs::Op::ParentInverted => {
                    // like Child (right)
                    if stack.len() >= 2 {
                        let mut parent = stack.pop().unwrap();
                        let child = stack.pop().unwrap();
                        let ch = compute_item_hash(&child, &mut cost);
                        parent.right = Some(ch);
                        stack.push(parent);
                    }
                }
                grovedb_merk::proofs::Op::ChildInverted => {
                    // like Parent (left)
                    if stack.len() >= 2 {
                        let child = stack.pop().unwrap();
                        let mut parent = stack.pop().unwrap();
                        let ch = compute_item_hash(&child, &mut cost);
                        parent.left = Some(ch);
                        stack.push(parent);
                    }
                }
            }
        }
        if let Some(root) = stack.pop() {
            compute_item_hash(&root, &mut cost)
        } else {
            [0u8; 32]
        }
    }

    let state_root = recompute_root_from_ops(&root_ops);
    let (doc, key) = parse_grovedb_proof_full(raw_proof)?;
    Ok((doc, key, state_root))
}

/// Parse raw Merk operations without header (for SDK integration)
/// The SDK provides raw Merk proof operations without the state root header
pub fn parse_raw_merk_proof(raw_proof: &[u8]) -> Result<Vec<MerkleNode>> {
    // Use Merk's Decoder for raw merk proof bytes
    let ops: Vec<_> = grovedb_merk::proofs::Decoder::new(raw_proof)
        .filter_map(|r| r.ok())
        .collect();
    // Reuse the evaluator above to compute the path
    let nodes = {
        #[allow(clippy::redundant_clone)]
        let ops_ref: Vec<grovedb_merk::proofs::Op> = ops.clone();
        // inline minimal evaluator
        let mut result = Vec::new();
        let mut stack: Vec<(bool, Option<[u8; 32]>)> = Vec::new();
        for op in &ops_ref {
            match op {
                grovedb_merk::proofs::Op::Push(node)
                | grovedb_merk::proofs::Op::PushInverted(node) => {
                    let contains_leaf = matches!(
                        node,
                        grovedb_merk::proofs::Node::KV(_, _)
                            | grovedb_merk::proofs::Node::KVHash(_)
                            | grovedb_merk::proofs::Node::KVDigest(_, _)
                            | grovedb_merk::proofs::Node::KVValueHash(_, _, _)
                            | grovedb_merk::proofs::Node::KVValueHashFeatureType(_, _, _, _)
                            | grovedb_merk::proofs::Node::KVRefValueHash(_, _, _)
                    );
                    let hash = if let grovedb_merk::proofs::Node::Hash(h) = node {
                        Some(*h)
                    } else {
                        None
                    };
                    stack.push((contains_leaf, hash));
                }
                grovedb_merk::proofs::Op::Parent | grovedb_merk::proofs::Op::ChildInverted => {
                    // left child
                    if stack.len() >= 2 {
                        let top = stack.pop().unwrap();
                        let next = stack.pop().unwrap();
                        let (parent, child) = (top, next);
                        if child.0 && !parent.0 {
                            if let Some(h) = parent.1 {
                                result.push(MerkleNode {
                                    hash: h,
                                    is_left: false,
                                });
                            }
                        } else if parent.0 && !child.0 {
                            if let Some(h) = child.1 {
                                result.push(MerkleNode {
                                    hash: h,
                                    is_left: true,
                                });
                            }
                        }
                        stack.push((parent.0 || child.0, None));
                    }
                }
                grovedb_merk::proofs::Op::Child | grovedb_merk::proofs::Op::ParentInverted => {
                    // right child
                    if stack.len() >= 2 {
                        let top = stack.pop().unwrap();
                        let next = stack.pop().unwrap();
                        let (parent, child) = (next, top);
                        if child.0 && !parent.0 {
                            if let Some(h) = parent.1 {
                                result.push(MerkleNode {
                                    hash: h,
                                    is_left: true,
                                });
                            }
                        } else if parent.0 && !child.0 {
                            if let Some(h) = child.1 {
                                result.push(MerkleNode {
                                    hash: h,
                                    is_left: false,
                                });
                            }
                        }
                        stack.push((parent.0 || child.0, None));
                    }
                }
            }
        }
        result
    };
    Ok(nodes)
}

// Deprecated decoders removed to avoid confusion.

/// Parse SDK's bincode-encoded GroveDBProof format
///
/// The SDK encodes proofs with a specific structure:
/// - 2 bytes: length prefix  
/// - 32 bytes: state root hash
/// - Variable metadata bytes
/// - Merk proof operations (starting around byte 40-42)
#[cfg(any(test, feature = "sdk_test_helpers"))]
pub fn parse_sdk_grovedb_proof(encoded_proof: &[u8]) -> Result<Vec<MerkleNode>> {
    // Deterministic parser for the SDK proof binary format observed in fixtures.
    // Format:
    //   [0..1]   2-byte length prefix (ignored)
    //   [2..33]  32-byte state root (ignored here)
    //   [..]     variable metadata (ignored)
    //   [..]     merk-like ops stream where a Push is encoded as 0x01 0x20 <32 bytes>
    //            and Parent is 0x02; we extract only 32-byte hash-carrying ops.
    if encoded_proof.len() < 34 {
        return Err(Error::Parser("Proof too short for SDK format".into()));
    }

    let mut i = 34; // skip len + state root

    // Find the anchor sequence 0x02 0x01 0x20 which marks start of the first push after a parent.
    let mut start = None;
    while i + 2 < encoded_proof.len() {
        if encoded_proof[i] == 0x02 && encoded_proof[i + 1] == 0x01 && encoded_proof[i + 2] == 0x20
        {
            start = Some(i);
            break;
        }
        i += 1;
    }
    // Fallback: if not found, use first 0x01 0x20
    if start.is_none() {
        i = 34;
        while i + 1 < encoded_proof.len() {
            if encoded_proof[i] == 0x01 && encoded_proof[i + 1] == 0x20 {
                start = Some(i);
                break;
            }
            i += 1;
        }
    }
    let mut idx =
        start.ok_or_else(|| Error::Parser("Could not locate SDK merk ops start".into()))?;

    let mut nodes = Vec::new();
    let end = encoded_proof.len();
    // Linear parse with safety caps
    while idx < end && nodes.len() < 4096 {
        match encoded_proof[idx] {
            // Push variants (hash-carrying): 0x01/0x03/0x04/0x10/0x11 then 0x20 then 32 bytes
            0x01 | 0x03 | 0x04 | 0x10 | 0x11 => {
                if idx + 34 <= end && encoded_proof[idx + 1] == 0x20 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&encoded_proof[idx + 2..idx + 34]);
                    nodes.push(MerkleNode {
                        hash: h,
                        is_left: false,
                    });
                    idx += 34;
                } else {
                    // Not enough bytes or unexpected length marker; stop
                    break;
                }
            }
            // Parent marker: advance by 1
            0x02 => {
                idx += 1;
            }
            // Unknown byte: advance by 1 to avoid infinite loops
            _ => {
                idx += 1;
            }
        }
    }

    if nodes.is_empty() {
        return Err(Error::Parser("No recognizable SDK hash ops found".into()));
    }
    Ok(nodes)
}

pub struct GroveDBParser;

impl GroveDBParser {
    pub fn parse_proof(raw_proof: &[u8]) -> Result<ParsedProof> {
        // Decode layered proof and return parsed paths (production-only path)
        let cfg = bincode::config::standard()
            .with_big_endian()
            .with_no_limit();
        let (_proof, _): (grovedb::operations::proof::GroveDBProof, usize) =
            bincode::decode_from_slice(raw_proof, cfg)
                .map_err(|e| Error::Parser(format!("Layered decode failed (bincode2): {}", e)))?;

        let (document_path, key_path) = parse_grovedb_proof_full(raw_proof)?;
        Ok(ParsedProof {
            state_root: [0u8; 32],
            document_path,
            key_path,
        })
    }

    // Parse raw Merk operations is handled by parse_raw_merk_proof at module level.

    // No legacy encode/decode helpers; layered proofs only for production
}

pub struct ProofValidator;

impl ProofValidator {
    pub fn validate_parsed_proof(proof: &ParsedProof) -> Result<()> {
        if proof.document_path.is_empty() {
            return Err(Error::Parser("Empty document path".into()));
        }

        if proof.document_path.len() > 64 {
            return Err(Error::Parser("Document path too deep".into()));
        }

        if proof.key_path.len() > 64 {
            return Err(Error::Parser("Key path too deep".into()));
        }

        for node in &proof.document_path {
            if node.hash == [0u8; 32] {
                return Err(Error::Parser("Invalid null hash in document path".into()));
            }
        }

        for node in &proof.key_path {
            if node.hash == [0u8; 32] {
                return Err(Error::Parser("Invalid null hash in key path".into()));
            }
        }

        Ok(())
    }

    pub fn estimate_proof_size(parsed_proof: &ParsedProof) -> usize {
        32 + // state root
        4 +  // proof length
        (parsed_proof.document_path.len() * 33) + // document path (32 bytes hash + 1 byte direction)
        (parsed_proof.key_path.len() * 33) // key path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_validation() {
        let valid_proof = ParsedProof {
            state_root: [1u8; 32],
            document_path: vec![MerkleNode {
                hash: [2u8; 32],
                is_left: true,
            }],
            key_path: vec![],
        };

        assert!(ProofValidator::validate_parsed_proof(&valid_proof).is_ok());

        let invalid_proof = ParsedProof {
            state_root: [1u8; 32],
            document_path: vec![],
            key_path: vec![],
        };

        assert!(ProofValidator::validate_parsed_proof(&invalid_proof).is_err());
    }
}
