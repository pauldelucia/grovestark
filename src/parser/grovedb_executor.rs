//! GroveDB proof executor utilities built on top of the official Merk decoder.
use crate::error::{Error, Result};
use crate::types::MerkleNode;
use grovedb::operations::proof::{GroveDBProof, LayerProof};
use grovedb_merk::proofs::{Decoder, Node as MerkNode, Op as MerkOp};

/// Convenience struct to carry a layer and the Grove path that led to it.
struct LayerInfo<'a> {
    path: Vec<Vec<u8>>,
    layer: &'a LayerProof,
}

/// Decode the layered GroveDB proof (bincode v2, big-endian) into its structured form.
fn decode_layered_proof(proof_bytes: &[u8]) -> Result<GroveDBProof> {
    let cfg = bincode::config::standard()
        .with_big_endian()
        .with_no_limit();

    bincode::decode_from_slice::<GroveDBProof, _>(proof_bytes, cfg)
        .map(|(proof, _)| proof)
        .map_err(|e| Error::Parser(format!("Layered decode failed (bincode2): {}", e)))
}

/// Collect every LayerProof reachable from the root along with its accumulated path keys.
fn collect_layers<'a>(
    layer: &'a LayerProof,
    path: &mut Vec<Vec<u8>>,
    out: &mut Vec<LayerInfo<'a>>,
) {
    out.push(LayerInfo {
        path: path.clone(),
        layer,
    });

    for (key, child) in &layer.lower_layers {
        path.push(key.clone());
        collect_layers(child, path, out);
        path.pop();
    }
}

/// Reconstruct a Merkle path (sibling hash + side) from Merk operations using the official enums.
fn path_from_ops(ops: &[MerkOp]) -> Vec<MerkleNode> {
    #[derive(Clone, Debug)]
    struct Item {
        contains_leaf: bool,
        hash: Option<[u8; 32]>,
    }

    let mut stack: Vec<Item> = Vec::new();
    let mut path: Vec<MerkleNode> = Vec::new();

    fn push_item(stack: &mut Vec<Item>, node: &MerkNode) {
        let contains_leaf = matches!(
            node,
            MerkNode::KV(_, _)
                | MerkNode::KVHash(_)
                | MerkNode::KVDigest(_, _)
                | MerkNode::KVValueHash(_, _, _)
                | MerkNode::KVValueHashFeatureType(_, _, _, _)
                | MerkNode::KVRefValueHash(_, _, _)
        );
        let hash = if let MerkNode::Hash(h) = node {
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
            if let Some(hash) = parent.hash {
                path.push(MerkleNode {
                    hash,
                    is_left: !attaches_left,
                });
            }
        } else if parent.contains_leaf && !child.contains_leaf {
            if let Some(hash) = child.hash {
                path.push(MerkleNode {
                    hash,
                    is_left: attaches_left,
                });
            }
        }

        stack.push(Item {
            contains_leaf: parent.contains_leaf || child.contains_leaf,
            hash: None,
        });
    }

    for op in ops {
        match op {
            MerkOp::Push(node) | MerkOp::PushInverted(node) => push_item(&mut stack, node),
            MerkOp::Parent | MerkOp::ChildInverted => combine(&mut stack, true, &mut path),
            MerkOp::Child | MerkOp::ParentInverted => combine(&mut stack, false, &mut path),
        }
    }

    path
}

/// Parse a GroveDB layered proof and extract all sibling hashes necessary for Merkle verification.
pub fn parse_grovedb_nodes(proof_bytes: &[u8]) -> Result<Vec<MerkleNode>> {
    let proof = decode_layered_proof(proof_bytes)?;

    let mut layers = Vec::new();
    let GroveDBProof::V0(v0) = &proof;
    collect_layers(&v0.root_layer, &mut Vec::new(), &mut layers);

    let mut nodes = Vec::new();
    for info in layers {
        let ops = Decoder::new(&info.layer.merk_proof)
            .map(|res| {
                res.map_err(|e| {
                    Error::Parser(format!("Failed to decode Merk proof operations: {:?}", e))
                })
            })
            .collect::<Result<Vec<MerkOp>>>()?;
        nodes.extend(path_from_ops(&ops));
    }

    Ok(nodes)
}

/// Extract the closest (deepest) 32-byte identity identifier present in the layered key proof.
pub fn extract_closest_identity_id_from_key_proof(proof_bytes: &[u8]) -> Result<[u8; 32]> {
    let proof = decode_layered_proof(proof_bytes)?;

    let mut layers = Vec::new();
    let GroveDBProof::V0(v0) = &proof;
    collect_layers(&v0.root_layer, &mut Vec::new(), &mut layers);

    let mut candidates: Vec<Vec<u8>> = Vec::new();

    for info in layers {
        // Path keys leading to this layer (ordered from root to current)
        candidates.extend(info.path.clone());

        // Keys embedded inside merk nodes for this layer
        let ops = Decoder::new(&info.layer.merk_proof)
            .map(|res| {
                res.map_err(|e| {
                    Error::Parser(format!("Failed to decode Merk proof operations: {:?}", e))
                })
            })
            .collect::<Result<Vec<MerkOp>>>()?;

        for op in ops {
            if let MerkOp::Push(node) | MerkOp::PushInverted(node) = op {
                match node {
                    MerkNode::KV(key, _)
                    | MerkNode::KVValueHash(key, _, _)
                    | MerkNode::KVValueHashFeatureType(key, _, _, _)
                    | MerkNode::KVRefValueHash(key, _, _)
                    | MerkNode::KVDigest(key, _)
                    | MerkNode::KVCount(key, _, _)
                    | MerkNode::KVRefValueHashCount(key, _, _, _)
                    | MerkNode::KVDigestCount(key, _, _) => candidates.push(key),
                    MerkNode::Hash(_) | MerkNode::KVHash(_) | MerkNode::KVHashCount(_, _) => {}
                }
            }
        }
    }

    if let Some(bytes) = candidates.iter().rev().find(|key| key.len() == 32) {
        let mut id = [0u8; 32];
        id.copy_from_slice(bytes);
        Ok(id)
    } else {
        Err(Error::InvalidInput(
            "Could not locate 32-byte identity ID in key proof (closest)".into(),
        ))
    }
}
