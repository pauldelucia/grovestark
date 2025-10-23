use crate::Error;

/// Merk proof operation types based on grovedb encoding
#[derive(Debug, Clone, PartialEq)]
pub enum MerkOp {
    Push(MerkNode),
    PushInverted(MerkNode),
    Parent,
    Child,
    ParentInverted,
    ChildInverted,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MerkNode {
    Hash([u8; 32]),
    KVHash([u8; 32]),
    KV(Vec<u8>, Vec<u8>),
    KVValueHash(Vec<u8>, Vec<u8>, [u8; 32]),
    KVDigest(Vec<u8>, [u8; 32]),
    KVRefValueHash(Vec<u8>, Vec<u8>, [u8; 32]),
    KVValueHashFeatureType(Vec<u8>, Vec<u8>, [u8; 32], u8), // Simplified feature type
}

/// Decode a single Merk operation from bytes
pub fn decode_merk_op(input: &[u8]) -> Result<(MerkOp, usize), Error> {
    if input.is_empty() {
        return Err(Error::InvalidInput("Empty input".into()));
    }

    let op_code = input[0];
    let mut consumed = 1;

    let op = match op_code {
        // Push operations
        0x01 => {
            if input.len() < 33 {
                return Err(Error::InvalidInput(
                    "Insufficient data for Push(Hash)".into(),
                ));
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&input[1..33]);
            consumed = 33;
            MerkOp::Push(MerkNode::Hash(hash))
        }
        0x02 => {
            if input.len() < 33 {
                return Err(Error::InvalidInput(
                    "Insufficient data for Push(KVHash)".into(),
                ));
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&input[1..33]);
            consumed = 33;
            MerkOp::Push(MerkNode::KVHash(hash))
        }
        0x03 => {
            if input.len() < 2 {
                return Err(Error::InvalidInput(
                    "Insufficient data for Push(KV) key length".into(),
                ));
            }
            let key_len = input[1] as usize;
            let mut pos = 2;

            if input.len() < pos + key_len + 2 {
                return Err(Error::InvalidInput(
                    "Insufficient data for Push(KV) key".into(),
                ));
            }
            let key = input[pos..pos + key_len].to_vec();
            pos += key_len;

            let value_len = u16::from_le_bytes([input[pos], input[pos + 1]]) as usize;
            pos += 2;

            if input.len() < pos + value_len {
                return Err(Error::InvalidInput(
                    "Insufficient data for Push(KV) value".into(),
                ));
            }
            let value = input[pos..pos + value_len].to_vec();
            consumed = pos + value_len;

            MerkOp::Push(MerkNode::KV(key, value))
        }
        0x04 => {
            if input.len() < 2 {
                return Err(Error::InvalidInput(
                    "Insufficient data for Push(KVValueHash) key length".into(),
                ));
            }
            let key_len = input[1] as usize;
            let mut pos = 2;

            if input.len() < pos + key_len + 2 {
                return Err(Error::InvalidInput(
                    "Insufficient data for Push(KVValueHash) key".into(),
                ));
            }
            let key = input[pos..pos + key_len].to_vec();
            pos += key_len;

            let value_len = u16::from_le_bytes([input[pos], input[pos + 1]]) as usize;
            pos += 2;

            if input.len() < pos + value_len + 32 {
                return Err(Error::InvalidInput(
                    "Insufficient data for Push(KVValueHash)".into(),
                ));
            }
            let value = input[pos..pos + value_len].to_vec();
            pos += value_len;

            let mut hash = [0u8; 32];
            hash.copy_from_slice(&input[pos..pos + 32]);
            consumed = pos + 32;

            MerkOp::Push(MerkNode::KVValueHash(key, value, hash))
        }
        0x05 => {
            if input.len() < 2 {
                return Err(Error::InvalidInput(
                    "Insufficient data for Push(KVDigest) key length".into(),
                ));
            }
            let key_len = input[1] as usize;
            let mut pos = 2;

            if input.len() < pos + key_len + 32 {
                return Err(Error::InvalidInput(
                    "Insufficient data for Push(KVDigest)".into(),
                ));
            }
            let key = input[pos..pos + key_len].to_vec();
            pos += key_len;

            let mut hash = [0u8; 32];
            hash.copy_from_slice(&input[pos..pos + 32]);
            consumed = pos + 32;

            MerkOp::Push(MerkNode::KVDigest(key, hash))
        }
        0x06 => {
            // KVRefValueHash
            if input.len() < 2 {
                return Err(Error::InvalidInput(
                    "Insufficient data for Push(KVRefValueHash) key length".into(),
                ));
            }
            let key_len = input[1] as usize;
            let mut pos = 2;

            if input.len() < pos + key_len + 2 {
                return Err(Error::InvalidInput(
                    "Insufficient data for Push(KVRefValueHash) key".into(),
                ));
            }
            let key = input[pos..pos + key_len].to_vec();
            pos += key_len;

            let value_len = u16::from_le_bytes([input[pos], input[pos + 1]]) as usize;
            pos += 2;

            if input.len() < pos + value_len + 32 {
                return Err(Error::InvalidInput(
                    "Insufficient data for Push(KVRefValueHash)".into(),
                ));
            }
            let value = input[pos..pos + value_len].to_vec();
            pos += value_len;

            let mut hash = [0u8; 32];
            hash.copy_from_slice(&input[pos..pos + 32]);
            consumed = pos + 32;

            MerkOp::Push(MerkNode::KVRefValueHash(key, value, hash))
        }
        0x07 => {
            // KVValueHashFeatureType
            if input.len() < 2 {
                return Err(Error::InvalidInput(
                    "Insufficient data for Push(KVValueHashFeatureType) key length".into(),
                ));
            }
            let key_len = input[1] as usize;
            let mut pos = 2;

            if input.len() < pos + key_len + 2 {
                return Err(Error::InvalidInput(
                    "Insufficient data for Push(KVValueHashFeatureType) key".into(),
                ));
            }
            let key = input[pos..pos + key_len].to_vec();
            pos += key_len;

            let value_len = u16::from_le_bytes([input[pos], input[pos + 1]]) as usize;
            pos += 2;

            if input.len() < pos + value_len + 32 + 1 {
                return Err(Error::InvalidInput(
                    "Insufficient data for Push(KVValueHashFeatureType)".into(),
                ));
            }
            let value = input[pos..pos + value_len].to_vec();
            pos += value_len;

            let mut hash = [0u8; 32];
            hash.copy_from_slice(&input[pos..pos + 32]);
            pos += 32;

            let feature_type = input[pos];
            consumed = pos + 1;

            // TreeFeatureType can be multi-byte, check for SummedMerkNode
            if feature_type == 0x01 && input.len() > pos + 1 {
                // This is likely a SummedMerkNode with a value
                consumed = pos + 2; // Skip the sum value byte
            }

            MerkOp::Push(MerkNode::KVValueHashFeatureType(
                key,
                value,
                hash,
                feature_type,
            ))
        }

        // PushInverted operations (0x08-0x0e)
        0x08 => {
            if input.len() < 33 {
                return Err(Error::InvalidInput(
                    "Insufficient data for PushInverted(Hash)".into(),
                ));
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&input[1..33]);
            consumed = 33;
            MerkOp::PushInverted(MerkNode::Hash(hash))
        }

        // Parent/Child operations
        0x10 => MerkOp::Parent,
        0x11 => MerkOp::Child,
        0x12 => MerkOp::ParentInverted,
        0x13 => MerkOp::ChildInverted,

        _ => {
            return Err(Error::InvalidInput(format!(
                "Unknown operation code: 0x{:02x}",
                op_code
            )))
        }
    };

    Ok((op, consumed))
}

/// Decode all Merk operations from a proof
pub fn decode_merk_proof(proof_bytes: &[u8]) -> Result<Vec<MerkOp>, Error> {
    let mut ops = Vec::new();
    let mut pos = 0;

    while pos < proof_bytes.len() {
        let (op, consumed) = decode_merk_op(&proof_bytes[pos..])?;
        ops.push(op);
        pos += consumed;
    }

    Ok(ops)
}

/// Extract Merkle path from operations
///
/// According to GroveDB documentation:
/// - Op::Parent means the previous pushed node is the LEFT child (is_left = true)
/// - Op::Child means the previous pushed node is the RIGHT child (is_left = false)
pub fn extract_merkle_path_from_ops(ops: &[MerkOp]) -> Vec<(bool, [u8; 32])> {
    let mut path = Vec::new();
    let mut pending_node: Option<(Option<[u8; 32]>, bool)> = None;

    for op in ops {
        match op {
            MerkOp::Push(node) => {
                // Store any pending node first
                if let Some((Some(hash), is_left)) = pending_node.take() {
                    path.push((is_left, hash));
                }

                // Extract hash from this node and mark as pending
                // We don't know yet if it's left or right
                let hash = extract_hash_from_node(node);
                pending_node = Some((hash, false)); // Default to right
            }
            MerkOp::PushInverted(node) => {
                // Store any pending node first
                if let Some((Some(hash), is_left)) = pending_node.take() {
                    path.push((is_left, hash));
                }

                // Inverted nodes are always right siblings
                if let Some(hash) = extract_hash_from_node(node) {
                    // PushInverted is always a right sibling
                    pending_node = Some((Some(hash), false));
                }
            }
            MerkOp::Parent => {
                // Parent means the previous pushed node is a LEFT child
                if let Some((Some(hash), _)) = &mut pending_node {
                    path.push((true, *hash)); // LEFT sibling
                    pending_node = None;
                }
            }
            MerkOp::Child => {
                // Child means the previous pushed node is a RIGHT child
                if let Some((Some(hash), _)) = &mut pending_node {
                    path.push((false, *hash)); // RIGHT sibling
                    pending_node = None;
                }
            }
            MerkOp::ParentInverted => {
                // ParentInverted means the previous node is a RIGHT child
                if let Some((Some(hash), _)) = &mut pending_node {
                    path.push((false, *hash)); // RIGHT sibling
                    pending_node = None;
                }
            }
            MerkOp::ChildInverted => {
                // ChildInverted means the previous node is a LEFT child
                if let Some((Some(hash), _)) = &mut pending_node {
                    path.push((true, *hash)); // LEFT sibling
                    pending_node = None;
                }
            }
        }
    }

    // Add any remaining pending node (might be a leaf)
    if let Some((Some(hash), is_left)) = pending_node {
        path.push((is_left, hash));
    }

    path
}

fn extract_hash_from_node(node: &MerkNode) -> Option<[u8; 32]> {
    match node {
        MerkNode::Hash(h) | MerkNode::KVHash(h) => Some(*h),
        MerkNode::KVValueHash(_, _, h) | MerkNode::KVDigest(_, h) => Some(*h),
        MerkNode::KVRefValueHash(_, _, h) => Some(*h),
        MerkNode::KVValueHashFeatureType(_, _, h, _) => Some(*h),
        MerkNode::KV(_, _) => None, // KV nodes don't directly provide a hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_push_hash() {
        let mut data = vec![0x01];
        data.extend_from_slice(&[0x42; 32]);

        let (op, consumed) = decode_merk_op(&data).unwrap();
        assert_eq!(consumed, 33);
        assert!(matches!(op, MerkOp::Push(MerkNode::Hash(_))));
    }

    #[test]
    fn test_decode_parent() {
        let data = vec![0x10];
        let (op, consumed) = decode_merk_op(&data).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(op, MerkOp::Parent);
    }

    #[test]
    fn test_decode_proof_sequence() {
        // Simple proof with push and parent
        let mut proof = vec![0x01]; // Push Hash
        proof.extend_from_slice(&[0xAA; 32]);
        proof.push(0x10); // Parent
        proof.push(0x01); // Push Hash
        proof.extend_from_slice(&[0xBB; 32]);

        let ops = decode_merk_proof(&proof).unwrap();
        assert_eq!(ops.len(), 3);
        assert!(matches!(ops[0], MerkOp::Push(MerkNode::Hash(_))));
        assert_eq!(ops[1], MerkOp::Parent);
        assert!(matches!(ops[2], MerkOp::Push(MerkNode::Hash(_))));
    }
}
