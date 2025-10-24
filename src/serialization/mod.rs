//! Production-grade serialization and deserialization for STARK proofs
//!
//! This module provides efficient binary serialization for all proof components
//! with proper versioning and error handling.

use crate::error::{Error, Result};
use crate::types::{FRIProof, PublicInputs, PublicOutputs, QueryRound, STARKProof};
use std::io::{Read, Write};

/// Version identifier for proof format
const PROOF_VERSION: u32 = 1;

/// Magic bytes to identify valid proof files
const PROOF_MAGIC: &[u8; 4] = b"GSPF"; // GroveSTARK Proof Format

/// Serialize a STARK proof to bytes
pub fn serialize_proof(proof: &STARKProof) -> Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(estimate_proof_size(proof));

    // Write header
    buffer.write_all(PROOF_MAGIC)?;
    buffer.write_all(&PROOF_VERSION.to_le_bytes())?;

    // Write proof components with length prefixes
    write_bytes(&mut buffer, &proof.trace_commitment)?;
    write_bytes(&mut buffer, &proof.constraint_commitment)?;

    // Write FRI proof
    serialize_fri_proof(&mut buffer, &proof.fri_proof)?;

    // Write POW nonce
    buffer.write_all(&proof.pow_nonce.to_le_bytes())?;

    // Write public inputs
    serialize_public_inputs(&mut buffer, &proof.public_inputs)?;

    // Write public outputs
    serialize_public_outputs(&mut buffer, &proof.public_outputs)?;

    // Calculate checksum on current buffer contents
    let checksum = calculate_checksum(&buffer);
    buffer.write_all(&checksum.to_le_bytes())?;

    Ok(buffer)
}

/// Deserialize a STARK proof from bytes
pub fn deserialize_proof(data: &[u8]) -> Result<STARKProof> {
    let mut reader = std::io::Cursor::new(data);

    // Verify header
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != PROOF_MAGIC {
        return Err(Error::InvalidProofFormat("Invalid magic bytes".into()));
    }

    let mut version_bytes = [0u8; 4];
    reader.read_exact(&mut version_bytes)?;
    let version = u32::from_le_bytes(version_bytes);
    if version != PROOF_VERSION {
        return Err(Error::InvalidProofFormat(format!(
            "Unsupported proof version: {} (expected {})",
            version, PROOF_VERSION
        )));
    }

    // Read proof components
    let trace_commitment = read_bytes(&mut reader)?;
    let constraint_commitment = read_bytes(&mut reader)?;

    // Read FRI proof
    let fri_proof = deserialize_fri_proof(&mut reader)?;

    // Read POW nonce
    let mut nonce_bytes = [0u8; 8];
    reader.read_exact(&mut nonce_bytes)?;
    let pow_nonce = u64::from_le_bytes(nonce_bytes);

    // Read public inputs
    let public_inputs = deserialize_public_inputs(&mut reader)?;

    // Read public outputs
    let public_outputs = deserialize_public_outputs(&mut reader)?;

    // Verify checksum
    let data_len = reader.position() as usize;
    let mut checksum_bytes = [0u8; 4];
    reader.read_exact(&mut checksum_bytes)?;
    let expected_checksum = u32::from_le_bytes(checksum_bytes);
    let actual_checksum = calculate_checksum(&data[..data_len]);

    if expected_checksum != actual_checksum {
        return Err(Error::InvalidProofFormat("Checksum mismatch".into()));
    }

    Ok(STARKProof {
        trace_commitment,
        constraint_commitment,
        fri_proof,
        pow_nonce,
        public_inputs,
        public_outputs,
    })
}

/// Serialize FRI proof component
fn serialize_fri_proof<W: Write>(writer: &mut W, fri_proof: &FRIProof) -> Result<()> {
    // Write final polynomial
    write_bytes(writer, &fri_proof.final_polynomial)?;

    // Write proof of work
    writer.write_all(&fri_proof.proof_of_work.to_le_bytes())?;

    Ok(())
}

/// Deserialize FRI proof component
fn deserialize_fri_proof<R: Read>(reader: &mut R) -> Result<FRIProof> {
    // Read number of query rounds
    let mut num_rounds_bytes = [0u8; 4];
    reader.read_exact(&mut num_rounds_bytes)?;
    let num_rounds = u32::from_le_bytes(num_rounds_bytes) as usize;

    if num_rounds > 10000 {
        return Err(Error::InvalidProofFormat(format!(
            "Too many query rounds: {}",
            num_rounds
        )));
    }

    // Read each query round
    let mut query_rounds = Vec::with_capacity(num_rounds);
    for _ in 0..num_rounds {
        query_rounds.push(deserialize_query_round(reader)?);
    }

    // Read final polynomial
    let final_polynomial = read_bytes(reader)?;

    // Read proof of work
    let mut pow_bytes = [0u8; 8];
    reader.read_exact(&mut pow_bytes)?;
    let proof_of_work = u64::from_le_bytes(pow_bytes);

    Ok(FRIProof {
        final_polynomial,
        proof_of_work,
    })
}

/// Serialize a query round
fn serialize_query_round<W: Write>(writer: &mut W, round: &QueryRound) -> Result<()> {
    // Write leaf index
    writer.write_all(&(round.leaf_index as u32).to_le_bytes())?;

    // Write number of authentication paths
    writer.write_all(&(round.authentication_paths.len() as u32).to_le_bytes())?;

    // Write each authentication path
    for path in &round.authentication_paths {
        writer.write_all(&(path.len() as u32).to_le_bytes())?;
        for hash in path {
            writer.write_all(hash)?;
        }
    }

    // Write evaluations
    writer.write_all(&(round.evaluations.len() as u32).to_le_bytes())?;
    for eval in &round.evaluations {
        write_bytes(writer, eval)?;
    }

    Ok(())
}

/// Deserialize a query round
fn deserialize_query_round<R: Read>(reader: &mut R) -> Result<QueryRound> {
    // Read leaf index
    let mut index_bytes = [0u8; 4];
    reader.read_exact(&mut index_bytes)?;
    let leaf_index = u32::from_le_bytes(index_bytes) as usize;

    // Read authentication paths
    let mut num_paths_bytes = [0u8; 4];
    reader.read_exact(&mut num_paths_bytes)?;
    let num_paths = u32::from_le_bytes(num_paths_bytes) as usize;

    if num_paths > 1000 {
        return Err(Error::InvalidProofFormat(format!(
            "Too many authentication paths: {}",
            num_paths
        )));
    }

    let mut authentication_paths = Vec::with_capacity(num_paths);
    for _ in 0..num_paths {
        let mut path_len_bytes = [0u8; 4];
        reader.read_exact(&mut path_len_bytes)?;
        let path_len = u32::from_le_bytes(path_len_bytes) as usize;

        if path_len > 100 {
            return Err(Error::InvalidProofFormat(format!(
                "Authentication path too long: {}",
                path_len
            )));
        }

        let mut path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            let mut hash = [0u8; 32];
            reader.read_exact(&mut hash)?;
            path.push(hash);
        }
        authentication_paths.push(path);
    }

    // Read evaluations
    let mut num_evals_bytes = [0u8; 4];
    reader.read_exact(&mut num_evals_bytes)?;
    let num_evals = u32::from_le_bytes(num_evals_bytes) as usize;

    if num_evals > 1000 {
        return Err(Error::InvalidProofFormat(format!(
            "Too many evaluations: {}",
            num_evals
        )));
    }

    let mut evaluations = Vec::with_capacity(num_evals);
    for _ in 0..num_evals {
        evaluations.push(read_bytes(reader)?);
    }

    Ok(QueryRound {
        leaf_index,
        authentication_paths,
        evaluations,
    })
}

/// Serialize public inputs
fn serialize_public_inputs<W: Write>(writer: &mut W, inputs: &PublicInputs) -> Result<()> {
    writer.write_all(&inputs.state_root)?;
    writer.write_all(&inputs.contract_id)?;
    writer.write_all(&inputs.message_hash)?;
    writer.write_all(&inputs.timestamp.to_le_bytes())?;
    Ok(())
}

/// Deserialize public inputs
fn deserialize_public_inputs<R: Read>(reader: &mut R) -> Result<PublicInputs> {
    let mut state_root = [0u8; 32];
    reader.read_exact(&mut state_root)?;

    let mut contract_id = [0u8; 32];
    reader.read_exact(&mut contract_id)?;

    let mut message_hash = [0u8; 32];
    reader.read_exact(&mut message_hash)?;

    let mut timestamp_bytes = [0u8; 8];
    reader.read_exact(&mut timestamp_bytes)?;
    let timestamp = u64::from_le_bytes(timestamp_bytes);

    Ok(PublicInputs {
        state_root,
        contract_id,
        message_hash,
        timestamp,
    })
}

/// Serialize public outputs
fn serialize_public_outputs<W: Write>(writer: &mut W, outputs: &PublicOutputs) -> Result<()> {
    writer.write_all(&[outputs.verified as u8])?;
    writer.write_all(&[outputs.key_security_level])?;
    writer.write_all(&outputs.proof_commitment)?;
    Ok(())
}

/// Deserialize public outputs
fn deserialize_public_outputs<R: Read>(reader: &mut R) -> Result<PublicOutputs> {
    let mut verified_byte = [0u8; 1];
    reader.read_exact(&mut verified_byte)?;
    let verified = verified_byte[0] != 0;

    let mut security_level = [0u8; 1];
    reader.read_exact(&mut security_level)?;
    let key_security_level = security_level[0];

    let mut proof_commitment = [0u8; 32];
    reader.read_exact(&mut proof_commitment)?;

    Ok(PublicOutputs {
        verified,
        key_security_level,
        proof_commitment,
    })
}

/// Write bytes with length prefix
fn write_bytes<W: Write>(writer: &mut W, data: &[u8]) -> Result<()> {
    writer.write_all(&(data.len() as u32).to_le_bytes())?;
    writer.write_all(data)?;
    Ok(())
}

/// Read bytes with length prefix
fn read_bytes<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as usize;

    if len > 10_000_000 {
        return Err(Error::InvalidProofFormat(format!(
            "Data too large: {} bytes",
            len
        )));
    }

    let mut data = vec![0u8; len];
    reader.read_exact(&mut data)?;
    Ok(data)
}

/// Calculate checksum for data integrity
fn calculate_checksum(data: &[u8]) -> u32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    (hasher.finish() & 0xFFFFFFFF) as u32
}

/// Estimate the size of a serialized proof
fn estimate_proof_size(proof: &STARKProof) -> usize {
    let mut size = 0;
    size += 4 + 4; // Magic + version
    size += 4 + proof.trace_commitment.len();
    size += 4 + proof.constraint_commitment.len();
    size += 4; // Number of query rounds
    size += 4 + proof.fri_proof.final_polynomial.len();
    size += 8; // Proof of work
    size += 8; // POW nonce
    size += 32 * 3 + 8; // Public inputs
    size += 2 + 32; // Public outputs
    size += 4; // Checksum

    size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_serialization_roundtrip() {
        let proof = create_test_proof();

        let serialized = serialize_proof(&proof).unwrap();
        let deserialized = deserialize_proof(&serialized).unwrap();

        assert_eq!(proof.trace_commitment, deserialized.trace_commitment);
        assert_eq!(
            proof.constraint_commitment,
            deserialized.constraint_commitment
        );
        assert_eq!(proof.pow_nonce, deserialized.pow_nonce);
        assert_eq!(
            proof.public_inputs.state_root,
            deserialized.public_inputs.state_root
        );
        assert_eq!(
            proof.public_outputs.verified,
            deserialized.public_outputs.verified
        );
    }

    #[test]
    fn test_invalid_magic_bytes() {
        let mut data = vec![0u8; 100];
        data[0..4].copy_from_slice(b"XXXX");

        let result = deserialize_proof(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_checksum_validation() {
        let proof = create_test_proof();
        let mut serialized = serialize_proof(&proof).unwrap();

        // Corrupt the data
        serialized[50] ^= 0xFF;

        let result = deserialize_proof(&serialized);
        assert!(result.is_err());
    }

    fn create_test_proof() -> STARKProof {
        STARKProof {
            trace_commitment: vec![1u8; 32],
            constraint_commitment: vec![2u8; 32],
            fri_proof: FRIProof {
                final_polynomial: vec![5u8; 64],
                proof_of_work: 12345,
            },
            pow_nonce: 67890,
            public_inputs: PublicInputs {
                state_root: [6u8; 32],
                contract_id: [7u8; 32],
                message_hash: [8u8; 32],
                timestamp: 1234567890,
            },
            public_outputs: PublicOutputs {
                verified: true,
                key_security_level: 2,
                proof_commitment: [9u8; 32],
            },
        }
    }
}
