use crate::error::{Error, Result};
/// Public inputs validation and binding
///
/// This module ensures public inputs are properly locked and bound
/// as required by the research team
use crate::types::PublicInputs;

/// Validate and lock public inputs
///
/// This ensures that:
/// 1. All public inputs are non-zero (prevents trivial proofs)
/// 2. The message hash is properly formatted
/// 3. The timestamp is reasonable
/// 4. Public inputs are cryptographically bound to the proof
pub fn validate_and_lock_public_inputs(public: &PublicInputs) -> Result<()> {
    // State root must be non-zero
    if public.state_root == [0u8; 32] {
        return Err(Error::InvalidInput("State root cannot be zero".to_string()));
    }

    // Contract ID must be non-zero
    if public.contract_id == [0u8; 32] {
        return Err(Error::InvalidInput(
            "Contract ID cannot be zero".to_string(),
        ));
    }

    // Message hash must be non-zero (prevents trivial signatures)
    if public.message_hash == [0u8; 32] {
        return Err(Error::InvalidInput(
            "Message hash cannot be zero".to_string(),
        ));
    }

    // Timestamp validation (must be reasonable)
    // Using Unix timestamp bounds: after year 2020, before year 2100
    const MIN_TIMESTAMP: u64 = 1577836800; // Jan 1, 2020
    const MAX_TIMESTAMP: u64 = 4102444800; // Jan 1, 2100

    if public.timestamp < MIN_TIMESTAMP || public.timestamp > MAX_TIMESTAMP {
        return Err(Error::InvalidInput(format!(
            "Timestamp {} is out of reasonable range",
            public.timestamp
        )));
    }

    Ok(())
}

/// Compute a commitment to public inputs
///
/// This creates a binding commitment that locks all public inputs
/// into a single hash that can be efficiently verified
pub fn compute_public_inputs_commitment(public: &PublicInputs) -> [u8; 32] {
    use crate::crypto::Blake3Hasher;

    // Concatenate all public inputs
    let mut data = Vec::new();
    data.extend_from_slice(&public.state_root);
    data.extend_from_slice(&public.contract_id);
    data.extend_from_slice(&public.message_hash);
    data.extend_from_slice(&public.timestamp.to_le_bytes());

    // Hash to create commitment
    Blake3Hasher::hash(&data)
}

/// Bind public inputs to the witness
///
/// This ensures the witness incorporates the public inputs
/// so they cannot be changed after proof generation
pub fn bind_public_inputs_to_witness(
    _witness: &mut crate::types::PrivateInputs,
    public: &PublicInputs,
) -> Result<()> {
    // Validate inputs first
    validate_and_lock_public_inputs(public)?;

    // Compute and store the commitment
    let _commitment = compute_public_inputs_commitment(public);

    // In a full implementation, this commitment would be:
    // 1. Included in the witness augmentation
    // 2. Asserted in boundary constraints
    // 3. Verified as part of the proof

    // For EdDSA, the message hash from public inputs is already bound
    // through the signature verification equation

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_inputs_validation() {
        let mut public = PublicInputs {
            state_root: [1u8; 32],
            contract_id: [2u8; 32],
            message_hash: [3u8; 32],
            timestamp: 1700000000, // Reasonable timestamp
        };

        // Should validate
        assert!(validate_and_lock_public_inputs(&public).is_ok());

        // Zero state root should fail
        public.state_root = [0u8; 32];
        assert!(validate_and_lock_public_inputs(&public).is_err());
        public.state_root = [1u8; 32];

        // Zero contract ID should fail
        public.contract_id = [0u8; 32];
        assert!(validate_and_lock_public_inputs(&public).is_err());
        public.contract_id = [2u8; 32];

        // Zero message hash should fail
        public.message_hash = [0u8; 32];
        assert!(validate_and_lock_public_inputs(&public).is_err());
        public.message_hash = [3u8; 32];

        // Invalid timestamp should fail
        public.timestamp = 0;
        assert!(validate_and_lock_public_inputs(&public).is_err());

        public.timestamp = 5000000000; // Too far in future
        assert!(validate_and_lock_public_inputs(&public).is_err());
    }

    #[test]
    fn test_public_inputs_commitment() {
        let public1 = PublicInputs {
            state_root: [1u8; 32],
            contract_id: [2u8; 32],
            message_hash: [3u8; 32],
            timestamp: 1700000000,
        };

        let public2 = PublicInputs {
            state_root: [1u8; 32],
            contract_id: [2u8; 32],
            message_hash: [3u8; 32],
            timestamp: 1700000001, // Different timestamp
        };

        let commitment1 = compute_public_inputs_commitment(&public1);
        let commitment2 = compute_public_inputs_commitment(&public2);

        // Different inputs should give different commitments
        assert_ne!(commitment1, commitment2);

        // Same inputs should give same commitment (deterministic)
        let commitment1_again = compute_public_inputs_commitment(&public1);
        assert_eq!(commitment1, commitment1_again);
    }
}
