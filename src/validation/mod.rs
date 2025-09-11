pub mod public_inputs;

use crate::error::{Error, Result};
use crate::types::{PrivateInputs, PublicInputs, STARKConfig};

pub use public_inputs::{
    bind_public_inputs_to_witness, compute_public_inputs_commitment,
    validate_and_lock_public_inputs,
};

/// Validate witness structure
pub fn validate_witness(witness: &PrivateInputs) -> Result<()> {
    // Check that required fields are non-zero
    if witness.private_key == [0u8; 32] {
        return Err(Error::InvalidInput(
            "Private key cannot be zero".to_string(),
        ));
    }

    if witness.signature_r == [0u8; 32] {
        return Err(Error::InvalidInput(
            "Signature R cannot be zero".to_string(),
        ));
    }

    if witness.signature_s == [0u8; 32] {
        return Err(Error::InvalidInput(
            "Signature S cannot be zero".to_string(),
        ));
    }

    // Document CBOR should not be empty
    if witness.document_cbor.is_empty() {
        return Err(Error::InvalidInput(
            "Document CBOR cannot be empty".to_string(),
        ));
    }

    Ok(())
}

/// Validate that identity-aware witness has consistent data
pub fn validate_identity_witness(witness: &PrivateInputs) -> Result<()> {
    // Allow relaxing owner/identity check in certain negative tests
    let relax = std::env::var("GS_RELAX_ID_VALIDATION").unwrap_or_default() == "1";
    if !relax && witness.owner_id != witness.identity_id {
        return Err(Error::InvalidInput(
            "Owner ID must match Identity ID for valid proof".into(),
        ));
    }

    // Check all required paths are present
    if witness.owner_id_leaf_to_doc_path.is_empty() {
        return Err(Error::InvalidInput("Missing owner_id to doc path".into()));
    }
    if witness.docroot_to_state_path.is_empty() {
        return Err(Error::InvalidInput("Missing doc to state path".into()));
    }
    if witness.identity_leaf_to_state_path.is_empty() {
        return Err(Error::InvalidInput("Missing identity to state path".into()));
    }
    if witness.key_leaf_to_keysroot_path.is_empty() {
        return Err(Error::InvalidInput("Missing key to keys_root path".into()));
    }

    // Check key usage tag is valid
    if witness.key_usage_tag == [0u8; 16] {
        return Err(Error::InvalidInput("Invalid key usage tag".into()));
    }

    // Check public key is non-zero
    if witness.pubkey_a_compressed == [0u8; 32] {
        return Err(Error::InvalidInput("Invalid public key".into()));
    }

    Ok(())
}

/// Validate public inputs
pub fn validate_public_inputs(public: &PublicInputs) -> Result<()> {
    validate_and_lock_public_inputs(public)
}

/// Validate STARK configuration
pub fn validate_config(config: &STARKConfig) -> Result<()> {
    // Check expansion factor is power of 2
    if !config.expansion_factor.is_power_of_two() {
        return Err(Error::InvalidInput(
            "Expansion factor must be power of 2".to_string(),
        ));
    }

    // Check folding factor
    if ![2, 4, 8, 16].contains(&config.folding_factor) {
        return Err(Error::InvalidInput(
            "Folding factor must be 2, 4, 8, or 16".to_string(),
        ));
    }

    // Check trace length
    if !config.trace_length.is_power_of_two() {
        return Err(Error::InvalidInput(
            "Trace length must be power of 2".to_string(),
        ));
    }

    // Enforce production guardrails (release builds). Allow opt-out via env for tooling.
    #[cfg(not(test))]
    {
        let allow_weak = std::env::var("GS_ALLOW_WEAK_PARAMS").unwrap_or_default() == "1";
        if !allow_weak {
            const MIN_EXPANSION_FACTOR: usize = 16;
            const MIN_NUM_QUERIES: usize = 48;
            const MIN_FOLDING_FACTOR: usize = 4;

            if config.expansion_factor < MIN_EXPANSION_FACTOR {
                return Err(Error::InvalidInput(format!(
                    "Expansion factor too low for production: {} < {}",
                    config.expansion_factor, MIN_EXPANSION_FACTOR
                )));
            }
            if config.num_queries < MIN_NUM_QUERIES {
                return Err(Error::InvalidInput(format!(
                    "Number of queries too low for production: {} < {}",
                    config.num_queries, MIN_NUM_QUERIES
                )));
            }
            if config.folding_factor < MIN_FOLDING_FACTOR {
                return Err(Error::InvalidInput(format!(
                    "Folding factor too low for production: {} < {}",
                    config.folding_factor, MIN_FOLDING_FACTOR
                )));
            }
        }
    }

    Ok(())
}
