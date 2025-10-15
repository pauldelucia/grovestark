#![allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::field_reassign_with_default,
    clippy::manual_memcpy,
    clippy::needless_range_loop,
    clippy::assign_op_pattern,
    clippy::len_zero,
    clippy::get_first,
    clippy::collapsible_if,
    clippy::for_kv_map,
    clippy::vec_init_then_push,
    clippy::nonminimal_bool,
    clippy::assertions_on_constants,
    clippy::redundant_closure,
    clippy::only_used_in_recursion,
    clippy::len_without_is_empty,
    clippy::if_same_then_else,
    clippy::needless_borrows_for_generic_args,
    dead_code,
    unexpected_cfgs
)]
//! GroveSTARK - A custom STARK prover for Dash Platform GroveDB proofs
//!
//! This library provides zero-knowledge proofs of document ownership within
//! contracts without revealing document contents or user identity.

pub mod air;
pub mod crypto;
pub mod ed25519_helpers;
pub mod error;
pub mod error_handling;
pub mod field;
pub mod layout;
pub mod parser;
pub mod phases;
pub mod prover;
pub mod resilience;
pub mod serialization;
pub mod stark_winterfell;
pub mod stark_winterfell_trace;
pub mod test_utils;
pub mod types;
pub mod utils;
pub mod validation;

pub use error::{Error, Result};
pub use prover::GroveSTARK;
pub use types::{
    BatchProof, MerkleNode, PrivateInputs, PublicInputs, PublicOutputs, STARKConfig, STARKProof,
};

// Ed25519 point conversion utilities for integration
pub use crypto::ed25519::{
    augment_witness_with_extended, decompress_ed25519_point, decompress_to_extended_limbs,
    limbs_to_bytes_le, DecompressError, ExtPointLimbs,
};

// Ed25519 helpers for Dash Evo Tool integration
pub use ed25519_helpers::{
    compressed_to_extended, compute_eddsa_hash_h, create_witness_from_platform_proofs,
    populate_witness_with_extended,
};

// Testing-only function - DO NOT USE IN PRODUCTION
#[doc(hidden)]
pub use ed25519_helpers::create_witness_from_platform_proofs_no_validation;

// GroveDB proof parsing for Dash Evo Tool integration
pub use parser::{parse_grovedb_proof, parse_raw_merk_proof, GroveDBParser};
