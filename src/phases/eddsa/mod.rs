pub mod aux_trace;
pub mod constraints;
pub mod scalar_range;
pub mod trace;
pub mod witness_augmentation;

pub use constraints::evaluate_eddsa_constraints;
pub use scalar_range::{
    compute_scalar_borrow_chain, generate_scalar_range_constraints, ED25519_GROUP_ORDER,
};
// Main EdDSA phase generation is in aux_trace::fill_eddsa_phase_with_aux
// trace.rs only exports column constants and helper functions
pub use witness_augmentation::augment_eddsa_witness;
#[cfg(test)]
pub use witness_augmentation::create_placeholder_eddsa_witness;
