//! GroveVM implementation in the AIR
//!
//! This module implements GroveDB proof verification directly in the STARK proof
//! as a stack machine, according to GUIDANCE.md and GROVEVM_IMPLEMENTATION_PLAN.md

pub mod blake3_integration;
pub mod constraints;
pub mod proof_parser;
pub mod range_check;
pub mod trace;
pub mod types;

pub use constraints::GroveVMConstraints;
pub use trace::GroveVMTraceBuilder;
pub use types::*;

// Re-export main types
pub use types::{GroveVMState, Op, GROVEVM_AUX_WIDTH};
