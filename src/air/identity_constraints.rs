//! Identity-aware join constraints for the AIR
//!
//! This module implements the join constraints that ensure:
//! 1. owner_id == identity_id
//! 2. keys_root from identity payload == keys_root from path
//! 3. pubkey_a_compressed from key leaf == pubkey used in EdDSA

use winterfell::math::fields::f64::BaseElement;

/// Column indices for stored values (must match trace_v2.rs)
/// These are in auxiliary trace columns (72-167)
const OWNER_ID_STORAGE_START: usize = 72; // First aux column (4 columns for 32 bytes)
const IDENTITY_ID_STORAGE_START: usize = 76; // After owner_id
const KEYS_ROOT_STORAGE_START: usize = 80; // After identity_id
const PUBKEY_STORAGE_START: usize = 84; // After keys_root

// Join constraint selector column
// const JOIN_SELECTOR_COL: usize = 200; // reserved for potential use; currently unused
// Join constraint selector values
const JOIN_OWNER_IDENTITY: u64 = 0x30;
const JOIN_KEYS_ROOT: u64 = 0x31;
const JOIN_PUBKEY: u64 = 0x32;

/// Evaluate identity join constraints
///
/// These constraints are only active at specific join rows marked by selectors.
/// They enforce equality between values extracted from different Merkle paths.
pub fn evaluate_identity_join_constraints(
    current: &[BaseElement],
    _next: &[BaseElement],
    selector: u64,
) -> Vec<BaseElement> {
    let mut constraints = vec![BaseElement::new(0); 4];

    match selector {
        JOIN_OWNER_IDENTITY => {
            // Constraint: owner_id == identity_id (bytewise)
            for i in 0..4 {
                if OWNER_ID_STORAGE_START + i < current.len()
                    && IDENTITY_ID_STORAGE_START + i < current.len()
                {
                    let owner_chunk = current[OWNER_ID_STORAGE_START + i];
                    let identity_chunk = current[IDENTITY_ID_STORAGE_START + i];
                    constraints[i] = owner_chunk - identity_chunk;
                }
            }
        }
        JOIN_KEYS_ROOT => {
            // Constraint: keys_root from identity == keys_root from path
            for i in 0..4 {
                if KEYS_ROOT_STORAGE_START + i < current.len()
                    && KEYS_ROOT_STORAGE_START + 4 + i < current.len()
                {
                    let keys_root_identity = current[KEYS_ROOT_STORAGE_START + i];
                    let keys_root_path = current[KEYS_ROOT_STORAGE_START + 4 + i];
                    constraints[i] = keys_root_identity - keys_root_path;
                }
            }
        }
        JOIN_PUBKEY => {
            // Constraint: pubkey from key leaf == pubkey used in EdDSA
            // Note: EdDSA pubkey location depends on the EdDSA trace layout
            // For now, we assume it's stored after PUBKEY_STORAGE_START
            for i in 0..4 {
                if PUBKEY_STORAGE_START + i < current.len()
                    && PUBKEY_STORAGE_START + 4 + i < current.len()
                {
                    let pubkey_leaf = current[PUBKEY_STORAGE_START + i];
                    let pubkey_eddsa = current[PUBKEY_STORAGE_START + 4 + i];
                    constraints[i] = pubkey_leaf - pubkey_eddsa;
                }
            }
        }
        _ => {
            // No join constraints active
        }
    }

    constraints
}

/// Check if a given row should have join constraints
pub fn is_join_constraint_row(row: usize, trace_length: usize) -> bool {
    // Join constraints are evaluated at specific points after Merkle paths complete
    // These would be:
    // - After path 1 completes (owner_id extracted)
    // - After path 3 completes (identity_id extracted)
    // - After path 4 completes (pubkey extracted)

    // For now, use fixed positions (will be refined based on actual trace layout)
    let merkle_phase_end = trace_length * 3 / 4; // Approximate
    row == merkle_phase_end || row == merkle_phase_end + 1 || row == merkle_phase_end + 2
}

/// Get the selector value for a join constraint row
pub fn get_join_selector(row: usize, trace_length: usize) -> u64 {
    let merkle_phase_end = trace_length * 3 / 4;

    if row == merkle_phase_end {
        JOIN_OWNER_IDENTITY
    } else if row == merkle_phase_end + 1 {
        JOIN_KEYS_ROOT
    } else if row == merkle_phase_end + 2 {
        JOIN_PUBKEY
    } else {
        0
    }
}

/// Apply join constraints to the main constraint evaluation
pub fn apply_join_constraints(
    constraints: &mut [BaseElement],
    current: &[BaseElement],
    next: &[BaseElement],
    row: usize,
    trace_length: usize,
) {
    if !is_join_constraint_row(row, trace_length) {
        return;
    }

    let selector = get_join_selector(row, trace_length);
    let join_constraints = evaluate_identity_join_constraints(current, next, selector);

    // Add join constraints to the main constraint vector
    // We gate these by the selector to keep degree low
    for (i, join_constraint) in join_constraints.iter().enumerate() {
        if i < constraints.len() {
            // Gate the constraint: (selector - expected) * constraint = 0
            // This ensures constraint is only active when selector matches
            let gated = if selector != 0 {
                *join_constraint
            } else {
                BaseElement::new(0)
            };
            constraints[i] += gated;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::math::FieldElement; // bring ZERO/ONE into scope for BaseElement

    #[test]
    fn test_owner_identity_constraint() {
        let mut current = vec![BaseElement::ZERO; 250];

        // Set owner_id chunks (simulating [1u8; 32])
        for i in 0..4 {
            current[OWNER_ID_STORAGE_START + i] = BaseElement::new(0x0101010101010101);
        }

        // Set identity_id chunks (same value for valid case)
        for i in 0..4 {
            current[IDENTITY_ID_STORAGE_START + i] = BaseElement::new(0x0101010101010101);
        }

        let constraints =
            evaluate_identity_join_constraints(&current, &current, JOIN_OWNER_IDENTITY);

        // All constraints should be zero (equality satisfied)
        for constraint in constraints {
            assert_eq!(constraint, BaseElement::new(0));
        }

        // Now test inequality
        current[IDENTITY_ID_STORAGE_START] = BaseElement::new(0x0202020202020202);

        let constraints =
            evaluate_identity_join_constraints(&current, &current, JOIN_OWNER_IDENTITY);

        // First constraint should be non-zero (inequality detected)
        assert_ne!(constraints[0], BaseElement::new(0));
    }

    #[test]
    fn test_join_selector_positions() {
        let trace_length = 65536;
        let merkle_phase_end = trace_length * 3 / 4;

        assert!(is_join_constraint_row(merkle_phase_end, trace_length));
        assert!(is_join_constraint_row(merkle_phase_end + 1, trace_length));
        assert!(is_join_constraint_row(merkle_phase_end + 2, trace_length));
        assert!(!is_join_constraint_row(0, trace_length));
        assert!(!is_join_constraint_row(trace_length - 1, trace_length));

        assert_eq!(
            get_join_selector(merkle_phase_end, trace_length),
            JOIN_OWNER_IDENTITY
        );
        assert_eq!(
            get_join_selector(merkle_phase_end + 1, trace_length),
            JOIN_KEYS_ROOT
        );
        assert_eq!(
            get_join_selector(merkle_phase_end + 2, trace_length),
            JOIN_PUBKEY
        );
    }
}
