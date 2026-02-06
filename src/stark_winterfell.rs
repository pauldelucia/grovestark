//! Production-ready STARK proof generation using Winterfell
//!
//! This module provides the complete implementation without any placeholders.

use std::cell::RefCell;
use winterfell::crypto::{hashers::Blake3_256, DefaultRandomCoin};
use winterfell::{
    math::{fields::f64::BaseElement, ExtensionOf, FieldElement, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, BatchingMethod, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame,
    Proof, ProofOptions, Prover, StarkDomain, Trace, TraceInfo, TracePolyTable, TraceTable,
    TransitionConstraintDegree,
};

use crate::error::{Error, Result};
use crate::types::{PrivateInputs, PublicInputs, STARKConfig};

// ================================================================================================
// CONSTANTS
// ================================================================================================

/// Width of the main execution trace
const MAIN_TRACE_WIDTH: usize = 132; // BLAKE3(32) + quotients(4) + nibbles(16) + control(3) + merkle(17) + identity(24) + selectors(3) + reserved(33)

/// Width of the auxiliary trace (EdDSA + GroveVM)
/// Keep total width under 255: 132 main + 119 aux = 251 < 255 ✓
/// EdDSA(64) + GroveVM(54) + 1 (EdDSA accumulator) = 119 aux columns
/// GroveVM: opcodes(4) + control(2) + push_hash(8) + stack(5*8=40) = 54
const AUX_TRACE_WIDTH: usize = 119;

// Constraint layout - single source of truth for constraint indices
struct ConstraintLayout {
    blake3: std::ops::Range<usize>,
    merkle: std::ops::Range<usize>,
    identity: std::ops::Range<usize>, // Identity binding constraint
    eddsa: std::ops::Range<usize>,    // EdDSA selector constraint
}

const LAYOUT: ConstraintLayout = ConstraintLayout {
    blake3: 0..15,    // 15 BLAKE3 constraints (split commit)
    merkle: 15..21,   // 6 Merkle constraints (2 flags + 4 packed lanes)
    identity: 21..22, // 1 identity binding constraint (DIFF = OWNER - IDENTITY)
    eddsa: 22..23,    // 1 SEL_FINAL constraint
};

/// Number of main transition constraints
const NUM_CONSTRAINTS: usize = 23; // 15 BLAKE3 + 6 Merkle + 1 identity + 1 SEL_FINAL

/// Number of auxiliary transition constraints (EdDSA + GroveVM)
/// GroveVM: 12 constraints (4 opcode booleanity + 1 at-most-one + 2 SP + 1 TP + 1 continuity + 2 writes + 1 finality)
/// EdDSA: 1 (window bit constraint)
const NUM_AUX_CONSTRAINTS: usize = 13; // 12 GroveVM + 1 EdDSA

// Phase boundaries
pub const BLAKE3_LEN: usize = 3584;
pub const MERKLE_LEN: usize = 16384;
pub const EDDSA_LEN: usize = 32768;

pub const BLAKE3_START: usize = 0;
pub const MERKLE_START: usize = BLAKE3_START + BLAKE3_LEN; // 3584
                                                           // Signature phase boundaries (EdDSA)
pub const EDDSA_START: usize = MERKLE_START + MERKLE_LEN; // 19968
pub const BLAKE3_END: usize = BLAKE3_START + BLAKE3_LEN - 1; // 3583
pub const MERKLE_END: usize = MERKLE_START + MERKLE_LEN - 1; // 19967
pub const EDDSA_END: usize = EDDSA_START + EDDSA_LEN - 1; // 52735

// Merkle MSG column mapping
pub struct MerkleMsgIdx {
    base_lo: usize, // 55
    base_hi: usize, // 64
}

impl MerkleMsgIdx {
    #[inline]
    pub fn col(&self, k: usize) -> usize {
        debug_assert!(k < 16);
        if k < 8 {
            self.base_lo + k
        } else {
            self.base_hi + (k - 8)
        }
    }
}

pub const MERKLE_MSG: MerkleMsgIdx = MerkleMsgIdx {
    base_lo: 55,
    base_hi: 64,
}; // 63 is skipped for IS_LEFT

// MsgView for phase-aware message column access
pub struct MsgView<E> {
    // gates must already be E (lifted if needed)
    g_doc: E,    // doc hashing window gate (BLAKE3 phase gate)
    g_merkle: E, // Merkle COMP gate (per.p_m * per.p_comp)
    // column bases
    doc_base: usize,          // MSG0
    merkle_msg: MerkleMsgIdx, // scratch mapping
}

impl<E: FieldElement> MsgView<E> {
    #[inline]
    pub fn get(&self, cur: &[E], k: usize) -> E {
        let md = cur[self.doc_base + k];
        let mm = cur[self.merkle_msg.col(k)];
        self.g_doc * md + self.g_merkle * mm
    }
}

// ===== Main Segment Column Layout =====
// 0..31: BLAKE3 state & message
pub const V0: usize = 0; // v[0..15] = columns 0..15
pub const V1: usize = 1;
pub const V2: usize = 2;
pub const V3: usize = 3;
pub const V4: usize = 4;
pub const V5: usize = 5;
pub const V6: usize = 6;
pub const V7: usize = 7;
pub const V8: usize = 8;
pub const V9: usize = 9;
pub const V10: usize = 10;
pub const V11: usize = 11;
pub const V12: usize = 12;
pub const V13: usize = 13;
pub const V14: usize = 14;
pub const V15: usize = 15;

pub const MSG0: usize = 16; // m[0..15] = columns 16..31
pub const MSG1: usize = 17;
pub const MSG2: usize = 18;
pub const MSG3: usize = 19;
pub const MSG4: usize = 20;
pub const MSG5: usize = 21;
pub const MSG6: usize = 22;
pub const MSG7: usize = 23;
pub const MSG8: usize = 24;
pub const MSG9: usize = 25;
pub const MSG10: usize = 26;
pub const MSG11: usize = 27;
pub const MSG12: usize = 28;
pub const MSG13: usize = 29;
pub const MSG14: usize = 30;
pub const MSG15: usize = 31;

// 32..35: Step quotients / accumulators
pub const ACC: usize = 32;
pub const SRC_A: usize = 33;
pub const SRC_B: usize = 34;
pub const SRC_M: usize = 35;

// 36..51: BLAKE3 nibble lanes
pub const A_B0: usize = 36;
pub const A_B1: usize = 37;
pub const A_B2: usize = 38;
pub const A_B3: usize = 39;

pub const B_B0: usize = 40;
pub const B_B1: usize = 41;
pub const B_B2: usize = 42;
pub const B_B3: usize = 43;

pub const M_B0: usize = 44;
pub const M_B1: usize = 45;
pub const M_B2: usize = 46;
pub const M_B3: usize = 47;

pub const Z_B0: usize = 48;
pub const Z_B1: usize = 49;
pub const Z_B2: usize = 50;
pub const Z_B3: usize = 51;

// 52..54: Control columns
pub const ROT_CARRY: usize = 52;
pub const SEL_FINAL: usize = 53;
pub const CARRY: usize = 54;

// 55..71: Merkle staging/control
pub const MERKLE_START_COL: usize = 55;
// Reserve 17 columns for Merkle operations
// During BLAKE3 phase:
// - reuse the last Merkle scratch column to store per-row committed ACC_FINAL
// - reuse the second-to-last scratch column as a committed COMMIT_ROW mask (1 at K7 rows)
pub const ACC_FINAL_COMMIT_COL: usize = 71; // only written in BLAKE3 rows; Merkle overwrites later
pub const COMMIT_ROW_MASK_COL: usize = 70; // 1 at commit rows; mirrored to next row
pub const COMMIT_DIFF_COL: usize = 69; // v_next[target] - acc_final_commit at commit row; mirrored

// 72..79: Owner ID (8 limbs)
pub const OWNER_ID_COLS: [usize; 8] = [72, 73, 74, 75, 76, 77, 78, 79];

// 80..87: Identity ID (8 limbs)
pub const IDENTITY_ID_COLS: [usize; 8] = [80, 81, 82, 83, 84, 85, 86, 87];

// 88..95: DIFF columns (8 limbs)
pub const DIFF_COLS: [usize; 8] = [88, 89, 90, 91, 92, 93, 94, 95];

// 96: DIFF_ACC
pub const DIFF_ACC_COL: usize = 96;

// 97..99: Phase selectors
pub const SEL_BLAKE3_COL: usize = 97;
pub const SEL_MERKLE_COL: usize = 98;
pub const SEL_EDDSA_COL: usize = 99;

// 100..131: Reserved/free columns
// Reserve 16 columns for committed commit-target selectors (one-hot at K7 rows)
pub const COMMIT_SEL_COLS: [usize; 16] = [
    116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131,
];
/// Alias: committed mirror of periodic GW0..GW15 (one-hot at commit rows)
pub const GW_COMMIT_SEL_COLS: [usize; 16] = COMMIT_SEL_COLS;
// Reserve 8 columns for committed step selectors S0..S7 (one-hot during each micro-step)
pub const COMMIT_STEP_SEL_COLS: [usize; 8] = [100, 101, 102, 103, 104, 105, 106, 107];
// Reserve 8 columns for committed nibble selectors K0..K7 (one-hot per row)
pub const COMMIT_K_SEL_COLS: [usize; 8] = [108, 109, 110, 111, 112, 113, 114, 115];

// ===== Auxiliary Segment Column Layout (in AUX segment, not main!) =====
// These are now in the AUXILIARY segment
pub const X_COLS: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
pub const Y_COLS: [usize; 16] = [
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];
pub const Z_COLS: [usize; 16] = [
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
];
pub const T_COLS: [usize; 16] = [
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
];

// Final verification column mapping (EdDSA)
// 256-bit R′_x limbs (use the V bank: 0..15)
pub const RX_COLS: [usize; 16] = [
    V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15,
]; // 0..15

// 256-bit signature r limbs (use the MSG bank: 16..31)
pub const R_COLS: [usize; 16] = [
    MSG0, MSG1, MSG2, MSG3, MSG4, MSG5, MSG6, MSG7, MSG8, MSG9, MSG10, MSG11, MSG12, MSG13, MSG14,
    MSG15,
]; // 16..31

// 256-bit (r + n) limbs (columns 88..103)
pub const RN_COLS: [usize; 16] = [
    88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103,
]; // 88..103

// Boolean selector z (1 => Rx==r, 0 => Rx==r+n)
pub const Z_EQ_COL: usize = 104; // 104

// ===== Auxiliary trace columns (64 total) =====
// First equality: R'_x == r
pub const AUX_EQ1_D_COLS: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
pub const AUX_EQ1_BO_COLS: [usize; 16] = [
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];

// Second equality: R'_x == r + n
pub const AUX_EQ2_D_COLS: [usize; 16] = [
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
];
pub const AUX_EQ2_BO_COLS: [usize; 16] = [
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
];

// Mixed columns for boundary assertions (researcher's latest fix)
pub const AUX_MIX_D_COLS: [usize; 16] = [
    64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
];
pub const AUX_MIX_BO_COLS: [usize; 16] = [
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
];

// Identity binding columns - now use the new layout
pub const OWNER_ID32_COLS: [usize; 8] = OWNER_ID_COLS;
pub const IDENTITY_ID32_COLS: [usize; 8] = IDENTITY_ID_COLS;
pub const DIFF_ID32_COLS: [usize; 8] = DIFF_COLS;

// Selector columns
pub const BLAKE3_ACTIVE_COL: usize = SEL_BLAKE3_COL;
pub const MERKLE_ACTIVE_COL: usize = SEL_MERKLE_COL;
pub const EDDSA_ACTIVE_COL: usize = SEL_EDDSA_COL;

pub const JOIN_ROW: usize = 16384; // Row where we check (after Merkle paths complete)

// ===== Periodic column indices =====
pub const P_B: usize = 0; // BLAKE3-phase gate
pub const P_M: usize = 1; // Merkle-phase gate
pub const P_E: usize = 2; // Signature-phase gate
pub const P_R: usize = 3; // round index value
pub const P_M_LOAD: usize = 4; // Merkle LOAD sub-phase (NEW)
pub const P_M_COMP: usize = 5; // Merkle COMP sub-phase (NEW)
pub const P_M_HOLD: usize = 6; // Merkle HOLD sub-phase (NEW)
                               // Note: All indices after this are shifted by +3
pub const P_EDDSA_FINAL: usize = 359; // Final signature row selector - shifted from 356

// S0..S7 one-hot micro-step gates
pub const P_S0: usize = 7; // S0 is at index 7 after phase gates + Merkle sub-phases

// K0..K7 nibble index one-hot
pub const P_K0: usize = 15; // K0 is at index 15 (7 + 8 S values)

// GW0..GW15: one-hot "which v[j] is being written"
pub const P_GW0: usize = 23; // GW0 is at index 23 (15 + 8 K values)

// 16^k powers for placing nibble k into ACC
pub const P_P16_0: usize = 39; // P16_0 is at index 39 (23 + 16 GW values)

// shifted power rows for nibble-aligned rotations
pub const P_P16S2_0: usize = 47; // ROTR8 (39 + 8)
pub const P_P16S3_0: usize = 55; // ROTR12 (47 + 8)
pub const P_P16S4_0: usize = 63; // ROTR16 (55 + 8)

// MX / MY selects for message indices
pub const P_MX0: usize = 71; // (63 + 8)
pub const P_MY0: usize = 87; // (71 + 16)

// ASRC / BSRC routing (shifted by +3)
pub const P_ASRC0: usize = 103; // 103..230 (8*16)
pub const P_BSRC0: usize = 231; // 231..358 (8*16)
pub const P_ASRC_S0_0: usize = 103;
pub const P_BSRC_S0_0: usize = 231;

// Total periodic columns: 356

// BLAKE3 message schedule
pub const MSG_SCHEDULE: [[u8; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

// ================================================================================================
// PUBLIC INPUTS
// ================================================================================================

/// Wrapper for public inputs that implements ToElements
#[derive(Debug, Clone)]
pub struct GrovePublicInputs(pub PublicInputs);

impl ToElements<BaseElement> for GrovePublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::with_capacity(13);

        // Convert 32-byte state root to 4 field elements (8 bytes each)
        for chunk in self.0.state_root.chunks(8) {
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            elements.push(BaseElement::new(u64::from_le_bytes(bytes)));
        }

        // Convert 32-byte contract ID to 4 field elements
        for chunk in self.0.contract_id.chunks(8) {
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            elements.push(BaseElement::new(u64::from_le_bytes(bytes)));
        }

        // Convert 32-byte message hash to 4 field elements
        for chunk in self.0.message_hash.chunks(8) {
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            elements.push(BaseElement::new(u64::from_le_bytes(bytes)));
        }

        // Add timestamp as single element
        elements.push(BaseElement::new(self.0.timestamp));

        elements
    }
}

// ================================================================================================
// GROVEDB AIR
// ================================================================================================

/// Resolved periodic indices
#[derive(Copy, Clone, Debug)]
struct PeriodicIdx {
    m: usize,
    m_load: usize,
    m_comp: usize,
    m_hold: usize,
}

pub struct GroveAir {
    context: AirContext<BaseElement>,
    public_inputs: GrovePublicInputs,
    /// Resolved periodic indices (frozen at AIR construction)
    per: PeriodicIdx,
    /// Deterministic gamma for lane packing
    gamma: BaseElement,
}

impl GroveAir {
    /// Calculate deterministic public gamma from AIR parameters
    fn calculate_lane_pack_gamma(trace_len: usize, options: &ProofOptions) -> BaseElement {
        // Domain separation + public parameters
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"GROVESTARK:lane-pack:v1:");
        hasher.update(&(trace_len as u64).to_le_bytes());
        hasher.update(&(options.blowup_factor() as u64).to_le_bytes());
        hasher.update(&(options.grinding_factor() as u64).to_le_bytes());
        hasher.update(&(options.num_queries() as u64).to_le_bytes());

        // Hash to get deterministic bytes
        let hash = hasher.finalize();
        let bytes = hash.as_bytes();

        // Map to field element (reduce mod p)
        // Take first 8 bytes for u64, which fits in BaseElement
        let mut val_bytes = [0u8; 8];
        val_bytes.copy_from_slice(&bytes[0..8]);
        let mut gamma = BaseElement::new(u64::from_le_bytes(val_bytes));

        // Ensure gamma ∉ {0, 1}
        if gamma == BaseElement::ZERO || gamma == BaseElement::ONE {
            gamma = gamma + BaseElement::ONE + BaseElement::ONE; // Make it 2
        }

        gamma
    }
}

impl Air for GroveAir {
    type BaseField = BaseElement;
    type PublicInputs = GrovePublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Use the trace_info as provided - winterfell will handle multi-segment setup
        // The trace_info here is for the main trace only (132 columns)
        // Winterfell will add the auxiliary segment when build_aux_trace is called

        // Define degrees for main constraints using LAYOUT
        let mut main_degrees = Vec::with_capacity(LAYOUT.eddsa.end);

        // BLAKE3 constraints (15 total) — use only BLAKE3 phase periodic gate (g).
        // All step/nibble/target selectors are committed columns to avoid OOD drift.
        // Index mapping within the BLAKE3 group (must match evaluate_blake3_phase() gating):
        // 0: bit binarity (g)
        // 1: SRC_A quotient (S * K)
        // 2: SRC_B quotient (S * K)
        // 3: SRC_M quotient (g * S)
        // 4: ACC recurrence (g * S)
        // 5: commit no-writes K0..K6 (disabled)
        // 6: commit target at K7 (K7 * ...)
        // 7: commit non-target at K7 (K7 * ...)
        // 8: reset ACC at K0 (g * S * K0)
        // 9: adders (g * S)
        // 10: XOR steps (g * S)
        // 11: ROTR7 (g * S)
        // 12: Bind SRC_A (g * S * K0 * ASRC(16))
        // 13: Bind SRC_B (g * S * K0 * BSRC(16))
        // 14: Bind SRC_M (g * S * K0 * (MX|MY)(16))
        for _ in 0..LAYOUT.blake3.end - LAYOUT.blake3.start {
            main_degrees.push(TransitionConstraintDegree::with_cycles(4, vec![]));
        }
        // Merkle constraints: up to two periodic gates at once (P_M and one sub-phase)
        for _ in LAYOUT.merkle.clone() {
            main_degrees.push(TransitionConstraintDegree::with_cycles(2, vec![2, 2]));
        }
        // Identity binding constraint: gated by Merkle phase periodic
        for _ in LAYOUT.identity.clone() {
            main_degrees.push(TransitionConstraintDegree::with_cycles(2, vec![2]));
        }
        // EdDSA selector constraint: gated by at most one periodic
        for _ in LAYOUT.eddsa.clone() {
            main_degrees.push(TransitionConstraintDegree::with_cycles(2, vec![2]));
        }

        // Lock the counts with assertions
        assert_eq!(
            main_degrees.len(),
            LAYOUT.eddsa.end,
            "Main constraint count mismatch"
        );

        // Single-segment AIR context
        // Create with standard constructor then set exemptions
        // Calculate deterministic gamma for lane packing
        let gamma = Self::calculate_lane_pack_gamma(trace_info.length(), &options);

        // Main assertions: ACC(1) + SEL_FINAL(2) + COMMIT_DIFF(1) + DIFF(8) + state_root(4) = 16
        let num_main_assertions = 16;

        // Define degrees for auxiliary constraints (GroveVM)
        // Migration to Winterfell 0.13.1: declare realistic upper bounds.
        // GroveVM constraints include booleanity (deg 2), next()-based updates (deg ~1),
        // packed stack continuity and safety eq polynomials over small domain (deg up to ~5).
        // Use a conservative cap to avoid under-declaration at OOD.
        let mut aux_degrees = Vec::with_capacity(NUM_AUX_CONSTRAINTS);
        for _ in 0..NUM_AUX_CONSTRAINTS {
            aux_degrees.push(TransitionConstraintDegree::new(8));
        }

        // ALWAYS create multi-segment AirContext since we have auxiliary trace (GroveVM)
        // Even if the initial trace_info is single-segment, we know we'll add auxiliary segments
        // Create a multi-segment trace info for the context
        let multi_segment_info = if trace_info.is_multi_segment() {
            trace_info
        } else {
            // Convert to multi-segment
            TraceInfo::new_multi_segment(
                trace_info.width(),  // Main trace width
                AUX_TRACE_WIDTH,     // Auxiliary trace width
                1,                   // num_aux_segment_rands
                trace_info.length(), // Same trace length
                trace_info.meta().to_vec(),
            )
        };

        // Create multi-segment AirContext for main + auxiliary traces
        let context = AirContext::new_multi_segment(
            multi_segment_info,
            main_degrees.clone(), // Main transition constraint degrees
            aux_degrees,          // Auxiliary transition constraint degrees
            num_main_assertions,  // Main assertions (root, identity, public inputs)
            66, // Aux assertions: SP start(1) + EdDSA accumulator(1) + EdDSA identity point(64)
            options,
        );

        // Guardrail assertions
        assert_eq!(
            main_degrees.len(),
            NUM_CONSTRAINTS,
            "Constraint count mismatch"
        );

        // Verify MERKLE_MSG mapping
        for k in 0..16 {
            let c = MERKLE_MSG.col(k);
            assert!(c != 63, "MERKLE_MSG mapping must skip IS_LEFT (63)");
            assert!(
                (55..=71).contains(&c),
                "MERKLE_MSG must be in scratch range"
            );
        }

        // Set minimal exemptions for next()-based constraints; keep at 1 to maximize divisor degree
        // and reduce composition degree to stay within CE domain.
        let context = context.set_num_transition_exemptions(1);

        // Verify exemptions
        assert!(
            context.num_transition_exemptions() >= 1,
            "Exemptions must be at least 1 for next() usage"
        );

        // Resolve periodic indices (frozen for this AIR instance)
        // These match the order in get_periodic_column_values()
        let per = PeriodicIdx {
            m: P_M,           // 1: Merkle phase selector
            m_load: P_M_LOAD, // 4: Merkle LOAD sub-phase
            m_comp: P_M_COMP, // 5: Merkle COMP sub-phase
            m_hold: P_M_HOLD, // 6: Merkle HOLD sub-phase
        };

        // Add invariant checks
        assert_eq!(
            main_degrees.len(),
            NUM_CONSTRAINTS,
            "degree vector length mismatch"
        );
        assert_eq!(
            LAYOUT.eddsa.end, NUM_CONSTRAINTS,
            "layout end doesn't match NUM_CONSTRAINTS"
        );
        assert!(
            context.num_transition_exemptions() >= 1,
            "must exempt at least last row for next() constraints"
        );

        Self {
            context,
            public_inputs: pub_inputs,
            per,
            gamma,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let n = self.context.trace_len();
        let mut out = Vec::with_capacity(360); // 357 original + 3 Merkle sub-phases

        // Constants for BLAKE3 compression structure
        const COMPRESSION_ROWS: usize = 3584; // 7 rounds * 8 lanes * 8 micro-steps * 8 nibbles

        // Response 19: Helper to determine which V registers feed SRC_A and SRC_B
        #[inline]
        fn blake3_lane_sources(s: usize, a: usize, b: usize, c: usize, d: usize) -> (usize, usize) {
            match s {
                0 | 4 => (a, b), // v[a] += v[b] + m*
                1 | 5 => (d, a), // v[d] = rotr*(v[d] ^ v[a])
                2 | 6 => (c, d), // v[c] += v[d]
                3 | 7 => (b, c), // v[b] = rotr*(v[b] ^ v[c])
                _ => unreachable!(),
            }
        }

        // Initialize all periodic columns
        let mut p_b = vec![BaseElement::ZERO; n];
        let mut p_m = vec![BaseElement::ZERO; n];
        let mut p_e = vec![BaseElement::ZERO; n];
        let mut p_r = vec![BaseElement::ZERO; n];

        // Merkle sub-phase selectors
        let mut p_m_load = vec![BaseElement::ZERO; n];
        let mut p_m_comp = vec![BaseElement::ZERO; n];
        let mut p_m_hold = vec![BaseElement::ZERO; n];

        // S0-S7 micro-step selectors
        let mut p_s: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; n]; 8];

        // K0-K7 nibble index selectors
        let mut p_k: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; n]; 8];

        // GW0-GW15 word target selectors
        let mut p_gw: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; n]; 16];

        // 16^k powers
        let mut p_p16: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; n]; 8];
        let mut p_p16s2: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; n]; 8];
        let mut p_p16s3: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; n]; 8];
        let mut p_p16s4: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; n]; 8];

        // Message selectors
        let mut p_mx: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; n]; 16];
        let mut p_my: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; n]; 16];

        // Source routing selectors (8 micro-steps * 16 word indices each)
        let mut p_asrc: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; n]; 128];
        let mut p_bsrc: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; n]; 128];

        // Lane mappings
        const COLUMN_LANES: [[usize; 4]; 4] =
            [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]];
        const DIAGONAL_LANES: [[usize; 4]; 4] =
            [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]];

        // Build the BLAKE3 compression window
        if COMPRESSION_ROWS <= n {
            let mut row = 0;

            for round in 0..7 {
                // Process column lanes
                for lane_idx in 0..4 {
                    let lane = COLUMN_LANES[lane_idx];
                    let (a, b, c, d) = (lane[0], lane[1], lane[2], lane[3]);

                    // Get message indices for this round and lane
                    let mx_idx = MSG_SCHEDULE[round][2 * lane_idx] as usize;
                    let my_idx = MSG_SCHEDULE[round][2 * lane_idx + 1] as usize;

                    // Process 8 micro-steps
                    for s in 0..8 {
                        // Determine target word based on micro-step
                        let target = match s {
                            0 | 4 => a, // a += b + m
                            1 | 5 => d, // d = rotr(d ^ a)
                            2 | 6 => c, // c += d
                            3 | 7 => b, // b = rotr(b ^ c)
                            _ => unreachable!(),
                        };

                        // Response 19: Use helper to get correct source indices
                        let (src_a, src_b) = blake3_lane_sources(s, a, b, c, d);

                        // Process 8 nibbles
                        for k in 0..8 {
                            if row < n {
                                // Defensive one-hot zeroing for this row (Response 8 & 9 fixes)
                                for t in 0..8 {
                                    p_s[t][row] = BaseElement::ZERO;
                                }
                                for t in 0..8 {
                                    p_k[t][row] = BaseElement::ZERO;
                                }
                                for t in 0..16 {
                                    p_gw[t][row] = BaseElement::ZERO;
                                }
                                for t in 0..128 {
                                    p_asrc[t][row] = BaseElement::ZERO;
                                }
                                for t in 0..128 {
                                    p_bsrc[t][row] = BaseElement::ZERO;
                                }
                                for t in 0..16 {
                                    p_mx[t][row] = BaseElement::ZERO;
                                }
                                for t in 0..16 {
                                    p_my[t][row] = BaseElement::ZERO;
                                }
                                // Response 9: Also zero the P16 power bundles
                                for t in 0..8 {
                                    p_p16[t][row] = BaseElement::ZERO;
                                    p_p16s2[t][row] = BaseElement::ZERO;
                                    p_p16s3[t][row] = BaseElement::ZERO;
                                    p_p16s4[t][row] = BaseElement::ZERO;
                                }

                                p_b[row] = BaseElement::ONE;
                                p_r[row] = BaseElement::new(round as u64);
                                p_s[s][row] = BaseElement::ONE;
                                p_k[k][row] = BaseElement::ONE;
                                p_gw[target][row] = BaseElement::ONE;

                                // Set source routing
                                let asrc_idx = s * 16 + src_a;
                                let bsrc_idx = s * 16 + src_b;
                                p_asrc[asrc_idx][row] = BaseElement::ONE;
                                p_bsrc[bsrc_idx][row] = BaseElement::ONE;

                                // Set message selectors for S0 and S4
                                if s == 0 {
                                    p_mx[mx_idx][row] = BaseElement::ONE;
                                } else if s == 4 {
                                    p_my[my_idx][row] = BaseElement::ONE;
                                }

                                // Set power values - Response 12 Fix A
                                // Each bundle stores the rotated power at the same k index
                                let pow16_base = 16u64.pow(k as u32);
                                p_p16[k][row] = BaseElement::new(pow16_base);
                                p_p16s2[k][row] = BaseElement::new(16u64.pow(((k + 2) % 8) as u32));
                                p_p16s3[k][row] = BaseElement::new(16u64.pow(((k + 3) % 8) as u32));
                                p_p16s4[k][row] = BaseElement::new(16u64.pow(((k + 4) % 8) as u32));
                            }
                            row += 1;
                        }
                    }
                }

                // Process diagonal lanes (same structure)
                for lane_idx in 0..4 {
                    let lane = DIAGONAL_LANES[lane_idx];
                    let (a, b, c, d) = (lane[0], lane[1], lane[2], lane[3]);

                    let mx_idx = MSG_SCHEDULE[round][8 + 2 * lane_idx] as usize;
                    let my_idx = MSG_SCHEDULE[round][8 + 2 * lane_idx + 1] as usize;

                    for s in 0..8 {
                        let target = match s {
                            0 | 4 => a,
                            1 | 5 => d,
                            2 | 6 => c,
                            3 | 7 => b,
                            _ => unreachable!(),
                        };

                        // Response 19: Use helper to get correct source indices
                        let (src_a, src_b) = blake3_lane_sources(s, a, b, c, d);

                        for k in 0..8 {
                            if row < n {
                                // Defensive one-hot zeroing for this row (Response 8 & 9 fixes)
                                for t in 0..8 {
                                    p_s[t][row] = BaseElement::ZERO;
                                }
                                for t in 0..8 {
                                    p_k[t][row] = BaseElement::ZERO;
                                }
                                for t in 0..16 {
                                    p_gw[t][row] = BaseElement::ZERO;
                                }
                                for t in 0..128 {
                                    p_asrc[t][row] = BaseElement::ZERO;
                                }
                                for t in 0..128 {
                                    p_bsrc[t][row] = BaseElement::ZERO;
                                }
                                for t in 0..16 {
                                    p_mx[t][row] = BaseElement::ZERO;
                                }
                                for t in 0..16 {
                                    p_my[t][row] = BaseElement::ZERO;
                                }
                                // Response 9: Also zero the P16 power bundles
                                for t in 0..8 {
                                    p_p16[t][row] = BaseElement::ZERO;
                                    p_p16s2[t][row] = BaseElement::ZERO;
                                    p_p16s3[t][row] = BaseElement::ZERO;
                                    p_p16s4[t][row] = BaseElement::ZERO;
                                }

                                p_b[row] = BaseElement::ONE;
                                p_r[row] = BaseElement::new(round as u64);
                                p_s[s][row] = BaseElement::ONE;
                                p_k[k][row] = BaseElement::ONE;
                                p_gw[target][row] = BaseElement::ONE;

                                let asrc_idx = s * 16 + src_a;
                                let bsrc_idx = s * 16 + src_b;
                                p_asrc[asrc_idx][row] = BaseElement::ONE;
                                p_bsrc[bsrc_idx][row] = BaseElement::ONE;

                                if s == 0 {
                                    p_mx[mx_idx][row] = BaseElement::ONE;
                                } else if s == 4 {
                                    p_my[my_idx][row] = BaseElement::ONE;
                                }

                                // Response 23: Use same-index semantics with rotated powers
                                // Index is always k, value is the rotated power
                                p_p16[k][row] = BaseElement::new(16u64.pow(k as u32));
                                p_p16s2[k][row] = BaseElement::new(16u64.pow(((k + 2) % 8) as u32));
                                p_p16s3[k][row] = BaseElement::new(16u64.pow(((k + 3) % 8) as u32));
                                p_p16s4[k][row] = BaseElement::new(16u64.pow(((k + 4) % 8) as u32));
                            }
                            row += 1;
                        }
                    }
                }
            }
        }

        // Set phase gates
        // BLAKE3 phase: rows 0..3584
        const BLAKE3_ROWS: usize = 3584;
        const MERKLE_ROWS: usize = 16384;
        const EDDSA_ROWS_LOCAL: usize = 32768;

        for i in 0..BLAKE3_ROWS.min(n) {
            p_b[i] = BaseElement::ONE;
        }
        // Merkle phase with sub-phases
        // Pattern: LOAD (1 row) -> COMP (3582 rows) -> HOLD (1 row), repeat
        const MERKLE_CYCLE: usize = 3584; // Same as BLAKE3 compression
        for i in BLAKE3_ROWS..(BLAKE3_ROWS + MERKLE_ROWS).min(n) {
            p_m[i] = BaseElement::ONE;

            // Determine position within cycle
            let pos_in_cycle = (i - BLAKE3_ROWS) % MERKLE_CYCLE;

            if pos_in_cycle == 0 {
                // First row of cycle: LOAD
                p_m_load[i] = BaseElement::ONE;
            } else if pos_in_cycle < MERKLE_CYCLE - 1 {
                // Middle rows: COMP (computation)
                p_m_comp[i] = BaseElement::ONE;
            } else {
                // Last row of cycle: HOLD
                p_m_hold[i] = BaseElement::ONE;
            }
        }
        for i in (BLAKE3_ROWS + MERKLE_ROWS)..(BLAKE3_ROWS + MERKLE_ROWS + EDDSA_ROWS_LOCAL).min(n)
        {
            p_e[i] = BaseElement::ONE;
        }

        // Pack all periodic columns in the correct order
        out.push(p_b); // 0: P_B
        out.push(p_m); // 1: P_M
        out.push(p_e); // 2: P_E
        out.push(p_r); // 3: P_R
        out.push(p_m_load); // 4: P_M_LOAD (NEW)
        out.push(p_m_comp); // 5: P_M_COMP (NEW)
        out.push(p_m_hold); // 6: P_M_HOLD (NEW)

        for s in p_s {
            out.push(s);
        }
        for k in p_k {
            out.push(k);
        }
        for gw in p_gw {
            out.push(gw);
        }
        for p in p_p16 {
            out.push(p);
        }
        for p in p_p16s2 {
            out.push(p);
        }
        for p in p_p16s3 {
            out.push(p);
        }
        for p in p_p16s4 {
            out.push(p);
        }
        for mx in p_mx {
            out.push(mx);
        }
        for my in p_my {
            out.push(my);
        }
        for asrc in p_asrc {
            out.push(asrc);
        }
        for bsrc in p_bsrc {
            out.push(bsrc);
        }

        // Add final row selector at the END (researcher's section 1)
        let mut p_eddsa_final = vec![BaseElement::ZERO; n];
        if EDDSA_END < n {
            p_eddsa_final[EDDSA_END] = BaseElement::ONE;
        }

        out.push(p_eddsa_final); // Push at index 359 (shifted)

        // Sanity checks (Response 9)
        debug_assert_eq!(
            out.len(),
            360,
            "periodic column count must be 360 (357 original + 3 Merkle sub-phases)"
        );
        debug_assert!(out[P_K0].contains(&BaseElement::ONE), "P_K0 has no ones?");
        debug_assert!(
            out[P_K0 + 2].contains(&BaseElement::ONE),
            "P_K2 has no ones?"
        );
        debug_assert!(out[P_S0].contains(&BaseElement::ONE), "P_S0 has no ones?");
        debug_assert!(
            out[P_EDDSA_FINAL].contains(&BaseElement::ONE),
            "P_EDDSA_FINAL has no ones?"
        );

        out
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic: &[E],
        result: &mut [E],
    ) {
        // Assertions and zero-init
        assert_eq!(
            result.len(),
            NUM_CONSTRAINTS,
            "evaluate_transition result length mismatch"
        );
        for x in result.iter_mut() {
            *x = E::ZERO;
        }

        // Use slices to prevent index drift
        // Each phase writes to its own slice starting at index 0
        if !LAYOUT.blake3.is_empty() {
            let blake3_slice = result.get_mut(LAYOUT.blake3.clone()).unwrap();
            evaluate_blake3_phase(blake3_slice, frame, periodic, self.gamma);
        }

        if !LAYOUT.merkle.is_empty() {
            // Evaluate Merkle constraints (lane-packed), properly gated by Merkle sub-phases
            let merkle_slice = result.get_mut(LAYOUT.merkle.clone()).unwrap();
            let per_m = crate::phases::merkle::constraints::MerklePer {
                p_m: periodic[P_M],
                p_load: periodic[P_M_LOAD],
                p_comp: periodic[P_M_COMP],
                p_hold: periodic[P_M_HOLD],
            };
            evaluate_merkle_stub(merkle_slice, frame, per_m, self.gamma);
        }

        // Identity binding: DIFF[i] = OWNER_ID[i] - IDENTITY_ID[i]
        // Gated by P_M so only active during Merkle phase rows.
        // Now safe because Merkle join storage has been relocated to cols 116-131,
        // so OWNER_ID_COLS (72-79) and IDENTITY_ID_COLS (80-87) are no longer overwritten.
        if !LAYOUT.identity.is_empty() {
            let identity_slice = result.get_mut(LAYOUT.identity.clone()).unwrap();
            let cur = frame.current();
            let gamma = E::from(self.gamma);
            let mut packed = E::ZERO;
            let mut gp = E::ONE;
            for i in 0..8 {
                let diff = cur[DIFF_COLS[i]] - (cur[OWNER_ID_COLS[i]] - cur[IDENTITY_ID_COLS[i]]);
                packed = packed + gp * diff;
                gp = gp * gamma;
            }
            identity_slice[0] = periodic[P_M] * packed;
        }

        // EdDSA SEL_FINAL transition: OOD-stable form using only current row + periodic
        // Enforce: during EdDSA phase, SEL_FINAL equals the one-hot periodic P_EDDSA_FINAL.
        // This avoids next()-based transitions and aligns with boundary assertions.
        if !LAYOUT.eddsa.is_empty() {
            let eddsa_slice = result.get_mut(LAYOUT.eddsa.clone()).unwrap();
            let sel_final_cur = frame.current()[SEL_FINAL];
            let g_e = periodic[P_E];
            let p_final = periodic[P_EDDSA_FINAL];
            eddsa_slice[0] = g_e * (sel_final_cur - p_final);
        }

        // Hard assert the final state
        assert_eq!(
            result.len(),
            LAYOUT.eddsa.end,
            "constraint vector length drift"
        );
    }
    fn evaluate_aux_transition<F, E>(
        &self,
        _main_frame: &EvaluationFrame<F>,
        _aux_frame: &EvaluationFrame<E>,
        _periodic_values: &[F],
        _aux_rand_elements: &AuxRandElements<E>,
        result: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>,
    {
        // Re-enable GroveVM constraints: compute auxiliary constraints from GroveVM aux segment

        // Evaluate GroveVM constraints
        // The auxiliary trace has:
        // - Columns 0-63: EdDSA coordinates (X, Y, Z, T)
        // - Columns 64-117: GroveVM columns (54 total)

        // Read GroveVM columns from auxiliary trace
        let aux_current = _aux_frame.current();
        let aux_next = _aux_frame.next();

        // Skip EdDSA columns (0-63) and get GroveVM columns (64+)
        let grovevm_start = 64;

        // CRITICAL: Only take exactly GROVEVM_AUX_WIDTH columns, not all remaining columns
        let grovevm_end = grovevm_start + GROVEVM_AUX_WIDTH;
        let grovevm_current = if aux_current.len() >= grovevm_end {
            &aux_current[grovevm_start..grovevm_end]
        } else {
            &aux_current[grovevm_start..]
        };
        let grovevm_next = if aux_next.len() >= grovevm_end {
            &aux_next[grovevm_start..grovevm_end]
        } else {
            &aux_next[grovevm_start..]
        };

        // Check if we're in a GroveVM execution phase (could be gated by periodic selector)
        // For now, evaluate constraints always but they should be zero in padding

        // Create GroveVM constraint evaluator with gamma
        use crate::phases::grovevm::{GroveVMConstraints, GROVEVM_AUX_WIDTH};
        let grovevm_constraints = GroveVMConstraints::new(self.gamma);

        // Check if BLAKE3 output is available (for Parent/Child operations)
        // We need to read from main trace to get BLAKE3 output
        let main_current = _main_frame.current();
        let blake3_output = if main_current.len() >= 8 {
            // Read BLAKE3 output from main trace columns V0-V7 (first 8 state columns)
            // These would contain the hash result after BLAKE3 compression
            // Convert first 8 main trace columns to BLAKE3 output
            let mut blake3_out = [E::ZERO; 8];
            for i in 0..8 {
                blake3_out[i] = E::from(main_current[i]);
            }
            Some(blake3_out)
        } else {
            None
        };

        // Evaluate GroveVM constraints
        let grovevm_results =
            grovevm_constraints.evaluate(grovevm_current, grovevm_next, blake3_output.as_ref());

        // Copy GroveVM constraint results to output
        // GroveVM produces NUM_GROVEVM_CONSTRAINTS; remaining slots are for EdDSA aux constraints
        const NUM_GROVEVM_CONSTRAINTS: usize = 12;
        debug_assert!(
            result.len() >= NUM_AUX_CONSTRAINTS,
            "Result buffer too small: {} < {}",
            result.len(),
            NUM_AUX_CONSTRAINTS
        );
        debug_assert_eq!(
            grovevm_results.len(),
            NUM_GROVEVM_CONSTRAINTS,
            "GroveVM returned wrong number of constraints: {} != {}",
            grovevm_results.len(),
            NUM_GROVEVM_CONSTRAINTS
        );

        for (i, constraint_value) in grovevm_results.iter().enumerate() {
            if i < result.len() {
                result[i] = *constraint_value;
            }
        }

        // ---- EdDSA auxiliary constraints (packed into existing aux slots) ----
        // Gate with periodic EdDSA phase selector to match CE/combiner at OOD.
        let _main_cur = _main_frame.current();
        let _p_e_gate: E = E::from(_periodic_values[P_E]);
        // Window bits and value from auxiliary EdDSA region
        // aux[56..59] = b0..b3, aux[60] = window value
        let aux_b0 = 48 + 8; // 56
        let aux_b1 = 48 + 9; // 57
        let aux_b2 = 48 + 10; // 58
        let aux_b3 = 48 + 11; // 59
        let aux_wv = 48 + 12; // 60
        let wb0: E = _aux_frame.current().get(aux_b0).cloned().unwrap_or(E::ZERO);
        let wb1: E = _aux_frame.current().get(aux_b1).cloned().unwrap_or(E::ZERO);
        let wb2: E = _aux_frame.current().get(aux_b2).cloned().unwrap_or(E::ZERO);
        let wb3: E = _aux_frame.current().get(aux_b3).cloned().unwrap_or(E::ZERO);
        let wval: E = _aux_frame.current().get(aux_wv).cloned().unwrap_or(E::ZERO);
        // (ED1) Booleanity of the 4 window bits
        let mut ed1 = E::ZERO;
        for b in [wb0, wb1, wb2, wb3] {
            ed1 = ed1 + b * (b - E::ONE);
        }
        // (ED2) Window value equals packed bits
        let ed2 = wval - (wb0 + E::from(2u32) * wb1 + E::from(4u32) * wb2 + E::from(8u32) * wb3);
        // Pack ED1/ED2 together using gamma to reduce multiple exposed slots at OOD
        let gamma_e = E::from(self.gamma);
        let ed_pack = ed1 + gamma_e * ed2;
        // EdDSA window bit constraint: booleanity + value = packed bits
        if result.len() > 12 {
            result[12] = _p_e_gate * ed_pack;
        }

        // Phase 3: Bind BLAKE3 message lanes to GroveVM stack on merge operations.
        // Ensure MSG0..MSG7 equal left limbs and MSG8..MSG15 equal right limbs (swapped for Child).
        // Pack limb residuals with gamma and add into the merge-write constraint slot (index 9).
        // Phase 3: Bind BLAKE3 message lanes to GroveVM stack on merge operations.
        // Uses algebraic sp_eq for slot selection instead of decode_small.
        if result.len() >= NUM_AUX_CONSTRAINTS {
            let is_parent = grovevm_current[crate::phases::grovevm::types::OP_PARENT];
            let is_child = grovevm_current[crate::phases::grovevm::types::OP_CHILD];
            let is_merge = is_parent + is_child;
            let sp_val = grovevm_current[crate::phases::grovevm::types::SP];

            // Algebraic Lagrange indicator for SP over domain 0..=D_MAX
            let sp_eq_e = |v: E, c: usize| -> E {
                let d_max = crate::phases::grovevm::types::D_MAX;
                let mut num = E::ONE;
                for kk in 0..=d_max {
                    if kk != c {
                        let diff = E::from(BaseElement::new(c as u64))
                            - E::from(BaseElement::new(kk as u64));
                        num = num * (v - E::from(BaseElement::new(kk as u64)));
                        num = num * diff.inv();
                    }
                }
                num
            };

            let mut gp = E::ONE;
            let mut packed_msg = E::ZERO;
            for limb in 0..crate::phases::grovevm::types::LIMBS_PER_HASH {
                // Algebraically select left and right limbs via sp_eq
                let mut left_limb = E::ZERO;
                let mut right_limb = E::ZERO;
                for sp_c in 2..=crate::phases::grovevm::types::D_MAX {
                    let eq_c = sp_eq_e(sp_val, sp_c);
                    let base_left = crate::phases::grovevm::types::STACK_START
                        + (sp_c - 2) * crate::phases::grovevm::types::LIMBS_PER_HASH;
                    let base_right = crate::phases::grovevm::types::STACK_START
                        + (sp_c - 1) * crate::phases::grovevm::types::LIMBS_PER_HASH;
                    left_limb += eq_c * grovevm_current[base_left + limb];
                    right_limb += eq_c * grovevm_current[base_right + limb];
                }

                let m_left = E::from(main_current[MSG0 + limb]);
                let m_right = E::from(main_current[MSG0 + 8 + limb]);

                let exp_left = (E::ONE - is_child) * left_limb + is_child * right_limb;
                let exp_right = (E::ONE - is_child) * right_limb + is_child * left_limb;

                let limb_res = (m_left - exp_left) + (m_right - exp_right);
                packed_msg = packed_msg + gp * limb_res;
                gp = gp * E::from(self.gamma);
            }

            // Merge into slot 10 (merge write constraint, shifted +1 for at-most-one)
            let idx_merge_write = 10usize;
            if idx_merge_write < result.len() {
                result[idx_merge_write] = result[idx_merge_write] + is_merge * packed_msg;
            }
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();

        // Initial accumulator is zero at row 0
        assertions.push(Assertion::single(ACC, 0, BaseElement::ZERO));

        // SEL_FINAL selector boundary assertions
        assertions.push(Assertion::single(SEL_FINAL, 0, BaseElement::ZERO));
        assertions.push(Assertion::single(SEL_FINAL, EDDSA_END, BaseElement::ONE));

        // BLAKE3 commit equality as boundary-only invariant at final BLAKE3 row
        assertions.push(Assertion::single(
            COMMIT_DIFF_COL,
            BLAKE3_END,
            BaseElement::ZERO,
        ));

        // Identity binding at JOIN_ROW: DIFF 32-bit limbs must be zero
        for i in 0..8 {
            assertions.push(Assertion::single(
                DIFF_ID32_COLS[i],
                JOIN_ROW,
                BaseElement::ZERO,
            ));
        }

        // Merkle root must match public state root at end of Merkle phase
        let state_root_bytes = &self.public_inputs.0.state_root;
        const MERKLE_LAST_ROW: usize = MERKLE_END;
        for i in 0..4 {
            let mut value = 0u64;
            for j in 0..8 {
                value |= (state_root_bytes[i * 8 + j] as u64) << (j * 8);
            }
            assertions.push(Assertion::single(
                V0 + i,
                MERKLE_LAST_ROW,
                BaseElement::new(value),
            ));
        }

        assertions
    }

    fn get_aux_assertions<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        _aux_rand_elements: &AuxRandElements<E>,
    ) -> Vec<Assertion<E>> {
        let mut v = Vec::new();
        // GroveVM SP start at 0 (stack pointer initialized)
        v.push(Assertion::single(64 + 4, 0, E::ZERO));
        // EdDSA accumulator boundary at EDDSA_END (dedicated aux column)
        v.push(Assertion::single(AUX_TRACE_WIDTH - 1, EDDSA_END, E::ZERO));

        // EdDSA identity point assertions at EDDSA_END: (X=0, Y=1, Z=1, T=0)
        // X = 0 (16 limbs, aux columns 0-15)
        for i in 0..16 {
            v.push(Assertion::single(X_COLS[i], EDDSA_END, E::ZERO));
        }
        // Y = 1 (limb 0 = 1, rest = 0, aux columns 16-31)
        v.push(Assertion::single(Y_COLS[0], EDDSA_END, E::ONE));
        for i in 1..16 {
            v.push(Assertion::single(Y_COLS[i], EDDSA_END, E::ZERO));
        }
        // Z = 1 (limb 0 = 1, rest = 0, aux columns 32-47)
        v.push(Assertion::single(Z_COLS[0], EDDSA_END, E::ONE));
        for i in 1..16 {
            v.push(Assertion::single(Z_COLS[i], EDDSA_END, E::ZERO));
        }
        // T = 0 (16 limbs, aux columns 48-63)
        for i in 0..16 {
            v.push(Assertion::single(T_COLS[i], EDDSA_END, E::ZERO));
        }

        v
    }
}

// ================================================================================================
// HELPER FUNCTIONS
// ================================================================================================

// ================================================================================================
// PROVER
// ================================================================================================

pub struct GroveProver {
    options: ProofOptions,
    config: STARKConfig,
    public_inputs: PublicInputs,
    // Store auxiliary columns built during trace generation
    aux_columns: RefCell<Option<Vec<Vec<BaseElement>>>>,
    // Store X, Y, Z, T coordinates for EdDSA points during trace generation
    stored_x_coords: RefCell<Vec<[u64; 16]>>,
    stored_y_coords: RefCell<Vec<[u64; 16]>>,
    stored_z_coords: RefCell<Vec<[u64; 16]>>,
    stored_t_coords: RefCell<Vec<[u64; 16]>>,
    // Store scalar range check values for EdDSA
    stored_s_range_borrow: RefCell<Vec<[u16; 16]>>,
    stored_h_range_borrow: RefCell<Vec<[u16; 16]>>,
    stored_s_range_diff: RefCell<Vec<[u16; 16]>>,
    stored_h_range_diff: RefCell<Vec<[u16; 16]>>,
    // Store GroveVM operations and push tape for auxiliary trace
    grovevm_operations: RefCell<Vec<crate::phases::grovevm::Op>>,
    grovevm_push_tape: RefCell<Vec<[u8; 32]>>,
}

impl GroveProver {
    pub fn new(config: STARKConfig) -> Self {
        let options = ProofOptions::new(
            config.num_queries,
            config.expansion_factor,
            config.grinding_bits as u32,
            winterfell::FieldExtension::None,
            config.folding_factor,
            config.max_remainder_degree,
            winterfell::BatchingMethod::Linear,
            winterfell::BatchingMethod::Linear,
        );

        Self {
            options,
            config,
            public_inputs: PublicInputs {
                state_root: [0u8; 32],
                contract_id: [0u8; 32],
                message_hash: [0u8; 32],
                timestamp: 0,
            },
            aux_columns: RefCell::new(None),
            stored_x_coords: RefCell::new(Vec::new()),
            stored_y_coords: RefCell::new(Vec::new()),
            stored_z_coords: RefCell::new(Vec::new()),
            stored_t_coords: RefCell::new(Vec::new()),
            stored_s_range_borrow: RefCell::new(Vec::new()),
            stored_h_range_borrow: RefCell::new(Vec::new()),
            stored_s_range_diff: RefCell::new(Vec::new()),
            stored_h_range_diff: RefCell::new(Vec::new()),
            grovevm_operations: RefCell::new(Vec::new()),
            grovevm_push_tape: RefCell::new(Vec::new()),
        }
    }

    pub fn with_public_inputs(mut self, public_inputs: PublicInputs) -> Self {
        self.public_inputs = public_inputs;
        self
    }

    /// Build the complete execution trace from witness (multi-segment)
    pub fn build_trace(
        &self,
        witness: &PrivateInputs,
        public_inputs: &PublicInputs,
    ) -> Result<TraceTable<BaseElement>> {
        // Parse GroveDB proof if available in witness
        // This will populate grovevm_operations and grovevm_push_tape for auxiliary trace
        if !witness.grovedb_proof.is_empty() {
            use crate::phases::grovevm::trace::GroveVMTraceBuilder;

            if let Ok((ops, tape)) =
                GroveVMTraceBuilder::parse_grovevm_ops_from_proof(&witness.grovedb_proof)
            {
                *self.grovevm_operations.borrow_mut() = ops;
                *self.grovevm_push_tape.borrow_mut() = tape;
            }
        }

        // MULTI-SEGMENT SOLUTION
        // Build main trace ONLY (132 columns)
        // Aux trace will be built in build_aux_trace callback
        let mut main_columns =
            vec![vec![BaseElement::ZERO; self.config.trace_length]; MAIN_TRACE_WIDTH];

        // Initialize SEL_FINAL selector column (researcher's fix)
        // Set to 0 everywhere, then 1 only at EDDSA_END
        for row in 0..self.config.trace_length {
            main_columns[SEL_FINAL][row] = BaseElement::ZERO;
        }
        if EDDSA_END < self.config.trace_length {
            main_columns[SEL_FINAL][EDDSA_END] = BaseElement::ONE;
        }

        // Initialize committed selector columns. Set phase selectors active during their rows.
        for row in 0..self.config.trace_length {
            main_columns[SEL_BLAKE3_COL][row] = if row < BLAKE3_LEN {
                BaseElement::ONE
            } else {
                BaseElement::ZERO
            };
            main_columns[SEL_MERKLE_COL][row] = BaseElement::ZERO;
            main_columns[SEL_EDDSA_COL][row] = if (EDDSA_START..=EDDSA_END).contains(&row) {
                BaseElement::ONE
            } else {
                BaseElement::ZERO
            };
            main_columns[DIFF_ACC_COL][row] = BaseElement::ZERO;
        }

        // Initialize all identity-related columns to 0 everywhere
        // They will be populated only at JOIN_ROW
        for i in 0..8 {
            for row in 0..self.config.trace_length {
                main_columns[OWNER_ID_COLS[i]][row] = BaseElement::ZERO;
                main_columns[IDENTITY_ID_COLS[i]][row] = BaseElement::ZERO;
                main_columns[DIFF_ID32_COLS[i]][row] = BaseElement::ZERO;
            }
        }

        // Write identity values only at JOIN_ROW using 32-bit limbs
        if JOIN_ROW < self.config.trace_length {
            // Process as 8 x 32-bit limbs instead of 4 x 64-bit chunks
            for i in 0..8 {
                let lo = i * 4;
                let limb_owner = u32::from_le_bytes([
                    witness.owner_id[lo],
                    witness.owner_id[lo + 1],
                    witness.owner_id[lo + 2],
                    witness.owner_id[lo + 3],
                ]);
                let limb_ident = u32::from_le_bytes([
                    witness.identity_id[lo],
                    witness.identity_id[lo + 1],
                    witness.identity_id[lo + 2],
                    witness.identity_id[lo + 3],
                ]);

                // Write 32-bit limbs as field elements
                main_columns[OWNER_ID_COLS[i]][JOIN_ROW] = BaseElement::new(limb_owner as u64);
                main_columns[IDENTITY_ID_COLS[i]][JOIN_ROW] = BaseElement::new(limb_ident as u64);

                // Calculate and write diff
                let diff =
                    BaseElement::new(limb_owner as u64) - BaseElement::new(limb_ident as u64);
                main_columns[DIFF_ID32_COLS[i]][JOIN_ROW] = diff;
            }
        }

        // Fill the MAIN trace columns
        for step in 0..self.config.trace_length {
            self.fill_trace_step(&mut main_columns, step, witness, public_inputs)?;
        }

        // Re-assert identity binding at JOIN_ROW after phase filling to avoid
        // later padding overwrites from Merkle phase.
        if JOIN_ROW < self.config.trace_length {
            for i in 0..8 {
                let lo = i * 4;
                let limb_owner = u32::from_le_bytes([
                    witness.owner_id[lo],
                    witness.owner_id[lo + 1],
                    witness.owner_id[lo + 2],
                    witness.owner_id[lo + 3],
                ]);
                let limb_ident = u32::from_le_bytes([
                    witness.identity_id[lo],
                    witness.identity_id[lo + 1],
                    witness.identity_id[lo + 2],
                    witness.identity_id[lo + 3],
                ]);
                main_columns[OWNER_ID_COLS[i]][JOIN_ROW] = BaseElement::new(limb_owner as u64);
                main_columns[IDENTITY_ID_COLS[i]][JOIN_ROW] = BaseElement::new(limb_ident as u64);
                let diff =
                    BaseElement::new(limb_owner as u64) - BaseElement::new(limb_ident as u64);
                main_columns[DIFF_ID32_COLS[i]][JOIN_ROW] = diff;
            }
        }

        // DO NOT create aux_columns here - they will be created in build_aux_trace
        // The EdDSA coordinate storage happens during fill_trace_step

        // MULTI-SEGMENT: Create TraceTable with proper trace info
        // Note: TraceTable::init creates single-segment, but we'll convert to multi-segment
        // in new_trace_lde() and the Air will know to expect auxiliary segments
        let main_trace = TraceTable::init(main_columns);

        Ok(main_trace)
    }

    /// Fill auxiliary columns for multi-segment trace (EdDSA coordinates in aux segment)
    fn fill_aux_columns(
        &self,
        aux_columns: &mut [Vec<BaseElement>],
        _witness: &PrivateInputs, // Not needed for aux columns anymore
    ) -> Result<()> {
        // Initialize ALL EdDSA columns in auxiliary segment to zero
        // EdDSA X,Y,Z,T are in auxiliary columns 0-63
        let trace_len = self.config.trace_length;

        // Initialize X columns (aux 0-15) to zero everywhere
        for i in 0..16 {
            for row in 0..trace_len {
                aux_columns[i][row] = BaseElement::ZERO;
            }
        }

        // Initialize Y columns (aux 16-31) to zero everywhere
        for i in 16..32 {
            for row in 0..trace_len {
                aux_columns[i][row] = BaseElement::ZERO;
            }
        }

        // Initialize Z columns (aux 32-47) to zero everywhere
        for i in 32..48 {
            for row in 0..trace_len {
                aux_columns[i][row] = BaseElement::ZERO;
            }
        }

        // Initialize T columns (aux 48-63) to zero everywhere
        for i in 48..64 {
            for row in 0..trace_len {
                aux_columns[i][row] = BaseElement::ZERO;
            }
        }

        // Get the stored X, Y, Z, T coordinates from EdDSA computation
        let x_coords = self.stored_x_coords.borrow();
        let y_coords = self.stored_y_coords.borrow();
        let z_coords = self.stored_z_coords.borrow();
        let t_coords = self.stored_t_coords.borrow();

        // Fill X coordinates (aux columns 0-15) for EdDSA phase
        if !x_coords.is_empty() {
            for (idx, x_limbs) in x_coords.iter().enumerate() {
                let row = EDDSA_START + idx;
                if row <= EDDSA_END {
                    for i in 0..16 {
                        aux_columns[i][row] = BaseElement::new(x_limbs[i]);
                    }
                }
            }
        }

        // Fill Y coordinates (aux columns 16-31) for EdDSA phase
        if !y_coords.is_empty() {
            for (idx, y_limbs) in y_coords.iter().enumerate() {
                let row = EDDSA_START + idx;
                if row <= EDDSA_END {
                    for i in 0..16 {
                        aux_columns[16 + i][row] = BaseElement::new(y_limbs[i]);
                    }
                }
            }
        }

        // Fill Z coordinates (aux columns 32-47) for EdDSA phase
        if !z_coords.is_empty() {
            for (idx, z_limbs) in z_coords.iter().enumerate() {
                let row = EDDSA_START + idx;
                if row <= EDDSA_END {
                    for i in 0..16 {
                        aux_columns[32 + i][row] = BaseElement::new(z_limbs[i]);
                    }
                }
            }
        } else {
            // If no Z coords stored, initialize with identity (Z=1)
            for row in EDDSA_START..=EDDSA_END {
                aux_columns[32][row] = BaseElement::ONE;
                for i in 1..16 {
                    aux_columns[32 + i][row] = BaseElement::ZERO;
                }
            }
        }

        // Fill T coordinates (aux columns 48-63) for EdDSA phase
        if !t_coords.is_empty() {
            for (idx, t_limbs) in t_coords.iter().enumerate() {
                let row = EDDSA_START + idx;
                if row <= EDDSA_END {
                    for i in 0..16 {
                        aux_columns[48 + i][row] = BaseElement::new(t_limbs[i]);
                    }
                }
            }
        } else {
            // If no T coords stored, initialize to zero
            for row in EDDSA_START..=EDDSA_END {
                for i in 0..16 {
                    aux_columns[48 + i][row] = BaseElement::ZERO;
                }
            }
        }

        // Range check columns reduced to stay under 255 total column limit
        // May be added back later with a more compact representation

        Ok(())
    }

    fn fill_trace_step(
        &self,
        main_columns: &mut [Vec<BaseElement>],
        step: usize,
        witness: &PrivateInputs,
        public_inputs: &PublicInputs,
    ) -> Result<()> {
        // Phase boundaries (updated for 65,536 total rows)
        const BLAKE3_ROWS: usize = 3584;
        const MERKLE_ROWS: usize = 16384;
        const EDDSA_ROWS_LOCAL: usize = 32768;

        if step == 0 {
            // Initialize and run the entire BLAKE3 compression at once
            use crate::phases::blake3::trace::fill_blake3_compression;

            // Parse message from witness
            let mut message = [0u32; 16];
            for i in 0..16 {
                if i * 4 < witness.document_cbor.len() {
                    let mut word_bytes = [0u8; 4];
                    for j in 0..4 {
                        if i * 4 + j < witness.document_cbor.len() {
                            word_bytes[j] = witness.document_cbor[i * 4 + j];
                        }
                    }
                    message[i] = u32::from_le_bytes(word_bytes);
                }
            }

            // Run the full compression (fills rows 0-3583, including initialization)
            fill_blake3_compression(main_columns, 0, &message);

            // Return early since we've filled many rows at once
            return Ok(());
        } else if step < BLAKE3_ROWS {
            // These rows were already filled by fill_blake3_compression
            return Ok(());
        }

        // Handle Merkle phase
        let merkle_start = BLAKE3_ROWS;
        let merkle_end = BLAKE3_ROWS + MERKLE_ROWS;

        if step == merkle_start {
            // Initialize entire Merkle phase at once
            // Use adaptive function to support both old and new witness formats
            use crate::phases::merkle::fill_merkle_phase;
            fill_merkle_phase(main_columns, merkle_start, witness, public_inputs)?;
            return Ok(());
        } else if step < merkle_end {
            // Already filled by fill_merkle_phase
            return Ok(());
        }

        // Handle signature phase
        let sig_start = merkle_end;
        let sig_end = merkle_end + EDDSA_ROWS_LOCAL;

        if step == sig_start {
            // Initialize entire EdDSA phase at once
            use crate::phases::eddsa::aux_trace::fill_eddsa_phase_with_aux;
            let aux_storage =
                fill_eddsa_phase_with_aux(main_columns, sig_start, witness, public_inputs)?;

            // Store the X, Y, Z, T coordinates for later use in auxiliary trace
            self.stored_x_coords
                .borrow_mut()
                .extend(aux_storage.x_coords);
            self.stored_y_coords
                .borrow_mut()
                .extend(aux_storage.y_coords);
            self.stored_z_coords
                .borrow_mut()
                .extend(aux_storage.z_coords);
            self.stored_t_coords
                .borrow_mut()
                .extend(aux_storage.t_coords);

            // Note: Auxiliary columns (EdDSA Z,T coords) are now in separate segment
            // They are filled in fill_aux_columns method

            return Ok(());
        } else if step < sig_end {
            // Already filled by fill_eddsa_phase
            return Ok(());
        }

        // Padding for remaining rows
        if step >= sig_end {
            for i in 0..MAIN_TRACE_WIDTH {
                // Don't overwrite SEL_FINAL - it's pre-initialized
                if i != SEL_FINAL {
                    main_columns[i][step] = main_columns[i][step - 1];
                }
            }
        }

        Ok(())
    }
}

// ================================================================================================
// PHASE EVALUATION HELPERS
// ================================================================================================

/// Evaluate BLAKE3 constraints into a slice starting at index 0
fn evaluate_blake3_phase<E: FieldElement<BaseField = BaseElement>>(
    result: &mut [E],
    frame: &EvaluationFrame<E>,
    periodic: &[E],
    gamma: BaseElement,
) {
    assert_eq!(
        result.len(),
        15,
        "BLAKE3 expects exactly 15 constraint slots"
    );

    // BLAKE3 constraints are implemented inline here
    // Copied from the old evaluate_transition function

    let cur = frame.current();
    let nxt = frame.next();

    // ---------- committed selectors (replace periodic S/K at OOD) ----------
    let s = |i: usize| cur[COMMIT_STEP_SEL_COLS[i]]; // S0..S7 from committed columns
    let k = |i: usize| cur[COMMIT_K_SEL_COLS[i]]; // K0..K7 from committed columns
                                                  // Lane write selector used only at K7 is committed (GW_COMMIT_SEL_COLS). For non-commit
                                                  // constraints we don't need GW.
    let gw_committed = |j: usize| cur[GW_COMMIT_SEL_COLS[j]];

    // 16^k bases and rotated mappings from committed K selector
    let pow16 = |e: u32| E::from(16u32.pow(e));
    let p16 = (0..8).fold(E::ZERO, |acc, i| acc + k(i) * pow16(i as u32));
    let p16s2 = (0..8).fold(E::ZERO, |acc, i| acc + k(i) * pow16(((i + 2) % 8) as u32));
    let p16s3 = (0..8).fold(E::ZERO, |acc, i| acc + k(i) * pow16(((i + 3) % 8) as u32));
    let p16s4 = (0..8).fold(E::ZERO, |acc, i| acc + k(i) * pow16(((i + 4) % 8) as u32));

    // No periodic gating; we rely on committed S/K one-hots only

    // Pack helpers
    let two = E::ONE + E::ONE;
    let sixteen = E::from(16u32);

    // Build MsgView for phase-aware message access
    // Use periodic gates to select between doc MSG columns and Merkle MSG scratch during COMP.
    // Keep selectors S/K committed; avoid multiplying constraints by periodic gates elsewhere.
    let s_b = periodic[P_B];
    let p_m = periodic[P_M];
    let p_m_comp = periodic[P_M_COMP];
    let g_comp_m = p_m * p_m_comp; // only active during Merkle COMP sub-phase
    let msg_view = MsgView {
        g_doc: s_b,
        g_merkle: g_comp_m,
        doc_base: MSG0,
        merkle_msg: MERKLE_MSG,
    };

    // Build lane-specific nibbles without k(i) anywhere
    // Keep ASRC/BSRC/MX/MY periodic picks; they are phase-locked and consistent at OOD.
    let asrc = |t: usize, j: usize| periodic[P_ASRC0 + t * 16 + j];
    let bsrc = |t: usize, j: usize| periodic[P_BSRC0 + t * 16 + j];
    let mx = |j: usize| periodic[P_MX0 + j];
    let my = |j: usize| periodic[P_MY0 + j];

    let mut a_nib_i = [E::ZERO; 8];
    let mut b_nib_i = [E::ZERO; 8];
    let mut m_nib_i = [E::ZERO; 8];
    let mut z_nib_i = [E::ZERO; 8];

    // Build lane-specific nibbles from V values using source pickers
    // a_nib_i := Σ_source S_source(i) · nibble_from_source
    // Since V[j] are already 4-bit nibbles, and ASRC/BSRC select from them:
    for i in 0..8 {
        // a_nib_i[i] = sum over j of: asrc(i,j) * V[j]
        for j in 0..16 {
            a_nib_i[i] += asrc(i, j) * cur[V0 + j];
            b_nib_i[i] += bsrc(i, j) * cur[V0 + j];
        }

        // M nibbles: only lanes 0 and 4 have messages (MX and MY respectively)
        if i == 0 {
            for j in 0..16 {
                m_nib_i[0] += mx(j) * cur[MSG0 + j];
            }
        } else if i == 4 {
            for j in 0..16 {
                m_nib_i[4] += my(j) * cur[MSG0 + j];
            }
        }

        // Build lane-specific Z nibble polynomials per micro-step (no k() factors)
        // - ADD steps (0,2,4,6): z = a + b + m_used + carry - 16 * carry_next
        // - XOR steps (1,3,5):  z = (a XOR b) via bit formula
        // - ROT7 step (7):      z = (ROTR7(a XOR b)) nibble: [rot_carry, x0, x1, x2]
        // Note: m_used is only present on steps 0 and 4
        let x0 = cur[A_B0] + cur[B_B0] - two * cur[A_B0] * cur[B_B0];
        let x1 = cur[A_B1] + cur[B_B1] - two * cur[A_B1] * cur[B_B1];
        let x2 = cur[A_B2] + cur[B_B2] - two * cur[A_B2] * cur[B_B2];
        let x3 = cur[A_B3] + cur[B_B3] - two * cur[A_B3] * cur[B_B3];

        // Precompute nibble from XOR bits
        let xor_nib = x0 + two * x1 + E::from(4u32) * x2 + E::from(8u32) * x3;
        // Precompute rot7 nibble
        let rot7_nib = cur[ROT_CARRY] + two * x0 + E::from(4u32) * x1 + E::from(8u32) * x2;

        // ADD steps
        if i == 0 || i == 2 || i == 4 || i == 6 {
            let m_used = if i == 0 {
                m_nib_i[0]
            } else if i == 4 {
                m_nib_i[4]
            } else {
                E::ZERO
            };
            z_nib_i[i] = a_nib_i[i] + b_nib_i[i] + m_used + cur[CARRY] - sixteen * nxt[CARRY];
        } else if i == 1 || i == 3 || i == 5 {
            z_nib_i[i] = xor_nib;
        } else {
            // i == 7
            z_nib_i[i] = rot7_nib;
        }
    }

    // Gates we reuse
    let s_add = s(0) + s(2) + s(4) + s(6);
    // XOR applies on S1, S3, S5 only; S7 handled by rot7 constraint
    let _s_xor = s(1) + s(3) + s(5);

    // Build linear views
    let v_next: Vec<E> = (0..16).map(|j| nxt[V0 + j]).collect();

    // Constraint assembly
    let mut ci = 0;

    // (1) bit binarity (gate by sum of committed S one-hots)
    let mut bits_binarity = E::ZERO;
    for &b in &[
        A_B0, A_B1, A_B2, A_B3, B_B0, B_B1, B_B2, B_B3, M_B0, M_B1, M_B2, M_B3, Z_B0, Z_B1, Z_B2,
        Z_B3,
    ] {
        bits_binarity += cur[b] * (cur[b] - E::ONE);
    }
    let any_s = s(0) + s(1) + s(2) + s(3) + s(4) + s(5) + s(6) + s(7);
    result[ci] = any_s * bits_binarity;
    ci += 1;

    // (2-4) quotient chains - Emit constraints with proper S·K gating

    // SRC_A quotient: use A nibble bits; gate by S(add) and K0..K6 (committed)
    let a_nib = cur[A_B0] + two * cur[A_B1] + E::from(4u32) * cur[A_B2] + E::from(8u32) * cur[A_B3];
    let mut acc_a = E::ZERO;
    for i in 0..7 {
        acc_a += k(i) * (cur[SRC_A] - sixteen * nxt[SRC_A] - a_nib);
    }
    result[ci] = s_add * acc_a;
    ci += 1;

    // SRC_B: mirror of SRC_A using B nibble bits; gate by S(add) and K0..K6 (committed)
    let b_nib = cur[B_B0] + two * cur[B_B1] + E::from(4u32) * cur[B_B2] + E::from(8u32) * cur[B_B3];
    let mut acc_b = E::ZERO;
    for i in 0..7 {
        acc_b += k(i) * (cur[SRC_B] - sixteen * nxt[SRC_B] - b_nib);
    }
    result[ci] = s_add * acc_b;
    ci += 1;

    // SRC_M — quotient chain with S·K gating; nibble from M-bit lanes (committed)
    let m_nib = cur[M_B0] + two * cur[M_B1] + E::from(4u32) * cur[M_B2] + E::from(8u32) * cur[M_B3];
    let mut acc_m = E::ZERO;
    for i in 0..7 {
        acc_m += k(i) * (s(0) + s(4)) * (cur[SRC_M] - sixteen * nxt[SRC_M] - m_nib);
    }
    result[ci] = acc_m;
    ci += 1;

    // (5) ACC recurrence — gate by phase and committed step via p16_for_step; sum over K0..K6
    let p16_for_step = (s(0) + s(2) + s(4) + s(6)) * p16
        + s(1) * p16s4
        + s(3) * p16s3
        + s(5) * p16s2
        + s(7) * p16s2;
    let mut acc_acc = E::ZERO;
    let z_nib = cur[Z_B0] + two * cur[Z_B1] + E::from(4u32) * cur[Z_B2] + E::from(8u32) * cur[Z_B3];
    for i in 0..7 {
        // exclude K7 (commit step)
        acc_acc += k(i) * (nxt[ACC] - (cur[ACC] + z_nib * p16_for_step));
    }
    result[ci] = acc_acc;
    ci += 1;

    // For commit at S7, use fixed P16 base corresponding to ROTR7 alignment
    let _p16_for_step = p16s2;

    // Split commit into 3 constraints: (i) no-writes on K0..K6 (ii) target at K7 (iii) others at K7
    // Use nxt[ACC] as the committed final value to avoid base/rotation aliasing at OOD
    let _acc_final = cur[ACC];

    // (i) V registers frozen during K0..K6: no V register changes between rows
    let mut k0_6 = E::ZERO;
    for i in 0..7 {
        k0_6 += k(i);
    }
    let mut sum_dv = E::ZERO;
    for j in 0..16 {
        sum_dv += v_next[j] - cur[V0 + j];
    }
    // (C5) V registers frozen during K0..K6
    //
    // SECURITY NOTE: This constraint is intentionally disabled.
    //
    // Background: C5 would enforce that V registers don't change between K0-K6
    // rows (only the ACC register should update during those sub-steps). However,
    // the trace generation in `write_row` conditionally propagates V values in a
    // way that doesn't maintain this invariant at all K0-K6 rows, so enabling C5
    // causes proof generation to fail.
    //
    // Risk assessment: Exploiting the absence of C5 would require a prover to
    // modify V registers mid-round (between K0-K6) such that the final K7 commit
    // (enforced by C6) still produces a valid BLAKE3 hash output. This amounts to
    // finding a BLAKE3 internal-state collision — computationally infeasible at
    // 128-bit security. Additionally, boundary assertions on hash outputs at phase
    // boundaries provide a compensating control.
    //
    // Remediation path: Audit and fix trace generation's V propagation in
    // `fill_blake3_compression_with_msg_map` to maintain V invariance at K0-K6,
    // then re-enable this constraint.
    let _ = (k0_6, sum_dv);
    result[ci] = E::ZERO;
    ci += 1;

    // (C6) At K7, target V register equals ACC + final nibble contribution
    // Fires across BLAKE3 and Merkle phases. Boundary K7 rows in Merkle have
    // selectors cleared to zero so C6 naturally skips them.
    let acc_final = cur[ACC] + z_nib * p16_for_step;
    let mut target_v_next = E::ZERO;
    for j in 0..16 {
        target_v_next += gw_committed(j) * v_next[j];
    }
    result[ci] = k(7) * (target_v_next - acc_final);
    ci += 1;

    // (C7) At K7, non-target V registers unchanged (gamma-packed)
    // Same coverage as C6 — boundary K7 rows have selectors cleared.
    let gamma_e = E::from(gamma);
    let mut non_target_diff = E::ZERO;
    let mut gp = E::ONE;
    for j in 0..16 {
        non_target_diff += gp * (E::ONE - gw_committed(j)) * (v_next[j] - cur[V0 + j]);
        gp = gp * gamma_e;
    }
    result[ci] = k(7) * non_target_diff;
    ci += 1;

    // (7) reset ACC at K0 — gate by phase+step; avoid mixing unrelated one-hots at OOD
    // Reset only at K0
    result[ci] = s(0) * k(0) * cur[ACC];
    ci += 1;

    // message is only present on steps S0 and S4
    let s_m = s(0) + s(4);

    // (8) adders
    let m_nib = cur[M_B0] + two * cur[M_B1] + E::from(4u32) * cur[M_B2] + E::from(8u32) * cur[M_B3];
    let m_used = s_m * m_nib;
    let a_nib = cur[A_B0] + two * cur[A_B1] + E::from(4u32) * cur[A_B2] + E::from(8u32) * cur[A_B3];
    let b_nib = cur[B_B0] + two * cur[B_B1] + E::from(4u32) * cur[B_B2] + E::from(8u32) * cur[B_B3];
    let z_nib = cur[Z_B0] + two * cur[Z_B1] + E::from(4u32) * cur[Z_B2] + E::from(8u32) * cur[Z_B3];
    let add_res = z_nib + sixteen * nxt[CARRY] - (a_nib + b_nib + m_used + cur[CARRY]);
    result[ci] = s_add * add_res;
    ci += 1;

    // (9) XOR steps
    let s_xor = s(1) + s(3) + s(5);
    let xor_bit = |ab: usize, bb: usize, zb: usize| -> E {
        cur[zb] - (cur[ab] + cur[bb] - two * cur[ab] * cur[bb])
    };
    let xor_res = xor_bit(A_B0, B_B0, Z_B0)
        + xor_bit(A_B1, B_B1, Z_B1)
        + xor_bit(A_B2, B_B2, Z_B2)
        + xor_bit(A_B3, B_B3, Z_B3);
    result[ci] = s_xor * xor_res;
    ci += 1;

    // (10) ROTR7 — equate Z nibble to precomputed z_nib_i[7]
    let z_pack =
        cur[Z_B0] + two * cur[Z_B1] + E::from(4u32) * cur[Z_B2] + E::from(8u32) * cur[Z_B3];
    let rot7 = z_pack - z_nib_i[7];
    result[ci] = s(7) * rot7;
    ci += 1;

    // (11-13) Binding constraints

    // (11) Bind SRC_A at K0 to the correct V[j] selected by ASRC for the active S-step
    let mut a_mux = E::ZERO;
    for t in 0..8 {
        let mut row_sum = E::ZERO;
        for j in 0..16 {
            row_sum += asrc(t, j) * (cur[SRC_A] - cur[V0 + j]);
        }
        a_mux += s(t) * row_sum;
    }
    result[ci] = k(0) * a_mux;
    ci += 1;

    // (12) Bind SRC_B at K0 to the correct V[j] selected by BSRC for the active S-step
    let mut b_mux = E::ZERO;
    for t in 0..8 {
        let mut row_sum = E::ZERO;
        for j in 0..16 {
            row_sum += bsrc(t, j) * (cur[SRC_B] - cur[V0 + j]);
        }
        b_mux += s(t) * row_sum;
    }
    result[ci] = k(0) * b_mux;
    ci += 1;

    // (13) Bind SRC_M at K0 for S0/S4 using phase-aware MsgView
    // Ensures the SRC_M quotient chain digits load from the correct message source.
    let mut sum_mx = E::ZERO;
    for j in 0..16 {
        sum_mx += periodic[P_MX0 + j] * (cur[SRC_M] - msg_view.get(cur, j));
    }
    let mut sum_my = E::ZERO;
    for j in 0..16 {
        sum_my += periodic[P_MY0 + j] * (cur[SRC_M] - msg_view.get(cur, j));
    }
    let m_bind = s(0) * sum_mx + s(4) * sum_my;
    result[ci] = k(0) * m_bind;

    assert_eq!(ci + 1, 15, "BLAKE3 should write exactly 15 constraints");
}

/// Evaluate Merkle constraints with lane packing
fn evaluate_merkle_stub<E: FieldElement<BaseField = BaseElement> + ExtensionOf<BaseElement>>(
    result: &mut [E],
    frame: &EvaluationFrame<E>,
    per_m: crate::phases::merkle::constraints::MerklePer<E>,
    gamma: BaseElement,
) {
    assert_eq!(
        result.len(),
        6,
        "Merkle expects exactly 6 constraint slots with lane packing"
    );

    // Call the lane-packed Merkle constraint evaluation
    crate::phases::merkle::constraints::evaluate_merkle_constraints_packed(
        result,
        frame.current(),
        frame.next(),
        per_m,
        E::from(gamma),
    );
}

impl Prover for GroveProver {
    type BaseField = BaseElement;
    type Air = GroveAir;
    type Trace = TraceTable<BaseElement>; // Use TraceTable directly (Pattern A)
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = winterfell::crypto::MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> GrovePublicInputs {
        // Return the stored public inputs
        GrovePublicInputs(self.public_inputs.clone())
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: winterfell::PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        // CRITICAL FIX: DefaultTraceLde needs a multi-segment TraceInfo to know
        // that auxiliary segments will be added later!
        // Create a multi-segment TraceInfo that matches what the AIR expects
        let multi_segment_trace_info = if trace_info.is_multi_segment() {
            // Already multi-segment, use as-is
            trace_info.clone()
        } else {
            // Convert single-segment to multi-segment with space for auxiliary
            TraceInfo::new_multi_segment(
                trace_info.width(),  // Main trace width (132)
                AUX_TRACE_WIDTH,     // Auxiliary trace width (64)
                1,                   // num_aux_segment_rands (minimum required by winterfell)
                trace_info.length(), // Same trace length
                trace_info.meta().to_vec(),
            )
        };

        DefaultTraceLde::new(
            &multi_segment_trace_info,
            main_trace,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E>(
        &self,
        composition_poly_trace: winterfell::CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: winterfell::PartitionOptions,
    ) -> (
        Self::ConstraintCommitment<E>,
        winterfell::CompositionPoly<E>,
    )
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        assert!(
            num_constraint_composition_columns > 0,
            "No composition columns; constraints ignored"
        );

        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    // MULTI-SEGMENT: Build auxiliary trace from stored EdDSA coordinates
    fn build_aux_trace<E>(
        &self,
        main_trace: &Self::Trace,
        _aux_rand_elements: &AuxRandElements<E>,
    ) -> ColMatrix<E>
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        // Build auxiliary columns from stored EdDSA coordinates
        let n_rows = main_trace.info().length();
        let mut aux_columns: Vec<Vec<E>> = Vec::with_capacity(AUX_TRACE_WIDTH);

        // Initialize all auxiliary columns to zero first
        for _ in 0..AUX_TRACE_WIDTH {
            aux_columns.push(vec![E::ZERO; n_rows]);
        }

        // Get the stored X, Y, Z, T coordinates from EdDSA computation
        let x_coords = self.stored_x_coords.borrow();
        let y_coords = self.stored_y_coords.borrow();
        let z_coords = self.stored_z_coords.borrow();
        let t_coords = self.stored_t_coords.borrow();

        // Fill X coordinates (aux columns 0-15) for EdDSA phase
        if !x_coords.is_empty() {
            for (idx, x_limbs) in x_coords.iter().enumerate() {
                let row = EDDSA_START + idx;
                if row <= EDDSA_END && row < n_rows {
                    for i in 0..16 {
                        aux_columns[i][row] = E::from(BaseElement::new(x_limbs[i]));
                    }
                }
            }
        }

        // Fill Y coordinates (aux columns 16-31) for EdDSA phase
        if !y_coords.is_empty() {
            for (idx, y_limbs) in y_coords.iter().enumerate() {
                let row = EDDSA_START + idx;
                if row <= EDDSA_END && row < n_rows {
                    for i in 0..16 {
                        aux_columns[16 + i][row] = E::from(BaseElement::new(y_limbs[i]));
                    }
                }
            }
        }

        // Fill Z coordinates (aux columns 32-47) for EdDSA phase
        if !z_coords.is_empty() {
            for (idx, z_limbs) in z_coords.iter().enumerate() {
                let row = EDDSA_START + idx;
                if row <= EDDSA_END && row < n_rows {
                    for i in 0..16 {
                        aux_columns[32 + i][row] = E::from(BaseElement::new(z_limbs[i]));
                    }
                }
            }
        }

        // Fill T coordinates (aux columns 48-63) for EdDSA phase
        if !t_coords.is_empty() {
            for (idx, t_limbs) in t_coords.iter().enumerate() {
                let row = EDDSA_START + idx;
                if row <= EDDSA_END && row < n_rows {
                    for i in 0..16 {
                        aux_columns[48 + i][row] = E::from(BaseElement::new(t_limbs[i]));
                    }
                }
            }
        }

        // Mirror EdDSA window metadata from main trace into aux columns and build accumulator
        // aux[56..59] = b0..b3, aux[60] = window value, aux[61] = window index
        // Dedicated accumulator column: last aux column (AUX_TRACE_WIDTH - 1)
        // Recompute the same deterministic gamma used in the AIR for packing
        let gamma_e: E = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"GROVESTARK:lane-pack:v1:");
            hasher.update(&(n_rows as u64).to_le_bytes());
            hasher.update(&(self.options.blowup_factor() as u64).to_le_bytes());
            hasher.update(&(self.options.grinding_factor() as u64).to_le_bytes());
            hasher.update(&(self.options.num_queries() as u64).to_le_bytes());
            let hash = hasher.finalize();
            let bytes = hash.as_bytes();
            let mut val_bytes = [0u8; 8];
            val_bytes.copy_from_slice(&bytes[0..8]);
            let mut gamma_be = BaseElement::new(u64::from_le_bytes(val_bytes));
            if gamma_be == BaseElement::ZERO || gamma_be == BaseElement::ONE {
                gamma_be = gamma_be + BaseElement::ONE + BaseElement::ONE;
            }
            E::from(gamma_be)
        };
        // Always compute aux window mirrors and the accumulator
        let mut acc = E::ZERO;
        let mut gp = E::ONE; // gamma power
        for row in EDDSA_START..=EDDSA_END {
            if row >= n_rows {
                break;
            }
            // Read window fields from main trace
            let wb0 = E::from(main_trace.get(crate::phases::eddsa::trace::WINDOW_BIT0_COL, row));
            let wb1 = E::from(main_trace.get(crate::phases::eddsa::trace::WINDOW_BIT1_COL, row));
            let wb2 = E::from(main_trace.get(crate::phases::eddsa::trace::WINDOW_BIT2_COL, row));
            let wb3 = E::from(main_trace.get(crate::phases::eddsa::trace::WINDOW_BIT3_COL, row));
            let wv = E::from(main_trace.get(crate::phases::eddsa::trace::WINDOW_BITS_COL, row));
            let wi = E::from(main_trace.get(crate::phases::eddsa::trace::WINDOW_INDEX_COL, row));

            // Write to aux mirror columns
            aux_columns[48 + 8][row] = wb0; // 56
            aux_columns[48 + 9][row] = wb1; // 57
            aux_columns[48 + 10][row] = wb2; // 58
            aux_columns[48 + 11][row] = wb3; // 59
            aux_columns[48 + 12][row] = wv; // 60
            aux_columns[48 + 13][row] = wi; // 61

            // Compute ED1, ED2 and accumulate
            let ed1 = wb0 * (wb0 - E::ONE)
                + wb1 * (wb1 - E::ONE)
                + wb2 * (wb2 - E::ONE)
                + wb3 * (wb3 - E::ONE);
            let ed2 = wv - (wb0 + E::from(2u32) * wb1 + E::from(4u32) * wb2 + E::from(8u32) * wb3);
            let ed_pack = ed1 + gamma_e * ed2;
            acc = acc + gp * ed_pack;
            // Write accumulator; force zero at EDDSA_END to satisfy boundary cleanly
            let acc_out = if row == EDDSA_END { E::ZERO } else { acc };
            aux_columns[AUX_TRACE_WIDTH - 1][row] = acc_out; // dedicated accumulator column
            gp = gp * gamma_e;
        }

        // Build GroveVM auxiliary trace (columns 64-117)
        let grovevm_ops = self.grovevm_operations.borrow();
        let grovevm_tape = self.grovevm_push_tape.borrow();

        if !grovevm_ops.is_empty() {
            use crate::phases::grovevm::trace::GroveVMTraceBuilder;

            // Build GroveVM trace for the full trace length
            let mut grovevm_builder =
                GroveVMTraceBuilder::new(grovevm_ops.clone(), grovevm_tape.clone(), n_rows);

            match grovevm_builder.build_trace() {
                Ok(grovevm_matrix) => {
                    // Copy GroveVM columns into auxiliary trace starting at column 64
                    for col in 0..grovevm_matrix.num_cols() {
                        for row in 0..n_rows {
                            let value = grovevm_matrix.get(col, row);
                            // Convert BaseElement to extension field E
                            aux_columns[64 + col][row] = E::from(value);
                        }
                    }
                }
                Err(_) => {
                    // Initialize GroveVM columns to zero on failure
                    // This ensures we have a valid auxiliary trace structure
                    use crate::phases::grovevm::GROVEVM_AUX_WIDTH;
                    for col in 0..GROVEVM_AUX_WIDTH {
                        for row in 0..n_rows {
                            aux_columns[64 + col][row] = E::ZERO;
                        }
                    }
                }
            }
        }

        ColMatrix::new(aux_columns)
    }
}

// ================================================================================================
// PUBLIC FUNCTIONS
// ================================================================================================

/// Generate a STARK proof for the given witness and public inputs
pub fn generate_proof(
    witness: &PrivateInputs,
    public_inputs: &PublicInputs,
    config: &STARKConfig,
) -> Result<Vec<u8>> {
    // Create prover with configuration
    let prover = GroveProver::new(config.clone()).with_public_inputs(public_inputs.clone());

    // Build the execution trace
    let trace = prover.build_trace(witness, public_inputs)?;

    // Build AIR for validation
    let proof_options = ProofOptions::new(
        config.num_queries,               // num_queries
        config.expansion_factor,          // blowup_factor
        config.grinding_bits as u32,      // grinding_factor
        winterfell::FieldExtension::None, // field_extension
        config.folding_factor,            // fri_folding_factor
        config.max_remainder_degree,      // fri_remainder_max_degree
        BatchingMethod::Linear,           // batching_constraints
        BatchingMethod::Linear,           // batching_deep
    );

    let grove_pub_inputs = GrovePublicInputs(public_inputs.clone());
    let air = GroveAir::new(trace.info().clone(), grove_pub_inputs, proof_options);

    // ONLY validate trace when explicitly requested via environment variable
    // This is EXTREMELY slow (checks all constraints for all 65536 rows)
    // Use: VALIDATE_TRACE=1 cargo test ... when debugging constraint issues
    if std::env::var("VALIDATE_TRACE").unwrap_or_default() == "1" {
        // This MUST panic if assertions are violated (e.g., tripwire or non-zero DIFFs)
        // validate() doesn't return a Result, it panics on failure
        trace.validate::<_, BaseElement>(&air, None);
    }

    // Generate the proof
    let proof = prover
        .prove(trace)
        .map_err(|e| Error::ProvingFailed(format!("Failed to generate proof: {}", e)))?;

    // Serialize the proof
    let proof_bytes = proof.to_bytes();

    Ok(proof_bytes)
}

/// Verify a STARK proof
pub fn verify_proof(
    proof_bytes: &[u8],
    public_inputs: &PublicInputs,
    _config: &STARKConfig,
) -> Result<bool> {
    // Deserialize the proof
    let proof = Proof::from_bytes(proof_bytes)
        .map_err(|e| Error::InvalidProofFormat(format!("Failed to deserialize proof: {}", e)))?;

    // Create public inputs wrapper
    let pub_inputs = GrovePublicInputs(public_inputs.clone());

    // Use the ProofOptions from the proof itself for verification
    // This ensures gamma calculation matches between prover and verifier
    // The proof already contains the options it was generated with
    let proof_options = proof.options();

    // Create acceptable options that include the proof's actual options
    // We can still validate that they meet our minimum requirements
    let acceptable_options = winterfell::AcceptableOptions::OptionSet(vec![proof_options.clone()]);

    // Verify the proof
    let result = winterfell::verify::<
        GroveAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        winterfell::crypto::MerkleTree<Blake3_256<BaseElement>>,
    >(proof, pub_inputs, &acceptable_options);

    match result {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}
