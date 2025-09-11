// Single source of truth for column layout
// As per GUIDANCE.md recommendation

/// Main trace segment layout (width: 132)
pub struct LayoutMain {
    // BLAKE3 state (0-15)
    pub blake3_state: [usize; 16],
    // Message words (16-31)
    pub msg: [usize; 16],
    // Quotient/accumulator columns (32-35)
    pub acc: usize,
    pub src_a: usize,
    pub src_b: usize,
    pub src_m: usize,
    // BLAKE3 nibble lanes (36-51) - NO CONFLICT WITH EdDSA
    pub a_nibbles: [usize; 4], // A_B0-A_B3
    pub b_nibbles: [usize; 4], // B_B0-B_B3
    pub m_nibbles: [usize; 4], // M_B0-M_B3
    pub z_nibbles: [usize; 4], // Z_B0-Z_B3
    // Control columns (52-54)
    pub carry: usize,
    pub rot_carry: usize,
    pub sel_final: usize,
    // Merkle/misc columns (55-71)
    pub merkle_scratch: [usize; 17],
    // Owner ID as 8×32-bit limbs (72-79)
    pub owner_id: [usize; 8],
    // Identity ID as 8×32-bit limbs (80-87)
    pub identity_id: [usize; 8],
    // Difference columns (88-95)
    pub diff: [usize; 8],
    // Accumulator for diff (96)
    pub diff_acc: usize,
    // Phase selectors (97-99)
    pub sel_blake3: usize,
    pub sel_merkle: usize,
    pub sel_eddsa: usize,
    // Padding/reserved (100-131)
    pub reserved: [usize; 32],
}

/// Auxiliary trace segment layout (width: 119)
/// EdDSA (64 columns) + GroveVM (54 columns) + 1 accumulator column = 119 total
pub struct LayoutAux {
    // EdDSA coordinates (0-63)
    pub x: [usize; 16], // X coordinate limbs (0-15)
    pub y: [usize; 16], // Y coordinate limbs (16-31)
    pub z: [usize; 16], // Z coordinate limbs (32-47)
    pub t: [usize; 16], // T coordinate limbs (48-63)

    // GroveVM columns (64-117) - 54 columns total
    // Per phases/grovevm/types.rs layout:
    pub grovevm_op_push_h: usize,      // 64 - Push hash opcode
    pub grovevm_op_push_kv: usize,     // 65 - Push KV hash opcode
    pub grovevm_op_parent: usize,      // 66 - Parent opcode
    pub grovevm_op_child: usize,       // 67 - Child opcode
    pub grovevm_sp: usize,             // 68 - Stack pointer
    pub grovevm_tp: usize,             // 69 - Tape cursor
    pub grovevm_push_hash: [usize; 8], // 70-77 - Push tape input (8 u32 limbs)
    pub grovevm_stack: [usize; 40],    // 78-117 - Stack (5 slots × 8 limbs = 40)
}

/// Combined layout structure
pub struct Layout {
    pub main: LayoutMain,
    pub aux: LayoutAux,
}

/// The single source of truth for column indices
pub const LAYOUT: Layout = Layout {
    main: LayoutMain {
        // BLAKE3 state columns (0-15)
        blake3_state: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        // Message columns (16-31)
        msg: [
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ],
        // Quotient columns (32-35)
        acc: 32,
        src_a: 33,
        src_b: 34,
        src_m: 35,
        // BLAKE3 nibbles (36-51)
        a_nibbles: [36, 37, 38, 39],
        b_nibbles: [40, 41, 42, 43],
        m_nibbles: [44, 45, 46, 47],
        z_nibbles: [48, 49, 50, 51],
        // Control (52-54)
        carry: 52,
        rot_carry: 53,
        sel_final: 54,
        // Merkle scratch space (55-71)
        merkle_scratch: [
            55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71,
        ],
        // Identity binding (72-95)
        owner_id: [72, 73, 74, 75, 76, 77, 78, 79],
        identity_id: [80, 81, 82, 83, 84, 85, 86, 87],
        diff: [88, 89, 90, 91, 92, 93, 94, 95],
        // Diff accumulator (96)
        diff_acc: 96,
        // Phase selectors (97-99)
        sel_blake3: 97,
        sel_merkle: 98,
        sel_eddsa: 99,
        // Reserved/padding (100-131)
        reserved: [
            100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
            117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131,
        ],
    },
    aux: LayoutAux {
        // EdDSA coordinates (0-63)
        x: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        y: [
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ],
        z: [
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        ],
        t: [
            48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ],
        // GroveVM columns (64-117)
        grovevm_op_push_h: 64,
        grovevm_op_push_kv: 65,
        grovevm_op_parent: 66,
        grovevm_op_child: 67,
        grovevm_sp: 68,
        grovevm_tp: 69,
        grovevm_push_hash: [70, 71, 72, 73, 74, 75, 76, 77],
        grovevm_stack: [
            78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99,
            100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
            117,
        ],
    },
};

// Helper functions for backward compatibility during migration
impl LayoutMain {
    pub const fn v_col(i: usize) -> usize {
        LAYOUT.main.blake3_state[i]
    }

    pub const fn msg_col(i: usize) -> usize {
        LAYOUT.main.msg[i]
    }
}

impl LayoutAux {
    pub const fn x_col(i: usize) -> usize {
        LAYOUT.aux.x[i]
    }

    pub const fn y_col(i: usize) -> usize {
        LAYOUT.aux.y[i]
    }

    pub const fn z_col(i: usize) -> usize {
        LAYOUT.aux.z[i]
    }

    pub const fn t_col(i: usize) -> usize {
        LAYOUT.aux.t[i]
    }
}

// Constants for trace dimensions
pub const MAIN_TRACE_WIDTH: usize = 132;
pub const AUX_TRACE_WIDTH: usize = 119; // EdDSA (64) + GroveVM (54) + accumulator (1)
pub const TOTAL_TRACE_WIDTH: usize = MAIN_TRACE_WIDTH + AUX_TRACE_WIDTH;

// Phase boundaries (unchanged)
pub const BLAKE3_START: usize = 0;
pub const BLAKE3_END: usize = 3583;
pub const MERKLE_START: usize = 3584;
pub const MERKLE_END: usize = 19967;
pub const EDDSA_START: usize = 19968;
pub const EDDSA_END: usize = 52735;
pub const JOIN_ROW: usize = 16384;

// Validation function to ensure no overlaps
#[cfg(debug_assertions)]
pub fn validate_layout() {
    use std::collections::HashSet;

    // Check main segment for overlaps
    let mut main_used = HashSet::new();

    // Add all main columns
    for &col in &LAYOUT.main.blake3_state {
        assert!(
            main_used.insert(col),
            "Overlap in blake3_state at column {}",
            col
        );
    }
    for &col in &LAYOUT.main.msg {
        assert!(main_used.insert(col), "Overlap in msg at column {}", col);
    }
    assert!(main_used.insert(LAYOUT.main.acc), "Overlap at acc column");
    assert!(
        main_used.insert(LAYOUT.main.src_a),
        "Overlap at src_a column"
    );
    assert!(
        main_used.insert(LAYOUT.main.src_b),
        "Overlap at src_b column"
    );
    assert!(
        main_used.insert(LAYOUT.main.src_m),
        "Overlap at src_m column"
    );

    for &col in &LAYOUT.main.a_nibbles {
        assert!(
            main_used.insert(col),
            "Overlap in a_nibbles at column {}",
            col
        );
    }
    for &col in &LAYOUT.main.b_nibbles {
        assert!(
            main_used.insert(col),
            "Overlap in b_nibbles at column {}",
            col
        );
    }
    for &col in &LAYOUT.main.m_nibbles {
        assert!(
            main_used.insert(col),
            "Overlap in m_nibbles at column {}",
            col
        );
    }
    for &col in &LAYOUT.main.z_nibbles {
        assert!(
            main_used.insert(col),
            "Overlap in z_nibbles at column {}",
            col
        );
    }

    assert!(
        main_used.insert(LAYOUT.main.carry),
        "Overlap at carry column"
    );
    assert!(
        main_used.insert(LAYOUT.main.rot_carry),
        "Overlap at rot_carry column"
    );
    assert!(
        main_used.insert(LAYOUT.main.sel_final),
        "Overlap at sel_final column"
    );

    for &col in &LAYOUT.main.merkle_scratch {
        assert!(
            main_used.insert(col),
            "Overlap in merkle_scratch at column {}",
            col
        );
    }

    for &col in &LAYOUT.main.owner_id {
        assert!(
            main_used.insert(col),
            "Overlap in owner_id at column {}",
            col
        );
    }
    for &col in &LAYOUT.main.identity_id {
        assert!(
            main_used.insert(col),
            "Overlap in identity_id at column {}",
            col
        );
    }
    for &col in &LAYOUT.main.diff {
        assert!(main_used.insert(col), "Overlap in diff at column {}", col);
    }

    assert!(
        main_used.insert(LAYOUT.main.diff_acc),
        "Overlap at diff_acc column"
    );
    assert!(
        main_used.insert(LAYOUT.main.sel_blake3),
        "Overlap at sel_blake3 column"
    );
    assert!(
        main_used.insert(LAYOUT.main.sel_merkle),
        "Overlap at sel_merkle column"
    );
    assert!(
        main_used.insert(LAYOUT.main.sel_eddsa),
        "Overlap at sel_eddsa column"
    );

    for &col in &LAYOUT.main.reserved {
        assert!(
            main_used.insert(col),
            "Overlap in reserved at column {}",
            col
        );
    }

    // Check aux segment for overlaps
    let mut aux_used = HashSet::new();

    for &col in &LAYOUT.aux.x {
        assert!(aux_used.insert(col), "Overlap in aux.x at column {}", col);
    }
    for &col in &LAYOUT.aux.y {
        assert!(aux_used.insert(col), "Overlap in aux.y at column {}", col);
    }
    for &col in &LAYOUT.aux.z {
        assert!(aux_used.insert(col), "Overlap in aux.z at column {}", col);
    }
    for &col in &LAYOUT.aux.t {
        assert!(aux_used.insert(col), "Overlap in aux.t at column {}", col);
    }

    // GroveVM columns validation
    assert!(
        aux_used.insert(LAYOUT.aux.grovevm_op_push_h),
        "Overlap at grovevm_op_push_h column"
    );
    assert!(
        aux_used.insert(LAYOUT.aux.grovevm_op_push_kv),
        "Overlap at grovevm_op_push_kv column"
    );
    assert!(
        aux_used.insert(LAYOUT.aux.grovevm_op_parent),
        "Overlap at grovevm_op_parent column"
    );
    assert!(
        aux_used.insert(LAYOUT.aux.grovevm_op_child),
        "Overlap at grovevm_op_child column"
    );
    assert!(
        aux_used.insert(LAYOUT.aux.grovevm_sp),
        "Overlap at grovevm_sp column"
    );
    assert!(
        aux_used.insert(LAYOUT.aux.grovevm_tp),
        "Overlap at grovevm_tp column"
    );

    for &col in &LAYOUT.aux.grovevm_push_hash {
        assert!(
            aux_used.insert(col),
            "Overlap in grovevm_push_hash at column {}",
            col
        );
    }

    for &col in &LAYOUT.aux.grovevm_stack {
        assert!(
            aux_used.insert(col),
            "Overlap in grovevm_stack at column {}",
            col
        );
    }

    println!("✅ Layout validation passed: No overlaps detected");
}
