use crate::crypto::edwards_arithmetic::ExtendedPoint;
use crate::crypto::scalar_mult_correct;
use crate::stark_winterfell::{T_COLS, X_COLS, Y_COLS, Z_COLS};
use winterfell::math::fields::f64::BaseElement;

/// Store X, Y, Z, T coordinates during EdDSA trace generation
pub struct EddsaAuxStorage {
    pub x_coords: Vec<[u64; 16]>,
    pub y_coords: Vec<[u64; 16]>,
    pub z_coords: Vec<[u64; 16]>,
    pub t_coords: Vec<[u64; 16]>,
}

impl Default for EddsaAuxStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl EddsaAuxStorage {
    pub fn new() -> Self {
        Self {
            x_coords: Vec::new(),
            y_coords: Vec::new(),
            z_coords: Vec::new(),
            t_coords: Vec::new(),
        }
    }

    /// Add a point's X, Y, Z, T coordinates to storage
    pub fn store_point(&mut self, point: &ExtendedPoint) {
        self.x_coords.push(point.x);
        self.y_coords.push(point.y);
        self.z_coords.push(point.z);
        self.t_coords.push(point.t);
    }

    /// Get the number of stored points
    pub fn len(&self) -> usize {
        self.z_coords.len()
    }
}

/// Helper functions for writing identity point
fn write_limbs_u16(
    trace: &mut [Vec<BaseElement>],
    cols: &[usize; 16],
    row: usize,
    limbs: &[u16; 16],
) {
    for i in 0..16 {
        trace[cols[i]][row] = BaseElement::new(limbs[i] as u64);
    }
}

fn one_limbs() -> [u16; 16] {
    let mut o = [0u16; 16];
    o[0] = 1;
    o
}

fn zero_limbs() -> [u16; 16] {
    [0u16; 16]
}

fn write_identity_row(trace: &mut [Vec<BaseElement>], row: usize) {
    write_limbs_u16(trace, &X_COLS, row, &zero_limbs());

    // Write Y = 1, but skip Y[2] (column 54) which conflicts with SEL_FINAL
    let y_limbs = one_limbs();
    for i in 0..16 {
        if i != 2 {
            // Skip Y[2] to avoid SEL_FINAL conflict
            trace[Y_COLS[i]][row] = BaseElement::new(y_limbs[i] as u64);
        }
    }

    write_limbs_u16(trace, &Z_COLS, row, &one_limbs());

    // Write T = 0, but skip T[5] (column 53) which is SEL_FINAL
    let t_limbs = zero_limbs();
    for i in 0..16 {
        if i != 5 {
            // Skip T[5] to avoid overwriting SEL_FINAL
            trace[T_COLS[i]][row] = BaseElement::new(t_limbs[i] as u64);
        }
    }
}

/// Modified version of fill_eddsa_phase that returns Z and T coordinates
pub fn fill_eddsa_phase_with_aux(
    trace: &mut [Vec<BaseElement>],
    start_row: usize,
    witness: &crate::types::PrivateInputs,
    _public_inputs: &crate::types::PublicInputs,
) -> crate::error::Result<EddsaAuxStorage> {
    use crate::crypto::edwards_arithmetic::{is_identity_projective, Ed25519Constants};
    use crate::phases::eddsa::trace::{
        bytes_to_limbs, store_extended_point, H_SCALAR_COLS, PHASE_SELECTOR_COL, S_SCALAR_COLS,
        WINDOW_BIT0_COL, WINDOW_BIT1_COL, WINDOW_BIT2_COL, WINDOW_BIT3_COL, WINDOW_BITS_COL,
        WINDOW_INDEX_COL,
    };
    use crate::stark_winterfell::EDDSA_END;

    let mut aux_storage = EddsaAuxStorage::new();

    // Convert 32-byte arrays to 16-bit limb representation
    let s_scalar = bytes_to_limbs(&witness.signature_s);
    let h_scalar = bytes_to_limbs(&witness.hash_h);

    // Use the precomputed extended coordinates from the witness
    let r_x = bytes_to_limbs(&witness.r_extended_x);
    let r_y = bytes_to_limbs(&witness.r_extended_y);
    let r_z = bytes_to_limbs(&witness.r_extended_z);
    let r_t = bytes_to_limbs(&witness.r_extended_t);

    let a_x = bytes_to_limbs(&witness.a_extended_x);
    let a_y = bytes_to_limbs(&witness.a_extended_y);
    let a_z = bytes_to_limbs(&witness.a_extended_z);
    let a_t = bytes_to_limbs(&witness.a_extended_t);

    // Initialize scalar columns at start
    for i in 0..16 {
        trace[S_SCALAR_COLS[i]][start_row] = BaseElement::new(s_scalar[i]);
        trace[H_SCALAR_COLS[i]][start_row] = BaseElement::new(h_scalar[i]);
    }

    // Create extended points from the witness values
    let r_point = ExtendedPoint {
        x: r_x,
        y: r_y,
        z: r_z,
        t: r_t,
    };

    let a_point = ExtendedPoint {
        x: a_x,
        y: a_y,
        z: a_z,
        t: a_t,
    };

    // Convert points to the correct scalar mult module format
    let r_ext = scalar_mult_correct::convert_from_extended(&r_point);
    let a_ext = scalar_mult_correct::convert_from_extended(&a_point);

    // Get base point in correct format
    let constants = Ed25519Constants::new();
    let base_ext = scalar_mult_correct::convert_from_extended(&constants.base_point);

    // Convert scalars to bytes for the correct implementation
    let mut s_bytes = [0u8; 32];
    let mut h_bytes = [0u8; 32];

    for i in 0..16 {
        s_bytes[i * 2] = (s_scalar[i] & 0xFF) as u8;
        s_bytes[i * 2 + 1] = ((s_scalar[i] >> 8) & 0xFF) as u8;
        h_bytes[i * 2] = (h_scalar[i] & 0xFF) as u8;
        h_bytes[i * 2 + 1] = ((h_scalar[i] >> 8) & 0xFF) as u8;
    }

    // Debug logging only in debug builds
    #[cfg(debug_assertions)]
    {
        println!("🔍 STARK trace EdDSA computation:");
        println!("  s_bytes: {:02x?}...", &s_bytes[..8]);
        println!("  h_bytes: {:02x?}...", &h_bytes[..8]);
        println!(
            "  r_ext: x[0]={}, y[0]={}, z[0]={}, t[0]={}",
            r_ext.x[0], r_ext.y[0], r_ext.z[0], r_ext.t[0]
        );
        println!(
            "  a_ext: x[0]={}, y[0]={}, z[0]={}, t[0]={}",
            a_ext.x[0], a_ext.y[0], a_ext.z[0], a_ext.t[0]
        );
        println!(
            "  base_ext: x[0]={}, y[0]={}, z[0]={}, t[0]={}",
            base_ext.x[0], base_ext.y[0], base_ext.z[0], base_ext.t[0]
        );
    }

    // Use the correct scalar multiplication
    let final_ext =
        scalar_mult_correct::eddsa_verify_combine(&s_bytes, &h_bytes, &r_ext, &a_ext, &base_ext);

    // Convert back to ExtendedPoint format
    let cofactor_result = scalar_mult_correct::convert_to_extended(&final_ext);

    #[cfg(debug_assertions)]
    {
        println!(
            "  final_ext: x[0]={}, y[0]={}, z[0]={}, t[0]={}",
            final_ext.x[0], final_ext.y[0], final_ext.z[0], final_ext.t[0]
        );
        println!(
            "  cofactor_result: x[0]={}, y[0]={}, z[0]={}, t[0]={}",
            cofactor_result.x[0], cofactor_result.y[0], cofactor_result.z[0], cofactor_result.t[0]
        );
        println!(
            "  is_identity: {}",
            is_identity_projective(&cofactor_result)
        );
    }

    let mut current_row = start_row;

    // Phase 1: [s]B computation with actual scalar multiplication steps
    // Decompose s into 4-bit windows for multiplication
    let s_nibbles = scalar_mult_correct::decompose_radix16_windows_from_le_bytes(&s_bytes);

    // Precompute table [0*B .. 15*B] for base point
    let base_table = scalar_mult_correct::table_0_to_15(&base_ext);

    // Initialize accumulator to identity
    let mut acc_sb = scalar_mult_correct::ed_identity();

    // Process 64 windows from MSB to LSB
    for window_idx in (0..64).rev() {
        // Store window metadata
        trace[WINDOW_INDEX_COL][current_row] = BaseElement::new((63 - window_idx) as u64);
        let window_bits = s_nibbles[window_idx];
        trace[WINDOW_BITS_COL][current_row] = BaseElement::new(window_bits as u64);

        // Store bit decomposition (4-bit window) in main trace
        trace[WINDOW_BIT0_COL][current_row] = BaseElement::new((window_bits & 1) as u64);
        trace[WINDOW_BIT1_COL][current_row] = BaseElement::new(((window_bits >> 1) & 1) as u64);
        trace[WINDOW_BIT2_COL][current_row] = BaseElement::new(((window_bits >> 2) & 1) as u64);
        trace[WINDOW_BIT3_COL][current_row] = BaseElement::new(((window_bits >> 3) & 1) as u64);

        // Note: aux window mirroring is handled in build_aux_trace; do not write aux indices here

        trace[PHASE_SELECTOR_COL][current_row] = BaseElement::new(0); // Phase 0 = [s]B

        // Perform 4 doublings
        acc_sb = scalar_mult_correct::ed_double(&acc_sb);
        acc_sb = scalar_mult_correct::ed_double(&acc_sb);
        acc_sb = scalar_mult_correct::ed_double(&acc_sb);
        acc_sb = scalar_mult_correct::ed_double(&acc_sb);

        // Add table entry if window_bits != 0
        if window_bits != 0 {
            acc_sb = scalar_mult_correct::ed_add(&acc_sb, &base_table[window_bits as usize]);
        }

        // Convert to ExtendedPoint and store
        let acc_ext = scalar_mult_correct::convert_to_extended(&acc_sb);
        store_extended_point(trace, current_row, &acc_ext);
        aux_storage.store_point(&acc_ext);
        current_row += 1;
    }

    // Phase 2: [h]A computation with actual scalar multiplication steps
    // Decompose h into 4-bit windows for multiplication
    let h_nibbles = scalar_mult_correct::decompose_radix16_windows_from_le_bytes(&h_bytes);

    // Precompute table [0*A .. 15*A] for public key
    let a_table = scalar_mult_correct::table_0_to_15(&a_ext);

    // Initialize accumulator to identity
    let mut acc_ha = scalar_mult_correct::ed_identity();

    // Process 64 windows from MSB to LSB
    for window_idx in (0..64).rev() {
        // Store window metadata
        trace[WINDOW_INDEX_COL][current_row] = BaseElement::new((63 - window_idx) as u64);
        let window_bits = h_nibbles[window_idx];
        trace[WINDOW_BITS_COL][current_row] = BaseElement::new(window_bits as u64);

        // Store bit decomposition (4-bit window)
        trace[WINDOW_BIT0_COL][current_row] = BaseElement::new((window_bits & 1) as u64);
        trace[WINDOW_BIT1_COL][current_row] = BaseElement::new(((window_bits >> 1) & 1) as u64);
        trace[WINDOW_BIT2_COL][current_row] = BaseElement::new(((window_bits >> 2) & 1) as u64);
        trace[WINDOW_BIT3_COL][current_row] = BaseElement::new(((window_bits >> 3) & 1) as u64);

        trace[PHASE_SELECTOR_COL][current_row] = BaseElement::new(1); // Phase 1 = [h]A

        // Perform 4 doublings
        acc_ha = scalar_mult_correct::ed_double(&acc_ha);
        acc_ha = scalar_mult_correct::ed_double(&acc_ha);
        acc_ha = scalar_mult_correct::ed_double(&acc_ha);
        acc_ha = scalar_mult_correct::ed_double(&acc_ha);

        // Add table entry if window_bits != 0
        if window_bits != 0 {
            acc_ha = scalar_mult_correct::ed_add(&acc_ha, &a_table[window_bits as usize]);
        }

        // Convert to ExtendedPoint and store
        let acc_ext = scalar_mult_correct::convert_to_extended(&acc_ha);
        store_extended_point(trace, current_row, &acc_ext);
        aux_storage.store_point(&acc_ext);
        current_row += 1;
    }

    // Phase 3: Combine - Store the actual result
    trace[PHASE_SELECTOR_COL][current_row] = BaseElement::new(2); // Phase 2 = combine
    store_extended_point(trace, current_row, &cofactor_result);
    aux_storage.store_point(&cofactor_result);
    current_row += 1;

    // Phase 4: Already done in eddsa_verify_combine (x8), but add placeholder rows
    for _i in 0..3 {
        trace[PHASE_SELECTOR_COL][current_row] = BaseElement::new(3); // Phase 3 = x8
        store_extended_point(trace, current_row, &cofactor_result);
        aux_storage.store_point(&cofactor_result);
        current_row += 1;
    }

    // Check if the result is projective identity and write explicit identity
    let final_point = cofactor_result;

    #[cfg(debug_assertions)]
    {
        println!(
            "🔍 Identity check at row {}: is_identity = {}",
            EDDSA_END,
            is_identity_projective(&final_point)
        );
        println!(
            "  final_point: x[0]={}, y[0]={}, z[0]={}, t[0]={}",
            final_point.x[0], final_point.y[0], final_point.z[0], final_point.t[0]
        );
    }

    if is_identity_projective(&final_point) {
        // Explicitly write identity (0:1:1:0) at EDDSA_END
        #[cfg(debug_assertions)]
        println!("✅ Writing identity to row {}", EDDSA_END);
        write_identity_row(trace, EDDSA_END);

        // Verify what was actually written
        #[cfg(debug_assertions)]
        {
            println!("  Verification after write:");
            println!(
                "    trace[X_COLS[0]][{}] = {}",
                EDDSA_END,
                trace[X_COLS[0]][EDDSA_END].as_int()
            );
            println!(
                "    trace[Y_COLS[0]][{}] = {}",
                EDDSA_END,
                trace[Y_COLS[0]][EDDSA_END].as_int()
            );
            println!(
                "    trace[Z_COLS[0]][{}] = {}",
                EDDSA_END,
                trace[Z_COLS[0]][EDDSA_END].as_int()
            );
            println!(
                "    trace[T_COLS[0]][{}] = {}",
                EDDSA_END,
                trace[T_COLS[0]][EDDSA_END].as_int()
            );
        }

        aux_storage.store_point(&final_point);
    } else {
        // Signature verification failed - return error (unless skip_eddsa is enabled)
        #[cfg(not(feature = "skip_eddsa"))]
        {
            #[cfg(debug_assertions)]
            println!("❌ EdDSA verification failed - not identity!");
            return Err(crate::error::Error::InvalidSignature(
                "EdDSA signature verification failed: result is not identity".to_string(),
            ));
        }

        #[cfg(feature = "skip_eddsa")]
        {
            eprintln!("⚠️ SKIP_EDDSA: Bypassing EdDSA verification failure for FRI testing");
            // Store a dummy identity point to continue
            aux_storage.store_point(&ExtendedPoint {
                x: [0; 16],
                y: [1; 16],
                z: [1; 16],
                t: [0; 16],
            });
        }
    }

    // Fill remaining rows with final values
    #[cfg(debug_assertions)]
    println!(
        "📝 Filling rows {} to {} (exclusive) with values from row {}",
        current_row,
        EDDSA_END,
        current_row - 1
    );
    for row in current_row..EDDSA_END {
        for col in 0..trace.len() {
            trace[col][row] = trace[col][current_row - 1];
        }
        // Store the same final point for all remaining rows
        aux_storage.store_point(&final_point);
    }

    // Verify the identity wasn't overwritten
    #[cfg(debug_assertions)]
    {
        println!("🔍 Final verification of row {}:", EDDSA_END);
        println!(
            "    trace[Z_COLS[0]][{}] = {} (should be 1)",
            EDDSA_END,
            trace[Z_COLS[0]][EDDSA_END].as_int()
        );
    }

    Ok(aux_storage)
}
