//! BLAKE3 trace generation

use crate::stark_winterfell::*;
use crate::types::PrivateInputs;
use crate::types::PublicInputs;
use winterfell::math::fields::f64::BaseElement;
use winterfell::math::FieldElement;

/// Fill the BLAKE3 phase of the trace
pub fn fill_blake3_phase(
    trace: &mut [Vec<BaseElement>],
    witness: &PrivateInputs,
    _public_inputs: &PublicInputs,
) -> Result<(), crate::error::Error> {
    // Extract message from witness (document CBOR)
    let mut message = [0u32; 16];

    // Convert CBOR bytes to 32-bit words
    // For now, just pad with zeros if not enough data
    for i in 0..16 {
        let mut word = 0u32;
        for j in 0..4 {
            let byte_idx = i * 4 + j;
            if byte_idx < witness.document_cbor.len() {
                word |= (witness.document_cbor[byte_idx] as u32) << (j * 8);
            }
        }
        message[i] = word;
    }

    // Run the BLAKE3 compression
    fill_blake3_compression(trace, 0, &message);

    Ok(())
}

/// Run a complete BLAKE3 compression (7 rounds × 8 lanes × 8 micro-steps × 8 nibbles = 3584 rows)
pub fn fill_blake3_compression(
    trace: &mut [Vec<BaseElement>],
    start_row: usize,
    message: &[u32; 16], // Pass message from caller
) {
    // Default: use standard MSG columns (16-31)
    fill_blake3_compression_with_msg_map(trace, start_row, message, |i| {
        crate::stark_winterfell::MSG0 + i
    })
}

/// Parameterized BLAKE3 compression with custom message column mapping
pub fn fill_blake3_compression_with_msg_map(
    trace: &mut [Vec<BaseElement>],
    start_row: usize,
    message: &[u32; 16],
    msg_map: impl Fn(usize) -> usize, // maps 0..15 -> column index
) {
    // BLAKE3 IV (split into 32-bit words)
    let mut v = [
        0x6A09E667u32,
        0xF3BCC908u32,
        0xBB67AE85u32,
        0x84CAA73Bu32,
        0x3C6EF372u32,
        0xFE94F82Bu32,
        0xA54FF53Au32,
        0x5F1D36F1u32,
        0x510E527Fu32,
        0xADE682D1u32,
        0x9B05688Cu32,
        0x2B3E6C1Fu32,
        0x1F83D9ABu32,
        0xFB41BD6Bu32,
        0x5BE0CD19u32,
        0x137E2179u32,
    ];

    // Use the message passed from caller
    let m = *message;

    // Message schedule for 7 rounds
    const MSG_SCHEDULE: [[usize; 16]; 7] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
        [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
        [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
        [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
        [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
        [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
    ];

    // Initialize V and MSG values at the first row only
    // V values will be propagated by the commit logic
    for i in 0..16 {
        trace[V0 + i][start_row] = BaseElement::new(v[i] as u64);
        trace[msg_map(i)][start_row] = BaseElement::new(m[i] as u64);
    }

    // Initialize auxiliary columns to zero for all rows
    for row in start_row..(start_row + 3584) {
        // MSG values stay constant throughout, using the provided mapping
        for i in 0..16 {
            trace[msg_map(i)][row] = BaseElement::new(m[i] as u64);
        }
        // Initialize auxiliary columns
        trace[ACC][row] = BaseElement::ZERO;
        trace[SRC_A][row] = BaseElement::ZERO;
        trace[SRC_B][row] = BaseElement::ZERO;
        trace[SRC_M][row] = BaseElement::ZERO;
        for i in 0..4 {
            trace[A_B0 + i][row] = BaseElement::ZERO;
            trace[B_B0 + i][row] = BaseElement::ZERO;
            trace[M_B0 + i][row] = BaseElement::ZERO;
            trace[Z_B0 + i][row] = BaseElement::ZERO;
        }
        trace[CARRY][row] = BaseElement::ZERO;
        trace[ROT_CARRY][row] = BaseElement::ZERO;
        // Initialize committed commit-target selector columns to zero
        for i in 0..16 {
            trace[COMMIT_SEL_COLS[i]][row] = BaseElement::ZERO;
        }
        // Initialize committed step selectors S0..S7 to zero
        for t in 0..8 {
            trace[COMMIT_STEP_SEL_COLS[t]][row] = BaseElement::ZERO;
        }
        // Initialize committed nibble selectors K0..K7 to zero
        for k in 0..8 {
            trace[COMMIT_K_SEL_COLS[k]][row] = BaseElement::ZERO;
        }
        // Initialize ACC_FINAL_COMMIT, COMMIT_ROW_MASK, and COMMIT_DIFF columns to zero
        trace[ACC_FINAL_COMMIT_COL][row] = BaseElement::ZERO;
        trace[COMMIT_ROW_MASK_COL][row] = BaseElement::ZERO;
        trace[COMMIT_DIFF_COL][row] = BaseElement::ZERO;
    }

    let mut row = start_row;

    // Process 7 rounds
    for round in 0..7 {
        let schedule = MSG_SCHEDULE[round];

        // Column lanes: (0,4,8,12), (1,5,9,13), (2,6,10,14), (3,7,11,15)
        for i in 0..4 {
            let (a, b, c, d) = (i, i + 4, i + 8, i + 12);
            let mx = m[schedule[2 * i]];
            let my = m[schedule[2 * i + 1]];
            run_lane(trace, &mut row, &mut v, a, b, c, d, mx, my);
        }

        // Diagonal lanes: (0,5,10,15), (1,6,11,12), (2,7,8,13), (3,4,9,14)
        const DIAG: [[usize; 4]; 4] =
            [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]];
        for i in 0..4 {
            let (a, b, c, d) = (DIAG[i][0], DIAG[i][1], DIAG[i][2], DIAG[i][3]);
            let mx = m[schedule[8 + 2 * i]];
            let my = m[schedule[8 + 2 * i + 1]];
            run_lane(trace, &mut row, &mut v, a, b, c, d, mx, my);
        }
    }
}

/// Run one lane (8 micro-steps × 8 nibbles = 64 rows)
fn run_lane(
    trace: &mut [Vec<BaseElement>],
    row: &mut usize,
    v: &mut [u32; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    mx: u32,
    my: u32,
) {
    // S0: v[a] += v[b] + mx
    run_add(trace, row, v, a, b, mx, 0);

    // S1: v[d] = rotr16(v[d] ^ v[a])
    run_xor_rotr(trace, row, v, d, a, 16, 1);

    // S2: v[c] += v[d]
    run_add(trace, row, v, c, d, 0, 2);

    // S3: v[b] = rotr12(v[b] ^ v[c])
    run_xor_rotr(trace, row, v, b, c, 12, 3);

    // S4: v[a] += v[b] + my
    run_add(trace, row, v, a, b, my, 4);

    // S5: v[d] = rotr8(v[d] ^ v[a])
    run_xor_rotr(trace, row, v, d, a, 8, 5);

    // S6: v[c] += v[d]
    run_add(trace, row, v, c, d, 0, 6);

    // S7: v[b] = rotr7(v[b] ^ v[c])
    run_xor_rotr(trace, row, v, b, c, 7, 7);
}

/// S0/S2/S4/S6: Addition micro-step (8 nibbles)
fn run_add(
    trace: &mut [Vec<BaseElement>],
    row: &mut usize,
    v: &mut [u32; 16],
    target: usize,
    source: usize,
    msg: u32,
    s_index: usize,
) {
    let a_val = v[target];
    let b_val = v[source];
    let result = a_val.wrapping_add(b_val).wrapping_add(msg);

    // Decompose into nibbles
    let mut src_a = a_val;
    let mut src_b = b_val;
    let mut src_m = msg;
    let mut acc = 0u32;
    let mut carry = 0u8;

    for k in 0..8 {
        let a_nib = (src_a & 0xF) as u8;
        let b_nib = (src_b & 0xF) as u8;
        let m_nib = (src_m & 0xF) as u8;

        // Add with carry
        let sum = a_nib as u16 + b_nib as u16 + m_nib as u16 + carry as u16;
        let z_nib = (sum & 0xF) as u8;
        let carry_out = (sum >> 4) as u8;

        // Response 22: Compute acc_next BEFORE writing row
        let position = k; // S0/S2/S4/S6: no rotation
        let acc_next = acc | ((z_nib as u32) << (4 * position));

        // Mark committed step selector for this row
        trace[COMMIT_STEP_SEL_COLS[s_index]][*row] = BaseElement::ONE;

        // Write to trace - pass current carry (input), not carry_out
        write_row(
            trace, *row, k, src_a, src_b, src_m, a_nib, b_nib, m_nib, z_nib, carry, 0, acc,
        );

        // Response 22: Make the recurrence true immediately for k<7
        if k < 7 && *row + 1 < trace[0].len() {
            trace[ACC][*row + 1] = BaseElement::new(acc_next as u64);
        }

        // Write carry_out to NEXT row
        if *row + 1 < trace[0].len() {
            trace[CARRY][*row + 1] = BaseElement::new(carry_out as u64);
        }

        // Update carry for next iteration
        carry = carry_out;

        // Response 15/16: Commit at K7 for addition steps
        if k == 7 {
            // Response 16: Only commit to V, not to ACC (ACC stays 0 for reset at K0)
            commit_v_next(trace, *row, target, acc_next);
        }

        // Update acc for next iteration
        acc = acc_next;

        src_a >>= 4;
        src_b >>= 4;
        src_m >>= 4;
        *row += 1;
    }

    // Update state
    v[target] = result;

    // Response 15: Don't auto-copy V columns - this was undoing commits
    // The commit logic in commit_v_next handles V register updates correctly
}

/// S1/S3/S5/S7: XOR and rotate micro-step (8 nibbles)
fn run_xor_rotr(
    trace: &mut [Vec<BaseElement>],
    row: &mut usize,
    v: &mut [u32; 16],
    target: usize,
    source: usize,
    rotation: u32,
    s_index: usize,
) {
    let a_val = v[target];
    let b_val = v[source];
    let xor_result = a_val ^ b_val;

    // Decompose XOR operands
    let mut src_a = a_val;
    let mut src_b = b_val;
    let mut acc = 0u32;

    if rotation == 7 {
        // Response 17: S7 ROTR7 = ROTR8 placement + 1-bit in-nibble shift with carry chain
        // Seed carry with bit31 of xor_result
        let mut carry = ((xor_result >> 31) & 1) as u8;

        for k in 0..8 {
            // Operand nibbles for bit-slicing columns
            let a_nib = (src_a & 0xF) as u8;
            let b_nib = (src_b & 0xF) as u8;

            // XOR nibble bits (x0..x3) from the unrotated XOR result
            let x_nib = ((xor_result >> (4 * k)) & 0xF) as u8;
            let x0 = x_nib & 1;
            let x1 = (x_nib >> 1) & 1;
            let x2 = (x_nib >> 2) & 1;
            let x3 = (x_nib >> 3) & 1;

            // In-nibble wiring for ROTR7 (matches constraint 10):
            // z0 = carry; z1 = x0; z2 = x1; z3 = x2; next_carry = x3
            let z0 = carry;
            let z1 = x0;
            let z2 = x1;
            let z3 = x2;
            let z_nib = z0 | (z1 << 1) | (z2 << 2) | (z3 << 3);
            let next_carry = x3;

            // ACC placement uses ROTR8 nibble shift (k -> k+2)
            let position = (k + 2) % 8;

            // Response 22: Compute acc_next BEFORE writing row
            let acc_next = acc | ((z_nib as u32) << (4 * position));

            // Mark committed step selector for this row
            trace[COMMIT_STEP_SEL_COLS[s_index]][*row] = BaseElement::ONE;

            // Write *previous* ACC, then update it (our convention)
            write_row(
                trace, *row, k, src_a, src_b, 0, a_nib, b_nib, 0, z_nib,
                0,     // CARRY column is for adders; unused here
                carry, // ROT_CARRY (current)
                acc,
            );

            // Response 22: Make the recurrence true immediately for k<7
            if k < 7 && *row + 1 < trace[0].len() {
                trace[ACC][*row + 1] = BaseElement::new(acc_next as u64);
            }

            // Push this nibble into ACC at ROTR8 position
            acc = acc_next;

            // Advance the carry chain: write next ROT_CARRY into next row
            if *row + 1 < trace[0].len() {
                trace[ROT_CARRY][*row + 1] = BaseElement::new(next_carry as u64);
            }
            carry = next_carry;

            // Advance sources and row
            src_a >>= 4;
            src_b >>= 4;
            *row += 1;
        }

        // Finalize: the word that was actually written is the ACC we built
        v[target] = acc;

        // Commit to V at K7 (last row just written is row-1)
        if *row > 0 {
            commit_v_next(trace, *row - 1, target, acc);
        }
    } else {
        // S1/S3/S5: Use unrotated XOR for nibbles (Response 13)
        // But ACC placement handles the rotation via position offset
        let off = match rotation {
            16 => 4,
            12 => 3,
            8 => 2,
            _ => 0,
        };

        for k in 0..8 {
            let a_nib = (src_a & 0xF) as u8;
            let b_nib = (src_b & 0xF) as u8;
            // Response 13: Z nibbles from UNROTATED xor_result for XOR constraint
            let z_nib = ((xor_result >> (4 * k)) & 0xF) as u8;
            let position = (k + off) % 8;

            // Response 22: Compute acc_next BEFORE writing row
            let acc_next = acc | ((z_nib as u32) << (4 * position));

            // Mark committed step selector for this row
            trace[COMMIT_STEP_SEL_COLS[s_index]][*row] = BaseElement::ONE;

            write_row(
                trace, *row, k, src_a, src_b, 0, a_nib, b_nib, 0, z_nib, 0, 0, acc,
            );

            // Response 22: Make the recurrence true immediately for k<7
            if k < 7 && *row + 1 < trace[0].len() {
                trace[ACC][*row + 1] = BaseElement::new(acc_next as u64);
            }

            acc = acc_next;

            // Commit at K7
            if k == 7 {
                commit_v_next(trace, *row, target, acc);
            }

            src_a >>= 4;
            src_b >>= 4;
            *row += 1;
        }

        // The final result should be what we accumulated in ACC
        // NOT the simple rotation (Response 13: nibble placement differs)
        v[target] = acc;
    }
}

/// Commit accumulated value to target V register at K7 (Response 15)
#[inline]
fn commit_v_next(
    trace: &mut [Vec<BaseElement>],
    row: usize,    // current row r (where K7=1)
    target: usize, // 0..15
    acc_final: u32,
) {
    let next = row + 1;
    // carry-forward for all words
    for j in 0..16 {
        trace[V0 + j][next] = trace[V0 + j][row];
    }
    // overwrite the targeted word with the final accumulated value
    trace[V0 + target][next] = BaseElement::new(acc_final as u64);

    // Mark committed selector for this K7 row (one-hot) and mirror to next row
    for j in 0..16 {
        let val = if j == target {
            BaseElement::ONE
        } else {
            BaseElement::ZERO
        };
        trace[COMMIT_SEL_COLS[j]][row] = val;
        trace[COMMIT_SEL_COLS[j]][next] = val;
    }

    // Store committed ACC_FINAL value for this row and mirror it into the next row
    // This supports a C6 form that compares nxt[Vj] with nxt[ACC_FINAL_COMMIT_COL]
    let acc_elem = BaseElement::new(acc_final as u64);
    trace[ACC_FINAL_COMMIT_COL][row] = acc_elem;
    trace[ACC_FINAL_COMMIT_COL][next] = acc_elem;

    // Mark commit-row mask (1 at commit rows), mirror into next row for OOD-safe gating
    trace[COMMIT_ROW_MASK_COL][row] = BaseElement::ONE;
    trace[COMMIT_ROW_MASK_COL][next] = BaseElement::ONE;

    // Compute diff at commit and mirror: next[V_target] - next[ACC_FINAL_COMMIT]
    let v_target_next = trace[V0 + target][next];
    let diff = v_target_next - acc_elem;
    trace[COMMIT_DIFF_COL][row] = diff;
    trace[COMMIT_DIFF_COL][next] = diff;
}

/// Write a single trace row
fn write_row(
    trace: &mut [Vec<BaseElement>],
    row: usize,
    k: usize,
    src_a: u32,
    src_b: u32,
    src_m: u32,
    a_nib: u8,
    b_nib: u8,
    m_nib: u8,
    z_nib: u8,
    carry: u8,
    rot_carry: u8,
    acc: u32,
) {
    // Mark committed K selector for this row (one-hot)
    trace[COMMIT_K_SEL_COLS[k]][row] = BaseElement::ONE;

    // Propagate V values from previous row
    // Only propagate if the current row doesn't already have values
    // (commit_v_next may have already written values at K0 after K7)
    if row > 0 {
        // Check if V0 is zero (uninitialized) - if so, propagate
        if trace[V0][row] == BaseElement::ZERO {
            for i in 0..16 {
                trace[V0 + i][row] = trace[V0 + i][row - 1];
            }
        }
    }

    // ACC column
    // Response 20: Hard guarantee - at K0 the accumulator must be 0 (matches reset gate)
    // Response 22: Don't overwrite ACC if it was already pre-written
    if k == 0 {
        trace[ACC][row] = BaseElement::ZERO;
    } else if trace[ACC][row] == BaseElement::ZERO {
        // Only write if not already set (Response 22 pre-writes for k<7)
        trace[ACC][row] = BaseElement::new(acc as u64);
    }

    // Source quotient chains (only at K0 do we load full values)
    if k == 0 {
        trace[SRC_A][row] = BaseElement::new(src_a as u64);
        trace[SRC_B][row] = BaseElement::new(src_b as u64);
        trace[SRC_M][row] = BaseElement::new(src_m as u64);
    } else {
        // Continue quotient chain from previous row
        // These were already shifted in the calling function
        trace[SRC_A][row] = BaseElement::new(src_a as u64);
        trace[SRC_B][row] = BaseElement::new(src_b as u64);
        trace[SRC_M][row] = BaseElement::new(src_m as u64);
    }

    // Nibble bits
    for i in 0..4 {
        trace[A_B0 + i][row] = BaseElement::new(((a_nib >> i) & 1) as u64);
        trace[B_B0 + i][row] = BaseElement::new(((b_nib >> i) & 1) as u64);
        trace[M_B0 + i][row] = BaseElement::new(((m_nib >> i) & 1) as u64);
        trace[Z_B0 + i][row] = BaseElement::new(((z_nib >> i) & 1) as u64);
    }

    // Carry bits
    // For CARRY: only write if not already set (addition steps write carry_out to next row)
    // This prevents XOR steps from overwriting carry values from previous addition steps
    if trace[CARRY][row] == BaseElement::ZERO {
        trace[CARRY][row] = BaseElement::new(carry as u64);
    }
    // For ROT_CARRY: similar protection - S7 writes next carry, don't overwrite
    if trace[ROT_CARRY][row] == BaseElement::ZERO {
        trace[ROT_CARRY][row] = BaseElement::new(rot_carry as u64);
    }

    // V and MSG values are already pre-populated for all rows, no need to copy
}

/// Initialize trace at row 0 before compression
pub fn init_blake3_trace(trace: &mut [Vec<BaseElement>], start_row: usize, message: &[u32; 16]) {
    // Set initial V values (BLAKE3 IV)
    trace[V0][start_row] = BaseElement::new(0x6A09E667u64);
    trace[V1][start_row] = BaseElement::new(0xF3BCC908u64);
    trace[V2][start_row] = BaseElement::new(0xBB67AE85u64);
    trace[V3][start_row] = BaseElement::new(0x84CAA73Bu64);
    trace[V4][start_row] = BaseElement::new(0x3C6EF372u64);
    trace[V5][start_row] = BaseElement::new(0xFE94F82Bu64);
    trace[V6][start_row] = BaseElement::new(0xA54FF53Au64);
    trace[V7][start_row] = BaseElement::new(0x5F1D36F1u64);
    trace[V8][start_row] = BaseElement::new(0x510E527Fu64);
    trace[V9][start_row] = BaseElement::new(0xADE682D1u64);
    trace[V10][start_row] = BaseElement::new(0x9B05688Cu64);
    trace[V11][start_row] = BaseElement::new(0x2B3E6C1Fu64);
    trace[V12][start_row] = BaseElement::new(0x1F83D9ABu64);
    trace[V13][start_row] = BaseElement::new(0xFB41BD6Bu64);
    trace[V14][start_row] = BaseElement::new(0x5BE0CD19u64);
    trace[V15][start_row] = BaseElement::new(0x137E2179u64);

    // Set message values
    for i in 0..16 {
        trace[MSG0 + i][start_row] = BaseElement::new(message[i] as u64);
    }

    // Initialize auxiliary columns
    trace[ACC][start_row] = BaseElement::ZERO;
    trace[SRC_A][start_row] = BaseElement::ZERO;
    trace[SRC_B][start_row] = BaseElement::ZERO;
    trace[SRC_M][start_row] = BaseElement::ZERO;

    for i in 0..4 {
        trace[A_B0 + i][start_row] = BaseElement::ZERO;
        trace[B_B0 + i][start_row] = BaseElement::ZERO;
        trace[M_B0 + i][start_row] = BaseElement::ZERO;
        trace[Z_B0 + i][start_row] = BaseElement::ZERO;
    }

    trace[CARRY][start_row] = BaseElement::ZERO;
    trace[ROT_CARRY][start_row] = BaseElement::ZERO;
}
