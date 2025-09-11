//! Trace generation for BLAKE3 micro-steps based on Response 5

use crate::error::Result;
use crate::stark_winterfell::*;
use winterfell::math::fields::f64::BaseElement;
use winterfell::math::FieldElement;

/// Helper to decompose a u32 into 8 nibbles (4 bits each)
fn decompose_to_nibbles(value: u32) -> [u8; 8] {
    let mut nibbles = [0u8; 8];
    for i in 0..8 {
        nibbles[i] = ((value >> (4 * i)) & 0xF) as u8;
    }
    nibbles
}

/// Helper to decompose a nibble into 4 bits
fn nibble_to_bits(nibble: u8) -> [BaseElement; 4] {
    [
        BaseElement::new((nibble & 1) as u64),
        BaseElement::new(((nibble >> 1) & 1) as u64),
        BaseElement::new(((nibble >> 2) & 1) as u64),
        BaseElement::new(((nibble >> 3) & 1) as u64),
    ]
}

/// Compute XOR of two nibbles
fn xor_nibbles(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Add three nibbles with carry
fn add_nibbles_with_carry(a: u8, b: u8, m: u8, carry_in: u8) -> (u8, u8) {
    let sum = a as u16 + b as u16 + m as u16 + carry_in as u16;
    let result = (sum & 0xF) as u8;
    let carry_out = (sum >> 4) as u8;
    (result, carry_out)
}

/// Lane mappings from Response 4
const COLUMN_LANES: [[usize; 4]; 4] =
    [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]];

const DIAGONAL_LANES: [[usize; 4]; 4] =
    [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]];

/// Run a single lane of BLAKE3 compression
pub fn run_blake3_lane(
    trace_columns: &mut [Vec<BaseElement>],
    start_row: usize,
    round: usize,
    lane_idx: usize,
    is_diagonal: bool,
    msg_schedule: &[[u8; 16]; 7],
) -> Result<()> {
    // Get the lane indices (a, b, c, d)
    let lane = if is_diagonal {
        DIAGONAL_LANES[lane_idx]
    } else {
        COLUMN_LANES[lane_idx]
    };
    let (a, b, c, d) = (lane[0], lane[1], lane[2], lane[3]);

    // Get message indices for this round and lane
    let msg_offset = if is_diagonal { 8 } else { 0 };
    let mx_idx = msg_schedule[round][msg_offset + 2 * lane_idx] as usize;
    let my_idx = msg_schedule[round][msg_offset + 2 * lane_idx + 1] as usize;

    // Process 8 micro-steps
    for s in 0..8 {
        // Determine target word and sources based on micro-step
        let (target, src_a_idx, src_b_idx) = match s {
            0 | 4 => (a, a, b), // a += b + m
            1 | 5 => (d, d, a), // d = rotr(d ^ a)
            2 | 6 => (c, c, d), // c += d
            3 | 7 => (b, b, c), // b = rotr(b ^ c)
            _ => unreachable!(),
        };

        // Get the message index for S0 and S4
        let msg_idx = if s == 0 {
            mx_idx
        } else if s == 4 {
            my_idx
        } else {
            0
        };

        // Process 8 nibbles for this micro-step
        run_micro_step(
            trace_columns,
            start_row + s * 8,
            s,
            target,
            src_a_idx,
            src_b_idx,
            msg_idx,
        )?;
    }

    Ok(())
}

/// Run a single micro-step (8 rows for 8 nibbles)
fn run_micro_step(
    trace_columns: &mut [Vec<BaseElement>],
    start_row: usize,
    micro_step: usize,
    target_idx: usize,
    src_a_idx: usize,
    src_b_idx: usize,
    msg_idx: usize,
) -> Result<()> {
    // At K0, read the full 32-bit values
    let row = start_row;

    // Get current V values as u32 (they're stored as u64 BaseElements)
    let v_values: Vec<u32> = (0..16)
        .map(|i| trace_columns[V0 + i][row].as_int() as u32)
        .collect();

    let msg_values: Vec<u32> = (0..16)
        .map(|i| trace_columns[MSG0 + i][row].as_int() as u32)
        .collect();

    // Get source values
    let src_a_val = v_values[src_a_idx];
    let src_b_val = v_values[src_b_idx];
    let src_m_val = if micro_step == 0 || micro_step == 4 {
        msg_values[msg_idx]
    } else {
        0
    };

    // Decompose into nibbles
    let a_nibbles = decompose_to_nibbles(src_a_val);
    let b_nibbles = decompose_to_nibbles(src_b_val);
    let m_nibbles = decompose_to_nibbles(src_m_val);

    // Process based on micro-step type
    let mut z_nibbles = [0u8; 8];
    let mut carry = 0u8;
    let mut rot_carry = 0u8;

    match micro_step {
        0 | 2 | 4 | 6 => {
            // Addition steps
            for k in 0..8 {
                let m_val = if micro_step == 0 || micro_step == 4 {
                    m_nibbles[k]
                } else {
                    0
                };
                let (z, new_carry) = add_nibbles_with_carry(
                    a_nibbles[k],
                    b_nibbles[k],
                    m_val,
                    if k == 0 { 0 } else { carry },
                );
                z_nibbles[k] = z;
                carry = new_carry;

                // Write to trace at row start_row + k
                let row = start_row + k;

                // Set SRC values at K0
                if k == 0 {
                    trace_columns[SRC_A][row] = BaseElement::new(src_a_val as u64);
                    trace_columns[SRC_B][row] = BaseElement::new(src_b_val as u64);
                    trace_columns[SRC_M][row] = BaseElement::new(src_m_val as u64);
                    trace_columns[ACC][row] = BaseElement::ZERO;
                } else {
                    // Update quotient chains
                    let prev_src_a = trace_columns[SRC_A][row - 1].as_int() as u32;
                    let prev_src_b = trace_columns[SRC_B][row - 1].as_int() as u32;
                    let prev_src_m = trace_columns[SRC_M][row - 1].as_int() as u32;

                    trace_columns[SRC_A][row] = BaseElement::new((prev_src_a >> 4) as u64);
                    trace_columns[SRC_B][row] = BaseElement::new((prev_src_b >> 4) as u64);
                    trace_columns[SRC_M][row] = BaseElement::new((prev_src_m >> 4) as u64);
                }

                // Write nibble bits
                let a_bits = nibble_to_bits(a_nibbles[k]);
                let b_bits = nibble_to_bits(b_nibbles[k]);
                let m_bits = nibble_to_bits(m_nibbles[k]);
                let z_bits = nibble_to_bits(z_nibbles[k]);

                for i in 0..4 {
                    trace_columns[A_B0 + i][row] = a_bits[i];
                    trace_columns[B_B0 + i][row] = b_bits[i];
                    trace_columns[M_B0 + i][row] = m_bits[i];
                    trace_columns[Z_B0 + i][row] = z_bits[i];
                }

                // Write carry
                trace_columns[CARRY][row] = BaseElement::new(carry as u64);

                // Update ACC
                if k == 0 {
                    trace_columns[ACC][row] = BaseElement::new(z_nibbles[k] as u64);
                } else {
                    let prev_acc = trace_columns[ACC][row - 1].as_int();
                    let z_contribution = (z_nibbles[k] as u64) << (4 * k);
                    trace_columns[ACC][row] = BaseElement::new(prev_acc + z_contribution);
                }
            }
        }
        1 | 3 | 5 | 7 => {
            // XOR steps with rotation
            let rotation = match micro_step {
                1 => 16, // ROTR16
                3 => 12, // ROTR12
                5 => 8,  // ROTR8
                7 => 7,  // ROTR7
                _ => unreachable!(),
            };

            // For XOR steps
            for k in 0..8 {
                z_nibbles[k] = xor_nibbles(a_nibbles[k], b_nibbles[k]);
            }

            // Apply rotation to z_nibbles
            let z_value = nibbles_to_u32(&z_nibbles);
            let rotated = z_value.rotate_right(rotation);
            let rotated_nibbles = decompose_to_nibbles(rotated);

            // Handle ROTR7 special case
            if micro_step == 7 {
                // ROTR7 needs special handling with ROT_CARRY
                // First do ROTR8, then shift left by 1
                let rotr8 = z_value.rotate_right(8);
                let rotr7 = (rotr8 << 1) | ((rotr8 >> 31) & 1);
                rot_carry = ((rotr8 >> 31) & 1) as u8;
                z_nibbles = decompose_to_nibbles(rotr7);
            } else {
                z_nibbles = rotated_nibbles;
            }

            // Write to trace
            for k in 0..8 {
                let row = start_row + k;

                // Set SRC values at K0
                if k == 0 {
                    trace_columns[SRC_A][row] = BaseElement::new(src_a_val as u64);
                    trace_columns[SRC_B][row] = BaseElement::new(src_b_val as u64);
                    trace_columns[SRC_M][row] = BaseElement::ZERO;
                    trace_columns[ACC][row] = BaseElement::ZERO;
                } else {
                    // Update quotient chains
                    let prev_src_a = trace_columns[SRC_A][row - 1].as_int() as u32;
                    let prev_src_b = trace_columns[SRC_B][row - 1].as_int() as u32;

                    trace_columns[SRC_A][row] = BaseElement::new((prev_src_a >> 4) as u64);
                    trace_columns[SRC_B][row] = BaseElement::new((prev_src_b >> 4) as u64);
                    trace_columns[SRC_M][row] = BaseElement::ZERO;
                }

                // Write nibble bits
                let a_bits = nibble_to_bits(a_nibbles[k]);
                let b_bits = nibble_to_bits(b_nibbles[k]);
                let z_bits = nibble_to_bits(z_nibbles[k]);

                for i in 0..4 {
                    trace_columns[A_B0 + i][row] = a_bits[i];
                    trace_columns[B_B0 + i][row] = b_bits[i];
                    trace_columns[M_B0 + i][row] = BaseElement::ZERO;
                    trace_columns[Z_B0 + i][row] = z_bits[i];
                }

                // Write ROT_CARRY for S7
                if micro_step == 7 {
                    trace_columns[ROT_CARRY][row] = BaseElement::new(rot_carry as u64);
                } else {
                    trace_columns[ROT_CARRY][row] = BaseElement::ZERO;
                }

                trace_columns[CARRY][row] = BaseElement::ZERO;

                // Update ACC with rotated nibble at appropriate position
                let nibble_position = match rotation {
                    16 => (k + 4) % 8, // ROTR16
                    12 => (k + 3) % 8, // ROTR12
                    8 => (k + 2) % 8,  // ROTR8
                    7 => k,            // Special case, handled differently
                    _ => k,
                };

                if k == 0 {
                    trace_columns[ACC][row] = BaseElement::new(z_nibbles[nibble_position] as u64);
                } else {
                    let prev_acc = trace_columns[ACC][row - 1].as_int();
                    let z_contribution = (z_nibbles[nibble_position] as u64) << (4 * k);
                    trace_columns[ACC][row] = BaseElement::new(prev_acc + z_contribution);
                }
            }
        }
        _ => unreachable!(),
    }

    // At K7, commit ACC back to target V
    let last_row = start_row + 7;
    let final_acc = trace_columns[ACC][last_row].as_int() as u32;

    // Update the target V column for the next row
    if last_row + 1 < trace_columns[0].len() {
        trace_columns[V0 + target_idx][last_row + 1] = BaseElement::new(final_acc as u64);

        // Copy other V values forward
        for i in 0..16 {
            if i != target_idx {
                trace_columns[V0 + i][last_row + 1] = trace_columns[V0 + i][last_row];
            }
        }

        // Copy MSG values forward
        for i in 0..16 {
            trace_columns[MSG0 + i][last_row + 1] = trace_columns[MSG0 + i][last_row];
        }
    }

    Ok(())
}

/// Convert nibbles back to u32
fn nibbles_to_u32(nibbles: &[u8; 8]) -> u32 {
    let mut value = 0u32;
    for i in 0..8 {
        value |= (nibbles[i] as u32) << (4 * i);
    }
    value
}

/// Run complete BLAKE3 compression (7 rounds)
pub fn run_blake3_compression(
    trace_columns: &mut [Vec<BaseElement>],
    start_row: usize,
) -> Result<()> {
    // Use the canonical BLAKE3 message schedule
    let msg_schedule = MSG_SCHEDULE;

    let mut current_row = start_row;

    for round in 0..7 {
        // Process column lanes
        for lane_idx in 0..4 {
            run_blake3_lane(
                trace_columns,
                current_row,
                round,
                lane_idx,
                false, // column lane
                &msg_schedule,
            )?;
            current_row += 64; // 8 micro-steps * 8 nibbles
        }

        // Process diagonal lanes
        for lane_idx in 0..4 {
            run_blake3_lane(
                trace_columns,
                current_row,
                round,
                lane_idx,
                true, // diagonal lane
                &msg_schedule,
            )?;
            current_row += 64; // 8 micro-steps * 8 nibbles
        }
    }

    Ok(())
}
