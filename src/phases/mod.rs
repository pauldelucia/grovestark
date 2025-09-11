pub mod blake3;
pub mod eddsa;
pub mod grovevm;
pub mod merkle;

// Signature phases

/// Phase identifiers for the STARK proof
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Blake3,
    Merkle,
    Eddsa,
}

/// Phase boundaries in the trace
pub struct PhaseBoundaries {
    pub blake3_start: usize,
    pub blake3_end: usize,
    pub merkle_start: usize,
    pub merkle_end: usize,
    pub eddsa_start: usize,
    pub eddsa_end: usize,
}

impl PhaseBoundaries {
    pub fn new(_trace_length: usize) -> Self {
        // Updated for 65,536 total rows
        const BLAKE3_ROWS: usize = 3584;
        const MERKLE_ROWS: usize = 16384;
        const EDDSA_ROWS: usize = 32768;

        Self {
            blake3_start: 0,
            blake3_end: BLAKE3_ROWS - 1,
            merkle_start: BLAKE3_ROWS,
            merkle_end: BLAKE3_ROWS + MERKLE_ROWS - 1,
            eddsa_start: BLAKE3_ROWS + MERKLE_ROWS,
            eddsa_end: BLAKE3_ROWS + MERKLE_ROWS + EDDSA_ROWS - 1,
        }
    }

    pub fn get_phase(&self, row: usize) -> Phase {
        if row <= self.blake3_end {
            Phase::Blake3
        } else if row <= self.merkle_end {
            Phase::Merkle
        } else {
            Phase::Eddsa
        }
    }
}
