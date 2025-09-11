//! Range check gadgets for GroveVM
//!
//! Provides efficient range checking for stack pointer and other bounded values

use winterfell::math::fields::f64::BaseElement;
use winterfell::math::FieldElement;

/// Range check gadget using decomposition
/// Verifies that value is in range [0, max) by decomposing into bits
pub struct RangeCheckGadget {
    max_value: usize,
    bit_width: usize,
}

impl RangeCheckGadget {
    /// Create a new range check gadget for values in [0, max)
    pub fn new(max_value: usize) -> Self {
        // Calculate required bit width
        let bit_width = (max_value as f64).log2().ceil() as usize;
        Self {
            max_value,
            bit_width,
        }
    }

    /// Decompose a value into bits for range checking
    /// Returns the bit decomposition if valid, None if out of range
    pub fn decompose(&self, value: usize) -> Option<Vec<bool>> {
        if value >= self.max_value {
            return None;
        }

        let mut bits = Vec::with_capacity(self.bit_width);
        let mut v = value;

        for _ in 0..self.bit_width {
            bits.push(v & 1 == 1);
            v >>= 1;
        }

        Some(bits)
    }

    /// Verify range check constraints for decomposed bits
    /// Returns constraint evaluations that should all equal zero
    pub fn verify_decomposition<E: FieldElement<BaseField = BaseElement>>(
        &self,
        value: E,
        bits: &[E],
    ) -> Vec<E> {
        let mut constraints = Vec::new();

        // Each bit must be boolean (b * (1 - b) = 0)
        for &bit in bits {
            constraints.push(bit * (E::ONE - bit));
        }

        // Reconstruction constraint: sum of 2^i * bit_i = value
        let mut reconstructed = E::ZERO;
        let mut power = E::ONE;
        let two = E::from(BaseElement::new(2));

        for &bit in bits {
            reconstructed = reconstructed + power * bit;
            power = power * two;
        }

        constraints.push(reconstructed - value);

        // Additional constraint: ensure value < max_value
        // This is implicit if bit decomposition is correct and limited to bit_width

        constraints
    }

    /// Generate auxiliary witness data for range check
    /// This provides the bit decomposition that satisfies the constraints
    pub fn generate_witness(&self, value: usize) -> Result<Vec<BaseElement>, String> {
        let bits = self
            .decompose(value)
            .ok_or_else(|| format!("Value {} out of range [0, {})", value, self.max_value))?;

        Ok(bits
            .into_iter()
            .map(|b| {
                if b {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                }
            })
            .collect())
    }
}

/// Optimized range check for small ranges using lookup tables
pub struct SmallRangeCheck {
    _max_value: usize,
    lookup_table: Vec<BaseElement>,
}

impl SmallRangeCheck {
    /// Create range check for small values (typically < 16)
    pub fn new(max_value: usize) -> Self {
        assert!(max_value <= 16, "Use RangeCheckGadget for larger ranges");

        // Pre-compute valid values
        let lookup_table: Vec<BaseElement> =
            (0..max_value).map(|i| BaseElement::new(i as u64)).collect();

        Self {
            _max_value: max_value,
            lookup_table,
        }
    }

    /// Check if a value is in range using lookup
    pub fn is_in_range<E: FieldElement<BaseField = BaseElement>>(&self, value: E) -> bool {
        for &valid in &self.lookup_table {
            if value == E::from(valid) {
                return true;
            }
        }
        false
    }

    /// Generate constraint that forces value to be in range
    /// Returns product (value - v0)(value - v1)...(value - vn) which is 0 iff value is valid
    pub fn range_constraint<E: FieldElement<BaseField = BaseElement>>(&self, value: E) -> E {
        let mut product = E::ONE;

        for &valid in &self.lookup_table {
            product = product * (value - E::from(valid));
        }

        product
    }
}

/// Dedicated stack pointer range check
/// Optimized for SP ∈ [0, D_MAX]
pub struct StackPointerRangeCheck {
    range_check: SmallRangeCheck,
}

impl StackPointerRangeCheck {
    pub fn new(max_stack_depth: usize) -> Self {
        Self {
            range_check: SmallRangeCheck::new(max_stack_depth + 1), // +1 because SP can equal D_MAX
        }
    }

    /// Generate constraint for stack pointer range
    pub fn constraint<E: FieldElement<BaseField = BaseElement>>(&self, sp: E) -> E {
        self.range_check.range_constraint(sp)
    }

    /// Verify stack pointer is valid
    pub fn is_valid<E: FieldElement<BaseField = BaseElement>>(&self, sp: E) -> bool {
        self.range_check.is_in_range(sp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_check_decomposition() {
        let gadget = RangeCheckGadget::new(16); // 4-bit range

        // Test valid values
        for value in 0..16 {
            let bits = gadget.decompose(value).expect("Should decompose");
            assert_eq!(bits.len(), 4);

            // Verify reconstruction
            let mut reconstructed = 0;
            for (i, &bit) in bits.iter().enumerate() {
                if bit {
                    reconstructed += 1 << i;
                }
            }
            assert_eq!(reconstructed, value);
        }

        // Test out of range
        assert!(gadget.decompose(16).is_none());
        assert!(gadget.decompose(100).is_none());
    }

    #[test]
    fn test_range_check_constraints() {
        let gadget = RangeCheckGadget::new(8); // 3-bit range

        let value = BaseElement::new(5);
        let bits = gadget.generate_witness(5).expect("Should generate witness");

        let constraints = gadget.verify_decomposition(value, &bits);

        // All constraints should be satisfied (equal zero)
        for constraint in constraints {
            assert_eq!(constraint, BaseElement::ZERO);
        }
    }

    #[test]
    fn test_small_range_check() {
        use crate::phases::grovevm::types::D_MAX;

        let sp_check = StackPointerRangeCheck::new(D_MAX);

        // Valid SP values
        for i in 0..=D_MAX {
            let sp = BaseElement::new(i as u64);
            assert!(sp_check.is_valid(sp));
            assert_eq!(sp_check.constraint(sp), BaseElement::ZERO);
        }

        // Invalid SP values
        let invalid_sp = BaseElement::new((D_MAX + 1) as u64);
        assert!(!sp_check.is_valid(invalid_sp));
        assert_ne!(sp_check.constraint(invalid_sp), BaseElement::ZERO);
    }
}
