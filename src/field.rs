use ark_ff::fields::{Fp64, MontBackend, MontConfig};
use ark_ff::{Field as ArkField, PrimeField};
use std::ops::{Add, Div, Mul, Neg, Sub};

#[derive(MontConfig)]
#[modulus = "18446744069414584321"]
#[generator = "3"]
pub struct GoldilocksConfig;

pub type GoldilocksField = Fp64<MontBackend<GoldilocksConfig, 1>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldElement(pub GoldilocksField);

impl FieldElement {
    pub const ZERO: Self = Self(GoldilocksField::ZERO);
    pub const ONE: Self = Self(GoldilocksField::ONE);

    pub fn new(value: u64) -> Self {
        Self(GoldilocksField::from(value))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut value = 0u64;
        for (i, &byte) in bytes.iter().take(8).enumerate() {
            value |= (byte as u64) << (i * 8);
        }
        Self::new(value)
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let value = self.as_u64();
        let mut bytes = [0u8; 8];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = ((value >> (i * 8)) & 0xff) as u8;
        }
        bytes
    }

    pub fn as_u64(&self) -> u64 {
        let bytes = self.0.into_bigint().0;
        bytes[0]
    }

    pub fn pow(&self, exp: u64) -> Self {
        let mut result = Self::ONE;
        let mut base = *self;
        let mut e = exp;

        while e > 0 {
            if e & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            e >>= 1;
        }

        result
    }

    pub fn inverse(&self) -> Option<Self> {
        self.0.inverse().map(Self)
    }

    pub fn sqrt(&self) -> Option<Self> {
        self.0.sqrt().map(Self)
    }
}

impl Add for FieldElement {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl Sub for FieldElement {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }
}

impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        Self(self.0 * other.0)
    }
}

impl Div for FieldElement {
    type Output = Self;

    fn div(self, other: Self) -> Self {
        Self(self.0 / other.0)
    }
}

impl Neg for FieldElement {
    type Output = Self;

    fn neg(self) -> Self {
        Self(-self.0)
    }
}

pub struct FieldOperations;

impl FieldOperations {
    pub fn add_mod32(a: u32, b: u32) -> u32 {
        a.wrapping_add(b)
    }

    pub fn xor(a: u32, b: u32) -> u32 {
        a ^ b
    }

    pub fn rotr(value: u32, shift: u32) -> u32 {
        value.rotate_right(shift)
    }

    pub fn rotl(value: u32, shift: u32) -> u32 {
        value.rotate_left(shift)
    }

    pub fn interpolate(points: &[(FieldElement, FieldElement)]) -> Vec<FieldElement> {
        let n = points.len();
        let mut coefficients = vec![FieldElement::ZERO; n];

        for (i, &(xi, yi)) in points.iter().enumerate().take(n) {
            let mut term = yi;

            for (j, &(xj, _)) in points.iter().enumerate().take(n) {
                if i != j {
                    term = term * (xi - xj).inverse().unwrap();
                }
            }

            coefficients[i] = term;
        }

        coefficients
    }

    pub fn evaluate_polynomial(coefficients: &[FieldElement], x: FieldElement) -> FieldElement {
        let mut result = FieldElement::ZERO;
        let mut x_power = FieldElement::ONE;

        for &coeff in coefficients {
            result = result + coeff * x_power;
            x_power = x_power * x;
        }

        result
    }

    pub fn batch_inverse(elements: &[FieldElement]) -> Vec<FieldElement> {
        let n = elements.len();
        if n == 0 {
            return vec![];
        }

        let mut products = vec![FieldElement::ONE; n];
        products[0] = elements[0];

        for i in 1..n {
            products[i] = products[i - 1] * elements[i];
        }

        let mut inv = products[n - 1].inverse().unwrap();
        let mut inverses = vec![FieldElement::ZERO; n];

        for i in (1..n).rev() {
            inverses[i] = inv * products[i - 1];
            inv = inv * elements[i];
        }
        inverses[0] = inv;

        inverses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_arithmetic() {
        let a = FieldElement::new(5);
        let b = FieldElement::new(7);

        let sum = a + b;
        let product = a * b;
        let difference = b - a;

        assert_eq!(sum.as_u64(), 12);
        assert_eq!(product.as_u64(), 35);
        assert_eq!(difference.as_u64(), 2);
    }

    #[test]
    fn test_field_inverse() {
        let a = FieldElement::new(7);
        let inv = a.inverse().unwrap();
        let product = a * inv;

        assert_eq!(product, FieldElement::ONE);
    }

    #[test]
    fn test_batch_inverse() {
        let elements = vec![
            FieldElement::new(2),
            FieldElement::new(3),
            FieldElement::new(5),
        ];

        let inverses = FieldOperations::batch_inverse(&elements);

        for (elem, inv) in elements.iter().zip(inverses.iter()) {
            assert_eq!(*elem * *inv, FieldElement::ONE);
        }
    }
}
