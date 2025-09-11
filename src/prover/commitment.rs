use crate::crypto::{Blake3Hasher, MerkleTree};
use crate::error::{Error, Result};
use crate::field::FieldElement;

pub struct PolynomialCommitment {
    pub merkle_root: [u8; 32],
    pub evaluations: Vec<FieldElement>,
    tree: MerkleTree,
}

impl PolynomialCommitment {
    pub fn new(evaluations: Vec<FieldElement>) -> Result<Self> {
        let leaves = evaluations
            .iter()
            .map(|eval| {
                let mut bytes = [0u8; 32];
                bytes[..8].copy_from_slice(&eval.to_bytes());
                Blake3Hasher::hash(&bytes)
            })
            .collect();

        let tree = MerkleTree::new(leaves)?;
        let merkle_root = tree.root();

        Ok(Self {
            merkle_root,
            evaluations,
            tree,
        })
    }

    pub fn open(&self, position: usize) -> Result<CommitmentOpening> {
        if position >= self.evaluations.len() {
            return Err(Error::FRI("Position out of bounds".into()));
        }

        let proof = self.tree.get_proof(position)?;

        Ok(CommitmentOpening {
            position,
            evaluation: self.evaluations[position],
            merkle_proof: proof,
        })
    }

    pub fn batch_open(&self, positions: &[usize]) -> Result<Vec<CommitmentOpening>> {
        let mut openings = Vec::new();

        for &position in positions {
            openings.push(self.open(position)?);
        }

        Ok(openings)
    }

    pub fn verify_opening(root: &[u8; 32], opening: &CommitmentOpening) -> bool {
        let mut leaf_bytes = [0u8; 32];
        leaf_bytes[..8].copy_from_slice(&opening.evaluation.to_bytes());
        let leaf_hash = Blake3Hasher::hash(&leaf_bytes);

        opening.merkle_proof.leaf == leaf_hash
            && opening.merkle_proof.root == *root
            && MerkleTree::verify_proof(&opening.merkle_proof)
    }
}

#[derive(Debug, Clone)]
pub struct CommitmentOpening {
    pub position: usize,
    pub evaluation: FieldElement,
    pub merkle_proof: crate::crypto::merkle::MerkleProof,
}

pub struct MultiPolynomialCommitment {
    pub commitments: Vec<PolynomialCommitment>,
    pub combined_root: [u8; 32],
}

impl MultiPolynomialCommitment {
    pub fn new(polynomials: Vec<Vec<FieldElement>>) -> Result<Self> {
        let mut commitments = Vec::new();
        let mut roots = Vec::new();

        for poly in polynomials {
            let commitment = PolynomialCommitment::new(poly)?;
            roots.push(commitment.merkle_root);
            commitments.push(commitment);
        }

        let combined_root =
            Blake3Hasher::multi_hash(&roots.iter().map(|r| &r[..]).collect::<Vec<_>>());

        Ok(Self {
            commitments,
            combined_root,
        })
    }

    pub fn open_all(&self, position: usize) -> Result<Vec<CommitmentOpening>> {
        let mut openings = Vec::new();

        for commitment in &self.commitments {
            openings.push(commitment.open(position)?);
        }

        Ok(openings)
    }

    pub fn verify_openings(&self, openings: &[CommitmentOpening]) -> bool {
        if openings.len() != self.commitments.len() {
            return false;
        }

        for (opening, commitment) in openings.iter().zip(&self.commitments) {
            if !PolynomialCommitment::verify_opening(&commitment.merkle_root, opening) {
                return false;
            }
        }

        true
    }
}

pub struct CommitmentScheme {
    pub domain_size: usize,
    pub blowup_factor: usize,
}

impl CommitmentScheme {
    pub fn new(domain_size: usize, blowup_factor: usize) -> Self {
        Self {
            domain_size,
            blowup_factor,
        }
    }

    pub fn commit_trace(&self, trace: &[Vec<FieldElement>]) -> Result<TraceCommitment> {
        let lde_domain_size = self.domain_size * self.blowup_factor;
        let mut lde_trace = Vec::new();

        for column in trace {
            let lde_column = self.low_degree_extension(column, lde_domain_size)?;
            lde_trace.push(lde_column);
        }

        let commitment = MultiPolynomialCommitment::new(lde_trace)?;

        Ok(TraceCommitment {
            commitment,
            domain_size: self.domain_size,
            lde_domain_size,
        })
    }

    fn low_degree_extension(
        &self,
        values: &[FieldElement],
        target_size: usize,
    ) -> Result<Vec<FieldElement>> {
        if values.len() > target_size {
            return Err(Error::FRI("Values exceed target size".into()));
        }

        let mut extended = values.to_vec();
        extended.resize(target_size, FieldElement::ZERO);

        self.fft(&mut extended, false)?;
        self.fft(&mut extended, true)?;

        Ok(extended)
    }

    fn fft(&self, values: &mut [FieldElement], inverse: bool) -> Result<()> {
        let n = values.len();
        if n <= 1 {
            return Ok(());
        }

        if n & (n - 1) != 0 {
            return Err(Error::FRI("FFT size must be power of 2".into()));
        }

        let mut j = 0;
        for i in 1..n {
            let mut bit = n >> 1;
            while j & bit != 0 {
                j ^= bit;
                bit >>= 1;
            }
            j ^= bit;

            if i < j {
                values.swap(i, j);
            }
        }

        let mut len = 2;
        while len <= n {
            let half_len = len >> 1;
            let table_step = n / len;

            for i in (0..n).step_by(len) {
                for (k, j) in (i..i + half_len).enumerate() {
                    let omega = self.get_twiddle_factor(k * table_step, n, inverse);
                    let t = omega * values[j + half_len];
                    values[j + half_len] = values[j] - t;
                    values[j] = values[j] + t;
                }
            }

            len <<= 1;
        }

        if inverse {
            let n_inv = FieldElement::new(n as u64)
                .inverse()
                .ok_or_else(|| Error::FRI("Cannot compute inverse of n".into()))?;
            for value in values.iter_mut() {
                *value = *value * n_inv;
            }
        }

        Ok(())
    }

    fn get_twiddle_factor(&self, k: usize, n: usize, inverse: bool) -> FieldElement {
        // For FFT in Goldilocks field, we need proper roots of unity
        // Use a primitive n-th root of unity

        // For powers of 2 (which FFT requires), use known roots
        if n.is_power_of_two() {
            // Start with a primitive 2^32-th root of unity in Goldilocks
            let primitive_root = FieldElement::new(1753635133440165772u64);

            // Adjust for the specific power of 2 we need
            let log_n = n.trailing_zeros();
            let root_n = if log_n <= 32 {
                let exp = 1u64 << (32 - log_n);
                primitive_root.pow(exp)
            } else {
                // For n > 2^32, we need different handling
                // For now, use a simple multiplicative generator
                FieldElement::new(3)
            };

            // Compute the k-th power

            if inverse {
                // For inverse FFT, use the inverse of the root
                let inv_root = root_n.inverse().unwrap_or(FieldElement::ONE);
                inv_root.pow(k as u64)
            } else {
                root_n.pow(k as u64)
            }
        } else {
            // Non-power-of-2 shouldn't happen in FFT
            FieldElement::ONE
        }
    }
}

pub struct TraceCommitment {
    pub commitment: MultiPolynomialCommitment,
    pub domain_size: usize,
    pub lde_domain_size: usize,
}

impl TraceCommitment {
    pub fn query(&self, position: usize) -> Result<Vec<CommitmentOpening>> {
        self.commitment.open_all(position)
    }

    pub fn verify_query(&self, position: usize, openings: &[CommitmentOpening]) -> bool {
        if openings.iter().any(|o| o.position != position) {
            return false;
        }

        self.commitment.verify_openings(openings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_commitment() {
        let evaluations = vec![
            FieldElement::new(1),
            FieldElement::new(2),
            FieldElement::new(3),
            FieldElement::new(4),
        ];

        let commitment = PolynomialCommitment::new(evaluations.clone()).unwrap();

        for i in 0..evaluations.len() {
            let opening = commitment.open(i).unwrap();
            assert_eq!(opening.evaluation, evaluations[i]);
            assert!(PolynomialCommitment::verify_opening(
                &commitment.merkle_root,
                &opening
            ));
        }
    }

    #[test]
    fn test_multi_polynomial_commitment() {
        let polynomials = vec![
            vec![FieldElement::new(1), FieldElement::new(2)],
            vec![FieldElement::new(3), FieldElement::new(4)],
        ];

        let multi_commitment = MultiPolynomialCommitment::new(polynomials).unwrap();

        let openings = multi_commitment.open_all(0).unwrap();
        assert_eq!(openings.len(), 2);
        assert!(multi_commitment.verify_openings(&openings));
    }

    #[test]
    fn test_fft() {
        let scheme = CommitmentScheme::new(4, 2);
        let mut values = vec![
            FieldElement::new(1),
            FieldElement::new(2),
            FieldElement::new(3),
            FieldElement::new(4),
        ];

        let original = values.clone();
        scheme.fft(&mut values, false).unwrap();
        scheme.fft(&mut values, true).unwrap();

        for i in 0..original.len() {
            let diff = (values[i] - original[i]).as_u64();
            assert!(diff < 1000);
        }
    }
}
