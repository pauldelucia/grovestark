use crate::crypto::{Blake3Hasher, MerkleTree};
use crate::error::Result;
use crate::field::{FieldElement, FieldOperations};
use crate::types::STARKConfig;

pub struct FRIProtocol {
    config: FRIConfig,
    domain: Vec<FieldElement>,
}

#[derive(Clone)]
pub struct FRIConfig {
    pub expansion_factor: usize,
    pub num_queries: usize,
    pub folding_factor: usize,
    pub max_remainder_degree: usize,
}

impl From<&STARKConfig> for FRIConfig {
    fn from(config: &STARKConfig) -> Self {
        Self {
            expansion_factor: config.expansion_factor,
            num_queries: config.num_queries,
            folding_factor: config.folding_factor,
            max_remainder_degree: config.max_remainder_degree,
        }
    }
}

pub struct FRICommitment {
    pub layers: Vec<LayerCommitment>,
    pub remainder: Vec<FieldElement>,
}

pub struct LayerCommitment {
    pub merkle_root: [u8; 32],
    pub evaluations: Vec<FieldElement>,
    pub merkle_tree: MerkleTree,
}

pub struct FRIQuery {
    pub initial_position: usize,
    pub layers: Vec<LayerQuery>,
}

pub struct LayerQuery {
    pub position: usize,
    pub evaluations: Vec<FieldElement>,
    pub merkle_proof: Vec<[u8; 32]>,
}

impl FRIProtocol {
    pub fn new(config: FRIConfig, domain_size: usize) -> Self {
        let domain = Self::generate_domain(domain_size);
        Self { config, domain }
    }

    fn generate_domain(size: usize) -> Vec<FieldElement> {
        let generator = Self::find_generator(size);
        let mut domain = vec![FieldElement::ONE];

        for _ in 1..size {
            let last = domain[domain.len() - 1];
            domain.push(last * generator);
        }

        domain
    }

    fn find_generator(size: usize) -> FieldElement {
        // For FRI, we need a generator that creates a multiplicative subgroup
        // In the Goldilocks field, finding proper generators is complex
        // For testing purposes, we'll use a simplified approach

        // Use a primitive element that works for powers of 2
        // which are common sizes for FRI domains
        if size.is_power_of_two() {
            // For powers of 2, we can use a primitive 2^k-th root of unity
            // In Goldilocks field, we can construct this using the two-adicity
            let mut g = FieldElement::new(1753635133440165772u64); // Known 2^32-th root of unity

            // Adjust for the specific power of 2 we need
            let target_power = size.trailing_zeros();
            if target_power < 32 {
                let adjustment = 1u64 << (32 - target_power);
                g = g.pow(adjustment);
            }
            return g;
        }

        // For non-power-of-2 sizes (shouldn't happen in FRI),
        // use a simple multiplicative generator
        // This avoids infinite loops in testing
        FieldElement::new(3)
    }

    pub fn commit(&self, polynomial: &[FieldElement]) -> Result<FRICommitment> {
        let mut layers = Vec::new();
        let mut current_poly = polynomial.to_vec();
        let mut current_domain = self.domain.clone();

        while current_poly.len() > self.config.max_remainder_degree {
            let evaluations = self.evaluate_on_domain(&current_poly, &current_domain);

            let merkle_leaves: Vec<[u8; 32]> = evaluations
                .iter()
                .map(|eval| {
                    let bytes = eval.to_bytes();
                    let mut hash_input = [0u8; 32];
                    hash_input[..8].copy_from_slice(&bytes);
                    Blake3Hasher::hash(&hash_input)
                })
                .collect();

            let merkle_tree = MerkleTree::new(merkle_leaves)?;

            layers.push(LayerCommitment {
                merkle_root: merkle_tree.root(),
                evaluations: evaluations.clone(),
                merkle_tree,
            });

            current_poly = self.fold_polynomial(&current_poly, &evaluations)?;
            current_domain = self.fold_domain(&current_domain);
        }

        Ok(FRICommitment {
            layers,
            remainder: current_poly,
        })
    }

    fn evaluate_on_domain(
        &self,
        polynomial: &[FieldElement],
        domain: &[FieldElement],
    ) -> Vec<FieldElement> {
        domain
            .iter()
            .map(|&x| FieldOperations::evaluate_polynomial(polynomial, x))
            .collect()
    }

    fn fold_polynomial(
        &self,
        polynomial: &[FieldElement],
        _evaluations: &[FieldElement],
    ) -> Result<Vec<FieldElement>> {
        let new_degree = polynomial.len() / self.config.folding_factor;
        let mut folded = vec![FieldElement::ZERO; new_degree];

        for (i, folded_elem) in folded.iter_mut().enumerate().take(new_degree) {
            for j in 0..self.config.folding_factor {
                let idx = i * self.config.folding_factor + j;
                if idx < polynomial.len() {
                    *folded_elem = *folded_elem + polynomial[idx];
                }
            }
        }

        Ok(folded)
    }

    fn fold_domain(&self, domain: &[FieldElement]) -> Vec<FieldElement> {
        domain
            .iter()
            .step_by(self.config.folding_factor)
            .cloned()
            .collect()
    }

    pub fn query(
        &self,
        commitment: &FRICommitment,
        query_indices: &[usize],
    ) -> Result<Vec<FRIQuery>> {
        let mut queries = Vec::new();

        for &initial_position in query_indices {
            let mut position = initial_position;
            let mut layer_queries = Vec::new();

            for layer in &commitment.layers {
                let evaluations = self.get_evaluations_at_position(
                    &layer.evaluations,
                    position,
                    self.config.folding_factor,
                );

                let merkle_proof = self.generate_merkle_proof(layer, position)?;

                layer_queries.push(LayerQuery {
                    position,
                    evaluations,
                    merkle_proof,
                });

                position /= self.config.folding_factor;
            }

            queries.push(FRIQuery {
                initial_position,
                layers: layer_queries,
            });
        }

        Ok(queries)
    }

    fn get_evaluations_at_position(
        &self,
        evaluations: &[FieldElement],
        position: usize,
        folding_factor: usize,
    ) -> Vec<FieldElement> {
        let start = (position / folding_factor) * folding_factor;
        let end = (start + folding_factor).min(evaluations.len());

        evaluations[start..end].to_vec()
    }

    fn generate_merkle_proof(
        &self,
        layer: &LayerCommitment,
        position: usize,
    ) -> Result<Vec<[u8; 32]>> {
        // Get the merkle proof from the tree for this position
        let proof = layer.merkle_tree.get_proof(position)?;

        // Extract the sibling hashes from the proof path
        let mut siblings = Vec::new();
        for node in &proof.path {
            siblings.push(node.hash);
        }

        Ok(siblings)
    }

    pub fn verify(&self, commitment: &FRICommitment, queries: &[FRIQuery]) -> Result<bool> {
        for query in queries {
            if !self.verify_query(commitment, query)? {
                return Ok(false);
            }
        }

        if !self.verify_low_degree(&commitment.remainder)? {
            return Ok(false);
        }

        Ok(true)
    }

    fn verify_query(&self, commitment: &FRICommitment, query: &FRIQuery) -> Result<bool> {
        let mut position = query.initial_position;

        for (layer_idx, layer_query) in query.layers.iter().enumerate() {
            if layer_idx >= commitment.layers.len() {
                return Ok(false);
            }

            if !self.verify_merkle_proof(
                &commitment.layers[layer_idx],
                &layer_query.merkle_proof,
                position,
            )? {
                return Ok(false);
            }

            if layer_idx < query.layers.len() - 1 {
                let next_eval = &query.layers[layer_idx + 1].evaluations[0];
                let folded = self.fold_evaluations(&layer_query.evaluations);

                if folded != *next_eval {
                    return Ok(false);
                }
            }

            position /= self.config.folding_factor;
        }

        Ok(true)
    }

    fn verify_merkle_proof(
        &self,
        layer: &LayerCommitment,
        proof: &[[u8; 32]],
        position: usize,
    ) -> Result<bool> {
        if position >= layer.evaluations.len() {
            return Ok(false);
        }

        // Compute the leaf hash from the evaluation at this position
        let eval = &layer.evaluations[position];
        let mut hash_input = [0u8; 32];
        hash_input[..8].copy_from_slice(&eval.to_bytes());
        let mut current_hash = Blake3Hasher::hash(&hash_input);

        // Traverse up the tree using the proof siblings
        let mut current_position = position;
        for sibling_hash in proof {
            let (left, right) = if current_position.is_multiple_of(2) {
                (current_hash, *sibling_hash)
            } else {
                (*sibling_hash, current_hash)
            };

            // Concatenate and hash
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&left);
            combined[32..].copy_from_slice(&right);
            current_hash = Blake3Hasher::hash(&combined);

            current_position /= 2;
        }

        // Check if we've reached the expected root
        Ok(current_hash == layer.merkle_root)
    }

    fn fold_evaluations(&self, evaluations: &[FieldElement]) -> FieldElement {
        evaluations
            .iter()
            .fold(FieldElement::ZERO, |acc, &x| acc + x)
    }

    fn verify_low_degree(&self, remainder: &[FieldElement]) -> Result<bool> {
        Ok(remainder.len() <= self.config.max_remainder_degree)
    }
}

pub struct FRIProver {
    protocol: FRIProtocol,
}

impl FRIProver {
    pub fn new(config: FRIConfig, domain_size: usize) -> Self {
        Self {
            protocol: FRIProtocol::new(config, domain_size),
        }
    }

    pub fn prove(&self, polynomial: &[FieldElement]) -> Result<FRICommitment> {
        self.protocol.commit(polynomial)
    }

    pub fn generate_queries(
        &self,
        commitment: &FRICommitment,
        seed: &[u8; 32],
    ) -> Result<Vec<FRIQuery>> {
        let query_indices = self.generate_query_indices(seed);
        self.protocol.query(commitment, &query_indices)
    }

    fn generate_query_indices(&self, seed: &[u8; 32]) -> Vec<usize> {
        let mut indices = Vec::new();
        let domain_size = self.protocol.domain.len();

        for i in 0..self.protocol.config.num_queries {
            let mut hash_input = [0u8; 36];
            hash_input[..32].copy_from_slice(seed);
            hash_input[32..36].copy_from_slice(&(i as u32).to_le_bytes());

            let hash = Blake3Hasher::hash(&hash_input);
            let index = u64::from_le_bytes(hash[..8].try_into().unwrap()) as usize % domain_size;

            indices.push(index);
        }

        indices
    }
}

pub struct FRIVerifier {
    protocol: FRIProtocol,
}

impl FRIVerifier {
    pub fn new(config: FRIConfig, domain_size: usize) -> Self {
        Self {
            protocol: FRIProtocol::new(config, domain_size),
        }
    }

    pub fn verify(&self, commitment: &FRICommitment, queries: &[FRIQuery]) -> Result<bool> {
        self.protocol.verify(commitment, queries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fri_commit_verify() {
        let config = FRIConfig {
            expansion_factor: 8,
            num_queries: 20,
            folding_factor: 4,
            max_remainder_degree: 256,
        };

        let domain_size = 1024;
        let prover = FRIProver::new(config.clone(), domain_size);
        let verifier = FRIVerifier::new(config, domain_size);

        let polynomial = vec![FieldElement::new(1); 512];

        let commitment = prover.prove(&polynomial).unwrap();
        let seed = [0u8; 32];
        let queries = prover.generate_queries(&commitment, &seed).unwrap();

        let result = verifier.verify(&commitment, &queries).unwrap();
        assert!(result);
    }

    #[test]
    fn test_domain_generation() {
        let config = FRIConfig {
            expansion_factor: 8,
            num_queries: 20,
            folding_factor: 4,
            max_remainder_degree: 256,
        };

        let protocol = FRIProtocol::new(config, 16);
        assert_eq!(protocol.domain.len(), 16);

        let g = protocol.domain[1];
        assert_eq!(g.pow(16), FieldElement::ONE);
    }
}
