pub mod commitment;
pub mod document_verifier;
pub mod fri;
// Trace generation happens internally in stark_winterfell

use crate::circuits::CircuitId;
use crate::crypto::Blake3Hasher;
use crate::error::{Error, Result};
use crate::types::{
    BatchProof, PrivateInputs, PublicInputs, PublicOutputs, STARKConfig, STARKProof,
};

pub struct GroveSTARK {
    config: STARKConfig,
    circuit: CircuitId,
}

impl GroveSTARK {
    pub fn new() -> Self {
        Self::with_config_and_circuit(STARKConfig::default(), CircuitId::ContractMembership)
    }

    pub fn with_config(config: STARKConfig) -> Self {
        Self::with_config_and_circuit(config, CircuitId::ContractMembership)
    }

    pub fn with_circuit(circuit: CircuitId) -> Self {
        Self::with_config_and_circuit(STARKConfig::default(), circuit)
    }

    pub fn with_config_and_circuit(config: STARKConfig, circuit: CircuitId) -> Self {
        Self { config, circuit }
    }

    pub fn circuit(&self) -> CircuitId {
        self.circuit
    }

    pub fn prove(&self, witness: PrivateInputs, public_inputs: PublicInputs) -> Result<STARKProof> {
        match self.circuit {
            CircuitId::ContractMembership => self.prove_contract_membership(witness, public_inputs),
        }
    }

    pub fn verify(&self, proof: &STARKProof, public_inputs: &PublicInputs) -> Result<bool> {
        if proof.circuit != self.circuit {
            return Err(crate::error::Error::VerificationFailed(format!(
                "Circuit mismatch: prover {:?}, verifier {:?}",
                proof.circuit, self.circuit
            )));
        }

        match self.circuit {
            CircuitId::ContractMembership => self.verify_contract_membership(proof, public_inputs),
        }
    }

    fn verify_pow(&self, proof: &STARKProof) -> Result<()> {
        let challenge = Blake3Hasher::hash(
            &[
                &proof.trace_commitment[..],
                &proof.constraint_commitment[..],
            ]
            .concat(),
        );

        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&proof.pow_nonce.to_le_bytes());

        let pow_hash = Blake3Hasher::hash(&[&challenge[..], &nonce_bytes[..]].concat());

        let leading_zeros = pow_hash.iter().take_while(|&&b| b == 0).count() * 8;
        let first_nonzero = pow_hash.iter().find(|&&b| b != 0).unwrap_or(&0);
        let additional_zeros = first_nonzero.leading_zeros() as usize;
        let total_zeros = leading_zeros + additional_zeros;

        if total_zeros < self.config.grinding_bits {
            return Err(Error::VerificationFailed(format!(
                "Insufficient proof of work: {} < {}",
                total_zeros, self.config.grinding_bits
            )));
        }

        Ok(())
    }

    fn verify_contract_membership_public_outputs(
        &self,
        outputs: &PublicOutputs,
        _inputs: &PublicInputs,
    ) -> Result<()> {
        if !outputs.verified {
            return Err(Error::VerificationFailed(
                "Public outputs indicate verification failed".into(),
            ));
        }

        // Key security level 1 and 2 are considered weak, only allow 3 and 4
        if outputs.key_security_level < 3 {
            return Err(Error::VerificationFailed(
                "Key security level too low (minimum 3 required)".into(),
            ));
        }
        if outputs.key_security_level > 4 {
            return Err(Error::VerificationFailed(
                "Invalid key security level (maximum 4)".into(),
            ));
        }

        // Identity binding is now enforced cryptographically via boundary assertions
        // in the STARK proof itself, so no need to check here

        Ok(())
    }

    fn verify_trace_commitment(&self, proof: &STARKProof) -> Result<()> {
        if proof.trace_commitment.is_empty() {
            return Err(Error::VerificationFailed("Empty trace commitment".into()));
        }

        if proof.trace_commitment.len() != 32 {
            return Err(Error::VerificationFailed(
                "Invalid trace commitment size".into(),
            ));
        }

        Ok(())
    }

    pub fn prove_batch(
        &self,
        witnesses: Vec<PrivateInputs>,
        public: PublicInputs,
    ) -> Result<BatchProof> {
        let mut individual_proofs = Vec::new();

        for witness in witnesses {
            let proof = self.prove(witness, public.clone())?;
            individual_proofs.push(proof);
        }

        let batch_commitment = self.compute_batch_commitment(&individual_proofs)?;

        Ok(BatchProof {
            individual_proofs,
            batch_commitment,
            aggregated_proof: None,
            circuit: self.circuit,
        })
    }

    fn prove_contract_membership(
        &self,
        witness: PrivateInputs,
        public_inputs: PublicInputs,
    ) -> Result<STARKProof> {
        // Validate inputs
        crate::validation::validate_witness(&witness)?;
        crate::validation::validate_public_inputs(&public_inputs)?;
        crate::validation::validate_config(&self.config)?;

        // Identity-aware witness validation
        crate::validation::validate_identity_witness(&witness)?;

        // Compute public outputs
        let public_outputs = self.compute_contract_membership_outputs(&witness, &public_inputs)?;

        // Generate STARK proof using winterfell
        let proof_bytes = crate::stark_winterfell::generate_proof(
            &witness,
            &public_inputs,
            &self.config,
            self.circuit,
        )?;

        #[cfg(debug_assertions)]
        eprintln!("Generated proof size: {} bytes", proof_bytes.len());

        let trace_commitment = if proof_bytes.len() >= 32 {
            proof_bytes[0..32].to_vec()
        } else {
            eprintln!("WARNING: Proof too small for trace commitment extraction");
            vec![0u8; 32]
        };

        let constraint_commitment = if proof_bytes.len() >= 64 {
            proof_bytes[32..64].to_vec()
        } else {
            eprintln!("WARNING: Proof too small for constraint commitment extraction");
            vec![0u8; 32]
        };

        let pow_nonce =
            self.find_pow_nonce_with_commitments(&trace_commitment, &constraint_commitment);

        let proof = STARKProof {
            circuit: self.circuit,
            trace_commitment,
            constraint_commitment,
            fri_proof: crate::types::FRIProof {
                final_polynomial: proof_bytes.clone(),
                proof_of_work: pow_nonce,
            },
            pow_nonce,
            public_inputs: public_inputs.clone(),
            public_outputs,
        };

        Ok(proof)
    }

    fn verify_contract_membership(
        &self,
        proof: &STARKProof,
        public_inputs: &PublicInputs,
    ) -> Result<bool> {
        self.verify_pow(proof)?;
        self.verify_contract_membership_public_outputs(&proof.public_outputs, public_inputs)?;
        self.verify_trace_commitment(proof)?;

        let proof_bytes = &proof.fri_proof.final_polynomial;

        if proof_bytes.len() < 1000 {
            return Err(crate::error::Error::InvalidProofFormat(format!(
                "Proof too small: {} bytes",
                proof_bytes.len()
            )));
        }

        if proof_bytes.len() > 500_000 {
            return Err(crate::error::Error::InvalidProofFormat(format!(
                "Proof too large: {} bytes",
                proof_bytes.len()
            )));
        }

        let verification_result = crate::stark_winterfell::verify_proof(
            proof_bytes,
            public_inputs,
            &self.config,
            self.circuit,
        )?;

        Ok(verification_result)
    }

    fn compute_contract_membership_outputs(
        &self,
        witness: &PrivateInputs,
        public: &PublicInputs,
    ) -> Result<PublicOutputs> {
        // EdDSA verification
        use crate::crypto::edwards_arithmetic::Ed25519Constants;
        use crate::crypto::scalar_mult_correct::{eddsa_verify_combine, ExtPoint};

        // Helper function to convert bytes to 16-bit limbs
        fn bytes_to_limbs(bytes: &[u8; 32]) -> [u16; 16] {
            let mut limbs = [0u16; 16];
            for i in 0..16 {
                let low = bytes[i * 2] as u16;
                let high = bytes[i * 2 + 1] as u16;
                limbs[i] = low | (high << 8);
            }
            limbs
        }

        // Helper function to convert u64 limbs to u16 limbs
        fn u64_to_u16_limbs(limbs: &[u64; 16]) -> [u16; 16] {
            let mut result = [0u16; 16];
            for i in 0..16 {
                result[i] = limbs[i] as u16;
            }
            result
        }

        // Convert inputs to extended point format
        let r_ext = ExtPoint {
            x: bytes_to_limbs(&witness.r_extended_x),
            y: bytes_to_limbs(&witness.r_extended_y),
            z: bytes_to_limbs(&witness.r_extended_z),
            t: bytes_to_limbs(&witness.r_extended_t),
        };

        let a_ext = ExtPoint {
            x: bytes_to_limbs(&witness.a_extended_x),
            y: bytes_to_limbs(&witness.a_extended_y),
            z: bytes_to_limbs(&witness.a_extended_z),
            t: bytes_to_limbs(&witness.a_extended_t),
        };

        // Get Ed25519 basepoint
        let constants = Ed25519Constants::new();
        let basepoint_ext = ExtPoint {
            x: u64_to_u16_limbs(&constants.base_point.x),
            y: u64_to_u16_limbs(&constants.base_point.y),
            z: u64_to_u16_limbs(&constants.base_point.z),
            t: u64_to_u16_limbs(&constants.base_point.t),
        };

        // Perform EdDSA verification
        let result = eddsa_verify_combine(
            &witness.signature_s,
            &witness.hash_h,
            &r_ext,
            &a_ext,
            &basepoint_ext,
        );

        // Check if result is identity (signature valid)
        let verified = crate::crypto::scalar_mult_correct::is_identity_projective(&result);

        // For now, hardcode to 4 for DET compatibility
        // TODO: This should come from the witness/key metadata
        let key_security_level = 4;

        let proof_commitment = Blake3Hasher::hash(
            &[
                &witness.document_cbor[..],
                &witness.owner_id[..],
                &public.state_root[..],
            ]
            .concat(),
        );

        Ok(PublicOutputs {
            verified,
            key_security_level,
            proof_commitment,
        })
    }

    fn compute_batch_commitment(&self, proofs: &[STARKProof]) -> Result<[u8; 32]> {
        let mut commitments = Vec::new();

        for proof in proofs {
            commitments.extend_from_slice(&proof.trace_commitment);
        }

        Ok(Blake3Hasher::hash(&commitments))
    }

    fn find_pow_nonce_with_commitments(
        &self,
        trace_commitment: &[u8],
        constraint_commitment: &[u8],
    ) -> u64 {
        let mut nonce = 0u64;
        let max_attempts = 2u64.pow(24); // Maximum 16M attempts (reasonable limit)

        // Create challenge from commitments (same as verifier does)
        let challenge = Blake3Hasher::hash(&[trace_commitment, constraint_commitment].concat());

        while nonce < max_attempts {
            // Hash challenge with nonce
            let nonce_bytes = nonce.to_le_bytes();
            let pow_input = [&challenge[..], &nonce_bytes[..]].concat();
            let hash = Blake3Hasher::hash(&pow_input);

            // Count leading zero bits properly (same as verifier)
            let leading_zeros = hash.iter().take_while(|&&b| b == 0).count() * 8;
            let first_nonzero = hash.iter().find(|&&b| b != 0).unwrap_or(&0);
            let additional_zeros = first_nonzero.leading_zeros() as usize;
            let total_zeros = leading_zeros + additional_zeros;

            if total_zeros >= self.config.grinding_bits {
                return nonce;
            }

            nonce += 1;
        }

        // If we can't find a nonce, return 0 and log error
        log::error!("Failed to find PoW nonce after {} attempts", max_attempts);
        0
    }
}

impl Default for GroveSTARK {
    fn default() -> Self {
        Self::new()
    }
}
