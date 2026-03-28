#![allow(dead_code)]

use crate::types::ProofSystemId;

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("invalid proof length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("verification failed: {reason}")]
    VerificationFailed { reason: String },
    #[error("backend error: {0}")]
    BackendError(String),
}

pub trait ProofVerifier: Send + Sync {
    fn verify(
        &self,
        proof_data: &[u8],
        public_inputs: &[[u8; 32]],
    ) -> Result<bool, VerificationError>;

    fn proof_system_id(&self) -> ProofSystemId;
    fn expected_proof_length(&self) -> usize;
}

pub struct MockVerifier {
    pub system_id: ProofSystemId,
    pub should_pass: bool,
}

impl ProofVerifier for MockVerifier {
    fn verify(
        &self,
        proof_data: &[u8],
        _public_inputs: &[[u8; 32]],
    ) -> Result<bool, VerificationError> {
        let expected = self.expected_proof_length();
        if proof_data.len() != expected {
            return Err(VerificationError::InvalidLength {
                expected,
                actual: proof_data.len(),
            });
        }
        Ok(self.should_pass)
    }

    fn proof_system_id(&self) -> ProofSystemId {
        self.system_id
    }

    fn expected_proof_length(&self) -> usize {
        match self.system_id {
            ProofSystemId::Groth16 => 320,
            ProofSystemId::Plonk => 256,
            ProofSystemId::Halo2 => 192,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_verifier_passes_correct_length() {
        let v = MockVerifier {
            system_id: ProofSystemId::Groth16,
            should_pass: true,
        };
        let proof = vec![0u8; 320];
        assert!(v.verify(&proof, &[]).unwrap());
    }

    #[test]
    fn mock_verifier_rejects_wrong_length() {
        let v = MockVerifier {
            system_id: ProofSystemId::Groth16,
            should_pass: true,
        };
        let proof = vec![0u8; 100];
        let err = v.verify(&proof, &[]).unwrap_err();
        assert!(matches!(
            err,
            VerificationError::InvalidLength {
                expected: 320,
                actual: 100
            }
        ));
    }

    #[test]
    fn mock_verifier_can_fail() {
        let v = MockVerifier {
            system_id: ProofSystemId::Plonk,
            should_pass: false,
        };
        let proof = vec![0u8; 256];
        assert!(!v.verify(&proof, &[]).unwrap());
    }

    #[test]
    fn mock_verifier_halo2_length() {
        let v = MockVerifier {
            system_id: ProofSystemId::Halo2,
            should_pass: true,
        };
        assert_eq!(v.expected_proof_length(), 192);
    }
}
