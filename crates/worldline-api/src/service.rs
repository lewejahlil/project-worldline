//! Proving service orchestration — connects API types to the proving pipeline.
//!
//! The `ProvingService` accepts a [`ProofRequest`], invokes the real proving
//! pipeline for each requested proof system, and returns a [`ProofResponse`]
//! with pre-encoded calldata ready for on-chain submission.
//!
//! Supports partial success: if 2 of 3 provers succeed, the response contains
//! results for the successful provers with per-system status reporting.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Instant, SystemTime};

use worldline_recursion::{
    Halo2Prover, InnerProofOutput, InnerProver, MultiProverPipeline, PipelineOutput, ProofSystemId,
    StfInputs,
};

use crate::encoding::{encode_proof, encode_public_inputs};
use crate::error::{ApiError, ProvingError, ValidationError};
use crate::types::{
    EncodedProof, HealthStatus, ProofRequest, ProofResponse, ProofStatus, ProverHealth,
    ProverResult,
};

// ── Configuration ────────────────────────────────────────────────────────────

/// Configuration for the proving service.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Groth16 circuit artifacts (WASM + zkey). `None` if Groth16 is not available.
    pub groth16: Option<SubprocessArtifacts>,
    /// Plonk circuit artifacts (WASM + zkey). `None` if Plonk is not available.
    pub plonk: Option<SubprocessArtifacts>,
    /// Whether the Halo2 prover is enabled (native Rust, no artifacts needed).
    pub halo2_enabled: bool,
    /// Program verification key (pinned in adapter constructors).
    pub program_vkey: [u8; 32],
    /// Policy hash (pinned in adapter constructors).
    pub policy_hash: [u8; 32],
}

/// File paths for snarkjs-based prover artifacts.
#[derive(Debug, Clone)]
pub struct SubprocessArtifacts {
    pub wasm_path: PathBuf,
    pub zkey_path: PathBuf,
}

// ── Health tracking ──────────────────────────────────────────────────────────

struct ProverHealthState {
    status: HealthStatus,
    last_proof_at: Option<SystemTime>,
    last_proving_time_ms: Option<u64>,
    total_proofs: u64,
    total_time_ms: u64,
}

impl ProverHealthState {
    fn new(available: bool) -> Self {
        Self {
            status: if available {
                HealthStatus::Available
            } else {
                HealthStatus::Unavailable
            },
            last_proof_at: None,
            last_proving_time_ms: None,
            total_proofs: 0,
            total_time_ms: 0,
        }
    }

    fn record_success(&mut self, duration_ms: u64) {
        self.status = HealthStatus::Available;
        self.last_proof_at = Some(SystemTime::now());
        self.last_proving_time_ms = Some(duration_ms);
        self.total_proofs += 1;
        self.total_time_ms += duration_ms;
    }

    fn record_failure(&mut self) {
        self.status = HealthStatus::Degraded;
    }

    fn to_health(&self, proof_system_id: u8) -> ProverHealth {
        ProverHealth {
            proof_system_id,
            status: self.status,
            last_proof_at: self.last_proof_at,
            avg_proving_time_ms: if self.total_proofs > 0 {
                Some(self.total_time_ms / self.total_proofs)
            } else {
                None
            },
        }
    }
}

// ── ProvingService ───────────────────────────────────────────────────────────

/// Orchestrates proof generation across multiple ZK proof systems.
///
/// Accepts a [`ProofRequest`], invokes the proving pipeline, and returns a
/// [`ProofResponse`] with pre-encoded calldata. Handles partial success
/// when some provers fail.
pub struct ProvingService {
    config: ServiceConfig,
    health: BTreeMap<u8, ProverHealthState>,
}

impl ProvingService {
    /// Create a new proving service with the given configuration.
    pub fn new(config: ServiceConfig) -> Self {
        let mut health = BTreeMap::new();
        health.insert(1, ProverHealthState::new(config.groth16.is_some()));
        health.insert(2, ProverHealthState::new(config.plonk.is_some()));
        health.insert(3, ProverHealthState::new(config.halo2_enabled));
        Self { config, health }
    }

    /// Generate proofs for the given request.
    ///
    /// Invokes the real proving pipeline for each requested proof system.
    /// Returns a `ProofResponse` with pre-encoded calldata including the
    /// 256-byte `publicInputs` with `submissionBinding` at word 7.
    ///
    /// Supports partial success: if some provers fail, the response contains
    /// results for the successful ones with `ProofStatus::Partial`.
    pub fn prove(&mut self, request: &ProofRequest) -> Result<ProofResponse, ApiError> {
        self.validate(request)?;

        let stf_inputs = self.build_stf_inputs(request);
        let requested: Vec<ProofSystemId> = request
            .requested_systems
            .iter()
            .filter_map(|&id| id_to_system(id))
            .collect();

        // Try the full pipeline first (all requested systems together).
        // If it succeeds, all provers are consistent and we get the shared
        // stfCommitment/proverSetDigest.
        let pipeline_result = self.execute_pipeline(&requested, &stf_inputs, request.quorum_count);

        match pipeline_result {
            Ok(output) => self.build_success_response(request, &output, &requested),
            Err(_pipeline_err) => {
                // Pipeline failed — try each prover individually for partial success.
                self.build_partial_response(request, &stf_inputs, &requested)
            }
        }
    }

    /// Report health status for all configured proof systems.
    pub fn health(&self) -> Vec<ProverHealth> {
        self.health
            .iter()
            .map(|(&id, state)| state.to_health(id))
            .collect()
    }

    /// Report health for a specific proof system.
    pub fn health_for(&self, proof_system_id: u8) -> Option<ProverHealth> {
        self.health
            .get(&proof_system_id)
            .map(|state| state.to_health(proof_system_id))
    }

    // ── Validation ───────────────────────────────────────────────────────

    fn validate(&self, request: &ProofRequest) -> Result<(), ValidationError> {
        if request.batch_size == 0 || request.batch_size > 1024 {
            return Err(ValidationError::BatchSizeOutOfRange(request.batch_size));
        }
        if request.quorum_count == 0 || request.quorum_count > 3 {
            return Err(ValidationError::QuorumOutOfRange(request.quorum_count));
        }
        if request.requested_systems.is_empty() {
            return Err(ValidationError::NoSystemsRequested);
        }
        for &id in &request.proof_system_ids {
            if id != 0 && !(1..=3).contains(&id) {
                return Err(ValidationError::InvalidProofSystemId(id));
            }
        }
        // Check that prover_ids has enough non-zero slots for requested systems
        let non_zero_slots = request.prover_ids.iter().filter(|&&id| id != 0).count();
        if request.requested_systems.len() > non_zero_slots {
            return Err(ValidationError::ProverSlotMismatch {
                requested: request.requested_systems.len(),
                available: non_zero_slots,
            });
        }
        // Verify requested systems are available
        for &sys_id in &request.requested_systems {
            match sys_id {
                1 if self.config.groth16.is_none() => {
                    return Err(ValidationError::NoSystemsRequested)
                }
                2 if self.config.plonk.is_none() => {
                    return Err(ValidationError::NoSystemsRequested)
                }
                3 if !self.config.halo2_enabled => return Err(ValidationError::NoSystemsRequested),
                1..=3 => {}
                other => return Err(ValidationError::InvalidProofSystemId(other as u64)),
            }
        }
        Ok(())
    }

    // ── Pipeline execution ───────────────────────────────────────────────

    fn build_stf_inputs(&self, request: &ProofRequest) -> StfInputs {
        StfInputs {
            pre_state_root: request.pre_state_root,
            post_state_root: request.post_state_root,
            batch_commitment: request.batch_commitment,
            batch_size: request.batch_size,
            prover_ids: request.prover_ids,
            proof_system_ids: request.proof_system_ids,
            quorum_count: request.quorum_count,
        }
    }

    fn execute_pipeline(
        &mut self,
        systems: &[ProofSystemId],
        inputs: &StfInputs,
        quorum: u64,
    ) -> Result<PipelineOutput, ProvingError> {
        let mut pipeline = MultiProverPipeline::new(quorum as u8, 4)
            .map_err(|e| ProvingError::Pipeline(e.to_string()))?;

        for &system in systems {
            let prover = self.create_prover(system)?;
            pipeline.add_prover(prover);
        }

        let start = Instant::now();
        let output = pipeline
            .execute(inputs)
            .map_err(|e| ProvingError::Pipeline(e.to_string()))?;
        let elapsed_ms = start.elapsed().as_millis() as u64;

        // Record success for all participating provers
        for inner in &output.inner_outputs {
            let sys_id = inner.proof_system as u8;
            if let Some(health) = self.health.get_mut(&sys_id) {
                health.record_success(elapsed_ms);
            }
        }

        Ok(output)
    }

    fn create_prover(&self, system: ProofSystemId) -> Result<Box<dyn InnerProver>, ProvingError> {
        match system {
            ProofSystemId::Groth16 => {
                let artifacts =
                    self.config
                        .groth16
                        .as_ref()
                        .ok_or(ProvingError::ProverUnavailable {
                            system: ProofSystemId::Groth16,
                        })?;
                let prover = worldline_recursion::Groth16Prover::new(
                    artifacts.wasm_path.clone(),
                    artifacts.zkey_path.clone(),
                )
                .map_err(|e| ProvingError::ProverFailed {
                    system: ProofSystemId::Groth16,
                    reason: e.to_string(),
                })?;
                Ok(Box::new(prover))
            }
            ProofSystemId::Plonk => {
                let artifacts =
                    self.config
                        .plonk
                        .as_ref()
                        .ok_or(ProvingError::ProverUnavailable {
                            system: ProofSystemId::Plonk,
                        })?;
                let prover = worldline_recursion::PlonkProver::new(
                    artifacts.wasm_path.clone(),
                    artifacts.zkey_path.clone(),
                )
                .map_err(|e| ProvingError::ProverFailed {
                    system: ProofSystemId::Plonk,
                    reason: e.to_string(),
                })?;
                Ok(Box::new(prover))
            }
            ProofSystemId::Halo2 => {
                let prover = Halo2Prover::new().map_err(|e| ProvingError::ProverFailed {
                    system: ProofSystemId::Halo2,
                    reason: e.to_string(),
                })?;
                Ok(Box::new(prover))
            }
        }
    }

    // ── Single-prover execution for partial success ──────────────────────

    fn execute_single_prover(
        &mut self,
        system: ProofSystemId,
        inputs: &StfInputs,
    ) -> Result<InnerProofOutput, ProvingError> {
        let prover = self.create_prover(system)?;
        let start = Instant::now();
        let output = prover.prove(inputs).map_err(|e| {
            let sys_id = system as u8;
            if let Some(health) = self.health.get_mut(&sys_id) {
                health.record_failure();
            }
            ProvingError::ProverFailed {
                system,
                reason: e.to_string(),
            }
        })?;
        let elapsed_ms = start.elapsed().as_millis() as u64;
        let sys_id = system as u8;
        if let Some(health) = self.health.get_mut(&sys_id) {
            health.record_success(elapsed_ms);
        }
        Ok(output)
    }

    // ── Response builders ────────────────────────────────────────────────

    fn build_success_response(
        &self,
        request: &ProofRequest,
        output: &PipelineOutput,
        requested: &[ProofSystemId],
    ) -> Result<ProofResponse, ApiError> {
        let stf_commitment = output.stf_commitment;
        let prover_set_digest = output.prover_set_digest;

        let encoded_public_inputs =
            encode_public_inputs(&stf_commitment, request).map_err(ApiError::Encoding)?;

        let mut proofs = BTreeMap::new();
        let mut encoded_proofs = BTreeMap::new();

        for inner in &output.inner_outputs {
            let sys_id = inner.proof_system as u8;
            proofs.insert(
                sys_id,
                ProverResult {
                    proof_system_id: sys_id,
                    success: true,
                    error: None,
                    proof_length: inner.proof_data.len(),
                },
            );

            let calldata = encode_proof(
                inner.proof_system,
                &inner.proof_data,
                &stf_commitment,
                &prover_set_digest,
            )
            .map_err(ApiError::Encoding)?;

            encoded_proofs.insert(
                sys_id,
                EncodedProof {
                    proof_system_id: sys_id,
                    calldata,
                    raw_proof: inner.proof_data.clone(),
                },
            );
        }

        // Add failure entries for requested systems that weren't in the output
        for &system in requested {
            let sys_id = system as u8;
            proofs.entry(sys_id).or_insert(ProverResult {
                proof_system_id: sys_id,
                success: false,
                error: Some("not present in pipeline output".to_string()),
                proof_length: 0,
            });
        }

        Ok(ProofResponse {
            status: ProofStatus::Complete,
            proofs,
            stf_commitment,
            prover_set_digest,
            encoded_public_inputs,
            encoded_proofs,
            program_vkey: self.config.program_vkey,
            policy_hash: self.config.policy_hash,
        })
    }

    fn build_partial_response(
        &mut self,
        request: &ProofRequest,
        inputs: &StfInputs,
        requested: &[ProofSystemId],
    ) -> Result<ProofResponse, ApiError> {
        let mut proofs = BTreeMap::new();
        let mut encoded_proofs = BTreeMap::new();
        let mut successful_outputs: Vec<InnerProofOutput> = Vec::new();

        for &system in requested {
            let sys_id = system as u8;
            match self.execute_single_prover(system, inputs) {
                Ok(output) => {
                    proofs.insert(
                        sys_id,
                        ProverResult {
                            proof_system_id: sys_id,
                            success: true,
                            error: None,
                            proof_length: output.proof_data.len(),
                        },
                    );
                    successful_outputs.push(output);
                }
                Err(e) => {
                    proofs.insert(
                        sys_id,
                        ProverResult {
                            proof_system_id: sys_id,
                            success: false,
                            error: Some(e.to_string()),
                            proof_length: 0,
                        },
                    );
                }
            }
        }

        let success_count = successful_outputs.len();
        let total_requested = requested.len();

        if success_count == 0 {
            return Ok(ProofResponse {
                status: ProofStatus::Failed,
                proofs,
                stf_commitment: [0u8; 32],
                prover_set_digest: [0u8; 32],
                encoded_public_inputs: vec![0u8; 256],
                encoded_proofs,
                program_vkey: self.config.program_vkey,
                policy_hash: self.config.policy_hash,
            });
        }

        // Use the first successful output's public signals as the reference
        let stf_commitment = successful_outputs[0].public_signals[0];
        let prover_set_digest = successful_outputs[0].public_signals[1];

        let encoded_public_inputs =
            encode_public_inputs(&stf_commitment, request).map_err(ApiError::Encoding)?;

        for output in &successful_outputs {
            let sys_id = output.proof_system as u8;
            let calldata = encode_proof(
                output.proof_system,
                &output.proof_data,
                &stf_commitment,
                &prover_set_digest,
            )
            .map_err(ApiError::Encoding)?;

            encoded_proofs.insert(
                sys_id,
                EncodedProof {
                    proof_system_id: sys_id,
                    calldata,
                    raw_proof: output.proof_data.clone(),
                },
            );
        }

        let status = if success_count == total_requested {
            ProofStatus::Complete
        } else {
            ProofStatus::Partial
        };

        Ok(ProofResponse {
            status,
            proofs,
            stf_commitment,
            prover_set_digest,
            encoded_public_inputs,
            encoded_proofs,
            program_vkey: self.config.program_vkey,
            policy_hash: self.config.policy_hash,
        })
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn id_to_system(id: u8) -> Option<ProofSystemId> {
    match id {
        1 => Some(ProofSystemId::Groth16),
        2 => Some(ProofSystemId::Plonk),
        3 => Some(ProofSystemId::Halo2),
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn halo2_service() -> ProvingService {
        ProvingService::new(ServiceConfig {
            groth16: None,
            plonk: None,
            halo2_enabled: true,
            program_vkey: [0xAA; 32],
            policy_hash: [0xBB; 32],
        })
    }

    fn halo2_request() -> ProofRequest {
        ProofRequest {
            pre_state_root: [0u8; 32],
            post_state_root: [0u8; 32],
            batch_commitment: [0u8; 32],
            batch_size: 100,
            requested_systems: vec![3], // Halo2
            prover_ids: [101, 102, 103],
            proof_system_ids: [1, 2, 3],
            quorum_count: 1,
            l2_start: 0,
            l2_end: 100,
            output_root: [0u8; 32],
            l1_block_hash: [0u8; 32],
            domain_separator: [0xDD; 32],
            window_close_timestamp: 1700000000,
        }
    }

    #[test]
    fn prove_halo2_returns_complete() {
        let mut service = halo2_service();
        let request = halo2_request();

        let response = service.prove(&request).unwrap();

        assert_eq!(response.status, ProofStatus::Complete);
        assert_eq!(response.proofs.len(), 1);
        assert!(response.proofs[&3].success);
        assert_eq!(response.proofs[&3].proof_length, 2016);
        assert_ne!(response.stf_commitment, [0u8; 32]);
        assert_ne!(response.prover_set_digest, [0u8; 32]);
        assert_eq!(response.encoded_public_inputs.len(), 256);
        assert_eq!(response.program_vkey, [0xAA; 32]);
        assert_eq!(response.policy_hash, [0xBB; 32]);
    }

    #[test]
    fn prove_halo2_encoded_proof_present() {
        let mut service = halo2_service();
        let request = halo2_request();

        let response = service.prove(&request).unwrap();

        assert!(response.encoded_proofs.contains_key(&3));
        let encoded = &response.encoded_proofs[&3];
        assert_eq!(encoded.proof_system_id, 3);
        // Halo2 ABI encoding: 128 + 2016 = 2144 bytes
        assert_eq!(encoded.calldata.len(), 128 + 2016);
        assert_eq!(encoded.raw_proof.len(), 2016);
    }

    #[test]
    fn prove_halo2_public_inputs_word7_is_binding() {
        let mut service = halo2_service();
        let request = halo2_request();

        let response = service.prove(&request).unwrap();

        // Verify word 7 = keccak256(abi.encode(words 1-6))
        let pi = &response.encoded_public_inputs;
        let words_1_6 = &pi[32..224];
        let expected = {
            use tiny_keccak::Hasher;
            let mut hasher = tiny_keccak::Keccak::v256();
            let mut out = [0u8; 32];
            hasher.update(words_1_6);
            hasher.finalize(&mut out);
            out
        };
        assert_eq!(&pi[224..256], &expected);
    }

    #[test]
    fn prove_validates_batch_size() {
        let mut service = halo2_service();
        let mut request = halo2_request();
        request.batch_size = 0;

        let err = service.prove(&request).unwrap_err();
        assert!(matches!(
            err,
            ApiError::Validation(ValidationError::BatchSizeOutOfRange(0))
        ));
    }

    #[test]
    fn prove_validates_quorum() {
        let mut service = halo2_service();
        let mut request = halo2_request();
        request.quorum_count = 5;

        let err = service.prove(&request).unwrap_err();
        assert!(matches!(
            err,
            ApiError::Validation(ValidationError::QuorumOutOfRange(5))
        ));
    }

    #[test]
    fn prove_validates_no_systems() {
        let mut service = halo2_service();
        let mut request = halo2_request();
        request.requested_systems = vec![];

        let err = service.prove(&request).unwrap_err();
        assert!(matches!(
            err,
            ApiError::Validation(ValidationError::NoSystemsRequested)
        ));
    }

    #[test]
    fn prove_validates_unavailable_system() {
        let mut service = halo2_service(); // Only Halo2 enabled
        let mut request = halo2_request();
        request.requested_systems = vec![1]; // Groth16 not configured

        let err = service.prove(&request).unwrap_err();
        assert!(matches!(err, ApiError::Validation(_)));
    }

    #[test]
    fn health_reports_all_systems() {
        let service = halo2_service();
        let health = service.health();

        assert_eq!(health.len(), 3);

        // Groth16 and Plonk are unavailable
        assert_eq!(health[0].proof_system_id, 1);
        assert_eq!(health[0].status, HealthStatus::Unavailable);
        assert_eq!(health[1].proof_system_id, 2);
        assert_eq!(health[1].status, HealthStatus::Unavailable);

        // Halo2 is available
        assert_eq!(health[2].proof_system_id, 3);
        assert_eq!(health[2].status, HealthStatus::Available);
    }

    #[test]
    fn health_updates_after_successful_proof() {
        let mut service = halo2_service();
        let request = halo2_request();

        // Before proving
        let health = service.health_for(3).unwrap();
        assert!(health.last_proof_at.is_none());

        // After proving
        service.prove(&request).unwrap();
        let health = service.health_for(3).unwrap();
        assert!(health.last_proof_at.is_some());
        assert!(health.avg_proving_time_ms.is_some());
        assert_eq!(health.status, HealthStatus::Available);
    }

    #[test]
    fn response_serde_roundtrip() {
        let mut service = halo2_service();
        let request = halo2_request();

        let response = service.prove(&request).unwrap();
        let json = serde_json::to_string(&response).unwrap();
        let parsed: ProofResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.status, response.status);
        assert_eq!(parsed.stf_commitment, response.stf_commitment);
        assert_eq!(parsed.prover_set_digest, response.prover_set_digest);
        assert_eq!(parsed.encoded_public_inputs.len(), 256);
        assert_eq!(parsed.proofs.len(), response.proofs.len());
    }

    #[test]
    fn partial_success_when_unavailable_system_requested_alongside_halo2() {
        // Create service with Halo2 only but request both Groth16 and Halo2.
        // Validation will reject requesting unavailable Groth16.
        let mut service = halo2_service();
        let mut request = halo2_request();
        request.requested_systems = vec![1, 3]; // Groth16 + Halo2

        // This should fail validation since Groth16 is not configured
        let err = service.prove(&request).unwrap_err();
        assert!(matches!(err, ApiError::Validation(_)));
    }

    #[test]
    fn prove_validates_prover_slot_mismatch() {
        let mut service = halo2_service();
        let mut request = halo2_request();
        request.prover_ids = [101, 0, 0]; // Only 1 non-zero slot
        request.requested_systems = vec![3, 3]; // 2 systems requested

        let err = service.prove(&request).unwrap_err();
        assert!(matches!(
            err,
            ApiError::Validation(ValidationError::ProverSlotMismatch { .. })
        ));
    }
}
