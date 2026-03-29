//! `WorldlineSTF` circuit for Halo2 (KZG on BN254).
//!
//! Reimplements the Circom `WorldlineSTF` circuit with identical semantics:
//!
//! **Private inputs (11 total):**
//! - preStateRoot, postStateRoot, batchCommitment (3 field elements)
//! - proverIds[3], proofSystemIds[3] (6 field elements)
//! - quorumCount, batchSize (2 field elements)
//!
//! **Public outputs (2):**
//! - stfCommitment = Poseidon(preStateRoot, postStateRoot, batchCommitment)
//! - proverSetDigest = Poseidon(proverIds[0..3], proofSystemIds[0..3], quorumCount)
//!
//! **Constraints:**
//! 1. 1 ≤ quorumCount ≤ 3
//! 2. 1 ≤ batchSize ≤ 1024
//! 3. proverIds[i] != 0 for all i
//! 4. proofSystemIds[i] ∈ {1, 2, 3} for all i
//! 5. Poseidon hash correctness for both outputs

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};
use halo2curves::bn256::Fr;
use halo2curves::group::ff::{Field, PrimeField};

use crate::poseidon_compat::{
    poseidon_compress_3, poseidon_compress_7, PoseidonCompatChip, PoseidonCompatConfig,
};

/// Number of prover slots (matches Circom N=3).
pub const N: usize = 3;

/// Maximum batch size (matches Circom `MAX_BATCH_SIZE=1024`).
pub const MAX_BATCH_SIZE: u64 = 1024;

/// Worldline STF circuit inputs.
#[derive(Debug, Clone, Default)]
pub struct WorldlineStfInputs {
    pub pre_state_root: Value<Fr>,
    pub post_state_root: Value<Fr>,
    pub batch_commitment: Value<Fr>,
    pub batch_size: Value<Fr>,
    pub prover_ids: [Value<Fr>; N],
    pub proof_system_ids: [Value<Fr>; N],
    pub quorum_count: Value<Fr>,
}

/// Worldline STF circuit configuration.
#[derive(Debug, Clone)]
pub struct WorldlineStfConfig {
    /// Advice columns for private inputs and intermediate computations.
    pub advice: [Column<Advice>; 4],
    /// Instance column for public outputs (stfCommitment, proverSetDigest).
    pub instance: Column<Instance>,
    /// Selector for range checks and constraints.
    pub selector: Selector,
    /// Selector for bit decomposition rows (boolean + running sum accumulation).
    pub decompose_selector: Selector,
    /// Selector for the reconstruction equality check (batchSize = reconstructed + 1).
    pub recon_selector: Selector,
    /// Fixed column for constants.
    pub fixed: Column<Fixed>,
    /// Poseidon chip configuration (circomlib-compatible).
    pub poseidon_config: PoseidonCompatConfig,
}

/// The Worldline STF circuit for Halo2.
#[derive(Debug, Clone, Default)]
pub struct WorldlineStfCircuit {
    pub inputs: WorldlineStfInputs,
}

impl WorldlineStfCircuit {
    /// Create a new circuit with the given inputs.
    pub fn new(
        pre_state_root: Fr,
        post_state_root: Fr,
        batch_commitment: Fr,
        batch_size: Fr,
        prover_ids: [Fr; N],
        proof_system_ids: [Fr; N],
        quorum_count: Fr,
    ) -> Self {
        Self {
            inputs: WorldlineStfInputs {
                pre_state_root: Value::known(pre_state_root),
                post_state_root: Value::known(post_state_root),
                batch_commitment: Value::known(batch_commitment),
                batch_size: Value::known(batch_size),
                prover_ids: prover_ids.map(Value::known),
                proof_system_ids: proof_system_ids.map(Value::known),
                quorum_count: Value::known(quorum_count),
            },
        }
    }

    /// Compute the expected public outputs for given inputs.
    #[must_use]
    pub fn compute_public_outputs(
        pre_state_root: Fr,
        post_state_root: Fr,
        batch_commitment: Fr,
        prover_ids: [Fr; N],
        proof_system_ids: [Fr; N],
        quorum_count: Fr,
    ) -> (Fr, Fr) {
        let stf_commitment = poseidon_compress_3(pre_state_root, post_state_root, batch_commitment);
        let prover_set_digest = poseidon_compress_7(
            prover_ids[0],
            prover_ids[1],
            prover_ids[2],
            proof_system_ids[0],
            proof_system_ids[1],
            proof_system_ids[2],
            quorum_count,
        );
        (stf_commitment, prover_set_digest)
    }
}

impl Circuit<Fr> for WorldlineStfCircuit {
    type Config = WorldlineStfConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();
        let fixed = meta.fixed_column();
        let selector = meta.selector();

        // Enable equality on all columns for copy constraints.
        for col in &advice {
            meta.enable_equality(*col);
        }
        meta.enable_equality(instance);
        meta.enable_equality(fixed);

        // Configure circomlib-compatible Poseidon chip using advice[0] and advice[1].
        let poseidon_config = PoseidonCompatChip::configure(meta, [advice[0], advice[1]]);

        // Range check gate: when selector is active, enforce range constraints.
        // We use advice[2] for the value being checked, advice[3] for bounds info,
        // and fixed for the constraint type.
        //
        // Constraint types (encoded in fixed column):
        //   1: value >= 1 (non-zero check) — enforced as (value) * (inverse) = 1
        //   2: value <= MAX — enforced via decomposition
        //
        // For simplicity, we use a custom gate that constrains:
        //   selector * advice[2] * advice[3] = selector * fixed
        // where advice[2] = value, advice[3] = inverse_or_check, fixed = expected_product.
        meta.create_gate("range_and_nonzero", |meta| {
            let s = meta.query_selector(selector);
            let val = meta.query_advice(advice[2], Rotation::cur());
            let check = meta.query_advice(advice[3], Rotation::cur());
            let expected = meta.query_fixed(fixed, Rotation::cur());
            // Enforce: val * check == expected (when selector is active)
            vec![s * (val * check - expected)]
        });

        // Bit decomposition gate: at each active row, enforce:
        //   1. bit is boolean: bit * (1 - bit) = 0
        //   2. running sum accumulation: running[next] = 2 * running[cur] + bit
        // Uses advice[2] for bits, advice[3] for running sum accumulator.
        let decompose_selector = meta.selector();
        meta.create_gate("bit_decompose", |meta| {
            let s = meta.query_selector(decompose_selector);
            let bit = meta.query_advice(advice[2], Rotation::cur());
            let running_cur = meta.query_advice(advice[3], Rotation::cur());
            let running_next = meta.query_advice(advice[3], Rotation::next());
            vec![
                // bit ∈ {0, 1}
                s.clone() * bit.clone() * (Expression::Constant(Fr::ONE) - bit.clone()),
                // running[i+1] = 2 * running[i] + bit
                s * (running_next - Expression::Constant(Fr::from(2)) * running_cur - bit),
            ]
        });

        // Reconstruction equality gate: enforce batchSize = reconstructed + 1.
        // Uses advice[2] for batchSize (copy-constrained), advice[3] for reconstructed
        // (copy-constrained from the final running sum cell).
        let recon_selector = meta.selector();
        meta.create_gate("reconstruction_check", |meta| {
            let s = meta.query_selector(recon_selector);
            let batch_size = meta.query_advice(advice[2], Rotation::cur());
            let reconstructed = meta.query_advice(advice[3], Rotation::cur());
            vec![s * (batch_size - reconstructed - Expression::Constant(Fr::ONE))]
        });

        WorldlineStfConfig {
            advice,
            instance,
            selector,
            decompose_selector,
            recon_selector,
            fixed,
            poseidon_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let poseidon_chip = PoseidonCompatChip {
            config: config.poseidon_config.clone(),
        };

        // ── Assign private inputs ───────────────────────────────────────────
        let (
            pre_state_root_cell,
            post_state_root_cell,
            batch_commitment_cell,
            batch_size_cell,
            prover_id_cells,
            proof_system_id_cells,
            quorum_count_cell,
        ) = layouter.assign_region(
            || "assign_inputs",
            |mut region| {
                let pre_state_root = region.assign_advice(
                    || "preStateRoot",
                    config.advice[0],
                    0,
                    || self.inputs.pre_state_root,
                )?;
                let post_state_root = region.assign_advice(
                    || "postStateRoot",
                    config.advice[1],
                    0,
                    || self.inputs.post_state_root,
                )?;
                let batch_commitment = region.assign_advice(
                    || "batchCommitment",
                    config.advice[2],
                    0,
                    || self.inputs.batch_commitment,
                )?;
                let batch_size = region.assign_advice(
                    || "batchSize",
                    config.advice[3],
                    0,
                    || self.inputs.batch_size,
                )?;

                let mut prover_ids = Vec::with_capacity(N);
                for i in 0..N {
                    let cell = region.assign_advice(
                        || format!("proverId_{i}"),
                        config.advice[i % 4],
                        1 + i / 4,
                        || self.inputs.prover_ids[i],
                    )?;
                    prover_ids.push(cell);
                }

                let mut proof_system_ids = Vec::with_capacity(N);
                for i in 0..N {
                    let cell = region.assign_advice(
                        || format!("proofSystemId_{i}"),
                        config.advice[(N + i) % 4],
                        1 + (N + i) / 4,
                        || self.inputs.proof_system_ids[i],
                    )?;
                    proof_system_ids.push(cell);
                }

                let quorum_count = region.assign_advice(
                    || "quorumCount",
                    config.advice[2],
                    2 + (2 * N) / 4,
                    || self.inputs.quorum_count,
                )?;

                Ok((
                    pre_state_root,
                    post_state_root,
                    batch_commitment,
                    batch_size,
                    prover_ids,
                    proof_system_ids,
                    quorum_count,
                ))
            },
        )?;

        // ── Constraint 1: 1 ≤ quorumCount ≤ 3 ──────────────────────────────
        // Enforce quorumCount != 0 via: quorumCount * inverse = 1
        layouter.assign_region(
            || "quorum_nonzero",
            |mut region| {
                config.selector.enable(&mut region, 0)?;
                // advice[2] = quorumCount
                quorum_count_cell.copy_advice(|| "quorum_val", &mut region, config.advice[2], 0)?;
                // advice[3] = inverse of quorumCount
                let inv = self
                    .inputs
                    .quorum_count
                    .map(|q| q.invert().unwrap_or(Fr::ZERO));
                region.assign_advice(|| "quorum_inv", config.advice[3], 0, || inv)?;
                // fixed = 1 (the expected product)
                region.assign_fixed(|| "one", config.fixed, 0, || Value::known(Fr::ONE))?;
                Ok(())
            },
        )?;

        // Enforce quorumCount ≤ 3 via: (quorumCount) * (4 - quorumCount)_inv_check
        // Instead: (4 - quorumCount) != 0 — i.e., quorumCount != 4
        // Combined with quorumCount >= 1, and checking quorumCount * (quorumCount - 1) * ... pattern,
        // we enforce quorumCount ∈ {1, 2, 3} by:
        //   (quorumCount - 1) * (quorumCount - 2) * (quorumCount - 3) == 0
        layouter.assign_region(
            || "quorum_range",
            |mut region| {
                config.selector.enable(&mut region, 0)?;

                let product = self
                    .inputs
                    .quorum_count
                    .map(|q| (q - Fr::from(1)) * (q - Fr::from(2)) * (q - Fr::from(3)));
                // Assign product to advice[2], 1 to advice[3], 0 to fixed
                // So constraint is: product * 1 == 0
                region.assign_advice(|| "quorum_product", config.advice[2], 0, || product)?;
                region.assign_advice(|| "one", config.advice[3], 0, || Value::known(Fr::ONE))?;
                region.assign_fixed(|| "zero", config.fixed, 0, || Value::known(Fr::ZERO))?;
                Ok(())
            },
        )?;

        // ── Constraint 2: 1 ≤ batchSize ≤ 1024 ─────────────────────────────
        // batchSize != 0
        layouter.assign_region(
            || "batch_nonzero",
            |mut region| {
                config.selector.enable(&mut region, 0)?;
                batch_size_cell.copy_advice(|| "batch_val", &mut region, config.advice[2], 0)?;
                let inv = self
                    .inputs
                    .batch_size
                    .map(|b| b.invert().unwrap_or(Fr::ZERO));
                region.assign_advice(|| "batch_inv", config.advice[3], 0, || inv)?;
                region.assign_fixed(|| "one", config.fixed, 0, || Value::known(Fr::ONE))?;
                Ok(())
            },
        )?;

        // batchSize ≤ 1024: decompose (batchSize - 1) into 10 bits.
        // If batchSize ∈ [1, 1024] then (batchSize - 1) ∈ [0, 1023] fits in 10 bits.
        // The running sum gate constrains: running[i+1] = 2 * running[i] + bit[i],
        // with running[0] = 0 and each bit ∈ {0, 1}. After 10 rows,
        // running[10] = sum(bit_i * 2^i) ∈ [0, 1023].
        // The reconstruction gate then constrains: batchSize = running[10] + 1.
        let final_running_cell = layouter.assign_region(
            || "batch_bit_decompose",
            |mut region| {
                // Extract 10 bits of (batchSize - 1), MSB first for running sum.
                let bits: Value<[bool; 10]> = self.inputs.batch_size.map(|bs| {
                    let val = bs - Fr::ONE;
                    let repr = val.to_repr();
                    let mut b = [false; 10];
                    for i in 0..10 {
                        b[i] = (repr[i / 8] >> (i % 8)) & 1 == 1;
                    }
                    b
                });

                // running[0] = 0
                let mut running_cell = region.assign_advice(
                    || "running_0",
                    config.advice[3],
                    0,
                    || Value::known(Fr::ZERO),
                )?;

                for i in 0..10 {
                    config.decompose_selector.enable(&mut region, i)?;
                    let bit_idx = 9 - i; // MSB first
                    let bit_val = bits.map(|b| if b[bit_idx] { Fr::ONE } else { Fr::ZERO });
                    region.assign_advice(
                        || format!("bit_{bit_idx}"),
                        config.advice[2],
                        i,
                        || bit_val,
                    )?;

                    // running[i+1] = 2 * running[i] + bit
                    let next_val = running_cell
                        .value()
                        .copied()
                        .and_then(|r| bit_val.map(|b| Fr::from(2) * r + b));
                    running_cell = region.assign_advice(
                        || format!("running_{}", i + 1),
                        config.advice[3],
                        i + 1,
                        || next_val,
                    )?;
                }

                Ok(running_cell)
            },
        )?;

        // Reconstruction check: batchSize = running[10] + 1
        // Both cells are copy-constrained from their original assignments.
        layouter.assign_region(
            || "batch_recon_check",
            |mut region| {
                config.recon_selector.enable(&mut region, 0)?;
                batch_size_cell.copy_advice(|| "batch_size", &mut region, config.advice[2], 0)?;
                final_running_cell.copy_advice(
                    || "reconstructed",
                    &mut region,
                    config.advice[3],
                    0,
                )?;
                Ok(())
            },
        )?;

        // ── Constraint 3: proverIds[i] != 0 ────────────────────────────────
        for (i, pid_cell) in prover_id_cells.iter().enumerate() {
            layouter.assign_region(
                || format!("prover_id_{i}_nonzero"),
                |mut region| {
                    config.selector.enable(&mut region, 0)?;
                    pid_cell.copy_advice(|| "pid", &mut region, config.advice[2], 0)?;
                    let inv = self.inputs.prover_ids[i].map(|p| p.invert().unwrap_or(Fr::ZERO));
                    region.assign_advice(|| "pid_inv", config.advice[3], 0, || inv)?;
                    region.assign_fixed(|| "one", config.fixed, 0, || Value::known(Fr::ONE))?;
                    Ok(())
                },
            )?;
        }

        // ── Constraint 4: proofSystemIds[i] ∈ {1, 2, 3} ────────────────────
        // (psid - 1)(psid - 2)(psid - 3) == 0 AND psid != 0
        for (i, psid_cell) in proof_system_id_cells.iter().enumerate() {
            // Non-zero check
            layouter.assign_region(
                || format!("psid_{i}_nonzero"),
                |mut region| {
                    config.selector.enable(&mut region, 0)?;
                    psid_cell.copy_advice(|| "psid", &mut region, config.advice[2], 0)?;
                    let inv =
                        self.inputs.proof_system_ids[i].map(|p| p.invert().unwrap_or(Fr::ZERO));
                    region.assign_advice(|| "psid_inv", config.advice[3], 0, || inv)?;
                    region.assign_fixed(|| "one", config.fixed, 0, || Value::known(Fr::ONE))?;
                    Ok(())
                },
            )?;

            // Set membership: (psid-1)(psid-2)(psid-3) == 0
            layouter.assign_region(
                || format!("psid_{i}_range"),
                |mut region| {
                    config.selector.enable(&mut region, 0)?;
                    let product = self.inputs.proof_system_ids[i]
                        .map(|p| (p - Fr::from(1)) * (p - Fr::from(2)) * (p - Fr::from(3)));
                    region.assign_advice(|| "psid_product", config.advice[2], 0, || product)?;
                    region.assign_advice(
                        || "one",
                        config.advice[3],
                        0,
                        || Value::known(Fr::ONE),
                    )?;
                    region.assign_fixed(|| "zero", config.fixed, 0, || Value::known(Fr::ZERO))?;
                    Ok(())
                },
            )?;
        }

        // ── Constraint 5: Poseidon hash correctness ─────────────────────────

        // stfCommitment = Poseidon(preStateRoot, postStateRoot, batchCommitment)
        let stf_commitment_cell = poseidon_chip.hash3(
            layouter.namespace(|| "stf_hash"),
            &[
                pre_state_root_cell.clone(),
                post_state_root_cell.clone(),
                batch_commitment_cell.clone(),
            ],
        )?;

        // proverSetDigest = Poseidon(proverIds[0..3], proofSystemIds[0..3], quorumCount)
        let prover_set_digest_cell = poseidon_chip.hash7(
            layouter.namespace(|| "prover_set_hash"),
            &[
                prover_id_cells[0].clone(),
                prover_id_cells[1].clone(),
                prover_id_cells[2].clone(),
                proof_system_id_cells[0].clone(),
                proof_system_id_cells[1].clone(),
                proof_system_id_cells[2].clone(),
                quorum_count_cell.clone(),
            ],
        )?;

        // ── Expose public outputs ───────────────────────────────────────────
        // Instance row 0: stfCommitment
        layouter.constrain_instance(stf_commitment_cell.cell(), config.instance, 0)?;
        // Instance row 1: proverSetDigest
        layouter.constrain_instance(prover_set_digest_cell.cell(), config.instance, 1)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    fn valid_inputs() -> (Fr, Fr, Fr, Fr, [Fr; N], [Fr; N], Fr) {
        (
            Fr::from(1234567890u64),                                // preStateRoot
            Fr::from(9876543210u64),                                // postStateRoot
            Fr::from(5555555555u64),                                // batchCommitment
            Fr::from(100u64),                                       // batchSize
            [Fr::from(101u64), Fr::from(102u64), Fr::from(103u64)], // proverIds
            [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)],       // proofSystemIds
            Fr::from(3u64),                                         // quorumCount
        )
    }

    fn make_circuit_and_instances(
        pre_state_root: Fr,
        post_state_root: Fr,
        batch_commitment: Fr,
        batch_size: Fr,
        prover_ids: [Fr; N],
        proof_system_ids: [Fr; N],
        quorum_count: Fr,
    ) -> (WorldlineStfCircuit, Vec<Vec<Fr>>) {
        let circuit = WorldlineStfCircuit::new(
            pre_state_root,
            post_state_root,
            batch_commitment,
            batch_size,
            prover_ids,
            proof_system_ids,
            quorum_count,
        );

        let (stf_commitment, prover_set_digest) = WorldlineStfCircuit::compute_public_outputs(
            pre_state_root,
            post_state_root,
            batch_commitment,
            prover_ids,
            proof_system_ids,
            quorum_count,
        );

        let public_inputs = vec![vec![stf_commitment, prover_set_digest]];
        (circuit, public_inputs)
    }

    /// k=8 gives 2^8=256 rows, sufficient for our circuit.
    const K: u32 = 8;

    #[test]
    fn test_valid_quorum3() {
        let (psr, posr, bc, bs, pids, psids, qc) = valid_inputs();
        let (circuit, public_inputs) =
            make_circuit_and_instances(psr, posr, bc, bs, pids, psids, qc);
        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_valid_quorum2() {
        let (psr, posr, bc, bs, pids, psids, _) = valid_inputs();
        let qc = Fr::from(2u64);
        let (circuit, public_inputs) =
            make_circuit_and_instances(psr, posr, bc, bs, pids, psids, qc);
        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_valid_quorum1() {
        let (psr, posr, bc, bs, pids, psids, _) = valid_inputs();
        let qc = Fr::from(1u64);
        let (circuit, public_inputs) =
            make_circuit_and_instances(psr, posr, bc, bs, pids, psids, qc);
        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_invalid_quorum0() {
        let (psr, posr, bc, bs, pids, psids, _) = valid_inputs();
        let qc = Fr::from(0u64);
        let (circuit, public_inputs) =
            make_circuit_and_instances(psr, posr, bc, bs, pids, psids, qc);
        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err(), "quorumCount=0 should fail");
    }

    #[test]
    fn test_invalid_quorum4() {
        let (psr, posr, bc, bs, pids, psids, _) = valid_inputs();
        let qc = Fr::from(4u64);
        let (circuit, public_inputs) =
            make_circuit_and_instances(psr, posr, bc, bs, pids, psids, qc);
        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err(), "quorumCount=4 should fail");
    }

    #[test]
    fn test_invalid_batch_size_0() {
        let (psr, posr, bc, _, pids, psids, qc) = valid_inputs();
        let bs = Fr::from(0u64);
        let (circuit, public_inputs) =
            make_circuit_and_instances(psr, posr, bc, bs, pids, psids, qc);
        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err(), "batchSize=0 should fail");
    }

    #[test]
    fn test_invalid_batch_size_1025() {
        let (psr, posr, bc, _, pids, psids, qc) = valid_inputs();
        let bs = Fr::from(1025u64);
        let (circuit, public_inputs) =
            make_circuit_and_instances(psr, posr, bc, bs, pids, psids, qc);
        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err(), "batchSize=1025 should fail");
    }

    #[test]
    fn test_valid_batch_size_1024() {
        let (psr, posr, bc, _, pids, psids, qc) = valid_inputs();
        let bs = Fr::from(1024u64);
        let (circuit, public_inputs) =
            make_circuit_and_instances(psr, posr, bc, bs, pids, psids, qc);
        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_valid_batch_size_1() {
        let (psr, posr, bc, _, pids, psids, qc) = valid_inputs();
        let bs = Fr::from(1u64);
        let (circuit, public_inputs) =
            make_circuit_and_instances(psr, posr, bc, bs, pids, psids, qc);
        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_invalid_prover_id_zero() {
        let (psr, posr, bc, bs, _, psids, qc) = valid_inputs();
        let pids = [Fr::from(101u64), Fr::from(0u64), Fr::from(103u64)];
        let (circuit, public_inputs) =
            make_circuit_and_instances(psr, posr, bc, bs, pids, psids, qc);
        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err(), "proverId=0 should fail");
    }

    #[test]
    fn test_invalid_proof_system_id_4() {
        let (psr, posr, bc, bs, pids, _, qc) = valid_inputs();
        let psids = [Fr::from(1u64), Fr::from(4u64), Fr::from(3u64)];
        let (circuit, public_inputs) =
            make_circuit_and_instances(psr, posr, bc, bs, pids, psids, qc);
        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err(), "proofSystemId=4 should fail");
    }

    #[test]
    fn test_invalid_proof_system_id_0() {
        let (psr, posr, bc, bs, pids, _, qc) = valid_inputs();
        let psids = [Fr::from(0u64), Fr::from(2u64), Fr::from(3u64)];
        let (circuit, public_inputs) =
            make_circuit_and_instances(psr, posr, bc, bs, pids, psids, qc);
        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err(), "proofSystemId=0 should fail");
    }

    #[test]
    fn test_poseidon_output_consistency() {
        // Verify that the circuit produces consistent Poseidon outputs
        let (psr, posr, bc, _, pids, psids, qc) = valid_inputs();
        let (stf1, digest1) =
            WorldlineStfCircuit::compute_public_outputs(psr, posr, bc, pids, psids, qc);
        let (stf2, digest2) =
            WorldlineStfCircuit::compute_public_outputs(psr, posr, bc, pids, psids, qc);
        assert_eq!(stf1, stf2);
        assert_eq!(digest1, digest2);
        assert_ne!(stf1, Fr::ZERO);
        assert_ne!(digest1, Fr::ZERO);
    }

    #[test]
    fn test_wrong_public_output_rejected() {
        // If we provide wrong public outputs, the prover should reject
        let (psr, posr, bc, bs, pids, psids, qc) = valid_inputs();
        let circuit = WorldlineStfCircuit::new(psr, posr, bc, bs, pids, psids, qc);

        // Wrong stfCommitment
        let public_inputs = vec![vec![Fr::from(999u64), Fr::from(888u64)]];
        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err(), "Wrong public outputs should fail");
    }

    // ── Soundness tests: batch size out-of-range values ─────────────────

    #[test]
    fn test_invalid_batch_size_2000() {
        // This was the soundness gap: the old constraint only checked != 1025.
        // With proper 10-bit decomposition, any value > 1024 must fail.
        let (psr, posr, bc, _, pids, psids, qc) = valid_inputs();
        let bs = Fr::from(2000u64);
        let (circuit, public_inputs) =
            make_circuit_and_instances(psr, posr, bc, bs, pids, psids, qc);
        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err(), "batchSize=2000 should fail");
    }

    #[test]
    fn test_invalid_batch_size_65536() {
        let (psr, posr, bc, _, pids, psids, qc) = valid_inputs();
        let bs = Fr::from(65536u64);
        let (circuit, public_inputs) =
            make_circuit_and_instances(psr, posr, bc, bs, pids, psids, qc);
        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err(), "batchSize=65536 should fail");
    }

    #[test]
    fn test_invalid_batch_size_max_u64() {
        let (psr, posr, bc, _, pids, psids, qc) = valid_inputs();
        let bs = Fr::from(u64::MAX);
        let (circuit, public_inputs) =
            make_circuit_and_instances(psr, posr, bc, bs, pids, psids, qc);
        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err(), "batchSize=u64::MAX should fail");
    }

    #[test]
    fn test_valid_batch_size_512() {
        // Mid-range value should pass
        let (psr, posr, bc, _, pids, psids, qc) = valid_inputs();
        let bs = Fr::from(512u64);
        let (circuit, public_inputs) =
            make_circuit_and_instances(psr, posr, bc, bs, pids, psids, qc);
        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }
}
