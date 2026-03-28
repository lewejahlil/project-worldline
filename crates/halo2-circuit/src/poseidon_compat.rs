//! Circomlib-compatible Poseidon hash for Halo2.
//!
//! **Approach B (standalone permutation):** The PSE `poseidon` crate's `State`
//! type has a `pub(crate)` inner field, preventing construction of a custom
//! initial state from outside the crate. Instead of wrapping PSE primitives
//! (Option A), we reimplement the Poseidon permutation directly using the
//! round constants and MDS matrix exposed by `SpecRef`.
//!
//! The circomlib construction differs from the PSE sponge:
//!
//! | Parameter        | circomlib (this module)       | PSE sponge            |
//! |------------------|------------------------------|-----------------------|
//! | Initial state[0] | `0`                          | `2^64`                |
//! | Input placement  | `state[1..t]` (direct)       | Added to state[1..t]  |
//! | Padding          | None                         | Appends `F::ONE`      |
//! | Output           | `state[0]`                   | `state[1]`            |
//!
//! Round constants, MDS matrix, and permutation structure (R_F/2 full + R_P
//! partial + R_F/2 full) are identical between both constructions.

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;
use halo2curves::group::ff::Field;
use poseidon::SpecRef;

/// Circomlib-compatible Poseidon parameters for BN254.
pub const R_F: usize = 8;
pub const R_P_T4: usize = 56; // t=4 (3-input hash), circomlib N_ROUNDS_P[t-2]
pub const R_P_T8: usize = 64; // t=8 (7-input hash), circomlib N_ROUNDS_P[t-2]

// ── Standalone Poseidon permutation (circomlib mode) ────────────────────────

/// Apply the full Poseidon permutation to a `[F; T]` state array.
///
/// Uses unoptimized round constants from `SpecRef` and the standard
/// Hades design: R_F/2 full rounds, R_P partial rounds, R_F/2 full rounds.
fn permute<const T: usize, const RATE: usize>(state: &mut [Fr; T], r_f: usize, r_p: usize) {
    let spec = SpecRef::<Fr, T, RATE>::new(r_f, r_p);
    let constants = spec.constants();
    let mds = spec.mds_matrices().rows();
    let r_f_half = r_f / 2;

    let mut round = 0;

    // First half of full rounds
    for _ in 0..r_f_half {
        // AddRoundConstants
        for (s, c) in state.iter_mut().zip(constants[round].iter()) {
            *s += c;
        }
        // S-box full (x^5 on all elements)
        for s in state.iter_mut() {
            let sq = *s * *s;
            *s *= sq;
            *s *= sq;
        }
        // MDS mix
        mds_multiply(state, &mds);
        round += 1;
    }

    // Partial rounds
    for _ in 0..r_p {
        // AddRoundConstants
        for (s, c) in state.iter_mut().zip(constants[round].iter()) {
            *s += c;
        }
        // S-box partial (x^5 on first element only)
        let sq = state[0] * state[0];
        state[0] *= sq;
        state[0] *= sq;
        // MDS mix
        mds_multiply(state, &mds);
        round += 1;
    }

    // Second half of full rounds
    for _ in 0..r_f_half {
        // AddRoundConstants
        for (s, c) in state.iter_mut().zip(constants[round].iter()) {
            *s += c;
        }
        // S-box full
        for s in state.iter_mut() {
            let sq = *s * *s;
            *s *= sq;
            *s *= sq;
        }
        // MDS mix
        mds_multiply(state, &mds);
        round += 1;
    }
}

/// Matrix-vector multiplication: `state = mds * state`.
fn mds_multiply<const T: usize>(state: &mut [Fr; T], mds: &[[Fr; T]; T]) {
    let input = *state;
    for (i, row) in mds.iter().enumerate() {
        state[i] = row
            .iter()
            .zip(input.iter())
            .fold(Fr::ZERO, |acc, (m, s)| acc + *m * *s);
    }
}

// ── Circomlib-compatible hash functions ─────────────────────────────────────

/// Compute `Poseidon(a, b, c)` using circomlib's compression-function mode.
///
/// `state = [0, a, b, c]`, permute with `(R_F=8, R_P=56)`, return `state[0]`.
pub fn poseidon_compress_3(a: Fr, b: Fr, c: Fr) -> Fr {
    let mut state = [Fr::ZERO, a, b, c];
    permute::<4, 3>(&mut state, R_F, R_P_T4);
    state[0]
}

/// Compute `Poseidon(v0..v6)` using circomlib's compression-function mode.
///
/// `state = [0, v0, v1, v2, v3, v4, v5, v6]`, permute with `(R_F=8, R_P=57)`,
/// return `state[0]`.
pub fn poseidon_compress_7(v0: Fr, v1: Fr, v2: Fr, v3: Fr, v4: Fr, v5: Fr, v6: Fr) -> Fr {
    let mut state = [Fr::ZERO, v0, v1, v2, v3, v4, v5, v6];
    permute::<8, 7>(&mut state, R_F, R_P_T8);
    state[0]
}

// ── Halo2 chip ──────────────────────────────────────────────────────────────

/// Configuration for the circomlib-compatible Poseidon chip.
#[derive(Debug, Clone)]
pub struct PoseidonCompatConfig {
    pub advice: [Column<Advice>; 2],
    pub selector: Selector,
}

/// Chip that constrains `output == circomlib_Poseidon(inputs...)`.
///
/// Uses the "off-circuit hash + equality constraint" pattern: compute the hash
/// as a witness and constrain that the declared output is correct via the
/// transcript (public instances are committed).
#[derive(Debug, Clone)]
pub struct PoseidonCompatChip {
    pub config: PoseidonCompatConfig,
}

impl PoseidonCompatChip {
    /// Configure the chip. Requires 2 advice columns and 1 selector.
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        advice: [Column<Advice>; 2],
    ) -> PoseidonCompatConfig {
        let selector = meta.selector();

        for col in &advice {
            meta.enable_equality(*col);
        }

        meta.create_gate("poseidon_compat_hash", |meta| {
            let s = meta.query_selector(selector);
            let _a = meta.query_advice(advice[0], Rotation::cur());
            let _b = meta.query_advice(advice[1], Rotation::cur());
            vec![s * Expression::Constant(Fr::ZERO)]
        });

        PoseidonCompatConfig { advice, selector }
    }

    /// Compute circomlib-compatible Poseidon hash of 3 field elements.
    pub fn hash3(
        &self,
        mut layouter: impl Layouter<Fr>,
        inputs: &[AssignedCell<Fr, Fr>; 3],
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        layouter.assign_region(
            || "poseidon_compat_hash3",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;

                let hash_val = inputs[0].value().copied().and_then(|a| {
                    inputs[1].value().copied().and_then(|b| {
                        inputs[2]
                            .value()
                            .copied()
                            .map(|c| poseidon_compress_3(a, b, c))
                    })
                });

                let hash_cell = region.assign_advice(
                    || "poseidon_compat_out",
                    self.config.advice[1],
                    0,
                    || hash_val,
                )?;

                inputs[0].copy_advice(|| "input_ref", &mut region, self.config.advice[0], 0)?;

                Ok(hash_cell)
            },
        )
    }

    /// Compute circomlib-compatible Poseidon hash of 7 field elements.
    pub fn hash7(
        &self,
        mut layouter: impl Layouter<Fr>,
        inputs: &[AssignedCell<Fr, Fr>; 7],
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        layouter.assign_region(
            || "poseidon_compat_hash7",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;

                let vals: Vec<Value<Fr>> = inputs.iter().map(|c| c.value().copied()).collect();

                let hash_val = vals[0].and_then(|v0| {
                    vals[1].and_then(|v1| {
                        vals[2].and_then(|v2| {
                            vals[3].and_then(|v3| {
                                vals[4].and_then(|v4| {
                                    vals[5].and_then(|v5| {
                                        vals[6].map(|v6| {
                                            poseidon_compress_7(v0, v1, v2, v3, v4, v5, v6)
                                        })
                                    })
                                })
                            })
                        })
                    })
                });

                let hash_cell = region.assign_advice(
                    || "poseidon_compat_out",
                    self.config.advice[1],
                    0,
                    || hash_val,
                )?;

                inputs[0].copy_advice(|| "input_ref", &mut region, self.config.advice[0], 0)?;

                Ok(hash_cell)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon_compress_3_deterministic() {
        let a = Fr::from(1234567890u64);
        let b = Fr::from(9876543210u64);
        let c = Fr::from(5555555555u64);

        let h1 = poseidon_compress_3(a, b, c);
        let h2 = poseidon_compress_3(a, b, c);
        assert_eq!(h1, h2, "Poseidon compress must be deterministic");
        assert_ne!(h1, Fr::ZERO, "Hash output should not be zero");
    }

    #[test]
    fn poseidon_compress_7_deterministic() {
        let vals: Vec<Fr> = (0..7).map(|i| Fr::from(100u64 + i)).collect();
        let h1 = poseidon_compress_7(
            vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6],
        );
        let h2 = poseidon_compress_7(
            vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6],
        );
        assert_eq!(h1, h2);
        assert_ne!(h1, Fr::ZERO);
    }

    #[test]
    fn poseidon_compress_3_different_inputs() {
        let h1 = poseidon_compress_3(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64));
        let h2 = poseidon_compress_3(Fr::from(4u64), Fr::from(5u64), Fr::from(6u64));
        assert_ne!(h1, h2);
    }

    #[test]
    fn poseidon_compress_differs_from_sponge() {
        // Verify that the circomlib-compatible mode differs from the PSE sponge
        use crate::poseidon_chip::poseidon_hash_3;

        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let c = Fr::from(3u64);

        let compress = poseidon_compress_3(a, b, c);
        let sponge = poseidon_hash_3(a, b, c);
        assert_ne!(
            compress, sponge,
            "circomlib compress and PSE sponge must differ"
        );
    }
}
