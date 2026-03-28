//! Poseidon cross-system conformance tests.
//!
//! Verifies whether the Halo2 (PSE) Poseidon implementation produces identical
//! hash outputs to circomlib's Poseidon for the same BN254 field inputs.
//!
//! ## Reference values
//!
//! Computed via `circomlibjs.buildPoseidon()` using the standard circomlib
//! `Poseidon(nInputs)` template from `circuits/poseidon.circom`:
//!
//! Inputs (from `circuits/test/worldline_stf.test.ts` validInputs()):
//!   - preStateRoot  = 1234567890
//!   - postStateRoot  = 9876543210
//!   - batchCommitment = 5555555555
//!   - proverIds       = [101, 102, 103]
//!   - proofSystemIds  = [1, 2, 3]
//!   - quorumCount     = 3
//!
//! circomlib outputs:
//! - stfCommitment   = Poseidon(preStateRoot, postStateRoot, batchCommitment)
//!   = 0x2e1de696850f25d0594670ee7fd253af5893e313da0d8a161d63fa9994baf9e4
//! - proverSetDigest = Poseidon(101, 102, 103, 1, 2, 3, 3)
//!   = 0x1fd78c89d17a4450342e2a585e8d944473b80295914aa47d519d7ee0e5cc453f
//!
//! ## Mismatch analysis
//!
//! The PSE `poseidon` crate (v0.2.0) and circomlib use **different Poseidon
//! constructions** over the same BN254 scalar field:
//!
//! | Parameter            | circomlib                              | PSE poseidon crate         |
//! |----------------------|----------------------------------------|----------------------------|
//! | Mode                 | Compression function (single perm)     | Sponge (absorb + squeeze)  |
//! | Initial state[0]     | `0` (initialState signal)              | `2^64` (capacity marker)   |
//! | Input placement      | `state[1..t]` before 1st ARC           | Added to `state[1..RATE]`  |
//! | Padding              | None                                   | Appends `F::ONE` after inputs |
//! | Output               | `state[0]` after final MDS mix         | `state[1]` after squeeze   |
//! | R_F / R_P (t=4)      | 8 / 56                                 | 8 / 56 (same)              |
//! | R_F / R_P (t=8)      | 8 / 57                                 | 8 / 57 (same)              |
//! | Round constants      | POSEIDON_C/S/M/P from Grain LFSR       | Grain LFSR (same seed)     |
//!
//! While both implementations use the same round parameters (R_F, R_P) and the
//! same round constant generation (Grain LFSR), the **construction mode** differs:
//!
//! - circomlib uses a **fixed-length compression function**: inputs are placed
//!   directly into the state alongside an `initialState=0` capacity element,
//!   a single permutation is applied, and `state[0]` is the output.
//!
//! - PSE uses a **variable-length sponge**: the capacity is initialized to `2^64`,
//!   inputs are absorbed in RATE-sized chunks into `state[1..]`, a `1` padding
//!   element is appended, then `state[1]` is squeezed as output.
//!
//! These are fundamentally incompatible constructions. For cross-system
//! verification (Halo2 proof matching Groth16 stfCommitment), the Halo2 circuit
//! would need a Poseidon gadget that reimplements circomlib's compression-function
//! mode rather than the PSE sponge.
//!
//! The tests below are marked `#[ignore]` because the outputs diverge.
//! They serve as documentation of the exact values and the root cause.

use halo2curves::bn256::Fr;
use halo2curves::group::ff::PrimeField;
use worldline_halo2_circuit::{poseidon_compress_3, poseidon_compress_7, WorldlineStfCircuit};

/// Convert a hex string (with 0x prefix) to a BN254 Fr element.
fn fr_from_hex(hex_str: &str) -> Fr {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let mut bytes = hex::decode(hex_str).expect("valid hex");
    // hex is big-endian, Fr::from_repr expects little-endian
    bytes.reverse();
    let mut repr = [0u8; 32];
    repr[..bytes.len()].copy_from_slice(&bytes);
    Fr::from_repr(repr).expect("valid field element")
}

/// Convert Fr to hex string for display.
fn fr_to_hex(f: &Fr) -> String {
    let repr = f.to_repr();
    let mut bytes = repr.as_ref().to_vec();
    bytes.reverse();
    format!("0x{}", hex::encode(bytes))
}

// ── circomlib reference values ──────────────────────────────────────────────

/// circomlib Poseidon(1234567890, 9876543210, 5555555555) output.
/// Computed via: `circomlibjs.buildPoseidon()([1234567890n, 9876543210n, 5555555555n])`
const CIRCOMLIB_STF_COMMITMENT: &str =
    "0x2e1de696850f25d0594670ee7fd253af5893e313da0d8a161d63fa9994baf9e4";

/// circomlib Poseidon(101, 102, 103, 1, 2, 3, 3) output.
/// Computed via: `circomlibjs.buildPoseidon()([101n, 102n, 103n, 1n, 2n, 3n, 3n])`
const CIRCOMLIB_PROVER_SET_DIGEST: &str =
    "0x1fd78c89d17a4450342e2a585e8d944473b80295914aa47d519d7ee0e5cc453f";

// ── Test 1: Poseidon 3-input conformance ────────────────────────────────────

/// Verify that Halo2's Poseidon(3) produces the same output as circomlib's.
///
/// IGNORED: The outputs diverge due to different constructions
/// (sponge vs compression function). See module-level docs for details.
///
/// Halo2 PSE output:  0x06a3ec151a5931765cbe6a5c50aef89ca0b13c21432dff8ab5a2bdfc58c906e1
/// circomlib output:   0x2e1de696850f25d0594670ee7fd253af5893e313da0d8a161d63fa9994baf9e4
#[test]
fn poseidon_3input_matches_circomlib() {
    let pre_state_root = Fr::from(1234567890u64);
    let post_state_root = Fr::from(9876543210u64);
    let batch_commitment = Fr::from(5555555555u64);

    let halo2_output = poseidon_compress_3(pre_state_root, post_state_root, batch_commitment);
    let circomlib_expected = fr_from_hex(CIRCOMLIB_STF_COMMITMENT);

    eprintln!("Halo2 PSE stfCommitment:  {}", fr_to_hex(&halo2_output));
    eprintln!(
        "circomlib stfCommitment:   {}",
        fr_to_hex(&circomlib_expected)
    );

    assert_eq!(
        halo2_output,
        circomlib_expected,
        "Poseidon(3) output mismatch: PSE sponge vs circomlib compression.\n\
         Halo2:    {}\n\
         Expected: {}",
        fr_to_hex(&halo2_output),
        fr_to_hex(&circomlib_expected),
    );
}

// ── Test 2: Poseidon 7-input conformance ────────────────────────────────────

/// Verify that Halo2's Poseidon(7) produces the same output as circomlib's.
///
/// IGNORED: Same root cause as poseidon_3input_matches_circomlib.
///
/// Halo2 PSE output:  0x1e5f4a068ea1e76965749081cc5e80d077198ceeb91169e295fbdf0d7b489711
/// circomlib output:   0x1fd78c89d17a4450342e2a585e8d944473b80295914aa47d519d7ee0e5cc453f
#[test]
fn poseidon_7input_matches_circomlib() {
    let halo2_output = poseidon_compress_7(
        Fr::from(101u64),
        Fr::from(102u64),
        Fr::from(103u64),
        Fr::from(1u64),
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(3u64),
    );
    let circomlib_expected = fr_from_hex(CIRCOMLIB_PROVER_SET_DIGEST);

    eprintln!("Halo2 PSE proverSetDigest: {}", fr_to_hex(&halo2_output));
    eprintln!(
        "circomlib proverSetDigest:  {}",
        fr_to_hex(&circomlib_expected)
    );

    assert_eq!(
        halo2_output,
        circomlib_expected,
        "Poseidon(7) output mismatch: PSE sponge vs circomlib compression.\n\
         Halo2:    {}\n\
         Expected: {}",
        fr_to_hex(&halo2_output),
        fr_to_hex(&circomlib_expected),
    );
}

// ── Test 3: stfCommitment full-circuit cross-system ─────────────────────────

/// Run the full Halo2 STF circuit with circom test inputs and compare
/// the stfCommitment public output to the circomlib expected value.
///
/// IGNORED: The Poseidon mismatch propagates to the circuit's public outputs.
#[test]
fn stf_commitment_cross_system() {
    use halo2_proofs::dev::MockProver;

    let pre_state_root = Fr::from(1234567890u64);
    let post_state_root = Fr::from(9876543210u64);
    let batch_commitment = Fr::from(5555555555u64);
    let batch_size = Fr::from(100u64);
    let prover_ids = [Fr::from(101u64), Fr::from(102u64), Fr::from(103u64)];
    let proof_system_ids = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let quorum_count = Fr::from(3u64);

    // Compute Halo2 outputs (these will match the circuit's public instances)
    let (halo2_stf, halo2_digest) = WorldlineStfCircuit::compute_public_outputs(
        pre_state_root,
        post_state_root,
        batch_commitment,
        prover_ids,
        proof_system_ids,
        quorum_count,
    );

    // Verify the circuit satisfies with Halo2's own outputs
    let circuit = WorldlineStfCircuit::new(
        pre_state_root,
        post_state_root,
        batch_commitment,
        batch_size,
        prover_ids,
        proof_system_ids,
        quorum_count,
    );
    let prover = MockProver::run(8, &circuit, vec![vec![halo2_stf, halo2_digest]]).unwrap();
    prover.assert_satisfied();

    // Now compare with circomlib expected values
    let circomlib_stf = fr_from_hex(CIRCOMLIB_STF_COMMITMENT);

    eprintln!("Halo2 circuit stfCommitment:  {}", fr_to_hex(&halo2_stf));
    eprintln!(
        "circomlib stfCommitment:       {}",
        fr_to_hex(&circomlib_stf)
    );

    assert_eq!(
        halo2_stf,
        circomlib_stf,
        "stfCommitment from Halo2 circuit does not match circomlib.\n\
         Halo2:    {}\n\
         Expected: {}",
        fr_to_hex(&halo2_stf),
        fr_to_hex(&circomlib_stf),
    );
}

// ── Test 4: proverSetDigest full-circuit cross-system ───────────────────────

/// Run the full Halo2 STF circuit with circom test inputs and compare
/// the proverSetDigest public output to the circomlib expected value.
///
/// IGNORED: The Poseidon mismatch propagates to the circuit's public outputs.
#[test]
fn prover_set_digest_cross_system() {
    use halo2_proofs::dev::MockProver;

    let pre_state_root = Fr::from(1234567890u64);
    let post_state_root = Fr::from(9876543210u64);
    let batch_commitment = Fr::from(5555555555u64);
    let batch_size = Fr::from(100u64);
    let prover_ids = [Fr::from(101u64), Fr::from(102u64), Fr::from(103u64)];
    let proof_system_ids = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let quorum_count = Fr::from(3u64);

    let (halo2_stf, halo2_digest) = WorldlineStfCircuit::compute_public_outputs(
        pre_state_root,
        post_state_root,
        batch_commitment,
        prover_ids,
        proof_system_ids,
        quorum_count,
    );

    // Verify the circuit satisfies with Halo2's own outputs
    let circuit = WorldlineStfCircuit::new(
        pre_state_root,
        post_state_root,
        batch_commitment,
        batch_size,
        prover_ids,
        proof_system_ids,
        quorum_count,
    );
    let prover = MockProver::run(8, &circuit, vec![vec![halo2_stf, halo2_digest]]).unwrap();
    prover.assert_satisfied();

    // Now compare with circomlib expected values
    let circomlib_digest = fr_from_hex(CIRCOMLIB_PROVER_SET_DIGEST);

    eprintln!(
        "Halo2 circuit proverSetDigest: {}",
        fr_to_hex(&halo2_digest)
    );
    eprintln!(
        "circomlib proverSetDigest:      {}",
        fr_to_hex(&circomlib_digest)
    );

    assert_eq!(
        halo2_digest,
        circomlib_digest,
        "proverSetDigest from Halo2 circuit does not match circomlib.\n\
         Halo2:    {}\n\
         Expected: {}",
        fr_to_hex(&halo2_digest),
        fr_to_hex(&circomlib_digest),
    );
}
