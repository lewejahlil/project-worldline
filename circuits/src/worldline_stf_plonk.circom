pragma circom 2.1.6;

/**
 * worldline_stf_plonk.circom — Independent Path B implementation of the
 * Worldline State Transition Function commitment circuit.
 *
 * This circuit is a ground-up reimplementation of the same STF specification
 * as circuits/stf/worldline_stf.circom. It exists to provide implementation
 * diversity: a bug in the original circuit that silently produces wrong
 * commitments would be caught because this circuit would produce a different
 * public output for the same inputs.
 *
 * Specification compliance:
 *   - 11 private inputs: preStateRoot, postStateRoot, batchCommitment,
 *     proverIds[3], proofSystemIds[3], quorumCount, batchSize
 *   - 2 public outputs: stfCommitment, proverSetDigest
 *   - stfCommitment   = Poseidon(preStateRoot, postStateRoot, batchCommitment)
 *   - proverSetDigest = Poseidon(proverIds[0], proverIds[1], proverIds[2],
 *                                proofSystemIds[0], proofSystemIds[1],
 *                                proofSystemIds[2], quorumCount)
 *
 * Structural differences from original:
 *   - Range validation factored into self-contained ValidateRange template
 *   - Non-zero check uses a direct product constraint instead of IsZero gadget
 *   - Proof-system membership check uses a polynomial identity approach
 *   - Signal names differ throughout (e.g. stateHash, setHash, lo, hi)
 *   - Template decomposition is different but hash inputs/outputs are identical
 *
 * Curve: BN254 (field order q ≈ 2^254)
 */

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// ---------------------------------------------------------------------------
// Helper: enforce  lo <= x <= hi  using LessEqThan comparators.
// `bits` must be wide enough to represent hi.
// ---------------------------------------------------------------------------
template ValidateRange(bits) {
    signal input x;
    signal input lo;
    signal input hi;

    component checkLo = LessEqThan(bits);
    checkLo.in[0] <== lo;
    checkLo.in[1] <== x;
    checkLo.out === 1;

    component checkHi = LessEqThan(bits);
    checkHi.in[0] <== x;
    checkHi.in[1] <== hi;
    checkHi.out === 1;
}

// ---------------------------------------------------------------------------
// Helper: enforce x != 0 by requiring a multiplicative inverse exists.
// If x == 0 there is no field element inv such that x * inv == 1.
// ---------------------------------------------------------------------------
template NonZero() {
    signal input x;
    signal inv;
    inv <-- x != 0 ? 1 / x : 0;
    x * inv === 1;
}

// ---------------------------------------------------------------------------
// Helper: enforce x in {1, 2, 3} using the polynomial (x-1)(x-2)(x-3) == 0.
// This is a single-constraint membership check over the small set {1,2,3}.
// ---------------------------------------------------------------------------
template InSet123() {
    signal input x;
    signal a;
    signal b;
    a <== x - 1;        // x - 1
    b <== x - 2;        // x - 2
    signal c;
    c <== a * b;         // (x-1)(x-2)
    signal d;
    d <== x - 3;        // x - 3
    c * d === 0;         // (x-1)(x-2)(x-3) == 0  ⟺  x ∈ {1,2,3}
}

// ---------------------------------------------------------------------------
// STF state hash: Poseidon(preStateRoot, postStateRoot, batchCommitment)
// Identical hash parameters to the original — ensures output parity.
// ---------------------------------------------------------------------------
template StateTransitionHash() {
    signal input preRoot;
    signal input postRoot;
    signal input batchCmt;
    signal output stateHash;

    component h = Poseidon(3);
    h.inputs[0] <== preRoot;
    h.inputs[1] <== postRoot;
    h.inputs[2] <== batchCmt;
    stateHash <== h.out;
}

// ---------------------------------------------------------------------------
// Prover-set hash: Poseidon(pid0, pid1, pid2, sys0, sys1, sys2, quorum)
// Input ordering matches the original ProverSetDigest(N=3) template so that
// both circuits produce numerically identical proverSetDigest values.
// ---------------------------------------------------------------------------
template ProverSetHash() {
    signal input pid[3];     // prover IDs
    signal input sys[3];     // proof-system IDs
    signal input quorum;
    signal output setHash;

    component h = Poseidon(7);
    // Indices 0..2 → proverIds  (matches original: inputs[i] for i in 0..N-1)
    h.inputs[0] <== pid[0];
    h.inputs[1] <== pid[1];
    h.inputs[2] <== pid[2];
    // Indices 3..5 → proofSystemIds  (matches original: inputs[N+i] for i in 0..N-1)
    h.inputs[3] <== sys[0];
    h.inputs[4] <== sys[1];
    h.inputs[5] <== sys[2];
    // Index 6 → quorumCount  (matches original: inputs[2*N])
    h.inputs[6] <== quorum;
    setHash <== h.out;
}

// ---------------------------------------------------------------------------
// Main template: WorldlineSTFV2
//
// Identical public interface to WorldlineSTF(3,1024):
//   outputs: stfCommitment, proverSetDigest
// All inputs are private.
// ---------------------------------------------------------------------------
template WorldlineSTFV2() {
    // ── Private inputs ──────────────────────────────────────────────────────
    signal input preStateRoot;
    signal input postStateRoot;
    signal input batchCommitment;
    signal input batchSize;
    signal input proverIds[3];
    signal input proofSystemIds[3];
    signal input quorumCount;

    // ── Public outputs ───────────────────────────────────────────────────────
    signal output stfCommitment;
    signal output proverSetDigest;

    // ── 1. Compute stfCommitment ─────────────────────────────────────────────
    component stateHash = StateTransitionHash();
    stateHash.preRoot    <== preStateRoot;
    stateHash.postRoot   <== postStateRoot;
    stateHash.batchCmt   <== batchCommitment;
    stfCommitment        <== stateHash.stateHash;

    // ── 2. Compute proverSetDigest ────────────────────────────────────────────
    component setHash = ProverSetHash();
    setHash.pid[0]  <== proverIds[0];
    setHash.pid[1]  <== proverIds[1];
    setHash.pid[2]  <== proverIds[2];
    setHash.sys[0]  <== proofSystemIds[0];
    setHash.sys[1]  <== proofSystemIds[1];
    setHash.sys[2]  <== proofSystemIds[2];
    setHash.quorum  <== quorumCount;
    proverSetDigest <== setHash.setHash;

    // ── 3. Validate quorumCount in [1, 3] ────────────────────────────────────
    component quorumRange = ValidateRange(8);
    quorumRange.x  <== quorumCount;
    quorumRange.lo <== 1;
    quorumRange.hi <== 3;

    // ── 4. Validate batchSize in [1, 1024] ───────────────────────────────────
    component batchRange = ValidateRange(32);
    batchRange.x  <== batchSize;
    batchRange.lo <== 1;
    batchRange.hi <== 1024;

    // ── 5. Enforce proverIds non-zero ────────────────────────────────────────
    component pidNonZero[3];
    for (var i = 0; i < 3; i++) {
        pidNonZero[i] = NonZero();
        pidNonZero[i].x <== proverIds[i];
    }

    // ── 6. Enforce proofSystemIds in {1, 2, 3} ───────────────────────────────
    component sysCheck[3];
    for (var i = 0; i < 3; i++) {
        sysCheck[i] = InSet123();
        sysCheck[i].x <== proofSystemIds[i];
    }
}

component main = WorldlineSTFV2();
