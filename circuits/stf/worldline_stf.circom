pragma circom 2.1.6;

include "../lib/poseidon_utils.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

/**
 * WorldlineSTF — State Transition Function commitment circuit.
 *
 * Proves commitment integrity: that the pre-state, post-state, and batch
 * commitment are bound together with a valid Poseidon hash, and that the
 * prover set attestation is bound to those same values.
 *
 * Public outputs (automatically public as output signals):
 *   - stfCommitment   = Poseidon(preStateRoot, postStateRoot, batchCommitment)
 *   - proverSetDigest = Poseidon(proverIds || proofSystemIds || quorumCount)
 *
 * @param N              Number of prover slots (fixed at compile time).
 * @param MAX_BATCH_SIZE Upper bound on batchSize for range checking.
 */
template WorldlineSTF(N, MAX_BATCH_SIZE) {
    // ── Private inputs ───────────────────────────────────────────────────────
    signal input preStateRoot;
    signal input postStateRoot;
    signal input batchCommitment;
    signal input batchSize;
    signal input proverIds[N];
    signal input proofSystemIds[N];
    signal input quorumCount;

    // ── Public outputs ───────────────────────────────────────────────────────
    signal output stfCommitment;
    signal output proverSetDigest;

    // ── 1. STF Commitment: Poseidon(preStateRoot, postStateRoot, batchCommitment) ──
    component stfHash = STFCommitment();
    stfHash.preStateRoot <== preStateRoot;
    stfHash.postStateRoot <== postStateRoot;
    stfHash.batchCommitment <== batchCommitment;
    stfCommitment <== stfHash.commitment;

    // ── 2. Prover Set Digest: Poseidon(proverIds, proofSystemIds, quorumCount) ──
    component proverHash = ProverSetDigest(N);
    for (var i = 0; i < N; i++) {
        proverHash.proverIds[i] <== proverIds[i];
        proverHash.proofSystemIds[i] <== proofSystemIds[i];
    }
    proverHash.quorumCount <== quorumCount;
    proverSetDigest <== proverHash.digest;

    // ── 3. Range check: 1 <= quorumCount <= N ────────────────────────────────
    component quorumGe1 = GreaterEqThan(8);
    quorumGe1.in[0] <== quorumCount;
    quorumGe1.in[1] <== 1;
    quorumGe1.out === 1;

    component quorumLeN = LessEqThan(8);
    quorumLeN.in[0] <== quorumCount;
    quorumLeN.in[1] <== N;
    quorumLeN.out === 1;

    // ── 4. Range check: 1 <= batchSize <= MAX_BATCH_SIZE ─────────────────────
    component batchGe1 = GreaterEqThan(32);
    batchGe1.in[0] <== batchSize;
    batchGe1.in[1] <== 1;
    batchGe1.out === 1;

    component batchLeMax = LessEqThan(32);
    batchLeMax.in[0] <== batchSize;
    batchLeMax.in[1] <== MAX_BATCH_SIZE;
    batchLeMax.out === 1;

    // ── 5. Non-zero prover IDs ───────────────────────────────────────────────
    // A zero prover ID indicates an empty slot — all slots must be populated.
    component proverIdIsZero[N];
    for (var i = 0; i < N; i++) {
        proverIdIsZero[i] = IsZero();
        proverIdIsZero[i].in <== proverIds[i];
        proverIdIsZero[i].out === 0; // Must NOT be zero
    }

    // ── 6. Proof system IDs in {1, 2, 3} ────────────────────────────────────
    // 1=Groth16, 2=Plonk, 3=Halo2
    component sysGe1[N];
    component sysLe3[N];
    for (var i = 0; i < N; i++) {
        sysGe1[i] = GreaterEqThan(8);
        sysGe1[i].in[0] <== proofSystemIds[i];
        sysGe1[i].in[1] <== 1;
        sysGe1[i].out === 1;

        sysLe3[i] = LessEqThan(8);
        sysLe3[i].in[0] <== proofSystemIds[i];
        sysLe3[i].in[1] <== 3;
        sysLe3[i].out === 1;
    }
}

// N=3 prover slots (Groth16, Plonk, Halo2), MAX_BATCH_SIZE=1024
component main = WorldlineSTF(3, 1024);
