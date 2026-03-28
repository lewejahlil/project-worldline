pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";

/**
 * Computes stfCommitment = Poseidon(preStateRoot, postStateRoot, batchCommitment)
 *
 * This is the canonical Worldline STF commitment hash. It binds the pre-state,
 * post-state, and batch data commitment into a single field element that serves
 * as the primary public signal for on-chain verification.
 */
template STFCommitment() {
    signal input preStateRoot;
    signal input postStateRoot;
    signal input batchCommitment;
    signal output commitment;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== preStateRoot;
    hasher.inputs[1] <== postStateRoot;
    hasher.inputs[2] <== batchCommitment;
    commitment <== hasher.out;
}

/**
 * Computes proverSetDigest = Poseidon(proverId[0], ..., proverId[N-1],
 *                                      proofSystemId[0], ..., proofSystemId[N-1],
 *                                      quorumCount)
 *
 * N is fixed at compile time. For Worldline's initial deployment, N=3
 * (one slot per proof system: Groth16, Plonk, Halo2).
 *
 * Prover IDs and proof system IDs must be sorted in ascending order by proverId
 * before being passed to this template. Sorting is enforced off-chain by the
 * Rust driver; the circuit trusts the ordering but binds all values into the hash
 * so that any reordering produces a different digest.
 */
template ProverSetDigest(N) {
    signal input proverIds[N];
    signal input proofSystemIds[N];
    signal input quorumCount;
    signal output digest;

    // Hash all prover IDs + system IDs + quorum into a single commitment
    // Input count: N proverIds + N proofSystemIds + 1 quorumCount = 2N+1
    component hasher = Poseidon(2 * N + 1);

    for (var i = 0; i < N; i++) {
        hasher.inputs[i] <== proverIds[i];
        hasher.inputs[N + i] <== proofSystemIds[i];
    }
    hasher.inputs[2 * N] <== quorumCount;

    digest <== hasher.out;
}
