pragma circom 2.1.6;

// The Worldline v1.0 circuit implements a simple proof-of-presence primitive:
// given a private secret, the prover demonstrates knowledge of the secret that
// squares to a publicly known commitment. The circuit structure is intentionally
// small to keep proving times fast while exercising the workflow for larger
// circuits.

template SquareHash() {
    signal input secret;
    signal input publicHash;
    signal output isValid;

    signal computed;
    computed <== secret * secret;

    // Enforce equality between the computed value and the provided commitment.
    computed === publicHash;

    // Expose a boolean-ish output that downstream tooling can use to assert
    // correctness without parsing constraints directly.
    isValid <== 1;
}

component main = SquareHash();
