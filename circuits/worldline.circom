pragma circom 2.1.6;

// The Worldline v1.0 circuit implements a simple proof-of-presence primitive:
// given a private secret, the prover demonstrates knowledge of the secret that
// squares to a publicly known commitment. The circuit structure is intentionally
// small to keep proving times fast while exercising the workflow for larger
// circuits.

template SquareHash() {
    signal input secret;
    signal input publicHash;

    signal computed;
    computed <== secret * secret;

    // Enforce equality between the computed value and the provided commitment.
    computed === publicHash;

    // INF-005 remediation: removed redundant `isValid` output signal.
    // It was assigned `1` unconditionally and was not in the public interface,
    // so it contributed one R1CS constraint without providing a verifiable guarantee.
}

component main {public [publicHash]} = SquareHash();
