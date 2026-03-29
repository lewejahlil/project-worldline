/**
 * Compile the WorldlineSTF circuit end-to-end.
 *
 * Steps:
 *   1. Run circom compiler to produce .r1cs, .wasm, .sym
 *   2. Report constraint count
 *   3. Verify zero unconstrained signals via --inspect
 *
 * Produces artifacts needed by the trusted setup and test scripts.
 */
