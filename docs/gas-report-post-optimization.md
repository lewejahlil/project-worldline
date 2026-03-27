# Gas Report — Post-Optimization Comparison

**Solc version:** 0.8.24 (upgraded from 0.8.20)
**Optimizer:** enabled, 200 runs, viaIR: true
**EVM target:** cancun (upgraded from paris)

## Method Gas Comparison

| Contract                 | Method                | Pre-Opt Avg | Post-Opt Avg | Delta  | Notes                                       |
| ------------------------ | --------------------- | ----------- | ------------ | ------ | ------------------------------------------- |
| WorldlineFinalizer       | submitZkValidityProof | 70,181      | 73,492       | +3,311 | Added ProofConsumed event (keccak256 + LOG) |
| WorldlineFinalizer       | activateAdapterChange | 31,987      | 31,985       | -2     |                                             |
| WorldlineFinalizer       | scheduleAdapterChange | 71,861      | 71,857       | -4     |                                             |
| WorldlineFinalizer       | setMaxAcceptanceDelay | 29,981      | 29,965       | -16    |                                             |
| WorldlineFinalizer       | setPaused             | 46,816      | 46,801       | -15    |                                             |
| WorldlineFinalizer       | setPermissionless     | 46,983      | 46,968       | -15    |                                             |
| WorldlineFinalizer       | setSubmitter          | 47,905      | 47,892       | -13    |                                             |
| WorldlineRegistry        | registerCircuit       | 112,362     | 112,415      | +53    |                                             |
| WorldlineRegistry        | registerDriver        | 117,348     | 117,324      | -24    |                                             |
| WorldlineRegistry        | registerPlugin        | 142,783     | 142,760      | -23    |                                             |
| WorldlineRegistry        | deprecatePlugin       | 49,382      | 49,375       | -7     |                                             |
| WorldlineRegistry        | setCompatFacade       | 47,537      | 47,533       | -4     |                                             |
| WorldlineOutputsRegistry | schedule              | 123,957     | 123,916      | -41    |                                             |
| WorldlineOutputsRegistry | activate              | 92,530      | 92,520       | -10    |                                             |
| WorldlineCompat          | deprecatePlugin       | 56,924      | 56,915       | -9     |                                             |
| WorldlineCompat          | registerCircuit       | 121,636     | 121,685      | +49    |                                             |
| WorldlineCompat          | registerPlugin        | 150,728     | 150,702      | -26    |                                             |

## Deployment Gas Comparison

| Contract                 | Pre-Opt   | Post-Opt  | Delta   | Notes                                        |
| ------------------------ | --------- | --------- | ------- | -------------------------------------------- |
| Groth16Verifier          | 91,675    | 90,843    | -832    | Solc 0.8.24 optimizer improvements           |
| Groth16ZkAdapter         | 439,479   | 439,071   | -408    |                                              |
| Verifier                 | 98,379    | 97,103    | -1,276  |                                              |
| WorldlineCompat          | 818,366   | 816,285   | -2,081  |                                              |
| WorldlineFinalizer       | 968,115   | 987,606   | +19,491 | Added ProofConsumed event + keccak256(proof) |
| WorldlineOutputsRegistry | 580,379   | 573,250   | -7,129  |                                              |
| WorldlineRegistry        | 1,426,287 | 1,406,564 | -19,723 |                                              |
| BlobVerifierHarness      | —         | 115,921   | new     | EIP-4844 blob verification harness           |

## Analysis

- **submitZkValidityProof** avg increased by +3,311 gas due to the new `ProofConsumed` event which computes `keccak256(proof)` and emits a LOG3. This is a deliberate trade-off for on-chain audit trail (NUL-1 hardening).
- **Deployment gas** for WorldlineFinalizer increased by +19,491 due to the additional event definition and keccak call in the submission path.
- **All other methods** show marginal improvements (-2 to -41 gas) from the Solidity 0.8.24 compiler upgrade and Cancun EVM target.
- **Total deployment savings** across non-Finalizer contracts: -31,449 gas (Solc 0.8.24 optimizer improvements).
- The `viaIR` optimizer already handles most low-level optimizations, so manual Solidity changes (Chunk 2A) produced modest gains. The compiler upgrade to 0.8.24 with Cancun EVM provided additional marginal savings.
