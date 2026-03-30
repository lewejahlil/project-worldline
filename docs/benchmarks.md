# Worldline v1.0 — Benchmark Report

**Date generated:** 2026-03-21 (updated 2026-03-30 with real verifier gas data)
**Environment:**

| Property          | Value                               |
| ----------------- | ----------------------------------- |
| OS                | Linux 6.18.5                        |
| Node.js           | v22.22.0                            |
| Rust / rustc      | 1.93.1 (2026-02-11)                 |
| Solidity compiler | 0.8.34 (via IR, optimizer 200 runs) |
| Hardhat           | hardhat-gas-reporter                |
| Criterion         | 0.5.1                               |

---

## 1. On-Chain Gas Costs

Gas measured via `REPORT_GAS=true npx hardhat test` against a local Hardhat network (block limit 60,000,000 gas). All 239 tests pass. Optimizer is enabled with 200 runs.

### Method Gas Usage

| Contract                     | Function                      | Min Gas | Avg Gas | Max Gas | # Calls |
| ---------------------------- | ----------------------------- | ------: | ------: | ------: | ------: |
| **WorldlineFinalizer**       | `submitZkValidityProof`       |  69,046 |  93,702 | 303,119 |     100 |
| **WorldlineFinalizer**       | `submitZkValidityProofRouted` |  85,183 | 132,810 | 476,049 |      58 |
| **ProofRouter**              | `routeProof`                  |  43,625 |  65,703 | 106,540 |       6 |
| **ProofRouter**              | `registerAdapter`             |  56,196 |  56,228 |  56,229 |     186 |
| **WorldlineRegistry**        | `setCompatFacade`             |  52,585 |  52,590 |  52,597 |      10 |
| **WorldlineOutputsRegistry** | `schedule`                    |  52,169 | 131,633 | 146,081 |      13 |
| **WorldlineOutputsRegistry** | `activate`                    |       — |  96,623 |       — |       9 |
| **WorldlineOutputsRegistry** | `setMinTimelock`              |       — |  34,629 |       — |       2 |
| **WorldlineCompat**          | `registerCircuit`             | 103,947 | 120,985 | 152,886 |      27 |
| **WorldlineCompat**          | `registerDriver`              | 122,121 | 133,902 | 167,371 |      25 |
| **WorldlineCompat**          | `registerPlugin`              | 147,693 | 150,001 | 155,801 |      14 |
| **WorldlineCompat**          | `deprecatePlugin`             |  54,342 |  55,608 |  61,912 |       6 |
| **WorldlineFinalizer**       | `activateAdapterChange`       |       — |  36,355 |       — |       5 |
| **WorldlineFinalizer**       | `scheduleAdapterChange`       |       — |  77,099 |       — |       5 |
| **WorldlineFinalizer**       | `setMaxAcceptanceDelay`       |       — |  35,440 |       — |       2 |
| **WorldlineFinalizer**       | `setPaused`                   |       — |  51,734 |       — |       3 |
| **WorldlineFinalizer**       | `setPermissionless`           |       — |  52,209 |       — |      94 |
| **WorldlineFinalizer**       | `setProofRouter`              |  52,350 |  52,361 |  52,362 |      82 |
| **WorldlineFinalizer**       | `setSubmitter`                |  31,338 |  50,450 |  53,250 |      47 |

> **Key hot-path notes:**
>
> - `submitZkValidityProof` max of **303,119 gas** includes real Groth16 BN254 pairing verification (ecPairing precompile). The min of ~69k is mock-verifier paths.
> - `submitZkValidityProofRouted` max of **476,049 gas** includes real Plonk/Halo2 verification through the ProofRouter. Plonk pairing is more expensive than Groth16 due to 9 G1 point evaluations; Halo2 SHPLONK is the most expensive.
> - `WorldlineOutputsRegistry.schedule` has a wide range (52k–146k) because the first SSTORE on a new slot costs extra vs. overwriting an existing pending entry.
> - The increase in call counts (100 calls for `submitZkValidityProof`, 58 for routed) reflects the addition of real-verifier integration tests.

### Deployment Gas (constructor + code upload)

| Contract                 | Deployment Gas (avg) | % of Block Limit (60M) |
| ------------------------ | -------------------: | ---------------------: |
| Halo2Verifier            |            2,168,554 |                   3.6% |
| WorldlineFinalizer       |            1,903,200 |                   3.2% |
| WorldlineRegistry        |            1,669,050 |                   2.8% |
| PlonkVerifierV2          |            1,237,065 |                   2.1% |
| ProofRouter              |            1,008,149 |                   1.7% |
| WorldlineOutputsRegistry |              923,411 |                   1.5% |
| WorldlineCompat          |              769,532 |                   1.3% |
| Groth16ZkAdapter         |              419,055 |                   0.7% |
| Halo2ZkAdapter           |              398,762 |                   0.7% |
| PlonkZkAdapter           |              374,089 |                   0.6% |
| Groth16Verifier          |              331,714 |                   0.6% |
| BlobKzgVerifier          |              228,908 |                   0.4% |

---

## 2. Contract Bytecode Sizes

Deployed bytecode extracted from Hardhat compilation artifacts (`artifacts/contracts/src/**/*.json`, field `deployedBytecode`). The EVM hard limit is **24,576 bytes** (EIP-170).

| Contract                 | Deployed Bytecode (bytes) | % of 24 KB Limit | Notes                                                              |
| ------------------------ | ------------------------: | ---------------: | ------------------------------------------------------------------ |
| Verifier                 |                       178 |             0.7% | Minimal stub for testing; real Groth16 verifier would be ~10–14 KB |
| WorldlineRegistry        |                     5,257 |            21.4% | Largest deployable contract; comfortable headroom                  |
| WorldlineCompat          |                     3,275 |            13.3% | Facade/proxy layer                                                 |
| WorldlineFinalizer       |                     2,685 |            10.9% | ZK finalization logic                                              |
| WorldlineOutputsRegistry |                     2,001 |             8.1% | Timelock output registry                                           |
| Groth16ZkAdapter         |                       809 |             3.3% | Pluggable verifier adapter                                         |
| IZkAggregatorVerifier    |                         0 |             0.0% | Interface — no deployable bytecode                                 |
| Ownable                  |                         0 |             0.0% | Abstract base — no standalone artifact                             |

> All contracts are well within the 24 KB EVM limit. `Halo2Verifier` is the largest verifier at 3.6% of the block gas limit for deployment. `PlonkVerifierV2` at 1.2M gas is moderate. `Groth16Verifier` is the cheapest verifier to deploy at 332k gas. All three ZK adapters are similarly sized (~370–420k gas).

---

## 3. Rust Crate Performance (Criterion Benchmarks)

Benchmarks run in release mode (`cargo bench -p worldline-registry`) using [Criterion](https://bheisler.github.io/criterion.rs/book/). These are **off-chain operations** running on the local development machine. Each benchmark ran 100 samples. Confidence interval shown as [lower, point estimate, upper] at 95%.

Raw output: [`docs/rust-bench.txt`](rust-bench.txt)

### `load` — Deserialize registry snapshot from disk

| Entries |     Mean | Confidence Interval   |
| ------: | -------: | --------------------- |
|      10 |  21.1 µs | [21.0 µs – 21.3 µs]   |
|     100 | 183.0 µs | [181.5 µs – 184.7 µs] |
|     500 | 882.5 µs | [874.6 µs – 891.6 µs] |

### `save` — Serialize and write registry snapshot to disk

| Entries |     Mean | Confidence Interval   |
| ------: | -------: | --------------------- |
|      10 |  88.5 µs | [86.0 µs – 91.1 µs]   |
|     100 | 138.4 µs | [135.6 µs – 141.3 µs] |
|     500 | 359.5 µs | [349.6 µs – 374.5 µs] |

> Save times are dominated by `fs::File::create` + write syscall overhead, explaining why the 10-entry case is close to the 100-entry case.

### `register_circuit` / `register_plugin` — Single insert into a 100-entry snapshot

| Benchmark                         |   Mean | Confidence Interval |
| --------------------------------- | -----: | ------------------- |
| `register_circuit` (100 existing) | 359 ns | [350 ns – 369 ns]   |
| `register_plugin` (100 existing)  | 353 ns | [347 ns – 361 ns]   |

> O(1) HashSet duplicate detection keeps single-insert cost constant regardless of registry size.

### `build_compat_snapshot` — Build SDK-facing compatibility view

| Entries |     Mean | Confidence Interval   |
| ------: | -------: | --------------------- |
|      10 |  1.97 µs | [1.96 µs – 1.98 µs]   |
|     100 |  28.9 µs | [28.7 µs – 29.1 µs]   |
|     500 | 146.8 µs | [145.1 µs – 148.7 µs] |

> Linear in the number of entries — involves cloning strings for circuit IDs, backend IDs, and plugin metadata.

### `serialization_roundtrip` — JSON serialize then deserialize (in-memory, no I/O)

| Entries |     Mean | Confidence Interval   |
| ------: | -------: | --------------------- |
|     100 | 161.0 µs | [159.1 µs – 163.3 µs] |

---

## 4. Circuit Metrics

`circom` is **not installed** in this environment. The metrics below require `circom 2.1.6` and `snarkjs` to generate. To reproduce:

```bash
npm run c:compile          # circom → .r1cs + .wasm
snarkjs r1cs info circuits/artifacts/worldline.r1cs
```

| Metric           | Value                                                 |
| ---------------- | ----------------------------------------------------- |
| Constraint count | — _(requires circom 2.1.6)_                           |
| Wire count       | — _(requires circom 2.1.6)_                           |
| Public inputs    | — _(requires circom 2.1.6)_                           |
| Private inputs   | — _(requires circom 2.1.6)_                           |
| Circuit file     | `circuits/worldline.circom`                           |
| r1cs artifact    | `circuits/artifacts/worldline.r1cs` _(not generated)_ |

> **Note:** The circuit test suite (`circuits/test/worldline.test.ts`) and export scripts are present. The circuit uses a Groth16 proving system with a `powersOfTau28_hez_final_10.ptau` ceremony file (downloaded via `npm run c:ptau`). Constraint count will be small for the demo `worldline.circom`; production circuits would have substantially more constraints.

> **Proving time benchmarks require a live Groth16 prover and are not included here.** See Section 5.

---

## 5. Proving Performance (Placeholder — Future Work)

The following metrics require access to a live proving infrastructure and are recorded here as TBD. They will be populated once a full Groth16 prover setup is available.

| Metric                                 | Value | Notes                                                          |
| -------------------------------------- | ----- | -------------------------------------------------------------- |
| Groth16 proving time                   | TBD   | Seconds per proof; depends on constraint count and hardware    |
| Proof size                             | TBD   | Bytes; Groth16 proofs are typically 192–256 bytes              |
| Recursion overhead per inner proof     | TBD   | Relevant when aggregating multiple window proofs               |
| End-to-end window finalization latency | TBD   | From L2 window close → `submitZkValidityProof` confirmed on L1 |
| Verifier key generation time           | TBD   | One-time cost during setup ceremony                            |
| Witness generation time                | TBD   | wasm-based witness generation for the worldline circuit        |

> These metrics are pending prover infrastructure access. The on-chain verification costs are captured in Section 1: `submitZkValidityProof` avg **93,702 gas** (max **303,119** with real Groth16 pairing), `submitZkValidityProofRouted` avg **132,810 gas** (max **476,049** with real Plonk/Halo2 pairing).
