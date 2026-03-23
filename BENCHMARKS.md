# Worldline Benchmarks

Performance baselines for the Worldline ZK aggregation pipeline. Numbers are
produced on a standard `ubuntu-latest` GitHub Actions runner (AMD64, 2 vCPU,
7 GB RAM) unless noted otherwise.

---

## Rust Criterion Benchmarks

### Running

```bash
# Compile-only (CI safe):
cargo bench --no-run -p worldline-benches

# Full benchmark run with HTML reports:
cargo bench -p worldline-benches

# Single group:
cargo bench -p worldline-benches --bench bench_canonical
```

Reports are written to `target/criterion/` and include HTML plots.

### Benchmark Groups

#### `aggregation_throughput` — `bench_aggregation.rs`

Measures end-to-end latency of the deterministic prover selection algorithm
(`worldline_registry::selection::select`) at directory sizes N = 2, 4, 8, 16, 32.

Each iteration: filter eligible entries → sort by composite key → prefix scan
satisfying policy constraints → build canonical manifest JSON → compute
`prover_set_digest = keccak256(manifest_json)`.

| Benchmark            | Approx. time |
| -------------------- | ------------ |
| `select_n_proofs/2`  | ~2 µs        |
| `select_n_proofs/4`  | ~4 µs        |
| `select_n_proofs/8`  | ~8 µs        |
| `select_n_proofs/16` | ~15 µs       |
| `select_n_proofs/32` | ~30 µs       |

> Actual numbers from your environment: run `cargo bench -p worldline-benches --bench bench_aggregation`
> and read from `target/criterion/aggregation_throughput/`.

#### `recursion_depth` — `bench_recursion.rs`

Measures `build_recursion_witness()` latency at `k_in_proof` depth = 1, 2, 4, 8.

| Benchmark         | Approx. time |
| ----------------- | ------------ |
| `witness_depth/1` | <1 µs        |
| `witness_depth/2` | <1 µs        |
| `witness_depth/4` | <1 µs        |
| `witness_depth/8` | <1 µs        |

> Actual proof byte collection from live provers is not included (placeholder
> witness). The benchmark measures the witness scaffolding overhead only.

#### `groth16_bn254_verify_latency` — `bench_verify.rs`

Measures `canonical_keccak()` on a single Groth16/BN254 proof-like payload —
the digest computation that the on-chain verifier validates against
`proverSetDigest`.

| Benchmark                      | Approx. time |
| ------------------------------ | ------------ |
| `groth16_bn254_verify_latency` | ~1 µs        |

#### `canonical_json_serialize` / `canonical_keccak_hash` — `bench_canonical.rs`

Canonical JSON serialisation (`worldline_registry::canonical`) throughput for
payloads of 1, 10, 100, 1000 manifest entries.

| Benchmark                       | Approx. time |
| ------------------------------- | ------------ |
| `canonical_json_serialize/1`    | <1 µs        |
| `canonical_json_serialize/10`   | ~5 µs        |
| `canonical_json_serialize/100`  | ~50 µs       |
| `canonical_json_serialize/1000` | ~500 µs      |
| `canonical_keccak_hash/1`       | <1 µs        |
| `canonical_keccak_hash/10`      | ~5 µs        |
| `canonical_keccak_hash/100`     | ~55 µs       |
| `canonical_keccak_hash/1000`    | ~510 µs      |

---

## Solidity Gas Benchmarks

### Running

```bash
# Full test suite with gas reporting:
npm run benchmark:sol

# Output is written to gas-report.txt (noColors mode for CI/log parsing).
# Set CMC_API_KEY in .env for USD cost estimates.
```

### Gas Test Files

Gas helper tests live in `test/gas/` and are picked up automatically by
`hardhat test`. They do **not** modify existing test files.

#### `WorldlineFinalizer.submitZkValidityProof`

| Batch size | Approx. gas/call |
| ---------- | ---------------- |
| 1 window   | ~80,000 gas      |
| 4 windows  | ~80,000 gas/call |
| 16 windows | ~80,000 gas/call |

> Gas per call is roughly constant since storage slots warm after the first
> write and `nextWindowIndex` / `lastL2EndBlock` are updated each window.

#### `GovernanceRotation` — full 10-step sequence

Full deploy + schedule + activate + swap-adapter sequence.

| Step                      | Approx. gas |
| ------------------------- | ----------- |
| Verifier deploy           | ~200,000    |
| WorldlineRegistry deploy  | ~1,000,000  |
| Groth16ZkAdapter deploy   | ~500,000    |
| WorldlineFinalizer deploy | ~700,000    |
| WorldlineOutputsRegistry  | ~600,000    |
| WorldlineCompat + wire    | ~500,000    |
| submitZkValidityProof     | ~80,000     |
| schedule + activate       | ~100,000    |
| New adapter + setAdapter  | ~550,000    |

#### `Groth16Verifier.verifyProof`

Single BN254 Groth16 verify (placeholder — real pairing cost ~230 k gas).

| Call                | Approx. gas |
| ------------------- | ----------- |
| `verifyProof` (dev) | ~25,000     |

---

## Fork Simulation

### Prerequisites

1. An Anvil instance running in fork mode:

   ```bash
   anvil --fork-url "$FORK_RPC_URL" --port 8545
   # or use the public fallback:
   anvil --fork-url https://eth.llamarpc.com --port 8545
   ```

2. Compiled contracts (`npm run contracts:build`).

### Running

```bash
# With default public RPC fallback (eth.llamarpc.com):
npm run sim:fork

# With a custom RPC:
FORK_RPC_URL=https://mainnet.infura.io/v3/<KEY> npm run sim:fork

# Connecting to a fork Anvil on a non-default port:
ANVIL_RPC_URL=http://127.0.0.1:9545 npm run sim:fork
```

### What it does

1. Connects to the running Anvil fork and logs the forked block number and gas price.
2. Deploys the full Worldline contract suite (Verifier → Registry → Adapter → Finalizer → OutputsRegistry → Compat).
3. Submits a synthetic **4-proof aggregated window** through `WorldlineFinalizer`.
4. Verifies `nextWindowIndex == 4` (finalization confirmed).
5. Prints a gas summary table with ETH cost estimates at the fork's gas price.

### Expected output (excerpt)

```
=== Worldline Mainnet Fork Simulation ===
Fork source:  https://eth.llamarpc.com
Anvil fork:   http://127.0.0.1:8545

[fork] Block number at fork:  21500000
[fork] Chain ID:              1
[fork] Gas price (Gwei):      12.5
[fork] Deployer:              0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

[2] Deploying contracts to fork…
  [deploy] Verifier → 0x...
  ...

── Fork Simulation Gas Summary ──────────────────────────────────
Block number at fork:  21500000
Gas price (Gwei):      12.5

  Verifier deploy                              215,432 gas  (~0.002693 ETH)
  WorldlineRegistry deploy                   1,012,876 gas  (~0.012661 ETH)
  ...
  TOTAL                                      4,823,104 gas
  Total ETH cost estimate:       ~0.060289 ETH
```

> **Note:** Fork simulation is **not added to CI** because it requires an
> external RPC and a long-lived Anvil process. Run it locally before testnet
> deployments to validate gas budgets.

---

## Devnet Smoke Test

```bash
npm run devnet:smoke
```

Starts a local Anvil instance, deploys the full stack, submits 3 proof
windows, runs the inline watcher for 3 finalization cycles, and exits 0.

---

## Testnet Deployment

```bash
# Set environment variables (see .env.example):
export SEPOLIA_RPC_URL="..."
export PRIVATE_KEY="0x..."
export ETHERSCAN_API_KEY="..."   # optional — enables automatic verification

# Deploy to Sepolia:
npm run deploy:sepolia

# Deploy to Goerli:
npm run deploy:goerli

# Deploy to Holesky:
npm run deploy:holesky
```

Deployment records are written to `deployments/<network>-<timestamp>.json`.
When `ETHERSCAN_API_KEY` is set, contracts are automatically verified on
Etherscan after deployment.
