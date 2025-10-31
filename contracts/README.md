# Worldline Smart Contracts

The smart contracts expose the on-chain registry and compatibility façade for the
Worldline protocol. The key building blocks are:

- `WorldlineRegistry` – stores registered plugins, circuits, and driver metadata.
- `WorldlineCompat` – thin façade that lets legacy callers interact with the
  registry using stable method signatures.
- `zk/Verifier.sol` – generated contract used to validate zero-knowledge proofs
  produced by the Circom circuit.

The contracts are intentionally framework-agnostic: they compile with both
Hardhat and Foundry. Tests in this repository use Hardhat via `npm test`.
