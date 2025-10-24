# Worldline Circuits

The `circuits` package hosts the zero-knowledge circuits that underpin the Worldline
proof-of-presence protocol. The initial release ships with a single circuit that
proves knowledge of a secret that hashes to a known public commitment. The circuit
is intentionally tiny, enabling fast proving in local development environments,
while still exercising the tooling necessary for production-scale circuits.

## Directory layout

- `worldline.circom` – the canonical circuit definition.
- `scripts/` – helper TypeScript utilities used by the npm tasks defined in the
  repository root.
- `artifacts/` – generated files such as the snark witness generator and verifier
  contract.

## Usage

Install dependencies from the repository root:

```bash
npm ci
```

Then run the build pipeline:

```bash
npm run c:ptau      # downloads the Powers of Tau file
npm run c:compile   # compiles the circuit
npm run c:setup     # generates the proving and verification keys
npm run c:export    # exports the Solidity verifier
```

The exported verifier is copied into `contracts/src/zk/Verifier.sol` and used by the
Worldline smart contracts.
