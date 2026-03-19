# Worldline Smart Contracts

The smart contracts expose the on-chain registry, finality pipeline, and
compatibility facade for the Worldline protocol.

## Contracts

| Contract                    | Description                                                     |
|-----------------------------|-----------------------------------------------------------------|
| `WorldlineRegistry`        | Stores registered plugins, circuits, and driver metadata        |
| `WorldlineCompat`          | Thin facade for stable method signatures over the registry      |
| `WorldlineFinalizer`       | Accepts one ZK proof per contiguous window, verifies via adapter |
| `WorldlineOutputsRegistry` | Timelocked two-step schedule/activate for domain configurations |
| `zk/Verifier`              | Dev-only demo verifier (secret² == publicHash)                  |
| `zk/Groth16ZkAdapter`      | Adapter pinning programVKey and policyHash for Groth16 proofs   |
| `interfaces/IZkAggregatorVerifier` | Interface for pluggable ZK verification adapters        |
| `utils/Ownable`            | Minimal ownership pattern                                       |

## Building

```bash
npm ci
npx hardhat compile
```

## Testing

```bash
npx hardhat test
```

To include gas reporting:

```bash
REPORT_GAS=true npx hardhat test
```

## Deployment

The `devnet/index.js` script deploys the full stack to a local Anvil network:

```bash
npm run devnet
```

For production deployments, configure `hardhat.config.ts` with your target
network and deploy using Hardhat Ignition or a custom deploy script.
