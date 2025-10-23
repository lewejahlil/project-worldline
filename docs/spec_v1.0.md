# Project Wordline - Specification v1.0

Status: Final
Author: Lewej Whitelow (lewejahlil)
License: CC BY 4.0

## 1. Abstract
Each L2 window finalizes by verifying a single succinct proof on L1. Off-chain,
an Aggregator STF validates multiple inner proofs from vendor-neutral prover
plugins, enforces a policy (e.g., >=2 distinct families), proves deterministic
subset selection, binds provenance to canonical L1 DA (deposits + EIP-4844
blobs), and outputs one outer proof. No on-chain k-of-n. Public inputs ABI is a
fixed 160 bytes.

## 2. Goals / Non-goals
- Goals: gas-flat L1; vendor neutrality; multi-prover safety; L1-only
  provenance; OP-Stack compatibility; reproducible benchmarking.
- Non-goals: on-chain aggregation or k-of-n; reliance on preconfirmation/flash
  state; vendor-specific code paths.

## 3. Terminology
- Window: contiguous L2 block range with a single L1 proof submission slot.
- Inner proof: proof produced by a plugin prover for the STF over a window.
- Outer proof: aggregated proof verified on L1 by the adapter.
- Family: SNARK, STARK, Hybrid, or Other.

## 4. L1 Contracts

### 4.1 ZkL2OutputOracle
- submitZkProof(bytes proof, bytes publicInputs)
- Rules:
  - publicInputs.length == 160 (ABI stable)
  - Must match next window; windows are contiguous and monotonic
  - Permissioned or permissionless first-valid-wins
  - Pause respected

Events:
- OutputProposed(windowIndex, outputRoot, l2StartBlock, l2EndBlock)
- ProofAccepted(indexed windowIndex, indexed policyHash, programVKey, proverSetDigest)

### 4.2 Adapters
- AggregatorAdapter (required): verifies the outer proof, pins programVKey, and
  checks stfCommitment.
- DirectVerifierAdapter (optional, generic kill-switch): forwards to any EVM
  verifier address. Never vendor-specific.

## 5. Public Inputs (ABI-level; 160 bytes, big-endian)
- [0..31]   stfCommitment (bytes32)
- [32..63]  l2StartBlock (uint256)
- [64..95]  l2EndBlock   (uint256)
- [96..127] outputRoot   (bytes32)
- [128..159] l1BlockHash (bytes32)

Optimization: in-circuit, compress these 160 bytes to 1-2 field elements as
public signals; ABI remains unchanged.

## 6. Commitments and Provenance (normative)
stfCommitment = keccak256(ELF || canonJSON(rollup_config) || domain_tag ||
meta_commit)

meta_commit = keccak256(
  policyHash || programVKey || aggregatorVersion || proverSetDigest ||
  l1AnchorBlockNumber || l1AnchorBlockHash || l1InputsMerkleRoot ||
  derivationPipelineVersion || l2ChainId || oracleAddress ||
  pluginSetDigest || l1FinalityMinDepth
)

- Chain binding: l2ChainId and oracleAddress prevent cross-chain replay.
- Supply chain: pluginSetDigest is a keccak over canonJSON(manifest) for all
  inner provers observed (S_all).
- Finality: proof acceptable only if l1AnchorBlockNumber has at least
  l1FinalityMinDepth confirmations on canonical L1 (enforced by watcher).

## 7. Inputs Merkle (normative ordering)
- Deposit leaf: 0x01 || be64(l1Block) || be32(txIndex) || be32(logIndex) ||
  keccak(rlpLog)
- Blob leaf:    0x02 || be64(l1Block) || be32(blobIndex) || blobVersionedHash
- Sort all leaves lexicographically by (type, block, index fields).
- Zero-input window root = keccak256(0x00).

## 8. Policy (canonical JSON, vendor-neutral)
{
  "version": "1.0",
  "min_count": 2,
  "min_distinct_families": 2,
  "required_families": ["SNARK","STARK"],
  "allowlist_provers": [],
  "fallback_tiers": []
}

- No silent degrade: if unmet and no fallback_tiers, the window fails closed.

## 9. Deterministic Selection (proved in-circuit)
- Key per inner: family_ascii_lower || 0x00 || prover_id_ascii_lower ||
  proofMetaHash (canonJSON(proofMeta) hashed).
- S_all: all valid inner proofs observed before deadline; proverSetDigest =
  keccak(S_all).
- Selected subset: lexicographically smallest subset satisfying policy.
- Equality on outputRoot proven in-circuit.

## 10. Outer Proof Backends (diversity)
- Two independent implementations (e.g., BN254 Groth16/KZG and a Plonkish
  backend on a distinct curve). Identical I/O. Strict CI parity (accept/reject
  must match on shared corpus).
- If Groth16 is used, the EVM verifier should use a 3-pairing check and custom
  errors. Public-input compression reduces calldata and MSM work.

## 11. Watcher (acceptance gate)
- Type-1 recompute from canonical L1 only.
- Multi-provider RPC, blob cache, retry/backoff.
- Enforces l1FinalityMinDepth, chain binding, registry parity, duplicates
  detection.
- Emits SLO metrics (policy satisfaction, submission latency).

## 12. Benchmarks (reproducible)
- Corpus: >= 100 OP-Stack mainnet-like windows (fixtures).
- Metrics: latency (CPU/GPU), memory, outer proof size, L1 gas, cost from
  plugin quotes.
- Commands: make bench-cpu, make bench-gpu, make bench-report.

## 13. Governance and Registry
- SuperchainOutputsRegistry holds {oracle, programVKey, policyHash}.
- Timelock: Pending -> Active with events.
- Watcher rejects proofs not matching the active record.

## 14. Compatibility
- Blob DA per EIP-4844; blob target and max increases under EIP-7691 reduce DA
  cost and allow larger windows. Future PeerDAS does not require spec changes.

## 15. Security Invariants
- Windows are contiguous and monotonic.
- First valid wins in permissionless mode.
- stfCommitment binds chain, program, policy, provenance, and observed provers.
- No reliance on preconfirmation or flash state.

## 16. Rollout
- Phase A: docs + mock demos; Phase B: aggregator default; Phase C: registry
  across chains. Permissionless after monitors and audits are satisfied.
