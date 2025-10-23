# Project Wordline - Design v1.0

Status: Final
Author: Lewej Whitelow (lewejahlil)
License: CC BY 4.0

## A. Architecture
L1: ZkL2OutputOracle, AggregatorAdapter, optional DirectVerifierAdapter,
SuperchainOutputsRegistry.

Off-chain:
- Proposer Broker: discovers and runs prover plugins (sandboxed), collects inner
  proofs and quotes, executes deterministic selection, invokes Aggregator.
- Aggregator (ZK): two outer backends; proves policy satisfaction, subset
  consistency, provenance binding; compresses public inputs.
- Watcher: Type-1 recompute, DA quorum/cache, finality-depth, registry parity.

## B. Prover Plugin API
Manifest (prover.json):
- prover_id (<=64 ascii lower), family (SNARK|STARK|Hybrid|Other), version
  (semver), vkey_commitment (32 bytes hex), image_digest (sha256:...),
  cosign_subject (optional), cmd (array), env_required (array), timeout_ms.

Quote mode:
- Returns expected_cycles, latency_ms, cost_usd without proving.
- Broker solves for minimal latency (tie-break by cost) subject to policy/SLO.

pluginSetDigest:
- keccak over canonJSON of manifests used in S_all; bound into meta_commit.

## C. Aggregator (ZK) details
- Inner-verifier gadgets: SNARK verifier (KZG/Plonkish) and STARK verifier
  abstractions.
- Deterministic subset: lexicographic selection by key; equality on outputRoot.
- Provenance binding: l1AnchorBlock*, l1InputsMerkleRoot, derivation version,
  programVKey, policyHash, proverSetDigest, pluginSetDigest, chain/oracle.
- Public-input compression: hash 160B ABI to 1-2 field elements as public
  signals; keep ABI unchanged.
- Backends diversity: distinct curves/arith; strict parity on shared corpus.

## D. Broker
- Sandbox: rootless containers, seccomp, no network by default, read-only
  filesystem, CPU/memory caps, timeouts, env allowlist.
- Deterministic selection: S_all constructed before deadline; duplicates
  forbidden; selection recorded along with quotes.
- Submission: produces outer proof + 160B inputs and submits to L1.

## E. Watcher
- Multi-RPC quorum, blob cache, retry/backoff.
- Enforces l1FinalityMinDepth; chain/oracle binding; registry parity.
- SLOs and alerts: policy_satisfied_window, submission_latency_p95, da_quorum.

## F. Runbooks (to be expanded with code)
- Normal ops: update policy/program key, add/remove plugins, rotate keys,
  adjust window size.
- Incidents: backends diverge, policy unmet, plugin crash storms, reorgs beyond
  depth, emergency switch to DirectVerifierAdapter.

## G. Bench & Cost
- Bench harness emits JSON; report generator produces Markdown charts.
- Broker optimizer uses quotes to minimize real-world cost.

## H. Gas tactics
- Use immutables, custom errors, Yul for tight loops in verifiers.
- Gas snapshot in CI with budgets and regressions gate.
