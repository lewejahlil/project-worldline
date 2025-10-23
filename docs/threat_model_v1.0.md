# Project Wordline - Threat Model v1.0

Status: Final
Author: Lewej Whitelow (lewejahlil)
License: CC BY 4.0

Method: STRIDE with abuse cases. Defaults are fail-closed.

1) Data withholding / DA failures
- Risk: missing blobs or deposits cause wrong inputs root.
- Mitigation: watcher DA quorum, cache, retry/backoff; fail window closed.

2) Cross-chain replay
- Risk: valid proof replayed on another chain.
- Mitigation: bind l2ChainId and oracleAddress into meta_commit; watcher checks.

3) Prover supply-chain compromise
- Risk: malicious plugin binary.
- Mitigation: pluginSetDigest bound; cosign image digests; sandbox defaults; timeouts.

4) Determinism / selection manipulation
- Risk: nondeterministic subsets.
- Mitigation: canonical key; in-circuit proof of subset; duplicates forbidden;
  S_all hashed as proverSetDigest.

5) Common-mode failure of backends
- Risk: single bug breaks all.
- Mitigation: two independent backends on distinct curves; CI parity gate.

6) L1 reorg ambiguity
- Risk: shallow anchors become invalid.
- Mitigation: l1FinalityMinDepth bound; watcher enforces depth.

7) Gas griefing / DoS
- Risk: calldata bloat; repeated invalid submits.
- Mitigation: fixed 160B inputs; duplicates revert; 3-pairing verifier; gas
  budget CI.

8) Governance risk
- Risk: sudden policy/VK change.
- Mitigation: registry timelock; pending->active with events; watcher parity.

9) Privacy / secrets
- Risk: plugin exfiltrates secrets.
- Mitigation: no-net by default; env allowlist; read-only FS; logs capture.

Residual risks documented with response playbooks. Incidents default to
fail-closed behavior.
