# ZK Ceremony Procedure — Project Worldline

## Overview

Worldline uses a Groth16/BN254 proving system. Groth16 requires a **trusted setup ceremony**
(Phase 2) that must be conducted with multiple independent contributors and a verifiable
random beacon. If any single party knows the "toxic waste" (the secret randomness used to
construct the common reference string), they can forge proofs for **any statement**.

This document describes the full ceremony procedure for production deployments.

## Development Setup (Local / CI)

The development ceremony uses a single contributor and a fixed beacon. It is **not safe for
production** — the developer who runs it knows the toxic waste.

```bash
npm run c:ptau          # Download Powers of Tau (with SHA-256 integrity check)
npm run c:compile       # Compile circuit to R1CS + WASM
npm run c:setup         # Run the full 4-step ceremony (phase2begin + contribute + beacon + verify)
npm run c:export        # Export Solidity verifier from worldline_final.zkey
```

The `c:setup` script chains the following four steps:

1. **Phase 2 Begin**: `snarkjs groth16 setup` — generates `worldline_0000.zkey` from the R1CS and ptau
2. **Contribute**: `snarkjs zkey contribute` — adds a contribution with random entropy, producing `worldline_0001.zkey`
3. **Beacon**: `snarkjs zkey beacon` — applies a random beacon, producing `worldline_final.zkey`
4. **Verify**: `snarkjs zkey verify` — verifies the final zkey against the R1CS and ptau

The beacon hash (`0102030405060708...1f20`) in the development scripts is a **placeholder**.
Production MUST use a publicly committed beacon source.

## Production Ceremony Requirements

### Minimum Requirements

- **At least 5 independent contributors** from different organizations/jurisdictions
- Each contributor must generate their own random entropy and destroy it after contributing
- Contributions must be chained: each contributor's output becomes the next contributor's input
- A **verifiable random beacon** must be applied as the final step

### Beacon Requirements

The beacon must reference a public randomness source that was committed to **before** the
ceremony began. Acceptable sources include:

- A future Ethereum block hash (commit to a block number before it is mined)
- A future Bitcoin block hash
- Output of a publicly verifiable randomness beacon (e.g., drand)

The beacon hash and its source URL must be recorded in the ceremony transcript.

### Step-by-Step Production Procedure

```bash
# 1. Generate initial zkey (coordinator runs this)
snarkjs groth16 setup worldline.r1cs powersOfTau28_hez_final_10.ptau worldline_0000.zkey

# 2. Contributor 1 adds their contribution
snarkjs zkey contribute worldline_0000.zkey worldline_0001.zkey \
  --name="Contributor 1 (Org A)" -v -e="<random entropy>"

# 3. Contributor 2 adds their contribution
snarkjs zkey contribute worldline_0001.zkey worldline_0002.zkey \
  --name="Contributor 2 (Org B)" -v -e="<random entropy>"

# ... repeat for N contributors ...

# N+1. Apply the verifiable random beacon
snarkjs zkey beacon worldline_000N.zkey worldline_final.zkey \
  <BEACON_HASH> 10 -n="Final Beacon: <source description>"

# N+2. Verify the final key
snarkjs zkey verify worldline.r1cs powersOfTau28_hez_final_10.ptau worldline_final.zkey

# N+3. Export the verifier contract
snarkjs zkey export solidityverifier worldline_final.zkey Groth16Verifier.sol
```

### Verification Output

The output of `snarkjs zkey verify` must be:
- Saved as a text file and committed to the audit record
- Included in the ceremony transcript
- Verified independently by at least 2 parties

### Ceremony Transcript

The ceremony coordinator must publish a transcript containing:

1. **Participant list**: Name/pseudonym, organization, contribution index
2. **Contribution hashes**: The hash of each intermediate zkey
3. **Beacon specification**: The beacon hash value and its source (block number, URL)
4. **Beacon commitment proof**: Evidence that the beacon source was committed before the ceremony
5. **Verification output**: Full output of `snarkjs zkey verify` for the final zkey
6. **Timing**: Timestamps for each contribution
7. **snarkjs version**: Must match the pinned version in `package.json` (currently `0.7.6`)

### Security Properties

As long as **at least one contributor** honestly generates random entropy and destroys it:
- The toxic waste is unknown to any party
- No party can forge proofs
- The CRS is secure

This is the "1-of-N" trust assumption of Groth16 ceremonies.

## Post-Ceremony Checklist

- [ ] All contributions verified with `snarkjs zkey verify`
- [ ] Beacon applied with publicly verifiable source
- [ ] Ceremony transcript published
- [ ] Verifier contract exported from `worldline_final.zkey` (not any intermediate key)
- [ ] `export-verifier.ts` safety check confirms `*_final.zkey` filename
- [ ] Exported verifier contract audited
- [ ] Intermediate zkey files (`worldline_0000.zkey`, `worldline_0001.zkey`, etc.) deleted
- [ ] All contributors confirmed destruction of their entropy

## References

- [snarkjs Phase 2 documentation](https://github.com/iden3/snarkjs#7-prepare-phase-2)
- [Hermez Powers of Tau ceremony](https://blog.hermez.io/hermez-cryptographic-setup/)
- Trail of Bits, ZKDocs: Groth16 trusted setup requirements
- TRM Labs, 2026 Crypto Crime Report — February 2026 snarkjs exploit class (CRI-002)
