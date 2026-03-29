/**
 * Fork verification tests.
 *
 * Runs against a forked mainnet Hardhat network (configured in hardhat.config.ts).
 * Validates that contracts deploy correctly and operate under mainnet EVM conditions.
 */

import { expect } from "chai";
import { ethers, network, upgrades } from "hardhat";

const FORK_RPC = process.env["MAINNET_RPC_URL"] || "https://ethereum-rpc.publicnode.com";

// ── Constants ────────────────────────────────────────────────────────────────

const DOMAIN = ethers.keccak256(ethers.toUtf8Bytes("fork-test-domain"));
const PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("fork-test-vkey"));
const POLICY_HASH = ethers.keccak256(ethers.toUtf8Bytes("fork-test-policy"));
const PROVER_SET_DIGEST = ethers.keccak256(ethers.toUtf8Bytes("fork-test-prover-digest"));
const MAX_ACCEPTANCE_DELAY = 7200;
const GENESIS_L2_BLOCK = 0n;

// ── Helpers ──────────────────────────────────────────────────────────────────

function computeStfCommitment(
  l2Start: bigint,
  l2End: bigint,
  windowCloseTimestamp: bigint
): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256"],
      [l2Start, l2End, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, windowCloseTimestamp]
    )
  );
}

function encodeProof(l2Start: bigint, l2End: bigint, windowCloseTimestamp: bigint): string {
  const stfCommitment = computeStfCommitment(l2Start, l2End, windowCloseTimestamp);
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256", "uint256"],
    [
      [1n, 2n],
      [
        [1n, 2n],
        [3n, 4n]
      ],
      [1n, 2n],
      BigInt(stfCommitment),
      BigInt(PROVER_SET_DIGEST)
    ]
  );
}

function encodePublicInputs(l2Start: bigint, l2End: bigint, windowCloseTimestamp: bigint): string {
  const stfCommitment = computeStfCommitment(l2Start, l2End, windowCloseTimestamp);
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256"],
    [stfCommitment, l2Start, l2End, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, windowCloseTimestamp]
  );
}

async function getWindowTimestamp(): Promise<bigint> {
  const block = await ethers.provider.getBlock("latest");
  return BigInt(block!.timestamp) + BigInt(MAX_ACCEPTANCE_DELAY) - 60n;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("Fork — Verification", function () {
  this.timeout(120_000);

  before(async function () {
    await network.provider.request({
      method: "hardhat_reset",
      params: [{ forking: { jsonRpcUrl: FORK_RPC } }]
    });
  });

  after(async function () {
    // Reset to clean in-process EVM so subsequent test suites are unaffected.
    await network.provider.request({ method: "hardhat_reset", params: [] });
  });

  it("fork is active — block number is a realistic mainnet height", async function () {
    const blockNumber = await ethers.provider.getBlockNumber();
    expect(blockNumber).to.be.greaterThan(0);
    console.log(`    fork block: ${blockNumber}`);
  });

  it("deploys MockGroth16Verifier on fork without revert", async function () {
    const [deployer] = await ethers.getSigners();
    const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier", deployer);
    const verifier = await MockVerifier.deploy();
    await verifier.waitForDeployment();
    expect(await verifier.getAddress()).to.match(/^0x[0-9a-fA-F]{40}$/);
  });

  it("BN254 ecAdd precompile (0x06) returns valid output", async function () {
    // ecAdd(G1, G1): input = (x1, y1, x2, y2) = (1, 2, 1, 2)
    const input = ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "uint256", "uint256", "uint256"],
      [1n, 2n, 1n, 2n]
    );
    const result = await ethers.provider.call({
      to: "0x0000000000000000000000000000000000000006",
      data: input
    });
    expect(result).to.not.equal("0x");
    expect(result.length).to.equal(2 + 128); // 0x + 64 bytes (2 uint256)
  });

  it("BN254 ecScalarMul precompile (0x07) returns valid output", async function () {
    // ecScalarMul(G1, 1): input = (x, y, scalar) = (1, 2, 1)
    const input = ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "uint256", "uint256"],
      [1n, 2n, 1n]
    );
    const result = await ethers.provider.call({
      to: "0x0000000000000000000000000000000000000007",
      data: input
    });
    expect(result).to.not.equal("0x");
    expect(result.length).to.equal(2 + 128);
  });

  it("BN254 ecPairing precompile (0x08) returns 1 for empty input", async function () {
    // Empty input → pairing product of empty set = 1 (identity element)
    const result = await ethers.provider.call({
      to: "0x0000000000000000000000000000000000000008",
      data: "0x"
    });
    const value = BigInt(result);
    expect(value).to.equal(1n);
  });

  it("deploys full contract stack on fork without revert", async function () {
    const [deployer] = await ethers.getSigners();

    const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier", deployer);
    const verifier = await MockVerifier.deploy();
    await verifier.waitForDeployment();

    const Adapter = await ethers.getContractFactory("Groth16ZkAdapter", deployer);
    const adapter = await Adapter.deploy(await verifier.getAddress(), PROGRAM_VKEY, POLICY_HASH);
    await adapter.waitForDeployment();

    const Registry = await ethers.getContractFactory("WorldlineRegistry", deployer);
    const registry = (await upgrades.deployProxy(Registry, [await verifier.getAddress()], {
      kind: "uups"
    })) as any;
    await registry.waitForDeployment();

    const Finalizer = await ethers.getContractFactory("WorldlineFinalizer", deployer);
    const finalizer = (await upgrades.deployProxy(
      Finalizer,
      [
        await adapter.getAddress(),
        DOMAIN,
        MAX_ACCEPTANCE_DELAY,
        GENESIS_L2_BLOCK,
        ethers.ZeroAddress
      ],
      { kind: "uups" }
    )) as any;
    await finalizer.waitForDeployment();

    expect(await verifier.getAddress()).to.match(/^0x[0-9a-fA-F]{40}$/);
    expect(await adapter.getAddress()).to.match(/^0x[0-9a-fA-F]{40}$/);
    expect(await registry.getAddress()).to.match(/^0x[0-9a-fA-F]{40}$/);
    expect(await finalizer.getAddress()).to.match(/^0x[0-9a-fA-F]{40}$/);
  });

  it("registry registerDriver and finalizer setSubmitter operate on fork", async function () {
    const [owner, prover] = await ethers.getSigners();

    const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier", owner);
    const verifier = await MockVerifier.deploy();
    await verifier.waitForDeployment();

    const Registry = await ethers.getContractFactory("WorldlineRegistry", owner);
    const registry = (await upgrades.deployProxy(Registry, [await verifier.getAddress()], {
      kind: "uups"
    })) as any;
    await registry.waitForDeployment();

    const Adapter = await ethers.getContractFactory("Groth16ZkAdapter", owner);
    const adapter = await Adapter.deploy(await verifier.getAddress(), PROGRAM_VKEY, POLICY_HASH);
    await adapter.waitForDeployment();

    const Finalizer = await ethers.getContractFactory("WorldlineFinalizer", owner);
    const finalizer = (await upgrades.deployProxy(
      Finalizer,
      [
        await adapter.getAddress(),
        DOMAIN,
        MAX_ACCEPTANCE_DELAY,
        GENESIS_L2_BLOCK,
        ethers.ZeroAddress
      ],
      { kind: "uups" }
    )) as any;
    await finalizer.waitForDeployment();

    // Register driver in registry
    const driverId = ethers.keccak256(ethers.toUtf8Bytes("driver-groth16-fork-test"));
    await (await (registry as any).registerDriver(driverId, "v1.0.0", "https://test.local")).wait();
    const driver = await (registry as any).getDriver(driverId);
    expect(driver.id).to.equal(driverId);

    // Set submitter on finalizer
    await (await (finalizer as any).setSubmitter(prover.address, true)).wait();
    expect(await (finalizer as any).submitters(prover.address)).to.equal(true);
  });

  it("submits a proof through the full pipeline on fork", async function () {
    const [owner] = await ethers.getSigners();

    const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier", owner);
    const verifier = await MockVerifier.deploy();
    await verifier.waitForDeployment();

    const Adapter = await ethers.getContractFactory("Groth16ZkAdapter", owner);
    const adapter = await Adapter.deploy(await verifier.getAddress(), PROGRAM_VKEY, POLICY_HASH);
    await adapter.waitForDeployment();

    const Finalizer = await ethers.getContractFactory("WorldlineFinalizer", owner);
    const finalizer = (await upgrades.deployProxy(
      Finalizer,
      [
        await adapter.getAddress(),
        DOMAIN,
        MAX_ACCEPTANCE_DELAY,
        GENESIS_L2_BLOCK,
        ethers.ZeroAddress
      ],
      { kind: "uups" }
    )) as any;
    await finalizer.waitForDeployment();

    await (await (finalizer as any).setPermissionless(true)).wait();

    const ts = await getWindowTimestamp();
    const proof = encodeProof(GENESIS_L2_BLOCK, GENESIS_L2_BLOCK + 100n, ts);
    const publicInputs = encodePublicInputs(GENESIS_L2_BLOCK, GENESIS_L2_BLOCK + 100n, ts);

    const tx = await (finalizer as any).submitZkValidityProof(proof, publicInputs);
    const receipt = await tx.wait();
    expect(receipt.status).to.equal(1);

    expect(await (finalizer as any).nextWindowIndex()).to.equal(1n);
  });

  it("full pipeline on fork: deploy all → register → submit → verify accepted", async function () {
    const [owner, prover] = await ethers.getSigners();

    const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier", owner);
    const verifier = await MockVerifier.deploy();
    await verifier.waitForDeployment();

    const Adapter = await ethers.getContractFactory("Groth16ZkAdapter", owner);
    const adapter = await Adapter.deploy(await verifier.getAddress(), PROGRAM_VKEY, POLICY_HASH);
    await adapter.waitForDeployment();

    const Registry = await ethers.getContractFactory("WorldlineRegistry", owner);
    const registry = (await upgrades.deployProxy(Registry, [await verifier.getAddress()], {
      kind: "uups"
    })) as any;
    await registry.waitForDeployment();

    const Finalizer = await ethers.getContractFactory("WorldlineFinalizer", owner);
    const finalizer = (await upgrades.deployProxy(
      Finalizer,
      [
        await adapter.getAddress(),
        DOMAIN,
        MAX_ACCEPTANCE_DELAY,
        GENESIS_L2_BLOCK,
        ethers.ZeroAddress
      ],
      { kind: "uups" }
    )) as any;
    await finalizer.waitForDeployment();

    // Register
    const driverId = ethers.keccak256(ethers.toUtf8Bytes("driver-pipeline-fork"));
    await (await (registry as any).registerDriver(driverId, "v1.0.0", "https://fork.local")).wait();
    await (await (finalizer as any).setSubmitter(prover.address, true)).wait();

    // Submit 3 sequential windows from prover
    const ts = await getWindowTimestamp();
    let cursor = GENESIS_L2_BLOCK;
    for (let i = 0; i < 3; i++) {
      const l2End = cursor + 100n;
      const proof = encodeProof(cursor, l2End, ts);
      const publicInputs = encodePublicInputs(cursor, l2End, ts);
      const tx = await (finalizer as any)
        .connect(prover)
        .submitZkValidityProof(proof, publicInputs);
      await tx.wait();
      cursor = l2End;
    }

    expect(await (finalizer as any).nextWindowIndex()).to.equal(3n);

    const filter = (finalizer as any).filters.ZkProofAccepted();
    const currentBlock = await ethers.provider.getBlockNumber();
    const events = await (finalizer as any).queryFilter(filter, currentBlock - 1000, currentBlock);
    expect(events).to.have.length(3);
  });
});
