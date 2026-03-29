/**
 * Fork gas comparison tests.
 *
 * Measures gas costs for key operations on a forked mainnet Hardhat network.
 * Validates gas costs under real EVM precompile pricing (ecAdd, ecScalarMul, ecPairing).
 */

import { expect } from "chai";
import { ethers, network, upgrades } from "hardhat";

const FORK_RPC = process.env["MAINNET_RPC_URL"] || "https://ethereum-rpc.publicnode.com";

// ── Constants ────────────────────────────────────────────────────────────────

const DOMAIN = ethers.keccak256(ethers.toUtf8Bytes("fork-gas-domain"));
const PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("fork-gas-vkey"));
const POLICY_HASH = ethers.keccak256(ethers.toUtf8Bytes("fork-gas-policy"));
const PROVER_SET_DIGEST = ethers.keccak256(ethers.toUtf8Bytes("fork-gas-prover-digest"));
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

describe("Fork — Gas Comparison", function () {
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

  let gasTable: Array<{ operation: string; gasUsed: bigint }> = [];

  after(function () {
    console.log("\n  ┌─────────────────────────────────────────────┬──────────────┐");
    console.log("  │ Operation                                   │   Gas Used   │");
    console.log("  ├─────────────────────────────────────────────┼──────────────┤");
    for (const row of gasTable) {
      const op = row.operation.padEnd(43);
      const gas = row.gasUsed.toLocaleString().padStart(12);
      console.log(`  │ ${op} │ ${gas} │`);
    }
    console.log("  └─────────────────────────────────────────────┴──────────────┘");
  });

  it("measures gas: MockGroth16Verifier deploy", async function () {
    const [deployer] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("MockGroth16Verifier", deployer);
    const contract = await Factory.deploy();
    await contract.waitForDeployment();
    const receipt = await ethers.provider.getTransactionReceipt(
      contract.deploymentTransaction()!.hash
    );
    const gas = receipt!.gasUsed;
    gasTable.push({ operation: "MockGroth16Verifier.deploy", gasUsed: gas });
    expect(gas).to.be.greaterThan(0n);
    console.log(`    MockGroth16Verifier deploy: ${gas.toLocaleString()} gas`);
  });

  it("measures gas: Groth16ZkAdapter deploy", async function () {
    const [deployer] = await ethers.getSigners();
    const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier", deployer);
    const verifier = await MockVerifier.deploy();
    await verifier.waitForDeployment();

    const Factory = await ethers.getContractFactory("Groth16ZkAdapter", deployer);
    const contract = await Factory.deploy(await verifier.getAddress(), PROGRAM_VKEY, POLICY_HASH);
    await contract.waitForDeployment();
    const receipt = await ethers.provider.getTransactionReceipt(
      contract.deploymentTransaction()!.hash
    );
    const gas = receipt!.gasUsed;
    gasTable.push({ operation: "Groth16ZkAdapter.deploy", gasUsed: gas });
    expect(gas).to.be.greaterThan(0n);
    console.log(`    Groth16ZkAdapter deploy: ${gas.toLocaleString()} gas`);
  });

  it("measures gas: WorldlineRegistry deploy", async function () {
    const [deployer] = await ethers.getSigners();
    const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier", deployer);
    const verifier = await MockVerifier.deploy();
    await verifier.waitForDeployment();

    const Factory = await ethers.getContractFactory("WorldlineRegistry", deployer);
    const contract = (await upgrades.deployProxy(Factory, [await verifier.getAddress()], {
      kind: "uups"
    })) as any;
    await contract.waitForDeployment();
    const receipt = await ethers.provider.getTransactionReceipt(
      contract.deploymentTransaction()!.hash
    );
    const gas = receipt!.gasUsed;
    gasTable.push({ operation: "WorldlineRegistry.deploy", gasUsed: gas });
    expect(gas).to.be.greaterThan(0n);
    console.log(`    WorldlineRegistry deploy: ${gas.toLocaleString()} gas`);
  });

  it("measures gas: WorldlineFinalizer deploy", async function () {
    const [deployer] = await ethers.getSigners();
    const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier", deployer);
    const verifier = await MockVerifier.deploy();
    await verifier.waitForDeployment();

    const Adapter = await ethers.getContractFactory("Groth16ZkAdapter", deployer);
    const adapter = await Adapter.deploy(await verifier.getAddress(), PROGRAM_VKEY, POLICY_HASH);
    await adapter.waitForDeployment();

    const Factory = await ethers.getContractFactory("WorldlineFinalizer", deployer);
    const contract = (await upgrades.deployProxy(
      Factory,
      [
        await adapter.getAddress(),
        DOMAIN,
        MAX_ACCEPTANCE_DELAY,
        GENESIS_L2_BLOCK,
        ethers.ZeroAddress
      ],
      { kind: "uups" }
    )) as any;
    await contract.waitForDeployment();
    const receipt = await ethers.provider.getTransactionReceipt(
      contract.deploymentTransaction()!.hash
    );
    const gas = receipt!.gasUsed;
    gasTable.push({ operation: "WorldlineFinalizer.deploy", gasUsed: gas });
    expect(gas).to.be.greaterThan(0n);
    console.log(`    WorldlineFinalizer deploy: ${gas.toLocaleString()} gas`);
  });

  it("measures gas: registerDriver", async function () {
    const [deployer] = await ethers.getSigners();
    const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier", deployer);
    const verifier = await MockVerifier.deploy();
    await verifier.waitForDeployment();

    const Registry = await ethers.getContractFactory("WorldlineRegistry", deployer);
    const registry = (await upgrades.deployProxy(Registry, [await verifier.getAddress()], {
      kind: "uups"
    })) as any;
    await registry.waitForDeployment();

    const driverId = ethers.keccak256(ethers.toUtf8Bytes("driver-gas-test"));
    const tx = await (registry as any).registerDriver(driverId, "v1.0.0", "https://gas-test.local");
    const receipt = await tx.wait();
    const gas = receipt!.gasUsed;
    gasTable.push({ operation: "WorldlineRegistry.registerDriver", gasUsed: gas });
    expect(gas).to.be.greaterThan(0n);
    console.log(`    registerDriver: ${gas.toLocaleString()} gas`);
  });

  it("measures gas: setSubmitter", async function () {
    const [owner, prover] = await ethers.getSigners();
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

    const tx = await (finalizer as any).setSubmitter(prover.address, true);
    const receipt = await tx.wait();
    const gas = receipt!.gasUsed;
    gasTable.push({ operation: "WorldlineFinalizer.setSubmitter", gasUsed: gas });
    expect(gas).to.be.greaterThan(0n);
    console.log(`    setSubmitter: ${gas.toLocaleString()} gas`);
  });

  it("measures gas: submitZkValidityProof", async function () {
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
    const gas = receipt!.gasUsed;
    gasTable.push({ operation: "WorldlineFinalizer.submitZkValidityProof", gasUsed: gas });
    expect(gas).to.be.greaterThan(0n);
    console.log(`    submitZkValidityProof: ${gas.toLocaleString()} gas`);
  });

  it("measures gas: verifyProof (MockGroth16Verifier)", async function () {
    const [deployer] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("MockGroth16Verifier", deployer);
    const verifier = await Factory.deploy();
    await verifier.waitForDeployment();

    // Estimate gas for verifyProof call
    const gas = await (verifier as any).verifyProof.estimateGas(
      [1n, 2n],
      [
        [1n, 2n],
        [3n, 4n]
      ],
      [1n, 2n],
      [1n, 2n]
    );
    gasTable.push({ operation: "MockGroth16Verifier.verifyProof", gasUsed: gas });
    expect(gas).to.be.greaterThan(0n);
    console.log(`    verifyProof (mock): ${gas.toLocaleString()} gas`);
  });
});
