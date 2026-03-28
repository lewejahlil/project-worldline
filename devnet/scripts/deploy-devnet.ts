/**
 * Devnet deployment script.
 *
 * Deploys the full Worldline contract stack to the local Hardhat devnet and
 * logs each address as JSON to stdout. Run with:
 *
 *   npx hardhat run devnet/scripts/deploy-devnet.ts \
 *     --config devnet/hardhat.config.devnet.ts \
 *     --network localhost
 */

import { ethers } from "hardhat";

const PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("devnet-program-vkey"));
const POLICY_HASH = ethers.keccak256(ethers.toUtf8Bytes("devnet-policy-hash"));
const DOMAIN = ethers.keccak256(ethers.toUtf8Bytes("devnet-domain"));
const MAX_ACCEPTANCE_DELAY = 3600; // 1 hour
const GENESIS_L2_BLOCK = 0;

async function main(): Promise<void> {
  const [deployer] = await ethers.getSigners();
  console.error(`Deploying from: ${await deployer.getAddress()}`);

  // 1. MockGroth16Verifier — always-true verifier for devnet
  const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier");
  const verifier = await MockVerifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  console.error(`  MockGroth16Verifier → ${verifierAddr}`);

  // 2. Groth16ZkAdapter — wraps verifier with pinned vKey and policyHash
  const Adapter = await ethers.getContractFactory("Groth16ZkAdapter");
  const adapter = await Adapter.deploy(verifierAddr, PROGRAM_VKEY, POLICY_HASH);
  await adapter.waitForDeployment();
  const adapterAddr = await adapter.getAddress();
  console.error(`  Groth16ZkAdapter   → ${adapterAddr}`);

  // 3. WorldlineRegistry — circuit/driver/plugin metadata registry
  const Registry = await ethers.getContractFactory("WorldlineRegistry");
  const registry = await Registry.deploy(verifierAddr);
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.error(`  WorldlineRegistry  → ${registryAddr}`);

  // 4. WorldlineFinalizer — proof submission endpoint
  const Finalizer = await ethers.getContractFactory("WorldlineFinalizer");
  const finalizer = await Finalizer.deploy(
    adapterAddr,
    DOMAIN,
    MAX_ACCEPTANCE_DELAY,
    GENESIS_L2_BLOCK
  );
  await finalizer.waitForDeployment();
  const finalizerAddr = await finalizer.getAddress();
  console.error(`  WorldlineFinalizer → ${finalizerAddr}`);

  // Output JSON to stdout for downstream consumption
  const addresses = {
    verifier: verifierAddr,
    adapter: adapterAddr,
    registry: registryAddr,
    finalizer: finalizerAddr
  };
  console.log(JSON.stringify(addresses, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
