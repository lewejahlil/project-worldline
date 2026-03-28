/**
 * Devnet prover seeding script.
 *
 * Registers 3 prover drivers (Groth16, Plonk, Halo2) in WorldlineRegistry and
 * authorises the corresponding accounts as submitters in WorldlineFinalizer.
 * Quorum is set to 2 (2-of-3 submitters).
 *
 * Expects the following environment variables (output of deploy-devnet.ts):
 *   REGISTRY_ADDRESS   — WorldlineRegistry contract address
 *   FINALIZER_ADDRESS  — WorldlineFinalizer contract address
 *
 * Run with:
 *   REGISTRY_ADDRESS=0x... FINALIZER_ADDRESS=0x... \
 *   npx hardhat run devnet/scripts/seed-provers.ts \
 *     --config devnet/hardhat.config.devnet.ts \
 *     --network localhost
 */

import { ethers } from "hardhat";

// Proof system IDs matching the domain quick-ref
const PROOF_SYSTEMS = [
  { id: 1, name: "Groth16" },
  { id: 2, name: "Plonk" },
  { id: 3, name: "Halo2" }
];

// On-chain quorum encoding: proverSetDigest = Poseidon(proverIds, proofSystemIds, quorumCount)
// Off-chain: circuit enforces 2-of-3 quorum. On-chain we register all 3 as authorized submitters.
const QUORUM_COUNT = 2;

async function main(): Promise<void> {
  const signers = await ethers.getSigners();
  const [deployer, prover1, prover2, prover3] = signers;

  const registryAddr = process.env["REGISTRY_ADDRESS"];
  const finalizerAddr = process.env["FINALIZER_ADDRESS"];

  if (!registryAddr || !finalizerAddr) {
    throw new Error(
      "REGISTRY_ADDRESS and FINALIZER_ADDRESS env vars are required.\n" +
        "Run deploy-devnet.ts first and pass the output addresses."
    );
  }

  console.log(`Seeding provers on registry: ${registryAddr}`);
  console.log(`Configuring submitters on finalizer: ${finalizerAddr}`);
  console.log(`Quorum: ${QUORUM_COUNT}-of-${PROOF_SYSTEMS.length}\n`);

  const registry = await ethers.getContractAt("WorldlineRegistry", registryAddr, deployer);
  const finalizer = await ethers.getContractAt("WorldlineFinalizer", finalizerAddr, deployer);

  const proverAccounts = [prover1, prover2, prover3];

  for (let i = 0; i < PROOF_SYSTEMS.length; i++) {
    const ps = PROOF_SYSTEMS[i];
    const account = proverAccounts[i];
    const proverId = ethers.keccak256(ethers.toUtf8Bytes(`prover-${ps.id}`));
    const driverId = ethers.keccak256(ethers.toUtf8Bytes(`driver-${ps.id}`));

    // Register driver entry in WorldlineRegistry
    const tx = await (registry as any).registerDriver(
      driverId,
      `v1.0.0-${ps.name.toLowerCase()}`,
      `https://devnet.worldline.local/prover/${ps.id}`
    );
    await tx.wait();
    console.log(
      `  [registry] Driver ${ps.name} (id=${driverId.slice(0, 10)}…) → ${await account.getAddress()}`
    );
    void proverId;

    // Authorise the prover account as a submitter on WorldlineFinalizer
    const tx2 = await (finalizer as any).setSubmitter(await account.getAddress(), true);
    await tx2.wait();
    console.log(`  [finalizer] setSubmitter ${await account.getAddress()} = true`);
  }

  // Disable permissionless mode so only registered submitters can submit
  const tx3 = await (finalizer as any).setPermissionless(false);
  await tx3.wait();
  console.log("\n  [finalizer] permissionless = false (only registered submitters may submit)");

  console.log(
    `\nDone. ${PROOF_SYSTEMS.length} provers registered. Quorum: ${QUORUM_COUNT}-of-${PROOF_SYSTEMS.length}.`
  );
  console.log(
    `Prover accounts:\n` +
      proverAccounts
        .map((a, i) => `  Prover ${i + 1} (${PROOF_SYSTEMS[i].name}): ${a.address}`)
        .join("\n")
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
