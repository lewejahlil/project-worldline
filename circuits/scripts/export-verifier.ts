import * as fs from "fs";
import * as path from "path";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const snarkjs = require("snarkjs");

const ZKEY_PATH = path.resolve(__dirname, "../artifacts/worldline_final.zkey");
const R1CS_PATH = path.resolve(__dirname, "../artifacts/worldline.r1cs");
const PTAU_PATH = path.resolve(__dirname, "../ptau/powersOfTau28_hez_final_10.ptau");
const OUTPUT_PATH = path.resolve(__dirname, "../../contracts/src/zk/Groth16Verifier.sol");

async function main(): Promise<void> {
  // Safety check: only export from a *_final.zkey to prevent exporting from an
  // intermediate (unfinished ceremony) key. This is a CRI-002 remediation guard.
  const zkeyFilename = path.basename(ZKEY_PATH);
  if (!zkeyFilename.endsWith("_final.zkey")) {
    console.error(
      // eslint-disable-line no-console
      `ERROR: ZKEY_PATH must point to a *_final.zkey file, got: ${zkeyFilename}\n` +
        "Exporting from an intermediate zkey (e.g. worldline_0000.zkey) is unsafe.\n" +
        "Run the full ceremony: npm run c:setup"
    );
    process.exit(1);
  }

  if (!fs.existsSync(ZKEY_PATH)) {
    console.error(`zkey not found at ${ZKEY_PATH}`); // eslint-disable-line no-console
    console.error("Run 'npm run c:compile' and 'npm run c:setup' first."); // eslint-disable-line no-console
    process.exit(1);
  }

  // Verify the zkey against the r1cs and ptau before exporting.
  // This ensures the exported verifier matches a properly completed ceremony.
  // eslint-disable-next-line no-console
  console.log("Verifying zkey before export...");
  if (fs.existsSync(R1CS_PATH) && fs.existsSync(PTAU_PATH)) {
    const verifyResult = await snarkjs.zKey.verify(R1CS_PATH, PTAU_PATH, ZKEY_PATH);
    if (!verifyResult) {
      console.error("ERROR: snarkjs zkey verify FAILED. The zkey may be corrupted or incomplete."); // eslint-disable-line no-console
      console.error("Re-run the full ceremony: npm run c:setup"); // eslint-disable-line no-console
      process.exit(1);
    }
    console.log("zkey verification passed ✓"); // eslint-disable-line no-console
  } else {
    console.warn(
      // eslint-disable-line no-console
      "WARNING: r1cs or ptau not found — skipping zkey verify.\n" +
        "  Run 'npm run c:setup:verify' manually to verify the zkey."
    );
  }

  // eslint-disable-next-line no-console
  console.log(`Reading zkey from ${ZKEY_PATH}...`);

  const templates = {
    groth16: fs.readFileSync(
      path.resolve(__dirname, "../../node_modules/snarkjs/templates/verifier_groth16.sol.ejs"),
      "utf-8"
    )
  };

  const solidityCode: string = await snarkjs.zKey.exportSolidityVerifier(ZKEY_PATH, templates);

  const outputDir = path.dirname(OUTPUT_PATH);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  fs.writeFileSync(OUTPUT_PATH, solidityCode);
  // eslint-disable-next-line no-console
  console.log(`Groth16 verifier written to ${OUTPUT_PATH}`);
}

main().catch((err: Error) => {
  console.error(err); // eslint-disable-line no-console
  process.exit(1);
});
