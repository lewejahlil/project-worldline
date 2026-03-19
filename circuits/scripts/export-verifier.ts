import * as fs from "fs";
import * as path from "path";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const snarkjs = require("snarkjs");

const ZKEY_PATH = path.resolve(__dirname, "../artifacts/worldline_final.zkey");
const OUTPUT_PATH = path.resolve(__dirname, "../../contracts/src/zk/Groth16Verifier.sol");

async function main(): Promise<void> {
  if (!fs.existsSync(ZKEY_PATH)) {
    console.error(`zkey not found at ${ZKEY_PATH}`); // eslint-disable-line no-console
    console.error("Run 'npm run c:compile' and 'npm run c:setup' first."); // eslint-disable-line no-console
    process.exit(1);
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
