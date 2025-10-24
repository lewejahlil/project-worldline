import { copyFileSync, existsSync } from "fs";
import { join } from "path";

const SOURCE = join(process.cwd(), "circuits", "artifacts", "Verifier.sol");
const TARGET = join(process.cwd(), "contracts", "src", "zk", "Verifier.sol");

if (!existsSync(SOURCE)) {
  console.error(
    "Verifier.sol missing – run `npm run c:compile` and `npm run c:setup` first."
  );
  process.exit(1);
}

copyFileSync(SOURCE, TARGET);
console.log(`Copied verifier to ${TARGET}`);
