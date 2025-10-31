import { createWriteStream, existsSync, mkdirSync } from "fs";
import { get } from "https";
import { join } from "path";

const PTAU_URL =
  "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_10.ptau";
const OUTPUT_DIR = join(process.cwd(), "circuits", "ptau");
const OUTPUT_FILE = join(OUTPUT_DIR, "powersOfTau28_hez_final_10.ptau");

if (!existsSync(OUTPUT_DIR)) {
  mkdirSync(OUTPUT_DIR, { recursive: true });
}

if (existsSync(OUTPUT_FILE)) {
  console.log("ptau file already present, skipping download");
  process.exit(0);
}

console.log(`Downloading ptau from ${PTAU_URL}`);
get(PTAU_URL, (response) => {
  if (response.statusCode && response.statusCode >= 400) {
    console.error(`Failed to download ptau: ${response.statusCode}`);
    process.exit(1);
  }

  const fileStream = createWriteStream(OUTPUT_FILE);
  response.pipe(fileStream);

  fileStream.on("finish", () => {
    fileStream.close();
    console.log(`ptau saved to ${OUTPUT_FILE}`);
  });
}).on("error", (err) => {
  console.error(`Error while downloading ptau: ${err.message}`);
  process.exit(1);
});
