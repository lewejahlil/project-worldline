import { createReadStream, createWriteStream, existsSync, mkdirSync, unlinkSync } from "fs";
import { createHash } from "crypto";
import { get } from "https";
import { IncomingMessage } from "http";
import { join } from "path";

const PTAU_URL = "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_10.ptau";
const OUTPUT_DIR = join(process.cwd(), "circuits", "ptau");
const OUTPUT_FILE = join(OUTPUT_DIR, "powersOfTau28_hez_final_10.ptau");

/**
 * Expected SHA-256 hash of powersOfTau28_hez_final_10.ptau.
 *
 * Source: Hermez / iden3 Powers of Tau ceremony files hosted at
 * https://storage.googleapis.com/zkevm/ptau/
 * Cross-referenced with the snarkjs documentation and community-verified hashes.
 * See: https://github.com/iden3/snarkjs#7-prepare-phase-2
 */
const PTAU_SHA256 = "53d0e9d1a3576412ada39a82c8ffadd7f110c1b13de56d89b52a472ce5e5edf4";

const MAX_RETRIES = 3;
const IDLE_TIMEOUT_MS = 30_000;
const MAX_REDIRECTS = 5;

const EXIT_CODES = {
  SUCCESS: 0,
  UNEXPECTED: 1,
  NETWORK: 2,
  HTTP: 3
} as const;

function cleanupPartialFile(): void {
  try {
    if (existsSync(OUTPUT_FILE)) {
      unlinkSync(OUTPUT_FILE);
    }
  } catch {
    // best-effort cleanup
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRetriable(statusCode: number | undefined): boolean {
  if (!statusCode) return true; // network-level error, worth retrying
  return statusCode >= 500;
}

function downloadFile(url: string, redirectCount = 0): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    if (redirectCount > MAX_REDIRECTS) {
      reject(new Error("Too many redirects"));
      return;
    }

    const request = get(url, (response: IncomingMessage) => {
      const { statusCode, headers } = response;

      // Handle redirects
      if (statusCode && statusCode >= 300 && statusCode < 400 && headers.location) {
        response.resume(); // drain the response
        downloadFile(headers.location, redirectCount + 1).then(resolve, reject);
        return;
      }

      if (statusCode !== 200) {
        response.resume();
        const err = new Error(`HTTP ${statusCode}`);
        (err as any).statusCode = statusCode;
        reject(err);
        return;
      }

      const fileStream = createWriteStream(OUTPUT_FILE);

      // Idle timeout: abort if no data arrives for 30s
      response.setTimeout(IDLE_TIMEOUT_MS, () => {
        request.destroy(new Error("Download stalled (idle timeout)"));
      });

      response.pipe(fileStream);

      fileStream.on("finish", () => {
        fileStream.close(() => resolve());
      });

      fileStream.on("error", (err) => {
        response.unpipe(fileStream);
        fileStream.close();
        reject(err);
      });

      response.on("error", (err: Error) => {
        fileStream.close();
        reject(err);
      });
    });

    request.on("error", (err) => {
      reject(err);
    });

    request.setTimeout(IDLE_TIMEOUT_MS, () => {
      request.destroy(new Error("Connection timeout"));
    });
  });
}

async function downloadWithRetry(): Promise<void> {
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      await downloadFile(PTAU_URL);
      return;
    } catch (err: any) {
      cleanupPartialFile();

      const statusCode = err?.statusCode as number | undefined;
      const isLastAttempt = attempt === MAX_RETRIES;

      if (!isRetriable(statusCode) || isLastAttempt) {
        if (statusCode && statusCode >= 400 && statusCode < 500) {
          console.error(`Failed to download ptau: HTTP ${statusCode}`);
          process.exit(EXIT_CODES.HTTP);
        }
        console.error(`Failed to download ptau after ${attempt} attempt(s): ${err.message}`);
        process.exit(statusCode ? EXIT_CODES.HTTP : EXIT_CODES.NETWORK);
      }

      const delayMs = 2000 * Math.pow(2, attempt - 1);
      console.warn(
        `Attempt ${attempt}/${MAX_RETRIES} failed: ${err.message}. Retrying in ${delayMs / 1000}s...`
      );
      await sleep(delayMs);
    }
  }
}

// --- Integrity verification ---

/**
 * Verify the SHA-256 hash of a file against an expected hex digest.
 *
 * @param filePath      - Path to the file to verify.
 * @param expectedSha256 - Expected lowercase hex SHA-256 digest.
 * @returns `true` if the hash matches.
 * @throws Error with a descriptive message if the hash does not match.
 */
export function verifyPtauIntegrity(filePath: string, expectedSha256: string): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(filePath);

    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => {
      const actual = hash.digest("hex");
      if (actual === expectedSha256) {
        resolve(true);
      } else {
        reject(
          new Error(
            `ptau integrity check FAILED.\n` +
              `  Expected SHA-256: ${expectedSha256}\n` +
              `  Actual SHA-256:   ${actual}\n` +
              `  File: ${filePath}\n` +
              `The file has been deleted. Re-run the download.`
          )
        );
      }
    });
    stream.on("error", (err) => reject(err));
  });
}

// --- Main ---

if (!existsSync(OUTPUT_DIR)) {
  mkdirSync(OUTPUT_DIR, { recursive: true });
}

if (existsSync(OUTPUT_FILE)) {
  console.log("ptau file already present, verifying integrity...");
  verifyPtauIntegrity(OUTPUT_FILE, PTAU_SHA256)
    .then(() => {
      console.log("ptau integrity verified ✓");
      process.exit(EXIT_CODES.SUCCESS);
    })
    .catch((err) => {
      console.error(err.message);
      cleanupPartialFile();
      process.exit(EXIT_CODES.UNEXPECTED);
    });
} else {
  console.log(`Downloading ptau from ${PTAU_URL}`);
  downloadWithRetry()
    .then(async () => {
      console.log(`ptau saved to ${OUTPUT_FILE}`);
      console.log("Verifying ptau integrity...");
      try {
        await verifyPtauIntegrity(OUTPUT_FILE, PTAU_SHA256);
        console.log("ptau integrity verified ✓");
      } catch (err: any) {
        cleanupPartialFile();
        console.error(err.message);
        process.exit(EXIT_CODES.UNEXPECTED);
      }
    })
    .catch((err) => {
      cleanupPartialFile();
      console.error(`Unexpected error: ${err.message}`);
      process.exit(EXIT_CODES.UNEXPECTED);
    });
}
