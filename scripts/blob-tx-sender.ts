import { ethers } from "hardhat";
import { encodeDataAsBlob, computeBlobSidecar, BlobSidecar } from "./blob-helpers";

export interface BlobTxOptions {
  to: string;
  data: string; // calldata for the contract call
  proofBatchData: Uint8Array; // raw proof batch bytes to encode as blob
  maxBlobBaseFee?: bigint; // defaults to 2x current blob base fee
}

/**
 * Fetches the current blob base fee via eth_blobBaseFee RPC call.
 * Falls back to 1 gwei if the node does not support the call (e.g., local Hardhat).
 */
export async function getCurrentBlobBaseFee(): Promise<bigint> {
  const provider = ethers.provider;
  try {
    const blobBaseFee = await provider.send("eth_blobBaseFee", []);
    return BigInt(blobBaseFee);
  } catch {
    // Hardhat Network does not support eth_blobBaseFee in all versions
    // Return a sensible default for testing
    return BigInt(1e9); // 1 gwei
  }
}

/**
 * Encodes proof batch data into a blob sidecar.
 * Returns the sidecar and the versioned hash for on-chain verification.
 */
export function prepareBlobFromProofBatch(proofBatchData: Uint8Array): BlobSidecar {
  const blob = encodeDataAsBlob(proofBatchData);
  return computeBlobSidecar(blob);
}

/**
 * Logs blob transaction metadata for observability.
 */
export function logBlobTxMetadata(sidecar: BlobSidecar, blobBaseFee: bigint): void {
  // eslint-disable-next-line no-console
  console.log({
    event: "blob_tx_prepared",
    versionedHash: sidecar.versionedHash,
    commitmentHex: Buffer.from(sidecar.commitment).toString("hex").slice(0, 16) + "...",
    blobBaseFee: blobBaseFee.toString()
  });
}
