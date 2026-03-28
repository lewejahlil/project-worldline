import { createHash } from "crypto";

import * as kzg from "c-kzg";
import { keccak256 } from "ethers";

// -------------------------------------------------------------------------
// EIP-4844 constants
// -------------------------------------------------------------------------

export const BYTES_PER_FIELD_ELEMENT = 32;
export const FIELD_ELEMENTS_PER_BLOB = 4096;
export const BYTES_PER_BLOB = BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB; // 131,072

// 31 usable bytes per field element (high byte must be 0 to stay below BLS_MODULUS)
export const USABLE_BYTES_PER_ELEMENT = 31;
export const MAX_BLOB_DATA_BYTES = FIELD_ELEMENTS_PER_BLOB * USABLE_BYTES_PER_ELEMENT;

// BLS12-381 field modulus
export const BLS_MODULUS = BigInt(
  "52435875175126190479447740508185965837690552500527637822603658699938581184513"
);

// KZG trusted setup — load once at module level
// Uses the official Ethereum mainnet Powers of Tau setup bundled with c-kzg
kzg.loadTrustedSetup();

// -------------------------------------------------------------------------
// Types
// -------------------------------------------------------------------------

export interface BlobSidecar {
  blob: Uint8Array; // BYTES_PER_BLOB raw blob data
  commitment: Uint8Array; // 48 bytes — KZG commitment
  proof: Uint8Array; // 48 bytes — KZG proof
  versionedHash: string; // bytes32 hex — 0x01 || SHA256(commitment)[1:]
}

export interface BlobSubmissionParams {
  blobIndex: number;
  openingPoint: string; // bytes32 hex
  claimedValue: string; // bytes32 hex
  commitment: Uint8Array;
  proof: Uint8Array;
  batchId: string; // bytes32 hex
  maxBlobBaseFee: bigint;
}

// -------------------------------------------------------------------------
// Blob encoding
// -------------------------------------------------------------------------

/**
 * Encodes arbitrary bytes into a KZG-compatible blob.
 *
 * Each 32-byte field element holds 31 bytes of data with the high byte set to 0x00.
 * This guarantees every field element is below the BLS12-381 field modulus.
 *
 * @param data - Raw bytes to encode (max MAX_BLOB_DATA_BYTES)
 * @returns Uint8Array of exactly BYTES_PER_BLOB length
 */
export function encodeDataAsBlob(data: Uint8Array): Uint8Array {
  if (data.length > MAX_BLOB_DATA_BYTES) {
    throw new Error(
      `Data too large for single blob: ${data.length} bytes exceeds max ${MAX_BLOB_DATA_BYTES}`
    );
  }

  const blob = new Uint8Array(BYTES_PER_BLOB); // zero-initialized

  for (let i = 0; i < data.length; i++) {
    const elementIndex = Math.floor(i / USABLE_BYTES_PER_ELEMENT);
    // Offset by 1 within each 32-byte element to keep the high byte 0x00
    const byteOffset = (i % USABLE_BYTES_PER_ELEMENT) + 1;
    blob[elementIndex * BYTES_PER_FIELD_ELEMENT + byteOffset] = data[i];
  }

  return blob;
}

/**
 * Decodes a blob back into the original data bytes.
 * Inverse of encodeDataAsBlob.
 *
 * @param blob - BYTES_PER_BLOB length Uint8Array
 * @param dataLength - original data length (needed to trim trailing zeros)
 * @returns Original data bytes
 */
export function decodeBlobToData(blob: Uint8Array, dataLength: number): Uint8Array {
  const data = new Uint8Array(dataLength);
  for (let i = 0; i < dataLength; i++) {
    const elementIndex = Math.floor(i / USABLE_BYTES_PER_ELEMENT);
    const byteOffset = (i % USABLE_BYTES_PER_ELEMENT) + 1;
    data[i] = blob[elementIndex * BYTES_PER_FIELD_ELEMENT + byteOffset];
  }
  return data;
}

// -------------------------------------------------------------------------
// KZG commitment and proof
// -------------------------------------------------------------------------

/**
 * Computes the KZG commitment, proof, and versioned hash for a blob.
 *
 * Versioned hash format (EIP-4844):
 *   0x01 || SHA256(commitment)[1:]
 * The 0x01 prefix is the KZG commitment version byte.
 *
 * @param blob - BYTES_PER_BLOB raw blob
 * @returns BlobSidecar with commitment, proof, and versioned hash
 */
export function computeBlobSidecar(blob: Uint8Array): BlobSidecar {
  if (blob.length !== BYTES_PER_BLOB) {
    throw new Error(`Blob must be exactly ${BYTES_PER_BLOB} bytes, got ${blob.length}`);
  }

  const commitment = kzg.blobToKzgCommitment(blob);
  const proof = kzg.computeBlobKzgProof(blob, commitment);

  // Compute versioned hash: 0x01 || SHA256(commitment)[1:]
  const sha256Hash = createHash("sha256").update(Buffer.from(commitment)).digest();
  const versionedHashBytes = Buffer.alloc(32);
  versionedHashBytes[0] = 0x01; // version byte
  sha256Hash.copy(versionedHashBytes, 1, 1, 32); // copy bytes [1..31]
  const versionedHash = "0x" + versionedHashBytes.toString("hex");

  return { blob, commitment, proof, versionedHash };
}

/**
 * Prepares BlobSubmissionParams for the BlobKzgVerifier.verifyBlob() call.
 * Uses a deterministic opening point derived from the versioned hash.
 *
 * @param sidecar - BlobSidecar from computeBlobSidecar
 * @param batchId - The proof batch ID this blob is associated with
 * @param maxBlobBaseFee - Maximum blob base fee to accept
 * @param blobIndex - Index of this blob in the transaction sidecar
 */
export function buildBlobSubmissionParams(
  sidecar: BlobSidecar,
  batchId: string,
  maxBlobBaseFee: bigint,
  blobIndex = 0
): BlobSubmissionParams {
  // Deterministic opening point: keccak256(versionedHash || batchId) mod BLS_MODULUS
  const challengeInput = keccak256("0x" + sidecar.versionedHash.slice(2) + batchId.slice(2));
  const openingPointBigInt = BigInt(challengeInput) % BLS_MODULUS;
  const openingPoint = "0x" + openingPointBigInt.toString(16).padStart(64, "0");

  // Evaluate the blob polynomial at the opening point to get the claimed value
  const openingPointBytes = Buffer.from(openingPoint.slice(2), "hex");
  const [proofAtPoint, claimedValueBytes] = kzg.computeKzgProof(sidecar.blob, openingPointBytes);

  return {
    blobIndex,
    openingPoint,
    claimedValue: "0x" + Buffer.from(claimedValueBytes).toString("hex").padStart(64, "0"),
    commitment: sidecar.commitment,
    proof: proofAtPoint,
    batchId,
    maxBlobBaseFee
  };
}
