/**
 * Canonical JSON serialisation and Keccak-256 hashing.
 *
 * Rules (compatible with RFC 8785 / JCS):
 * - UTF-8 encoding; no BOM.
 * - No insignificant whitespace.
 * - Object keys sorted lexicographically by their UTF-8 byte representation.
 * - Sorting applied recursively to nested objects.
 * - Array element order preserved.
 * - No trailing commas.
 *
 * CLI usage:
 *   ts-node scripts/canonical-json.ts '{"b":1,"a":2}'
 *   → prints canonical form and its keccak256 hash
 */

import { ethers } from "ethers";

/**
 * Produce the canonical JSON string for an arbitrary value.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value.toString();
  if (typeof value === "number") {
    // Use standard JSON number representation (no unnecessary precision).
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJson).join(",") + "]";
  }
  if (typeof value === "object" && value !== null) {
    const obj = value as Record<string, unknown>;
    const sortedKeys = Object.keys(obj).sort();
    const parts = sortedKeys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`);
    return "{" + parts.join(",") + "}";
  }
  // Fallback: delegate to JSON.stringify (handles bigint etc. by throwing).
  return JSON.stringify(value);
}

/**
 * Return the `0x`-prefixed Keccak-256 hash of the canonical JSON of `value`.
 * Uses ethers.js `keccak256` + `toUtf8Bytes`.
 */
export function canonicalKeccak(value: unknown): string {
  const json = canonicalJson(value);
  return ethers.keccak256(ethers.toUtf8Bytes(json));
}

// ── CLI mode ──────────────────────────────────────────────────────────────────

if (require.main === module) {
  const arg = process.argv[2];
  if (!arg) {
    console.error("Usage: ts-node scripts/canonical-json.ts '<json>'");
    process.exit(1);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(arg);
  } catch (e) {
    console.error("Invalid JSON input:", e);
    process.exit(1);
  }
  const canonical = canonicalJson(parsed);
  const hash = canonicalKeccak(parsed);
  console.log("Canonical:", canonical);
  console.log("Keccak256:", hash);
}
