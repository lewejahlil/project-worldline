/**
 * Reference Groth16 prover plugin for the Worldline SDK.
 *
 * Demonstrates the minimal surface area a prover plugin must implement
 * to integrate with the Worldline aggregator/driver. In production, the
 * `prove` function would invoke a full snarkjs Groth16 prover and the
 * `verify` function would call the generated Solidity verifier.
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const snarkjs = require("snarkjs");

export interface ProofInput {
  secret: bigint;
  publicHash: bigint;
}

export interface ProofResult {
  proof: unknown;
  publicSignals: string[];
}

export interface PluginConfig {
  wasmPath: string;
  zkeyPath: string;
  vkeyPath: string;
}

/**
 * Generate a Groth16 proof for the SquareHash circuit.
 */
export async function prove(
  config: PluginConfig,
  input: ProofInput
): Promise<ProofResult> {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    { secret: input.secret.toString(), publicHash: input.publicHash.toString() },
    config.wasmPath,
    config.zkeyPath
  );
  return { proof, publicSignals };
}

/**
 * Verify a Groth16 proof against the circuit's verification key.
 */
export async function verify(
  config: PluginConfig,
  proof: unknown,
  publicSignals: string[]
): Promise<boolean> {
  const fs = await import("fs");
  const vkey = JSON.parse(fs.readFileSync(config.vkeyPath, "utf-8"));
  return snarkjs.groth16.verify(vkey, publicSignals, proof);
}

/**
 * Plugin metadata used for directory registration.
 */
export const metadata = {
  family: "groth16",
  version: "0.1.0",
  description: "Reference Groth16 plugin for SquareHash circuit"
};
