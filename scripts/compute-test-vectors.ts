import { canonicalJson, canonicalKeccak } from "./canonical-json";

function pad(n: string, len: number = 64): string {
  return "0x" + n.repeat(len / n.length).slice(0, len);
}

function sortManifest(
  m: Array<{
    family: string;
    prover_id: string;
    version: string;
    vkey_commitment: string;
    image_digest: string;
  }>
) {
  return [...m].sort((a, b) => {
    const ka = `${a.family}\0${a.prover_id}\0${a.version}`;
    const kb = `${b.family}\0${b.prover_id}\0${b.version}`;
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}

// TV1: Basic selection, groth16 + plonk selected (smallest prefix with 2 families)
const m1 = sortManifest([
  {
    family: "groth16",
    prover_id: "g1",
    version: "1.0.0",
    vkey_commitment: pad("a"),
    image_digest: pad("1")
  },
  {
    family: "plonk",
    prover_id: "p1",
    version: "1.0.0",
    vkey_commitment: pad("c"),
    image_digest: pad("3")
  }
]);
console.log("TV1 canonical:", canonicalJson(m1));
console.log("TV1 digest:", canonicalKeccak(m1));
console.log();

// TV2: Required family groth16
const m2 = sortManifest([
  {
    family: "groth16",
    prover_id: "g1",
    version: "1.0.0",
    vkey_commitment: pad("a"),
    image_digest: pad("1")
  }
]);
console.log("TV2 canonical:", canonicalJson(m2));
console.log("TV2 digest:", canonicalKeccak(m2));
console.log();

// TV3: Allowlist: only g1 and p1
const m3 = sortManifest([
  {
    family: "groth16",
    prover_id: "g1",
    version: "1.0.0",
    vkey_commitment: pad("a"),
    image_digest: pad("1")
  },
  {
    family: "plonk",
    prover_id: "p1",
    version: "1.0.0",
    vkey_commitment: pad("c"),
    image_digest: pad("3")
  }
]);
console.log("TV3 canonical:", canonicalJson(m3));
console.log("TV3 digest:", canonicalKeccak(m3));
console.log();

// TV4: Fallback tier activates (required family missing, fallback selects groth16)
const m4 = sortManifest([
  {
    family: "groth16",
    prover_id: "g1",
    version: "1.0.0",
    vkey_commitment: pad("a"),
    image_digest: pad("1")
  }
]);
console.log("TV4 canonical:", canonicalJson(m4));
console.log("TV4 digest:", canonicalKeccak(m4));
console.log();

// TV5: Tie-break: g_fast (lower latency) + sp1
const m5 = sortManifest([
  {
    family: "groth16",
    prover_id: "g_fast",
    version: "1.0.0",
    vkey_commitment: pad("b"),
    image_digest: pad("2")
  },
  {
    family: "sp1",
    prover_id: "s1",
    version: "1.0.0",
    vkey_commitment: pad("c"),
    image_digest: pad("3")
  }
]);
console.log("TV5 canonical:", canonicalJson(m5));
console.log("TV5 digest:", canonicalKeccak(m5));
