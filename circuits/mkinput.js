const fs = require('fs');
const { keccak256 } = require('ethers').utils;

function toHex32(buf) {
  return '0x' + Buffer.from(buf).toString('hex').padStart(64, '0');
}
function toHex32BEU128(num) {
  const b = Buffer.alloc(32); // big-endian
  b.writeBigUInt64BE(0n, 0); // keep top 16 bytes zero
  b.writeBigUInt64BE(0n, 8);
  b.writeBigUInt64BE(BigInt(num) >> 64n, 16);
  b.writeBigUInt64BE(BigInt(num) & ((1n<<64n)-1n), 24);
  return '0x' + b.toString('hex');
}

if (process.argv.length < 3) {
  console.error("usage: node circuits/mkinput.js /path/to/abi.bin (160B)");
  process.exit(1);
}

const abi = fs.readFileSync(process.argv[2]);
if (abi.length !== 160) throw new Error("ABI must be 160 bytes");

const input = {
  abi0: toHex32(abi.slice(0, 32)),
  abi1: toHex32(abi.slice(32, 64)),
  abi2: toHex32(abi.slice(64, 96)),
  abi3: toHex32(abi.slice(96, 128)),
  abi4: toHex32(abi.slice(128, 160)),

  // must match Deploy.s.sol pinned immutables in Groth16Adapter
  programVKey_in: "0x00000000000000000000000000000000000000000000000000000000000A11CE",
  policyHash_in:  "0x0000000000000000000000000000000000000000000000000000000000000B0B",

  // bind to ABI for now so adapter and circuit agree
  proverSetDigest_in: keccak256('0x' + Buffer.from(abi).toString('hex'))
};

fs.mkdirSync("circuits/build", { recursive: true });
fs.writeFileSync("circuits/build/input.json", JSON.stringify(input, null, 2));
console.log("wrote circuits/build/input.json");
