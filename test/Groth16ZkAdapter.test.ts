import { ethers } from "hardhat";
import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";

const PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("program-vkey"));
const POLICY_HASH = ethers.keccak256(ethers.toUtf8Bytes("policy-hash"));

describe("Groth16ZkAdapter", function () {
  async function deployFixture() {
    const [owner] = await ethers.getSigners();

    const Verifier = await ethers.getContractFactory("Verifier");
    const verifier = await Verifier.deploy();

    const Adapter = await ethers.getContractFactory("Groth16ZkAdapter");
    const adapter = await Adapter.deploy(
      await verifier.getAddress(),
      PROGRAM_VKEY,
      POLICY_HASH
    );

    return { adapter, verifier, owner };
  }

  describe("deployment", function () {
    it("stores pinned programVKey", async function () {
      const { adapter } = await loadFixture(deployFixture);
      expect(await adapter.programVKeyPinned()).to.equal(PROGRAM_VKEY);
    });

    it("stores pinned policyHash", async function () {
      const { adapter } = await loadFixture(deployFixture);
      expect(await adapter.policyHashPinned()).to.equal(POLICY_HASH);
    });
  });

  describe("verify", function () {
    it("returns valid=true for correct proof with matching pinned values", async function () {
      const { adapter } = await loadFixture(deployFixture);
      const stfCommitment = ethers.keccak256(ethers.toUtf8Bytes("stf"));
      const proverDigest = ethers.keccak256(ethers.toUtf8Bytes("provers"));

      // Encode proof with the four public signals
      const proof = ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "bytes32", "bytes32"],
        [stfCommitment, PROGRAM_VKEY, POLICY_HASH, proverDigest]
      );

      // Encode publicInputs with secret=5, publicHash=25 (5²=25)
      const publicInputs = ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "uint256"],
        [5, 25]
      );

      const result = await adapter.verify(proof, publicInputs);
      expect(result.valid).to.be.true;
      expect(result.stfCommitment).to.equal(stfCommitment);
      expect(result.programVKey).to.equal(PROGRAM_VKEY);
      expect(result.policyHash).to.equal(POLICY_HASH);
      expect(result.proverSetDigest).to.equal(proverDigest);
    });

    it("reverts when programVKey does not match pinned value", async function () {
      const { adapter } = await loadFixture(deployFixture);
      const wrongVKey = ethers.keccak256(ethers.toUtf8Bytes("wrong"));
      const proof = ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "bytes32", "bytes32"],
        [ethers.ZeroHash, wrongVKey, POLICY_HASH, ethers.ZeroHash]
      );
      const publicInputs = ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "uint256"],
        [3, 9]
      );
      await expect(adapter.verify(proof, publicInputs))
        .to.be.revertedWithCustomError(adapter, "ProgramVKeyMismatch");
    });

    it("reverts when policyHash does not match pinned value", async function () {
      const { adapter } = await loadFixture(deployFixture);
      const wrongPolicy = ethers.keccak256(ethers.toUtf8Bytes("wrong"));
      const proof = ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "bytes32", "bytes32"],
        [ethers.ZeroHash, PROGRAM_VKEY, wrongPolicy, ethers.ZeroHash]
      );
      const publicInputs = ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "uint256"],
        [3, 9]
      );
      await expect(adapter.verify(proof, publicInputs))
        .to.be.revertedWithCustomError(adapter, "PolicyHashMismatch");
    });

    it("reverts when underlying proof is invalid (secret² != publicHash)", async function () {
      const { adapter, verifier } = await loadFixture(deployFixture);
      const proof = ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "bytes32", "bytes32"],
        [ethers.ZeroHash, PROGRAM_VKEY, POLICY_HASH, ethers.ZeroHash]
      );
      // 3² != 10
      const publicInputs = ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "uint256"],
        [3, 10]
      );
      await expect(adapter.verify(proof, publicInputs))
        .to.be.revertedWithCustomError(verifier, "InvalidProof");
    });
  });
});
