import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";

/**
 * BlobVerifier library tests.
 *
 * NOTE: Hardhat's local EVM does not support EIP-4844 blob transactions, so
 * `blobhash(0)` always returns bytes32(0). These tests verify the error paths
 * and the version-byte validation logic. Full blob integration testing requires
 * a Cancun-enabled devnet or mainnet fork with blob transaction support.
 */
describe("BlobVerifier", function () {
  async function deployFixture() {
    const Factory = await ethers.getContractFactory("BlobVerifierHarness");
    const harness = await Factory.deploy();
    return { harness };
  }

  describe("getBlobHash", function () {
    it("returns bytes32(0) when no blob exists (local EVM)", async function () {
      const { harness } = await loadFixture(deployFixture);
      const hash = await harness.getBlobHash(0);
      expect(hash).to.equal(ethers.ZeroHash);
    });
  });

  describe("verifyBlobHash", function () {
    it("reverts with NoBlobAtIndex when no blob at index", async function () {
      const { harness } = await loadFixture(deployFixture);
      const fakeHash = ethers.keccak256(ethers.toUtf8Bytes("fake-blob"));
      await expect(harness.verifyBlobHash(0, fakeHash)).to.be.revertedWithCustomError(
        harness,
        "NoBlobAtIndex"
      );
    });
  });

  describe("validateVersionByte", function () {
    it("accepts a hash with version byte 0x01", async function () {
      const { harness } = await loadFixture(deployFixture);
      // Construct a hash with 0x01 as the first byte
      const validHash = "0x01" + "aa".repeat(31);
      await expect(harness.validateVersionByte(validHash)).to.not.be.reverted;
    });

    it("rejects a hash with wrong version byte", async function () {
      const { harness } = await loadFixture(deployFixture);
      // Version byte 0x00 is invalid
      const invalidHash = "0x00" + "bb".repeat(31);
      await expect(harness.validateVersionByte(invalidHash)).to.be.revertedWithCustomError(
        harness,
        "InvalidVersionedHash"
      );
    });

    it("rejects a hash with version byte 0x02", async function () {
      const { harness } = await loadFixture(deployFixture);
      const invalidHash = "0x02" + "cc".repeat(31);
      await expect(harness.validateVersionByte(invalidHash)).to.be.revertedWithCustomError(
        harness,
        "InvalidVersionedHash"
      );
    });
  });
});
