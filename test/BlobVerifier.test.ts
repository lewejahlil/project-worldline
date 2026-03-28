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

describe("BlobKzgVerifier", function () {
  async function deployFixture() {
    const Factory = await ethers.getContractFactory("BlobKzgVerifier");
    const kzgVerifier = await Factory.deploy();
    return { kzgVerifier };
  }

  describe("view functions", function () {
    it("currentBlobBaseFee() returns a uint256", async function () {
      const { kzgVerifier } = await loadFixture(deployFixture);
      const fee = await kzgVerifier.currentBlobBaseFee();
      expect(typeof fee).to.equal("bigint");
    });

    it("getBlobHash() returns bytes32(0) outside a blob transaction", async function () {
      const { kzgVerifier } = await loadFixture(deployFixture);
      const hash = await kzgVerifier.getBlobHash(0);
      expect(hash).to.equal(ethers.ZeroHash);
    });
  });

  describe("input validation", function () {
    it("reverts with BlobBaseFeeExceedsMax when maxBlobBaseFee is 0 and fee > 0", async function () {
      const { kzgVerifier } = await loadFixture(deployFixture);
      const currentFee = await kzgVerifier.currentBlobBaseFee();
      if (currentFee > 0n) {
        await expect(
          kzgVerifier.verifyBlob(
            0,
            ethers.ZeroHash,
            ethers.ZeroHash,
            ethers.randomBytes(48),
            ethers.randomBytes(48),
            ethers.randomBytes(32),
            0n
          )
        ).to.be.revertedWithCustomError(kzgVerifier, "BlobBaseFeeExceedsMax");
      }
    });

    it("reverts with InvalidCommitmentLength for 32-byte commitment", async function () {
      const { kzgVerifier } = await loadFixture(deployFixture);
      await expect(
        kzgVerifier.verifyBlob(
          0,
          ethers.ZeroHash,
          ethers.ZeroHash,
          ethers.randomBytes(32), // wrong: should be 48
          ethers.randomBytes(48),
          ethers.randomBytes(32),
          ethers.parseUnits("1", "gwei")
        )
      ).to.be.revertedWithCustomError(kzgVerifier, "InvalidCommitmentLength");
    });

    it("reverts with InvalidProofLength for 32-byte proof", async function () {
      const { kzgVerifier } = await loadFixture(deployFixture);
      await expect(
        kzgVerifier.verifyBlob(
          0,
          ethers.ZeroHash,
          ethers.ZeroHash,
          ethers.randomBytes(48),
          ethers.randomBytes(32), // wrong: should be 48
          ethers.randomBytes(32),
          ethers.parseUnits("1", "gwei")
        )
      ).to.be.revertedWithCustomError(kzgVerifier, "InvalidProofLength");
    });

    it("reverts with PointOutOfField when openingPoint >= BLS_MODULUS", async function () {
      const { kzgVerifier } = await loadFixture(deployFixture);
      // Use max uint256 which is above the BLS modulus
      const maxPoint = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
      await expect(
        kzgVerifier.verifyBlob(
          0,
          maxPoint,
          ethers.ZeroHash,
          ethers.randomBytes(48),
          ethers.randomBytes(48),
          ethers.randomBytes(32),
          ethers.parseUnits("1", "gwei")
        )
      ).to.be.revertedWithCustomError(kzgVerifier, "PointOutOfField");
    });

    it("reverts with BlobHashZero when called outside a blob tx", async function () {
      const { kzgVerifier } = await loadFixture(deployFixture);
      // Use valid field elements (zero is below BLS_MODULUS)
      await expect(
        kzgVerifier.verifyBlob(
          0,
          ethers.ZeroHash,
          ethers.ZeroHash,
          ethers.randomBytes(48),
          ethers.randomBytes(48),
          ethers.randomBytes(32),
          ethers.parseUnits("1", "gwei")
        )
      ).to.be.revertedWithCustomError(kzgVerifier, "BlobHashZero");
    });
  });
});
