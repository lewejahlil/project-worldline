import { ethers } from "hardhat";
import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { Verifier } from "../typechain-types";

describe("Verifier", function () {
  async function deployVerifierFixture() {
    const Verifier = await ethers.getContractFactory("Verifier");
    const verifier: Verifier = await Verifier.deploy();
    return { verifier };
  }

  describe("verifyProof", function () {
    it("succeeds when secret² == publicHash", async function () {
      const { verifier } = await loadFixture(deployVerifierFixture);
      // 3² = 9
      await expect(verifier.verifyProof(3n, 9n)).to.not.be.reverted;
    });

    it("succeeds for secret=5, publicHash=25", async function () {
      const { verifier } = await loadFixture(deployVerifierFixture);
      await expect(verifier.verifyProof(5n, 25n)).to.not.be.reverted;
    });

    it("succeeds for zero: secret=0, publicHash=0", async function () {
      const { verifier } = await loadFixture(deployVerifierFixture);
      await expect(verifier.verifyProof(0n, 0n)).to.not.be.reverted;
    });

    it("succeeds for secret=1, publicHash=1", async function () {
      const { verifier } = await loadFixture(deployVerifierFixture);
      await expect(verifier.verifyProof(1n, 1n)).to.not.be.reverted;
    });

    it("reverts with InvalidProof when secret² != publicHash", async function () {
      const { verifier } = await loadFixture(deployVerifierFixture);
      // 3² = 9, but we pass 10
      await expect(verifier.verifyProof(3n, 10n))
        .to.be.revertedWithCustomError(verifier, "InvalidProof");
    });

    it("reverts when secret is correct but publicHash is off by one", async function () {
      const { verifier } = await loadFixture(deployVerifierFixture);
      await expect(verifier.verifyProof(5n, 24n))
        .to.be.revertedWithCustomError(verifier, "InvalidProof");
    });

    it("reverts when secret=0 but publicHash is non-zero", async function () {
      const { verifier } = await loadFixture(deployVerifierFixture);
      await expect(verifier.verifyProof(0n, 1n))
        .to.be.revertedWithCustomError(verifier, "InvalidProof");
    });

    it("handles a large valid pair within uint256 bounds", async function () {
      const { verifier } = await loadFixture(deployVerifierFixture);
      // Use 2^64 so that secret² = 2^128, well within uint256.
      const secret = 2n ** 64n;
      const publicHash = secret * secret; // 2^128
      await expect(verifier.verifyProof(secret, publicHash)).to.not.be.reverted;
    });

    it("reverts with overflow panic when secret² exceeds uint256 (Solidity 0.8 checked math)", async function () {
      const { verifier } = await loadFixture(deployVerifierFixture);
      // 2^128 * 2^128 = 2^256, which overflows uint256.
      const secret = 2n ** 128n;
      await expect(verifier.verifyProof(secret, 0n)).to.be.revertedWithPanic(
        0x11 // arithmetic overflow
      );
    });
  });
});
