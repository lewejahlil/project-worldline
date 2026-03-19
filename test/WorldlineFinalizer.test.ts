import { ethers } from "hardhat";
import { expect } from "chai";
import { loadFixture, time } from "@nomicfoundation/hardhat-toolbox/network-helpers";

const DOMAIN = ethers.keccak256(ethers.toUtf8Bytes("worldline-test-domain"));
const PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("program-vkey"));
const POLICY_HASH = ethers.keccak256(ethers.toUtf8Bytes("policy-hash"));
const PROVER_DIGEST = ethers.keccak256(ethers.toUtf8Bytes("prover-set"));

describe("WorldlineFinalizer", function () {
  async function deployFixture() {
    const [owner, submitter, stranger] = await ethers.getSigners();

    // Deploy the demo Verifier
    const Verifier = await ethers.getContractFactory("Verifier");
    const verifier = await Verifier.deploy();

    // Deploy the Groth16ZkAdapter
    const Adapter = await ethers.getContractFactory("Groth16ZkAdapter");
    const adapter = await Adapter.deploy(
      await verifier.getAddress(),
      PROGRAM_VKEY,
      POLICY_HASH
    );

    // Deploy the Finalizer with 1-hour max acceptance delay
    const Finalizer = await ethers.getContractFactory("WorldlineFinalizer");
    const finalizer = await Finalizer.deploy(
      await adapter.getAddress(),
      DOMAIN,
      3600
    );

    // Grant submitter role
    await finalizer.connect(owner).setSubmitter(submitter.address, true);

    return { finalizer, adapter, verifier, owner, submitter, stranger };
  }

  function encodePublicInputs(
    stfCommitment: string,
    l2Start: bigint,
    l2End: bigint,
    outputRoot: string,
    l1BlockHash: string,
    domainSep: string,
    windowCloseTimestamp: bigint
  ): string {
    return ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256"],
      [stfCommitment, l2Start, l2End, outputRoot, l1BlockHash, domainSep, windowCloseTimestamp]
    );
  }

  function encodeProof(
    stfCommitment: string,
    programVKey: string,
    policyHash: string,
    proverSetDigest: string
  ): string {
    return ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32"],
      [stfCommitment, programVKey, policyHash, proverSetDigest]
    );
  }

  describe("deployment", function () {
    it("sets the adapter", async function () {
      const { finalizer, adapter } = await loadFixture(deployFixture);
      expect(await finalizer.adapter()).to.equal(await adapter.getAddress());
    });

    it("sets the domain separator", async function () {
      const { finalizer } = await loadFixture(deployFixture);
      expect(await finalizer.domainSeparator()).to.equal(DOMAIN);
    });

    it("reverts if deployed with zero adapter", async function () {
      const Finalizer = await ethers.getContractFactory("WorldlineFinalizer");
      await expect(
        Finalizer.deploy(ethers.ZeroAddress, DOMAIN, 3600)
      ).to.be.revertedWithCustomError(Finalizer, "AdapterZero");
    });
  });

  describe("access control", function () {
    it("owner can submit", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      const ts = BigInt(await time.latest()) + 100n;
      const stf = ethers.keccak256(ethers.toUtf8Bytes("stf-1"));
      const proof = encodeProof(stf, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs = encodePublicInputs(stf, 0n, 100n, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, ts);
      await expect(finalizer.connect(owner).submitZkValidityProof(proof, inputs)).to.not.be.reverted;
    });

    it("authorized submitter can submit", async function () {
      const { finalizer, submitter } = await loadFixture(deployFixture);
      const ts = BigInt(await time.latest()) + 100n;
      const stf = ethers.keccak256(ethers.toUtf8Bytes("stf-2"));
      const proof = encodeProof(stf, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs = encodePublicInputs(stf, 0n, 100n, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, ts);
      await expect(finalizer.connect(submitter).submitZkValidityProof(proof, inputs)).to.not.be.reverted;
    });

    it("unauthorized caller cannot submit", async function () {
      const { finalizer, stranger } = await loadFixture(deployFixture);
      const ts = BigInt(await time.latest()) + 100n;
      const stf = ethers.keccak256(ethers.toUtf8Bytes("stf-3"));
      const proof = encodeProof(stf, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs = encodePublicInputs(stf, 0n, 100n, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, ts);
      await expect(
        finalizer.connect(stranger).submitZkValidityProof(proof, inputs)
      ).to.be.revertedWithCustomError(finalizer, "NotAuthorized");
    });

    it("permissionless mode allows anyone", async function () {
      const { finalizer, owner, stranger } = await loadFixture(deployFixture);
      await finalizer.connect(owner).setPermissionless(true);
      const ts = BigInt(await time.latest()) + 100n;
      const stf = ethers.keccak256(ethers.toUtf8Bytes("stf-4"));
      const proof = encodeProof(stf, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs = encodePublicInputs(stf, 0n, 100n, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, ts);
      await expect(finalizer.connect(stranger).submitZkValidityProof(proof, inputs)).to.not.be.reverted;
    });
  });

  describe("paused", function () {
    it("reverts when paused", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      await finalizer.connect(owner).setPaused(true);
      const ts = BigInt(await time.latest()) + 100n;
      const stf = ethers.keccak256(ethers.toUtf8Bytes("stf"));
      const proof = encodeProof(stf, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs = encodePublicInputs(stf, 0n, 100n, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, ts);
      await expect(
        finalizer.connect(owner).submitZkValidityProof(proof, inputs)
      ).to.be.revertedWithCustomError(finalizer, "Paused");
    });
  });

  describe("validation", function () {
    it("reverts on wrong input length", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      const proof = encodeProof(ethers.ZeroHash, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      await expect(
        finalizer.connect(owner).submitZkValidityProof(proof, "0x1234")
      ).to.be.revertedWithCustomError(finalizer, "BadInputsLen");
    });

    it("reverts on domain mismatch", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      const ts = BigInt(await time.latest()) + 100n;
      const stf = ethers.keccak256(ethers.toUtf8Bytes("stf"));
      const wrongDomain = ethers.keccak256(ethers.toUtf8Bytes("wrong-domain"));
      const proof = encodeProof(stf, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs = encodePublicInputs(stf, 0n, 100n, ethers.ZeroHash, ethers.ZeroHash, wrongDomain, ts);
      await expect(
        finalizer.connect(owner).submitZkValidityProof(proof, inputs)
      ).to.be.revertedWithCustomError(finalizer, "DomainMismatch");
    });
  });

  describe("events", function () {
    it("emits OutputProposed and ZkProofAccepted on success", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      const ts = BigInt(await time.latest()) + 100n;
      const stf = ethers.keccak256(ethers.toUtf8Bytes("stf-event"));
      const outputRoot = ethers.keccak256(ethers.toUtf8Bytes("output"));
      const proof = encodeProof(stf, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs = encodePublicInputs(stf, 0n, 50n, outputRoot, ethers.ZeroHash, DOMAIN, ts);

      await expect(finalizer.connect(owner).submitZkValidityProof(proof, inputs))
        .to.emit(finalizer, "OutputProposed")
        .withArgs(0n, outputRoot, 0n, 50n, stf)
        .and.to.emit(finalizer, "ZkProofAccepted")
        .withArgs(0n, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
    });
  });

  describe("contiguity", function () {
    it("enforces contiguous windows", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      const ts = BigInt(await time.latest()) + 200n;

      // Window 0: l2Start=0, l2End=100
      const stf1 = ethers.keccak256(ethers.toUtf8Bytes("stf-c1"));
      const proof1 = encodeProof(stf1, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs1 = encodePublicInputs(stf1, 0n, 100n, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, ts);
      await finalizer.connect(owner).submitZkValidityProof(proof1, inputs1);

      // Window 1: l2Start=100, l2End=200 — should succeed
      const stf2 = ethers.keccak256(ethers.toUtf8Bytes("stf-c2"));
      const proof2 = encodeProof(stf2, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs2 = encodePublicInputs(stf2, 100n, 200n, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, ts);
      await expect(finalizer.connect(owner).submitZkValidityProof(proof2, inputs2)).to.not.be.reverted;

      // Window 2: l2Start=0 — should fail (not contiguous)
      const stf3 = ethers.keccak256(ethers.toUtf8Bytes("stf-c3"));
      const proof3 = encodeProof(stf3, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs3 = encodePublicInputs(stf3, 0n, 300n, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, ts);
      await expect(
        finalizer.connect(owner).submitZkValidityProof(proof3, inputs3)
      ).to.be.revertedWithCustomError(finalizer, "NotContiguous");
    });
  });
});
