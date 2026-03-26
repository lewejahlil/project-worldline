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
      POLICY_HASH,
      true
    );

    // Deploy the Finalizer with 1-hour max acceptance delay
    const Finalizer = await ethers.getContractFactory("WorldlineFinalizer");
    const finalizer = await Finalizer.deploy(await adapter.getAddress(), DOMAIN, 3600);

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

    it("reverts if deployed with zero maxAcceptanceDelay", async function () {
      const { adapter } = await loadFixture(deployFixture);
      const Finalizer = await ethers.getContractFactory("WorldlineFinalizer");
      await expect(
        Finalizer.deploy(await adapter.getAddress(), DOMAIN, 0)
      ).to.be.revertedWithCustomError(Finalizer, "MaxAcceptanceDelayZero");
    });
  });

  describe("access control", function () {
    it("owner can submit", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      const ts = BigInt(await time.latest()) + 100n;
      const stf = ethers.keccak256(ethers.toUtf8Bytes("stf-1"));
      const proof = encodeProof(stf, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs = encodePublicInputs(
        stf,
        0n,
        100n,
        ethers.ZeroHash,
        ethers.ZeroHash,
        DOMAIN,
        ts
      );
      await expect(finalizer.connect(owner).submitZkValidityProof(proof, inputs)).to.not.be
        .reverted;
    });

    it("authorized submitter can submit", async function () {
      const { finalizer, submitter } = await loadFixture(deployFixture);
      const ts = BigInt(await time.latest()) + 100n;
      const stf = ethers.keccak256(ethers.toUtf8Bytes("stf-2"));
      const proof = encodeProof(stf, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs = encodePublicInputs(
        stf,
        0n,
        100n,
        ethers.ZeroHash,
        ethers.ZeroHash,
        DOMAIN,
        ts
      );
      await expect(finalizer.connect(submitter).submitZkValidityProof(proof, inputs)).to.not.be
        .reverted;
    });

    it("unauthorized caller cannot submit", async function () {
      const { finalizer, stranger } = await loadFixture(deployFixture);
      const ts = BigInt(await time.latest()) + 100n;
      const stf = ethers.keccak256(ethers.toUtf8Bytes("stf-3"));
      const proof = encodeProof(stf, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs = encodePublicInputs(
        stf,
        0n,
        100n,
        ethers.ZeroHash,
        ethers.ZeroHash,
        DOMAIN,
        ts
      );
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
      const inputs = encodePublicInputs(
        stf,
        0n,
        100n,
        ethers.ZeroHash,
        ethers.ZeroHash,
        DOMAIN,
        ts
      );
      await expect(finalizer.connect(stranger).submitZkValidityProof(proof, inputs)).to.not.be
        .reverted;
    });
  });

  describe("paused", function () {
    it("reverts when paused", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      await finalizer.connect(owner).setPaused(true);
      const ts = BigInt(await time.latest()) + 100n;
      const stf = ethers.keccak256(ethers.toUtf8Bytes("stf"));
      const proof = encodeProof(stf, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs = encodePublicInputs(
        stf,
        0n,
        100n,
        ethers.ZeroHash,
        ethers.ZeroHash,
        DOMAIN,
        ts
      );
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
      const inputs = encodePublicInputs(
        stf,
        0n,
        100n,
        ethers.ZeroHash,
        ethers.ZeroHash,
        wrongDomain,
        ts
      );
      await expect(
        finalizer.connect(owner).submitZkValidityProof(proof, inputs)
      ).to.be.revertedWithCustomError(finalizer, "DomainMismatch");
    });

    it("reverts when l2End <= l2Start", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      const ts = BigInt(await time.latest()) + 100n;
      const stf = ethers.keccak256(ethers.toUtf8Bytes("stf-range"));
      const proof = encodeProof(stf, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      // l2End=50 < l2Start=100
      const inputs = encodePublicInputs(
        stf,
        100n,
        50n,
        ethers.ZeroHash,
        ethers.ZeroHash,
        DOMAIN,
        ts
      );
      await expect(
        finalizer.connect(owner).submitZkValidityProof(proof, inputs)
      ).to.be.revertedWithCustomError(finalizer, "InvalidWindowRange");
    });

    it("reverts when l2End == l2Start (empty window)", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      const ts = BigInt(await time.latest()) + 100n;
      const stf = ethers.keccak256(ethers.toUtf8Bytes("stf-empty"));
      const proof = encodeProof(stf, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs = encodePublicInputs(
        stf,
        100n,
        100n,
        ethers.ZeroHash,
        ethers.ZeroHash,
        DOMAIN,
        ts
      );
      await expect(
        finalizer.connect(owner).submitZkValidityProof(proof, inputs)
      ).to.be.revertedWithCustomError(finalizer, "InvalidWindowRange");
    });

    it("reverts when proof is too old (TooOld)", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      // Use a windowCloseTimestamp far in the past
      const ts = BigInt(await time.latest()) - 7200n;
      const stf = ethers.keccak256(ethers.toUtf8Bytes("stf-old"));
      const proof = encodeProof(stf, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs = encodePublicInputs(
        stf,
        0n,
        100n,
        ethers.ZeroHash,
        ethers.ZeroHash,
        DOMAIN,
        ts
      );
      await expect(
        finalizer.connect(owner).submitZkValidityProof(proof, inputs)
      ).to.be.revertedWithCustomError(finalizer, "TooOld");
    });

    it("reverts when metaLocator exceeds 96 bytes", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      const ts = BigInt(await time.latest()) + 100n;
      const stf = ethers.keccak256(ethers.toUtf8Bytes("stf-meta"));
      const proof = encodeProof(stf, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs = encodePublicInputs(
        stf,
        0n,
        100n,
        ethers.ZeroHash,
        ethers.ZeroHash,
        DOMAIN,
        ts
      );
      const longLocator = "0x" + "ff".repeat(97); // 97 bytes > 96
      await expect(
        finalizer.connect(owner).submitZkValidityProofWithMeta(proof, inputs, longLocator)
      ).to.be.revertedWithCustomError(finalizer, "LocatorTooLong");
    });
  });

  describe("admin events", function () {
    it("setPaused emits PausedSet", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      await expect(finalizer.connect(owner).setPaused(true))
        .to.emit(finalizer, "PausedSet")
        .withArgs(true);
    });

    it("setPermissionless emits PermissionlessSet", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      await expect(finalizer.connect(owner).setPermissionless(true))
        .to.emit(finalizer, "PermissionlessSet")
        .withArgs(true);
    });

    it("setSubmitter emits SubmitterSet", async function () {
      const { finalizer, owner, stranger } = await loadFixture(deployFixture);
      await expect(finalizer.connect(owner).setSubmitter(stranger.address, true))
        .to.emit(finalizer, "SubmitterSet")
        .withArgs(stranger.address, true);
    });

    it("setMaxAcceptanceDelay emits MaxAcceptanceDelaySet", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      await expect(finalizer.connect(owner).setMaxAcceptanceDelay(7200))
        .to.emit(finalizer, "MaxAcceptanceDelaySet")
        .withArgs(7200);
    });

    it("setMaxAcceptanceDelay reverts on zero", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      await expect(finalizer.connect(owner).setMaxAcceptanceDelay(0)).to.be.revertedWithCustomError(
        finalizer,
        "MaxAcceptanceDelayZero"
      );
    });

    it("scheduleAdapterChange + activateAdapterChange emits AdapterSet", async function () {
      const { finalizer, owner, verifier } = await loadFixture(deployFixture);
      const Adapter = await ethers.getContractFactory("Groth16ZkAdapter");
      const adapter2 = await Adapter.deploy(
        await verifier.getAddress(),
        PROGRAM_VKEY,
        POLICY_HASH,
        true
      );
      await expect(finalizer.connect(owner).scheduleAdapterChange(await adapter2.getAddress()))
        .to.emit(finalizer, "AdapterChangeScheduled");
      // Fast-forward past adapter change delay (1 day)
      await time.increase(86401);
      await expect(finalizer.connect(owner).activateAdapterChange())
        .to.emit(finalizer, "AdapterSet")
        .withArgs(await adapter2.getAddress());
    });

    it("scheduleAdapterChange reverts on zero address", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      await expect(
        finalizer.connect(owner).scheduleAdapterChange(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(finalizer, "AdapterZero");
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

  describe("duplicate window", function () {
    it("second proof for the same window index reverts (NotContiguous)", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      const ts = BigInt(await time.latest()) + 200n;

      // Window 0: l2Start=0, l2End=100
      const stf1 = ethers.keccak256(ethers.toUtf8Bytes("stf-dup1"));
      const proof1 = encodeProof(stf1, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs1 = encodePublicInputs(
        stf1,
        0n,
        100n,
        ethers.ZeroHash,
        ethers.ZeroHash,
        DOMAIN,
        ts
      );
      await finalizer.connect(owner).submitZkValidityProof(proof1, inputs1);

      // Attempt window 0 again: l2Start=0, l2End=100.
      // nextWindowIndex is now 1 and lastL2EndBlock is 100, so l2Start=0 != 100 → NotContiguous.
      const stf2 = ethers.keccak256(ethers.toUtf8Bytes("stf-dup2"));
      const proof2 = encodeProof(stf2, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs2 = encodePublicInputs(
        stf2,
        0n,
        100n,
        ethers.ZeroHash,
        ethers.ZeroHash,
        DOMAIN,
        ts
      );
      await expect(
        finalizer.connect(owner).submitZkValidityProof(proof2, inputs2)
      ).to.be.revertedWithCustomError(finalizer, "NotContiguous");
    });
  });

  describe("StfMismatch", function () {
    it("reverts when adapter stfCommitment differs from publicInputs stfCommitment", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      const ts = BigInt(await time.latest()) + 200n;

      // publicInputs encodes stfCommitment = "stf-correct"
      const stfCorrect = ethers.keccak256(ethers.toUtf8Bytes("stf-correct"));
      // proof encodes stfCommitment = "stf-wrong" (adapter will return this)
      const stfWrong = ethers.keccak256(ethers.toUtf8Bytes("stf-wrong"));

      const proof = encodeProof(stfWrong, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs = encodePublicInputs(
        stfCorrect,
        0n,
        100n,
        ethers.ZeroHash,
        ethers.ZeroHash,
        DOMAIN,
        ts
      );

      await expect(
        finalizer.connect(owner).submitZkValidityProof(proof, inputs)
      ).to.be.revertedWithCustomError(finalizer, "StfMismatch");
    });
  });

  describe("contiguity", function () {
    it("enforces contiguous windows", async function () {
      const { finalizer, owner } = await loadFixture(deployFixture);
      const ts = BigInt(await time.latest()) + 200n;

      // Window 0: l2Start=0, l2End=100
      const stf1 = ethers.keccak256(ethers.toUtf8Bytes("stf-c1"));
      const proof1 = encodeProof(stf1, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs1 = encodePublicInputs(
        stf1,
        0n,
        100n,
        ethers.ZeroHash,
        ethers.ZeroHash,
        DOMAIN,
        ts
      );
      await finalizer.connect(owner).submitZkValidityProof(proof1, inputs1);

      // Window 1: l2Start=100, l2End=200 — should succeed
      const stf2 = ethers.keccak256(ethers.toUtf8Bytes("stf-c2"));
      const proof2 = encodeProof(stf2, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs2 = encodePublicInputs(
        stf2,
        100n,
        200n,
        ethers.ZeroHash,
        ethers.ZeroHash,
        DOMAIN,
        ts
      );
      await expect(finalizer.connect(owner).submitZkValidityProof(proof2, inputs2)).to.not.be
        .reverted;

      // Window 2: l2Start=0 — should fail (not contiguous)
      const stf3 = ethers.keccak256(ethers.toUtf8Bytes("stf-c3"));
      const proof3 = encodeProof(stf3, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
      const inputs3 = encodePublicInputs(
        stf3,
        0n,
        300n,
        ethers.ZeroHash,
        ethers.ZeroHash,
        DOMAIN,
        ts
      );
      await expect(
        finalizer.connect(owner).submitZkValidityProof(proof3, inputs3)
      ).to.be.revertedWithCustomError(finalizer, "NotContiguous");
    });
  });
});
