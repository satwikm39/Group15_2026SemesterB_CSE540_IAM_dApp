const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("IAM dApp - Smart Contract Test Suite", function () {
  let didRegistry, credentialStatus, accessControl;
  let admin, issuer, holder, verifier;

  const HOLDER_DID = "did:ethr:0xHolder";
  const ISSUER_DID = "did:ethr:0xIssuer";
  const VERIFIER_DID = "did:ethr:0xVerifier";

  const ROLE = {
    NONE: 0n,
    HOLDER: 1n,
    ISSUER: 2n,
    VERIFIER: 3n,
  };

  function buildKey(account, keyId = "key-1") {
    return {
      keyId,
      keyType: "EcdsaSecp256k1VerificationKey2019",
      controller: account.address,
      publicKeyHex: "0x1234",
    };
  }

  function buildService(serviceId = "svc-1") {
    return {
      serviceId,
      serviceType: "VerifiableCredentialService",
      endpoint: "https://example.com/service",
    };
  }

  async function registerDIDAs(signer, did) {
    await didRegistry
      .connect(signer)
      .registerDID(did, buildKey(signer), buildService(`${did}-svc`));
  }

  async function issueCredentialAsIssuer(subjectDID, payload = "demo-verifiable-credential-payload") {
    const credentialHash = ethers.keccak256(ethers.toUtf8Bytes(payload));
    const ipfsCID = "QmDemoCredentialCID";
    const tx = await credentialStatus
      .connect(issuer)
      .issueCredential(subjectDID, credentialHash, ipfsCID);
    const receipt = await tx.wait();
    const issued = receipt.logs
      .map((log) => {
        try {
          return credentialStatus.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((entry) => entry && entry.name === "CredentialIssued");

    return {
      credentialId: issued.args.credentialId,
      credentialHash,
      ipfsCID,
    };
  }

  beforeEach(async function () {
    [admin, issuer, holder, verifier] = await ethers.getSigners();

    const DIDRegistry = await ethers.getContractFactory("DIDRegistry");
    didRegistry = await DIDRegistry.deploy();

    const CredentialStatus = await ethers.getContractFactory("CredentialStatus");
    credentialStatus = await CredentialStatus.deploy();

    const AccessControl = await ethers.getContractFactory("AccessControl");
    accessControl = await AccessControl.deploy(
      await didRegistry.getAddress(),
      await credentialStatus.getAddress()
    );
  });

  // ---------------------------------------------------------------------------
  // DIDRegistry Tests
  // ---------------------------------------------------------------------------
  describe("DIDRegistry", function () {
    it("Should allow a user to register a new DID", async function () {
      await expect(
        didRegistry.connect(holder).registerDID(HOLDER_DID, buildKey(holder), buildService())
      ).to.emit(didRegistry, "DIDRegistered");

      const doc = await didRegistry.resolveDID(HOLDER_DID);
      expect(doc.controller).to.equal(holder.address);
      expect(doc.active).to.equal(true);
      expect(doc.publicKeys.length).to.equal(1);
      expect(doc.serviceEndpoints.length).to.equal(1);
    });

    it("Should revert when registering a duplicate DID", async function () {
      await registerDIDAs(holder, HOLDER_DID);
      await expect(
        didRegistry.connect(holder).registerDID(HOLDER_DID, buildKey(holder), buildService("svc-2"))
      ).to.be.revertedWith("DIDRegistry: DID already registered");
    });

    it("Should allow the controller to add a public key", async function () {
      await registerDIDAs(holder, HOLDER_DID);
      await expect(
        didRegistry.connect(holder).addPublicKey(HOLDER_DID, buildKey(holder, "key-2"))
      ).to.emit(didRegistry, "DIDUpdated");

      const doc = await didRegistry.resolveDID(HOLDER_DID);
      expect(doc.publicKeys.length).to.equal(2);
      expect(doc.publicKeys[1].keyId).to.equal("key-2");
    });

    it("Should revert when a non-controller attempts to update the DID", async function () {
      await registerDIDAs(holder, HOLDER_DID);
      await expect(
        didRegistry.connect(verifier).addPublicKey(HOLDER_DID, buildKey(verifier, "key-2"))
      ).to.be.revertedWith("DIDRegistry: Caller is not controller");
    });

    it("Should allow the controller to add a service endpoint", async function () {
      await registerDIDAs(holder, HOLDER_DID);
      await expect(
        didRegistry
          .connect(holder)
          .addServiceEndpoint(HOLDER_DID, buildService("svc-2"))
      ).to.emit(didRegistry, "DIDUpdated");

      const doc = await didRegistry.resolveDID(HOLDER_DID);
      expect(doc.serviceEndpoints.length).to.equal(2);
      expect(doc.serviceEndpoints[1].serviceId).to.equal("svc-2");
    });

    it("Should allow the controller to deactivate a DID", async function () {
      await registerDIDAs(holder, HOLDER_DID);
      await expect(didRegistry.connect(holder).deactivateDID(HOLDER_DID))
        .to.emit(didRegistry, "DIDDeactivated");
      expect(await didRegistry.isDIDActive(HOLDER_DID)).to.equal(false);
    });
  });

  // ---------------------------------------------------------------------------
  // CredentialStatus Tests
  // ---------------------------------------------------------------------------
  describe("CredentialStatus", function () {
    it("Should allow an issuer to anchor a credential on-chain", async function () {
      const credentialHash = ethers.keccak256(ethers.toUtf8Bytes("credential-1"));
      const ipfsCID = "QmAnchorCredential";
      const tx = await credentialStatus
        .connect(issuer)
        .issueCredential(HOLDER_DID, credentialHash, ipfsCID);

      await expect(tx).to.emit(credentialStatus, "CredentialIssued");

      const receipt = await tx.wait();
      const issued = receipt.logs
        .map((log) => {
          try {
            return credentialStatus.interface.parseLog(log);
          } catch {
            return null;
          }
        })
        .find((entry) => entry && entry.name === "CredentialIssued");

      const credentialId = issued.args.credentialId;
      const anchor = await credentialStatus.getCredentialAnchor(credentialId);
      expect(anchor.issuer).to.equal(issuer.address);
      expect(anchor.subjectDID).to.equal(HOLDER_DID);
      expect(anchor.credentialHash).to.equal(credentialHash);
      expect(anchor.ipfsCID).to.equal(ipfsCID);
    });

    it("Should correctly report a credential as not revoked after issuance", async function () {
      const { credentialId } = await issueCredentialAsIssuer(HOLDER_DID);
      expect(await credentialStatus.isRevoked(credentialId)).to.equal(false);
    });

    it("Should allow the issuer to revoke a credential", async function () {
      const { credentialId } = await issueCredentialAsIssuer(HOLDER_DID);
      await expect(credentialStatus.connect(issuer).revokeCredential(credentialId))
        .to.emit(credentialStatus, "CredentialRevoked");
      expect(await credentialStatus.isRevoked(credentialId)).to.equal(true);
    });

    it("Should revert revocation by a non-issuer", async function () {
      const { credentialId } = await issueCredentialAsIssuer(HOLDER_DID);
      await expect(
        credentialStatus.connect(holder).revokeCredential(credentialId)
      ).to.be.revertedWith("CredentialStatus: Caller is not the issuer");
    });

    it("Should verify credential integrity against the on-chain hash", async function () {
      const { credentialId, credentialHash } = await issueCredentialAsIssuer(HOLDER_DID, "integrity-payload");
      const tamperedHash = ethers.keccak256(ethers.toUtf8Bytes("tampered"));

      expect(
        await credentialStatus.verifyCredentialIntegrity(credentialId, credentialHash)
      ).to.equal(true);
      expect(
        await credentialStatus.verifyCredentialIntegrity(credentialId, tamperedHash)
      ).to.equal(false);
    });
  });

  // ---------------------------------------------------------------------------
  // AccessControl Tests
  // ---------------------------------------------------------------------------
  describe("AccessControl", function () {
    it("Should allow a DID holder to self-register as HOLDER role", async function () {
      await registerDIDAs(holder, HOLDER_DID);
      await expect(accessControl.connect(holder).registerAsHolder(HOLDER_DID))
        .to.emit(accessControl, "StakeholderRegistered");
      expect(await accessControl.getRole(holder.address)).to.equal(ROLE.HOLDER);
    });

    it("Should allow an admin to authorize an ISSUER", async function () {
      await registerDIDAs(issuer, ISSUER_DID);
      await expect(accessControl.connect(admin).authorizeIssuer(issuer.address, ISSUER_DID))
        .to.emit(accessControl, "IssuerAuthorized");
      expect(await accessControl.getRole(issuer.address)).to.equal(ROLE.ISSUER);
    });

    it("Should revert when a non-admin tries to authorize an issuer", async function () {
      await registerDIDAs(issuer, ISSUER_DID);
      await expect(
        accessControl.connect(holder).authorizeIssuer(issuer.address, ISSUER_DID)
      ).to.be.revertedWith("AccessControl: Caller is not an admin");
    });

    it("Should allow a holder to grant and revoke consent to a verifier", async function () {
      await registerDIDAs(holder, HOLDER_DID);
      await registerDIDAs(verifier, VERIFIER_DID);
      await accessControl.connect(holder).registerAsHolder(HOLDER_DID);
      await accessControl.connect(verifier).registerAsVerifier(VERIFIER_DID);
      const { credentialId } = await issueCredentialAsIssuer(HOLDER_DID, "consent-flow");

      await expect(
        accessControl.connect(holder).grantConsent(VERIFIER_DID, credentialId, 0)
      ).to.emit(accessControl, "ConsentGranted");

      expect(
        await accessControl.hasConsent(HOLDER_DID, VERIFIER_DID, credentialId)
      ).to.equal(true);

      await expect(
        accessControl.connect(holder).revokeConsent(VERIFIER_DID, credentialId)
      ).to.emit(accessControl, "ConsentRevoked");

      expect(
        await accessControl.hasConsent(HOLDER_DID, VERIFIER_DID, credentialId)
      ).to.equal(false);
    });

    it("Should return false for consent once the credential is revoked", async function () {
      await registerDIDAs(holder, HOLDER_DID);
      await registerDIDAs(verifier, VERIFIER_DID);
      await accessControl.connect(holder).registerAsHolder(HOLDER_DID);
      await accessControl.connect(verifier).registerAsVerifier(VERIFIER_DID);
      const { credentialId } = await issueCredentialAsIssuer(HOLDER_DID, "revocation-consent");

      await accessControl.connect(holder).grantConsent(VERIFIER_DID, credentialId, 0);
      expect(await accessControl.hasConsent(HOLDER_DID, VERIFIER_DID, credentialId)).to.equal(true);

      await credentialStatus.connect(issuer).revokeCredential(credentialId);
      expect(await accessControl.hasConsent(HOLDER_DID, VERIFIER_DID, credentialId)).to.equal(false);
    });
  });

  // ---------------------------------------------------------------------------
  // Demo: register DID → issue credential → verify integrity → log on-chain
  // ---------------------------------------------------------------------------
  describe("Demo E2E (identity → credential → verification)", function () {
    it("registers DID, issues credential, checks not revoked, verifies hash, logs VerificationLogged", async function () {
      await expect(
        didRegistry.connect(holder).registerDID(HOLDER_DID, buildKey(holder), buildService("holder-svc"))
      ).to.emit(didRegistry, "DIDRegistered");

      const doc = await didRegistry.resolveDID(HOLDER_DID);
      expect(doc.controller).to.equal(holder.address);
      expect(doc.active).to.be.true;

      const vcPayload = "demo-verifiable-credential-payload";
      const credentialHash = ethers.keccak256(ethers.toUtf8Bytes(vcPayload));
      const ipfsCID = "QmDemoPlaceholder";

      const issueTx = await credentialStatus
        .connect(issuer)
        .issueCredential(HOLDER_DID, credentialHash, ipfsCID);
      const issueReceipt = await issueTx.wait();
      const issued = issueReceipt.logs
        .map((log) => {
          try {
            return credentialStatus.interface.parseLog(log);
          } catch {
            return null;
          }
        })
        .find((p) => p && p.name === "CredentialIssued");
      expect(issued).to.not.equal(undefined);
      const credentialId = issued.args.credentialId;

      expect(await credentialStatus.isRevoked(credentialId)).to.equal(false);
      expect(await credentialStatus.verifyCredentialIntegrity(credentialId, credentialHash)).to.equal(true);

      await expect(credentialStatus.connect(verifier).logVerification(credentialId, true))
        .to.emit(credentialStatus, "VerificationLogged");
    });
  });
});
