/**
 * iam.test.js - Unit Test Scaffold for IAM dApp Smart Contracts
 *
 * Test coverage plan:
 *  - DIDRegistry:       registerDID, addPublicKey, addServiceEndpoint, deactivateDID, resolveDID
 *  - CredentialStatus:  issueCredential, revokeCredential, isRevoked, verifyCredentialIntegrity
 *  - AccessControl:     registerAsHolder, registerAsVerifier, authorizeIssuer, grantConsent, revokeConsent
 *
 * NOTE: Test implementations are stubs at this stage (Smart Contract Design Draft).
 *       Full test logic will be implemented in the Midterm Progress Update phase.
 */

const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("IAM dApp - Smart Contract Test Suite", function () {
  let didRegistry, credentialStatus, accessControl;
  let admin, issuer, holder, verifier;

  // Shared test DID strings
  const HOLDER_DID = "did:ethr:0xHolder";
  const ISSUER_DID = "did:ethr:0xIssuer";
  const VERIFIER_DID = "did:ethr:0xVerifier";

  // Deploy all contracts before each test group
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
      // TODO: Call didRegistry.registerDID() with valid args
      // TODO: Expect DIDRegistered event to be emitted
      // TODO: Expect resolveDID() to return the correct controller address
    });

    it("Should revert when registering a duplicate DID", async function () {
      // TODO: Register a DID once, then attempt again with the same DID
      // TODO: Expect revert with appropriate error message
    });

    it("Should allow the controller to add a public key", async function () {
      // TODO: Register a DID, then call addPublicKey()
      // TODO: Expect DIDUpdated event
    });

    it("Should revert when a non-controller attempts to update the DID", async function () {
      // TODO: Register a DID as `holder`, then attempt addPublicKey() as `verifier`
      // TODO: Expect revert with "Caller is not controller"
    });

    it("Should allow the controller to deactivate a DID", async function () {
      // TODO: Register and then deactivate a DID
      // TODO: Expect isDIDActive() to return false
    });
  });

  // ---------------------------------------------------------------------------
  // CredentialStatus Tests
  // ---------------------------------------------------------------------------
  describe("CredentialStatus", function () {

    it("Should allow an issuer to anchor a credential on-chain", async function () {
      // TODO: Call credentialStatus.issueCredential() with a mock hash and IPFS CID
      // TODO: Expect CredentialIssued event
      // TODO: Expect getCredentialAnchor() to return the correct data
    });

    it("Should correctly report a credential as not revoked after issuance", async function () {
      // TODO: Issue a credential and call isRevoked()
      // TODO: Expect false
    });

    it("Should allow the issuer to revoke a credential", async function () {
      // TODO: Issue then revoke a credential
      // TODO: Expect CredentialRevoked event
      // TODO: Expect isRevoked() to return true
    });

    it("Should revert revocation by a non-issuer", async function () {
      // TODO: Issue a credential as `issuer`, then attempt revoke as `holder`
      // TODO: Expect revert
    });

    it("Should verify credential integrity against the on-chain hash", async function () {
      // TODO: Issue credential with a known hash
      // TODO: Call verifyCredentialIntegrity() with the same hash — expect true
      // TODO: Call with a tampered hash — expect false
    });
  });

  // ---------------------------------------------------------------------------
  // AccessControl Tests
  // ---------------------------------------------------------------------------
  describe("AccessControl", function () {

    it("Should allow a DID holder to self-register as HOLDER role", async function () {
      // TODO: Register a DID in DIDRegistry for `holder`
      // TODO: Call accessControl.registerAsHolder()
      // TODO: Expect getRole(holder.address) to return Role.HOLDER
    });

    it("Should allow an admin to authorize an ISSUER", async function () {
      // TODO: Register a DID for `issuer`
      // TODO: Call authorizeIssuer() as `admin`
      // TODO: Expect getRole(issuer.address) to return Role.ISSUER
    });

    it("Should revert when a non-admin tries to authorize an issuer", async function () {
      // TODO: Attempt authorizeIssuer() as `holder` (non-admin)
      // TODO: Expect revert with "Caller is not an admin"
    });

    it("Should allow a holder to grant and revoke consent to a verifier", async function () {
      // TODO: Register Holder and Verifier
      // TODO: Issue a credential and get credentialId
      // TODO: Call grantConsent() — expect hasConsent() to return true
      // TODO: Call revokeConsent() — expect hasConsent() to return false
    });
  });

  // ---------------------------------------------------------------------------
  // Demo: register DID → issue credential → verify integrity → log on-chain
  // ---------------------------------------------------------------------------
  describe("Demo E2E (identity → credential → verification)", function () {
    it("registers DID, issues credential, checks not revoked, verifies hash, logs VerificationLogged", async function () {
      const holderPk = {
        keyId: "key-1",
        keyType: "EcdsaSecp256k1VerificationKey2019",
        controller: holder.address,
        publicKeyHex: "0x",
      };
      const emptyService = { serviceId: "", serviceType: "", endpoint: "" };

      await expect(
        didRegistry.connect(holder).registerDID(HOLDER_DID, holderPk, emptyService)
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
