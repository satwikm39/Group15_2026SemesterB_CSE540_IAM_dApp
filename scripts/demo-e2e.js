const { ethers } = require("hardhat");
const { saveCredential, getCredential, canonicalize } = require("./offchainStore");

async function deployAll() {
  const DIDRegistry = await ethers.getContractFactory("DIDRegistry");
  const didRegistry = await DIDRegistry.deploy();
  await didRegistry.waitForDeployment();

  const CredentialStatus = await ethers.getContractFactory("CredentialStatus");
  const credentialStatus = await CredentialStatus.deploy();
  await credentialStatus.waitForDeployment();

  const AccessControl = await ethers.getContractFactory("AccessControl");
  const accessControl = await AccessControl.deploy(
    await didRegistry.getAddress(),
    await credentialStatus.getAddress()
  );
  await accessControl.waitForDeployment();

  return { didRegistry, credentialStatus, accessControl };
}

function makeKey(signer, keyId) {
  return {
    keyId,
    keyType: "EcdsaSecp256k1VerificationKey2019",
    controller: signer.address,
    publicKeyHex: "0x1234",
  };
}

async function registerBaseDIDs(didRegistry, holder, issuer, verifier) {
  const holderDid = `did:ethr:${holder.address}`;
  const issuerDid = `did:ethr:${issuer.address}`;
  const verifierDid = `did:ethr:${verifier.address}`;

  const service = (id) => ({
    serviceId: id,
    serviceType: "VerifiableCredentialService",
    endpoint: "https://example.com/agent",
  });

  await didRegistry
    .connect(holder)
    .registerDID(holderDid, makeKey(holder, "holder-key-1"), service("holder-service"));
  await didRegistry
    .connect(issuer)
    .registerDID(issuerDid, makeKey(issuer, "issuer-key-1"), service("issuer-service"));
  await didRegistry
    .connect(verifier)
    .registerDID(verifierDid, makeKey(verifier, "verifier-key-1"), service("verifier-service"));

  return { holderDid, issuerDid, verifierDid };
}

async function main() {
  const [admin, issuer, holder, verifier] = await ethers.getSigners();
  console.log("Running IAM E2E demo with accounts:");
  console.log("- admin:", admin.address);
  console.log("- issuer:", issuer.address);
  console.log("- holder:", holder.address);
  console.log("- verifier:", verifier.address);

  const { didRegistry, credentialStatus, accessControl } = await deployAll();
  console.log("\nContracts deployed:");
  console.log("- DIDRegistry:", await didRegistry.getAddress());
  console.log("- CredentialStatus:", await credentialStatus.getAddress());
  console.log("- AccessControl:", await accessControl.getAddress());

  const { holderDid, issuerDid, verifierDid } = await registerBaseDIDs(
    didRegistry,
    holder,
    issuer,
    verifier
  );

  await accessControl.connect(holder).registerAsHolder(holderDid);
  await accessControl.connect(verifier).registerAsVerifier(verifierDid);
  await accessControl.connect(admin).authorizeIssuer(issuer.address, issuerDid);
  console.log("\nStakeholders registered and issuer authorized.");

  const vcPayload = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: ["VerifiableCredential", "IdentityAccessCredential"],
    issuer: issuerDid,
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: holderDid,
      department: "Engineering",
      accessLevel: "L2",
      active: true,
    },
  };

  const { cid, canonicalPayload } = await saveCredential(vcPayload);
  const credentialHash = ethers.keccak256(ethers.toUtf8Bytes(canonicalPayload));
  console.log("\nCredential stored in encrypted off-chain DB.");
  console.log("- CID:", cid);
  console.log("- Hash:", credentialHash);

  const issueTx = await credentialStatus
    .connect(issuer)
    .issueCredential(holderDid, credentialHash, cid);
  const issueReceipt = await issueTx.wait();
  const issuedEvent = issueReceipt.logs
    .map((log) => {
      try {
        return credentialStatus.interface.parseLog(log);
      } catch {
        return null;
      }
    })
    .find((entry) => entry && entry.name === "CredentialIssued");
  const credentialId = issuedEvent.args.credentialId;
  console.log("- Credential ID:", credentialId);

  await accessControl.connect(holder).grantConsent(verifierDid, credentialId, 0);
  console.log("\nHolder granted consent to verifier.");

  const fetchedCredential = await getCredential(cid);
  const fetchedHash = ethers.keccak256(
    ethers.toUtf8Bytes(canonicalize(fetchedCredential))
  );
  const integrityOk = await credentialStatus.verifyCredentialIntegrity(
    credentialId,
    fetchedHash
  );
  const revoked = await credentialStatus.isRevoked(credentialId);
  const hasConsent = await accessControl.hasConsent(
    holderDid,
    verifierDid,
    credentialId
  );
  const verified = integrityOk && !revoked && hasConsent;

  await credentialStatus.connect(verifier).logVerification(credentialId, verified);
  console.log("\nVerification result logged on-chain:", verified);

  await accessControl.connect(holder).revokeConsent(verifierDid, credentialId);
  const consentAfterRevoke = await accessControl.hasConsent(
    holderDid,
    verifierDid,
    credentialId
  );
  console.log("Consent after revoke:", consentAfterRevoke);

  await credentialStatus.connect(issuer).revokeCredential(credentialId);
  const revokedAfterIssuerAction = await credentialStatus.isRevoked(credentialId);
  console.log("Revoked after issuer action:", revokedAfterIssuerAction);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
