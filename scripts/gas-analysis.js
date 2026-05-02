const { ethers } = require("hardhat");

function keyFor(signer, keyId) {
  return {
    keyId,
    keyType: "EcdsaSecp256k1VerificationKey2019",
    controller: signer.address,
    publicKeyHex: "0x1234",
  };
}

function serviceFor(id) {
  return {
    serviceId: id,
    serviceType: "VerifiableCredentialService",
    endpoint: "https://example.com/service",
  };
}

async function gasUsed(txPromise) {
  const tx = await txPromise;
  const receipt = await tx.wait();
  return receipt.gasUsed;
}

function printRow(name, gas) {
  console.log(`${name.padEnd(32)} ${gas.toString()}`);
}

async function main() {
  const [admin, issuer, holder, verifier] = await ethers.getSigners();

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

  const holderDid = `did:ethr:${holder.address}`;
  const issuerDid = `did:ethr:${issuer.address}`;
  const verifierDid = `did:ethr:${verifier.address}`;

  const metrics = {};

  metrics.didRegisterHolder = await gasUsed(
    didRegistry
      .connect(holder)
      .registerDID(holderDid, keyFor(holder, "h-key"), serviceFor("h-svc"))
  );
  metrics.didRegisterIssuer = await gasUsed(
    didRegistry
      .connect(issuer)
      .registerDID(issuerDid, keyFor(issuer, "i-key"), serviceFor("i-svc"))
  );
  metrics.didRegisterVerifier = await gasUsed(
    didRegistry
      .connect(verifier)
      .registerDID(verifierDid, keyFor(verifier, "v-key"), serviceFor("v-svc"))
  );

  metrics.registerHolderRole = await gasUsed(
    accessControl.connect(holder).registerAsHolder(holderDid)
  );
  metrics.registerVerifierRole = await gasUsed(
    accessControl.connect(verifier).registerAsVerifier(verifierDid)
  );
  metrics.authorizeIssuer = await gasUsed(
    accessControl.connect(admin).authorizeIssuer(issuer.address, issuerDid)
  );

  const credentialHash = ethers.keccak256(ethers.toUtf8Bytes("gas-analysis-payload"));
  const issueTx = await credentialStatus
    .connect(issuer)
    .issueCredential(holderDid, credentialHash, "gas-analysis-cid");
  const issueReceipt = await issueTx.wait();
  metrics.issueCredential = issueReceipt.gasUsed;
  const issueEvent = issueReceipt.logs
    .map((log) => {
      try {
        return credentialStatus.interface.parseLog(log);
      } catch {
        return null;
      }
    })
    .find((entry) => entry && entry.name === "CredentialIssued");
  const credentialId = issueEvent.args.credentialId;

  metrics.grantConsent = await gasUsed(
    accessControl.connect(holder).grantConsent(verifierDid, credentialId, 0)
  );
  metrics.logVerification = await gasUsed(
    credentialStatus.connect(verifier).logVerification(credentialId, true)
  );
  metrics.revokeConsent = await gasUsed(
    accessControl.connect(holder).revokeConsent(verifierDid, credentialId)
  );
  metrics.revokeCredential = await gasUsed(
    credentialStatus.connect(issuer).revokeCredential(credentialId)
  );

  console.log("\nGas Usage Report");
  console.log("=".repeat(50));
  printRow("DID register (holder)", metrics.didRegisterHolder);
  printRow("DID register (issuer)", metrics.didRegisterIssuer);
  printRow("DID register (verifier)", metrics.didRegisterVerifier);
  printRow("Register holder role", metrics.registerHolderRole);
  printRow("Register verifier role", metrics.registerVerifierRole);
  printRow("Authorize issuer", metrics.authorizeIssuer);
  printRow("Issue credential", metrics.issueCredential);
  printRow("Grant consent", metrics.grantConsent);
  printRow("Log verification", metrics.logVerification);
  printRow("Revoke consent", metrics.revokeConsent);
  printRow("Revoke credential", metrics.revokeCredential);
  console.log("=".repeat(50));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
