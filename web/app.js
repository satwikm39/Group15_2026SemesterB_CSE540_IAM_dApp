/* global ethers, IAM_ABIS */

const state = {
  provider: null,
  signer: null,
  address: "",
  contracts: {},
};

const el = {
  walletStatus: document.getElementById("walletStatus"),
  logOutput: document.getElementById("logOutput"),
  didRegistryAddress: document.getElementById("didRegistryAddress"),
  credentialStatusAddress: document.getElementById("credentialStatusAddress"),
  accessControlAddress: document.getElementById("accessControlAddress"),
  didInput: document.getElementById("didInput"),
  keyIdInput: document.getElementById("keyIdInput"),
  publicKeyHexInput: document.getElementById("publicKeyHexInput"),
  serviceIdInput: document.getElementById("serviceIdInput"),
  serviceTypeInput: document.getElementById("serviceTypeInput"),
  serviceEndpointInput: document.getElementById("serviceEndpointInput"),
  issuerAddressInput: document.getElementById("issuerAddressInput"),
  verifierDidInput: document.getElementById("verifierDidInput"),
  holderDidInput: document.getElementById("holderDidInput"),
  consentExpiryInput: document.getElementById("consentExpiryInput"),
  credentialIdInput: document.getElementById("credentialIdInput"),
  subjectDidInput: document.getElementById("subjectDidInput"),
  credentialPayloadInput: document.getElementById("credentialPayloadInput"),
  cidInput: document.getElementById("cidInput"),
  computedHashInput: document.getElementById("computedHashInput"),
};

function appendLog(message) {
  const line = `[${new Date().toLocaleTimeString()}] ${message}`;
  el.logOutput.textContent = `${line}\n${el.logOutput.textContent}`;
}

function normalizeJson(obj) {
  if (Array.isArray(obj)) {
    return `[${obj.map(normalizeJson).join(",")}]`;
  }
  if (obj && typeof obj === "object") {
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${normalizeJson(obj[k])}`).join(",")}}`;
  }
  return JSON.stringify(obj);
}

function requireSigner() {
  if (!state.signer) {
    throw new Error("Connect wallet first.");
  }
}

function requireContracts() {
  const { didRegistry, credentialStatus, accessControl } = state.contracts;
  if (!didRegistry || !credentialStatus || !accessControl) {
    throw new Error("Bind contract addresses first.");
  }
}

async function connectWallet() {
  if (!window.ethereum) {
    throw new Error("MetaMask is required.");
  }

  state.provider = new ethers.BrowserProvider(window.ethereum);
  await state.provider.send("eth_requestAccounts", []);
  state.signer = await state.provider.getSigner();
  state.address = await state.signer.getAddress();
  const network = await state.provider.getNetwork();
  el.walletStatus.textContent = `Wallet: ${state.address} | chainId=${network.chainId}`;
  appendLog("Wallet connected.");
}

function bindContracts() {
  requireSigner();
  state.contracts.didRegistry = new ethers.Contract(
    el.didRegistryAddress.value.trim(),
    IAM_ABIS.DIDRegistry,
    state.signer
  );
  state.contracts.credentialStatus = new ethers.Contract(
    el.credentialStatusAddress.value.trim(),
    IAM_ABIS.CredentialStatus,
    state.signer
  );
  state.contracts.accessControl = new ethers.Contract(
    el.accessControlAddress.value.trim(),
    IAM_ABIS.AccessControl,
    state.signer
  );
  appendLog("Contracts bound.");
}

async function loadDeployments() {
  const response = await fetch("/deployments.json", { cache: "no-store" });
  if (!response.ok) {
    throw new Error("deployments.json not found. Run npm run deploy:local first.");
  }
  const payload = await response.json();
  el.didRegistryAddress.value = payload.contracts.DIDRegistry;
  el.credentialStatusAddress.value = payload.contracts.CredentialStatus;
  el.accessControlAddress.value = payload.contracts.AccessControl;
  appendLog(`Loaded deployments for network: ${payload.network}`);
}

async function withTx(label, task) {
  try {
    const tx = await task();
    const receipt = await tx.wait();
    appendLog(`${label} confirmed in tx ${receipt.hash}`);
    return receipt;
  } catch (err) {
    appendLog(`${label} failed: ${err.shortMessage || err.message}`);
    throw err;
  }
}

function didKeyStruct() {
  return {
    keyId: el.keyIdInput.value.trim(),
    keyType: "EcdsaSecp256k1VerificationKey2019",
    controller: state.address,
    publicKeyHex: el.publicKeyHexInput.value.trim() || "0x1234",
  };
}

function didServiceStruct() {
  return {
    serviceId: el.serviceIdInput.value.trim(),
    serviceType: el.serviceTypeInput.value.trim(),
    endpoint: el.serviceEndpointInput.value.trim(),
  };
}

async function registerDid() {
  requireSigner();
  requireContracts();
  const did = el.didInput.value.trim();
  await withTx("registerDID", () =>
    state.contracts.didRegistry.registerDID(did, didKeyStruct(), didServiceStruct())
  );
}

async function resolveDid() {
  requireContracts();
  const did = el.didInput.value.trim();
  const doc = await state.contracts.didRegistry.resolveDID(did);
  appendLog(
    `resolveDID => controller=${doc.controller}, active=${doc.active}, keys=${doc.publicKeys.length}, services=${doc.serviceEndpoints.length}`
  );
}

async function deactivateDid() {
  requireContracts();
  const did = el.didInput.value.trim();
  await withTx("deactivateDID", () => state.contracts.didRegistry.deactivateDID(did));
}

async function registerHolder() {
  requireContracts();
  const did = el.didInput.value.trim();
  await withTx("registerAsHolder", () => state.contracts.accessControl.registerAsHolder(did));
}

async function registerVerifier() {
  requireContracts();
  const did = el.didInput.value.trim();
  await withTx("registerAsVerifier", () => state.contracts.accessControl.registerAsVerifier(did));
}

async function authorizeIssuer() {
  requireContracts();
  const issuerAddress = el.issuerAddressInput.value.trim();
  const did = el.didInput.value.trim();
  await withTx("authorizeIssuer", () =>
    state.contracts.accessControl.authorizeIssuer(issuerAddress, did)
  );
}

function computeCredentialHash() {
  let payload;
  try {
    payload = JSON.parse(el.credentialPayloadInput.value);
  } catch {
    throw new Error("Credential JSON payload must be valid JSON.");
  }
  const normalized = normalizeJson(payload);
  const hash = ethers.keccak256(ethers.toUtf8Bytes(normalized));
  el.computedHashInput.value = hash;
  appendLog(`Computed hash: ${hash}`);
}

async function issueCredential() {
  requireContracts();
  const subjectDid = el.subjectDidInput.value.trim();
  const hash = el.computedHashInput.value.trim();
  const cid = el.cidInput.value.trim();
  const receipt = await withTx("issueCredential", () =>
    state.contracts.credentialStatus.issueCredential(subjectDid, hash, cid)
  );

  const iface = new ethers.Interface(IAM_ABIS.CredentialStatus);
  for (const log of receipt.logs) {
    try {
      const parsed = iface.parseLog(log);
      if (parsed.name === "CredentialIssued") {
        el.credentialIdInput.value = parsed.args.credentialId;
        appendLog(`CredentialIssued => credentialId=${parsed.args.credentialId}`);
      }
    } catch (err) {
      void err;
    }
  }
}

async function isRevoked() {
  requireContracts();
  const credentialId = el.credentialIdInput.value.trim();
  const result = await state.contracts.credentialStatus.isRevoked(credentialId);
  appendLog(`isRevoked => ${result}`);
}

async function revokeCredential() {
  requireContracts();
  const credentialId = el.credentialIdInput.value.trim();
  await withTx("revokeCredential", () =>
    state.contracts.credentialStatus.revokeCredential(credentialId)
  );
}

async function verifyIntegrity() {
  requireContracts();
  const credentialId = el.credentialIdInput.value.trim();
  const computedHash = el.computedHashInput.value.trim();
  const result = await state.contracts.credentialStatus.verifyCredentialIntegrity(
    credentialId,
    computedHash
  );
  appendLog(`verifyCredentialIntegrity => ${result}`);
}

async function logVerification() {
  requireContracts();
  const credentialId = el.credentialIdInput.value.trim();
  await withTx("logVerification", () =>
    state.contracts.credentialStatus.logVerification(credentialId, true)
  );
}

async function grantConsent() {
  requireContracts();
  const verifierDid = el.verifierDidInput.value.trim();
  const credentialId = el.credentialIdInput.value.trim();
  const expiresAt = BigInt(el.consentExpiryInput.value.trim() || "0");
  await withTx("grantConsent", () =>
    state.contracts.accessControl.grantConsent(verifierDid, credentialId, expiresAt)
  );
}

async function revokeConsent() {
  requireContracts();
  const verifierDid = el.verifierDidInput.value.trim();
  const credentialId = el.credentialIdInput.value.trim();
  await withTx("revokeConsent", () =>
    state.contracts.accessControl.revokeConsent(verifierDid, credentialId)
  );
}

async function hasConsent() {
  requireContracts();
  const holderDid = el.holderDidInput.value.trim();
  const verifierDid = el.verifierDidInput.value.trim();
  const credentialId = el.credentialIdInput.value.trim();
  const result = await state.contracts.accessControl.hasConsent(
    holderDid,
    verifierDid,
    credentialId
  );
  appendLog(`hasConsent => ${result}`);
}

function onClick(id, fn) {
  document.getElementById(id).addEventListener("click", async () => {
    try {
      await fn();
    } catch (err) {
      appendLog(err.shortMessage || err.message);
    }
  });
}

onClick("connectWalletBtn", connectWallet);
onClick("loadDeploymentsBtn", loadDeployments);
onClick("bindContractsBtn", bindContracts);
onClick("registerDidBtn", registerDid);
onClick("resolveDidBtn", resolveDid);
onClick("deactivateDidBtn", deactivateDid);
onClick("registerHolderBtn", registerHolder);
onClick("registerVerifierBtn", registerVerifier);
onClick("authorizeIssuerBtn", authorizeIssuer);
onClick("computeHashBtn", async () => computeCredentialHash());
onClick("issueCredentialBtn", issueCredential);
onClick("checkRevokedBtn", isRevoked);
onClick("revokeCredentialBtn", revokeCredential);
onClick("verifyIntegrityBtn", verifyIntegrity);
onClick("logVerificationBtn", logVerification);
onClick("grantConsentBtn", grantConsent);
onClick("revokeConsentBtn", revokeConsent);
onClick("hasConsentBtn", hasConsent);
