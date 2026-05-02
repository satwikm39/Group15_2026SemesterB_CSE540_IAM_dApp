const fs = require("fs/promises");
const path = require("path");
const crypto = require("crypto");

const STORE_DIR = path.join(process.cwd(), "offchain-db");
const STORE_FILE = path.join(STORE_DIR, "credentials.json");

function canonicalize(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function deriveKey(secret) {
  return crypto.createHash("sha256").update(secret).digest();
}

function encryptJSON(data, secret) {
  const iv = crypto.randomBytes(12);
  const key = deriveKey(secret);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(data), "utf8");
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    alg: "aes-256-gcm",
    iv: iv.toString("hex"),
    tag: tag.toString("hex"),
    ciphertext: encrypted.toString("hex"),
  };
}

function decryptJSON(record, secret) {
  const key = deriveKey(secret);
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(record.iv, "hex")
  );
  decipher.setAuthTag(Buffer.from(record.tag, "hex"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(record.ciphertext, "hex")),
    decipher.final(),
  ]);
  return JSON.parse(decrypted.toString("utf8"));
}

async function ensureStore() {
  await fs.mkdir(STORE_DIR, { recursive: true });
  try {
    await fs.access(STORE_FILE);
  } catch {
    await fs.writeFile(STORE_FILE, JSON.stringify({ records: {} }, null, 2), "utf8");
  }
}

async function readStore() {
  await ensureStore();
  const raw = await fs.readFile(STORE_FILE, "utf8");
  return JSON.parse(raw);
}

async function writeStore(data) {
  await fs.writeFile(STORE_FILE, JSON.stringify(data, null, 2), "utf8");
}

async function saveCredential(payload, opts = {}) {
  const secret = opts.secret || process.env.OFFCHAIN_SECRET || "dev-only-secret";
  const canonicalPayload = canonicalize(payload);
  const encryptedPayload = encryptJSON(payload, secret);
  const cid = crypto
    .createHash("sha256")
    .update(JSON.stringify(encryptedPayload))
    .digest("hex");

  const store = await readStore();
  store.records[cid] = {
    createdAt: new Date().toISOString(),
    payload: encryptedPayload,
  };
  await writeStore(store);

  return { cid, canonicalPayload };
}

async function getCredential(cid, opts = {}) {
  const secret = opts.secret || process.env.OFFCHAIN_SECRET || "dev-only-secret";
  const store = await readStore();
  const record = store.records[cid];
  if (!record) {
    throw new Error(`Credential not found for CID ${cid}`);
  }
  return decryptJSON(record.payload, secret);
}

module.exports = {
  canonicalize,
  saveCredential,
  getCredential,
};
