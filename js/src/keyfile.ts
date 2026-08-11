/**
 * Key files on disk: the one-liner persistence layer (Node only).
 *
 * Byte-compatible with the Python reference — a key file written by either
 * language loads in the other:
 *
 * - **Plain**: the raw 64-byte `signing || agreement` form (`KeyPair.toBytes`).
 * - **Encrypted**: the `FGID` v1 container — scrypt (N=2^15, r=8, p=1) +
 *   ChaCha20-Poly1305 with the header as authenticated data — selected by
 *   passing a passphrase.
 *
 * Node's fs and crypto modules are imported dynamically so the rest of the
 * package stays loadable in browsers; calling these functions outside Node
 * fails with a clear error instead of breaking the import graph.
 */

import { concatBytes } from "./bytes.js";
import { KeyFileError } from "./errors.js";
import { KeyPair } from "./keys.js";

const MAGIC = new TextEncoder().encode("FGID");
const VERSION = 1;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const RAW_KEY_BYTES = 64;
const SCRYPT_N = 2 ** 15;
const SCRYPT_R = 8;
const SCRYPT_P = 1;

async function nodeModules() {
  try {
    const [fs, crypto] = await Promise.all([import("node:fs/promises"), import("node:crypto")]);
    return { fs, crypto };
  } catch {
    throw new KeyFileError("key files require a Node.js runtime (fs + crypto are unavailable here)");
  }
}

type NodeCrypto = typeof import("node:crypto");

function deriveKey(crypto: NodeCrypto, passphrase: string, salt: Uint8Array): Buffer {
  // NFC-normalize first, mirroring the Python reference: the same passphrase
  // typed on different platforms must derive the same key.
  const normalized = passphrase.normalize("NFC");
  return crypto.scryptSync(Buffer.from(normalized, "utf-8"), salt, 32, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 64 * 1024 * 1024,
  });
}

function header(): Uint8Array {
  return concatBytes(MAGIC, new Uint8Array([VERSION]));
}

function startsWithMagic(data: Uint8Array): boolean {
  return data.length >= MAGIC.length && MAGIC.every((byte, i) => data[i] === byte);
}

/** Seal a keypair under a passphrase into the FGID v1 container. */
export async function encryptKeys(keys: KeyPair, passphrase: string): Promise<Uint8Array> {
  if (!passphrase) throw new KeyFileError("passphrase must not be empty");
  const { crypto } = await nodeModules();
  const salt = crypto.randomBytes(SALT_BYTES);
  const nonce = crypto.randomBytes(NONCE_BYTES);
  const head = header();
  const key = deriveKey(crypto, passphrase, salt);
  const cipher = crypto.createCipheriv("chacha20-poly1305", key, nonce, {
    authTagLength: TAG_BYTES,
  });
  cipher.setAAD(Buffer.from(head), { plaintextLength: RAW_KEY_BYTES });
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(keys.toBytes())), cipher.final()]);
  return concatBytes(head, salt, nonce, ciphertext, cipher.getAuthTag());
}

/** Open a passphrase-sealed FGID v1 container. Throws if it will not open. */
export async function decryptKeys(data: Uint8Array, passphrase: string): Promise<KeyPair> {
  const { crypto } = await nodeModules();
  const head = header();
  const prefix = head.length + SALT_BYTES + NONCE_BYTES;
  if (data.length <= prefix + TAG_BYTES || !startsWithMagic(data)) {
    throw new KeyFileError("not an encrypted fareground key file");
  }
  if (data[MAGIC.length] !== VERSION) {
    throw new KeyFileError(`unsupported key file version: ${data[MAGIC.length]}`);
  }
  const salt = data.slice(head.length, head.length + SALT_BYTES);
  const nonce = data.slice(head.length + SALT_BYTES, prefix);
  const ciphertext = data.slice(prefix, data.length - TAG_BYTES);
  const tag = data.slice(data.length - TAG_BYTES);
  const key = deriveKey(crypto, passphrase, salt);
  const decipher = crypto.createDecipheriv("chacha20-poly1305", key, nonce, {
    authTagLength: TAG_BYTES,
  });
  decipher.setAAD(Buffer.from(head), { plaintextLength: ciphertext.length });
  decipher.setAuthTag(tag);
  let plain: Buffer;
  try {
    plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new KeyFileError("could not decrypt key file — wrong passphrase or corrupt");
  }
  return KeyPair.fromBytes(new Uint8Array(plain));
}

/** Write a keypair to `path` (mode 0600), encrypted when a passphrase is given. */
export async function saveKeys(
  keys: KeyPair,
  path: string,
  passphrase: string | null = null
): Promise<void> {
  const { fs } = await nodeModules();
  const data = passphrase ? await encryptKeys(keys, passphrase) : keys.toBytes();
  const { dirname } = await import("node:path");
  await fs.mkdir(dirname(path), { recursive: true });
  await fs.writeFile(path, data, { mode: 0o600 });
}

/** Read a keypair from `path`, detecting plain vs encrypted format. */
export async function loadKeys(path: string, passphrase: string | null = null): Promise<KeyPair> {
  const { fs } = await nodeModules();
  const data = new Uint8Array(await fs.readFile(path));
  if (startsWithMagic(data)) {
    if (!passphrase) {
      throw new KeyFileError(`key file ${path} is encrypted — pass the passphrase it was created with`);
    }
    return decryptKeys(data, passphrase);
  }
  if (passphrase) {
    throw new KeyFileError(
      `key file ${path} is not encrypted, but a passphrase was given — ` +
        "refusing to guess which was intended"
    );
  }
  if (data.length !== RAW_KEY_BYTES) {
    throw new KeyFileError(
      `key file ${path} is corrupt: expected ${RAW_KEY_BYTES} raw bytes ` +
        `or an encrypted FGID container, got ${data.length} bytes`
    );
  }
  return KeyPair.fromBytes(data);
}

/** Load the keypair at `path` if it exists; otherwise generate and save one. */
export async function loadOrCreateKeys(
  path: string,
  passphrase: string | null = null
): Promise<KeyPair> {
  const { fs } = await nodeModules();
  try {
    await fs.access(path);
  } catch {
    const keys = await KeyPair.generate();
    await saveKeys(keys, path, passphrase);
    return keys;
  }
  return loadKeys(path, passphrase);
}
