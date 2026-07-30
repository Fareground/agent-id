/**
 * Key material for an agent: Ed25519 (signing) + X25519 (key agreement),
 * built on WebCrypto (`crypto.subtle`) — available in Node 20+ and modern
 * browsers, no dependencies.
 *
 * WebCrypto has no "raw" private-key format for these curves, so the raw
 * 32-byte seeds cross into/out of WebCrypto wrapped in the fixed PKCS#8 /
 * SPKI DER headers (the algorithm identifiers are constant, so this is plain
 * concatenation, not ASN.1).
 */

import { base58Encode } from "./base58.js";
import { bytesEqual, concatBytes } from "./bytes.js";
import { SignatureError } from "./errors.js";

const ED_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);
const ED_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);
const X_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
  0x04, 0x22, 0x04, 0x20,
]);

function require32(name: string, data: Uint8Array): Uint8Array {
  if (data.length !== 32) throw new Error(`${name} must be 32 raw bytes`);
  return data;
}

async function importEdPrivate(seed32: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "pkcs8",
    concatBytes(ED_PKCS8_PREFIX, require32("Ed25519 seed", seed32)) as BufferSource,
    "Ed25519",
    false,
    ["sign"]
  );
}

async function importEdPublic(raw32: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    require32("Ed25519 public key", raw32) as BufferSource,
    "Ed25519",
    false,
    ["verify"]
  );
}

/** Derive the raw Ed25519 public key from a 32-byte seed. */
export async function ed25519PublicFromSeed(seed32: Uint8Array): Promise<Uint8Array> {
  // Import as pkcs8, then round-trip through JWK to reach the public half.
  const priv = await crypto.subtle.importKey(
    "pkcs8",
    concatBytes(ED_PKCS8_PREFIX, require32("Ed25519 seed", seed32)) as BufferSource,
    "Ed25519",
    true,
    ["sign"]
  );
  const jwk = await crypto.subtle.exportKey("jwk", priv);
  return base64UrlDecode(jwk.x!);
}

async function x25519PublicFromRawPrivate(raw32: Uint8Array): Promise<Uint8Array> {
  const priv = await crypto.subtle.importKey(
    "pkcs8",
    concatBytes(X_PKCS8_PREFIX, require32("X25519 private key", raw32)) as BufferSource,
    "X25519",
    true,
    ["deriveBits"]
  );
  const jwk = await crypto.subtle.exportKey("jwk", priv);
  return base64UrlDecode(jwk.x!);
}

function base64UrlDecode(text: string): Uint8Array {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/");
  const withPad = padded + "=".repeat((4 - (padded.length % 4)) % 4);
  const binary = atob(withPad);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export async function ed25519Sign(seed32: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const key = await importEdPrivate(seed32);
  return new Uint8Array(await crypto.subtle.sign("Ed25519", key, message as BufferSource));
}

export async function ed25519Verify(
  rawPub32: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array
): Promise<boolean> {
  try {
    const key = await importEdPublic(rawPub32);
    return await crypto.subtle.verify(
      "Ed25519",
      key,
      signature as BufferSource,
      message as BufferSource
    );
  } catch {
    return false;
  }
}

/** Public halves, safe to publish (raw 32-byte keys). */
export class PublicKeys {
  constructor(
    public readonly signing: Uint8Array,
    public readonly agreement: Uint8Array
  ) {
    require32("signing public key", signing);
    require32("agreement public key", agreement);
  }

  async verify(signature: Uint8Array, message: Uint8Array): Promise<void> {
    if (!(await ed25519Verify(this.signing, message, signature))) {
      throw new SignatureError("Ed25519 signature verification failed");
    }
  }

  get signingB58(): string {
    return base58Encode(this.signing);
  }

  get agreementB58(): string {
    return base58Encode(this.agreement);
  }
}

/**
 * An agent's full key material. Private keys are held as raw 32-byte seeds so
 * the 64-byte wire serialization (`signing || agreement`) is exact; WebCrypto
 * key objects are created on demand for each operation.
 */
export class KeyPair {
  private constructor(
    private readonly signingSeed: Uint8Array,
    private readonly agreementSeed: Uint8Array,
    public readonly public_: PublicKeys
  ) {}

  static async generate(): Promise<KeyPair> {
    const signing = crypto.getRandomValues(new Uint8Array(32));
    const agreement = crypto.getRandomValues(new Uint8Array(32));
    return KeyPair.fromSeeds(signing, agreement);
  }

  static async fromSeeds(signingSeed: Uint8Array, agreementSeed: Uint8Array): Promise<KeyPair> {
    require32("signing seed", signingSeed);
    require32("agreement seed", agreementSeed);
    const publicKeys = new PublicKeys(
      await ed25519PublicFromSeed(signingSeed),
      await x25519PublicFromRawPrivate(agreementSeed)
    );
    return new KeyPair(new Uint8Array(signingSeed), new Uint8Array(agreementSeed), publicKeys);
  }

  /** Deserialize from the 64-byte raw form (`signing || agreement`). */
  static async fromBytes(data: Uint8Array): Promise<KeyPair> {
    if (data.length !== 64) throw new Error("KeyPair serialization must be exactly 64 bytes");
    return KeyPair.fromSeeds(data.slice(0, 32), data.slice(32));
  }

  /** Serialize private keys (64 bytes: signing || agreement). Caller owns secrecy. */
  toBytes(): Uint8Array {
    return concatBytes(this.signingSeed, this.agreementSeed);
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    return ed25519Sign(this.signingSeed, message);
  }

  /** True when both keypairs hold identical seeds. */
  equals(other: KeyPair): boolean {
    return (
      bytesEqual(this.signingSeed, other.signingSeed) &&
      bytesEqual(this.agreementSeed, other.agreementSeed)
    );
  }
}
