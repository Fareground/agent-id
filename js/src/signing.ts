/**
 * Domain-separated signing input (§3.1):
 *
 *   signing_input = uint16be(len(tag)) || tag || canonical_json(payload)
 *   tag = "fg-agent-id/v1/<context>"
 *
 * Every signature names what kind of artifact it covers, so a signature for
 * one artifact type can never be replayed as another.
 */

import { signingKeyFromAddress } from "./address.js";
import { base64Decode, base64Encode, concatBytes, utf8Encode } from "./bytes.js";
import { canonicalJson, type JsonValue } from "./canonical.js";
import { SignatureError } from "./errors.js";
import { ed25519Verify, type KeyPair } from "./keys.js";

export const DOMAIN = "fg-agent-id/v1";

export const CONTEXT_AGENT_CARD = "agent-card";
export const CONTEXT_DELEGATION = "delegation";
export const CONTEXT_REVOCATION = "revocation";
export const CONTEXT_KEY_REVOCATION = "key-revocation";
export const CONTEXT_KEY_ROTATION = "key-rotation";
export const CONTEXT_INCEPTION = "inception";
export const CONTEXT_CHALLENGE_RESPONSE = "challenge-response";

const MAX_TAG_BYTES = 0xffff;

export function domainTag(context: string): Uint8Array {
  if (!context) throw new Error("signing context must be a non-empty string");
  const tag = utf8Encode(`${DOMAIN}/${context}`);
  if (tag.length > MAX_TAG_BYTES) throw new Error("signing context tag is too long");
  return tag;
}

/** The exact bytes to sign or verify for `payload` under `context`. */
export function signingInput(context: string, payload: JsonValue): Uint8Array {
  const tag = domainTag(context);
  const prefix = new Uint8Array([(tag.length >> 8) & 0xff, tag.length & 0xff]);
  return concatBytes(prefix, tag, canonicalJson(payload));
}

/** Sign `payload` under `context`; returns a base64 signature. */
export async function signPayload(
  keys: KeyPair,
  context: string,
  payload: JsonValue
): Promise<string> {
  return base64Encode(await keys.sign(signingInput(context, payload)));
}

/**
 * Decode a base64 signature, rejecting any non-canonical spelling. Signatures
 * are identifiers as well as proofs (a delegation digest covers its
 * signature), so one signature must have exactly one wire form.
 */
export function decodeSignature(signature: string): Uint8Array {
  let raw: Uint8Array;
  try {
    raw = base64Decode(signature);
  } catch {
    throw new SignatureError("signature is not valid base64");
  }
  if (base64Encode(raw) !== signature) {
    throw new SignatureError("signature is not canonically base64-encoded");
  }
  return raw;
}

/** Verify a base64 signature over `payload` under `context` for a raw key. */
export async function verifyPayload(
  signingPublic: Uint8Array,
  context: string,
  payload: JsonValue,
  signature: string
): Promise<void> {
  const raw = decodeSignature(signature);
  if (!(await ed25519Verify(signingPublic, signingInput(context, payload), raw))) {
    throw new SignatureError("Ed25519 signature verification failed");
  }
}

/** Verify against the signing key an AMP address self-certifies. */
export async function verifyByAddress(
  address: string,
  context: string,
  payload: JsonValue,
  signature: string
): Promise<void> {
  await verifyPayload(signingKeyFromAddress(address), context, payload, signature);
}
