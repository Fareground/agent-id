/**
 * `did:amp` — a self-certifying DID method for AMP identities, in the spirit
 * of `did:key`. `amp:key:<b58>` <-> `did:amp:<b58>` share the same key.
 * Public keys are `publicKeyMultibase` (multibase base58btc `z` of a
 * multicodec-prefixed key: 0xed01 ed25519-pub, 0xec01 x25519-pub).
 */

import { ADDRESS_PREFIX, signingKeyFromAddress } from "./address.js";
import { base58Decode, base58Encode } from "./base58.js";
import { concatBytes } from "./bytes.js";
import { type JsonValue } from "./canonical.js";
import { type AgentCard } from "./card.js";
import { AddressError } from "./errors.js";

export const DID_PREFIX = "did:amp:";

const ED25519_MULTICODEC = new Uint8Array([0xed, 0x01]);
const X25519_MULTICODEC = new Uint8Array([0xec, 0x01]);

const DID_CONTEXT = [
  "https://www.w3.org/ns/did/v1",
  "https://w3id.org/security/suites/ed25519-2020/v1",
  "https://w3id.org/security/suites/x25519-2020/v1",
];

function multibaseB58(multicodec: Uint8Array, raw: Uint8Array): string {
  return "z" + base58Encode(concatBytes(multicodec, raw));
}

/** `amp:key:<b58>` -> `did:amp:<b58>` (validated round-trip). */
export function addressToDid(address: string): string {
  signingKeyFromAddress(address); // validate it decodes to a 32-byte key
  return DID_PREFIX + address.slice(ADDRESS_PREFIX.length);
}

/** `did:amp:<b58>` -> `amp:key:<b58>` (validated). */
export function didToAddress(did: string): string {
  return ADDRESS_PREFIX + didSuffix(did);
}

function didSuffix(did: string): string {
  if (!did.startsWith(DID_PREFIX)) {
    throw new AddressError(`not a did:amp identifier: ${JSON.stringify(did)}`);
  }
  const suffix = did.slice(DID_PREFIX.length);
  // The method-specific id is the first segment before any path/query/fragment.
  const methodId = suffix.split("/")[0]!.split("?")[0]!.split("#")[0]!;
  let key: Uint8Array;
  try {
    key = base58Decode(methodId);
  } catch {
    throw new AddressError(`did:amp id is not valid base58: ${JSON.stringify(did)}`);
  }
  if (key.length !== 32) {
    throw new AddressError(`did:amp id does not decode to a 32-byte key: ${JSON.stringify(did)}`);
  }
  return methodId;
}

/** The raw Ed25519 public key a `did:amp` certifies. */
export function signingKeyFromDid(did: string): Uint8Array {
  return base58Decode(didSuffix(did));
}

const KIND_TO_SERVICE: Readonly<Record<string, string>> = {
  relay: "AMPRelay",
  http: "AMPInbox",
};

/**
 * Build a W3C DID Document for an AgentCard's identity. Caller is responsible
 * for having verified the card; this assumes its key material is authentic.
 */
export function didDocument(card: AgentCard): Record<string, JsonValue> {
  const did = addressToDid(card.address);
  const signKey = base58Decode(card.signing_key);
  const agreeKey = base58Decode(card.agreement_key);
  const vmId = `${did}#key-1`;
  const kaId = `${did}#key-agreement`;

  const document: Record<string, JsonValue> = {
    "@context": [...DID_CONTEXT],
    id: did,
    alsoKnownAs: [card.address],
    verificationMethod: [
      {
        id: vmId,
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase: multibaseB58(ED25519_MULTICODEC, signKey),
      },
    ],
    authentication: [vmId],
    assertionMethod: [vmId],
    keyAgreement: [
      {
        id: kaId,
        type: "X25519KeyAgreementKey2020",
        controller: did,
        publicKeyMultibase: multibaseB58(X25519_MULTICODEC, agreeKey),
      },
    ],
  };
  if (card.operator) {
    document["controller"] = addressToDid(card.operator);
  }
  const services = Object.entries(card.endpoints)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([name, uri]) => ({
      id: `${did}#${name}`,
      type: KIND_TO_SERVICE[name] ?? "AMPEndpoint",
      serviceEndpoint: uri,
    }));
  if (services.length > 0) {
    document["service"] = services;
  }
  return document;
}

/**
 * Resolve a `did:amp` to a DID Document. Without a card, resolution is
 * deterministic and offline (verification method only). With a card, the card
 * is verified, must match the DID, and yields the fuller document.
 */
export async function resolve(did: string, card?: AgentCard): Promise<Record<string, JsonValue>> {
  const signingKey = signingKeyFromDid(did); // validates the identifier
  if (card !== undefined) {
    await card.verify();
    if (card.address !== didToAddress(did)) {
      throw new AddressError("card address does not match the DID being resolved");
    }
    return didDocument(card);
  }
  const canonical = DID_PREFIX + base58Encode(signingKey);
  const vmId = `${canonical}#key-1`;
  return {
    "@context": [...DID_CONTEXT],
    id: canonical,
    alsoKnownAs: [didToAddress(did)],
    verificationMethod: [
      {
        id: vmId,
        type: "Ed25519VerificationKey2020",
        controller: canonical,
        publicKeyMultibase: multibaseB58(ED25519_MULTICODEC, signingKey),
      },
    ],
    authentication: [vmId],
    assertionMethod: [vmId],
  };
}
