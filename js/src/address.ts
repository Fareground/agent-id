/** Self-certifying agent addresses: `amp:key:<base58(ed25519-signing-pub)>`. */

import { base58Decode, base58Encode } from "./base58.js";
import { AddressError } from "./errors.js";

export const ADDRESS_PREFIX = "amp:key:";

export function addressFromSigningKey(signingPublic: Uint8Array): string {
  if (signingPublic.length !== 32) {
    throw new AddressError("signing public key must be 32 raw bytes");
  }
  return ADDRESS_PREFIX + base58Encode(signingPublic);
}

export function signingKeyFromAddress(address: string): Uint8Array {
  if (!address.startsWith(ADDRESS_PREFIX)) {
    throw new AddressError(`not an AMP address: ${JSON.stringify(address)}`);
  }
  let key: Uint8Array;
  try {
    key = base58Decode(address.slice(ADDRESS_PREFIX.length));
  } catch {
    throw new AddressError(`invalid base58 in address: ${JSON.stringify(address)}`);
  }
  if (key.length !== 32) {
    throw new AddressError(`address does not decode to a 32-byte key: ${JSON.stringify(address)}`);
  }
  return key;
}
