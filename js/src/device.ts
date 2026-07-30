/**
 * Multi-device identity as plain delegation — TypeScript port of the Python
 * reference (`fg_agent_id/device.py`, SPEC §11).
 *
 * One identity, several devices, no new machinery: a stable identity key
 * delegates to a per-device key with the reserved `device` scope. Losing a
 * phone is a `Revocation` on that one grant; the device key never impersonates
 * the identity — it presents its delegation and signs with its own key, so a
 * verifier always sees WHICH device acted.
 *
 * Ported for parity: leaving each JS embedder to hand-roll device verification
 * is exactly what produces divergent bugs between the two implementations.
 */

import { Delegation, DelegationChain, RevocationRegistry } from "./delegation.js";
import { DelegationError } from "./errors.js";
import type { KeyPair } from "./keys.js";

/** Reserved scope marking a grant as a device delegation (SPEC §11). */
export const DEVICE_SCOPE = "device";

/** Devices are long-lived but not eternal: 30 days forces a re-issue cadence
 * without nagging daily. Deployments choose their own. */
export const DEFAULT_DEVICE_TTL_SECONDS = 30 * 24 * 3600;

/** Identity key grants a per-device key the right to act for it. The reserved
 * `device` scope is always added so verifiers can tell a device grant apart. */
export async function issueDeviceDelegation(options: {
  identityKeys: KeyPair;
  identityAddress: string;
  deviceAddress: string;
  scopes?: Iterable<string>;
  ttlSeconds?: number;
}): Promise<Delegation> {
  const scopes = new Set(options.scopes ?? []);
  scopes.add(DEVICE_SCOPE);
  return Delegation.grant({
    issuerKeys: options.identityKeys,
    issuerAddress: options.identityAddress,
    subjectAddress: options.deviceAddress,
    scopes,
    ttlSeconds: options.ttlSeconds ?? DEFAULT_DEVICE_TTL_SECONDS,
  });
}

/**
 * Does this device key currently act for this identity? Verifies the
 * delegation (chain) — signature, expiry, topology — checks it roots at
 * `identityAddress`, terminates at `deviceAddress`, and carries the `device`
 * scope, and consults `registry` for revocation. When `maxRegistryAgeSeconds`
 * is given the registry must also be fresh (§5.2) so a dead sync fails closed.
 * Returns the device's effective working scopes (the `device` marker removed).
 */
export async function verifyDevice(options: {
  delegation: Delegation | DelegationChain;
  identityAddress: string;
  deviceAddress: string;
  registry?: RevocationRegistry;
  now?: Date;
  leewaySeconds?: number;
  maxRegistryAgeSeconds?: number;
}): Promise<ReadonlySet<string>> {
  const chain =
    options.delegation instanceof DelegationChain
      ? options.delegation
      : new DelegationChain([options.delegation]);
  if (chain.links.length === 0) {
    throw new DelegationError("device verification needs a non-empty chain");
  }
  if (chain.rootIssuer !== options.identityAddress) {
    throw new DelegationError(
      `device chain roots at ${chain.rootIssuer}, not identity ${options.identityAddress}`
    );
  }
  let revoked: ReadonlySet<string> = new Set();
  let revokedKeys: ReadonlySet<string> = new Set();
  if (options.registry) {
    if (options.maxRegistryAgeSeconds !== undefined) {
      options.registry.requireFresh(options.maxRegistryAgeSeconds, options.now);
    }
    revoked = options.registry.digests;
    revokedKeys = options.registry.revokedKeys;
  }
  const scopes = await chain.verify(options.deviceAddress, {
    now: options.now,
    revoked,
    revokedKeys,
    leewaySeconds: options.leewaySeconds,
  });
  if (!scopes.has(DEVICE_SCOPE)) {
    throw new DelegationError(
      `chain to ${options.deviceAddress} does not carry the ${JSON.stringify(DEVICE_SCOPE)} scope`
    );
  }
  const working = new Set(scopes);
  working.delete(DEVICE_SCOPE);
  return working;
}
