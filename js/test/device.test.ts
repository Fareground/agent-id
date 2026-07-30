/** Multi-device delegation: issue, verify, wrong-device, and revocation.
 * Parity with the Python reference so JS embedders don't hand-roll it. */

import assert from "node:assert/strict";
import test from "node:test";

import {
  addressFromSigningKey,
  DEVICE_SCOPE,
  issueDeviceDelegation,
  KeyPair,
  Revocation,
  RevocationRegistry,
  verifyDevice,
} from "../src/index.js";

async function principal() {
  const keys = await KeyPair.generate();
  return { keys, address: addressFromSigningKey(keys.public_.signing) };
}

test("a device grant verifies for its device and yields working scopes", async () => {
  const identity = await principal();
  const device = await principal();
  const grant = await issueDeviceDelegation({
    identityKeys: identity.keys,
    identityAddress: identity.address,
    deviceAddress: device.address,
    scopes: ["read", "write"],
  });
  const scopes = await verifyDevice({
    delegation: grant,
    identityAddress: identity.address,
    deviceAddress: device.address,
  });
  // The reserved marker is stripped from the returned working scopes.
  assert.ok(scopes.has("read") && scopes.has("write"));
  assert.ok(!scopes.has(DEVICE_SCOPE));
});

test("a device grant does not verify for a different device or identity", async () => {
  const identity = await principal();
  const device = await principal();
  const other = await principal();
  const grant = await issueDeviceDelegation({
    identityKeys: identity.keys,
    identityAddress: identity.address,
    deviceAddress: device.address,
  });
  await assert.rejects(
    verifyDevice({
      delegation: grant,
      identityAddress: identity.address,
      deviceAddress: other.address,
    })
  );
  await assert.rejects(
    verifyDevice({
      delegation: grant,
      identityAddress: other.address,
      deviceAddress: device.address,
    })
  );
});

test("revoking a device grant stops it verifying", async () => {
  const identity = await principal();
  const device = await principal();
  const grant = await issueDeviceDelegation({
    identityKeys: identity.keys,
    identityAddress: identity.address,
    deviceAddress: device.address,
  });
  const registry = new RevocationRegistry();
  // Verifies while live.
  await verifyDevice({
    delegation: grant,
    identityAddress: identity.address,
    deviceAddress: device.address,
    registry,
  });
  // Lost phone: revoke that one grant.
  const revocation = await Revocation.revoke(identity.keys, grant);
  await registry.add(revocation);
  await assert.rejects(
    verifyDevice({
      delegation: grant,
      identityAddress: identity.address,
      deviceAddress: device.address,
      registry,
    })
  );
});
