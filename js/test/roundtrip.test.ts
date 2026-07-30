/** Round-trip tests: JS-signed artifacts verified by the spec's own rules. */

import assert from "node:assert/strict";
import test from "node:test";

import {
  addressFromSigningKey,
  AgentCard,
  Challenge,
  Delegation,
  DelegationChain,
  Inception,
  KeyPair,
  KeyRevocation,
  KeyRotation,
  keyCommitment,
  Revocation,
  RevocationRegistry,
  RotationChain,
  RotationRegistry,
  ChallengeStore,
} from "../src/index.js";

async function agent(): Promise<{ keys: KeyPair; address: string }> {
  const keys = await KeyPair.generate();
  return { keys, address: addressFromSigningKey(keys.public_.signing) };
}

test("keypair 64-byte raw serialization round-trips", async () => {
  const keys = await KeyPair.generate();
  const raw = keys.toBytes();
  assert.equal(raw.length, 64);
  const restored = await KeyPair.fromBytes(raw);
  assert.equal(restored.equals(keys), true);
  assert.deepEqual(restored.public_.signing, keys.public_.signing);
  assert.deepEqual(restored.public_.agreement, keys.public_.agreement);
});

test("agent card: create, serialize, re-parse, verify", async () => {
  const { keys, address } = await agent();
  const operator = await agent();
  const card = await AgentCard.create({
    keys,
    address,
    name: "js-agent",
    operator: operator.address,
    endpoints: { relay: "https://relay.example/amp" },
    policySummary: "round-trip",
  });
  await card.verify();
  const reparsed = AgentCard.fromJSON(JSON.parse(JSON.stringify(card.toJSON())));
  await reparsed.verify();
  assert.deepEqual(reparsed.payload(), card.payload());
});

test("agent card: unknown fields are preserved and signed", async () => {
  const { keys, address } = await agent();
  const card = await AgentCard.create({
    keys,
    address,
    name: "js-agent",
    extra: { experimental_field: "kept" },
  });
  await card.verify();
  const reparsed = AgentCard.fromJSON(card.toJSON());
  assert.equal(reparsed.extra["experimental_field"], "kept");
  await reparsed.verify();
});

test("critical: understood fields pass, unrecognized critical fields fail", async () => {
  const { keys, address } = await agent();
  const card = await AgentCard.create({
    keys,
    address,
    name: "js-agent",
    critical: ["policy_summary"],
  });
  await card.verify(); // known field named critical: fine

  const strict = await AgentCard.create({
    keys,
    address,
    name: "js-agent",
    critical: ["x_new_extension"],
    extra: { x_new_extension: true },
  });
  await assert.rejects(strict.verify(), /critical/);
  // A verifier that declares it understands the extension accepts it.
  await strict.verify(["x_new_extension"]);
});

test("delegation chain: intersection of scopes, terminal subject", async () => {
  const principal = await agent();
  const operator = await agent();
  const worker = await agent();
  const root = await Delegation.grant({
    issuerKeys: principal.keys,
    issuerAddress: principal.address,
    subjectAddress: operator.address,
    scopes: ["read", "write", "admin"],
    ttlSeconds: 3600,
  });
  const leaf = await Delegation.grant({
    issuerKeys: operator.keys,
    issuerAddress: operator.address,
    subjectAddress: worker.address,
    scopes: ["read", "deploy"],
    ttlSeconds: 3600,
  });
  const chain = new DelegationChain([root, leaf]);
  const scopes = await chain.verify(worker.address);
  assert.deepEqual([...scopes].sort(), ["read"]);
  // Empty chain verifies to no scopes.
  assert.deepEqual([...(await new DelegationChain().verify(worker.address))], []);
});

test("delegation survives JSON round-trip with identical digest", async () => {
  const issuer = await agent();
  const subject = await agent();
  const delegation = await Delegation.grant({
    issuerKeys: issuer.keys,
    issuerAddress: issuer.address,
    subjectAddress: subject.address,
    scopes: ["read"],
    ttlSeconds: 60,
  });
  const reparsed = Delegation.fromJSON(JSON.parse(JSON.stringify(delegation.toJSON())));
  await reparsed.verify();
  assert.equal(await reparsed.digest(), await delegation.digest());
});

test("revocation: registry admits verified revocations and flags the digest", async () => {
  const issuer = await agent();
  const subject = await agent();
  const delegation = await Delegation.grant({
    issuerKeys: issuer.keys,
    issuerAddress: issuer.address,
    subjectAddress: subject.address,
    scopes: ["read"],
    ttlSeconds: 3600,
  });
  const revocation = await Revocation.revoke(issuer.keys, delegation);
  await revocation.verify();
  const registry = new RevocationRegistry();
  await registry.add(revocation);
  assert.equal(await registry.isRevoked(delegation), true);
  await assert.rejects(
    new DelegationChain([delegation]).verify(subject.address, { revoked: registry.digests }),
    /revoked/
  );
});

test("key revocation: self and owner-chain forms verify", async () => {
  const owner = await agent();
  const worker = await agent();
  const selfRevocation = await KeyRevocation.create({
    issuerKeys: worker.keys,
    issuer: worker.address,
    address: worker.address,
  });
  await selfRevocation.verify();

  const proof = await Delegation.grant({
    issuerKeys: owner.keys,
    issuerAddress: owner.address,
    subjectAddress: worker.address,
    scopes: ["operate"],
    ttlSeconds: 1, // expiry must NOT block an owner recall
  });
  await new Promise((r) => setTimeout(r, 1100));
  const ownerRevocation = await KeyRevocation.create({
    issuerKeys: owner.keys,
    issuer: owner.address,
    address: worker.address,
    chain: new DelegationChain([proof]),
  });
  await ownerRevocation.verify();
  const reparsed = KeyRevocation.fromJSON(JSON.parse(JSON.stringify(ownerRevocation.toJSON())));
  await reparsed.verify();
});

test("revocation registry freshness semantics", () => {
  const registry = new RevocationRegistry();
  assert.equal(registry.isStale(60), true); // never synced counts as stale
  assert.throws(() => registry.requireFresh(60), /stale/);
  registry.markSynced();
  assert.equal(registry.isStale(60), false);
  registry.requireFresh(60);
});

test("challenge-response round-trip with single-use store", async () => {
  const { keys, address } = await agent();
  const store = new ChallengeStore(60);
  const challenge = store.issue("https://verifier.example");
  const response = await challenge.respond(keys, address);
  const consumed = store.consume(response.challengeId);
  assert.ok(consumed);
  const proven = await response.verify(consumed!, "https://verifier.example");
  assert.equal(proven, address);
  assert.equal(store.consume(response.challengeId), null); // single use
});

test("rotation: inception -> two rotations resolve to the latest key", async () => {
  const keysA = await KeyPair.generate();
  const keysB = await KeyPair.generate();
  const keysC = await KeyPair.generate();
  const keysD = await KeyPair.generate();
  const addressOf = (k: KeyPair) => addressFromSigningKey(k.public_.signing);

  const inception = await Inception.create(keysA, await keyCommitment(keysB.public_.signing));
  let chain = new RotationChain(inception);
  const rotation1 = await KeyRotation.create({
    currentKeys: keysA,
    identity: chain.identity,
    sequence: 1,
    nextAddress: addressOf(keysB),
    nextCommitment: await keyCommitment(keysC.public_.signing),
  });
  chain = await chain.extend(rotation1);
  const rotation2 = await KeyRotation.create({
    currentKeys: keysB,
    identity: chain.identity,
    sequence: 2,
    nextAddress: addressOf(keysC),
    nextCommitment: await keyCommitment(keysD.public_.signing),
  });
  chain = await chain.extend(rotation2);

  const state = await chain.resolve();
  assert.equal(state.identity, addressOf(keysA));
  assert.equal(state.currentAddress, addressOf(keysC));
  assert.equal(state.sequence, 2);

  const registry = new RotationRegistry();
  await registry.learn(chain);
  assert.equal(registry.resolve(chain.identity), addressOf(keysC));
  // Unknown identity resolves to itself.
  assert.equal(registry.resolve(addressOf(keysD)), addressOf(keysD));
});
