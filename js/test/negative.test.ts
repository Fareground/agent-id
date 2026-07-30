/** Negative tests: tampering, expiry, revocation, forks, wrong audience. */

import assert from "node:assert/strict";
import test from "node:test";

import {
  addressFromSigningKey,
  AgentCard,
  canonicalJson,
  Challenge,
  Delegation,
  DelegationChain,
  Inception,
  KeyPair,
  KeyRevocation,
  KeyRotation,
  keyCommitment,
  RotationChain,
  RotationRegistry,
  decodeSignature,
} from "../src/index.js";

async function agent(): Promise<{ keys: KeyPair; address: string }> {
  const keys = await KeyPair.generate();
  return { keys, address: addressFromSigningKey(keys.public_.signing) };
}

test("canonical JSON rejects floats and NaN/Infinity", () => {
  assert.throws(() => canonicalJson({ x: 1.5 }), /float/);
  assert.throws(() => canonicalJson({ x: NaN }), /NaN|float/);
  assert.throws(() => canonicalJson({ x: Infinity }), /NaN|Infinity/);
  assert.doesNotThrow(() => canonicalJson({ x: 3, y: true, z: null }));
});

test("non-canonical base64 signature spellings are rejected", () => {
  // Same bytes, alternate spelling with non-zero trailing bits.
  assert.throws(() => decodeSignature("AB=="), /canonically/); // "AA==" is canonical for 0x00
  assert.throws(() => decodeSignature("not base64!!"), /base64/);
});

test("tampered card signature fails", async () => {
  const { keys, address } = await agent();
  const card = await AgentCard.create({ keys, address, name: "victim" });
  const tampered = card.with({ signature: card.signature.slice(0, -4) + "AA==" });
  await assert.rejects(tampered.verify(), /signature/i);
  // Tampered payload under the original signature also fails.
  const renamed = AgentCard.fromJSON({ ...card.toJSON(), name: "mallory" });
  await assert.rejects(renamed.verify(), /signature/i);
});

test("card signed by a key that does not match its address fails", async () => {
  const { keys } = await agent();
  const other = await agent();
  const card = await AgentCard.create({ keys, address: other.address, name: "imposter" });
  await assert.rejects(card.verify(), /does not match its address/);
});

test("expired and future-dated delegations are rejected", async () => {
  const issuer = await agent();
  const subject = await agent();
  const expired = await Delegation.grant({
    issuerKeys: issuer.keys,
    issuerAddress: issuer.address,
    subjectAddress: subject.address,
    scopes: ["read"],
    ttlSeconds: -1,
  });
  await assert.rejects(expired.verify(), /expired/);

  const future = new Delegation({
    issuer: issuer.address,
    subject: subject.address,
    scopes: ["read"],
    issuedAt: new Date(Date.now() + 60_000),
    expiresAt: new Date(Date.now() + 120_000),
  });
  await assert.rejects(future.verify(), /future/);
});

test("chain with revoked identity key is invalid", async () => {
  const issuer = await agent();
  const subject = await agent();
  const delegation = await Delegation.grant({
    issuerKeys: issuer.keys,
    issuerAddress: issuer.address,
    subjectAddress: subject.address,
    scopes: ["read"],
    ttlSeconds: 3600,
  });
  const chain = new DelegationChain([delegation]);
  await assert.rejects(
    chain.verify(subject.address, { revokedKeys: new Set([issuer.address]) }),
    /revoked identity key/
  );
});

test("broken chain topology and wrong terminal subject are rejected", async () => {
  const a = await agent();
  const b = await agent();
  const c = await agent();
  const rootLink = await Delegation.grant({
    issuerKeys: a.keys,
    issuerAddress: a.address,
    subjectAddress: b.address,
    scopes: ["read"],
    ttlSeconds: 3600,
  });
  const unrelated = await Delegation.grant({
    issuerKeys: c.keys, // c was never delegated to by b
    issuerAddress: c.address,
    subjectAddress: c.address,
    scopes: ["read"],
    ttlSeconds: 3600,
  });
  await assert.rejects(
    new DelegationChain([rootLink, unrelated]).verify(c.address),
    /broken chain/
  );
  await assert.rejects(new DelegationChain([rootLink]).verify(c.address), /terminates at/);
});

test("owner key-revocation without a proof chain is rejected", async () => {
  const owner = await agent();
  const worker = await agent();
  const revocation = await KeyRevocation.create({
    issuerKeys: owner.keys,
    issuer: owner.address,
    address: worker.address,
  });
  await assert.rejects(revocation.verify(), /proof chain/);
});

test("owner recall is not blocked by an un-understood critical extension", async () => {
  // A compromised worker key must be revocable even when the proof chain
  // carries a critical extension the verifier doesn't understand — rejecting
  // the recall would keep the compromised key trusted, the opposite of the
  // marker's intent. Mirrors the Python test_owner_recall_is_not_blocked_by_criticality.
  const owner = await agent();
  const worker = await agent();
  const link = await Delegation.grant({
    issuerKeys: owner.keys,
    issuerAddress: owner.address,
    subjectAddress: worker.address,
    scopes: ["read"],
    ttlSeconds: 3600,
    critical: ["x-fg-unknown-policy"],
    extra: { "x-fg-unknown-policy": "some-value" },
  });
  const chain = new DelegationChain([link]);

  // A plain chain verification with no understood set still rejects (fail-closed).
  await assert.rejects(chain.verify(worker.address), /understand|critical/i);

  // But owner recall over the same chain must succeed.
  const revocation = await KeyRevocation.create({
    issuerKeys: owner.keys,
    issuer: owner.address,
    address: worker.address,
    chain,
  });
  await revocation.verify(); // must not throw
});

test("rotation: bad sequence, wrong signer, and commitment mismatch", async () => {
  const keysA = await KeyPair.generate();
  const keysB = await KeyPair.generate();
  const keysC = await KeyPair.generate();
  const addressOf = (k: KeyPair) => addressFromSigningKey(k.public_.signing);
  const inception = await Inception.create(keysA, await keyCommitment(keysB.public_.signing));

  // Sequence must be exactly previous + 1.
  const skipped = await KeyRotation.create({
    currentKeys: keysA,
    identity: inception.address,
    sequence: 2,
    nextAddress: addressOf(keysB),
    nextCommitment: await keyCommitment(keysC.public_.signing),
  });
  await assert.rejects(
    new RotationChain(inception, [skipped]).resolve(),
    /out of order/
  );

  // Revealed key must match the standing pre-rotation commitment.
  const wrongKey = await KeyRotation.create({
    currentKeys: keysA,
    identity: inception.address,
    sequence: 1,
    nextAddress: addressOf(keysC), // committed to B, reveals C
    nextCommitment: await keyCommitment(keysC.public_.signing),
  });
  await assert.rejects(
    new RotationChain(inception, [wrongKey]).resolve(),
    /pre-rotation commitment/
  );

  // Signature must come from the key currently in force.
  const wrongSigner = await KeyRotation.create({
    currentKeys: keysB,
    identity: inception.address,
    sequence: 1,
    nextAddress: addressOf(keysB),
    nextCommitment: await keyCommitment(keysC.public_.signing),
  });
  await assert.rejects(new RotationChain(inception, [wrongSigner]).resolve(), /in force/);
});

test("rotation fork detection: registry refuses to advance and brands the identity", async () => {
  const keysA = await KeyPair.generate();
  const keysB = await KeyPair.generate();
  const keysC = await KeyPair.generate();
  const keysD = await KeyPair.generate();
  const addressOf = (k: KeyPair) => addressFromSigningKey(k.public_.signing);
  const inception = await Inception.create(keysA, await keyCommitment(keysB.public_.signing));

  const honest = await KeyRotation.create({
    currentKeys: keysA,
    identity: inception.address,
    sequence: 1,
    nextAddress: addressOf(keysB),
    nextCommitment: await keyCommitment(keysC.public_.signing),
  });
  // Same sequence, same revealed key, DIFFERENT forward commitment — a fork.
  const forked = await KeyRotation.create({
    currentKeys: keysA,
    identity: inception.address,
    sequence: 1,
    nextAddress: addressOf(keysB),
    nextCommitment: await keyCommitment(keysD.public_.signing),
  });

  const registry = new RotationRegistry();
  await registry.learn(new RotationChain(inception, [honest]));
  await assert.rejects(
    registry.learn(new RotationChain(inception, [forked])),
    /conflicting records/
  );
  assert.equal(registry.isDuplicitous(inception.address), true);
  assert.equal(registry.duplicityEvidence(inception.address).length, 1);
  assert.throws(() => registry.resolve(inception.address), /compromised/);
});

test("challenge-response: wrong audience, purpose, nonce, and expiry rejected", async () => {
  const { keys, address } = await agent();
  const challenge = Challenge.issue("https://verifier.example", "authenticate", 60);
  const response = await challenge.respond(keys, address);

  await assert.rejects(response.verify(challenge, "https://attacker.example"), /addressed to/);
  await assert.rejects(response.verify(challenge, ""), /own audience/);

  const otherChallenge = Challenge.issue("https://verifier.example", "authenticate", 60);
  await assert.rejects(
    response.verify(otherChallenge, "https://verifier.example"),
    /does not match the issued challenge/
  );

  const wrongPurpose = Challenge.fromJSON({ ...challenge.toJSON(), purpose: "payment" });
  await assert.rejects(
    response.verify(wrongPurpose, "https://verifier.example"),
    /purpose/
  );

  const expired = Challenge.fromJSON({
    ...challenge.toJSON(),
    expires_at: "2020-01-01T00:00:00.000Z",
  });
  await assert.rejects(response.verify(expired, "https://verifier.example"), /expired/);
});

test("timezone-naive timestamps are rejected", async () => {
  assert.throws(
    () =>
      new Delegation({
        issuer: "amp:key:x",
        subject: "amp:key:y",
        scopes: [],
        issuedAt: "2026-01-01T00:00:00" as string,
        expiresAt: "2026-02-01T00:00:00Z",
      }),
    /timezone/
  );
});
