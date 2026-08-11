/** Facade layer: AgentIdentity / OwnerIdentity, mirroring the Python
 * facade tests so both languages keep one mental model. */

import assert from "node:assert/strict";
import test from "node:test";

import {
  AgentIdentity,
  DelegationChain,
  KeyRevocation,
  OwnerIdentity,
  RevocationRegistry,
} from "../src/index.js";

test("owner mints an authorized agent whose card self-verifies", async () => {
  const owner = await OwnerIdentity.generate("acme-corp");
  const agent = await owner.createAgent("acme-buyer", ["converse", "negotiate"]);

  assert.equal(agent.operator, owner.address);
  const card = await agent.card({ endpoints: { http: "https://buyer.example/inbox" } });
  await card.verify();
  assert.equal(card.operator, owner.address);

  const scopes = await agent.delegationChain.verify(agent.address);
  assert.deepEqual([...scopes].sort(), ["converse", "negotiate"]);
  assert.equal(agent.delegationChain.rootIssuer, owner.address);
});

test("agent identity: address derivation and immutable with* updates", async () => {
  const agent = await AgentIdentity.generate("alice");
  assert.ok(agent.address.startsWith("amp:key:"));
  assert.equal(agent.kind, "agent");
  assert.equal(agent.operator, null);

  const withOp = agent.withOperator("amp:key:someone");
  assert.equal(withOp.operator, "amp:key:someone");
  assert.equal(agent.operator, null); // original untouched
  assert.equal(withOp.address, agent.address); // same keys, same address
});

test("owner revokes a delegation it issued; refuses others", async () => {
  const owner = await OwnerIdentity.generate("owner");
  const stranger = await OwnerIdentity.generate("stranger");
  const agent = await AgentIdentity.generate("agent");

  const grant = await owner.grant(agent.address, ["read"], 3600);
  const revocation = await owner.revoke(grant);
  await revocation.verify();

  await assert.rejects(stranger.revoke(grant), /this owner issued/);

  const registry = new RevocationRegistry(new Date());
  await registry.add(revocation);
  const revokedDigests = registry.digests;
  await assert.rejects(
    new DelegationChain([grant]).verify(agent.address, { revoked: revokedDigests }),
    /revoked/
  );
});

test("owner recalls a compromised agent key via the delegation chain", async () => {
  const owner = await OwnerIdentity.generate("owner");
  const agent = await owner.createAgent("agent", ["converse"]);

  const recall = await owner.revokeAgentKey(agent);
  assert.ok(recall instanceof KeyRevocation);
  await recall.verify();
  assert.equal(recall.address, agent.address);
  assert.equal(recall.issuer, owner.address);

  // An owner that is not the chain root cannot recall.
  const other = await OwnerIdentity.generate("other");
  await assert.rejects(other.revokeAgentKey(agent), /not the root/);
});

test("agent self-revocation verifies", async () => {
  const agent = await AgentIdentity.generate("agent");
  const revocation = await agent.revokeOwnKey();
  await revocation.verify();
  assert.equal(revocation.address, agent.address);
  assert.equal(revocation.issuer, agent.address);
});

test("owner creates a human endpoint with converse scope", async () => {
  const owner = await OwnerIdentity.generate("sandro");
  const endpoint = await owner.createEndpoint();

  assert.equal(endpoint.kind, "human");
  assert.equal(endpoint.name, "sandro");
  assert.equal(endpoint.operator, owner.address);
  const scopes = await endpoint.delegationChain.verify(endpoint.address);
  assert.deepEqual([...scopes], ["converse"]);
});
