/**
 * Issue and verify a signed agent card (TypeScript build).
 *
 * Run from the repo root (build once with `cd js && npm install`):
 *
 *     node examples/js/01_identity.mjs
 */

import {
  AgentCard,
  OwnerIdentity,
  addressToDid,
} from "../../js/dist/src/index.js";

const owner = await OwnerIdentity.generate("acme-corp");
const agent = await owner.createAgent("acme-buyer", ["converse", "negotiate"]);

// The agent publishes a signed card describing itself.
const card = await agent.card({ endpoints: { http: "https://buyer.example/inbox" } });
console.log(`agent address : ${agent.address}`);
console.log(`agent DID     : ${addressToDid(agent.address)}`);
console.log(`operator      : ${card.operator}`);

// A peer receives the card as JSON and verifies it — the address IS the key.
const received = AgentCard.fromJSON(card.toJSON());
await received.verify();
console.log("card verifies : yes (self-certifying, no registry)");

// The delegation chain proves who stands behind the agent.
const scopes = await agent.delegationChain.verify(agent.address);
console.log(`owner grants  : ${[...scopes].sort().join(", ")} (rooted at ${agent.delegationChain.rootIssuer})`);
