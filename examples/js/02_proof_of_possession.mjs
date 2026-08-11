/**
 * Proof of possession: an audience-bound challenge/response round-trip.
 *
 * Run from the repo root (build once with `cd js && npm install`):
 *
 *     node examples/js/02_proof_of_possession.mjs
 */

import { AgentIdentity, ChallengeStore } from "../../js/dist/src/index.js";
import assert from "node:assert/strict";

const agent = await AgentIdentity.generate("prover");

// Verifier side: issue a challenge bound to this verifier's identity.
const store = new ChallengeStore();
const challenge = store.issue("https://verifier.example");
console.log(`challenge id  : ${challenge.challengeId}`);

// Agent side: sign the challenge with the identity key.
const response = await challenge.respond(agent.keys, agent.address);

// Verifier side: consume (single use), then verify against OUR audience.
const issued = store.consume(response.challengeId);
assert.ok(issued);
const address = await response.verify(issued, "https://verifier.example");
console.log(`proved holder : ${address}`);
assert.equal(address, agent.address);

// The challenge is gone now: a second use fails.
assert.equal(store.consume(response.challengeId), null);
console.log("replay        : blocked (challenge is single-use)");
