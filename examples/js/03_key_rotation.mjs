/**
 * Key rotation with pre-rotation commitments.
 *
 * The TypeScript build exposes the wire primitives (Inception, KeyRotation,
 * RotationChain, RotationRegistry); this walks one full rotation: a stable
 * name whose key in force changes, pre-committed one step ahead.
 *
 * Run from the repo root (build once with `cd js && npm install`):
 *
 *     node examples/js/03_key_rotation.mjs
 */

import {
  Inception,
  KeyPair,
  KeyRotation,
  RotationChain,
  RotationRegistry,
  addressFromSigningKey,
  keyCommitment,
} from "../../js/dist/src/index.js";
import assert from "node:assert/strict";

const addressOf = (keys) => addressFromSigningKey(keys.public_.signing);

const current = await KeyPair.generate(); // key in force
const next = await KeyPair.generate(); // pre-committed successor (keep cold)
const following = await KeyPair.generate(); // successor's successor

// Inception: the identity's stable name + a commitment to the next key.
const inception = await Inception.create(current, await keyCommitment(next.public_.signing));
let chain = new RotationChain(inception);
console.log(`stable name   : ${chain.identity}`);
console.log(`key in force  : ${addressOf(current)}`);

// Rotate: promote the pre-committed key, commit to a fresh one.
const rotation = await KeyRotation.create({
  currentKeys: current,
  identity: chain.identity,
  sequence: 1,
  nextAddress: addressOf(next),
  nextCommitment: await keyCommitment(following.public_.signing),
});
chain = await chain.extend(rotation);
console.log(`after rotate  : ${addressOf(next)}`);

const state = await chain.resolve();
assert.equal(state.identity, addressOf(current)); // the name never changes
assert.equal(state.currentAddress, addressOf(next)); // the key in force does

// Verifier side: learn the chain, resolve the stable name to the live key.
const registry = new RotationRegistry();
await registry.learn(chain);
assert.equal(registry.resolve(chain.identity), addressOf(next));
console.log(`resolves to   : ${registry.resolve(chain.identity)} (name unchanged)`);
