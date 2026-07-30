/** Spend scopes: grammar, intersection, and chain-level cap enforcement.
 * Parity with the Python reference (tests/test_spend.py) so a JS verifier
 * enforces the same monetary caps — no fail-open on money. */

import assert from "node:assert/strict";
import test from "node:test";

import {
  addressFromSigningKey,
  Delegation,
  DelegationChain,
  KeyPair,
  parseSpendScope,
  SpendAuthority,
  SpendScopeError,
  spendAuthorityFor,
} from "../src/index.js";

async function agent() {
  const keys = await KeyPair.generate();
  return { keys, address: addressFromSigningKey(keys.public_.signing) };
}

test("spend scope: parse asset-only, caps, and either order", () => {
  assert.equal(parseSpendScope("pay:usdc").txCap, null);
  const full = parseSpendScope("pay:usd:tx<=9.99:total<=100");
  assert.equal(full.asset, "usd");
  assert.equal(full.txCap?.text, "9.99");
  assert.equal(full.totalCap?.text, "100");
  // order-independent
  assert.equal(parseSpendScope("pay:usd:total<=100:tx<=9.99").txCap?.text, "9.99");
});

test("spend scope: render round-trips and malformed scopes are rejected", () => {
  for (const s of ["pay:usdc", "pay:usdc:tx<=25", "pay:usd:tx<=9.99:total<=100"]) {
    assert.equal(parseSpendScope(s).render(), s);
  }
  for (const bad of [
    "pay",
    "pay:",
    "pay:USD", // uppercase asset
    "pay:usd:tx<=-5", // signed
    "pay:usd:tx<=", // empty amount
    "pay:usd:tx<=1.2.3", // not a decimal
    "pay:usd:weird<=5", // unknown segment
    "pay:usd:tx<=1:tx<=2", // duplicate cap
  ]) {
    assert.throws(() => parseSpendScope(bad), SpendScopeError, `should reject ${bad}`);
  }
});

test("intersection takes the minimum cap on each axis", () => {
  const a = parseSpendScope("pay:usdc:tx<=100:total<=1000");
  const b = parseSpendScope("pay:usdc:tx<=25");
  const merged = a.intersect(b);
  assert.equal(merged.txCap?.text, "25");
  assert.equal(merged.totalCap?.text, "1000");
  assert.throws(() => a.intersect(parseSpendScope("pay:eth")), SpendScopeError);
});

test("chain spend authority enforces per-tx and total caps (the money fail-open)", async () => {
  const owner = await agent();
  const worker = await agent();
  const link = await Delegation.grant({
    issuerKeys: owner.keys,
    issuerAddress: owner.address,
    subjectAddress: worker.address,
    scopes: ["pay:usdc:tx<=25:total<=100"],
    ttlSeconds: 3600,
  });
  const chain = new DelegationChain([link]);

  // Within caps: allowed.
  const eff = SpendAuthority.verify(chain, "usdc", "25", "0");
  assert.equal(eff.txCap?.text, "25");

  // Over per-tx cap: rejected.
  assert.throws(() => SpendAuthority.verify(chain, "usdc", "25.01"), SpendScopeError);

  // Cumulative would exceed the total cap: rejected.
  assert.throws(() => SpendAuthority.verify(chain, "usdc", "20", "90"), SpendScopeError);

  // Unknown asset: no authority, rejected (fail-closed, not open).
  assert.throws(() => SpendAuthority.verify(chain, "eth", "1"), SpendScopeError);
});

test("a link without a spend scope for the asset voids chain authority", async () => {
  const owner = await agent();
  const mid = await agent();
  const worker = await agent();
  const l1 = await Delegation.grant({
    issuerKeys: owner.keys,
    issuerAddress: owner.address,
    subjectAddress: mid.address,
    scopes: ["pay:usdc:tx<=25"],
    ttlSeconds: 3600,
  });
  const l2 = await Delegation.grant({
    issuerKeys: mid.keys,
    issuerAddress: mid.address,
    subjectAddress: worker.address,
    scopes: ["read"], // no spend scope: chain grants no spend authority
    ttlSeconds: 3600,
  });
  const chain = new DelegationChain([l1, l2]);
  assert.equal(spendAuthorityFor(["read"], "usdc"), null);
  assert.throws(() => SpendAuthority.verify(chain, "usdc", "1"), SpendScopeError);
});
