/**
 * Spend scopes: a grammar for monetary authority in delegation chains.
 *
 * Port of the Python reference (`fg_agent_id/spend.py`) — byte-for-byte
 * identical grammar so a JS verifier enforces the same monetary caps a
 * Python issuer wrote. Without this, a JS verifier handed a `pay:usdc:tx<=25`
 * scope treats it as an opaque string and cannot enforce the cap — a
 * fail-open on money.
 *
 *     pay:<asset>[:tx<=<amount>][:total<=<amount>]
 *
 *     pay:usdc                     unlimited authority over usdc
 *     pay:usdc:tx<=25              at most 25 usdc per transaction
 *     pay:usd:tx<=9.99:total<=100  per-tx and cumulative caps
 *
 * Amounts are non-negative decimal strings — never floats — so the grammar
 * survives canonical JSON and cross-language parsing. Comparison is exact
 * (BigInt-scaled), never floating point. Composition down a chain is
 * intersection: the effective cap on each axis is the minimum across links,
 * and a link with no spend scope for the asset contributes no authority at
 * all, so a delegate can never spend more than ANY of its delegators allowed.
 *
 * Pure grammar and verification math: it moves no money and keeps no ledger —
 * the caller supplies `spentSoFar` from its own books.
 */

import type { DelegationChain } from "./delegation.js";
import { SpendScopeError } from "./errors.js";

export const SPEND_PREFIX = "pay";
const TX_CAP_PREFIX = "tx<=";
const TOTAL_CAP_PREFIX = "total<=";

// Opaque asset token: lowercase alphanumerics with ._- separators inside.
const ASSET_RE = /^[a-z0-9]+([._-][a-z0-9]+)*$/;
// Non-negative decimal, optional fraction; no sign, exponent, or bare dot.
const AMOUNT_RE = /^[0-9]+(\.[0-9]+)?$/;
// Enough for any real currency amount; bounds hostile megabyte-long numerals.
const MAX_AMOUNT_CHARS = 40;

/** A validated non-negative decimal amount, kept as its original string
 * spelling (trailing zeros preserved, matching Python's Decimal) with an
 * exact BigInt comparison. */
export class Amount {
  readonly text: string;

  constructor(text: string) {
    if (typeof text !== "string") {
      throw new SpendScopeError("amount must be a string");
    }
    if (text.length > MAX_AMOUNT_CHARS) {
      throw new SpendScopeError("amount is unreasonably long");
    }
    if (!AMOUNT_RE.test(text)) {
      throw new SpendScopeError(
        `amount must be a non-negative decimal like '25' or '9.99', got ${JSON.stringify(text)}`
      );
    }
    this.text = text;
  }

  /** Compare two amounts exactly: negative if a<b, 0 if equal, positive if a>b. */
  static compare(a: Amount, b: Amount): number {
    const [ai, af = ""] = a.text.split(".");
    const [bi, bf = ""] = b.text.split(".");
    const scale = Math.max(af.length, bf.length);
    const av = BigInt((ai ?? "0") + af.padEnd(scale, "0"));
    const bv = BigInt((bi ?? "0") + bf.padEnd(scale, "0"));
    return av < bv ? -1 : av > bv ? 1 : 0;
  }

  static min(a: Amount, b: Amount): Amount {
    return Amount.compare(a, b) <= 0 ? a : b;
  }

  toString(): string {
    return this.text;
  }
}

export function parseAmount(text: string): Amount {
  return new Amount(text);
}

function minCap(a: Amount | null, b: Amount | null): Amount | null {
  if (a === null) return b;
  if (b === null) return a;
  return Amount.min(a, b);
}

/** Parsed spend authority for one asset. `null` caps mean unlimited. */
export class SpendScope {
  readonly asset: string;
  readonly txCap: Amount | null;
  readonly totalCap: Amount | null;

  constructor(asset: string, txCap: Amount | null = null, totalCap: Amount | null = null) {
    this.asset = asset;
    this.txCap = txCap;
    this.totalCap = totalCap;
  }

  /** The scope string this authority spells as. */
  render(): string {
    const parts = [SPEND_PREFIX, this.asset];
    if (this.txCap !== null) parts.push(`${TX_CAP_PREFIX}${this.txCap.text}`);
    if (this.totalCap !== null) parts.push(`${TOTAL_CAP_PREFIX}${this.totalCap.text}`);
    return parts.join(":");
  }

  /** Compose two grants over the same asset: min of each cap. */
  intersect(other: SpendScope): SpendScope {
    if (this.asset !== other.asset) {
      throw new SpendScopeError(
        `cannot intersect spend scopes for different assets: ` +
          `${JSON.stringify(this.asset)} vs ${JSON.stringify(other.asset)}`
      );
    }
    return new SpendScope(
      this.asset,
      minCap(this.txCap, other.txCap),
      minCap(this.totalCap, other.totalCap)
    );
  }
}

/** True when a scope string is in the spend grammar (`pay:...`). */
export function isSpendScope(scope: unknown): scope is string {
  return typeof scope === "string" && scope.split(":", 1)[0] === SPEND_PREFIX;
}

/** Parse `pay:<asset>[:tx<=<amount>][:total<=<amount>]` or throw. */
export function parseSpendScope(scope: string): SpendScope {
  if (!isSpendScope(scope)) {
    throw new SpendScopeError(`not a spend scope: ${JSON.stringify(scope)}`);
  }
  const segments = scope.split(":");
  if (segments.length < 2 || !segments[1]) {
    throw new SpendScopeError(`spend scope is missing an asset: ${JSON.stringify(scope)}`);
  }
  const asset = segments[1];
  if (!ASSET_RE.test(asset)) {
    throw new SpendScopeError(`invalid asset token: ${JSON.stringify(asset)}`);
  }
  let txCap: Amount | null = null;
  let totalCap: Amount | null = null;
  for (const segment of segments.slice(2)) {
    if (segment.startsWith(TX_CAP_PREFIX)) {
      if (txCap !== null) {
        throw new SpendScopeError(`duplicate tx cap in scope: ${JSON.stringify(scope)}`);
      }
      txCap = parseAmount(segment.slice(TX_CAP_PREFIX.length));
    } else if (segment.startsWith(TOTAL_CAP_PREFIX)) {
      if (totalCap !== null) {
        throw new SpendScopeError(`duplicate total cap in scope: ${JSON.stringify(scope)}`);
      }
      totalCap = parseAmount(segment.slice(TOTAL_CAP_PREFIX.length));
    } else {
      throw new SpendScopeError(`unknown spend scope segment: ${JSON.stringify(segment)}`);
    }
  }
  return new SpendScope(asset, txCap, totalCap);
}

/** One grant's authority over `asset`, or null if it grants none. Several
 * spend scopes for the same asset within a grant intersect (narrower wins). */
export function spendAuthorityFor(
  scopes: Iterable<string>,
  asset: string
): SpendScope | null {
  let authority: SpendScope | null = null;
  for (const scope of scopes) {
    if (!isSpendScope(scope)) continue;
    const parsed = parseSpendScope(scope);
    if (parsed.asset !== asset) continue;
    authority = authority === null ? parsed : authority.intersect(parsed);
  }
  return authority;
}

/** Effective authority over `asset` down a chain of grants, root first. Any
 * link without a spend scope for the asset voids authority entirely. */
export function composeSpendAuthority(
  linksScopes: Iterable<Iterable<string>>,
  asset: string
): SpendScope | null {
  let effective: SpendScope | null = null;
  let sawLink = false;
  for (const scopes of linksScopes) {
    sawLink = true;
    const linkAuthority = spendAuthorityFor(scopes, asset);
    if (linkAuthority === null) return null;
    effective = effective === null ? linkAuthority : effective.intersect(linkAuthority);
  }
  return sawLink ? effective : null;
}

/** Chain-level spend verification: may this chain pay this amount now? */
export class SpendAuthority {
  /**
   * Check one prospective payment against a chain's composed caps. Authority
   * math only: the caller MUST have verified the chain itself first
   * (`DelegationChain.verify`) and supplies `spentSoFar` from its own ledger.
   * Throws `SpendScopeError` when the chain grants no authority over the
   * asset, the amount exceeds the per-transaction cap, or the cumulative
   * total would exceed the total cap. Returns the effective composed scope.
   */
  static verify(
    chain: DelegationChain,
    asset: string,
    amount: Amount | string,
    spentSoFar: Amount | string = "0"
  ): SpendScope {
    const amt = amount instanceof Amount ? amount : parseAmount(amount);
    const spent = spentSoFar instanceof Amount ? spentSoFar : parseAmount(spentSoFar);
    const effective = composeSpendAuthority(
      chain.links.map((link) => link.scopes),
      asset
    );
    if (effective === null) {
      throw new SpendScopeError(`chain grants no spend authority over ${JSON.stringify(asset)}`);
    }
    if (effective.txCap !== null && Amount.compare(amt, effective.txCap) > 0) {
      throw new SpendScopeError(
        `amount ${amt.text} exceeds per-transaction cap ${effective.txCap.text} ` +
          `for ${JSON.stringify(asset)}`
      );
    }
    if (effective.totalCap !== null) {
      // spent + amount, exact: scale both to the same fractional width.
      const total = addAmounts(spent, amt);
      if (Amount.compare(total, effective.totalCap) > 0) {
        throw new SpendScopeError(
          `amount ${amt.text} on top of ${spent.text} already spent exceeds ` +
            `total cap ${effective.totalCap.text} for ${JSON.stringify(asset)}`
        );
      }
    }
    return effective;
  }
}

/** Exact decimal addition of two non-negative Amounts. */
function addAmounts(a: Amount, b: Amount): Amount {
  const [ai, af = ""] = a.text.split(".");
  const [bi, bf = ""] = b.text.split(".");
  const scale = Math.max(af.length, bf.length);
  const av = BigInt((ai ?? "0") + af.padEnd(scale, "0"));
  const bv = BigInt((bi ?? "0") + bf.padEnd(scale, "0"));
  const sum = (av + bv).toString().padStart(scale + 1, "0");
  if (scale === 0) return new Amount(sum);
  const intPart = sum.slice(0, sum.length - scale);
  const fracPart = sum.slice(sum.length - scale);
  return new Amount(`${intPart}.${fracPart}`);
}
