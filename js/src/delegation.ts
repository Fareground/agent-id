/**
 * Delegation credentials: who authorized this agent, to do what, until when.
 * Chains compose root-first; effective scopes are the intersection of every
 * link. Includes Revocation / KeyRevocation and a freshness-aware registry.
 */

import { concatBytes, sha256Hex } from "./bytes.js";
import { type JsonValue } from "./canonical.js";
import { enforceCritical, parseCritical } from "./critical.js";
import { DelegationError, SignatureError } from "./errors.js";
import { type KeyPair } from "./keys.js";
import { canonicalTimestamp, parseTimestamp, requireString } from "./serde.js";
import {
  CONTEXT_DELEGATION,
  CONTEXT_KEY_REVOCATION,
  CONTEXT_REVOCATION,
  decodeSignature,
  signPayload,
  signingInput,
  verifyByAddress,
} from "./signing.js";

const DELEGATION_KNOWN_FIELDS: ReadonlySet<string> = new Set([
  "issuer",
  "subject",
  "scopes",
  "issued_at",
  "expires_at",
  "critical",
  "signature",
]);

/** A single signed grant. `issuer`/`subject` are agent addresses. */
export class Delegation {
  readonly issuer: string;
  readonly subject: string;
  readonly scopes: ReadonlySet<string>;
  readonly issuedAt: Date;
  readonly expiresAt: Date;
  readonly critical: readonly string[] | undefined;
  readonly signature: string;
  /** Unknown wire fields, preserved and included in the signed payload. */
  readonly extra: Readonly<Record<string, JsonValue>>;

  constructor(fields: {
    issuer: string;
    subject: string;
    scopes: Iterable<string>;
    issuedAt: Date | string;
    expiresAt: Date | string;
    critical?: readonly string[];
    signature?: string;
    extra?: Readonly<Record<string, JsonValue>>;
  }) {
    this.issuer = requireString("issuer", fields.issuer);
    this.subject = requireString("subject", fields.subject);
    this.scopes = new Set(fields.scopes);
    this.issuedAt = parseTimestamp("issued_at", fields.issuedAt);
    this.expiresAt = parseTimestamp("expires_at", fields.expiresAt);
    this.critical = fields.critical ? Object.freeze([...fields.critical]) : undefined;
    this.signature = fields.signature ?? "";
    const extra = { ...(fields.extra ?? {}) };
    const shadowed = Object.keys(extra).filter((k) => DELEGATION_KNOWN_FIELDS.has(k));
    if (shadowed.length > 0) {
      throw new Error(
        `extra must not shadow known delegation fields: ${shadowed.sort().join(", ")}`
      );
    }
    this.extra = Object.freeze(extra);
    // A critical marker must name a field that is actually present, or it
    // "protects" nothing — mirrors the Python reference's dangling-name check.
    if (this.critical) {
      const dangling = this.critical.filter((name) => !(name in extra));
      if (dangling.length > 0) {
        throw new Error(
          `critical names extension fields not present on the delegation: ` +
            `${dangling.sort().join(", ")}`
        );
      }
    }
  }

  payload(): Record<string, JsonValue> {
    const data: Record<string, JsonValue> = {
      issuer: this.issuer,
      subject: this.subject,
      scopes: [...this.scopes].sort(),
      issued_at: canonicalTimestamp(this.issuedAt),
      expires_at: canonicalTimestamp(this.expiresAt),
    };
    if (this.critical) data["critical"] = [...this.critical];
    Object.assign(data, this.extra);
    return data;
  }

  static async grant(options: {
    issuerKeys: KeyPair;
    issuerAddress: string;
    subjectAddress: string;
    scopes: Iterable<string>;
    ttlSeconds: number;
    critical?: readonly string[];
    extra?: Readonly<Record<string, JsonValue>>;
  }): Promise<Delegation> {
    const now = new Date();
    const unsigned = new Delegation({
      issuer: options.issuerAddress,
      subject: options.subjectAddress,
      scopes: options.scopes,
      issuedAt: now,
      expiresAt: new Date(now.getTime() + options.ttlSeconds * 1000),
      critical: options.critical,
      extra: options.extra,
    });
    const signature = await signPayload(options.issuerKeys, CONTEXT_DELEGATION, unsigned.payload());
    return unsigned.with({ signature });
  }

  /**
   * Stable identifier for this exact grant (used for revocation):
   * sha256(signing_input || decoded_signature) hex. Hashes the DECODED
   * signature so alternate base64 spellings cannot dodge a revocation.
   */
  async digest(): Promise<string> {
    const signed = signingInput(CONTEXT_DELEGATION, this.payload());
    return sha256Hex(concatBytes(signed, decodeSignature(this.signature)));
  }

  /**
   * Check signature and (by default) expiry. `checkValidityWindow: false`
   * verifies only the signature — for proving a past delegation relationship
   * (owner recall of a compromised key).
   */
  async verify(
    now?: Date,
    options: {
      checkValidityWindow?: boolean;
      leewaySeconds?: number;
      understoodExtensions?: Iterable<string>;
    } = {}
  ): Promise<void> {
    enforceCritical(this.critical, DELEGATION_KNOWN_FIELDS, options.understoodExtensions ?? []);
    const at = now ?? new Date();
    if (options.checkValidityWindow ?? true) {
      // Tolerate issuer/verifier clock skew on both edges of the window.
      const leewayMs = Math.max(0, options.leewaySeconds ?? 0) * 1000;
      if (at.getTime() - leewayMs >= this.expiresAt.getTime()) {
        throw new DelegationError(
          `delegation from ${this.issuer} expired at ${canonicalTimestamp(this.expiresAt)}`
        );
      }
      if (at.getTime() + leewayMs < this.issuedAt.getTime()) {
        throw new DelegationError("delegation issued in the future");
      }
    }
    try {
      await verifyByAddress(this.issuer, CONTEXT_DELEGATION, this.payload(), this.signature);
    } catch (error) {
      throw new DelegationError(
        `invalid delegation signature from ${this.issuer}: ${(error as Error).message}`
      );
    }
  }

  toJSON(): Record<string, JsonValue> {
    return { ...this.payload(), signature: this.signature };
  }

  static fromJSON(data: unknown): Delegation {
    if (data instanceof Delegation) return data;
    const record = data as Record<string, unknown>;
    const extra: Record<string, JsonValue> = {};
    for (const [key, value] of Object.entries(record)) {
      if (!DELEGATION_KNOWN_FIELDS.has(key) && key !== "extra") {
        extra[key] = value as JsonValue;
      }
    }
    return new Delegation({
      issuer: record["issuer"] as string,
      subject: record["subject"] as string,
      scopes: (record["scopes"] as string[]) ?? [],
      issuedAt: record["issued_at"] as string,
      expiresAt: record["expires_at"] as string,
      critical: parseCritical(record["critical"]),
      signature: (record["signature"] as string | undefined) ?? "",
      extra,
    });
  }

  with(update: { signature?: string }): Delegation {
    return new Delegation({
      issuer: this.issuer,
      subject: this.subject,
      scopes: this.scopes,
      issuedAt: this.issuedAt,
      expiresAt: this.expiresAt,
      critical: this.critical,
      signature: update.signature ?? this.signature,
      extra: this.extra,
    });
  }
}

/** A signed early recall of a specific delegation by its original issuer. */
export class Revocation {
  readonly issuer: string;
  readonly delegationDigest: string;
  readonly revokedAt: Date;
  readonly signature: string;

  constructor(fields: {
    issuer: string;
    delegationDigest: string;
    revokedAt: Date | string;
    signature?: string;
  }) {
    this.issuer = requireString("issuer", fields.issuer);
    this.delegationDigest = requireString("delegation_digest", fields.delegationDigest);
    this.revokedAt = parseTimestamp("revoked_at", fields.revokedAt);
    this.signature = fields.signature ?? "";
  }

  payload(): Record<string, JsonValue> {
    return {
      issuer: this.issuer,
      delegation_digest: this.delegationDigest,
      revoked_at: canonicalTimestamp(this.revokedAt),
    };
  }

  static async revoke(issuerKeys: KeyPair, delegation: Delegation): Promise<Revocation> {
    const unsigned = new Revocation({
      issuer: delegation.issuer,
      delegationDigest: await delegation.digest(),
      revokedAt: new Date(),
    });
    const signature = await signPayload(issuerKeys, CONTEXT_REVOCATION, unsigned.payload());
    return new Revocation({ ...unsigned.asFields(), signature });
  }

  /** Only the original issuer's key may revoke its own grant. */
  async verify(): Promise<void> {
    try {
      await verifyByAddress(this.issuer, CONTEXT_REVOCATION, this.payload(), this.signature);
    } catch (error) {
      throw new DelegationError(
        `invalid revocation signature from ${this.issuer}: ${(error as Error).message}`
      );
    }
  }

  asFields() {
    return {
      issuer: this.issuer,
      delegationDigest: this.delegationDigest,
      revokedAt: this.revokedAt,
      signature: this.signature,
    };
  }

  toJSON(): Record<string, JsonValue> {
    return { ...this.payload(), signature: this.signature };
  }

  static fromJSON(data: unknown): Revocation {
    const record = data as Record<string, unknown>;
    return new Revocation({
      issuer: record["issuer"] as string,
      delegationDigest: record["delegation_digest"] as string,
      revokedAt: record["revoked_at"] as string,
      signature: (record["signature"] as string | undefined) ?? "",
    });
  }
}

/** Ordered grants, root first. Each link's subject must issue the next link. */
export class DelegationChain {
  readonly links: readonly Delegation[];

  constructor(links: Iterable<Delegation | unknown> = []) {
    this.links = Object.freeze([...links].map((link) => Delegation.fromJSON(link)));
  }

  /**
   * Verify every link and the chain topology; returns the effective scopes
   * (intersection of all links). An empty chain verifies to no scopes.
   */
  async verify(
    agentAddress: string,
    options: {
      now?: Date;
      revoked?: ReadonlySet<string>;
      revokedKeys?: ReadonlySet<string>;
      checkValidityWindow?: boolean;
      leewaySeconds?: number;
      understoodExtensions?: Iterable<string>;
    } = {}
  ): Promise<ReadonlySet<string>> {
    if (this.links.length === 0) return new Set();
    const revoked = options.revoked ?? new Set<string>();
    const revokedKeys = options.revokedKeys ?? new Set<string>();
    const understood = new Set(options.understoodExtensions ?? []);
    let effective: Set<string> | null = null;
    for (let i = 0; i < this.links.length; i++) {
      const link = this.links[i]!;
      await link.verify(options.now, {
        checkValidityWindow: options.checkValidityWindow ?? true,
        leewaySeconds: options.leewaySeconds,
        understoodExtensions: understood,
      });
      if (revoked.has(await link.digest())) {
        throw new DelegationError(
          `delegation from ${link.issuer} to ${link.subject} has been revoked`
        );
      }
      if (revokedKeys.has(link.issuer) || revokedKeys.has(link.subject)) {
        const which = revokedKeys.has(link.issuer) ? link.issuer : link.subject;
        throw new DelegationError(`delegation touches revoked identity key (${which})`);
      }
      if (i > 0 && link.issuer !== this.links[i - 1]!.subject) {
        throw new DelegationError(
          `broken chain: link ${i} issued by ${link.issuer}, expected ${this.links[i - 1]!.subject}`
        );
      }
      const kept: string[] =
        effective === null ? [...link.scopes] : [...effective].filter((s) => link.scopes.has(s));
      effective = new Set(kept);
    }
    const last = this.links[this.links.length - 1]!;
    if (last.subject !== agentAddress) {
      throw new DelegationError(
        `chain terminates at ${last.subject}, not agent ${agentAddress}`
      );
    }
    return effective ?? new Set();
  }

  get rootIssuer(): string | null {
    return this.links.length > 0 ? this.links[0]!.issuer : null;
  }

  toJSON(): Record<string, JsonValue> {
    return { links: this.links.map((link) => link.toJSON()) };
  }

  static fromJSON(data: unknown): DelegationChain {
    if (data instanceof DelegationChain) return data;
    const record = data as Record<string, unknown>;
    return new DelegationChain((record["links"] as unknown[]) ?? []);
  }
}

/**
 * Revokes an agent's IDENTITY key. Honored when self-signed by the revoked
 * key, or when carrying a delegation `chain` proving the issuer roots a chain
 * terminating at the revoked address (expiry deliberately not applied there).
 */
export class KeyRevocation {
  readonly address: string;
  readonly issuer: string;
  readonly revokedAt: Date;
  readonly chain: DelegationChain | null;
  readonly signature: string;

  constructor(fields: {
    address: string;
    issuer: string;
    revokedAt: Date | string;
    chain?: DelegationChain | null;
    signature?: string;
  }) {
    this.address = requireString("address", fields.address);
    this.issuer = requireString("issuer", fields.issuer);
    this.revokedAt = parseTimestamp("revoked_at", fields.revokedAt);
    this.chain = fields.chain ?? null;
    this.signature = fields.signature ?? "";
  }

  payload(): Record<string, JsonValue> {
    return {
      address: this.address,
      chain: this.chain === null ? null : this.chain.toJSON(),
      issuer: this.issuer,
      revoked_at: canonicalTimestamp(this.revokedAt),
    };
  }

  static async create(options: {
    issuerKeys: KeyPair;
    issuer: string;
    address: string;
    chain?: DelegationChain | null;
  }): Promise<KeyRevocation> {
    const unsigned = new KeyRevocation({
      address: options.address,
      issuer: options.issuer,
      chain: options.chain ?? null,
      revokedAt: new Date(),
    });
    const signature = await signPayload(
      options.issuerKeys,
      CONTEXT_KEY_REVOCATION,
      unsigned.payload()
    );
    return new KeyRevocation({
      address: unsigned.address,
      issuer: unsigned.issuer,
      chain: unsigned.chain,
      revokedAt: unsigned.revokedAt,
      signature,
    });
  }

  /** Signature valid AND the issuer is entitled to revoke this address. */
  async verify(): Promise<void> {
    try {
      await verifyByAddress(this.issuer, CONTEXT_KEY_REVOCATION, this.payload(), this.signature);
    } catch (error) {
      throw new DelegationError(
        `invalid key-revocation signature from ${this.issuer}: ${(error as Error).message}`
      );
    }
    if (this.issuer === this.address) return; // self-revocation is always honorable
    if (this.chain === null) {
      throw new DelegationError("owner key-revocation must include a proof chain");
    }
    // Criticality MUST NOT block owner recall: rejecting a recall over an
    // un-understood extension would keep a compromised key trusted — the
    // opposite of the marker's intent. Treat every critical field named
    // anywhere in the proof chain as understood for this verification, so a
    // critical marker cannot veto the revocation. Mirrors the Python
    // reference (delegation.py: chain_critical union).
    const chainCritical = new Set<string>();
    for (const link of this.chain.links) {
      for (const name of link.critical ?? []) chainCritical.add(name);
    }
    await this.chain.verify(this.address, {
      checkValidityWindow: false,
      understoodExtensions: chainCritical,
    });
    if (this.chain.rootIssuer !== this.issuer) {
      throw new DelegationError("key-revocation chain does not root at the issuer");
    }
  }

  toJSON(): Record<string, JsonValue> {
    return {
      address: this.address,
      issuer: this.issuer,
      chain: this.chain === null ? null : this.chain.toJSON(),
      revoked_at: canonicalTimestamp(this.revokedAt),
      signature: this.signature,
    };
  }

  static fromJSON(data: unknown): KeyRevocation {
    const record = data as Record<string, unknown>;
    const chain = record["chain"];
    return new KeyRevocation({
      address: record["address"] as string,
      issuer: record["issuer"] as string,
      chain: chain === null || chain === undefined ? null : DelegationChain.fromJSON(chain),
      revokedAt: record["revoked_at"] as string,
      signature: (record["signature"] as string | undefined) ?? "",
    });
  }
}

/**
 * A node's known revocations. Entries are verified before admission, and the
 * registry tracks when it last synced so callers can fail closed on staleness
 * — "no revocation found" and "no revocation data" are different answers.
 */
export class RevocationRegistry {
  private readonly digests_ = new Set<string>();
  private readonly revokedKeys_ = new Set<string>();
  private syncedAt_: Date | null;

  constructor(syncedAt: Date | null = null) {
    this.syncedAt_ = syncedAt;
  }

  async add(revocation: Revocation): Promise<void> {
    await revocation.verify();
    this.digests_.add(revocation.delegationDigest);
  }

  async revokeKey(revocation: KeyRevocation): Promise<void> {
    await revocation.verify();
    this.revokedKeys_.add(revocation.address);
  }

  markSynced(when?: Date): void {
    this.syncedAt_ = when ?? new Date();
  }

  get syncedAt(): Date | null {
    return this.syncedAt_;
  }

  ageSeconds(now?: Date): number | null {
    if (this.syncedAt_ === null) return null;
    return ((now ?? new Date()).getTime() - this.syncedAt_.getTime()) / 1000;
  }

  /** True when this registry is too old to be trusted (never synced counts). */
  isStale(maxAgeSeconds: number, now?: Date): boolean {
    const age = this.ageSeconds(now);
    return age === null || age > maxAgeSeconds;
  }

  /** Fail closed when the registry is too stale to answer safely. */
  requireFresh(maxAgeSeconds: number, now?: Date): void {
    if (this.isStale(maxAgeSeconds, now)) {
      const age = this.ageSeconds(now);
      const detail = age === null ? "never synced" : `last synced ${Math.round(age)}s ago`;
      throw new DelegationError(
        `revocation data is stale (${detail}, limit ${Math.round(maxAgeSeconds)}s)`
      );
    }
  }

  /** True if this exact grant was revoked. Malformed signatures answer false. */
  async isRevoked(delegation: Delegation): Promise<boolean> {
    try {
      return this.digests_.has(await delegation.digest());
    } catch (error) {
      if (error instanceof SignatureError) return false;
      throw error;
    }
  }

  isKeyRevoked(address: string): boolean {
    return this.revokedKeys_.has(address);
  }

  get digests(): ReadonlySet<string> {
    return new Set(this.digests_);
  }

  get revokedKeys(): ReadonlySet<string> {
    return new Set(this.revokedKeys_);
  }
}
