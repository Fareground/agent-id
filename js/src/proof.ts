/**
 * Proof of possession: audience- and purpose-bound challenge-response. A
 * response is signed over {address, audience, challenge_id, nonce, purpose},
 * so a proof gathered by one verifier cannot be replayed to another.
 */

import { base64Decode, base64Encode } from "./bytes.js";
import { type JsonValue } from "./canonical.js";
import { SignatureError } from "./errors.js";
import { type KeyPair } from "./keys.js";
import { canonicalTimestamp, parseTimestamp, requireString } from "./serde.js";
import { CONTEXT_CHALLENGE_RESPONSE, signPayload, verifyByAddress } from "./signing.js";

export const NONCE_BYTES = 32;
export const DEFAULT_TTL_SECONDS = 120;
export const PURPOSE_AUTHENTICATE = "authenticate";

/** A verifier-issued, single-use, audience-scoped challenge (not signed). */
export class Challenge {
  readonly challengeId: string;
  readonly nonce: string; // base64 of >= NONCE_BYTES random bytes
  readonly audience: string;
  readonly purpose: string;
  readonly issuedAt: Date;
  readonly expiresAt: Date;

  constructor(fields: {
    challengeId: string;
    nonce: string;
    audience: string;
    purpose: string;
    issuedAt: Date | string;
    expiresAt: Date | string;
  }) {
    this.challengeId = requireString("challenge_id", fields.challengeId);
    this.nonce = requireString("nonce", fields.nonce);
    this.audience = requireString("audience", fields.audience);
    this.purpose = requireString("purpose", fields.purpose);
    if (!this.audience) {
      throw new Error("audience must not be empty — it is the replay defense");
    }
    this.issuedAt = parseTimestamp("issued_at", fields.issuedAt);
    this.expiresAt = parseTimestamp("expires_at", fields.expiresAt);
    if (this.nonceBytes().length < NONCE_BYTES) {
      throw new Error(`nonce must be at least ${NONCE_BYTES} bytes`);
    }
  }

  nonceBytes(): Uint8Array {
    try {
      return base64Decode(this.nonce);
    } catch {
      throw new Error("nonce is not valid base64");
    }
  }

  static issue(
    audience: string,
    purpose: string = PURPOSE_AUTHENTICATE,
    ttlSeconds: number = DEFAULT_TTL_SECONDS
  ): Challenge {
    const now = new Date();
    return new Challenge({
      challengeId: crypto.randomUUID(),
      nonce: base64Encode(crypto.getRandomValues(new Uint8Array(NONCE_BYTES))),
      audience,
      purpose,
      issuedAt: now,
      expiresAt: new Date(now.getTime() + ttlSeconds * 1000),
    });
  }

  isExpired(now?: Date): boolean {
    return (now ?? new Date()).getTime() >= this.expiresAt.getTime();
  }

  /** Agent side: sign this challenge, binding the response to its audience. */
  async respond(keys: KeyPair, address: string): Promise<ChallengeResponse> {
    return ChallengeResponse.create(keys, address, this);
  }

  toJSON(): Record<string, JsonValue> {
    return {
      challenge_id: this.challengeId,
      nonce: this.nonce,
      audience: this.audience,
      purpose: this.purpose,
      issued_at: canonicalTimestamp(this.issuedAt),
      expires_at: canonicalTimestamp(this.expiresAt),
    };
  }

  static fromJSON(data: unknown): Challenge {
    const record = data as Record<string, unknown>;
    return new Challenge({
      challengeId: record["challenge_id"] as string,
      nonce: record["nonce"] as string,
      audience: record["audience"] as string,
      purpose: (record["purpose"] as string | undefined) ?? PURPOSE_AUTHENTICATE,
      issuedAt: record["issued_at"] as string,
      expiresAt: record["expires_at"] as string,
    });
  }
}

/** An agent's signed answer, bound to the challenge AND its audience. */
export class ChallengeResponse {
  readonly challengeId: string;
  readonly address: string;
  readonly audience: string;
  readonly purpose: string;
  readonly nonce: string;
  readonly signature: string;

  constructor(fields: {
    challengeId: string;
    address: string;
    audience: string;
    purpose: string;
    nonce: string;
    signature?: string;
  }) {
    this.challengeId = requireString("challenge_id", fields.challengeId);
    this.address = requireString("address", fields.address);
    this.audience = requireString("audience", fields.audience);
    this.purpose = requireString("purpose", fields.purpose);
    this.nonce = requireString("nonce", fields.nonce);
    this.signature = requireString("signature", fields.signature ?? "");
  }

  payload(): Record<string, JsonValue> {
    return {
      address: this.address,
      audience: this.audience,
      challenge_id: this.challengeId,
      nonce: this.nonce,
      purpose: this.purpose,
    };
  }

  static async create(
    keys: KeyPair,
    address: string,
    challenge: Challenge
  ): Promise<ChallengeResponse> {
    const unsigned = new ChallengeResponse({
      challengeId: challenge.challengeId,
      address,
      audience: challenge.audience,
      purpose: challenge.purpose,
      nonce: challenge.nonce,
    });
    const signature = await signPayload(keys, CONTEXT_CHALLENGE_RESPONSE, unsigned.payload());
    return new ChallengeResponse({ ...unsigned, challengeId: unsigned.challengeId, signature });
  }

  /**
   * Verify against the issued challenge. `audience` is the verifier's OWN
   * identifier and must be supplied by the verifier, never read off the
   * response. Returns the proven address. Single-use enforcement is the
   * caller's job (consume the challenge from a shared store first).
   */
  async verify(challenge: Challenge, audience: string, now?: Date): Promise<string> {
    if (!audience) throw new SignatureError("verifier must supply its own audience");
    if (this.audience !== audience) {
      throw new SignatureError(
        `response is addressed to ${JSON.stringify(this.audience)}, not ${JSON.stringify(audience)}`
      );
    }
    if (challenge.audience !== audience) {
      throw new SignatureError("challenge was not issued for this audience");
    }
    if (this.challengeId !== challenge.challengeId) {
      throw new SignatureError("response does not match the issued challenge");
    }
    if (this.nonce !== challenge.nonce) {
      throw new SignatureError("response nonce does not match the issued challenge");
    }
    if (this.purpose !== challenge.purpose) {
      throw new SignatureError("response purpose does not match the issued challenge");
    }
    if (challenge.isExpired(now)) {
      throw new SignatureError("challenge has expired");
    }
    await verifyByAddress(this.address, CONTEXT_CHALLENGE_RESPONSE, this.payload(), this.signature);
    return this.address;
  }

  toJSON(): Record<string, JsonValue> {
    return { ...this.payload(), signature: this.signature };
  }

  static fromJSON(data: unknown): ChallengeResponse {
    const record = data as Record<string, unknown>;
    return new ChallengeResponse({
      challengeId: record["challenge_id"] as string,
      address: record["address"] as string,
      audience: record["audience"] as string,
      purpose: (record["purpose"] as string | undefined) ?? PURPOSE_AUTHENTICATE,
      nonce: record["nonce"] as string,
      signature: (record["signature"] as string | undefined) ?? "",
    });
  }
}

/**
 * Single-use challenge storage for one process. Consumption pops, so a nonce
 * can never be spent twice. Multi-worker deployments must back this with a
 * shared store offering an atomic consume.
 */
export class ChallengeStore {
  private readonly entries = new Map<string, { deadline: number; challenge: Challenge }>();

  constructor(private readonly ttlSeconds: number = DEFAULT_TTL_SECONDS) {}

  issue(audience: string, purpose: string = PURPOSE_AUTHENTICATE): Challenge {
    this.prune();
    const challenge = Challenge.issue(audience, purpose, this.ttlSeconds);
    this.entries.set(challenge.challengeId, {
      deadline: Date.now() + this.ttlSeconds * 1000,
      challenge,
    });
    return challenge;
  }

  /** Pop a challenge. Returns null if unknown, already used, or expired. */
  consume(challengeId: string): Challenge | null {
    this.prune();
    const entry = this.entries.get(challengeId);
    if (!entry) return null;
    this.entries.delete(challengeId);
    return entry.challenge;
  }

  get size(): number {
    this.prune();
    return this.entries.size;
  }

  private prune(): void {
    const now = Date.now();
    for (const [key, entry] of this.entries) {
      if (entry.deadline <= now) this.entries.delete(key);
    }
  }
}
