/**
 * Key rotation with pre-rotation commitments (KERI-style). The stable name is
 * the inception address; a verifier replays the signed history to learn which
 * key is authoritative now. Conflicting records at one sequence are proof the
 * signing key leaked — the registry refuses to advance.
 */

import { addressFromSigningKey, signingKeyFromAddress } from "./address.js";
import { sha256Hex } from "./bytes.js";
import { type JsonValue } from "./canonical.js";
import { RotationError } from "./errors.js";
import { type KeyPair } from "./keys.js";
import { canonicalTimestamp, parseTimestamp, requireString } from "./serde.js";
import {
  CONTEXT_INCEPTION,
  CONTEXT_KEY_ROTATION,
  signPayload,
  signingInput,
  verifyByAddress,
} from "./signing.js";

/** The pre-rotation commitment for a signing key: sha256 hex of the raw key. */
export async function keyCommitment(signingPublic: Uint8Array): Promise<string> {
  if (signingPublic.length !== 32) {
    throw new RotationError("signing public key must be 32 raw bytes");
  }
  return sha256Hex(signingPublic);
}

/** The commitment a given address would satisfy. */
export async function commitmentForAddress(address: string): Promise<string> {
  return keyCommitment(signingKeyFromAddress(address));
}

/** The genesis record: an identity announcing itself and its next key. */
export class Inception {
  readonly address: string;
  readonly nextCommitment: string;
  readonly createdAt: Date;
  readonly signature: string;

  constructor(fields: {
    address: string;
    nextCommitment: string;
    createdAt: Date | string;
    signature?: string;
  }) {
    this.address = requireString("address", fields.address);
    this.nextCommitment = requireString("next_commitment", fields.nextCommitment);
    this.createdAt = parseTimestamp("created_at", fields.createdAt);
    this.signature = fields.signature ?? "";
  }

  payload(): Record<string, JsonValue> {
    return {
      address: this.address,
      created_at: canonicalTimestamp(this.createdAt),
      next_commitment: this.nextCommitment,
    };
  }

  static async create(keys: KeyPair, nextCommitment: string): Promise<Inception> {
    const unsigned = new Inception({
      address: addressFromSigningKey(keys.public_.signing),
      nextCommitment,
      createdAt: new Date(),
    });
    const signature = await signPayload(keys, CONTEXT_INCEPTION, unsigned.payload());
    return new Inception({
      address: unsigned.address,
      nextCommitment: unsigned.nextCommitment,
      createdAt: unsigned.createdAt,
      signature,
    });
  }

  async verify(): Promise<void> {
    try {
      await verifyByAddress(this.address, CONTEXT_INCEPTION, this.payload(), this.signature);
    } catch (error) {
      throw new RotationError(
        `invalid inception signature for ${this.address}: ${(error as Error).message}`
      );
    }
  }

  toJSON(): Record<string, JsonValue> {
    return {
      address: this.address,
      next_commitment: this.nextCommitment,
      created_at: canonicalTimestamp(this.createdAt),
      signature: this.signature,
    };
  }

  static fromJSON(data: unknown): Inception {
    if (data instanceof Inception) return data;
    const record = data as Record<string, unknown>;
    return new Inception({
      address: record["address"] as string,
      nextCommitment: record["next_commitment"] as string,
      createdAt: record["created_at"] as string,
      signature: (record["signature"] as string | undefined) ?? "",
    });
  }
}

/** One succession step, signed by the key currently in force. */
export class KeyRotation {
  readonly identity: string; // inception address — the identity's stable name
  readonly sequence: number; // 1-based, contiguous
  readonly previous: string; // address handing over (and the signer)
  readonly nextAddress: string; // must satisfy the standing commitment
  readonly nextCommitment: string; // commitment to the key after this one
  readonly rotatedAt: Date;
  readonly signature: string;

  constructor(fields: {
    identity: string;
    sequence: number;
    previous: string;
    nextAddress: string;
    nextCommitment: string;
    rotatedAt: Date | string;
    signature?: string;
  }) {
    this.identity = requireString("identity", fields.identity);
    if (!Number.isInteger(fields.sequence) || typeof fields.sequence !== "number") {
      throw new TypeError("sequence must be an integer");
    }
    if (fields.sequence < 1) throw new RotationError("rotation sequence starts at 1");
    this.sequence = fields.sequence;
    this.previous = requireString("previous", fields.previous);
    this.nextAddress = requireString("next_address", fields.nextAddress);
    this.nextCommitment = requireString("next_commitment", fields.nextCommitment);
    this.rotatedAt = parseTimestamp("rotated_at", fields.rotatedAt);
    this.signature = fields.signature ?? "";
  }

  payload(): Record<string, JsonValue> {
    return {
      identity: this.identity,
      next_address: this.nextAddress,
      next_commitment: this.nextCommitment,
      previous: this.previous,
      rotated_at: canonicalTimestamp(this.rotatedAt),
      sequence: this.sequence,
    };
  }

  /** Sign a rotation with the key currently in force. */
  static async create(options: {
    currentKeys: KeyPair;
    identity: string;
    sequence: number;
    nextAddress: string;
    nextCommitment: string;
  }): Promise<KeyRotation> {
    const unsigned = new KeyRotation({
      identity: options.identity,
      sequence: options.sequence,
      previous: addressFromSigningKey(options.currentKeys.public_.signing),
      nextAddress: options.nextAddress,
      nextCommitment: options.nextCommitment,
      rotatedAt: new Date(),
    });
    const signature = await signPayload(options.currentKeys, CONTEXT_KEY_ROTATION, unsigned.payload());
    return new KeyRotation({
      identity: unsigned.identity,
      sequence: unsigned.sequence,
      previous: unsigned.previous,
      nextAddress: unsigned.nextAddress,
      nextCommitment: unsigned.nextCommitment,
      rotatedAt: unsigned.rotatedAt,
      signature,
    });
  }

  async verifySignature(): Promise<void> {
    try {
      await verifyByAddress(this.previous, CONTEXT_KEY_ROTATION, this.payload(), this.signature);
    } catch (error) {
      throw new RotationError(
        `invalid rotation signature from ${this.previous}: ${(error as Error).message}`
      );
    }
  }

  toJSON(): Record<string, JsonValue> {
    return { ...this.payload(), signature: this.signature };
  }

  static fromJSON(data: unknown): KeyRotation {
    if (data instanceof KeyRotation) return data;
    const record = data as Record<string, unknown>;
    return new KeyRotation({
      identity: record["identity"] as string,
      sequence: record["sequence"] as number,
      previous: record["previous"] as string,
      nextAddress: record["next_address"] as string,
      nextCommitment: record["next_commitment"] as string,
      rotatedAt: record["rotated_at"] as string,
      signature: (record["signature"] as string | undefined) ?? "",
    });
  }
}

/** Where an identity stands after replaying its history. */
export interface RotationState {
  readonly identity: string;
  readonly currentAddress: string;
  readonly nextCommitment: string;
  readonly sequence: number; // 0 at inception
}

/** An identity's full key history: inception plus ordered rotations. */
export class RotationChain {
  readonly inception: Inception;
  readonly rotations: readonly KeyRotation[];

  constructor(inception: Inception | unknown, rotations: Iterable<KeyRotation | unknown> = []) {
    this.inception = Inception.fromJSON(inception);
    this.rotations = Object.freeze([...rotations].map((r) => KeyRotation.fromJSON(r)));
  }

  /** The stable name: the address this identity was born with. */
  get identity(): string {
    return this.inception.address;
  }

  /** Replay the history and return the currently authoritative state. */
  async resolve(): Promise<RotationState> {
    await this.inception.verify();
    let current = this.inception.address;
    let commitment = this.inception.nextCommitment;
    let sequence = 0;

    for (const rotation of this.rotations) {
      if (rotation.identity !== this.identity) {
        throw new RotationError(
          `rotation names identity ${rotation.identity}, expected ${this.identity}`
        );
      }
      if (rotation.sequence !== sequence + 1) {
        throw new RotationError(
          `rotation out of order: got sequence ${rotation.sequence}, expected ${sequence + 1}`
        );
      }
      if (rotation.previous !== current) {
        throw new RotationError(
          `rotation ${rotation.sequence} signed by ${rotation.previous}, but ${current} is in force`
        );
      }
      const revealed = await commitmentForAddress(rotation.nextAddress);
      if (revealed !== commitment) {
        throw new RotationError(
          `rotation ${rotation.sequence} reveals a key that does not match ` +
            "the standing pre-rotation commitment"
        );
      }
      await rotation.verifySignature();
      current = rotation.nextAddress;
      commitment = rotation.nextCommitment;
      sequence = rotation.sequence;
    }

    return {
      identity: this.identity,
      currentAddress: current,
      nextCommitment: commitment,
      sequence,
    };
  }

  /** Append a rotation, verifying the extended chain before returning it. */
  async extend(rotation: KeyRotation): Promise<RotationChain> {
    const extended = new RotationChain(this.inception, [...this.rotations, rotation]);
    await extended.resolve();
    return extended;
  }

  toJSON(): Record<string, JsonValue> {
    return {
      inception: this.inception.toJSON(),
      rotations: this.rotations.map((r) => r.toJSON()),
    };
  }

  static fromJSON(data: unknown): RotationChain {
    if (data instanceof RotationChain) return data;
    const record = data as Record<string, unknown>;
    return new RotationChain(record["inception"], (record["rotations"] as unknown[]) ?? []);
  }
}

/**
 * A verifier's view of which key is authoritative for each identity. Refuses
 * to move backwards, and treats two conflicting records at one sequence
 * (inception included, at sequence 0) as proof of compromise — it records the
 * conflict and refuses to advance rather than silently preferring a history.
 */
export class RotationRegistry {
  private readonly states = new Map<string, RotationState>();
  /** `${identity} ${sequence}` -> fingerprint of the record seen there. */
  private readonly seen = new Map<string, string>();
  private readonly duplicity = new Map<string, (Inception | KeyRotation)[]>();

  private static async rotationFingerprint(rotation: KeyRotation): Promise<string> {
    return sha256Hex(signingInput(CONTEXT_KEY_ROTATION, rotation.payload()));
  }

  private static async inceptionFingerprint(inception: Inception): Promise<string> {
    return sha256Hex(signingInput(CONTEXT_INCEPTION, inception.payload()));
  }

  /** Verify a chain and adopt it if it advances what we already know. */
  async learn(chain: RotationChain): Promise<RotationState> {
    const state = await chain.resolve(); // verify before mutating anything
    const identity = state.identity;

    const steps: { sequence: number; fingerprint: string; record: Inception | KeyRotation }[] = [
      {
        sequence: 0,
        fingerprint: await RotationRegistry.inceptionFingerprint(chain.inception),
        record: chain.inception,
      },
      ...(await Promise.all(
        chain.rotations.map(async (r) => ({
          sequence: r.sequence,
          fingerprint: await RotationRegistry.rotationFingerprint(r),
          record: r as Inception | KeyRotation,
        }))
      )),
    ];

    for (const step of steps) {
      const key = `${identity} ${step.sequence}`;
      const established = this.seen.get(key);
      if (established !== undefined && established !== step.fingerprint) {
        // Record the evidence; do not apply any part of this chain.
        const evidence = this.duplicity.get(identity) ?? [];
        if (!evidence.includes(step.record)) evidence.push(step.record);
        this.duplicity.set(identity, evidence);
        throw new RotationError(
          `conflicting records at sequence ${step.sequence} for ${identity} — ` +
            "the signing key is compromised; refusing to advance"
        );
      }
    }

    for (const step of steps) {
      this.seen.set(`${identity} ${step.sequence}`, step.fingerprint);
    }

    const known = this.states.get(identity);
    if (known === undefined || state.sequence > known.sequence) {
      this.states.set(identity, state);
      return state;
    }
    return known;
  }

  /**
   * The address currently authoritative for `identity`. Fails closed on a
   * proven-compromised identity; falls back to the identity itself when no
   * rotation history is known.
   */
  resolve(identity: string): string {
    if (this.duplicity.has(identity)) {
      throw new RotationError(
        `${identity} is compromised — conflicting records proved the signing ` +
          "key leaked; refusing to resolve a trusted address"
      );
    }
    return this.states.get(identity)?.currentAddress ?? identity;
  }

  /** Known rotation state, or null if this identity's history is unknown. */
  state(identity: string): RotationState | null {
    return this.states.get(identity) ?? null;
  }

  /** True once conflicting records proved the signing key leaked. */
  isDuplicitous(identity: string): boolean {
    return this.duplicity.has(identity);
  }

  duplicityEvidence(identity: string): readonly (Inception | KeyRotation)[] {
    return [...(this.duplicity.get(identity) ?? [])];
  }
}
