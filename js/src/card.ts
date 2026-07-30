/**
 * AgentCard: the signed, publishable description of an agent. Unknown fields
 * are preserved and signed (`extra`), so a newer card carrying extension
 * fields still verifies here — and a `critical` list makes chosen extensions
 * understood-or-rejected (see critical.ts).
 */

import { signingKeyFromAddress } from "./address.js";
import { base58Decode } from "./base58.js";
import { bytesEqual } from "./bytes.js";
import { type JsonValue } from "./canonical.js";
import { enforceCritical, parseCritical } from "./critical.js";
import { SignatureError } from "./errors.js";
import { KeyPair, PublicKeys } from "./keys.js";
import { requireMapping, requireString } from "./serde.js";
import { CONTEXT_AGENT_CARD, signPayload, verifyPayload } from "./signing.js";

export const DEFAULT_PROTOCOL_VERSION = "0.1";

export type ParticipantKind = "agent" | "human" | "service";

const KINDS: ReadonlySet<string> = new Set(["agent", "human", "service"]);

const KNOWN_FIELDS: ReadonlySet<string> = new Set([
  "amp",
  "address",
  "name",
  "kind",
  "operator",
  "signing_key",
  "agreement_key",
  "agreement_prekey",
  "payload_types",
  "endpoints",
  "policy_summary",
  "critical",
  "signature",
]);

export interface AgentCardFields {
  amp?: string;
  address: string;
  name: string;
  kind?: ParticipantKind;
  operator?: string | null;
  signing_key: string;
  agreement_key: string;
  agreement_prekey?: string | null;
  payload_types?: readonly string[];
  endpoints?: Readonly<Record<string, string>>;
  policy_summary?: string;
  critical?: readonly string[];
  signature?: string;
  extra?: Readonly<Record<string, JsonValue>>;
}

export class AgentCard {
  readonly amp: string;
  readonly address: string;
  readonly name: string;
  readonly kind: ParticipantKind;
  readonly operator: string | null;
  readonly signing_key: string;
  readonly agreement_key: string;
  readonly agreement_prekey: string | null;
  readonly payload_types: readonly string[];
  readonly endpoints: Readonly<Record<string, string>>;
  readonly policy_summary: string;
  readonly critical: readonly string[] | undefined;
  readonly signature: string;
  /** Unknown wire fields, preserved and included in the signed payload. */
  readonly extra: Readonly<Record<string, JsonValue>>;

  constructor(fields: AgentCardFields) {
    this.amp = fields.amp ?? DEFAULT_PROTOCOL_VERSION;
    this.address = requireString("address", fields.address);
    this.name = requireString("name", fields.name);
    const kind = fields.kind ?? "agent";
    if (!KINDS.has(kind)) throw new Error(`unknown participant kind: ${kind}`);
    this.kind = kind;
    this.operator = fields.operator ?? null;
    this.signing_key = requireString("signing_key", fields.signing_key);
    this.agreement_key = requireString("agreement_key", fields.agreement_key);
    this.agreement_prekey = fields.agreement_prekey ?? null;
    this.payload_types = Object.freeze([...(fields.payload_types ?? ["text/plain", "application/json"])]);
    this.endpoints = Object.freeze({ ...(fields.endpoints ?? {}) });
    this.policy_summary = fields.policy_summary ?? "";
    this.critical = fields.critical ? Object.freeze([...fields.critical]) : undefined;
    this.signature = fields.signature ?? "";
    const extra = { ...(fields.extra ?? {}) };
    const shadowed = Object.keys(extra).filter((k) => KNOWN_FIELDS.has(k));
    if (shadowed.length > 0) {
      throw new Error(`extra must not shadow known card fields: ${shadowed.sort().join(", ")}`);
    }
    this.extra = Object.freeze(extra);
  }

  /** The signed view of this card: everything except the signature. */
  payload(): Record<string, JsonValue> {
    const data = this.toJSON();
    delete data["signature"];
    return data;
  }

  static async create(options: {
    keys: KeyPair;
    address: string;
    name: string;
    kind?: ParticipantKind;
    operator?: string | null;
    payloadTypes?: readonly string[];
    endpoints?: Readonly<Record<string, string>>;
    policySummary?: string;
    agreementPrekey?: string | null;
    critical?: readonly string[];
    extra?: Readonly<Record<string, JsonValue>>;
    protocolVersion?: string;
  }): Promise<AgentCard> {
    const publicKeys = options.keys.public_;
    const unsigned = new AgentCard({
      amp: options.protocolVersion ?? DEFAULT_PROTOCOL_VERSION,
      address: options.address,
      name: options.name,
      kind: options.kind,
      operator: options.operator ?? null,
      signing_key: publicKeys.signingB58,
      agreement_key: publicKeys.agreementB58,
      agreement_prekey: options.agreementPrekey ?? null,
      payload_types: options.payloadTypes,
      endpoints: options.endpoints,
      policy_summary: options.policySummary ?? "",
      critical: options.critical,
      extra: options.extra,
    });
    const signature = await signPayload(options.keys, CONTEXT_AGENT_CARD, unsigned.payload());
    return unsigned.with({ signature });
  }

  /**
   * Card must be signed by the key its address certifies, and every field it
   * marks critical must be understood (`understoodExtensions` names extension
   * fields the caller handles itself).
   */
  async verify(understoodExtensions: Iterable<string> = []): Promise<void> {
    enforceCritical(this.critical, KNOWN_FIELDS, understoodExtensions);
    const addressKey = signingKeyFromAddress(this.address);
    const declaredKey = base58Decode(this.signing_key);
    if (!bytesEqual(addressKey, declaredKey)) {
      throw new SignatureError("card signing_key does not match its address");
    }
    await verifyPayload(declaredKey, CONTEXT_AGENT_CARD, this.payload(), this.signature);
  }

  get publicKeys(): PublicKeys {
    return new PublicKeys(base58Decode(this.signing_key), base58Decode(this.agreement_key));
  }

  toJSON(): Record<string, JsonValue> {
    const data: Record<string, JsonValue> = {
      amp: this.amp,
      address: this.address,
      name: this.name,
      kind: this.kind,
      operator: this.operator,
      signing_key: this.signing_key,
      agreement_key: this.agreement_key,
      agreement_prekey: this.agreement_prekey,
      payload_types: [...this.payload_types],
      endpoints: { ...this.endpoints },
      policy_summary: this.policy_summary,
      signature: this.signature,
    };
    if (this.critical) data["critical"] = [...this.critical];
    Object.assign(data, this.extra);
    return data;
  }

  static fromJSON(data: unknown): AgentCard {
    const record = requireMapping("card", data);
    const extra: Record<string, JsonValue> = {};
    for (const [key, value] of Object.entries(record)) {
      if (!KNOWN_FIELDS.has(key) && key !== "extra") extra[key] = value as JsonValue;
    }
    return new AgentCard({
      amp: record["amp"] as string | undefined,
      address: record["address"] as string,
      name: record["name"] as string,
      kind: record["kind"] as ParticipantKind | undefined,
      operator: (record["operator"] as string | null | undefined) ?? null,
      signing_key: record["signing_key"] as string,
      agreement_key: record["agreement_key"] as string,
      agreement_prekey: (record["agreement_prekey"] as string | null | undefined) ?? null,
      payload_types: record["payload_types"] as string[] | undefined,
      endpoints: record["endpoints"] as Record<string, string> | undefined,
      policy_summary: record["policy_summary"] as string | undefined,
      critical: parseCritical(record["critical"]),
      signature: (record["signature"] as string | undefined) ?? "",
      extra,
    });
  }

  with(update: Partial<AgentCardFields>): AgentCard {
    return new AgentCard({
      amp: this.amp,
      address: this.address,
      name: this.name,
      kind: this.kind,
      operator: this.operator,
      signing_key: this.signing_key,
      agreement_key: this.agreement_key,
      agreement_prekey: this.agreement_prekey,
      payload_types: this.payload_types,
      endpoints: this.endpoints,
      policy_summary: this.policy_summary,
      critical: this.critical,
      signature: this.signature,
      extra: this.extra,
      ...update,
    });
  }
}
