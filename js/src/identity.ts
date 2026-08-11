/**
 * Ergonomic facade layer, mirroring the Python reference:
 *
 * - `AgentIdentity` — a participant's own identity: key material + name +
 *   delegation chain. Despite the historical name it identifies ANY
 *   participant (agent, human, or service); `kind` says which.
 * - `OwnerIdentity` — the principal (human/org) behind an agent: a cold
 *   keypair that never touches the wire and authorizes agents through
 *   signed delegation chains.
 *
 * Crypto is async here (WebCrypto), so factories and signing helpers return
 * promises; everything else matches the Python facade one-for-one.
 */

import { addressFromSigningKey } from "./address.js";
import { type JsonValue } from "./canonical.js";
import { AgentCard, type ParticipantKind } from "./card.js";
import { Delegation, DelegationChain, KeyRevocation, Revocation } from "./delegation.js";
import { KeyPair } from "./keys.js";
import { DEFAULT_PROTOCOL_VERSION } from "./version.js";

export const DEFAULT_DELEGATION_TTL_SECONDS = 30 * 24 * 3600;

/** A participant's own identity: key material + name + delegation chain. */
export class AgentIdentity {
  readonly keys: KeyPair;
  readonly name: string;
  readonly delegationChain: DelegationChain;
  readonly operator: string | null;
  readonly kind: ParticipantKind;

  constructor(fields: {
    keys: KeyPair;
    name: string;
    delegationChain?: DelegationChain;
    operator?: string | null;
    kind?: ParticipantKind;
  }) {
    this.keys = fields.keys;
    this.name = fields.name;
    this.delegationChain = fields.delegationChain ?? new DelegationChain();
    this.operator = fields.operator ?? null;
    this.kind = fields.kind ?? "agent";
    Object.freeze(this);
  }

  static async generate(
    name: string,
    options: { operator?: string | null; kind?: ParticipantKind } = {}
  ): Promise<AgentIdentity> {
    return new AgentIdentity({
      keys: await KeyPair.generate(),
      name,
      operator: options.operator ?? null,
      kind: options.kind ?? "agent",
    });
  }

  get address(): string {
    return addressFromSigningKey(this.keys.public_.signing);
  }

  withDelegation(chain: DelegationChain): AgentIdentity {
    return new AgentIdentity({
      keys: this.keys,
      name: this.name,
      delegationChain: chain,
      operator: this.operator,
      kind: this.kind,
    });
  }

  withOperator(operatorAddress: string): AgentIdentity {
    return new AgentIdentity({
      keys: this.keys,
      name: this.name,
      delegationChain: this.delegationChain,
      operator: operatorAddress,
      kind: this.kind,
    });
  }

  /**
   * Self-revoke this identity key ("I'm compromised — stop trusting me").
   * Any verifier that learns of it refuses all trust in this address.
   */
  async revokeOwnKey(): Promise<KeyRevocation> {
    return KeyRevocation.create({
      issuerKeys: this.keys,
      issuer: this.address,
      address: this.address,
    });
  }

  /** Issue this participant's signed, self-verifying card. */
  async card(
    options: {
      payloadTypes?: readonly string[];
      endpoints?: Readonly<Record<string, string>>;
      policySummary?: string;
      agreementPrekey?: string | null;
      protocolVersion?: string;
      critical?: readonly string[];
      extra?: Readonly<Record<string, JsonValue>>;
    } = {}
  ): Promise<AgentCard> {
    return AgentCard.create({
      keys: this.keys,
      address: this.address,
      name: this.name,
      kind: this.kind,
      operator: this.operator,
      payloadTypes: options.payloadTypes ?? ["text/plain", "application/json"],
      endpoints: options.endpoints,
      policySummary: options.policySummary ?? "",
      agreementPrekey: options.agreementPrekey ?? null,
      protocolVersion: options.protocolVersion ?? DEFAULT_PROTOCOL_VERSION,
      critical: options.critical,
      extra: options.extra,
    });
  }
}

/** A principal (human/org) that owns and authorizes agents. */
export class OwnerIdentity {
  readonly keys: KeyPair;
  readonly name: string;

  constructor(fields: { keys: KeyPair; name: string }) {
    this.keys = fields.keys;
    this.name = fields.name;
    Object.freeze(this);
  }

  static async generate(name: string): Promise<OwnerIdentity> {
    return new OwnerIdentity({ keys: await KeyPair.generate(), name });
  }

  get address(): string {
    return addressFromSigningKey(this.keys.public_.signing);
  }

  /** Issue a single delegation to any subject (an agent or an operator). */
  async grant(
    subjectAddress: string,
    scopes: Iterable<string>,
    ttlSeconds: number = DEFAULT_DELEGATION_TTL_SECONDS
  ): Promise<Delegation> {
    return Delegation.grant({
      issuerKeys: this.keys,
      issuerAddress: this.address,
      subjectAddress,
      scopes,
      ttlSeconds,
    });
  }

  /**
   * Recall a grant early. Distribute the revocation (e.g. via a relay) so
   * verifiers learn of it before the delegation's natural expiry.
   */
  async revoke(delegation: Delegation): Promise<Revocation> {
    if (delegation.issuer !== this.address) {
      throw new Error("can only revoke delegations this owner issued");
    }
    return Revocation.revoke(this.keys, delegation);
  }

  /**
   * Revoke a compromised agent's entire identity key, proving authority via
   * the agent's own delegation chain (which must root at this owner).
   */
  async revokeAgentKey(agent: AgentIdentity): Promise<KeyRevocation> {
    const chain = agent.delegationChain;
    if (chain.rootIssuer !== this.address) {
      throw new Error("this owner is not the root of the agent's delegation chain");
    }
    return KeyRevocation.create({
      issuerKeys: this.keys,
      issuer: this.address,
      address: agent.address,
      chain,
    });
  }

  /** Return the agent identity carrying an owner->agent delegation chain. */
  async authorizeAgent(
    agent: AgentIdentity,
    scopes: Iterable<string>,
    ttlSeconds: number = DEFAULT_DELEGATION_TTL_SECONDS
  ): Promise<AgentIdentity> {
    const chain = new DelegationChain([await this.grant(agent.address, scopes, ttlSeconds)]);
    return agent.withDelegation(chain).withOperator(this.address);
  }

  /** Mint a new agent keypair already authorized by this owner. */
  async createAgent(
    name: string,
    scopes: Iterable<string>,
    ttlSeconds: number = DEFAULT_DELEGATION_TTL_SECONDS
  ): Promise<AgentIdentity> {
    return this.authorizeAgent(await AgentIdentity.generate(name), scopes, ttlSeconds);
  }

  /**
   * Mint the owner's own HUMAN messaging endpoint: a hot keypair marked
   * `kind: "human"`, delegated by the owner's cold key, so a person can
   * converse with agents (or other humans) directly.
   */
  async createEndpoint(
    options: { name?: string; scopes?: Iterable<string>; ttlSeconds?: number } = {}
  ): Promise<AgentIdentity> {
    const endpoint = await AgentIdentity.generate(options.name ?? this.name, { kind: "human" });
    return this.authorizeAgent(
      endpoint,
      options.scopes ?? ["converse"],
      options.ttlSeconds ?? DEFAULT_DELEGATION_TTL_SECONDS
    );
  }
}

// Participant-neutral aliases, matching the Python facade.
export const ParticipantIdentity = AgentIdentity;
export type ParticipantIdentity = AgentIdentity;
