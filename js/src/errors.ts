/** Error hierarchy for the agent-id standard (mirrors the Python reference). */

export class AgentIdError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** Malformed or unresolvable agent address. */
export class AddressError extends AgentIdError {}

/** Signature failed verification. */
export class SignatureError extends AgentIdError {}

/** Delegation chain is invalid, expired, or lacks required scope. */
export class DelegationError extends AgentIdError {}

/** Key-rotation history is invalid, out of order, or contradictory. */
export class RotationError extends AgentIdError {}

export class SpendScopeError extends AgentIdError {}
