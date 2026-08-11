/**
 * @fareground/agent-id — TypeScript implementation of the fg-agent-id standard
 * (amp/0.2). Interoperates byte-for-byte with the Python reference; see
 * ../spec/SPEC.md and the conformance suite in test/.
 */

export { SPEC_VERSION, PACKAGE_VERSION } from "./version.js";
export {
  AgentIdError,
  AddressError,
  SignatureError,
  DelegationError,
  RotationError,
  SpendScopeError,
} from "./errors.js";
export { base58Encode, base58Decode } from "./base58.js";
export {
  concatBytes,
  utf8Encode,
  bytesToHex,
  hexToBytes,
  base64Encode,
  base64Decode,
  bytesEqual,
  sha256,
  sha256Hex,
} from "./bytes.js";
export { canonicalJson, compareCodePoints, type JsonValue } from "./canonical.js";
export {
  canonicalTimestamp,
  parseTimestamp,
} from "./serde.js";
export {
  KeyPair,
  PublicKeys,
  ed25519Sign,
  ed25519Verify,
  ed25519PublicFromSeed,
} from "./keys.js";
export { ADDRESS_PREFIX, addressFromSigningKey, signingKeyFromAddress } from "./address.js";
export {
  DOMAIN,
  CONTEXT_AGENT_CARD,
  CONTEXT_DELEGATION,
  CONTEXT_REVOCATION,
  CONTEXT_KEY_REVOCATION,
  CONTEXT_KEY_ROTATION,
  CONTEXT_INCEPTION,
  CONTEXT_CHALLENGE_RESPONSE,
  domainTag,
  signingInput,
  signPayload,
  decodeSignature,
  verifyPayload,
  verifyByAddress,
} from "./signing.js";
export { parseCritical, enforceCritical } from "./critical.js";
export {
  AgentCard,
  DEFAULT_PROTOCOL_VERSION,
  type AgentCardFields,
  type ParticipantKind,
} from "./card.js";
export {
  Delegation,
  DelegationChain,
  Revocation,
  KeyRevocation,
  RevocationRegistry,
} from "./delegation.js";
export {
  Amount,
  SpendScope,
  SpendAuthority,
  SPEND_PREFIX,
  parseAmount,
  parseSpendScope,
  isSpendScope,
  spendAuthorityFor,
  composeSpendAuthority,
} from "./spend.js";
export {
  DEVICE_SCOPE,
  DEFAULT_DEVICE_TTL_SECONDS,
  issueDeviceDelegation,
  verifyDevice,
} from "./device.js";
export {
  Challenge,
  ChallengeResponse,
  ChallengeStore,
  NONCE_BYTES,
  DEFAULT_TTL_SECONDS,
  PURPOSE_AUTHENTICATE,
} from "./proof.js";
export {
  Inception,
  KeyRotation,
  RotationChain,
  RotationRegistry,
  keyCommitment,
  commitmentForAddress,
  type RotationState,
} from "./rotation.js";
export {
  DID_PREFIX,
  addressToDid,
  didToAddress,
  signingKeyFromDid,
  didDocument,
  resolve,
} from "./did.js";
export {
  AgentIdentity,
  OwnerIdentity,
  ParticipantIdentity,
  DEFAULT_DELEGATION_TTL_SECONDS,
} from "./identity.js";
