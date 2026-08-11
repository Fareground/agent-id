# @fareground/agent-id (TypeScript)

Standalone TypeScript implementation of the agent-id standard (`amp/0.2`) —
the second independent implementation, proving the wire format is
implementation-independent. It reproduces every golden vector in
[`../spec/vectors.json`](../spec/vectors.json) byte-for-byte against the
Python reference.

- **Zero runtime dependencies.** Crypto is WebCrypto (`crypto.subtle`):
  Ed25519, X25519, SHA-256 — available in Node 20+ and modern browsers.
- **Full v0.2 wire surface**: canonical JSON, domain-separated signing input
  (all 7 contexts), `amp:key:` addresses, `did:amp` + DID documents, signed
  AgentCards (unknown fields preserved-and-signed), delegation chains with
  scope intersection, revocation + key revocation + freshness-aware registry,
  audience-bound challenge-response, and pre-rotation key rotation with fork
  detection.
- **Criticality**: cards and delegations may carry a `critical` list of field
  names; verification fails on a critical field this implementation does not
  understand, unless the caller declares it understood.

## Install

```bash
npm install @fareground/agent-id
```

The package is ESM-only — use `import`, not `require`.

## Build & conformance

```bash
cd js
npm install          # dev deps only (typescript, @types/node)
npm test             # tsc + full suite (conformance, round-trip, negative)
npm run conformance  # golden-vector conformance only
```

The conformance runner is data-driven over `../spec/vectors.json`: unknown
vector sections or artifact kinds are skipped with a log line, so the Python
side can add cases without breaking this runner.

## API sketch

Everything is exported from `@fareground/agent-id` (see `src/index.ts`). Crypto
operations are `async` (WebCrypto).

```ts
import {
  KeyPair, addressFromSigningKey,
  AgentCard, Delegation, DelegationChain, Revocation, KeyRevocation,
  RevocationRegistry, Challenge, ChallengeStore,
  Inception, KeyRotation, RotationChain, RotationRegistry, keyCommitment,
  addressToDid, didDocument, resolve,
} from "@fareground/agent-id";

const keys = await KeyPair.generate();
const address = addressFromSigningKey(keys.public_.signing);

// Signed, self-certifying card
const card = await AgentCard.create({ keys, address, name: "my-agent" });
await card.verify();

// Delegation chain, scopes = intersection of all links
const grant = await Delegation.grant({
  issuerKeys: keys, issuerAddress: address,
  subjectAddress: worker, scopes: ["read"], ttlSeconds: 3600,
});
const scopes = await new DelegationChain([grant]).verify(worker);

// Proof of possession (audience-bound)
const store = new ChallengeStore();
const challenge = store.issue("https://verifier.example");
const response = await challenge.respond(keys, address);
await response.verify(store.consume(response.challengeId)!, "https://verifier.example");

// Key rotation (pre-rotation commitments; forks refuse to advance)
const inception = await Inception.create(keys, await keyCommitment(nextKeys.public_.signing));
const state = await new RotationChain(inception).resolve();
```

Wire-level primitives are exported too: `canonicalJson`, `signingInput`,
`signPayload` / `verifyByAddress`, `base58Encode/Decode`, `canonicalTimestamp`.

## Parity notes vs the Python reference

- Serialization surface is `toJSON()` / `fromJSON()` (instead of pydantic-style
  `model_dump` / `model_validate`); wire bytes are identical.
- The passphrase-sealed key-file format (spec §9, scrypt + ChaCha20-Poly1305)
  is not implemented here — it is explicitly a local-storage recommendation,
  not a wire construction. The 64-byte raw form (`signing || agreement`) is.
- Registry snapshot persistence (`snapshot()`/`restore()`) is not ported;
  registries here are in-memory. Nothing interoperable depends on it.
