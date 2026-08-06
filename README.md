<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/wordmark-dark.svg" />
    <img src="assets/wordmark.svg" alt="Fareground" width="320" />
  </picture>
</p>

<h1 align="center">agent-id</h1>

<p align="center">
  <em>Self-certifying identity for AI agents — no registry, no CA, no central authority.</em>
</p>

<p align="center">
  <a href="https://github.com/Fareground/agent-id/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/Fareground/agent-id/ci.yml?branch=main&style=flat-square&label=CI" /></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.11+-3b82f6?style=flat-square" />
  <img alt="TypeScript" src="https://img.shields.io/badge/typescript-node%2020+-2dd4a7?style=flat-square" />
</p>

---

## Overview

**agent-id** gives any participant — an AI agent, a human, or a service — a
cryptographic identity that verifies on its own, with no registry, certificate
authority, or central lookup. It was extracted from the [Agent Messaging
Protocol (AMP)](https://github.com/Fareground/agent-messaging)
as a standalone standard any protocol can adopt.

### Identity model

- **Self-certifying addresses.** An address `amp:key:<base58>` *is* the holder's
  Ed25519 public key. Anything it signs verifies against the address itself — no
  registry required.
- **`did:amp` DIDs.** The same key expressed as a W3C DID (`did:amp:<base58>`),
  registry-free in the spirit of `did:key`, with DID Document resolution
  enriched by the signed card.
- **Agent keys vs owner keys.** Agents hold hot, rotatable keys. Owners (humans
  or organizations) hold cold keys that never touch the wire and authorize
  agents through signed **delegation chains** — scopes compose by intersection,
  so a chain can only narrow authority, never widen it.
- **Signed agent cards.** A publishable, self-verifying description of a
  participant (address, public keys, kind, operator, endpoints). Unknown fields
  are preserved and signed for forward compatibility.

### Security at a high level

- **Domain-separated signatures.** Every signature names the artifact type it
  covers, so one signature can never be replayed as a different kind of
  artifact.
- **Canonical JSON.** Every signature is computed over deterministic bytes
  (sorted keys, NFC, no floats, pinned timestamp spelling), so independent
  implementations agree byte-for-byte. Golden vectors live in
  [`spec/vectors.json`](spec/vectors.json).
- **Audience-bound proof of possession.** Challenge/response where the audience
  is inside the signed payload, so a proof gathered by one service cannot be
  replayed to another.
- **Key rotation with pre-rotation.** An identity keeps a stable name (its
  inception address) across key changes; each record commits in advance to the
  digest of the next key. Stealing the key in force is not enough to hijack the
  identity — the attacker would also need the pre-committed next key.
- **Revocation.** Recall a single delegation early, or revoke an entire identity
  key (self-revocation, or owner recall with a proof chain). The registry
  verifies before admission and tracks its own freshness, so "no revocation
  found" is never confused with "no revocation data".
- **Boring cryptography.** Ed25519 / X25519 / SHA-256 from audited primitives
  only. No invented crypto.

## Install

**Python** (reference implementation, only dependency is `cryptography`):

```bash
pip install git+https://github.com/Fareground/agent-id.git
```

The optional Redis-backed challenge store is an extra:

```bash
pip install "fg-agent-id[redis] @ git+https://github.com/Fareground/agent-id.git"
```

**TypeScript** (zero runtime dependencies, WebCrypto):

```bash
npm install @fg/agent-id
```

## Usage

### Python

```python
from fg_agent_id import AgentIdentity, OwnerIdentity

owner = OwnerIdentity.generate("acme-corp")
agent = owner.create_agent("acme-buyer", scopes={"converse", "negotiate"})

card = agent.card(endpoints={"http": "https://buyer.example/inbox"})
card.verify()                       # self-verifying: no registry needed
print(agent.address)                # amp:key:<base58>
print(card.did)                     # did:amp:<base58>

scopes = agent.delegation_chain.verify(agent.address)
assert scopes == frozenset({"converse", "negotiate"})
```

**Prove you hold the key, now, to a specific audience:**

```python
from fg_agent_id import ChallengeStore

store = ChallengeStore()                            # verifier side
challenge = store.issue(audience="https://myapp.example")

response = challenge.respond(agent.keys, agent.address)   # agent side

issued = store.consume(response.challenge_id)       # single use
assert issued is not None
address = response.verify(issued, audience="https://myapp.example")
```

Pass your own identifier as `audience` — never the one from the response. That
comparison is what stops a proof collected elsewhere from working here.

**Rotate keys without changing identity:**

```python
from fg_agent_id import RotatingIdentity, RotationRegistry

identity = RotatingIdentity.create()       # keys + a pre-committed next key
rotated = identity.rotate()                # promote next key, commit to a new one

assert rotated.identity == identity.identity   # stable name
assert rotated.address != identity.address     # key in force changed

registry = RotationRegistry()              # verifier side
registry.learn(rotated.chain)
assert registry.resolve(identity.identity) == rotated.address
```

**Keys at rest** (scrypt + ChaCha20-Poly1305):

```python
sealed = agent.keys.to_encrypted_bytes(passphrase)
agent_keys = KeyPair.from_encrypted_bytes(sealed, passphrase)
```

### TypeScript

Crypto operations are `async` (WebCrypto). Everything is exported from
`@fg/agent-id`.

```ts
import {
  KeyPair, addressFromSigningKey,
  AgentCard, Delegation, DelegationChain,
  Challenge, ChallengeStore,
} from "@fg/agent-id";

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
```

See [`js/README.md`](js/README.md) for the full TypeScript surface and parity
notes against the Python reference.

## Concepts

- **Address** — `amp:key:<base58>`; the Ed25519 public key itself, used as a
  stable identifier.
- **DID** — `did:amp:<base58>`; the same key as a resolvable W3C DID.
- **Agent card** — a signed, publishable participant description that verifies
  without a registry.
- **Delegation chain** — signed links from an owner to an agent; effective
  scopes are the intersection of every link.
- **Proof of possession** — an audience-bound challenge/response proving the
  holder controls the key right now.
- **Rotation chain** — pre-rotation commitments that let an identity change keys
  while keeping one stable name.
- **Revocation registry** — freshness-aware store that verifies revocations
  before admitting them.

## Project structure

```
src/fg_agent_id/   Python reference implementation
js/                TypeScript implementation (@fg/agent-id)
spec/              Wire spec (SPEC.md) + cross-implementation golden vectors
tests/             Python test suite
```

The full wire specification — addresses, `did:amp`, canonical JSON,
domain-separated signing, delegation, proof of possession, key rotation — is in
[`spec/SPEC.md`](spec/SPEC.md). Golden vectors in
[`spec/vectors.json`](spec/vectors.json) let independent implementations verify
byte-for-byte; regenerate them with `python spec/generate_vectors.py`.

> **Wire version `amp/0.2` is a breaking change** from `0.1`: signatures are now
> computed over a domain-separated signing input rather than bare canonical
> JSON, and signed timestamps use one pinned spelling. Artifacts signed under
> `0.1` will not verify.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, running the test
suites, and the rules around changing the wire format.

---

<p align="center">
  <sub>Built by <a href="https://github.com/Fareground">Fareground</a>.</sub>
</p>

<p align="center">
  <sub>Licensed under <a href="LICENSE">Apache-2.0</a>.</sub>
</p>
