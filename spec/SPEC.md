# Agent-ID Wire Specification

**Version:** `amp/0.2` · **Status:** draft · **Companion:** `spec/vectors.json` (golden conformance vectors)

> **Breaking change in 0.2.** Signatures are now computed over a
> domain-separated signing input (§3.1) instead of bare canonical JSON, and
> timestamps in signed payloads use one pinned spelling (§3.2). Artifacts
> signed under 0.1 do not verify under 0.2, by design: the whole point is that
> a signature states which kind of artifact it covers. 0.2 also adds proof of
> possession (§7) and key rotation (§8).

This document specifies the agent-id wire constructions — addresses, `did:amp`,
canonical JSON, and delegation credentials — precisely enough for an independent
implementation to interoperate byte-for-byte with the Python reference. Every
`MUST`/`SHOULD`/`MAY` is [RFC 2119]. Where this document and the code disagree,
the golden vectors in `spec/vectors.json` are authoritative for the byte-level
constructions they cover.

This standard was extracted from the Agent Messaging Protocol (AMP); the
`amp:key:` address prefix and `did:amp` method name are retained for wire
compatibility. Any protocol may adopt these identities unchanged.

## 1. Cryptographic primitives

| Purpose | Algorithm |
|---|---|
| Signatures | Ed25519 (deterministic) |
| Key agreement | X25519 |
| Hash | SHA-256 |

All raw public keys are 32 bytes (Ed25519, X25519).

### 1.1 Cryptographic agility (reserved)

Version 1 hardcodes the suite above. A future version MAY introduce
post-quantum or hybrid signatures; to keep that a version bump rather than a
fork, the migration path is reserved now:

- The signing-domain tag (`fg-agent-id/v1/<context>`, §3.1) is the
  authoritative wire-version knob. A new suite takes a new major (`v2`), and a
  verifier that does not recognize the tag MUST reject with a distinct
  "unsupported version" signal — never a bare signature failure, so a version
  mismatch is distinguishable from a forgery.
- A suite identifier belongs in the address, not only the DID document: a
  future address form carries a multicodec/ciphersuite prefix ahead of the key
  bytes so the algorithm travels with the identity. The v1 `amp:key:` form is
  the implicit Ed25519 suite; new suites take a new prefix and MUST NOT reuse
  it.
- An identity MAY bridge suites by signing a v2 inception that references its
  v1 inception (§8), so key-rotation history carries across an algorithm
  change rather than orphaning the identity.

Implementations MUST NOT silently accept an unknown suite; agility is a
negotiated upgrade, never a downgrade.

## 2. Identity and addresses

An address is self-certifying: `amp:key:<base58(ed25519_public_key)>`. The
address **is** the signing public key, so any signed artifact verifies from the
address alone with no registry.

Base58 uses the Bitcoin alphabet `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`,
big-endian, with leading `0x00` bytes encoded as leading `1`s. See
`vectors.base58` and `vectors.ed25519.address`.

### 2.1 `did:amp` method

The same key MAY be expressed as a W3C DID: `did:amp:<base58(ed25519_public_key)>`.
Like `did:key`, the method is registry-free and self-certifying — the DID **is**
the key, and its Ed25519 verification method resolves deterministically from the
identifier alone. `amp:key:<b58>` and `did:amp:<b58>` share the same `<b58>` and
map 1:1; a `did:amp` MAY carry a path/query/fragment, and the method-specific id
is the first segment. A signed `AgentCard` enriches resolution with the X25519
`keyAgreement` key and transport `service` endpoints. Public keys in the DID
Document are `publicKeyMultibase` (multibase base58btc `z` of a multicodec-
prefixed key: `0xed01` ed25519-pub, `0xec01` x25519-pub), so off-the-shelf DID
resolvers understand them.

## 3. Canonical JSON

Every signed payload is serialized to **canonical JSON** before
hashing/signing:

1. Object keys sorted by Unicode code point, ascending.
2. No insignificant whitespace (`,` and `:` separators only).
3. UTF-8 output, strings NFC-normalized.
4. No `NaN`/`Infinity`.
5. **No floating-point numbers** — floats format differently across languages and
   would break cross-implementation agreement. Use integers (e.g. milliseconds)
   or strings. Booleans are permitted.

See `vectors.canonical_json`.

### 3.1 Domain-separated signing input

Signatures MUST NOT be computed over bare canonical JSON. Every signature in
this standard is computed over:

```
signing_input(context, payload) =
    uint16be(len(tag)) || tag || canonical_json(payload)

tag = UTF-8("fg-agent-id/v1/" || context)
```

The length prefix makes the construction unambiguous without escaping: no
payload byte can be mistaken for part of the tag.

`context` is exactly one of:

| Context | Artifact |
|---|---|
| `agent-card` | §4 `AgentCard` |
| `delegation` | §5 `Delegation` |
| `revocation` | §5.1 `Revocation` |
| `key-revocation` | §5.1 `KeyRevocation` |
| `inception` | §8 `Inception` |
| `key-rotation` | §8 `KeyRotation` |
| `challenge-response` | §7 `ChallengeResponse` |

A verifier MUST verify under the context of the artifact type it expects, and
MUST NOT accept a signature that verifies only under a different context. A new
artifact type MUST take a new context string; contexts MUST NOT be reused.

Rationale: without domain separation, a signature harvested from one artifact
type can be presented as another whenever their payloads canonicalize
identically. The context makes each signature state what it is signing.

See `vectors.signing_input` and `vectors.artifacts.*.signing_input_hex`.

### 3.2 Timestamps in signed payloads

Timestamps inside signed payloads MUST be rendered as RFC 3339 UTC with exactly
three fractional digits and a `Z` suffix:

```
YYYY-MM-DDTHH:MM:SS.mmmZ        e.g. 2026-07-19T12:30:05.123Z
```

Implementations MUST convert to UTC and truncate (not round) to milliseconds
before rendering, MUST reject timezone-naive input, and SHOULD normalize a
parsed timestamp to this precision on construction so that an in-memory value
is byte-identical to what was signed.

Rationale: general ISO-8601 serializers vary in offset spelling and fractional
precision, so two implementations signing the same instant would otherwise
produce different bytes. See `vectors.canonical_timestamp`.

## 4. Agent cards

An `AgentCard` is the signed, publishable description of a participant:
`amp` (protocol version string, stamped by the embedding protocol), `address`,
`name`, `kind` (`agent`|`human`|`service`), `operator` (owner address or null),
`signing_key` / `agreement_key` (base58 raw public keys), optional
`agreement_prekey`, `payload_types`, `endpoints` (name → URI),
`policy_summary`, and optional `critical` (§4.1). The `signature` is base64
Ed25519 over
`signing_input("agent-card", card_without_signature)`. A verifier MUST check
that `signing_key` matches the key certified by `address`, then verify the
signature. Unknown fields MUST be preserved and included in the signed
payload, so newer cards verify on older implementations.

`endpoints` maps a transport name to a URI. Two names are reserved:

- `relay` — the relay this participant can be reached through.
- `wake` — a URL that MAY be sent a content-free notification when mail is
  waiting for a participant that is not currently connected. A sender MUST NOT
  include message content, sender identity, or any other metadata in a wake
  notification; it means only "connect and pull". The URL itself acts as the
  capability, so it SHOULD be unguessable and MUST be treated as a secret by
  anyone who learns it.

Note: because unknown fields are signed but not understood, a verifier MAY
accept a card carrying extension fields whose meaning it cannot evaluate —
unless the issuer marks them critical (§4.1).

### 4.1 Criticality marker

Cards and delegations MAY carry a `critical` field: a list of the names of
extension fields the verifier MUST understand to accept the artifact. The
rules, for both artifact types:

- `critical` is part of the signed payload. When present it MUST be a list of
  strings, serialized sorted ascending; each name MUST refer to an extension
  field present on the artifact and MUST NOT name a standard field.
- When the artifact carries no critical fields, the `critical` key MUST be
  **absent**, not empty — an artifact without extensions serializes
  byte-identically to one produced before this marker existed, so all
  pre-marker signatures remain valid (backward compatible).
- A verifier MUST reject an artifact whose `critical` list contains any name
  it does not understand, even when the signature verifies. Understanding is
  verifier-local: which extension names a verifier evaluates is its own
  configuration, not negotiated on the wire.
- A verifier MUST continue to accept unknown extension fields that are *not*
  listed in `critical` (§4 preserve-and-sign).

One exception: a `KeyRevocation` proof chain (§5.1) is evidence of past
control, not authority being exercised, so criticality MUST NOT block owner
recall — rejecting a recall over an un-understood extension would keep a
compromised key trusted, the opposite of the marker's intent.

See `vectors.artifacts.agent_card_critical` and
`vectors.artifacts.delegation_critical`.

## 5. Delegation

A `Delegation` is a signed credential: `issuer` and `subject` addresses,
`scopes` (serialized sorted, ascending), `issued_at`/`expires_at` (§3.2), and a
base64 Ed25519 `signature` by the issuer over
`signing_input("delegation", unsigned_payload)`. Its stable identifier
(`digest`) is `sha256(signing_input("delegation", payload) || signature_b64)`
hex. Like cards, delegations preserve-and-sign unknown extension fields and
MAY mark them must-understand via `critical` (§4.1).

Chains are ordered root-first; each link's subject MUST issue the next link,
and the final subject MUST be the agent being verified. Effective scopes are
the **intersection** of all links' scopes — a delegate can never hold more
authority than its delegator granted. An empty chain verifies to no scopes.
Verifiers MUST reject expired, future-dated, mis-signed, or broken chains.
Required scopes are only meaningful relative to issuers the verifier trusts;
an implementation MUST NOT treat a peer-self-signed scope as authoritative.

### 5.1 Revocation

- A `Revocation` recalls one delegation early: signed by the original issuer
  over `{issuer, delegation_digest, revoked_at}`.
- A `KeyRevocation` revokes an entire identity key: signed over
  `{address, issuer, revoked_at}`. It is honored when the issuer IS the
  revoked address (self-revocation) or when it carries a delegation `chain`
  proving the issuer roots a chain terminating at the revoked address.
- Registries MUST verify a revocation before admitting it, and revocations are
  permanent: restoring a persisted registry snapshot only ever grows the sets.
  A chain touching a revoked identity key (as issuer or subject) is invalid —
  a compromised root tears down every chain it ever signed.

### 5.2 Revocation freshness

Revocation answers are only as good as the data behind them. A registry MUST
record when it last completed a sync with its upstream source, and callers
SHOULD refuse to rely on a registry older than a deployment-defined bound. A
registry that has never synced MUST be treated as stale, not as empty.

This standard deliberately does not specify a distribution *transport* — that
belongs to the embedding protocol (a relay, a gossip network, a transparency
log). It does specify that implementations MUST be able to tell how old their
answer is, because "no revocation found" and "no revocation data" are different
answers and conflating them is a security failure. §5.3 specifies the
transport-agnostic *shape* revocation data moves in.

### 5.3 Revocation distribution feed

A revocation feed is an append-only log of revocation records with a
monotonic cursor, designed for delta sync (the shape of a `?since=<cursor>`
endpoint):

- A **feed entry** is `{seq, kind, record}`: `seq` a positive integer,
  strictly increasing, assigned once and never reused; `kind` one of
  `revocation` | `key-revocation`, mirroring the signing context of the
  record it carries; `record` the record's wire form (§5.1). The entry
  envelope is NOT signed — the record inside it is, and consumers verify the
  record, never the envelope.
- The feed is append-only. Entries MUST NOT be removed or reordered: a
  revocation is permanent (§5.1), so the log only grows.
- A producer MUST verify a record before appending it. A feed that relays
  unverified records launders garbage into every consumer that trusts its
  transport.
- Delta sync: a consumer presents its last cursor and receives every entry
  with `seq` greater than it, plus the feed's current cursor to persist. A
  cursor beyond the feed's current position MUST return no entries and the
  feed's real cursor, so a consumer with corrupted state converges rather
  than skipping records forever.
- **Verify-before-admit:** a consumer MUST verify every received record
  before admitting it into its registry, exactly as §5.1 requires — the feed
  is transport data, not an authority. If any record in a delta fails
  verification, the consumer MUST NOT record the sync as completed
  (freshness, §5.2): a half-applied delta is stale data, not fresh data.
- Completing a delta application (including an empty delta) counts as a sync
  for §5.2 freshness; the consumer SHOULD persist the returned cursor
  alongside its registry snapshot.

The reference implementation is `RevocationFeed` / `apply_feed_delta`.

## 6. Operational assumptions

Delegation expiry depends on **wall-clock** time; verifiers SHOULD keep clocks
synchronized (e.g. NTP). This is a deliberate, documented assumption.

## 7. Proof of possession

A static signature proves that a key signed something once. Authentication also
needs liveness ("the presenter holds the key now") and an audience ("this proof
was meant for me"). A challenge-response provides both.

A `Challenge` is issued by the verifier: `challenge_id`, `nonce` (base64,
at least 32 bytes from a CSPRNG), `audience`, `purpose`, `issued_at`,
`expires_at`. It is not signed — it is the verifier's own state.

A `ChallengeResponse` is signed by the agent over
`signing_input("challenge-response", {address, audience, challenge_id, nonce, purpose})`.

A verifier MUST:

1. supply **its own** identifier as the expected `audience` — never read the
   audience out of the response;
2. reject the response unless both the response's and the challenge's
   `audience` equal that identifier;
3. reject unless `challenge_id`, `nonce`, and `purpose` match the issued
   challenge;
4. reject an expired challenge;
5. verify the signature against the key certified by the response's `address`;
6. enforce **single use** — a challenge, once consumed, MUST NOT be accepted
   again.

Rationale: a nonce alone proves only that someone signed 32 random bytes. Since
the signer cannot tell what those bytes are for, a signature gathered by one
service can be replayed to another that happens to have issued the same
challenge, or that can induce a signature over a chosen nonce. Binding
`audience` and `purpose` into the signed payload makes a proof useless outside
the exact context it was produced for.

Deployments running more than one process MUST back single-use enforcement with
a shared store offering an atomic consume; per-process storage does not enforce
single use globally. The store contract is two operations — *issue* (create
and persist a challenge) and *consume* (atomically remove-and-return, such
that no two consumers of the same challenge id can both receive it) — and any
backend providing atomic consume qualifies (the reference ships an in-process
default and a Redis `GETDEL` implementation).

## 8. Key rotation

An address certifies its own key, so rotating the key would ordinarily change
the identity. Rotation gives an identity a **stable name** — its *inception
address* — plus a signed, ordered history that a verifier replays to learn
which key is authoritative now.

An `Inception` is signed by the identity's first key over
`signing_input("inception", {address, created_at, next_commitment})`, where
`next_commitment` is `sha256(next_signing_public_key)` hex — the **pre-rotation
commitment**.

A `KeyRotation` is signed by the key currently in force over
`signing_input("key-rotation", {identity, next_address, next_commitment, previous, rotated_at, sequence})`.

To resolve a rotation chain, a verifier MUST start from the verified inception
(current = inception address, commitment = inception `next_commitment`,
sequence = 0) and for each rotation in order:

1. reject unless `identity` equals the inception address;
2. reject unless `sequence` is exactly one greater than the previous;
3. reject unless `previous` equals the address currently in force;
4. reject unless `sha256(signing_key_of(next_address))` equals the standing
   commitment;
5. verify the signature against `previous`;
6. advance current, commitment, and sequence.

Rationale: because each record commits in advance to the digest of the next
key, compromising the key currently in force is not sufficient to hijack the
identity — an attacker would also need the pre-committed next key, which is
meant to be stored more securely. Without pre-rotation, key compromise is
terminal: the thief can simply rotate the identity away from its owner.

Two valid rotations at the same `sequence` naming different `next_address`
values are proof that the signing key leaked. A verifier MUST NOT silently pick
one; it MUST refuse to advance and SHOULD surface the conflict as evidence of
compromise.

A verifier that knows no rotation history for an address MUST treat that
address as its own current key.

### 8.1 Rotation ↔ card/DID composition

A rotating identity's **stable name is its inception address**, but a card
(§4) and a `did:amp` (§2.1) name the key *currently in force*, which changes on
every rotation. Left unlinked, a peer holding an old card or DID resolves it to
a superseded key with no signal that a rotation occurred. To compose the two
features:

- A card issued by a rotating identity SHOULD carry (inside the signed
  payload) its **inception address** and a reference to its rotation chain, so
  a holder of the card can discover that the key rotated and re-resolve the
  current key rather than trusting a stale one.
- DID resolution for a rotating identity SHOULD be defined against the
  inception address: `did:amp:<inception>` resolves through the rotation chain
  to the in-force key, so the DID is stable across rotations.
- A verifier presented with an artifact signed by a key that a known rotation
  chain has rotated *away from* MUST treat it as superseded, not current — the
  "unknown history ⇒ current key" default (§8) applies only when no history is
  known, never to override a rotation the verifier has already seen.

These are reserved requirements for the next revision; v1 cards/DIDs name the
in-force key directly.

## 9. Key storage

Private keys serialize to 64 raw bytes (`signing || agreement`). Because a
plaintext key file is a standing compromise, implementations SHOULD offer a
passphrase-sealed form. The reference format is:

```
"FGID" || version(1 byte) || salt(16) || nonce(12) || ChaCha20-Poly1305(...)
```

keyed by scrypt over the passphrase and salt, with the header as
authenticated-but-unencrypted data so that tampering with the version byte
fails to open rather than silently selecting different parameters. This format
is a recommendation, not a wire construction — nothing interoperable depends on
it.

## 10. Spend scopes

Monetary authority in a delegation chain is expressed as an ordinary scope
string in a dedicated grammar:

```
pay:<asset>[:tx<=<amount>][:total<=<amount>]

pay:usdc                      unlimited authority over usdc
pay:usdc:tx<=25               at most 25 usdc per transaction
pay:usd:tx<=9.99:total<=100   per-transaction and cumulative caps
```

- `<asset>` is an opaque token matching `[a-z0-9]+([._-][a-z0-9]+)*`. This
  standard compares assets for equality and assigns them no other meaning.
- `<amount>` is a non-negative decimal (`[0-9]+(.[0-9]+)?`) — no sign, no
  exponent, no leading/trailing bare dot. Amounts MUST be handled as exact
  decimals, never as binary floats (floats are also banned from canonical
  JSON, §3). An absent cap means unlimited on that axis. Each cap segment
  MUST appear at most once; segments other than the two cap forms MUST be
  rejected.
- **Composition is intersection**, like every other scope (§5): the effective
  authority over an asset down a chain caps each axis at the **minimum**
  across links, and a link carrying no spend scope for the asset contributes
  no authority at all — the chain then grants none. Several spend scopes for
  the same asset within one grant likewise intersect. Consequently a
  composed authority can never exceed any single link's cap.
- A verifier checking a prospective payment MUST first verify the chain
  itself (§5 — signatures, topology, expiry, revocation), then require
  `amount <= tx cap` and `spent_so_far + amount <= total cap` against the
  composed authority. `spent_so_far` comes from the verifier's own ledger.

This section is grammar and verification rules only. Settlement, ledgers, and
the movement of money belong to the embedding payment protocol (e.g. x402).

## 11. Multi-device identities

One identity on several devices needs no new machinery — it is the delegation
pattern (§5) with a reserved scope:

- A stable **identity key** (kept cold or in a platform keystore) delegates to
  a per-device key. The grant carries the reserved scope `device`, the
  device's working scopes, and an expiry.
- A device key MUST NOT hold the identity's private key; it proves "I
  currently act for identity X" by presenting its delegation and signing with
  its own key, so verifiers always see *which* device acted.
- A verifier accepts a device when the chain verifies (§5), roots at the
  identity's address, terminates at the device's address, carries the
  `device` scope, and touches no revoked delegation or key — consulting a
  revocation registry whose freshness satisfies the verifier's bound (§5.2).
  The device's effective scopes are the chain's, minus the `device` marker.
- A lost device is one `Revocation` (§5.1) of that grant; other devices are
  untouched. A compromised identity key is key rotation (§8) or key
  revocation (§5.1) — device delegation does not change either.

There is deliberately no device registry, enrollment flow, or sync protocol
in this standard.

[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
