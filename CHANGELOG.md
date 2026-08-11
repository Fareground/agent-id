# Changelog

All notable changes to `fg-agent-id`. Format loosely follows Keep a Changelog.
The wire protocol version (`amp/x.y`, see `spec/SPEC.md`) is tracked
separately from the package version; the Python and npm package versions move
in lockstep (see CONTRIBUTING.md).

## [0.2.0] — 2026-08-10

### Fixed

- **Wire protocol version aligned at `amp/0.2`.** The domain-tag rename below
  was a wire-breaking change and `spec/SPEC.md` already declared `amp/0.2`,
  but both implementations still stamped `"amp": "0.1"` into cards and the
  golden vectors. `SPEC_VERSION` (`amp/0.2`) and `DEFAULT_PROTOCOL_VERSION`
  (`0.2`) now live in one place per language (`version.py` / `version.ts`),
  vectors were regenerated, and a conformance test on each side asserts
  implementation == vectors. Cards emitted with defaults now carry `0.2` —
  a byte-level change to signed payloads, hence the minor bump.
- **npm package is installable.** Renamed `@fg/agent-id` →
  `@fareground/agent-id`; added `prepare` (builds `dist/` on git installs),
  a `files` whitelist, `publishConfig.access: public`, and repository/license
  metadata.

### Added

- **One-liner persistence.** `AgentIdentity.load_or_create(path, passphrase=None)`
  / `OwnerIdentity.load_or_create` (and the TS `loadOrCreate` equivalents):
  load the key file if it exists, otherwise generate and save — encrypted at
  rest when a passphrase is given. No new formats: plain files are the raw
  64-byte form, sealed files the existing `FGID` v1 container, and TypeScript
  now reads and writes both byte-compatibly (Node crypto scrypt +
  ChaCha20-Poly1305). Cross-language round-trip is tested (Python writes,
  TS loads, addresses match). Bare helpers exported as
  `save_keys` / `load_keys` / `load_or_create_keys`.
- **TypeScript facade layer.** `AgentIdentity` / `OwnerIdentity`
  (+ `ParticipantIdentity` alias) ported from the Python reference, async
  where WebCrypto requires it, with mirrored tests.
- **Runnable examples** (`examples/python`, `examples/js`): card
  issue/verify, proof-of-possession round-trip, key rotation.
- **Release automation** (`.github/workflows/release.yml`): on a `v*` tag —
  sdist+wheel build, twine check, tag/version guard, clean-venv smoke test,
  PyPI trusted publishing, then npm publish. `SECURITY.md` added.
- **Pluggable challenge store.** `ChallengeStoreBase` defines the store
  contract (issue + atomic single-use consume); the in-process store is now
  `InMemoryChallengeStore` (the `ChallengeStore` name remains as its alias)
  and `RedisChallengeStore` provides a shared multi-worker backend built on
  `GETDEL`. Redis is an optional extra (`pip install fg-agent-id[redis]`) —
  runtime dependencies are unchanged.
- **Revocation distribution feed** (SPEC §5.3): transport-agnostic
  append-only `RevocationFeed` with a monotonic cursor and `entries_since`
  delta sync, plus `apply_feed_delta`/`sync_registry` to pull a delta into a
  `RevocationRegistry` with verify-before-admit and §5.2 freshness semantics.
- **Criticality marker** (SPEC §4.1): cards and delegations may list
  extension fields in `critical` that a verifier MUST understand or reject.
  Absent list = no critical fields, so all pre-marker signatures stay valid;
  delegations now also preserve-and-sign unknown extension fields like cards.
  Golden vectors gained `agent_card_critical` and `delegation_critical`.
- **Spend scopes** (SPEC §10): `spend.py` implements the
  `pay:<asset>[:tx<=<amount>][:total<=<amount>]` grammar with exact-decimal
  amounts, min-cap chain composition, and
  `SpendAuthority.verify(chain, asset, amount, spent_so_far)`. Grammar and
  verification only — settlement stays with the payment protocol.
- **Multi-device as delegation** (SPEC §11): reserved `device` scope plus
  `issue_device_delegation` / `verify_device` helpers — chain verify,
  root/terminus checks, and revocation-registry consultation. No device
  registry or enrollment machinery.

### Changed

- **Renamed to `fg-agent-id`** (was `fareground-agent-id`); import path is now
  `fg_agent_id`. Aligns with the other Fareground `fg-*` packages.
- **Domain-separation tag is now `fg-agent-id/v1`** (was
  `fareground-agent-id/v1`). This is a **wire-breaking change**: the tag is part
  of the signing input, so artifacts signed under the old tag will not verify.
  Golden vectors in `spec/vectors.json` were regenerated. Nothing had been
  published, so no released artifacts are affected.

## [0.1.0]

- Initial extraction from the Agent Messaging Protocol (AMP) as a standalone
  identity standard any protocol can adopt.
- Self-certifying `amp:key:<base58>` addresses and `did:amp` DIDs.
- Signed agent cards with forward-compatible unknown-field preservation.
- Owner identities and delegation chains; scopes compose by intersection.
- Revocation: single-delegation recall, identity-key revocation (self and owner
  recall), freshness-tracking `RevocationRegistry`.
- Key rotation with pre-rotation commitments and stable inception identity.
- Audience-bound proof of possession.
- Canonical JSON with golden cross-implementation vectors.
