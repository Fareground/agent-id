# Changelog

All notable changes to `fg-agent-id`. Format loosely follows Keep a Changelog.
The wire protocol version is tracked separately from the package version and
remains `0.1` until the v1.0 freeze.

## [Unreleased]

### Added

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
