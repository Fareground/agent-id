"""Delegation credentials: who authorized this agent, to do what, until when.

A ``Delegation`` is a signed grant from an issuer key (a principal or an
operator) to a subject agent address, carrying a set of scopes and an expiry.
Chains compose principal -> operator -> agent; verification walks every link.

Wire format: every signature is computed over the domain-separated signing
input (``fg-agent-id/v1/<context>`` tag, length-prefixed, over the canonical
JSON of the unsigned payload) — see :mod:`fg_agent_id.signing` and
:mod:`fg_agent_id.canonical`. The dataclasses
expose a pydantic-compatible ``model_dump``/``model_validate``/``model_copy``
surface so embedding protocols keep their existing call sites.
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime, timedelta
from typing import Any

from .errors import DelegationError, SignatureError
from .keys import KeyPair
from .serde import (
    canonical_timestamp,
    normalize_timestamp,
    parse_datetime,
    require_mapping,
    require_str,
)
from .signing import (
    CONTEXT_DELEGATION,
    CONTEXT_KEY_REVOCATION,
    CONTEXT_REVOCATION,
    decode_signature,
    sign_payload,
    signing_input,
    verify_by_address,
)

logger = logging.getLogger(__name__)

# Bumped when the persisted format or the meaning of its contents changes.
# v2: delegation digests cover the decoded signature, not its base64 text.
SNAPSHOT_VERSION = 2


@dataclass(frozen=True)
class Delegation:
    """A single signed grant. ``issuer``/``subject`` are agent addresses."""

    issuer: str
    subject: str
    scopes: frozenset[str]
    issued_at: datetime
    expires_at: datetime
    signature: str = ""  # base64 ed25519 by issuer, over the canonical payload
    # Names of extension fields the verifier MUST understand (SPEC §4.1).
    critical: tuple[str, ...] = ()
    # Unknown wire fields, preserved and included in the signed payload.
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_str("issuer", self.issuer)
        require_str("subject", self.subject)
        require_str("signature", self.signature)
        require_mapping("extra", self.extra)
        object.__setattr__(self, "issued_at", normalize_timestamp("issued_at", self.issued_at))
        object.__setattr__(self, "expires_at", normalize_timestamp("expires_at", self.expires_at))
        object.__setattr__(self, "scopes", frozenset(self.scopes))
        object.__setattr__(self, "critical", tuple(self.critical))
        # `extra` merges over known fields in the wire payload; a colliding key
        # would silently rewrite (say) the issuer in the signed bytes.
        shadowed = {f.name for f in fields(type(self))} & set(self.extra)
        if shadowed:
            raise ValueError(
                f"extra must not shadow known delegation fields: {sorted(shadowed)}"
            )
        for name in self.critical:
            require_str("critical entry", name)
        dangling = set(self.critical) - set(self.extra)
        if dangling:
            raise ValueError(
                f"critical names extension fields not present on the "
                f"delegation: {sorted(dangling)}"
            )

    def _payload(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "issuer": self.issuer,
            "subject": self.subject,
            "scopes": sorted(self.scopes),
            "issued_at": canonical_timestamp(self.issued_at),
            "expires_at": canonical_timestamp(self.expires_at),
        }
        # Serialized only when present, so a delegation without extensions is
        # byte-identical to one produced before the marker existed (§4.1).
        if self.critical:
            data["critical"] = sorted(self.critical)
        data.update(self.extra)
        return data

    @classmethod
    def grant(
        cls,
        issuer_keys: KeyPair,
        issuer_address: str,
        subject_address: str,
        scopes: set[str],
        ttl_seconds: float,
        extra: dict[str, Any] | None = None,
        critical: tuple[str, ...] = (),
    ) -> Delegation:
        now = datetime.now(UTC)
        unsigned = cls(
            issuer=issuer_address,
            subject=subject_address,
            scopes=frozenset(scopes),
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            extra=extra or {},
            critical=critical,
        )
        signature = sign_payload(issuer_keys, CONTEXT_DELEGATION, unsigned._payload())
        return unsigned.model_copy(update={"signature": signature})

    @property
    def digest(self) -> str:
        """Stable identifier for this exact grant (used for revocation).

        Hashes the *decoded* signature, never its text. Base64 has more than
        one spelling for the same bytes, so hashing the string would give one
        signature several digests — and a revoked delegation could be re-spelled
        to miss its own revocation while still verifying.
        """
        signed = signing_input(CONTEXT_DELEGATION, self._payload())
        return hashlib.sha256(signed + decode_signature(self.signature)).hexdigest()

    def verify(self, now: datetime | None = None, *,
               check_validity_window: bool = True,
               leeway_seconds: float = 0.0,
               understood_extensions: Iterable[str] = ()) -> None:
        """Check signature and (by default) expiry.

        ``check_validity_window=False`` verifies only the signature, for the
        one case where expiry must not apply: proving that an owner *once*
        controlled an agent in order to revoke a compromised key. A recall that
        an expired delegation could block would be useless exactly when it is
        most needed. Raises DelegationError on any failure.

        ``leeway_seconds`` tolerates clock skew between issuer and verifier on
        both edges of the validity window: a freshly-minted grant whose
        ``issued_at`` is a few seconds ahead of the verifier's clock, and a
        just-expired grant, both stay valid within the leeway. Default 0 keeps
        the strict behavior; set it to a small value (a few seconds) in
        distributed deployments where NTP skew otherwise causes flaky auth.

        ``understood_extensions`` names the extension fields THIS verifier can
        evaluate; any ``critical`` name outside that set fails verification
        (SPEC §4.1) — accepting the grant while ignoring a constraint the
        issuer insists on would widen the grant.
        """
        now = now or datetime.now(UTC)
        if check_validity_window:
            leeway = timedelta(seconds=max(0.0, leeway_seconds))
            if now - leeway >= self.expires_at:
                raise DelegationError(
                    f"delegation from {self.issuer} expired at {self.expires_at}")
            if now + leeway < self.issued_at:
                raise DelegationError("delegation issued in the future")
        try:
            verify_by_address(self.issuer, CONTEXT_DELEGATION, self._payload(), self.signature)
        except Exception as exc:
            raise DelegationError(f"invalid delegation signature from {self.issuer}") from exc
        unrecognized = set(self.critical) - set(understood_extensions)
        if unrecognized:
            raise DelegationError(
                f"delegation from {self.issuer} marks extension fields critical "
                f"that this verifier does not understand: {sorted(unrecognized)}"
            )

    def model_dump(self, mode: str = "python") -> dict[str, Any]:
        if mode == "json":
            return {**self._payload(), "signature": self.signature}
        data: dict[str, Any] = {
            "issuer": self.issuer,
            "subject": self.subject,
            "scopes": self.scopes,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signature": self.signature,
        }
        if self.critical:
            data["critical"] = sorted(self.critical)
        data.update(self.extra)
        return data

    @classmethod
    def model_validate(cls, data: Any) -> Delegation:
        if isinstance(data, cls):
            return data
        known = {f.name for f in fields(cls)}
        extra = {
            k: v for k, v in data.items()
            if k not in known and k != "extra"
        }
        return cls(
            issuer=data["issuer"],
            subject=data["subject"],
            scopes=frozenset(data["scopes"]),
            issued_at=parse_datetime("issued_at", data["issued_at"]),
            expires_at=parse_datetime("expires_at", data["expires_at"]),
            signature=data.get("signature", ""),
            critical=tuple(data.get("critical", ())),
            extra=extra,
        )

    def model_copy(self, update: dict[str, Any] | None = None) -> Delegation:
        return dataclasses.replace(self, **(update or {}))


@dataclass(frozen=True)
class Revocation:
    """A signed early recall of a specific delegation by its original issuer."""

    issuer: str
    delegation_digest: str
    revoked_at: datetime
    signature: str = ""

    def __post_init__(self) -> None:
        require_str("issuer", self.issuer)
        require_str("delegation_digest", self.delegation_digest)
        object.__setattr__(self, "revoked_at", normalize_timestamp("revoked_at", self.revoked_at))

    def _payload(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "delegation_digest": self.delegation_digest,
            "revoked_at": canonical_timestamp(self.revoked_at),
        }

    @classmethod
    def revoke(cls, issuer_keys: KeyPair, delegation: Delegation) -> Revocation:
        unsigned = cls(
            issuer=delegation.issuer,
            delegation_digest=delegation.digest,
            revoked_at=datetime.now(UTC),
        )
        signature = sign_payload(issuer_keys, CONTEXT_REVOCATION, unsigned._payload())
        return unsigned.model_copy(update={"signature": signature})

    def verify(self) -> None:
        """Only the original issuer's key may revoke its own grant."""
        try:
            verify_by_address(self.issuer, CONTEXT_REVOCATION, self._payload(), self.signature)
        except Exception as exc:
            raise DelegationError(f"invalid revocation signature from {self.issuer}") from exc

    def model_dump(self, mode: str = "python") -> dict[str, Any]:
        revoked_at = canonical_timestamp(self.revoked_at) if mode == "json" else self.revoked_at
        return {
            "issuer": self.issuer,
            "delegation_digest": self.delegation_digest,
            "revoked_at": revoked_at,
            "signature": self.signature,
        }

    @classmethod
    def model_validate(cls, data: Any) -> Revocation:
        if isinstance(data, cls):
            return data
        return cls(
            issuer=data["issuer"],
            delegation_digest=data["delegation_digest"],
            revoked_at=parse_datetime("revoked_at", data["revoked_at"]),
            signature=data.get("signature", ""),
        )

    def model_copy(self, update: dict[str, Any] | None = None) -> Revocation:
        return dataclasses.replace(self, **(update or {}))


@dataclass(frozen=True)
class KeyRevocation:
    """Revokes an agent's IDENTITY key (its self-certifying address) — for a
    compromised or retired agent, stronger than revoking a single delegation.

    Honored when signed by either the revoked key itself (self-revocation:
    "I'm compromised, stop trusting me") or by an owner/operator that can prove,
    via ``chain``, it delegated to that agent (owner recall). Unlike a
    delegation revocation, this blocks the agent's identity entirely.
    """

    address: str  # the agent identity address being revoked
    issuer: str  # who signs the revocation (the address itself, or an owner)
    revoked_at: datetime
    chain: DelegationChain | None = None  # proof owner→agent, for owner recall
    signature: str = ""

    def __post_init__(self) -> None:
        require_str("address", self.address)
        require_str("issuer", self.issuer)
        object.__setattr__(self, "revoked_at", normalize_timestamp("revoked_at", self.revoked_at))
        if self.chain is not None and not isinstance(self.chain, DelegationChain):
            raise TypeError("chain must be a DelegationChain or None")

    def _payload(self) -> dict[str, Any]:
        # The proof chain is signed too. Leaving it out made it unauthenticated
        # data inside an object callers reasonably treat as fully signed: the
        # evidence recorded alongside a revocation could be swapped in transit
        # without invalidating the signature.
        return {
            "address": self.address,
            "chain": None if self.chain is None else self.chain.model_dump(mode="json"),
            "issuer": self.issuer,
            "revoked_at": canonical_timestamp(self.revoked_at),
        }

    @classmethod
    def create(cls, issuer_keys: KeyPair, issuer: str, address: str,
               chain: DelegationChain | None = None) -> KeyRevocation:
        unsigned = cls(address=address, issuer=issuer, chain=chain, revoked_at=datetime.now(UTC))
        signature = sign_payload(issuer_keys, CONTEXT_KEY_REVOCATION, unsigned._payload())
        return unsigned.model_copy(update={"signature": signature})

    def verify(self) -> None:
        """Signature valid AND the issuer is entitled to revoke this address:
        either it IS the address (self) or it roots a delegation chain to it."""
        try:
            verify_by_address(
                self.issuer, CONTEXT_KEY_REVOCATION, self._payload(), self.signature
            )
        except Exception as exc:
            raise DelegationError(f"invalid key-revocation signature from {self.issuer}") from exc
        if self.issuer == self.address:
            return  # self-revocation is always honorable
        if self.chain is None:
            raise DelegationError("owner key-revocation must include a proof chain")
        # The chain must delegate from the issuer (root) down to the revoked
        # agent. Expiry is deliberately NOT applied: revoking a compromised key
        # is the one moment an expired-but-once-valid delegation is still valid
        # proof that the owner controlled the agent, and blocking it on TTL
        # would defeat the recall exactly when it matters most.
        #
        # Criticality is likewise not applied: the chain is evidence of past
        # control, not authority being exercised, and a registry that rejected
        # a recall because it doesn't understand an extension field would keep
        # trusting a compromised key — the opposite of what critical is for.
        chain_critical = frozenset().union(*(link.critical for link in self.chain.links))
        self.chain.verify(self.address, check_validity_window=False,
                          understood_extensions=chain_critical)
        if self.chain.root_issuer != self.issuer:
            raise DelegationError("key-revocation chain does not root at the issuer")

    def model_dump(self, mode: str = "python") -> dict[str, Any]:
        revoked_at = canonical_timestamp(self.revoked_at) if mode == "json" else self.revoked_at
        return {
            "address": self.address,
            "issuer": self.issuer,
            "chain": None if self.chain is None else self.chain.model_dump(mode=mode),
            "revoked_at": revoked_at,
            "signature": self.signature,
        }

    @classmethod
    def model_validate(cls, data: Any) -> KeyRevocation:
        if isinstance(data, cls):
            return data
        chain = data.get("chain")
        return cls(
            address=data["address"],
            issuer=data["issuer"],
            chain=None if chain is None else DelegationChain.model_validate(chain),
            revoked_at=parse_datetime("revoked_at", data["revoked_at"]),
            signature=data.get("signature", ""),
        )

    def model_copy(self, update: dict[str, Any] | None = None) -> KeyRevocation:
        return dataclasses.replace(self, **(update or {}))


class RevocationRegistry:
    """A node's known revocations. Entries are verified before admission.

    Revocation is only as good as its freshness: a registry that has not
    synced in a week will happily accept a key revoked six days ago. The
    registry therefore tracks when it last completed a sync and can report
    staleness, so callers can decide whether to fail closed rather than trust
    an answer they know is out of date.
    """

    def __init__(self, synced_at: datetime | None = None):
        self._digests: set[str] = set()
        self._revoked_keys: set[str] = set()
        self._synced_at: datetime | None = synced_at

    def add(self, revocation: Revocation) -> None:
        revocation.verify()
        self._digests.add(revocation.delegation_digest)

    def revoke_key(self, revocation: KeyRevocation) -> None:
        revocation.verify()
        self._revoked_keys.add(revocation.address)

    def mark_synced(self, when: datetime | None = None) -> None:
        """Record that a full sync with an upstream source just completed."""
        self._synced_at = when or datetime.now(UTC)

    @property
    def synced_at(self) -> datetime | None:
        return self._synced_at

    def age_seconds(self, now: datetime | None = None) -> float | None:
        """Seconds since the last successful sync, or None if never synced."""
        if self._synced_at is None:
            return None
        return ((now or datetime.now(UTC)) - self._synced_at).total_seconds()

    def is_stale(self, max_age_seconds: float, now: datetime | None = None) -> bool:
        """True when this registry is too old to be trusted (never synced counts)."""
        age = self.age_seconds(now)
        return age is None or age > max_age_seconds

    def require_fresh(self, max_age_seconds: float, now: datetime | None = None) -> None:
        """Fail closed when the registry is too stale to answer safely."""
        if self.is_stale(max_age_seconds, now):
            age = self.age_seconds(now)
            detail = "never synced" if age is None else f"last synced {age:.0f}s ago"
            raise DelegationError(
                f"revocation data is stale ({detail}, limit {max_age_seconds:.0f}s)"
            )

    def is_revoked(self, delegation: Delegation) -> bool:
        """True if this exact grant was revoked.

        A malformed signature cannot be revoked because it was never valid, so
        this answers False rather than raising: callers commonly check
        revocation before verifying, and a predicate that throws on attacker
        bytes turns a clean rejection into an unhandled error.
        """
        try:
            return delegation.digest in self._digests
        except SignatureError:
            return False

    def is_key_revoked(self, address: str) -> bool:
        return address in self._revoked_keys

    @property
    def digests(self) -> frozenset[str]:
        return frozenset(self._digests)

    @property
    def revoked_keys(self) -> frozenset[str]:
        return frozenset(self._revoked_keys)

    def snapshot(self) -> dict[str, Any]:
        """Serializable view for durable persistence — a revocation registry
        that forgets on restart is a security hole. Persist this and restore it
        on boot (in addition to re-syncing from any directory service)."""
        return {
            "version": SNAPSHOT_VERSION,
            "digests": sorted(self._digests),
            "revoked_keys": sorted(self._revoked_keys),
        }

    def restore(self, snapshot: dict[str, Any]) -> None:
        """Load a previously saved snapshot. Additive (never removes) — a
        revocation is permanent, so restore only ever grows the sets.

        Delegation digests changed definition in wire version 0.2 (they now
        cover the decoded signature rather than its base64 text), so digests
        from an older snapshot will never match a live delegation. They are
        still loaded — a stale digest is harmless — but the mismatch is
        announced, because a revocation that silently stops applying is exactly
        the failure a registry exists to prevent. Re-sync from the source
        revocations after upgrading.
        """
        version = snapshot.get("version", 1)
        if version < SNAPSHOT_VERSION and snapshot.get("digests"):
            logger.warning(
                "restoring a v%s revocation snapshot: its %d delegation digests "
                "predate the v0.2 digest definition and will not match live "
                "delegations. Re-sync from the source revocations. Key "
                "revocations are unaffected.",
                version, len(snapshot.get("digests", [])),
            )
        self._digests.update(snapshot.get("digests", []))
        self._revoked_keys.update(snapshot.get("revoked_keys", []))


@dataclass(frozen=True)
class DelegationChain:
    """Ordered grants, root first. Each link's subject must issue the next link."""

    links: tuple[Delegation, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        links = tuple(Delegation.model_validate(link) for link in self.links)
        object.__setattr__(self, "links", links)

    def verify(
        self,
        agent_address: str,
        now: datetime | None = None,
        revoked: frozenset[str] = frozenset(),
        revoked_keys: frozenset[str] = frozenset(),
        *,
        check_validity_window: bool = True,
        leeway_seconds: float = 0.0,
        understood_extensions: Iterable[str] = (),
    ) -> frozenset[str]:
        """Verify every link and the chain topology.

        Returns the effective scopes: the intersection of all links' scopes
        (a delegate can never hold more authority than its delegator granted).
        An empty chain verifies to no scopes. Any link whose digest appears in
        ``revoked`` invalidates the whole chain. Any link whose issuer or subject
        key appears in ``revoked_keys`` also invalidates it — this is what lets a
        *compromised owner* (root) tear down every chain it ever signed, not just
        chains whose individual digests were revoked.

        ``check_validity_window=False`` skips per-link expiry, for proving a
        past delegation relationship (owner recall of a compromised key) where
        an expired-but-once-valid chain is exactly the proof required.
        """
        if not self.links:
            return frozenset()
        effective: frozenset[str] | None = None
        understood = frozenset(understood_extensions)
        for i, link in enumerate(self.links):
            link.verify(now, check_validity_window=check_validity_window,
                        leeway_seconds=leeway_seconds,
                        understood_extensions=understood)
            if link.digest in revoked:
                raise DelegationError(
                    f"delegation from {link.issuer} to {link.subject} has been revoked"
                )
            if link.issuer in revoked_keys or link.subject in revoked_keys:
                raise DelegationError(
                    f"delegation touches revoked identity key "
                    f"({link.issuer if link.issuer in revoked_keys else link.subject})"
                )
            if i > 0 and link.issuer != self.links[i - 1].subject:
                raise DelegationError(
                    f"broken chain: link {i} issued by {link.issuer}, "
                    f"expected {self.links[i - 1].subject}"
                )
            effective = link.scopes if effective is None else effective & link.scopes
        if self.links[-1].subject != agent_address:
            raise DelegationError(
                f"chain terminates at {self.links[-1].subject}, not agent {agent_address}"
            )
        return effective or frozenset()

    @property
    def root_issuer(self) -> str | None:
        return self.links[0].issuer if self.links else None

    def model_dump(self, mode: str = "python") -> dict[str, Any]:
        return {"links": [link.model_dump(mode=mode) for link in self.links]}

    @classmethod
    def model_validate(cls, data: Any) -> DelegationChain:
        if isinstance(data, cls):
            return data
        return cls(links=tuple(Delegation.model_validate(link) for link in data["links"]))

    def model_copy(self, update: dict[str, Any] | None = None) -> DelegationChain:
        return dataclasses.replace(self, **(update or {}))
