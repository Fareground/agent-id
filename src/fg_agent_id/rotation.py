"""Key rotation with pre-rotation commitments.

An address self-certifies its signing key, which is what makes the identity
registry-free — and also what makes rotation hard: change the key and you have
changed the name. This module gives an identity a *stable* name that survives
rotation, without reintroducing a registry.

The stable name is the **inception address** — the address the identity was
born with. Everything after that is a signed, ordered history:

    inception(addr A, commits to H(B))
      → rotation 1: signed by A, reveals B, commits to H(C)
        → rotation 2: signed by B, reveals C, commits to H(D)

A verifier replays that history from the inception address and learns which
key is authoritative *now*.

**Why the commitment matters.** Each record commits to the digest of the key
that will take over next. Rotating requires revealing a key matching the
standing commitment, so stealing the key that is currently in force is not
enough to hijack the identity — the attacker would also need the pre-committed
next key, which is meant to live somewhere colder. This is the pre-rotation
property from KERI, and it is the difference between "compromise is
recoverable" and "compromise is terminal".

Two different valid rotations at the same sequence are proof that the signing
key leaked; :class:`RotationRegistry` refuses to advance and surfaces the
conflict rather than silently picking one.
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .address import address_from_signing_key, signing_key_from_address
from .errors import RotationError
from .keys import KeyPair
from .serde import (
    canonical_timestamp,
    normalize_timestamp,
    parse_datetime,
    require_str,
)
from .signing import (
    CONTEXT_INCEPTION,
    CONTEXT_KEY_ROTATION,
    sign_payload,
    signing_input,
    verify_by_address,
)

logger = logging.getLogger(__name__)

# Bumped when the snapshot format changes incompatibly. v1 stored an address
# where v2 stores a rotation fingerprint.
SNAPSHOT_VERSION = 2


def key_commitment(signing_public: bytes) -> str:
    """The pre-rotation commitment for a signing key: sha256 hex of the key.

    The key is 32 uniformly random bytes, so its digest reveals nothing and
    cannot be brute-forced back to the key — no salt needed.
    """
    if len(signing_public) != 32:
        raise RotationError("signing public key must be 32 raw bytes")
    return hashlib.sha256(signing_public).hexdigest()


def commitment_for_address(address: str) -> str:
    """The commitment a given address would satisfy."""
    return key_commitment(signing_key_from_address(address))


@dataclass(frozen=True)
class Inception:
    """The genesis record: an identity announcing itself and its next key."""

    address: str
    next_commitment: str
    created_at: datetime
    signature: str = ""

    def __post_init__(self) -> None:
        require_str("address", self.address)
        require_str("next_commitment", self.next_commitment)
        require_str("signature", self.signature)
        object.__setattr__(self, "created_at", normalize_timestamp("created_at", self.created_at))

    def _payload(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "created_at": canonical_timestamp(self.created_at),
            "next_commitment": self.next_commitment,
        }

    @classmethod
    def create(cls, keys: KeyPair, next_commitment: str) -> Inception:
        """Sign an inception for ``keys``, committing to the next key's digest."""
        address = address_from_signing_key(keys.public.signing)
        unsigned = cls(
            address=address,
            next_commitment=next_commitment,
            created_at=datetime.now(UTC),
        )
        signature = sign_payload(keys, CONTEXT_INCEPTION, unsigned._payload())
        return dataclasses.replace(unsigned, signature=signature)

    def verify(self) -> None:
        try:
            verify_by_address(self.address, CONTEXT_INCEPTION, self._payload(), self.signature)
        except Exception as exc:
            raise RotationError(f"invalid inception signature for {self.address}") from exc

    def model_dump(self, mode: str = "python") -> dict[str, Any]:
        created = canonical_timestamp(self.created_at) if mode == "json" else self.created_at
        return {
            "address": self.address,
            "next_commitment": self.next_commitment,
            "created_at": created,
            "signature": self.signature,
        }

    @classmethod
    def model_validate(cls, data: Any) -> Inception:
        if isinstance(data, cls):
            return data
        return cls(
            address=data["address"],
            next_commitment=data["next_commitment"],
            created_at=parse_datetime("created_at", data["created_at"]),
            signature=data.get("signature", ""),
        )

    def model_copy(self, update: dict[str, Any] | None = None) -> Inception:
        return dataclasses.replace(self, **(update or {}))


@dataclass(frozen=True)
class KeyRotation:
    """One succession step, signed by the key currently in force."""

    identity: str  # the inception address — the identity's stable name
    sequence: int  # 1-based, contiguous
    previous: str  # address handing over (and the signer)
    next_address: str  # address taking over; must satisfy the standing commitment
    next_commitment: str  # commitment to the key after this one
    rotated_at: datetime
    signature: str = ""

    def __post_init__(self) -> None:
        for name in ("identity", "previous", "next_address", "next_commitment", "signature"):
            require_str(name, getattr(self, name))
        if not isinstance(self.sequence, int) or isinstance(self.sequence, bool):
            raise TypeError("sequence must be an int")
        if self.sequence < 1:
            raise RotationError("rotation sequence starts at 1")
        object.__setattr__(self, "rotated_at", normalize_timestamp("rotated_at", self.rotated_at))

    def _payload(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "next_address": self.next_address,
            "next_commitment": self.next_commitment,
            "previous": self.previous,
            "rotated_at": canonical_timestamp(self.rotated_at),
            "sequence": self.sequence,
        }

    @classmethod
    def create(
        cls,
        current_keys: KeyPair,
        identity: str,
        sequence: int,
        next_address: str,
        next_commitment: str,
    ) -> KeyRotation:
        """Sign a rotation with the key currently in force."""
        previous = address_from_signing_key(current_keys.public.signing)
        unsigned = cls(
            identity=identity,
            sequence=sequence,
            previous=previous,
            next_address=next_address,
            next_commitment=next_commitment,
            rotated_at=datetime.now(UTC),
        )
        signature = sign_payload(current_keys, CONTEXT_KEY_ROTATION, unsigned._payload())
        return dataclasses.replace(unsigned, signature=signature)

    def verify_signature(self) -> None:
        try:
            verify_by_address(
                self.previous, CONTEXT_KEY_ROTATION, self._payload(), self.signature
            )
        except Exception as exc:
            raise RotationError(f"invalid rotation signature from {self.previous}") from exc

    def model_dump(self, mode: str = "python") -> dict[str, Any]:
        data = dict(self._payload())
        if mode != "json":
            data["rotated_at"] = self.rotated_at
        data["signature"] = self.signature
        return data

    @classmethod
    def model_validate(cls, data: Any) -> KeyRotation:
        if isinstance(data, cls):
            return data
        return cls(
            identity=data["identity"],
            sequence=data["sequence"],
            previous=data["previous"],
            next_address=data["next_address"],
            next_commitment=data["next_commitment"],
            rotated_at=parse_datetime("rotated_at", data["rotated_at"]),
            signature=data.get("signature", ""),
        )

    def model_copy(self, update: dict[str, Any] | None = None) -> KeyRotation:
        return dataclasses.replace(self, **(update or {}))


@dataclass(frozen=True)
class RotationState:
    """Where an identity stands after replaying its history."""

    identity: str
    current_address: str
    next_commitment: str
    sequence: int  # 0 at inception


@dataclass(frozen=True)
class RotationChain:
    """An identity's full key history: inception plus ordered rotations."""

    inception: Inception
    rotations: tuple[KeyRotation, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "inception", Inception.model_validate(self.inception))
        object.__setattr__(
            self,
            "rotations",
            tuple(KeyRotation.model_validate(r) for r in self.rotations),
        )

    @property
    def identity(self) -> str:
        """The stable name: the address this identity was born with."""
        return self.inception.address

    def resolve(self) -> RotationState:
        """Replay the history and return the currently authoritative state.

        Raises :class:`RotationError` if any signature, ordering, or
        pre-rotation commitment fails to hold.
        """
        self.inception.verify()
        current = self.inception.address
        commitment = self.inception.next_commitment
        sequence = 0

        for rotation in self.rotations:
            if rotation.identity != self.identity:
                raise RotationError(
                    f"rotation names identity {rotation.identity}, expected {self.identity}"
                )
            if rotation.sequence != sequence + 1:
                raise RotationError(
                    f"rotation out of order: got sequence {rotation.sequence}, "
                    f"expected {sequence + 1}"
                )
            if rotation.previous != current:
                raise RotationError(
                    f"rotation {rotation.sequence} signed by {rotation.previous}, "
                    f"but {current} is in force"
                )
            revealed = commitment_for_address(rotation.next_address)
            if revealed != commitment:
                raise RotationError(
                    f"rotation {rotation.sequence} reveals a key that does not match "
                    "the standing pre-rotation commitment"
                )
            rotation.verify_signature()
            current = rotation.next_address
            commitment = rotation.next_commitment
            sequence = rotation.sequence

        return RotationState(
            identity=self.identity,
            current_address=current,
            next_commitment=commitment,
            sequence=sequence,
        )

    @property
    def current_address(self) -> str:
        """Convenience: the authoritative address after full verification."""
        return self.resolve().current_address

    def extend(self, rotation: KeyRotation) -> RotationChain:
        """Append a rotation, verifying the extended chain before returning it."""
        extended = dataclasses.replace(self, rotations=self.rotations + (rotation,))
        extended.resolve()
        return extended

    def model_dump(self, mode: str = "python") -> dict[str, Any]:
        return {
            "inception": self.inception.model_dump(mode=mode),
            "rotations": [r.model_dump(mode=mode) for r in self.rotations],
        }

    @classmethod
    def model_validate(cls, data: Any) -> RotationChain:
        if isinstance(data, cls):
            return data
        return cls(
            inception=Inception.model_validate(data["inception"]),
            rotations=tuple(
                KeyRotation.model_validate(r) for r in data.get("rotations", ())
            ),
        )

    def model_copy(self, update: dict[str, Any] | None = None) -> RotationChain:
        return dataclasses.replace(self, **(update or {}))


class RotationRegistry:
    """A verifier's view of which key is authoritative for each identity.

    Feed it chains as they are learned; ask it to resolve an identity to the
    address that should be trusted right now. It refuses to move backwards, and
    it treats two conflicting rotations at the same sequence as evidence of
    compromise rather than something to resolve by preference.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._states: dict[str, RotationState] = {}
        # (identity, seq) -> the full identity of the rotation seen there.
        # Keyed on everything the rotation commits to, not just next_address:
        # two rotations that hand over to the same key but pre-commit to
        # different successors are just as much proof of a leaked key, and
        # keying on next_address alone silently accepted that.
        self._seen: dict[tuple[str, int], str] = {}
        # Evidence is a rotation or, at sequence 0, an inception.
        self._duplicity: dict[str, list[Inception | KeyRotation]] = {}

    @staticmethod
    def _rotation_identity(rotation: KeyRotation) -> str:
        """A digest of everything a rotation asserts, for conflict detection."""
        return hashlib.sha256(
            signing_input(CONTEXT_KEY_ROTATION, rotation._payload())
        ).hexdigest()

    @staticmethod
    def _inception_identity(inception: Inception) -> str:
        """A digest of everything an inception asserts, for conflict detection.

        The genesis record must be conflict-checked like any rotation: two
        different signed inceptions for one address are proof the birth key
        leaked. Domain separation keeps this distinct from a rotation digest,
        so an inception and a sequence-1 rotation can never collide at (id, 0).
        """
        return hashlib.sha256(
            signing_input(CONTEXT_INCEPTION, inception._payload())
        ).hexdigest()

    def learn(self, chain: RotationChain) -> RotationState:
        """Verify a chain and adopt it if it advances what we already know.

        Conflicting records at one sequence — including the inception at
        sequence 0 — are treated as evidence that the signing key leaked: the
        registry records the conflict and refuses to advance rather than
        silently preferring one history over the other.
        """
        state = chain.resolve()  # verify before taking the lock
        identity = state.identity

        # (sequence, fingerprint, record) for every step, genesis included.
        steps: list[tuple[int, str, Any]] = [
            (0, self._inception_identity(chain.inception), chain.inception)
        ]
        steps.extend(
            (r.sequence, self._rotation_identity(r), r) for r in chain.rotations
        )

        with self._lock:
            conflict = None
            for sequence, fingerprint, record in steps:
                established = self._seen.get((identity, sequence))
                if established is not None and established != fingerprint:
                    conflict = (sequence, record)
                    break

            if conflict is not None:
                # Record the evidence, and do not apply any part of this chain —
                # a partially-applied conflicting history is worse than none.
                sequence, record = conflict
                evidence = self._duplicity.setdefault(identity, [])
                # Dedupe: replaying one conflicting chain must not grow this
                # list without bound. The proof is the record, not the count.
                if not any(e == record for e in evidence):
                    evidence.append(record)
                raise RotationError(
                    f"conflicting records at sequence {sequence} for "
                    f"{identity} — the signing key is compromised; refusing to advance"
                )

            for sequence, fingerprint, _ in steps:
                self._seen[(identity, sequence)] = fingerprint

            known = self._states.get(identity)
            if known is None or state.sequence > known.sequence:
                self._states[identity] = state
                return state
            return known

    def resolve(self, identity: str) -> str:
        """The address currently authoritative for ``identity``.

        Fails closed on a proven-compromised identity: once conflicting records
        have shown the signing key leaked, there is no authoritative address to
        return, so this raises rather than hand back a key the registry itself
        has proven untrustworthy. A caller that wants to resolve regardless can
        catch :class:`RotationError` or read :meth:`state` directly.

        Falls back to the identity itself when no rotation is known. That is
        correct for an identity that never rotated, but it is indistinguishable
        from "we have not synced this identity's history" — so a caller that
        needs the difference must check :meth:`state` for None rather than
        trusting this alone.
        """
        with self._lock:
            if identity in self._duplicity:
                raise RotationError(
                    f"{identity} is compromised — conflicting records proved the "
                    "signing key leaked; refusing to resolve a trusted address"
                )
            state = self._states.get(identity)
        return state.current_address if state else identity

    def state(self, identity: str) -> RotationState | None:
        """Known rotation state, or None if this identity's history is unknown."""
        with self._lock:
            return self._states.get(identity)

    def is_duplicitous(self, identity: str) -> bool:
        """True once conflicting rotations proved the signing key leaked."""
        with self._lock:
            return identity in self._duplicity

    def duplicity_evidence(
        self, identity: str
    ) -> tuple[Inception | KeyRotation, ...]:
        with self._lock:
            return tuple(self._duplicity.get(identity, ()))

    def snapshot(self) -> dict[str, Any]:
        """Serializable view for durable persistence across restarts."""
        with self._lock:
            return self._snapshot_locked()

    def _snapshot_locked(self) -> dict[str, Any]:
        return {
            "version": SNAPSHOT_VERSION,
            "states": {
                identity: {
                    "current_address": state.current_address,
                    "next_commitment": state.next_commitment,
                    "sequence": state.sequence,
                }
                for identity, state in self._states.items()
            },
            # `fingerprint`, not `next_address`: version 1 stored the address
            # here, and conflict detection now compares a digest of the whole
            # rotation. Reading a v1 value as a fingerprint would make every
            # honest re-learn look like a conflict.
            "seen": [
                {"identity": identity, "sequence": seq, "fingerprint": value}
                for (identity, seq), value in sorted(self._seen.items())
            ],
            "duplicity": sorted(self._duplicity),
        }

    def restore(self, snapshot: dict[str, Any]) -> None:
        """Load a saved snapshot. Additive — history is never unlearned."""
        with self._lock:
            self._restore_locked(snapshot)

    def _restore_locked(self, snapshot: dict[str, Any]) -> None:
        for identity, raw in snapshot.get("states", {}).items():
            state = RotationState(
                identity=identity,
                current_address=raw["current_address"],
                next_commitment=raw["next_commitment"],
                sequence=raw["sequence"],
            )
            known = self._states.get(identity)
            if known is None or state.sequence > known.sequence:
                self._states[identity] = state
        version = snapshot.get("version", 1)
        if version >= SNAPSHOT_VERSION:
            for entry in snapshot.get("seen", []):
                self._seen[(entry["identity"], entry["sequence"])] = (
                    entry["fingerprint"])
        elif snapshot.get("seen"):
            # A v1 snapshot stored addresses where fingerprints now go. Loading
            # them would make every honest re-learn compare digest-to-address
            # and read as a conflict, permanently branding good identities as
            # compromised. Dropping the history instead only costs the ability
            # to spot a conflict we had already seen — it is re-derived from the
            # next chain each identity presents.
            logger.warning(
                "discarding conflict history from a v%s rotation snapshot: its "
                "format predates fingerprint-based conflict detection and "
                "cannot be compared. Recorded duplicity is preserved.",
                version,
            )
        for identity in snapshot.get("duplicity", []):
            self._duplicity.setdefault(identity, [])


@dataclass(frozen=True)
class RotatingIdentity:
    """Helper that holds the current and pre-committed next keypairs.

    Keeping the next keypair distinct is the whole point of pre-rotation, so
    this deliberately holds two: callers are expected to store ``next_keys``
    somewhere colder than ``keys``.
    """

    identity: str
    keys: KeyPair
    next_keys: KeyPair
    chain: RotationChain

    @classmethod
    def create(
        cls, keys: KeyPair | None = None, next_keys: KeyPair | None = None
    ) -> RotatingIdentity:
        keys = keys or KeyPair.generate()
        next_keys = next_keys or KeyPair.generate()
        inception = Inception.create(keys, key_commitment(next_keys.public.signing))
        chain = RotationChain(inception=inception)
        return cls(
            identity=chain.identity, keys=keys, next_keys=next_keys, chain=chain
        )

    @property
    def address(self) -> str:
        """The address currently in force (changes as the identity rotates)."""
        return address_from_signing_key(self.keys.public.signing)

    def rotate(self, following_keys: KeyPair | None = None) -> RotatingIdentity:
        """Promote the pre-committed next key and commit to a fresh one."""
        following_keys = following_keys or KeyPair.generate()
        next_address = address_from_signing_key(self.next_keys.public.signing)
        rotation = KeyRotation.create(
            current_keys=self.keys,
            identity=self.identity,
            sequence=self.chain.resolve().sequence + 1,
            next_address=next_address,
            next_commitment=key_commitment(following_keys.public.signing),
        )
        return dataclasses.replace(
            self,
            keys=self.next_keys,
            next_keys=following_keys,
            chain=self.chain.extend(rotation),
        )
