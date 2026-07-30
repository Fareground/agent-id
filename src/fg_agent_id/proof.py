"""Proof of possession: prove you hold the key an address certifies, *here*.

A static signature (a card, a delegation) proves someone signed something once.
It does not prove the presenter holds the private key now, and it does not say
who the signature was meant for. Authentication needs both, so this module
adds a challenge-response where the signed payload names its audience.

The security property that matters: a response is bound to ``audience``, so a
signature collected by one verifier cannot be replayed to another. A verifier
that accepts a response without passing *its own* identifier as ``audience``
gets no such guarantee, which is why :meth:`ChallengeResponse.verify` requires
it as an argument rather than reading it off the response.

Flow::

    challenge = Challenge.issue(audience="https://workspace.example")  # verifier
    response = challenge.respond(keys, address)                        # agent
    response.verify(challenge, audience="https://workspace.example")   # verifier

The verifier must also enforce single use — see
:mod:`fg_agent_id.challenge_store` for the store interface, the in-process
default, and a Redis-backed shared store for multi-worker deployments.
"""

from __future__ import annotations

import base64
import dataclasses
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .errors import SignatureError
from .keys import KeyPair
from .serde import (
    canonical_timestamp,
    normalize_timestamp,
    parse_datetime,
    require_str,
)
from .signing import CONTEXT_CHALLENGE_RESPONSE, sign_payload, verify_by_address

NONCE_BYTES = 32
DEFAULT_TTL_SECONDS = 120.0
PURPOSE_AUTHENTICATE = "authenticate"


@dataclass(frozen=True)
class Challenge:
    """A verifier-issued, single-use, audience-scoped challenge."""

    challenge_id: str
    nonce: str  # base64 of NONCE_BYTES random bytes
    audience: str  # who this proof is for — an origin URL or an AMP address
    purpose: str
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        require_str("challenge_id", self.challenge_id)
        require_str("nonce", self.nonce)
        require_str("audience", self.audience)
        require_str("purpose", self.purpose)
        if not self.audience:
            raise ValueError("audience must not be empty — it is the replay defense")
        object.__setattr__(self, "issued_at", normalize_timestamp("issued_at", self.issued_at))
        object.__setattr__(self, "expires_at", normalize_timestamp("expires_at", self.expires_at))
        if len(self.nonce_bytes) < NONCE_BYTES:
            raise ValueError(f"nonce must be at least {NONCE_BYTES} bytes")

    @property
    def nonce_bytes(self) -> bytes:
        try:
            return base64.b64decode(self.nonce, validate=True)
        except Exception as exc:
            raise ValueError("nonce is not valid base64") from exc

    @classmethod
    def issue(
        cls,
        audience: str,
        purpose: str = PURPOSE_AUTHENTICATE,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
    ) -> Challenge:
        now = datetime.now(UTC)
        return cls(
            challenge_id=str(uuid.uuid4()),
            nonce=base64.b64encode(secrets.token_bytes(NONCE_BYTES)).decode(),
            audience=audience,
            purpose=purpose,
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )

    def is_expired(self, now: datetime | None = None, *, leeway_seconds: float = 0.0) -> bool:
        """True once the challenge's TTL has elapsed. ``leeway_seconds``
        tolerates clock skew between the issuer and the verifier so a
        short-TTL challenge isn't rejected purely because the two clocks
        disagree by a second or two."""
        moment = now or datetime.now(UTC)
        return moment - timedelta(seconds=max(0.0, leeway_seconds)) >= self.expires_at

    def respond(self, keys: KeyPair, address: str) -> ChallengeResponse:
        """Agent side: sign this challenge, binding the response to its audience."""
        return ChallengeResponse.create(keys, address, self)

    def model_dump(self, mode: str = "python") -> dict[str, Any]:
        stamp = canonical_timestamp if mode == "json" else (lambda v: v)
        return {
            "challenge_id": self.challenge_id,
            "nonce": self.nonce,
            "audience": self.audience,
            "purpose": self.purpose,
            "issued_at": stamp(self.issued_at),
            "expires_at": stamp(self.expires_at),
        }

    @classmethod
    def model_validate(cls, data: Any) -> Challenge:
        if isinstance(data, cls):
            return data
        return cls(
            challenge_id=data["challenge_id"],
            nonce=data["nonce"],
            audience=data["audience"],
            purpose=data.get("purpose", PURPOSE_AUTHENTICATE),
            issued_at=parse_datetime("issued_at", data["issued_at"]),
            expires_at=parse_datetime("expires_at", data["expires_at"]),
        )

    def model_copy(self, update: dict[str, Any] | None = None) -> Challenge:
        return dataclasses.replace(self, **(update or {}))


@dataclass(frozen=True)
class ChallengeResponse:
    """An agent's signed answer, bound to the challenge AND its audience."""

    challenge_id: str
    address: str
    audience: str
    purpose: str
    nonce: str
    signature: str = ""

    def __post_init__(self) -> None:
        for name in ("challenge_id", "address", "audience", "purpose", "nonce", "signature"):
            require_str(name, getattr(self, name))

    def _payload(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "audience": self.audience,
            "challenge_id": self.challenge_id,
            "nonce": self.nonce,
            "purpose": self.purpose,
        }

    @classmethod
    def create(cls, keys: KeyPair, address: str, challenge: Challenge) -> ChallengeResponse:
        unsigned = cls(
            challenge_id=challenge.challenge_id,
            address=address,
            audience=challenge.audience,
            purpose=challenge.purpose,
            nonce=challenge.nonce,
        )
        signature = sign_payload(keys, CONTEXT_CHALLENGE_RESPONSE, unsigned._payload())
        return dataclasses.replace(unsigned, signature=signature)

    def verify(
        self,
        challenge: Challenge,
        audience: str,
        now: datetime | None = None,
        *,
        leeway_seconds: float = 0.0,
    ) -> str:
        """Verify this response against the challenge that was issued.

        ``audience`` is the verifier's own identifier and MUST be supplied by
        the verifier, not taken from the response — that comparison is what
        stops a proof gathered elsewhere from being replayed here.

        Returns the proven address.
        """
        # Plain equality throughout: every value compared here is public (an
        # audience, a challenge id, a nonce the verifier just handed out), so
        # there is no secret for a timing side channel to leak. Constant-time
        # comparison of str also rejects non-ASCII outright, which would turn
        # an internationalized audience into a TypeError escaping as a 500.
        if not audience:
            raise SignatureError("verifier must supply its own audience")
        if self.audience != audience:
            raise SignatureError(
                f"response is addressed to {self.audience!r}, not {audience!r}"
            )
        if challenge.audience != audience:
            raise SignatureError("challenge was not issued for this audience")
        if self.challenge_id != challenge.challenge_id:
            raise SignatureError("response does not match the issued challenge")
        if self.nonce != challenge.nonce:
            raise SignatureError("response nonce does not match the issued challenge")
        if self.purpose != challenge.purpose:
            raise SignatureError("response purpose does not match the issued challenge")
        if challenge.is_expired(now, leeway_seconds=leeway_seconds):
            raise SignatureError("challenge has expired")
        verify_by_address(
            self.address, CONTEXT_CHALLENGE_RESPONSE, self._payload(), self.signature
        )
        return self.address

    def model_dump(self, mode: str = "python") -> dict[str, Any]:
        return {**self._payload(), "signature": self.signature}

    @classmethod
    def model_validate(cls, data: Any) -> ChallengeResponse:
        if isinstance(data, cls):
            return data
        return cls(
            challenge_id=data["challenge_id"],
            address=data["address"],
            audience=data["audience"],
            purpose=data.get("purpose", PURPOSE_AUTHENTICATE),
            nonce=data["nonce"],
            signature=data.get("signature", ""),
        )

    def model_copy(self, update: dict[str, Any] | None = None) -> ChallengeResponse:
        return dataclasses.replace(self, **(update or {}))
