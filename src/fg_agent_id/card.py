"""AgentCard: the signed, publishable description of an agent.

Everything a peer needs to contact an agent: address, public keys, operator,
supported payload types, transport endpoints, and a policy summary. The card
is signed by the agent's own key; because addresses are self-certifying, the
signature is verifiable from the card alone.

Unknown fields are preserved and signed (``extra``), so a newer card carrying
extension fields still verifies on an older peer — byte-compatible with the
original pydantic ``extra="allow"`` behavior.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field, fields
from enum import StrEnum
from typing import Any

from .address import signing_key_from_address
from .errors import SignatureError
from .keys import KeyPair, PublicKeys, base58_decode
from .serde import require_mapping, require_str
from .signing import CONTEXT_AGENT_CARD, sign_payload, verify_payload
from .version import DEFAULT_PROTOCOL_VERSION


class ParticipantKind(StrEnum):
    """Who is behind an endpoint. The protocol treats all kinds equally;
    the field exists so peers and policies can distinguish them."""

    AGENT = "agent"
    HUMAN = "human"
    SERVICE = "service"


@dataclass(frozen=True, kw_only=True)
class AgentCard:
    amp: str = DEFAULT_PROTOCOL_VERSION  # protocol version stamped by the embedder
    address: str
    name: str
    kind: ParticipantKind = ParticipantKind.AGENT
    operator: str | None = None  # operator's address, if operated
    signing_key: str  # base58 raw ed25519 public
    agreement_key: str  # base58 raw x25519 public (static; durable)
    agreement_prekey: str | None = None  # base58 raw x25519 public; rotatable
    # short-lived key. When present, initiators seal the first "knock" to it
    # instead of the static key, so a later compromise of the static key doesn't
    # expose past initiate payloads (forward secrecy for the first message,
    # bounded by prekey rotation cadence). Authenticated by the card signature.
    payload_types: tuple[str, ...] = ("text/plain", "application/json")
    endpoints: dict[str, str] = field(default_factory=dict)  # transport name -> URI
    policy_summary: str = ""
    signature: str = ""  # base64 ed25519 over canonical card sans signature
    # Names of extension fields the verifier MUST understand (SPEC §4.1).
    # Absent/empty = every extension field is optional to understand.
    critical: tuple[str, ...] = ()
    # Unknown wire fields, preserved and included in the signed payload.
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_str("address", self.address)
        require_str("name", self.name)
        require_str("signing_key", self.signing_key)
        require_str("agreement_key", self.agreement_key)
        require_mapping("endpoints", self.endpoints)
        require_mapping("extra", self.extra)
        # `extra` is merged over the known fields in model_dump, so a key that
        # collides with a real field would shadow it there — and model_copy
        # would then promote the shadow into the actual field, silently
        # rewriting (say) the address. Wire input can't do this (model_validate
        # partitions by field name), but a hand-built card could.
        shadowed = {f.name for f in fields(type(self))} & set(self.extra)
        if shadowed:
            raise ValueError(
                f"extra must not shadow known card fields: {sorted(shadowed)}"
            )
        object.__setattr__(self, "kind", ParticipantKind(self.kind))
        object.__setattr__(self, "payload_types", tuple(self.payload_types))
        object.__setattr__(self, "critical", tuple(self.critical))
        for name in self.critical:
            require_str("critical entry", name)
        # A critical name must point at an extension field that is actually
        # present — a marker for a field that does not exist protects nothing
        # and would make every verifier reject the card for no reason.
        dangling = set(self.critical) - set(self.extra)
        if dangling:
            raise ValueError(
                f"critical names extension fields not present on the card: "
                f"{sorted(dangling)}"
            )

    def _payload(self) -> dict[str, Any]:
        """The signed view of this card: everything except the signature."""
        data = self.model_dump(mode="json")
        data.pop("signature")
        data["payload_types"] = list(self.payload_types)
        return data

    @classmethod
    def create(
        cls,
        keys: KeyPair,
        address: str,
        name: str,
        kind: ParticipantKind = ParticipantKind.AGENT,
        operator: str | None = None,
        payload_types: tuple[str, ...] = ("text/plain", "application/json"),
        endpoints: dict[str, str] | None = None,
        policy_summary: str = "",
        agreement_prekey: str | None = None,
        protocol_version: str = DEFAULT_PROTOCOL_VERSION,
        extra: dict[str, Any] | None = None,
        critical: tuple[str, ...] = (),
    ) -> AgentCard:
        public = keys.public
        unsigned = cls(
            amp=protocol_version,
            address=address,
            name=name,
            kind=kind,
            operator=operator,
            signing_key=public.signing_b58,
            agreement_key=public.agreement_b58,
            agreement_prekey=agreement_prekey,
            payload_types=payload_types,
            endpoints=endpoints or {},
            policy_summary=policy_summary,
            extra=extra or {},
            critical=critical,
        )
        signature = sign_payload(keys, CONTEXT_AGENT_CARD, unsigned._payload())
        return unsigned.model_copy(update={"signature": signature})

    def verify(self, understood_extensions: Iterable[str] = ()) -> None:
        """Card must be signed by the key its address certifies.

        ``understood_extensions`` names the extension fields THIS verifier
        knows how to evaluate. Any name in the card's ``critical`` list outside
        that set fails verification — the issuer declared the field
        must-understand, and skipping it would mean accepting a card while
        ignoring a constraint it insists on (SPEC §4.1).
        """
        address_key = signing_key_from_address(self.address)
        declared_key = base58_decode(self.signing_key)
        if address_key != declared_key:
            raise SignatureError("card signing_key does not match its address")
        verify_payload(self.public_keys, CONTEXT_AGENT_CARD, self._payload(), self.signature)
        unrecognized = set(self.critical) - set(understood_extensions)
        if unrecognized:
            raise SignatureError(
                f"card marks extension fields critical that this verifier "
                f"does not understand: {sorted(unrecognized)}"
            )

    @property
    def did(self) -> str:
        """This identity as a ``did:amp`` DID (self-certifying, registry-free)."""
        from .did import address_to_did

        return address_to_did(self.address)

    def to_did_document(self) -> dict:
        """W3C DID Document for this card (verification method + key agreement +
        transport services). Verify the card first for untrusted input."""
        from .did import did_document

        return did_document(self)

    @property
    def public_keys(self) -> PublicKeys:
        return PublicKeys(
            signing=base58_decode(self.signing_key),
            agreement=base58_decode(self.agreement_key),
        )

    def seal_target(self):
        """The X25519 public key an initiator should seal the first message to:
        the rotatable prekey when advertised (forward secrecy), else the static
        agreement key. Authenticated either way by this card's signature."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

        raw = base58_decode(self.agreement_prekey) if self.agreement_prekey else None
        if raw is None:
            return self.public_keys.x25519_public()
        return X25519PublicKey.from_public_bytes(raw)

    # -- pydantic-compatible serialization surface ---------------------------

    def model_dump(self, mode: str = "python") -> dict[str, Any]:
        data: dict[str, Any] = {
            "amp": self.amp,
            "address": self.address,
            "name": self.name,
            "kind": str(self.kind) if mode == "json" else self.kind,
            "operator": self.operator,
            "signing_key": self.signing_key,
            "agreement_key": self.agreement_key,
            "agreement_prekey": self.agreement_prekey,
            "payload_types": list(self.payload_types),
            "endpoints": dict(self.endpoints),
            "policy_summary": self.policy_summary,
            "signature": self.signature,
        }
        # Serialized only when present, so a card without critical fields is
        # byte-identical to one produced before the marker existed (§4.1).
        if self.critical:
            data["critical"] = sorted(self.critical)
        data.update(self.extra)
        return data

    @classmethod
    def model_validate(cls, data: Any) -> AgentCard:
        if isinstance(data, cls):
            return data
        require_mapping("card", data)
        known = {f.name for f in fields(cls)} - {"extra"}
        kwargs = {k: v for k, v in data.items() if k in known}
        extra = {k: v for k, v in data.items() if k not in known and k != "extra"}
        return cls(**kwargs, extra=extra)

    def model_copy(self, update: dict[str, Any] | None = None) -> AgentCard:
        update = dict(update or {})
        # model_dump flattens extra to the top level, and model_validate drops a
        # literal "extra" key — so an update of {"extra": {...}} would silently
        # vanish. Merge it into the flattened form instead, so setting extension
        # fields via model_copy actually takes effect.
        merged = self.model_dump()
        if "extra" in update:
            extra = update.pop("extra")
            require_mapping("extra", extra)
            known = {f.name for f in fields(type(self))}
            merged = {k: v for k, v in merged.items()
                      if k in known or k in extra}
            merged.update(extra)
        merged.update(update)
        return type(self).model_validate(merged)
