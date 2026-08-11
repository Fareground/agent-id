"""fg-agent-id — self-certifying agent identity.

Keys, addresses, ``did:amp`` DIDs, signed agent cards, owner identities, and
delegation chains — the identity standard extracted from the Agent Messaging
Protocol (AMP), usable by any protocol that needs verifiable agent identity.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .address import address_from_signing_key, signing_key_from_address
from .canonical import canonical_json
from .card import AgentCard, ParticipantKind
from .challenge_store import (
    ChallengeStore,
    ChallengeStoreBase,
    InMemoryChallengeStore,
    RedisChallengeStore,
)
from .delegation import (
    Delegation,
    DelegationChain,
    KeyRevocation,
    Revocation,
    RevocationRegistry,
)
from .device import (
    DEVICE_SCOPE,
    issue_device_delegation,
    verify_device,
)
from .did import (
    address_to_did,
    did_document,
    did_to_address,
    resolve,
    signing_key_from_did,
)
from .errors import (
    AddressError,
    AgentIdError,
    DelegationError,
    RotationError,
    SignatureError,
    SpendScopeError,
)
from .feed import (
    ENTRY_KIND_KEY_REVOCATION,
    ENTRY_KIND_REVOCATION,
    FeedEntry,
    RevocationFeed,
    apply_feed_delta,
    sync_registry,
)
from .keys import KeyPair, PublicKeys
from .proof import (
    PURPOSE_AUTHENTICATE,
    Challenge,
    ChallengeResponse,
)
from .rotation import (
    Inception,
    KeyRotation,
    RotatingIdentity,
    RotationChain,
    RotationRegistry,
    RotationState,
    commitment_for_address,
    key_commitment,
)
from .signing import (
    CONTEXT_AGENT_CARD,
    CONTEXT_CHALLENGE_RESPONSE,
    CONTEXT_DELEGATION,
    CONTEXT_INCEPTION,
    CONTEXT_KEY_REVOCATION,
    CONTEXT_KEY_ROTATION,
    CONTEXT_REVOCATION,
    DOMAIN,
    sign_payload,
    signing_input,
    verify_by_address,
    verify_payload,
)
from .spend import (
    SpendAuthority,
    SpendScope,
    compose_spend_authority,
    is_spend_scope,
    parse_spend_scope,
    spend_authority_for,
)
from .version import DEFAULT_PROTOCOL_VERSION, PACKAGE_VERSION, SPEC_VERSION


@dataclass(frozen=True)
class AgentIdentity:
    """A participant's own identity: key material + name + delegation chain.

    Despite the historical name, this identifies ANY participant — an AI
    agent, a human, or a plain service. ``kind`` says which; the identity
    layer treats them all identically.
    """

    keys: KeyPair
    name: str
    delegation_chain: DelegationChain = field(default_factory=DelegationChain)
    operator: str | None = None
    kind: ParticipantKind = ParticipantKind.AGENT

    @classmethod
    def generate(
        cls,
        name: str,
        operator: str | None = None,
        kind: ParticipantKind = ParticipantKind.AGENT,
    ) -> AgentIdentity:
        return cls(keys=KeyPair.generate(), name=name, operator=operator, kind=kind)

    @property
    def address(self) -> str:
        return address_from_signing_key(self.keys.public.signing)

    def with_delegation(self, chain: DelegationChain) -> AgentIdentity:
        return AgentIdentity(
            keys=self.keys,
            name=self.name,
            delegation_chain=chain,
            operator=self.operator,
            kind=self.kind,
        )

    def with_operator(self, operator_address: str) -> AgentIdentity:
        return AgentIdentity(
            keys=self.keys,
            name=self.name,
            delegation_chain=self.delegation_chain,
            operator=operator_address,
            kind=self.kind,
        )

    def revoke_own_key(self) -> KeyRevocation:
        """Self-revoke this identity key ("I'm compromised — stop trusting me").
        Any verifier that learns of it refuses all trust in this address."""
        return KeyRevocation.create(self.keys, self.address, self.address)

    def card(
        self,
        payload_types: tuple[str, ...] = ("text/plain", "application/json"),
        endpoints: dict[str, str] | None = None,
        policy_summary: str = "",
        agreement_prekey: str | None = None,
        protocol_version: str = DEFAULT_PROTOCOL_VERSION,
    ) -> AgentCard:
        return AgentCard.create(
            keys=self.keys,
            address=self.address,
            name=self.name,
            kind=self.kind,
            operator=self.operator,
            payload_types=payload_types,
            endpoints=endpoints,
            policy_summary=policy_summary,
            agreement_prekey=agreement_prekey,
            protocol_version=protocol_version,
        )


from .owner import OwnerIdentity  # noqa: E402  (imports AgentIdentity lazily)

# Participant-neutral aliases: endpoints represent agents, humans, or
# services identically. The Agent* names remain for continuity.
ParticipantIdentity = AgentIdentity
ParticipantCard = AgentCard

__all__ = [
    "CONTEXT_AGENT_CARD",
    "CONTEXT_CHALLENGE_RESPONSE",
    "CONTEXT_DELEGATION",
    "CONTEXT_INCEPTION",
    "CONTEXT_KEY_REVOCATION",
    "CONTEXT_KEY_ROTATION",
    "CONTEXT_REVOCATION",
    "DEFAULT_PROTOCOL_VERSION",
    "DEVICE_SCOPE",
    "DOMAIN",
    "PACKAGE_VERSION",
    "SPEC_VERSION",
    "ENTRY_KIND_KEY_REVOCATION",
    "ENTRY_KIND_REVOCATION",
    "PURPOSE_AUTHENTICATE",
    "AddressError",
    "AgentCard",
    "AgentIdError",
    "AgentIdentity",
    "Challenge",
    "ChallengeResponse",
    "ChallengeStore",
    "ChallengeStoreBase",
    "DelegationError",
    "FeedEntry",
    "InMemoryChallengeStore",
    "ParticipantCard",
    "ParticipantIdentity",
    "Delegation",
    "DelegationChain",
    "Inception",
    "KeyPair",
    "KeyRevocation",
    "KeyRotation",
    "OwnerIdentity",
    "ParticipantKind",
    "PublicKeys",
    "RedisChallengeStore",
    "Revocation",
    "RevocationFeed",
    "RevocationRegistry",
    "RotatingIdentity",
    "RotationChain",
    "RotationError",
    "RotationRegistry",
    "RotationState",
    "SignatureError",
    "SpendAuthority",
    "SpendScope",
    "SpendScopeError",
    "address_from_signing_key",
    "address_to_did",
    "apply_feed_delta",
    "canonical_json",
    "commitment_for_address",
    "compose_spend_authority",
    "did_document",
    "did_to_address",
    "is_spend_scope",
    "issue_device_delegation",
    "key_commitment",
    "parse_spend_scope",
    "resolve",
    "sign_payload",
    "signing_input",
    "signing_key_from_address",
    "signing_key_from_did",
    "spend_authority_for",
    "sync_registry",
    "verify_by_address",
    "verify_device",
    "verify_payload",
]
