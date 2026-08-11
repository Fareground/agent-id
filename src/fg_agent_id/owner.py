"""Owner identity: the human or organization behind an agent.

Owners are first-class identities with their own keypair and AMP address.
They never appear on the wire directly — their authority reaches the network
as signed delegation chains attached to the agents they operate. Verifying a
peer therefore answers three questions at once: which agent, owned by whom,
allowed to do what.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .address import address_from_signing_key
from .delegation import Delegation, DelegationChain, KeyRevocation, Revocation
from .keyfile import load_or_create_keys
from .keys import KeyPair

if TYPE_CHECKING:
    from . import AgentIdentity

DEFAULT_DELEGATION_TTL_SECONDS = 30 * 24 * 3600.0


@dataclass(frozen=True)
class OwnerIdentity:
    """A principal (human/org) that owns and authorizes agents."""

    keys: KeyPair
    name: str

    @classmethod
    def generate(cls, name: str) -> OwnerIdentity:
        return cls(keys=KeyPair.generate(), name=name)

    @classmethod
    def load_or_create(
        cls,
        path: str | Path,
        passphrase: str | None = None,
        *,
        name: str | None = None,
    ) -> OwnerIdentity:
        """Load the owner keypair at ``path`` or mint and save one.

        Owner keys are cold keys — prefer a passphrase here even more than for
        agents. ``name`` defaults to the file's stem.
        """
        keys = load_or_create_keys(path, passphrase)
        return cls(keys=keys, name=name or Path(path).stem)

    @property
    def address(self) -> str:
        return address_from_signing_key(self.keys.public.signing)

    def grant(
        self,
        subject_address: str,
        scopes: set[str],
        ttl_seconds: float = DEFAULT_DELEGATION_TTL_SECONDS,
    ) -> Delegation:
        """Issue a single delegation to any subject (an agent or an operator)."""
        return Delegation.grant(self.keys, self.address, subject_address, scopes, ttl_seconds)

    def revoke(self, delegation: Delegation) -> Revocation:
        """Recall a grant early. Distribute the revocation (e.g. via a relay)
        so verifiers learn of it before the delegation's natural expiry."""
        if delegation.issuer != self.address:
            raise ValueError("can only revoke delegations this owner issued")
        return Revocation.revoke(self.keys, delegation)

    def revoke_agent_key(self, agent: AgentIdentity) -> KeyRevocation:
        """Revoke a compromised agent's entire identity key, proving authority
        via the agent's own delegation chain (which must root at this owner).
        Blocks the agent from opening any session, regardless of policy."""
        chain = agent.delegation_chain
        if chain.root_issuer != self.address:
            raise ValueError("this owner is not the root of the agent's delegation chain")
        return KeyRevocation.create(self.keys, self.address, agent.address, chain=chain)

    def authorize_agent(
        self,
        agent: AgentIdentity,
        scopes: set[str],
        ttl_seconds: float = DEFAULT_DELEGATION_TTL_SECONDS,
    ) -> AgentIdentity:
        """Return the agent identity carrying an owner->agent delegation chain."""
        chain = DelegationChain(links=(self.grant(agent.address, scopes, ttl_seconds),))
        return agent.with_delegation(chain).with_operator(self.address)

    def create_agent(
        self,
        name: str,
        scopes: set[str],
        ttl_seconds: float = DEFAULT_DELEGATION_TTL_SECONDS,
    ) -> AgentIdentity:
        """Mint a new agent keypair already authorized by this owner."""
        from . import AgentIdentity

        return self.authorize_agent(AgentIdentity.generate(name), scopes, ttl_seconds)

    def create_endpoint(
        self,
        name: str | None = None,
        scopes: set[str] | None = None,
        ttl_seconds: float = DEFAULT_DELEGATION_TTL_SECONDS,
    ) -> AgentIdentity:
        """Mint the owner's own HUMAN messaging endpoint.

        AMP is not agent-only: any principal can hold a node. This creates a
        hot keypair marked ``kind=human``, delegated by the owner's cold key,
        so a person can converse with agents (or other humans) directly —
        peers verify the human's owner and scopes exactly as they would an
        agent's.
        """
        from . import AgentIdentity
        from .card import ParticipantKind

        endpoint = AgentIdentity.generate(name or self.name, kind=ParticipantKind.HUMAN)
        return self.authorize_agent(endpoint, scopes or {"converse"}, ttl_seconds)
