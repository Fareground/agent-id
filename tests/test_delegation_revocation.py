"""Owner identity, delegation revocation, and the revocation registry."""

import pytest

from fg_agent_id import (
    AgentIdentity,
    KeyRevocation,
    OwnerIdentity,
    RevocationRegistry,
)
from fg_agent_id.errors import DelegationError


def test_owner_mints_authorized_agent():
    owner = OwnerIdentity.generate("acme-corp")
    agent = owner.create_agent("acme-buyer", scopes={"converse", "negotiate"})
    assert agent.operator == owner.address
    scopes = agent.delegation_chain.verify(agent.address)
    assert scopes == frozenset({"converse", "negotiate"})


def test_owner_creates_human_endpoint():
    owner = OwnerIdentity.generate("sandro")
    endpoint = owner.create_endpoint()
    assert endpoint.kind.value == "human"
    assert endpoint.delegation_chain.verify(endpoint.address) == frozenset({"converse"})


def test_revoked_delegation_invalidates_chain():
    owner = OwnerIdentity.generate("acme")
    agent = owner.create_agent("worker", {"trade"})
    grant = agent.delegation_chain.links[0]

    registry = RevocationRegistry()
    registry.add(owner.revoke(grant))
    assert registry.is_revoked(grant)
    with pytest.raises(DelegationError, match="revoked"):
        agent.delegation_chain.verify(agent.address, revoked=registry.digests)


def test_owner_cannot_revoke_delegation_it_did_not_issue():
    owner, stranger = OwnerIdentity.generate("acme"), OwnerIdentity.generate("stranger")
    agent = owner.create_agent("worker", {"trade"})
    with pytest.raises(ValueError, match="only revoke delegations this owner issued"):
        stranger.revoke(agent.delegation_chain.links[0])


def test_self_key_revocation_verifies_and_blocks_chains():
    agent = AgentIdentity.generate("agent")
    registry = RevocationRegistry()
    registry.revoke_key(agent.revoke_own_key())
    assert registry.is_key_revoked(agent.address)

    # any chain touching the revoked key is invalid
    owner = OwnerIdentity.generate("acme")
    delegated = owner.authorize_agent(agent, {"converse"})
    with pytest.raises(DelegationError, match="revoked identity key"):
        delegated.delegation_chain.verify(
            delegated.address, revoked_keys=registry.revoked_keys
        )


def test_owner_revokes_compromised_agent_key():
    owner = OwnerIdentity.generate("acme")
    agent = owner.create_agent("worker", {"converse"})
    revocation = owner.revoke_agent_key(agent)
    registry = RevocationRegistry()
    registry.revoke_key(revocation)
    assert registry.is_key_revoked(agent.address)


def test_owner_cannot_revoke_key_it_did_not_delegate():
    owner, stranger = OwnerIdentity.generate("acme"), OwnerIdentity.generate("stranger")
    agent = owner.create_agent("worker", {"converse"})
    with pytest.raises(ValueError, match="not the root"):
        stranger.revoke_agent_key(agent)


def test_forged_key_revocation_rejected():
    attacker = OwnerIdentity.generate("attacker")
    victim = AgentIdentity.generate("victim")
    forged = KeyRevocation.create(attacker.keys, attacker.address, victim.address)
    registry = RevocationRegistry()
    with pytest.raises(DelegationError, match="must include a proof chain"):
        registry.revoke_key(forged)


def test_revocation_registry_snapshot_restore_is_durable_and_additive():
    owner = OwnerIdentity.generate("acme")
    agent = owner.create_agent("worker", {"trade"})

    registry = RevocationRegistry()
    registry.revoke_key(owner.revoke_agent_key(agent))
    registry.add(owner.revoke(agent.delegation_chain.links[0]))

    snap = registry.snapshot()
    assert agent.address in snap["revoked_keys"]
    assert len(snap["digests"]) == 1

    restarted = RevocationRegistry()
    stray = AgentIdentity.generate("stray")
    restarted.revoke_key(stray.revoke_own_key())
    restarted.restore(snap)

    assert restarted.is_key_revoked(agent.address)  # restored
    assert restarted.is_key_revoked(stray.address)  # local preserved
    assert agent.delegation_chain.links[0].digest in restarted.digests

    restarted.restore({"digests": [], "revoked_keys": []})
    assert restarted.is_key_revoked(agent.address)


def test_wire_roundtrip_preserves_signatures():
    """model_dump(mode='json') -> model_validate keeps every artifact verifiable."""
    owner = OwnerIdentity.generate("acme")
    agent = owner.create_agent("worker", {"trade"})
    card = agent.card(endpoints={"http": "https://w.example"})

    from fg_agent_id import AgentCard, DelegationChain

    card2 = AgentCard.model_validate(card.model_dump(mode="json"))
    card2.verify()
    assert card2 == card

    chain2 = DelegationChain.model_validate(agent.delegation_chain.model_dump(mode="json"))
    assert chain2.verify(agent.address) == frozenset({"trade"})
    assert chain2.links[0].digest == agent.delegation_chain.links[0].digest

    rev = owner.revoke_agent_key(agent)
    rev2 = KeyRevocation.model_validate(rev.model_dump(mode="json"))
    rev2.verify()


def test_owner_recall_works_after_the_proving_delegation_expired():
    """Revoking a compromised key is exactly when the proving delegation may
    have lapsed — the recall must not be blocked by that delegation's TTL, or
    it is useless when it matters most."""
    owner = OwnerIdentity.generate("acme")
    # A short-lived grant, so it is already expired when we recall.
    agent = owner.create_agent("worker", {"converse"}, ttl_seconds=1)
    recall = owner.revoke_agent_key(agent)

    # Force "now" well past expiry by verifying against a future clock via the
    # chain — the recall path must ignore expiry entirely.
    import time
    time.sleep(1.1)

    # Sanity: the delegation itself is now expired.
    with pytest.raises(DelegationError, match="expired"):
        agent.delegation_chain.verify(agent.address)

    # The recall still verifies and admits.
    recall.verify()
    registry = RevocationRegistry()
    registry.revoke_key(recall)
    assert registry.is_key_revoked(agent.address)


def test_owner_recall_still_rejects_a_forged_expired_chain():
    """Ignoring expiry must not weaken signature/topology checks."""
    from datetime import UTC, datetime, timedelta

    from fg_agent_id import KeyPair, address_from_signing_key
    from fg_agent_id.delegation import Delegation, DelegationChain
    from fg_agent_id.signing import CONTEXT_DELEGATION, sign_payload

    owner = OwnerIdentity.generate("acme")
    attacker = KeyPair.generate()
    agent_addr = address_from_signing_key(KeyPair.generate().public.signing)
    past = datetime.now(UTC) - timedelta(hours=2)
    # A chain signed by the attacker, not the owner.
    forged = Delegation(issuer=owner.address, subject=agent_addr,
                        scopes=frozenset({"x"}), issued_at=past,
                        expires_at=past + timedelta(minutes=1))
    forged = forged.model_copy(update={"signature": sign_payload(
        attacker, CONTEXT_DELEGATION, forged._payload())})
    bad = KeyRevocation.create(owner.keys, owner.address, agent_addr,
                               chain=DelegationChain(links=(forged,)))
    with pytest.raises(DelegationError):
        bad.verify()


def test_clock_skew_leeway_tolerates_a_freshly_minted_grant():
    """A grant whose issued_at is a few seconds ahead of the verifier's clock
    (NTP skew) verifies within leeway but still fails without it."""
    from datetime import UTC, datetime, timedelta

    from fg_agent_id import Delegation, DelegationChain, OwnerIdentity, address_from_signing_key
    from fg_agent_id import KeyPair
    from fg_agent_id.errors import DelegationError

    from fg_agent_id.signing import CONTEXT_DELEGATION, sign_payload

    owner = OwnerIdentity.generate("acme")
    agent_addr = address_from_signing_key(KeyPair.generate().public.signing)
    now = datetime.now(UTC)
    # Issuer's clock is 3s ahead of the verifier's.
    issued = now + timedelta(seconds=3)
    grant = Delegation(issuer=owner.address, subject=agent_addr,
                       scopes=frozenset({"read"}), issued_at=issued,
                       expires_at=issued + timedelta(hours=1))
    grant = grant.model_copy(update={"signature": sign_payload(
        owner.keys, CONTEXT_DELEGATION, grant._payload())})
    verifier_now = now  # behind the issuer
    with pytest.raises(DelegationError, match="future"):
        grant.verify(now=verifier_now)
    grant.verify(now=verifier_now, leeway_seconds=5)  # tolerated

    chain = DelegationChain(links=(grant,))
    with pytest.raises(DelegationError):
        chain.verify(agent_addr, now=verifier_now)
    assert chain.verify(agent_addr, now=verifier_now, leeway_seconds=5) == frozenset({"read"})


def test_clock_skew_leeway_tolerates_a_just_expired_grant():
    from datetime import UTC, datetime, timedelta

    from fg_agent_id import Delegation, OwnerIdentity, address_from_signing_key, KeyPair
    from fg_agent_id.errors import DelegationError

    from fg_agent_id.signing import CONTEXT_DELEGATION, sign_payload

    owner = OwnerIdentity.generate("acme")
    agent_addr = address_from_signing_key(KeyPair.generate().public.signing)
    now = datetime.now(UTC)
    issued = now - timedelta(seconds=3)
    grant = Delegation(issuer=owner.address, subject=agent_addr,
                       scopes=frozenset({"read"}), issued_at=issued,
                       expires_at=issued + timedelta(seconds=1))
    grant = grant.model_copy(update={"signature": sign_payload(
        owner.keys, CONTEXT_DELEGATION, grant._payload())})
    with pytest.raises(DelegationError, match="expired"):
        grant.verify(now=now)
    grant.verify(now=now, leeway_seconds=5)  # within skew tolerance
