"""Identity layer: keys, addresses, cards, delegation chains."""

import pytest

from fg_agent_id import (
    AgentIdentity,
    Delegation,
    DelegationChain,
    KeyPair,
    address_from_signing_key,
    signing_key_from_address,
)
from fg_agent_id.errors import AddressError, DelegationError, SignatureError
from fg_agent_id.keys import base58_decode, base58_encode


def test_base58_roundtrip():
    for data in [b"", b"\x00\x00abc", b"hello world", bytes(range(32))]:
        assert base58_decode(base58_encode(data)) == data


def test_keypair_sign_verify():
    keys = KeyPair.generate()
    signature = keys.sign(b"message")
    keys.public.verify(signature, b"message")
    with pytest.raises(SignatureError):
        keys.public.verify(signature, b"tampered")


def test_keypair_serialization_roundtrip():
    keys = KeyPair.generate()
    restored = KeyPair.from_bytes(keys.to_bytes())
    restored.public.verify(keys.sign(b"x"), b"x")
    assert restored.public.agreement == keys.public.agreement


def test_address_roundtrip():
    keys = KeyPair.generate()
    address = address_from_signing_key(keys.public.signing)
    assert address.startswith("amp:key:")
    assert signing_key_from_address(address) == keys.public.signing


def test_address_rejects_garbage():
    with pytest.raises(AddressError):
        signing_key_from_address("not-an-address")
    with pytest.raises(AddressError):
        signing_key_from_address("amp:key:abc")


def test_agent_card_verifies():
    identity = AgentIdentity.generate("alice")
    card = identity.card(endpoints={"http": "https://alice.example"})
    card.verify()


def test_agent_card_tamper_detected():
    identity = AgentIdentity.generate("alice")
    card = identity.card()
    forged = card.model_copy(update={"name": "mallory"})
    with pytest.raises(SignatureError):
        forged.verify()


def test_card_address_key_mismatch_detected():
    alice, mallory = AgentIdentity.generate("alice"), AgentIdentity.generate("mallory")
    card = mallory.card().model_copy(update={"address": alice.address})
    with pytest.raises(SignatureError):
        card.verify()


def test_delegation_chain_scopes_intersect():
    principal = AgentIdentity.generate("principal")
    operator = AgentIdentity.generate("operator")
    agent = AgentIdentity.generate("agent")
    chain = DelegationChain(
        links=(
            Delegation.grant(
                principal.keys, principal.address, operator.address,
                {"converse", "negotiate", "spend"}, ttl_seconds=3600,
            ),
            Delegation.grant(
                operator.keys, operator.address, agent.address,
                {"converse", "negotiate"}, ttl_seconds=3600,
            ),
        )
    )
    assert chain.verify(agent.address) == frozenset({"converse", "negotiate"})
    assert chain.root_issuer == principal.address


def test_delegation_chain_broken_link_rejected():
    a, b, c = (AgentIdentity.generate(n) for n in "abc")
    chain = DelegationChain(
        links=(
            Delegation.grant(a.keys, a.address, b.address, {"converse"}, 3600),
            # c grants to c — issuer does not match previous subject (b)
            Delegation.grant(c.keys, c.address, c.address, {"converse"}, 3600),
        )
    )
    with pytest.raises(DelegationError, match="broken chain"):
        chain.verify(c.address)


def test_delegation_expired_rejected():
    a, b = AgentIdentity.generate("a"), AgentIdentity.generate("b")
    grant = Delegation.grant(a.keys, a.address, b.address, {"converse"}, ttl_seconds=-1)
    with pytest.raises(DelegationError, match="expired"):
        DelegationChain(links=(grant,)).verify(b.address)


def test_delegation_wrong_terminal_subject_rejected():
    a, b, c = (AgentIdentity.generate(n) for n in "abc")
    chain = DelegationChain(
        links=(Delegation.grant(a.keys, a.address, b.address, {"converse"}, 3600),)
    )
    with pytest.raises(DelegationError, match="terminates"):
        chain.verify(c.address)
