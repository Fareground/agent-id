"""Domain separation: a signature is only valid for the artifact type it signed."""

from __future__ import annotations

import base64

import pytest

from fg_agent_id import (
    AgentIdentity,
    KeyPair,
    OwnerIdentity,
    SignatureError,
    sign_payload,
    signing_input,
    verify_by_address,
    verify_payload,
)
from fg_agent_id.signing import (
    CONTEXT_AGENT_CARD,
    CONTEXT_DELEGATION,
    DOMAIN,
    domain_tag,
)


def test_signing_input_is_length_prefixed_and_tagged():
    payload = {"a": 1}
    data = signing_input(CONTEXT_DELEGATION, payload)
    tag = domain_tag(CONTEXT_DELEGATION)

    assert data[:2] == len(tag).to_bytes(2, "big")
    assert data[2:2 + len(tag)] == tag
    assert tag == f"{DOMAIN}/{CONTEXT_DELEGATION}".encode()


def test_different_contexts_produce_different_signing_input():
    payload = {"same": "payload"}
    assert signing_input(CONTEXT_DELEGATION, payload) != signing_input(
        CONTEXT_AGENT_CARD, payload
    )


def test_signature_does_not_transfer_across_contexts():
    """The attack domain separation exists to stop: a signature harvested for
    one artifact type must not verify as another."""
    keys = KeyPair.generate()
    payload = {"issuer": "x", "subject": "y"}
    signature = sign_payload(keys, CONTEXT_DELEGATION, payload)

    verify_payload(keys.public, CONTEXT_DELEGATION, payload, signature)
    with pytest.raises(SignatureError):
        verify_payload(keys.public, CONTEXT_AGENT_CARD, payload, signature)


def test_bare_canonical_signature_is_rejected():
    """A signature over undomained canonical JSON (the pre-v0.2 format) must
    not verify — old-format artifacts are not silently accepted."""
    from fg_agent_id import canonical_json

    keys = KeyPair.generate()
    payload = {"issuer": "x"}
    legacy = base64.b64encode(keys.sign(canonical_json(payload))).decode()

    with pytest.raises(SignatureError):
        verify_payload(keys.public, CONTEXT_DELEGATION, payload, legacy)


def test_malformed_base64_is_a_signature_error_not_a_crash():
    keys = KeyPair.generate()
    with pytest.raises(SignatureError):
        verify_payload(keys.public, CONTEXT_DELEGATION, {"a": 1}, "not base64!!")


def test_verify_by_address_uses_the_self_certified_key():
    identity = AgentIdentity.generate("scout")
    payload = {"hello": "world"}
    signature = sign_payload(identity.keys, CONTEXT_DELEGATION, payload)

    verify_by_address(identity.address, CONTEXT_DELEGATION, payload, signature)

    other = AgentIdentity.generate("impostor")
    with pytest.raises(SignatureError):
        verify_by_address(other.address, CONTEXT_DELEGATION, payload, signature)


def test_real_artifacts_still_verify_end_to_end():
    owner = OwnerIdentity.generate("acme")
    agent = owner.create_agent("worker", scopes={"read"})

    agent.card().verify()
    assert agent.delegation_chain.verify(agent.address) == frozenset({"read"})


def test_empty_context_is_rejected():
    with pytest.raises(ValueError):
        domain_tag("")
