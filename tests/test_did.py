"""``did:amp`` method: address<->DID mapping and DID Document resolution."""

import pytest

from fg_agent_id import (
    AgentIdentity,
    address_to_did,
    did_document,
    did_to_address,
    resolve,
    signing_key_from_did,
)
from fg_agent_id.did import DID_PREFIX
from fg_agent_id.errors import AddressError, SignatureError


def _identity_with_card(**endpoints):
    identity = AgentIdentity.generate("alice")
    return identity, identity.card(endpoints=endpoints or None)


def test_address_did_roundtrip():
    identity = AgentIdentity.generate("alice")
    did = address_to_did(identity.address)
    assert did.startswith(DID_PREFIX)
    assert did_to_address(did) == identity.address


def test_signing_key_recovered_from_did():
    identity = AgentIdentity.generate("alice")
    did = address_to_did(identity.address)
    assert signing_key_from_did(did) == identity.keys.public.signing


def test_did_suffix_tolerates_path_query_fragment():
    identity = AgentIdentity.generate("alice")
    did = address_to_did(identity.address)
    for suffix in ("#key-1", "?versionId=1", "/path"):
        assert did_to_address(did + suffix) == identity.address


def test_rejects_non_amp_did():
    with pytest.raises(AddressError):
        did_to_address("did:key:z6Mkabc")
    with pytest.raises(AddressError):
        signing_key_from_did("did:web:example.com")


def test_rejects_did_with_wrong_key_length():
    from fg_agent_id.keys import base58_encode

    bad = DID_PREFIX + base58_encode(b"\x01\x02\x03")
    with pytest.raises(AddressError):
        did_to_address(bad)


def test_did_document_has_verification_and_agreement_keys():
    _, card = _identity_with_card(http="https://alice.example/inbox")
    doc = did_document(card)
    did = address_to_did(card.address)
    assert doc["id"] == did
    assert card.address in doc["alsoKnownAs"]
    assert doc["verificationMethod"][0]["type"] == "Ed25519VerificationKey2020"
    assert doc["verificationMethod"][0]["publicKeyMultibase"].startswith("z")
    assert doc["keyAgreement"][0]["type"] == "X25519KeyAgreementKey2020"
    assert doc["authentication"] == [f"{did}#key-1"]


def test_did_document_maps_endpoints_to_services():
    _, card = _identity_with_card(
        relay="https://relay.example/amp", http="https://alice.example/inbox"
    )
    doc = did_document(card)
    services = {s["type"] for s in doc["service"]}
    assert services == {"AMPRelay", "AMPInbox"}


def test_did_document_omits_service_when_no_endpoints():
    _, card = _identity_with_card()
    assert "service" not in did_document(card)


def test_resolve_with_card_matches_and_returns_full_document():
    _, card = _identity_with_card(http="https://alice.example/inbox")
    doc = resolve(address_to_did(card.address), card)
    assert doc["keyAgreement"]
    assert doc["service"]


def test_resolve_cardless_is_deterministic_and_minimal():
    identity = AgentIdentity.generate("alice")
    did = address_to_did(identity.address)
    doc = resolve(did)
    assert doc["id"] == did
    assert len(doc["verificationMethod"]) == 1
    assert "keyAgreement" not in doc
    assert "service" not in doc


def test_resolve_rejects_card_mismatched_to_did():
    _, card = _identity_with_card()
    other = AgentIdentity.generate("mallory")
    with pytest.raises(AddressError):
        resolve(address_to_did(other.address), card)


def test_resolve_rejects_tampered_card():
    _, card = _identity_with_card()
    forged = card.model_copy(update={"name": "tampered"})
    with pytest.raises(SignatureError):
        resolve(address_to_did(card.address), forged)


def test_card_did_helpers_agree_with_module():
    _, card = _identity_with_card(http="https://alice.example/inbox")
    assert card.did == address_to_did(card.address)
    assert card.to_did_document() == did_document(card)


def test_multibase_encodes_multicodec_prefix():
    from fg_agent_id.did import _decode_multibase_b58, _multibase_b58

    key = bytes(range(32))
    encoded = _multibase_b58(b"\xed\x01", key)
    assert _decode_multibase_b58(encoded, b"\xed\x01") == key
    with pytest.raises(AddressError):
        _decode_multibase_b58(encoded, b"\xec\x01")  # wrong codec
