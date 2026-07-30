"""Golden cross-implementation vectors (spec/vectors.json).

These pin the exact bytes an independent implementation must reproduce. The
composite-artifact vectors matter most: canonical JSON and base58 are easy to
get right, whereas the signing payload of a card or a delegation is where two
implementations actually diverge.
"""

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fg_agent_id import key_commitment, signing_input, verify_by_address
from fg_agent_id.address import address_from_signing_key
from fg_agent_id.canonical import canonical_json
from fg_agent_id.keys import base58_decode, base58_encode
from fg_agent_id.serde import canonical_timestamp, parse_datetime

VECTORS = json.loads(
    (Path(__file__).parent.parent / "spec" / "vectors.json").read_text()
)


def test_canonical_json_vectors():
    for case in VECTORS["canonical_json"]:
        assert canonical_json(case["input"]).hex() == case["expected_hex"]


def test_base58_vectors():
    for case in VECTORS["base58"]:
        raw = bytes.fromhex(case["input_hex"])
        assert base58_encode(raw) == case["expected"]
        assert base58_decode(case["expected"]) == raw


def test_ed25519_signature_and_address_vector():
    v = VECTORS["ed25519"]
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(v["seed_hex"]))
    public = bytes.fromhex(v["public_hex"])
    assert private.public_key().public_bytes_raw() == public
    assert private.sign(bytes.fromhex(v["message_hex"])).hex() == v["signature_hex"]
    assert address_from_signing_key(public) == v["address"]


def test_canonical_timestamp_vectors():
    for case in VECTORS["canonical_timestamp"]:
        parsed = parse_datetime("input", case["input"])
        assert canonical_timestamp(parsed) == case["expected"]


def test_signing_input_vectors():
    for case in VECTORS["signing_input"]:
        assert (
            signing_input(case["context"], case["payload"]).hex()
            == case["expected_hex"]
        )


def test_key_commitment_vector():
    v = VECTORS["key_commitment"]
    assert key_commitment(bytes.fromhex(v["signing_public_hex"])) == v["expected"]


@pytest.mark.parametrize("name", sorted(VECTORS["artifacts"]))
def test_artifact_signing_payload_vectors(name):
    """Each signed artifact's exact signing bytes and signature are pinned."""
    case = VECTORS["artifacts"][name]
    assert signing_input(case["context"], case["payload"]).hex() == case["signing_input_hex"]


# Which payload field names the key that signed each artifact.
SIGNER_FIELD = {
    "agent_card": "address",
    "agent_card_critical": "address",
    "delegation": "issuer",
    "delegation_critical": "issuer",
    "revocation": "issuer",
    "key_revocation": "issuer",
    "inception": "address",
    "key_rotation": "previous",
    "challenge_response": "address",
}


@pytest.mark.parametrize("name", sorted(VECTORS["artifacts"]))
def test_artifact_signatures_verify(name):
    """Signatures in the vectors verify against the address that signed them."""
    case = VECTORS["artifacts"][name]
    signer = case["payload"][SIGNER_FIELD[name]]
    verify_by_address(signer, case["context"], case["payload"], case["signature_b64"])


@pytest.mark.parametrize("name", sorted(VECTORS["artifacts"]))
def test_artifact_signatures_reject_cross_context_replay(name):
    """A pinned signature must not verify under any other context."""
    from fg_agent_id import SignatureError

    case = VECTORS["artifacts"][name]
    signer = case["payload"][SIGNER_FIELD[name]]
    other_context = "agent-card" if case["context"] != "agent-card" else "delegation"

    with pytest.raises(SignatureError):
        verify_by_address(signer, other_context, case["payload"], case["signature_b64"])


def test_did_document_vector():
    v = VECTORS["did_document"]
    assert v["document"]["id"] == v["did"]
    methods = v["document"]["verificationMethod"]
    assert any(m["type"] == "Ed25519VerificationKey2020" for m in methods)


def test_delegation_digest_vector():
    """The digest covers the DECODED signature, not its base64 text — base64
    has several spellings per byte string, and hashing the text let a revoked
    delegation be re-spelled past its own revocation."""
    import hashlib

    case = VECTORS["artifacts"]["delegation"]
    signed = signing_input(case["context"], case["payload"])
    raw = base64.b64decode(case["signature_b64"], validate=True)
    assert hashlib.sha256(signed + raw).hexdigest() == case["digest"]


def test_signature_bytes_are_valid_base64():
    for case in VECTORS["artifacts"].values():
        assert len(base64.b64decode(case["signature_b64"], validate=True)) == 64
