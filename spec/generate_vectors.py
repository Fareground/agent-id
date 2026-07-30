"""Regenerate spec/vectors.json.

Every vector is derived from fixed seeds and fixed timestamps, so the output is
byte-stable across runs. Run this after any intentional wire-format change:

    python spec/generate_vectors.py

Then review the diff — an unexpected change here means the wire format moved.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from fg_agent_id import (
    AgentCard,
    Challenge,
    ChallengeResponse,
    Delegation,
    Inception,
    KeyPair,
    KeyRevocation,
    KeyRotation,
    ParticipantKind,
    Revocation,
    address_from_signing_key,
    canonical_json,
    did_document,
    key_commitment,
    signing_input,
)
from fg_agent_id.serde import canonical_timestamp
from fg_agent_id.signing import (
    CONTEXT_AGENT_CARD,
    CONTEXT_CHALLENGE_RESPONSE,
    CONTEXT_DELEGATION,
    CONTEXT_INCEPTION,
    CONTEXT_KEY_REVOCATION,
    CONTEXT_KEY_ROTATION,
    CONTEXT_REVOCATION,
)

SEED_A = bytes(range(32))
SEED_B = bytes(range(32, 64))
SEED_C = bytes(range(64, 96))
AGREEMENT_SEED = bytes(range(96, 128))

FIXED_TIME = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
FIXED_EXPIRY = datetime(2026, 2, 1, 0, 0, 0, tzinfo=UTC)


def keypair(seed: bytes) -> KeyPair:
    return KeyPair(
        signing_key=Ed25519PrivateKey.from_private_bytes(seed),
        agreement_key=X25519PrivateKey.from_private_bytes(AGREEMENT_SEED),
    )


def signed(context: str, payload: dict, keys: KeyPair) -> dict:
    data = signing_input(context, payload)
    return {
        "context": context,
        "payload": payload,
        "signing_input_hex": data.hex(),
        "signature_b64": base64.b64encode(keys.sign(data)).decode(),
    }


def build() -> dict:
    keys_a = keypair(SEED_A)
    keys_b = keypair(SEED_B)
    keys_c = keypair(SEED_C)
    addr_a = address_from_signing_key(keys_a.public.signing)
    addr_b = address_from_signing_key(keys_b.public.signing)
    addr_c = address_from_signing_key(keys_c.public.signing)

    card = AgentCard(
        address=addr_a,
        name="conformance-agent",
        kind=ParticipantKind.AGENT,
        operator=addr_b,
        signing_key=keys_a.public.signing_b58,
        agreement_key=keys_a.public.agreement_b58,
        payload_types=("application/json", "text/plain"),
        endpoints={"relay": "https://relay.example/amp", "wake": "https://agent.example/wake"},
        policy_summary="conformance",
    )

    # Criticality (§4.1): a card carrying an extension field the issuer marks
    # as must-understand. Verifiers that don't understand `x-conformance`
    # must reject this card even though its signature verifies.
    card_critical = AgentCard(
        address=addr_a,
        name="conformance-agent",
        kind=ParticipantKind.AGENT,
        operator=addr_b,
        signing_key=keys_a.public.signing_b58,
        agreement_key=keys_a.public.agreement_b58,
        payload_types=("application/json", "text/plain"),
        endpoints={"relay": "https://relay.example/amp"},
        policy_summary="conformance",
        critical=("x-conformance",),
        extra={"x-conformance": "required"},
    )

    delegation = Delegation(
        issuer=addr_b,
        subject=addr_a,
        scopes=frozenset({"read", "write"}),
        issued_at=FIXED_TIME,
        expires_at=FIXED_EXPIRY,
    )
    delegation_signature = base64.b64encode(
        keys_b.sign(signing_input(CONTEXT_DELEGATION, delegation._payload()))
    ).decode()
    signed_delegation = delegation.model_copy(update={"signature": delegation_signature})

    delegation_critical = Delegation(
        issuer=addr_b,
        subject=addr_a,
        scopes=frozenset({"read", "pay:usdc:tx<=25:total<=100"}),
        issued_at=FIXED_TIME,
        expires_at=FIXED_EXPIRY,
        critical=("x-conformance",),
        extra={"x-conformance": "required"},
    )

    revocation = Revocation(
        issuer=addr_b,
        delegation_digest=signed_delegation.digest,
        revoked_at=FIXED_TIME,
    )
    key_revocation = KeyRevocation(address=addr_a, issuer=addr_a, revoked_at=FIXED_TIME)

    inception = Inception(
        address=addr_a,
        next_commitment=key_commitment(keys_b.public.signing),
        created_at=FIXED_TIME,
    )
    rotation = KeyRotation(
        identity=addr_a,
        sequence=1,
        previous=addr_a,
        next_address=addr_b,
        next_commitment=key_commitment(keys_c.public.signing),
        rotated_at=FIXED_TIME,
    )

    challenge = Challenge(
        challenge_id="00000000-0000-4000-8000-000000000001",
        nonce=base64.b64encode(bytes(range(32))).decode(),
        audience="https://workspace.example",
        purpose="authenticate",
        issued_at=FIXED_TIME,
        expires_at=FIXED_EXPIRY,
    )
    response = ChallengeResponse(
        challenge_id=challenge.challenge_id,
        address=addr_a,
        audience=challenge.audience,
        purpose=challenge.purpose,
        nonce=challenge.nonce,
    )

    signed_card = AgentCard.create(
        keys=keys_a,
        address=addr_a,
        name="conformance-agent",
        kind=ParticipantKind.AGENT,
        operator=addr_b,
        payload_types=("application/json", "text/plain"),
        endpoints={"relay": "https://relay.example/amp", "wake": "https://agent.example/wake"},
        policy_summary="conformance",
    )

    return {
        "version": "amp/0.2",
        "note": (
            "Golden vectors for fg-agent-id. Signatures are computed over "
            "signing_input(context, payload) = uint16be(len(tag)) || tag || "
            "canonical_json(payload), where tag = 'fg-agent-id/v1/<context>'. "
            "Regenerate with spec/generate_vectors.py."
        ),
        "domain": "fg-agent-id/v1",
        "canonical_json": [
            {
                "input": {"b": 1, "a": "ü", "c": [3, 2, 1]},
                "expected_hex": canonical_json({"b": 1, "a": "ü", "c": [3, 2, 1]}).hex(),
            },
            {
                "input": {"z": 1, "a": 2, "m": 3},
                "expected_hex": canonical_json({"z": 1, "a": 2, "m": 3}).hex(),
            },
            {
                "input": {"nested": {"y": [1, {"x": True}], "w": None}},
                "expected_hex": canonical_json(
                    {"nested": {"y": [1, {"x": True}], "w": None}}
                ).hex(),
            },
        ],
        "base58": [
            {"input_hex": "000001", "expected": "112"},
            {"input_hex": "ffff", "expected": "LUv"},
            {
                "input_hex": bytes(range(32)).hex(),
                "expected": "1thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE",
            },
        ],
        "ed25519": {
            "seed_hex": SEED_A.hex(),
            "public_hex": keys_a.public.signing.hex(),
            "address": addr_a,
            "message_hex": b"amp-conformance".hex(),
            "signature_hex": keys_a.sign(b"amp-conformance").hex(),
        },
        "canonical_timestamp": [
            {"input": "2026-07-19T12:30:05.123456+00:00", "expected": "2026-07-19T12:30:05.123Z"},
            {"input": "2026-07-19T14:00:00+02:00", "expected": "2026-07-19T12:00:00.000Z"},
            {"input": "2026-01-01T00:00:00+00:00", "expected": canonical_timestamp(FIXED_TIME)},
        ],
        "signing_input": [
            {
                "context": CONTEXT_DELEGATION,
                "payload": {"a": 1},
                "expected_hex": signing_input(CONTEXT_DELEGATION, {"a": 1}).hex(),
            },
            {
                "context": CONTEXT_AGENT_CARD,
                "payload": {"a": 1},
                "expected_hex": signing_input(CONTEXT_AGENT_CARD, {"a": 1}).hex(),
            },
        ],
        "key_commitment": {
            "signing_public_hex": keys_b.public.signing.hex(),
            "expected": key_commitment(keys_b.public.signing),
        },
        "artifacts": {
            "agent_card": signed(CONTEXT_AGENT_CARD, card._payload(), keys_a),
            "agent_card_critical": signed(
                CONTEXT_AGENT_CARD, card_critical._payload(), keys_a
            ),
            "delegation": {
                **signed(CONTEXT_DELEGATION, delegation._payload(), keys_b),
                "digest": signed_delegation.digest,
            },
            "delegation_critical": signed(
                CONTEXT_DELEGATION, delegation_critical._payload(), keys_b
            ),
            "revocation": signed(CONTEXT_REVOCATION, revocation._payload(), keys_b),
            "key_revocation": signed(
                CONTEXT_KEY_REVOCATION, key_revocation._payload(), keys_a
            ),
            "inception": signed(CONTEXT_INCEPTION, inception._payload(), keys_a),
            "key_rotation": signed(CONTEXT_KEY_ROTATION, rotation._payload(), keys_a),
            "challenge_response": signed(
                CONTEXT_CHALLENGE_RESPONSE, response._payload(), keys_a
            ),
        },
        "did_document": {
            "address": addr_a,
            "did": f"did:amp:{addr_a.removeprefix('amp:key:')}",
            "document": did_document(signed_card),
        },
        "addresses": {"a": addr_a, "b": addr_b, "c": addr_c},
    }


def main() -> None:
    target = Path(__file__).parent / "vectors.json"
    target.write_text(json.dumps(build(), indent=2, sort_keys=False) + "\n")
    print(f"wrote {target}")


if __name__ == "__main__":
    main()
