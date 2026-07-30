"""Domain-separated signing input.

Every signature in this standard is computed over ``signing_input(context,
payload)`` rather than over bare canonical JSON. The context tag names what
kind of artifact is being signed, so a signature produced for one artifact
type can never be replayed as a valid signature for another — even if the two
payloads happen to canonicalize to the same bytes.

Wire construction (unambiguous by length prefix, not by delimiter):

    uint16be(len(tag)) || tag || canonical_json(payload)

where ``tag = "fg-agent-id/v1/<context>"`` encoded as UTF-8. The
length prefix means no escaping is needed and no payload can ever be parsed as
part of the tag.

Adding a new signed artifact type means adding a context constant here. Never
reuse a context across artifact types, and never sign a bare payload.
"""

from __future__ import annotations

import base64
from typing import Any

from .canonical import canonical_json
from .errors import SignatureError
from .keys import KeyPair, PublicKeys

DOMAIN = "fg-agent-id/v1"

# One constant per signed artifact type. These strings are wire-visible.
CONTEXT_AGENT_CARD = "agent-card"
CONTEXT_DELEGATION = "delegation"
CONTEXT_REVOCATION = "revocation"
CONTEXT_KEY_REVOCATION = "key-revocation"
CONTEXT_KEY_ROTATION = "key-rotation"
CONTEXT_INCEPTION = "inception"
CONTEXT_CHALLENGE_RESPONSE = "challenge-response"

_MAX_TAG_BYTES = 0xFFFF


def domain_tag(context: str) -> bytes:
    """The full UTF-8 domain tag for a context (``<DOMAIN>/<context>``)."""
    if not context:
        raise ValueError("signing context must be a non-empty string")
    tag = f"{DOMAIN}/{context}".encode()
    if len(tag) > _MAX_TAG_BYTES:
        raise ValueError("signing context tag is too long")
    return tag


def signing_input(context: str, payload: Any) -> bytes:
    """The exact bytes to sign or verify for ``payload`` under ``context``."""
    tag = domain_tag(context)
    return len(tag).to_bytes(2, "big") + tag + canonical_json(payload)


def sign_payload(keys: KeyPair, context: str, payload: Any) -> str:
    """Sign ``payload`` under ``context``; returns a base64 signature."""
    return base64.b64encode(keys.sign(signing_input(context, payload))).decode()


def decode_signature(signature: str) -> bytes:
    """Decode a base64 signature, rejecting any non-canonical spelling.

    ``b64decode(validate=True)`` still accepts padding characters whose unused
    trailing bits are non-zero, so a single 64-byte signature has 16 distinct
    base64 encodings. That matters because signatures are identifiers as well
    as proofs: a delegation's revocation digest covers its signature, so an
    alternate spelling of the *same* signature yields a different digest and
    slips past a revocation while still verifying. Requiring the canonical
    spelling means one signature has exactly one wire form.
    """
    try:
        raw = base64.b64decode(signature, validate=True)
    except Exception as exc:  # malformed base64 is a signature failure
        raise SignatureError("signature is not valid base64") from exc
    if base64.b64encode(raw).decode() != signature:
        raise SignatureError("signature is not canonically base64-encoded")
    return raw


def verify_payload(
    public: PublicKeys, context: str, payload: Any, signature: str
) -> None:
    """Verify a base64 signature over ``payload`` under ``context``."""
    public.verify(decode_signature(signature), signing_input(context, payload))


def verify_by_address(
    address: str, context: str, payload: Any, signature: str
) -> None:
    """Verify against the signing key an AMP address self-certifies."""
    from .address import signing_key_from_address

    public = PublicKeys(signing=signing_key_from_address(address), agreement=_NO_AGREEMENT)
    verify_payload(public, context, payload, signature)


# Signature verification only ever touches the Ed25519 half; this placeholder
# keeps PublicKeys' shape without implying a usable X25519 key.
_NO_AGREEMENT = b"\x00" * 32
