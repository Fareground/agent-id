"""Self-certifying agent addresses: ``amp:key:<base58(ed25519-signing-pub)>``.

The address *is* the signing public key, so any signed artifact from an agent
can be verified with nothing but its address — no registry required.
"""

from __future__ import annotations

from .errors import AddressError
from .keys import base58_decode, base58_encode

ADDRESS_PREFIX = "amp:key:"


def address_from_signing_key(signing_public: bytes) -> str:
    if len(signing_public) != 32:
        raise AddressError("signing public key must be 32 raw bytes")
    return ADDRESS_PREFIX + base58_encode(signing_public)


def signing_key_from_address(address: str) -> bytes:
    if not address.startswith(ADDRESS_PREFIX):
        raise AddressError(f"not an AMP address: {address!r}")
    try:
        key = base58_decode(address[len(ADDRESS_PREFIX):])
    except ValueError as exc:
        raise AddressError(f"invalid base58 in address: {address!r}") from exc
    if len(key) != 32:
        raise AddressError(f"address does not decode to a 32-byte key: {address!r}")
    return key
