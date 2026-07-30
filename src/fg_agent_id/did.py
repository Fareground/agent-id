"""``did:amp`` — a self-certifying DID method for AMP identities.

An AMP address is already a self-certifying Ed25519 key
(``amp:key:<base58(pub)>``), so ``did:amp`` is a thin, registry-free method in
the spirit of ``did:key``: the DID *is* the key, and its core verification
method resolves deterministically from the identifier alone — no network, no
ledger. The signed :class:`AgentCard` then enriches resolution with the
X25519 ``keyAgreement`` key and transport ``service`` endpoints.

    amp:key:<b58>   <->   did:amp:<b58>          (same underlying key)

Choosing a DID method (over a bespoke directory) lets AMP interoperate with the
decentralized-identity ecosystem: resolvers, DID Documents, verifiable
credentials, and DIDComm all speak this shape. Public keys are encoded as
``publicKeyMultibase`` (multibase base58btc of a multicodec-prefixed key),
exactly as ``did:key`` specifies, so an off-the-shelf resolver understands them.
"""

from __future__ import annotations

from .address import ADDRESS_PREFIX, signing_key_from_address
from .errors import AddressError
from .keys import base58_decode, base58_encode

DID_PREFIX = "did:amp:"

# Multicodec varint prefixes (unsigned-varint) for the multibase key encoding.
_ED25519_MULTICODEC = b"\xed\x01"  # ed25519-pub
_X25519_MULTICODEC = b"\xec\x01"  # x25519-pub

_DID_CONTEXT = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://w3id.org/security/suites/x25519-2020/v1",
]


def _multibase_b58(multicodec: bytes, raw: bytes) -> str:
    """multibase base58btc ('z') of a multicodec-prefixed key (did:key style)."""
    return "z" + base58_encode(multicodec + raw)


def _decode_multibase_b58(value: str, multicodec: bytes) -> bytes:
    if not value.startswith("z"):
        raise AddressError(f"unsupported multibase prefix in {value!r} (expected base58btc 'z')")
    decoded = base58_decode(value[1:])
    if not decoded.startswith(multicodec):
        raise AddressError("multicodec prefix does not match the expected key type")
    return decoded[len(multicodec):]


# -- address <-> did ---------------------------------------------------------


def address_to_did(address: str) -> str:
    """``amp:key:<b58>`` -> ``did:amp:<b58>`` (validated round-trip)."""
    signing_key_from_address(address)  # validate it decodes to a 32-byte key
    return DID_PREFIX + address[len(ADDRESS_PREFIX):]


def did_to_address(did: str) -> str:
    """``did:amp:<b58>`` -> ``amp:key:<b58>`` (validated)."""
    return ADDRESS_PREFIX + _did_suffix(did)


def _did_suffix(did: str) -> str:
    if not did.startswith(DID_PREFIX):
        raise AddressError(f"not a did:amp identifier: {did!r}")
    suffix = did[len(DID_PREFIX):]
    # A did:amp may carry a path/query/fragment; the method-specific id is the
    # first segment. Keep only that for the address mapping.
    method_id = suffix.split("/")[0].split("?")[0].split("#")[0]
    key = base58_decode(method_id)
    if len(key) != 32:
        raise AddressError(f"did:amp id does not decode to a 32-byte key: {did!r}")
    return method_id


def signing_key_from_did(did: str) -> bytes:
    """The raw Ed25519 public key a ``did:amp`` certifies."""
    return base58_decode(_did_suffix(did))


# -- DID Document ------------------------------------------------------------

_KIND_TO_SERVICE = {
    "relay": "AMPRelay",
    "http": "AMPInbox",
}


def did_document(card) -> dict:
    """Build a W3C DID Document for an AgentCard's identity.

    The verification method (Ed25519) comes from the identifier itself; the
    ``keyAgreement`` (X25519) and ``service`` entries come from the signed card.
    Caller is responsible for having verified the card (``card.verify()``); this
    function assumes the card's key material is authentic.
    """
    did = address_to_did(card.address)
    sign_key = base58_decode(card.signing_key)
    agree_key = base58_decode(card.agreement_key)
    vm_id = f"{did}#key-1"
    ka_id = f"{did}#key-agreement"

    document: dict = {
        "@context": list(_DID_CONTEXT),
        "id": did,
        "alsoKnownAs": [card.address],
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": _multibase_b58(_ED25519_MULTICODEC, sign_key),
            }
        ],
        "authentication": [vm_id],
        "assertionMethod": [vm_id],
        "keyAgreement": [
            {
                "id": ka_id,
                "type": "X25519KeyAgreementKey2020",
                "controller": did,
                "publicKeyMultibase": _multibase_b58(_X25519_MULTICODEC, agree_key),
            }
        ],
    }
    if card.operator:
        document["controller"] = address_to_did(card.operator)
    services = [
        {
            "id": f"{did}#{name}",
            "type": _KIND_TO_SERVICE.get(name, "AMPEndpoint"),
            "serviceEndpoint": uri,
        }
        for name, uri in sorted(card.endpoints.items())
    ]
    if services:
        document["service"] = services
    return document


def resolve(did: str, card=None) -> dict:
    """Resolve a ``did:amp`` to a DID Document.

    Without a card, resolution is deterministic and offline — the identifier
    alone yields the Ed25519 verification method (as with ``did:key``). With a
    card, it is verified and must match the DID; the fuller document (key
    agreement + services) is then returned.
    """
    signing_key = signing_key_from_did(did)  # validates the identifier
    if card is not None:
        card.verify()
        if card.address != did_to_address(did):
            raise AddressError("card address does not match the DID being resolved")
        return did_document(card)
    # Minimal, card-less resolution: verification method only.
    canonical = DID_PREFIX + base58_encode(signing_key)
    vm_id = f"{canonical}#key-1"
    return {
        "@context": list(_DID_CONTEXT),
        "id": canonical,
        "alsoKnownAs": [did_to_address(did)],
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "Ed25519VerificationKey2020",
                "controller": canonical,
                "publicKeyMultibase": _multibase_b58(_ED25519_MULTICODEC, signing_key),
            }
        ],
        "authentication": [vm_id],
        "assertionMethod": [vm_id],
    }
