"""Multi-device identity as plain delegation.

One human or agent identity, several devices, no new machinery: a stable
identity key delegates to a per-device key with the reserved ``device`` scope,
device-appropriate scopes, and an expiry. Losing a phone is
``Revocation.revoke`` on that one grant; rotating the identity key is §8 key
rotation. The device key never impersonates the identity key — it presents its
delegation and signs with its own key, so a verifier always sees WHICH device
acted (SPEC §11).

This module is a thin helper over the existing delegation primitives; there is
deliberately no device registry, enrollment flow, or sync protocol here.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from .delegation import Delegation, DelegationChain, RevocationRegistry
from .errors import DelegationError
from .keys import KeyPair

# Reserved scope marking a grant as a device delegation (SPEC §11).
DEVICE_SCOPE = "device"

# Devices are long-lived but not eternal: a default of 30 days forces a
# re-issue cadence without nagging daily. Deployments choose their own.
DEFAULT_DEVICE_TTL_SECONDS = 30 * 24 * 3600.0


def issue_device_delegation(
    identity_keys: KeyPair,
    identity_address: str,
    device_address: str,
    scopes: Iterable[str] = (),
    ttl_seconds: float = DEFAULT_DEVICE_TTL_SECONDS,
) -> Delegation:
    """Identity key grants a per-device key the right to act for it.

    ``scopes`` are the device's working scopes; the reserved ``device`` scope
    is always added so verifiers can tell a device grant from any other
    delegation. Sign with the identity key on a trusted machine; the device
    key never leaves its device.
    """
    return Delegation.grant(
        issuer_keys=identity_keys,
        issuer_address=identity_address,
        subject_address=device_address,
        scopes=set(scopes) | {DEVICE_SCOPE},
        ttl_seconds=ttl_seconds,
    )


def verify_device(
    delegation: Delegation | DelegationChain,
    identity_address: str,
    device_address: str,
    registry: RevocationRegistry | None = None,
    now: datetime | None = None,
    max_registry_age_seconds: float | None = None,
) -> frozenset[str]:
    """Does this device key currently act for this identity?

    Verifies the delegation (chain) — signature, expiry, topology — checks
    that it roots at ``identity_address``, terminates at ``device_address``,
    and carries the ``device`` scope, and consults ``registry`` for both
    delegation and identity-key revocation. When
    ``max_registry_age_seconds`` is given the registry must also be fresh
    (§5.2) — pass it whenever you have a bound, so a dead sync fails closed.

    Returns the device's effective working scopes (the reserved ``device``
    marker removed). Raises :class:`DelegationError` on any failure.
    """
    chain = (
        delegation
        if isinstance(delegation, DelegationChain)
        else DelegationChain(links=(delegation,))
    )
    if not chain.links:
        raise DelegationError("device verification needs a non-empty chain")
    if chain.root_issuer != identity_address:
        raise DelegationError(
            f"device chain roots at {chain.root_issuer}, not identity "
            f"{identity_address}"
        )
    revoked: frozenset[str] = frozenset()
    revoked_keys: frozenset[str] = frozenset()
    if registry is not None:
        if max_registry_age_seconds is not None:
            registry.require_fresh(max_registry_age_seconds, now)
        revoked = registry.digests
        revoked_keys = registry.revoked_keys
    scopes = chain.verify(device_address, now, revoked=revoked, revoked_keys=revoked_keys)
    if DEVICE_SCOPE not in scopes:
        raise DelegationError(
            f"chain to {device_address} does not carry the {DEVICE_SCOPE!r} scope"
        )
    return scopes - {DEVICE_SCOPE}
