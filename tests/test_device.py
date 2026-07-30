"""Multi-device as delegation: per-device keys acting for one identity."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from fg_agent_id import (
    AgentIdentity,
    DelegationChain,
    DelegationError,
    Revocation,
    RevocationRegistry,
    issue_device_delegation,
    verify_device,
)
from fg_agent_id.device import DEVICE_SCOPE


@pytest.fixture()
def identity():
    return AgentIdentity.generate("sandro")


@pytest.fixture()
def phone():
    return AgentIdentity.generate("sandro-phone")


def enroll(identity, device, scopes=("converse",), ttl_seconds=3600.0):
    return issue_device_delegation(
        identity.keys, identity.address, device.address,
        scopes=scopes, ttl_seconds=ttl_seconds,
    )


class TestIssue:
    def test_device_scope_is_always_present(self, identity, phone):
        delegation = enroll(identity, phone, scopes=("converse", "pay:usd:tx<=20"))
        assert DEVICE_SCOPE in delegation.scopes
        assert "converse" in delegation.scopes

    def test_grant_is_identity_to_device(self, identity, phone):
        delegation = enroll(identity, phone)
        assert delegation.issuer == identity.address
        assert delegation.subject == phone.address


class TestVerify:
    def test_valid_device_returns_working_scopes(self, identity, phone):
        scopes = verify_device(
            enroll(identity, phone, scopes=("converse", "read")),
            identity.address, phone.address,
        )
        assert scopes == {"converse", "read"}
        assert DEVICE_SCOPE not in scopes  # the marker is plumbing, not a grant

    def test_wrong_identity_is_rejected(self, identity, phone):
        stranger = AgentIdentity.generate("stranger")
        with pytest.raises(DelegationError, match="roots at"):
            verify_device(enroll(identity, phone), stranger.address, phone.address)

    def test_wrong_device_is_rejected(self, identity, phone):
        other = AgentIdentity.generate("other-device")
        with pytest.raises(DelegationError, match="terminates"):
            verify_device(enroll(identity, phone), identity.address, other.address)

    def test_ordinary_delegation_is_not_a_device_grant(self, identity, phone):
        from fg_agent_id import Delegation

        plain = Delegation.grant(
            identity.keys, identity.address, phone.address, {"converse"},
            ttl_seconds=3600,
        )
        with pytest.raises(DelegationError, match="device"):
            verify_device(plain, identity.address, phone.address)

    def test_expired_device_delegation_is_rejected(self, identity, phone):
        delegation = enroll(identity, phone, ttl_seconds=60)
        later = datetime.now(UTC) + timedelta(hours=1)
        with pytest.raises(DelegationError, match="expired"):
            verify_device(delegation, identity.address, phone.address, now=later)

    def test_empty_chain_is_rejected(self, identity, phone):
        with pytest.raises(DelegationError, match="non-empty"):
            verify_device(DelegationChain(), identity.address, phone.address)


class TestRevocation:
    def test_lost_phone_is_one_revocation(self, identity, phone):
        """Losing a device revokes that grant only; the identity survives."""
        delegation = enroll(identity, phone)
        registry = RevocationRegistry()
        registry.add(Revocation.revoke(identity.keys, delegation))
        registry.mark_synced()

        with pytest.raises(DelegationError, match="revoked"):
            verify_device(delegation, identity.address, phone.address,
                          registry=registry)

    def test_other_devices_survive_one_revocation(self, identity, phone):
        laptop = AgentIdentity.generate("laptop")
        phone_grant = enroll(identity, phone)
        laptop_grant = enroll(identity, laptop)
        registry = RevocationRegistry()
        registry.add(Revocation.revoke(identity.keys, phone_grant))
        registry.mark_synced()

        scopes = verify_device(laptop_grant, identity.address, laptop.address,
                               registry=registry)
        assert scopes == {"converse"}

    def test_revoked_identity_key_tears_down_all_devices(self, identity, phone):
        delegation = enroll(identity, phone)
        registry = RevocationRegistry()
        registry.revoke_key(identity.revoke_own_key())
        registry.mark_synced()

        with pytest.raises(DelegationError, match="revoked identity key"):
            verify_device(delegation, identity.address, phone.address,
                          registry=registry)

    def test_stale_registry_fails_closed_when_bound_given(self, identity, phone):
        delegation = enroll(identity, phone)
        registry = RevocationRegistry()  # never synced
        with pytest.raises(DelegationError, match="stale"):
            verify_device(delegation, identity.address, phone.address,
                          registry=registry, max_registry_age_seconds=300)
