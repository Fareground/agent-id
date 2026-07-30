"""Encrypted key files at rest, pinned timestamps, and revocation freshness."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from fg_agent_id import (
    Delegation,
    DelegationError,
    KeyPair,
    OwnerIdentity,
    RevocationRegistry,
)
from fg_agent_id.serde import canonical_timestamp, parse_datetime


class TestEncryptedKeyFile:
    def test_round_trip(self):
        keys = KeyPair.generate()
        sealed = keys.to_encrypted_bytes("correct horse battery staple")
        opened = KeyPair.from_encrypted_bytes(sealed, "correct horse battery staple")

        assert opened.to_bytes() == keys.to_bytes()

    def test_wrong_passphrase_fails(self):
        sealed = KeyPair.generate().to_encrypted_bytes("right")
        with pytest.raises(ValueError, match="wrong passphrase"):
            KeyPair.from_encrypted_bytes(sealed, "wrong")

    def test_private_key_is_not_in_the_ciphertext(self):
        keys = KeyPair.generate()
        sealed = keys.to_encrypted_bytes("pw")
        assert keys.to_bytes() not in sealed

    def test_tampered_ciphertext_fails(self):
        sealed = bytearray(KeyPair.generate().to_encrypted_bytes("pw"))
        sealed[-1] ^= 0xFF
        with pytest.raises(ValueError):
            KeyPair.from_encrypted_bytes(bytes(sealed), "pw")

    def test_tampered_header_fails(self):
        """The header is authenticated, so a flipped version byte cannot
        silently select different parameters."""
        sealed = bytearray(KeyPair.generate().to_encrypted_bytes("pw"))
        sealed[4] = 9
        with pytest.raises(ValueError, match="unsupported key file version"):
            KeyPair.from_encrypted_bytes(bytes(sealed), "pw")

    def test_rejects_foreign_data(self):
        with pytest.raises(ValueError, match="not an encrypted"):
            KeyPair.from_encrypted_bytes(b"random junk that is long enough", "pw")

    def test_empty_passphrase_rejected(self):
        with pytest.raises(ValueError, match="passphrase"):
            KeyPair.generate().to_encrypted_bytes("")

    def test_each_seal_uses_fresh_salt_and_nonce(self):
        keys = KeyPair.generate()
        assert keys.to_encrypted_bytes("pw") != keys.to_encrypted_bytes("pw")


class TestPinnedTimestamps:
    def test_canonical_form_is_millisecond_z(self):
        stamp = canonical_timestamp(datetime(2026, 7, 19, 12, 30, 5, 123456, tzinfo=UTC))
        assert stamp == "2026-07-19T12:30:05.123Z"

    def test_non_utc_input_is_converted(self):
        from datetime import timezone

        aware = datetime(2026, 7, 19, 14, 0, 0, tzinfo=timezone(timedelta(hours=2)))
        assert canonical_timestamp(aware) == "2026-07-19T12:00:00.000Z"

    def test_naive_datetime_is_rejected(self):
        with pytest.raises(ValueError, match="timezone-aware"):
            parse_datetime("when", datetime(2026, 7, 19, 12, 0, 0))

    def test_naive_string_is_rejected(self):
        with pytest.raises(ValueError, match="timezone"):
            parse_datetime("when", "2026-07-19T12:00:00")

    def test_z_suffix_parses(self):
        parsed = parse_datetime("when", "2026-07-19T12:30:05.123Z")
        assert canonical_timestamp(parsed) == "2026-07-19T12:30:05.123Z"

    def test_sub_millisecond_precision_is_dropped_at_construction(self):
        """In-memory state matches the wire exactly, so a JSON round-trip can
        never change what a signature covers."""
        owner = OwnerIdentity.generate("acme")
        agent = OwnerIdentity.generate("other")
        grant = owner.grant(agent.address, {"read"}, ttl_seconds=3600)

        assert grant.issued_at.microsecond % 1000 == 0
        revived = Delegation.model_validate(grant.model_dump(mode="json"))
        assert revived == grant
        revived.verify()

    def test_signature_survives_json_round_trip(self):
        owner = OwnerIdentity.generate("acme")
        subject = OwnerIdentity.generate("sub")
        grant = owner.grant(subject.address, {"read", "write"}, ttl_seconds=3600)

        revived = Delegation.model_validate(grant.model_dump(mode="json"))
        revived.verify()
        assert revived.digest == grant.digest


class TestRevocationFreshness:
    def test_never_synced_is_stale(self):
        registry = RevocationRegistry()
        assert registry.age_seconds() is None
        assert registry.is_stale(60)

    def test_fresh_after_sync(self):
        registry = RevocationRegistry()
        registry.mark_synced()
        assert not registry.is_stale(60)
        assert registry.age_seconds() < 5

    def test_goes_stale_with_age(self):
        registry = RevocationRegistry()
        registry.mark_synced(datetime.now(UTC) - timedelta(seconds=300))
        assert registry.is_stale(60)

    def test_require_fresh_fails_closed(self):
        registry = RevocationRegistry()
        with pytest.raises(DelegationError, match="never synced"):
            registry.require_fresh(60)

    def test_require_fresh_reports_age(self):
        registry = RevocationRegistry()
        registry.mark_synced(datetime.now(UTC) - timedelta(seconds=300))
        with pytest.raises(DelegationError, match="last synced"):
            registry.require_fresh(60)

    def test_require_fresh_passes_when_current(self):
        registry = RevocationRegistry()
        registry.mark_synced()
        registry.require_fresh(60)

    def test_revocations_still_work(self):
        owner = OwnerIdentity.generate("acme")
        agent = owner.create_agent("worker", scopes={"read"})
        grant = agent.delegation_chain.links[0]

        registry = RevocationRegistry()
        registry.mark_synced()
        assert not registry.is_revoked(grant)

        registry.add(owner.revoke(grant))
        assert registry.is_revoked(grant)
