"""Revocation distribution: append-only feed, delta sync, verify-before-admit."""

from __future__ import annotations

import pytest

from fg_agent_id import (
    AgentIdentity,
    Delegation,
    DelegationError,
    FeedEntry,
    KeyRevocation,
    Revocation,
    RevocationFeed,
    RevocationRegistry,
    apply_feed_delta,
    sync_registry,
)
from fg_agent_id.feed import ENTRY_KIND_KEY_REVOCATION, ENTRY_KIND_REVOCATION


@pytest.fixture()
def owner():
    return AgentIdentity.generate("owner")


@pytest.fixture()
def agent():
    return AgentIdentity.generate("worker")


def make_revocation(owner, agent) -> Revocation:
    delegation = Delegation.grant(
        owner.keys, owner.address, agent.address, {"read"}, ttl_seconds=3600
    )
    return Revocation.revoke(owner.keys, delegation)


class TestRevocationFeed:
    def test_append_assigns_monotonic_cursors(self, owner, agent):
        feed = RevocationFeed()
        first = feed.append(make_revocation(owner, agent))
        second = feed.append(agent.revoke_own_key())
        assert (first.seq, second.seq) == (1, 2)
        assert feed.cursor == 2

    def test_entry_kinds_name_their_record(self, owner, agent):
        feed = RevocationFeed()
        assert feed.append(make_revocation(owner, agent)).kind == ENTRY_KIND_REVOCATION
        assert feed.append(agent.revoke_own_key()).kind == ENTRY_KIND_KEY_REVOCATION

    def test_entries_since_returns_only_the_delta(self, owner, agent):
        feed = RevocationFeed()
        feed.append(make_revocation(owner, agent))
        _, cursor = feed.entries_since()
        feed.append(agent.revoke_own_key())

        delta, new_cursor = feed.entries_since(cursor)
        assert [e.seq for e in delta] == [2]
        assert new_cursor == 2

    def test_future_cursor_converges_instead_of_wedging(self, owner, agent):
        feed = RevocationFeed()
        feed.append(make_revocation(owner, agent))
        delta, cursor = feed.entries_since(999)
        assert delta == []
        assert cursor == 1

    def test_empty_feed(self):
        feed = RevocationFeed()
        assert feed.entries_since() == ([], 0)
        assert len(feed) == 0

    def test_append_verifies_before_admitting(self, owner, agent):
        tampered = make_revocation(owner, agent).model_copy(
            update={"delegation_digest": "deadbeef"}
        )
        with pytest.raises(DelegationError):
            RevocationFeed().append(tampered)

    def test_append_rejects_foreign_types(self):
        with pytest.raises(TypeError, match="Revocation"):
            RevocationFeed().append({"kind": "revocation"})  # type: ignore[arg-type]


class TestFeedEntry:
    def test_round_trips_through_wire_form(self, owner, agent):
        entry = RevocationFeed().append(make_revocation(owner, agent))
        revived = FeedEntry.model_validate(entry.model_dump())
        assert revived == entry
        assert isinstance(revived.revive(), Revocation)

    def test_key_revocation_revives_to_its_type(self, agent):
        entry = RevocationFeed().append(agent.revoke_own_key())
        assert isinstance(entry.revive(), KeyRevocation)

    def test_rejects_unknown_kind(self):
        with pytest.raises(ValueError, match="kind"):
            FeedEntry(seq=1, kind="gossip", record={})

    def test_rejects_non_positive_seq(self):
        with pytest.raises(ValueError, match="seq"):
            FeedEntry(seq=0, kind=ENTRY_KIND_REVOCATION, record={})


class TestSync:
    def test_sync_applies_both_kinds_and_marks_synced(self, owner, agent):
        feed = RevocationFeed()
        revocation = make_revocation(owner, agent)
        feed.append(revocation)
        feed.append(agent.revoke_own_key())

        registry = RevocationRegistry()
        assert registry.synced_at is None
        cursor = sync_registry(registry, feed)

        assert cursor == 2
        assert revocation.delegation_digest in registry.digests
        assert registry.is_key_revoked(agent.address)
        assert registry.synced_at is not None

    def test_delta_sync_resumes_from_cursor(self, owner, agent):
        feed = RevocationFeed()
        feed.append(make_revocation(owner, agent))
        registry = RevocationRegistry()
        cursor = sync_registry(registry, feed)

        feed.append(agent.revoke_own_key())
        cursor = sync_registry(registry, feed, since=cursor)
        assert cursor == 2
        assert registry.is_key_revoked(agent.address)

    def test_hostile_entry_aborts_before_marking_synced(self, owner, agent):
        """A feed is transport, not authority: an unverifiable record must
        neither land in the registry nor let the sync count as completed."""
        good = make_revocation(owner, agent)
        forged = good.model_dump(mode="json")
        forged["delegation_digest"] = "deadbeef"  # breaks the signature

        registry = RevocationRegistry()
        entries = [
            FeedEntry(seq=1, kind=ENTRY_KIND_REVOCATION, record=forged),
        ]
        with pytest.raises(DelegationError):
            apply_feed_delta(registry, entries, cursor=1)
        assert registry.digests == frozenset()
        assert registry.synced_at is None

    def test_apply_accepts_wire_dict_entries(self, owner, agent):
        """Entries fetched over HTTP arrive as dicts, not dataclasses."""
        feed = RevocationFeed()
        entry = feed.append(make_revocation(owner, agent))

        registry = RevocationRegistry()
        cursor = apply_feed_delta(registry, [entry.model_dump()], cursor=feed.cursor)
        assert cursor == 1
        assert entry.record["delegation_digest"] in registry.digests


class TestFeedGapDetection:
    def test_dropped_middle_entry_is_rejected(self, owner, agent):
        feed = RevocationFeed()
        feed.append(make_revocation(owner, agent))
        feed.append(make_revocation(owner, AgentIdentity.generate("w2")))
        feed.append(make_revocation(owner, AgentIdentity.generate("w3")))
        entries, cursor = feed.entries_since(0)
        # A buggy/hostile transport drops the middle entry (seq 2).
        tampered = [entries[0], entries[2]]
        registry = RevocationRegistry()
        with pytest.raises(ValueError, match="non-contiguous"):
            apply_feed_delta(registry, tampered, cursor, since=0)
        # The registry was not marked synced — the half-applied delta reads stale.
        assert registry.synced_at is None

    def test_truncated_tail_is_rejected(self, owner, agent):
        feed = RevocationFeed()
        feed.append(make_revocation(owner, agent))
        feed.append(make_revocation(owner, AgentIdentity.generate("w2")))
        entries, cursor = feed.entries_since(0)
        # Transport drops the last entry but still claims the full cursor.
        with pytest.raises(ValueError, match="truncated"):
            apply_feed_delta(RevocationRegistry(), entries[:1], cursor, since=0)

    def test_clean_delta_still_applies(self, owner, agent):
        feed = RevocationFeed()
        feed.append(make_revocation(owner, agent))
        feed.append(make_revocation(owner, AgentIdentity.generate("w2")))
        registry = RevocationRegistry()
        cursor = sync_registry(registry, feed)
        assert cursor == 2
        assert registry.synced_at is not None
