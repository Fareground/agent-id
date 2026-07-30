"""Revocation distribution: an append-only, cursor-addressed feed.

Revocation is only useful if it travels. This module gives a producer (a
relay, a directory, a workspace) an append-only log of verified revocation
records with a monotonic cursor, and gives a consumer a sync helper that
applies a feed delta into its :class:`~fg_agent_id.delegation.RevocationRegistry`
— verifying every record again before admission, because a feed is transport
data, not an authority.

The shape is deliberately the same as a ``?since=<cursor>`` HTTP endpoint:
``entries_since(cursor)`` returns everything newer than the caller's cursor
plus the new cursor to persist. How the entries move (HTTP, gossip, a file)
is out of scope — see SPEC §5.3.
"""

from __future__ import annotations

import dataclasses
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .delegation import KeyRevocation, Revocation, RevocationRegistry
from .serde import require_mapping, require_str

# Wire-visible entry kinds. They mirror the signing contexts of the records
# they carry (§3.1), so an entry names what it claims to be.
ENTRY_KIND_REVOCATION = "revocation"
ENTRY_KIND_KEY_REVOCATION = "key-revocation"

_ENTRY_KINDS = frozenset({ENTRY_KIND_REVOCATION, ENTRY_KIND_KEY_REVOCATION})

# Cursors start below the first assigned sequence number, so "give me
# everything" is simply entries_since(FEED_START_CURSOR).
FEED_START_CURSOR = 0


@dataclass(frozen=True)
class FeedEntry:
    """One revocation record at one feed position.

    ``record`` is the record's wire form (``model_dump(mode="json")``); the
    entry itself is not signed — the record inside it is, and consumers verify
    the record, never the envelope.
    """

    seq: int
    kind: str
    record: dict[str, Any]

    def __post_init__(self) -> None:
        if not isinstance(self.seq, int) or isinstance(self.seq, bool) or self.seq <= 0:
            raise ValueError(f"seq must be a positive integer, got {self.seq!r}")
        require_str("kind", self.kind)
        if self.kind not in _ENTRY_KINDS:
            raise ValueError(f"unknown feed entry kind: {self.kind!r}")
        require_mapping("record", self.record)

    def revive(self) -> Revocation | KeyRevocation:
        """Reconstruct the carried record as its dataclass (not yet verified)."""
        if self.kind == ENTRY_KIND_REVOCATION:
            return Revocation.model_validate(self.record)
        return KeyRevocation.model_validate(self.record)

    def model_dump(self, mode: str = "python") -> dict[str, Any]:
        return {"seq": self.seq, "kind": self.kind, "record": dict(self.record)}

    @classmethod
    def model_validate(cls, data: Any) -> FeedEntry:
        if isinstance(data, cls):
            return data
        require_mapping("entry", data)
        return cls(seq=data["seq"], kind=data["kind"], record=data["record"])

    def model_copy(self, update: dict[str, Any] | None = None) -> FeedEntry:
        return dataclasses.replace(self, **(update or {}))


class RevocationFeed:
    """Producer-side append-only log of verified revocation records.

    Append verifies before admitting — a feed that relays unverified records
    would launder garbage into every consumer that trusts its transport. The
    cursor is strictly monotonic and never reused; entries are never removed
    (a revocation is permanent, so the log only grows).
    """

    def __init__(self) -> None:
        self._entries: list[FeedEntry] = []
        self._seq = FEED_START_CURSOR
        self._lock = threading.Lock()

    def append(self, record: Revocation | KeyRevocation) -> FeedEntry:
        """Verify and append a record; returns its feed entry."""
        if isinstance(record, Revocation):
            kind = ENTRY_KIND_REVOCATION
        elif isinstance(record, KeyRevocation):
            kind = ENTRY_KIND_KEY_REVOCATION
        else:
            raise TypeError(
                f"record must be a Revocation or KeyRevocation, "
                f"got {type(record).__name__}"
            )
        record.verify()
        with self._lock:
            self._seq += 1
            entry = FeedEntry(seq=self._seq, kind=kind, record=record.model_dump(mode="json"))
            self._entries.append(entry)
        return entry

    def entries_since(self, cursor: int = FEED_START_CURSOR) -> tuple[list[FeedEntry], int]:
        """Everything newer than ``cursor``, plus the new cursor to persist.

        A consumer passes its last cursor so each sync transfers only the
        delta. A cursor from the future returns nothing and echoes the feed's
        real cursor, so a consumer with corrupted state converges instead of
        silently skipping records forever.
        """
        with self._lock:
            return [e for e in self._entries if e.seq > cursor], self._seq

    @property
    def cursor(self) -> int:
        """The sequence number of the newest entry (FEED_START_CURSOR if empty)."""
        with self._lock:
            return self._seq

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


def apply_feed_delta(
    registry: RevocationRegistry,
    entries: list[FeedEntry | dict[str, Any]],
    cursor: int,
    synced_at: datetime | None = None,
    *,
    since: int = FEED_START_CURSOR,
) -> int:
    """Apply a feed delta to a registry; returns the cursor to persist.

    Verify-before-admit: every record is re-verified by the registry on entry
    (``RevocationRegistry.add`` / ``revoke_key`` verify signatures), so a
    hostile or corrupted feed cannot plant a revocation. Any invalid record
    aborts the sync *before* the registry is marked synced — a half-applied
    delta must read as stale, not fresh.

    Feed sequence numbers are contiguous and monotonic (§5.3). The delta is
    validated against that on the consumer side too: entry seqs must strictly
    increase with no gaps, each must be newer than ``since``, and the delta's
    last seq must equal the ``cursor`` being persisted. This closes the
    consumer half of the "skipping records forever" hazard — a buggy or
    hostile transport that drops entries from the middle or tail can no longer
    leave the consumer silently missing revocations while still marking itself
    synced. Pass ``since`` = the cursor you synced from so a dropped head entry
    is caught as well. A detected gap raises ``ValueError`` before the registry
    is touched.

    Only marks the registry synced; the caller persists the returned cursor
    alongside its registry snapshot so the next sync can resume from it.
    """
    revived_entries = [FeedEntry.model_validate(entry) for entry in entries]
    previous = since
    for feed_entry in revived_entries:
        if feed_entry.seq <= since:
            raise ValueError(
                f"feed delta contains entry seq {feed_entry.seq} not newer than "
                f"since={since}"
            )
        if feed_entry.seq != previous + 1:
            raise ValueError(
                f"feed delta is non-contiguous: expected seq {previous + 1}, "
                f"got {feed_entry.seq} (a record was dropped or reordered)"
            )
        previous = feed_entry.seq
    if revived_entries and previous != cursor:
        raise ValueError(
            f"feed delta ends at seq {previous} but the cursor to persist is "
            f"{cursor} — the delta tail was truncated"
        )
    for feed_entry in revived_entries:
        record = feed_entry.revive()
        if isinstance(record, Revocation):
            registry.add(record)
        else:
            registry.revoke_key(record)
    registry.mark_synced(synced_at)
    return cursor


def sync_registry(
    registry: RevocationRegistry,
    feed: RevocationFeed,
    since: int = FEED_START_CURSOR,
    synced_at: datetime | None = None,
) -> int:
    """Pull a local/in-process feed's delta into a registry. For remote feeds,
    fetch ``entries_since`` over your transport and call
    :func:`apply_feed_delta` with the result."""
    entries, cursor = feed.entries_since(since)
    return apply_feed_delta(registry, entries, cursor, synced_at, since=since)
