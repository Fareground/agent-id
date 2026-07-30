"""Pluggable single-use challenge storage.

Single-use enforcement is only as strong as the store behind it: a per-process
dict cannot enforce "once, globally" across multiple workers. This module
defines the minimal store interface — issue a challenge, atomically consume it
exactly once — plus two implementations:

- :class:`InMemoryChallengeStore` — the default, correct for one process.
- :class:`RedisChallengeStore` — a shared store for multi-worker deployments,
  built on Redis ``GETDEL`` so consumption is atomic without a Lua script.

The ``redis`` client is an OPTIONAL dependency (``pip install
fg-agent-id[redis]``); the class itself is importable without it because it
accepts any pre-built client object.
"""

from __future__ import annotations

import abc
import json
import threading
import time
from typing import Any

from .proof import DEFAULT_TTL_SECONDS, PURPOSE_AUTHENTICATE, Challenge

REDIS_KEY_PREFIX = "fg-agent-id:challenge:"


class ChallengeStoreBase(abc.ABC):
    """Minimal contract every challenge store must honor.

    ``consume`` MUST be atomic: two concurrent consumers of the same
    ``challenge_id`` must never both receive the challenge. That atomicity is
    the whole point of the store — it is what turns "verify a signature" into
    "verify a signature at most once".
    """

    @abc.abstractmethod
    def issue(
        self, audience: str, purpose: str = PURPOSE_AUTHENTICATE
    ) -> Challenge:
        """Create, persist, and return a fresh challenge."""

    @abc.abstractmethod
    def consume(self, challenge_id: str) -> Challenge | None:
        """Atomically remove and return a challenge.

        Returns ``None`` when the id is unknown, already consumed, or expired.
        A challenge returned once MUST never be returned again.
        """


class InMemoryChallengeStore(ChallengeStoreBase):
    """Single-use challenge storage for one process.

    Consumption pops, so a nonce can never be spent twice. Expired entries are
    pruned on every access rather than by a timer, which keeps the store honest
    without a background task.

    Single-process only: with multiple workers each holds its own dict, so a
    challenge issued on one worker cannot be consumed on another and single-use
    stops being enforced globally. Deployments beyond one worker must use a
    shared implementation such as :class:`RedisChallengeStore`.
    """

    def __init__(self, ttl_seconds: float = DEFAULT_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._entries: dict[str, tuple[float, Challenge]] = {}
        self._lock = threading.Lock()

    def issue(
        self, audience: str, purpose: str = PURPOSE_AUTHENTICATE
    ) -> Challenge:
        challenge = Challenge.issue(audience, purpose, self._ttl)
        deadline = time.monotonic() + self._ttl
        with self._lock:
            self._prune_locked()
            self._entries[challenge.challenge_id] = (deadline, challenge)
        return challenge

    def consume(self, challenge_id: str) -> Challenge | None:
        with self._lock:
            self._prune_locked()
            entry = self._entries.pop(challenge_id, None)
        return entry[1] if entry else None

    def _prune_locked(self) -> None:
        now = time.monotonic()
        expired = [key for key, (deadline, _) in self._entries.items() if deadline <= now]
        for key in expired:
            del self._entries[key]

    def __len__(self) -> int:
        with self._lock:
            self._prune_locked()
            return len(self._entries)


# Historical name: the store predates the pluggable interface, and callers
# imported it as `ChallengeStore`. Kept as the default implementation's alias.
ChallengeStore = InMemoryChallengeStore


class RedisChallengeStore(ChallengeStoreBase):
    """Shared challenge storage backed by Redis.

    Every worker that shares the Redis instance shares the store, so a
    challenge issued by one worker can be consumed — exactly once — by any
    other. Atomicity comes from ``GETDEL`` (Redis >= 6.2): remove-and-return
    is a single server-side operation, so no two consumers can both win.
    Expiry is enforced twice: Redis ``PX`` reaps the key server-side, and the
    challenge's own ``expires_at`` is re-checked on consume so a lagging Redis
    clock cannot resurrect a stale challenge.

    ``client`` is any object with ``set(key, value, px=...)`` and
    ``getdel(key)`` — a ``redis.Redis``, a ``fakeredis.FakeRedis``, or a
    cluster client. Constructing from a URL requires the optional ``redis``
    package (``pip install fg-agent-id[redis]``).
    """

    def __init__(
        self,
        client: Any,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        key_prefix: str = REDIS_KEY_PREFIX,
    ) -> None:
        if not (hasattr(client, "set") and hasattr(client, "getdel")):
            raise TypeError(
                "client must provide set(...) and getdel(...) — GETDEL needs "
                "Redis >= 6.2 (or a redis-py client >= 4.0)"
            )
        self._client = client
        self._ttl = ttl_seconds
        self._prefix = key_prefix

    @classmethod
    def from_url(
        cls,
        url: str,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        key_prefix: str = REDIS_KEY_PREFIX,
    ) -> RedisChallengeStore:
        """Connect to Redis by URL. Requires the optional ``redis`` extra."""
        try:
            import redis
        except ImportError as exc:  # pragma: no cover - environment-dependent
            raise ImportError(
                "RedisChallengeStore.from_url requires the optional redis "
                "dependency: pip install fg-agent-id[redis]"
            ) from exc
        return cls(redis.Redis.from_url(url), ttl_seconds, key_prefix)

    def _key(self, challenge_id: str) -> str:
        return f"{self._prefix}{challenge_id}"

    def issue(
        self, audience: str, purpose: str = PURPOSE_AUTHENTICATE
    ) -> Challenge:
        challenge = Challenge.issue(audience, purpose, self._ttl)
        payload = json.dumps(challenge.model_dump(mode="json"))
        # PX (not EX) so sub-second TTLs used in tests still expire.
        self._client.set(
            self._key(challenge.challenge_id), payload, px=max(1, int(self._ttl * 1000))
        )
        return challenge

    def consume(self, challenge_id: str) -> Challenge | None:
        raw = self._client.getdel(self._key(challenge_id))
        if raw is None:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode()
        challenge = Challenge.model_validate(json.loads(raw))
        # Belt over Redis's PX suspenders: never hand back an expired challenge
        # even if the server-side reaper has not fired yet.
        if challenge.is_expired():
            return None
        return challenge
