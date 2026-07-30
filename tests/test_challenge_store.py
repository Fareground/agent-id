"""Pluggable challenge stores: one contract, in-memory and Redis backends."""

from __future__ import annotations

import pytest

from fg_agent_id import (
    ChallengeStore,
    ChallengeStoreBase,
    InMemoryChallengeStore,
    RedisChallengeStore,
)

try:
    import fakeredis
except ImportError:  # pragma: no cover - dev extra not installed
    fakeredis = None

AUDIENCE = "https://workspace.example"


def make_memory_store(ttl_seconds: float = 120.0) -> ChallengeStoreBase:
    return InMemoryChallengeStore(ttl_seconds=ttl_seconds)


def make_redis_store(ttl_seconds: float = 120.0) -> ChallengeStoreBase:
    return RedisChallengeStore(fakeredis.FakeRedis(), ttl_seconds=ttl_seconds)


STORE_FACTORIES = [pytest.param(make_memory_store, id="memory")]
if fakeredis is not None:
    STORE_FACTORIES.append(pytest.param(make_redis_store, id="redis"))
else:  # pragma: no cover
    STORE_FACTORIES.append(
        pytest.param(
            make_redis_store,
            id="redis",
            marks=pytest.mark.skip(reason="fakeredis not installed"),
        )
    )


@pytest.mark.parametrize("factory", STORE_FACTORIES)
class TestChallengeStoreContract:
    """Every store implementation must satisfy the same contract."""

    def test_is_a_challenge_store(self, factory):
        assert isinstance(factory(), ChallengeStoreBase)

    def test_issue_then_consume_round_trips(self, factory):
        store = factory()
        challenge = store.issue(AUDIENCE)
        assert store.consume(challenge.challenge_id) == challenge

    def test_consume_is_single_use(self, factory):
        store = factory()
        challenge = store.issue(AUDIENCE)
        assert store.consume(challenge.challenge_id) is not None
        assert store.consume(challenge.challenge_id) is None

    def test_unknown_id_returns_none(self, factory):
        assert factory().consume("nope") is None

    def test_purpose_survives_the_round_trip(self, factory):
        store = factory()
        challenge = store.issue(AUDIENCE, purpose="sign-transaction")
        assert store.consume(challenge.challenge_id).purpose == "sign-transaction"

    def test_challenges_are_independent(self, factory):
        store = factory()
        first = store.issue(AUDIENCE)
        second = store.issue(AUDIENCE)
        assert store.consume(second.challenge_id) == second
        assert store.consume(first.challenge_id) == first


def test_default_store_alias_is_in_memory():
    """`ChallengeStore` remains the historical name of the in-memory default."""
    assert ChallengeStore is InMemoryChallengeStore


def test_memory_store_prunes_expired_entries():
    store = InMemoryChallengeStore(ttl_seconds=-1)
    challenge = store.issue(AUDIENCE)
    assert store.consume(challenge.challenge_id) is None
    assert len(store) == 0


@pytest.mark.skipif(fakeredis is None, reason="fakeredis not installed")
class TestRedisChallengeStore:
    def test_expired_challenge_is_not_returned(self):
        # PX floor is 1ms; the challenge's own expires_at is also in the past,
        # so even if Redis hasn't reaped the key yet, consume returns None.
        store = RedisChallengeStore(fakeredis.FakeRedis(), ttl_seconds=-1)
        challenge = store.issue(AUDIENCE)
        assert store.consume(challenge.challenge_id) is None

    def test_workers_sharing_redis_share_the_store(self):
        """The multi-worker property the in-memory store cannot provide."""
        server = fakeredis.FakeServer()
        worker_a = RedisChallengeStore(fakeredis.FakeRedis(server=server))
        worker_b = RedisChallengeStore(fakeredis.FakeRedis(server=server))

        challenge = worker_a.issue(AUDIENCE)
        assert worker_b.consume(challenge.challenge_id) == challenge
        # ... and single-use holds across workers.
        assert worker_a.consume(challenge.challenge_id) is None

    def test_client_without_getdel_is_rejected(self):
        class LegacyClient:
            def set(self, *a, **k): ...

        with pytest.raises(TypeError, match="getdel"):
            RedisChallengeStore(LegacyClient())

    def test_keys_are_namespaced(self):
        client = fakeredis.FakeRedis()
        store = RedisChallengeStore(client)
        challenge = store.issue(AUDIENCE)
        assert client.exists(f"fg-agent-id:challenge:{challenge.challenge_id}")
