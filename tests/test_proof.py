"""Audience-bound proof of possession."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest

from fg_agent_id import (
    AgentIdentity,
    Challenge,
    ChallengeResponse,
    ChallengeStore,
    SignatureError,
)

AUDIENCE = "https://workspace.example"
OTHER_AUDIENCE = "https://evil.example"


def test_happy_path_proves_the_address():
    agent = AgentIdentity.generate("worker")
    challenge = Challenge.issue(AUDIENCE)
    response = challenge.respond(agent.keys, agent.address)

    assert response.verify(challenge, audience=AUDIENCE) == agent.address


def test_response_cannot_be_replayed_to_a_different_audience():
    """The core fix: a proof collected by one server is useless at another."""
    agent = AgentIdentity.generate("worker")
    challenge = Challenge.issue(AUDIENCE)
    response = challenge.respond(agent.keys, agent.address)

    with pytest.raises(SignatureError, match="addressed to"):
        response.verify(challenge, audience=OTHER_AUDIENCE)


def test_attacker_cannot_relabel_the_audience():
    """Rewriting the audience field invalidates the signature, because the
    audience is inside the signed payload."""
    agent = AgentIdentity.generate("worker")
    challenge = Challenge.issue(AUDIENCE)
    response = challenge.respond(agent.keys, agent.address)

    forged = response.model_copy(update={"audience": OTHER_AUDIENCE})
    tampered_challenge = challenge.model_copy(update={"audience": OTHER_AUDIENCE})

    with pytest.raises(SignatureError):
        forged.verify(tampered_challenge, audience=OTHER_AUDIENCE)


def test_verifier_must_supply_its_own_audience():
    agent = AgentIdentity.generate("worker")
    challenge = Challenge.issue(AUDIENCE)
    response = challenge.respond(agent.keys, agent.address)

    with pytest.raises(SignatureError, match="own audience"):
        response.verify(challenge, audience="")


def test_nonce_mismatch_is_rejected():
    agent = AgentIdentity.generate("worker")
    challenge = Challenge.issue(AUDIENCE)
    response = challenge.respond(agent.keys, agent.address)

    other = Challenge.issue(AUDIENCE).model_copy(
        update={"challenge_id": challenge.challenge_id}
    )
    with pytest.raises(SignatureError, match="nonce"):
        response.verify(other, audience=AUDIENCE)


def test_challenge_id_mismatch_is_rejected():
    agent = AgentIdentity.generate("worker")
    challenge = Challenge.issue(AUDIENCE)
    response = challenge.respond(agent.keys, agent.address)

    with pytest.raises(SignatureError, match="does not match the issued challenge"):
        response.verify(Challenge.issue(AUDIENCE), audience=AUDIENCE)


def test_purpose_is_bound():
    """A proof signed for one purpose cannot be reused for another."""
    agent = AgentIdentity.generate("worker")
    login = Challenge.issue(AUDIENCE, purpose="authenticate")
    response = login.respond(agent.keys, agent.address)

    elevated = login.model_copy(update={"purpose": "sign-transaction"})
    with pytest.raises(SignatureError, match="purpose"):
        response.verify(elevated, audience=AUDIENCE)


def test_expired_challenge_is_rejected():
    agent = AgentIdentity.generate("worker")
    challenge = Challenge.issue(AUDIENCE, ttl_seconds=60)
    response = challenge.respond(agent.keys, agent.address)

    later = datetime.now(UTC) + timedelta(seconds=120)
    with pytest.raises(SignatureError, match="expired"):
        response.verify(challenge, audience=AUDIENCE, now=later)


def test_wrong_key_cannot_answer_for_another_address():
    victim = AgentIdentity.generate("victim")
    attacker = AgentIdentity.generate("attacker")
    challenge = Challenge.issue(AUDIENCE)

    forged = ChallengeResponse.create(attacker.keys, victim.address, challenge)
    with pytest.raises(SignatureError):
        forged.verify(challenge, audience=AUDIENCE)


def test_nonce_is_full_entropy():
    challenge = Challenge.issue(AUDIENCE)
    assert len(base64.b64decode(challenge.nonce)) == 32


def test_short_nonce_is_rejected_at_construction():
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="at least"):
        Challenge(
            challenge_id="c1",
            nonce=base64.b64encode(b"short").decode(),
            audience=AUDIENCE,
            purpose="authenticate",
            issued_at=now,
            expires_at=now + timedelta(seconds=60),
        )


def test_empty_audience_is_rejected_at_construction():
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="audience"):
        Challenge(
            challenge_id="c1",
            nonce=base64.b64encode(b"\x00" * 32).decode(),
            audience="",
            purpose="authenticate",
            issued_at=now,
            expires_at=now + timedelta(seconds=60),
        )


def test_response_round_trips_through_json():
    agent = AgentIdentity.generate("worker")
    challenge = Challenge.issue(AUDIENCE)
    response = challenge.respond(agent.keys, agent.address)

    revived = ChallengeResponse.model_validate(response.model_dump())
    challenge_revived = Challenge.model_validate(challenge.model_dump(mode="json"))

    assert revived.verify(challenge_revived, audience=AUDIENCE) == agent.address


class TestChallengeStore:
    def test_issue_then_consume(self):
        store = ChallengeStore()
        challenge = store.issue(AUDIENCE)
        assert store.consume(challenge.challenge_id) == challenge

    def test_consume_is_single_use(self):
        store = ChallengeStore()
        challenge = store.issue(AUDIENCE)

        assert store.consume(challenge.challenge_id) is not None
        assert store.consume(challenge.challenge_id) is None

    def test_unknown_id_returns_none(self):
        assert ChallengeStore().consume("nope") is None

    def test_expired_entries_are_pruned(self):
        store = ChallengeStore(ttl_seconds=-1)
        challenge = store.issue(AUDIENCE)
        assert store.consume(challenge.challenge_id) is None
        assert len(store) == 0
