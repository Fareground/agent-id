"""Regressions for findings from the 2026-07-19 adversarial audit.

Each test reproduces a concrete attack that worked before the fix.
"""

from __future__ import annotations

import base64

import pytest

from fg_agent_id import (
    AgentCard,
    Challenge,
    KeyPair,
    OwnerIdentity,
    RevocationRegistry,
    SignatureError,
    sign_payload,
)
from fg_agent_id.signing import CONTEXT_DELEGATION, decode_signature

_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def alternate_encodings(signature: str) -> list[str]:
    """Other base64 strings that decode to the same bytes.

    The final character of a 64-byte base64 encoding carries only 2 significant
    bits; the other 4 are ignored on decode, so 16 spellings decode identically.
    """
    raw = base64.b64decode(signature)
    out = []
    for ch in _B64_ALPHABET:
        candidate = signature[:-3] + ch + "=="
        if candidate == signature:
            continue
        try:
            if base64.b64decode(candidate, validate=True) == raw:
                out.append(candidate)
        except Exception:
            pass
    return out


class TestSignatureMalleability:
    """A revoked delegation must not become valid again by re-spelling its
    signature. The digest used to hash the base64 *text*, so an alternate
    spelling produced a different digest and slipped past its own revocation."""

    def test_alternate_encodings_exist(self):
        owner = OwnerIdentity.generate("acme")
        subject = OwnerIdentity.generate("worker")
        grant = owner.grant(subject.address, {"read"}, ttl_seconds=3600)
        assert alternate_encodings(grant.signature), "no malleable spelling found"

    def test_non_canonical_signature_is_rejected(self):
        from fg_agent_id import DelegationError

        owner = OwnerIdentity.generate("acme")
        subject = OwnerIdentity.generate("worker")
        grant = owner.grant(subject.address, {"read"}, ttl_seconds=3600)

        for alt in alternate_encodings(grant.signature):
            # Delegation.verify wraps signature failures as DelegationError.
            with pytest.raises(DelegationError):
                grant.model_copy(update={"signature": alt}).verify()

    def test_revocation_cannot_be_dodged_by_re_spelling(self):
        owner = OwnerIdentity.generate("acme")
        subject = OwnerIdentity.generate("worker")
        grant = owner.grant(subject.address, {"read"}, ttl_seconds=3600)

        registry = RevocationRegistry()
        registry.add(owner.revoke(grant))
        assert registry.is_revoked(grant)

        from fg_agent_id import DelegationError

        for alt in alternate_encodings(grant.signature):
            evil = grant.model_copy(update={"signature": alt})
            # The re-spelled credential no longer verifies at all, so it can
            # never be presented as a live grant regardless of its digest.
            with pytest.raises(DelegationError):
                evil.verify()
            # And computing its digest is refused rather than silently
            # returning a different identifier that misses the revocation.
            with pytest.raises(SignatureError):
                _ = evil.digest

    def test_digest_is_stable_for_the_canonical_signature(self):
        owner = OwnerIdentity.generate("acme")
        subject = OwnerIdentity.generate("worker")
        grant = owner.grant(subject.address, {"read"}, ttl_seconds=3600)
        assert grant.digest == grant.model_copy().digest

    def test_decode_signature_rejects_non_canonical(self):
        keys = KeyPair.generate()
        sig = sign_payload(keys, CONTEXT_DELEGATION, {"a": 1})
        decode_signature(sig)  # canonical form is fine
        for alt in alternate_encodings(sig):
            with pytest.raises(SignatureError):
                decode_signature(alt)


class TestNonAsciiAudience:
    """Constant-time str comparison raised TypeError on non-ASCII, which is not
    a SignatureError — so a caller catching SignatureError saw a 500, and one
    catching broadly could fail open."""

    def test_internationalized_audience_verifies(self):
        agent = OwnerIdentity.generate("agent")
        audience = "https://wörkspace.example"
        challenge = Challenge.issue(audience)
        response = challenge.respond(agent.keys, agent.address)

        assert response.verify(challenge, audience=audience) == agent.address

    def test_internationalized_audience_mismatch_is_a_signature_error(self):
        agent = OwnerIdentity.generate("agent")
        challenge = Challenge.issue("https://wörkspace.example")
        response = challenge.respond(agent.keys, agent.address)

        with pytest.raises(SignatureError):
            response.verify(challenge, audience="https://öther.example")


class TestKeyRevocationChainIsSigned:
    """The proof chain travelled inside a signed object but outside the
    signature, so it could be swapped in transit without detection."""

    def test_swapping_the_chain_invalidates_the_signature(self):
        owner = OwnerIdentity.generate("owner")
        agent = owner.create_agent("worker", scopes={"read"})
        revocation = owner.revoke_agent_key(agent)
        revocation.verify()

        other_owner = OwnerIdentity.generate("other")
        other_agent = other_owner.create_agent("other-worker", scopes={"read"})
        swapped = revocation.model_copy(
            update={"chain": other_agent.delegation_chain})

        from fg_agent_id import DelegationError

        with pytest.raises(DelegationError):
            swapped.verify()

    def test_self_revocation_still_works(self):
        agent = OwnerIdentity.generate("agent")
        from fg_agent_id import AgentIdentity

        identity = AgentIdentity.generate("solo")
        identity.revoke_own_key().verify()
        assert agent  # sanity


class TestCardExtraShadowing:
    """`extra` merges over known fields in model_dump, so a colliding key
    shadowed a real field — and model_copy then promoted the shadow, silently
    rewriting the card's own address."""

    def test_shadowing_extra_is_rejected(self):
        keys = KeyPair.generate()
        from fg_agent_id import address_from_signing_key

        address = address_from_signing_key(keys.public.signing)
        with pytest.raises(ValueError, match="shadow"):
            AgentCard(
                address=address,
                name="evil",
                signing_key=keys.public.signing_b58,
                agreement_key=keys.public.agreement_b58,
                extra={"address": "amp:key:EVIL"},
            )

    def test_legitimate_extension_fields_still_work(self):
        identity = OwnerIdentity.generate("acme").create_agent("w", scopes=set())
        card = identity.card()
        extended = AgentCard.model_validate(
            {**card.model_dump(), "future_meta": "ok"})
        assert extended.extra == {"future_meta": "ok"}
        assert extended.model_copy().model_dump()["future_meta"] == "ok"


class TestPassphraseNormalization:
    """The same passphrase typed on different platforms arrives as different
    bytes; without NFC the owner is locked out of their own key file."""

    def test_nfd_and_nfc_passphrases_are_equivalent(self):
        import unicodedata

        keys = KeyPair.generate()
        nfc = unicodedata.normalize("NFC", "pässwörd")
        nfd = unicodedata.normalize("NFD", "pässwörd")
        assert nfc != nfd  # genuinely different byte sequences

        sealed = keys.to_encrypted_bytes(nfc)
        opened = KeyPair.from_encrypted_bytes(sealed, nfd)
        assert opened.to_bytes() == keys.to_bytes()

    def test_wrong_passphrase_still_fails(self):
        sealed = KeyPair.generate().to_encrypted_bytes("pässwörd")
        with pytest.raises(ValueError):
            KeyPair.from_encrypted_bytes(sealed, "different")


class TestCardModelCopyExtra:
    """model_copy flattens extra and model_validate drops a literal 'extra'
    key, so an update of {'extra': ...} silently vanished — a foot-gun for
    anyone setting extension fields programmatically."""

    def test_model_copy_can_set_extra(self):
        card = OwnerIdentity.generate("acme").create_agent("w", scopes=set()).card()
        updated = card.model_copy(update={"extra": {"custom": 1}})
        assert updated.extra == {"custom": 1}

    def test_model_copy_replaces_extra(self):
        card = OwnerIdentity.generate("acme").create_agent("w", scopes=set()).card()
        first = card.model_copy(update={"extra": {"a": 1}})
        second = first.model_copy(update={"extra": {"b": 2}})
        assert second.extra == {"b": 2}

    def test_model_copy_of_known_field_leaves_extra_untouched(self):
        card = OwnerIdentity.generate("acme").create_agent("w", scopes=set()).card()
        seeded = card.model_copy(update={"extra": {"keep": 1}})
        renamed = seeded.model_copy(update={"name": "renamed"})
        assert renamed.name == "renamed"
        assert renamed.extra == {"keep": 1}
