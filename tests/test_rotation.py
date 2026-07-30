"""Key rotation with pre-rotation commitments."""

from __future__ import annotations

import pytest

from fg_agent_id import (
    Inception,
    KeyPair,
    KeyRotation,
    RotatingIdentity,
    RotationChain,
    RotationError,
    RotationRegistry,
    key_commitment,
)


def test_new_identity_resolves_to_itself():
    identity = RotatingIdentity.create()
    state = identity.chain.resolve()

    assert state.current_address == identity.address
    assert state.sequence == 0
    assert state.identity == identity.identity


def test_rotation_advances_the_current_address_but_keeps_the_name():
    original = RotatingIdentity.create()
    rotated = original.rotate()

    assert rotated.identity == original.identity  # stable name survives
    assert rotated.address != original.address  # key in force changed
    assert rotated.chain.current_address == rotated.address


def test_multiple_rotations_replay_in_order():
    identity = RotatingIdentity.create()
    addresses = [identity.address]
    for _ in range(3):
        identity = identity.rotate()
        addresses.append(identity.address)

    state = identity.chain.resolve()
    assert state.sequence == 3
    assert state.current_address == addresses[-1]
    assert len(set(addresses)) == 4


def test_rotation_must_reveal_the_pre_committed_key():
    """The pre-rotation property: holding the current key is not enough to
    hijack the identity — the next key was committed to in advance."""
    identity = RotatingIdentity.create()
    attacker_key = KeyPair.generate()
    attacker_address = identity.chain.identity  # any address that isn't committed

    from fg_agent_id.address import address_from_signing_key

    hijack = KeyRotation.create(
        current_keys=identity.keys,  # attacker stole the in-force key
        identity=identity.identity,
        sequence=1,
        next_address=address_from_signing_key(attacker_key.public.signing),
        next_commitment=key_commitment(KeyPair.generate().public.signing),
    )
    assert attacker_address  # sanity

    with pytest.raises(RotationError, match="pre-rotation commitment"):
        RotationChain(inception=identity.chain.inception, rotations=(hijack,)).resolve()


def test_out_of_order_sequence_is_rejected():
    identity = RotatingIdentity.create().rotate()
    rotation = identity.chain.rotations[0]
    skewed = rotation.model_copy(update={"sequence": 5})

    with pytest.raises(RotationError, match="out of order"):
        RotationChain(inception=identity.chain.inception, rotations=(skewed,)).resolve()


def test_rotation_signed_by_a_key_not_in_force_is_rejected():
    identity = RotatingIdentity.create()
    stranger = RotatingIdentity.create()

    forged = KeyRotation.create(
        current_keys=stranger.keys,
        identity=identity.identity,
        sequence=1,
        next_address=stranger.chain.identity,
        next_commitment=key_commitment(KeyPair.generate().public.signing),
    )
    with pytest.raises(RotationError, match="in force"):
        RotationChain(inception=identity.chain.inception, rotations=(forged,)).resolve()


def test_tampered_rotation_signature_is_rejected():
    identity = RotatingIdentity.create().rotate()
    rotation = identity.chain.rotations[0]
    tampered = rotation.model_copy(update={"signature": rotation.signature[:-4] + "AAAA"})

    with pytest.raises(RotationError):
        RotationChain(inception=identity.chain.inception, rotations=(tampered,)).resolve()


def test_tampered_inception_signature_is_rejected():
    identity = RotatingIdentity.create()
    inception = identity.chain.inception
    tampered = inception.model_copy(
        update={"next_commitment": key_commitment(KeyPair.generate().public.signing)}
    )
    with pytest.raises(RotationError, match="inception"):
        RotationChain(inception=tampered).resolve()


def test_rotation_naming_a_different_identity_is_rejected():
    identity = RotatingIdentity.create().rotate()
    other = RotatingIdentity.create()
    rotation = identity.chain.rotations[0].model_copy(
        update={"identity": other.identity}
    )
    with pytest.raises(RotationError, match="names identity"):
        RotationChain(inception=identity.chain.inception, rotations=(rotation,)).resolve()


def test_chain_round_trips_through_json():
    identity = RotatingIdentity.create().rotate().rotate()
    revived = RotationChain.model_validate(identity.chain.model_dump(mode="json"))

    assert revived.resolve().current_address == identity.address


def test_inception_round_trips():
    keys = KeyPair.generate()
    inception = Inception.create(keys, key_commitment(KeyPair.generate().public.signing))
    revived = Inception.model_validate(inception.model_dump(mode="json"))
    revived.verify()
    assert revived == inception


class TestRotationRegistry:
    def test_resolves_unknown_identity_to_itself(self):
        registry = RotationRegistry()
        assert registry.resolve("amp:key:whatever") == "amp:key:whatever"

    def test_learns_current_address(self):
        identity = RotatingIdentity.create().rotate()
        registry = RotationRegistry()
        registry.learn(identity.chain)

        assert registry.resolve(identity.identity) == identity.address

    def test_does_not_move_backwards(self):
        first = RotatingIdentity.create().rotate()
        second = first.rotate()

        registry = RotationRegistry()
        registry.learn(second.chain)
        registry.learn(first.chain)  # stale view arrives late

        assert registry.resolve(first.identity) == second.address

    def test_same_next_key_but_different_follow_on_commitment_is_duplicity(self):
        """Two rotations that hand over to the same key but pre-commit to
        different successors are still proof the signing key leaked — keying
        conflict detection on next_address alone silently accepted this."""
        identity = RotatingIdentity.create()
        legit = identity.rotate()
        rotation_a = legit.chain.rotations[0]

        forged = KeyRotation.create(
            current_keys=identity.keys,  # attacker holds the in-force key
            identity=identity.identity,
            sequence=1,
            next_address=rotation_a.next_address,  # same handover target
            next_commitment=key_commitment(KeyPair.generate().public.signing),
        )
        chain_b = RotationChain(
            inception=identity.chain.inception, rotations=(forged,)
        )

        registry = RotationRegistry()
        registry.learn(legit.chain)
        with pytest.raises(RotationError, match="compromised"):
            registry.learn(chain_b)
        assert registry.is_duplicitous(identity.identity)

    def test_relearning_the_same_chain_is_not_duplicity(self):
        """Idempotence: seeing an identical history twice is normal."""
        identity = RotatingIdentity.create().rotate().rotate()
        registry = RotationRegistry()
        registry.learn(identity.chain)
        registry.learn(identity.chain)
        assert not registry.is_duplicitous(identity.identity)
        assert registry.resolve(identity.identity) == identity.address

    def test_conflict_does_not_partially_apply_the_chain(self):
        """A rejected chain must leave no trace — a half-applied conflicting
        history is worse than none."""
        identity = RotatingIdentity.create()
        legit = identity.rotate()
        registry = RotationRegistry()
        registry.learn(legit.chain)
        before = registry.state(identity.identity)

        forged = KeyRotation.create(
            current_keys=identity.keys,
            identity=identity.identity,
            sequence=1,
            next_address=legit.chain.rotations[0].next_address,
            next_commitment=key_commitment(KeyPair.generate().public.signing),
        )
        with pytest.raises(RotationError):
            registry.learn(RotationChain(inception=identity.chain.inception,
                                         rotations=(forged,)))

        assert registry.state(identity.identity) == before

    def test_divergent_next_address_at_same_sequence_is_duplicity(self):
        identity = RotatingIdentity.create()
        legit = identity.rotate()

        # Forge a chain whose inception commits to a DIFFERENT next key, so a
        # second valid-looking rotation exists at sequence 1 for this identity.
        attacker_next = KeyPair.generate()
        from fg_agent_id.address import address_from_signing_key

        forged_inception = Inception.create(
            identity.keys, key_commitment(attacker_next.public.signing)
        )
        forged_rotation = KeyRotation.create(
            current_keys=identity.keys,
            identity=forged_inception.address,
            sequence=1,
            next_address=address_from_signing_key(attacker_next.public.signing),
            next_commitment=key_commitment(KeyPair.generate().public.signing),
        )
        forged_chain = RotationChain(
            inception=forged_inception, rotations=(forged_rotation,)
        )

        registry = RotationRegistry()
        registry.learn(legit.chain)
        with pytest.raises(RotationError, match="compromised"):
            registry.learn(forged_chain)
        assert registry.is_duplicitous(identity.identity)
        assert registry.duplicity_evidence(identity.identity)

    def test_snapshot_restore_round_trip(self):
        identity = RotatingIdentity.create().rotate().rotate()
        registry = RotationRegistry()
        registry.learn(identity.chain)

        revived = RotationRegistry()
        revived.restore(registry.snapshot())

        assert revived.resolve(identity.identity) == identity.address
        assert revived.state(identity.identity).sequence == 2


def test_conflicting_inception_is_flagged_as_duplicity():
    """Two signed genesis records for one identity, committing to different
    next keys, prove the birth key leaked — the same signal a conflicting
    rotation gives, and it must be caught at sequence 0 too."""
    from fg_agent_id import RotationRegistry, address_from_signing_key

    seed = KeyPair.generate()
    addr = address_from_signing_key(seed.public.signing)
    inc1 = Inception.create(seed, key_commitment(KeyPair.generate().public.signing))
    inc2 = Inception.create(seed, key_commitment(KeyPair.generate().public.signing))

    reg = RotationRegistry()
    reg.learn(RotationChain(inception=inc1, rotations=()))
    with pytest.raises(RotationError, match="compromised"):
        reg.learn(RotationChain(inception=inc2, rotations=()))
    assert reg.is_duplicitous(addr)
    assert isinstance(reg.duplicity_evidence(addr)[0], Inception)


def test_relearning_the_same_inception_is_not_a_conflict():
    from fg_agent_id import RotationRegistry, address_from_signing_key

    seed = KeyPair.generate()
    addr = address_from_signing_key(seed.public.signing)
    inc = Inception.create(seed, key_commitment(KeyPair.generate().public.signing))
    reg = RotationRegistry()
    reg.learn(RotationChain(inception=inc, rotations=()))
    reg.learn(RotationChain(inception=inc, rotations=()))
    assert not reg.is_duplicitous(addr)


def test_resolve_fails_closed_on_a_compromised_identity():
    """Once duplicity is proven there is no address to trust, so resolve must
    refuse rather than hand back the last-good key."""
    from fg_agent_id import RotationRegistry, address_from_signing_key

    seed = KeyPair.generate()
    addr = address_from_signing_key(seed.public.signing)
    inc1 = Inception.create(seed, key_commitment(KeyPair.generate().public.signing))
    inc2 = Inception.create(seed, key_commitment(KeyPair.generate().public.signing))
    reg = RotationRegistry()
    reg.learn(RotationChain(inception=inc1, rotations=()))
    try:
        reg.learn(RotationChain(inception=inc2, rotations=()))
    except RotationError:
        pass

    assert reg.is_duplicitous(addr)
    with pytest.raises(RotationError, match="compromised"):
        reg.resolve(addr)
    # state() still exposes the raw record for a caller that wants it.
    assert reg.state(addr) is not None


def test_resolve_of_a_healthy_identity_still_works():
    from fg_agent_id import RotationRegistry, address_from_signing_key

    seed = KeyPair.generate()
    addr = address_from_signing_key(seed.public.signing)
    inc = Inception.create(seed, key_commitment(KeyPair.generate().public.signing))
    reg = RotationRegistry()
    reg.learn(RotationChain(inception=inc, rotations=()))
    assert reg.resolve(addr) == addr
