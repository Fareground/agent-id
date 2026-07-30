"""Criticality marker: must-understand extension fields (SPEC §4.1)."""

from __future__ import annotations

import pytest

from fg_agent_id import (
    AgentCard,
    AgentIdentity,
    Delegation,
    DelegationChain,
    DelegationError,
    KeyRevocation,
    OwnerIdentity,
    SignatureError,
)

EXT = "x-payment-policy"


@pytest.fixture()
def agent():
    return AgentIdentity.generate("worker")


@pytest.fixture()
def owner():
    return OwnerIdentity.generate("owner")


def make_critical_card(agent) -> AgentCard:
    return AgentCard.create(
        keys=agent.keys,
        address=agent.address,
        name="worker",
        extra={EXT: "strict"},
        critical=(EXT,),
    )


class TestCardCriticality:
    def test_verifier_that_understands_the_field_accepts(self, agent):
        make_critical_card(agent).verify(understood_extensions={EXT})

    def test_verifier_that_does_not_understand_rejects(self, agent):
        with pytest.raises(SignatureError, match="critical"):
            make_critical_card(agent).verify()

    def test_absent_critical_list_means_nothing_required(self, agent):
        card = AgentCard.create(
            keys=agent.keys, address=agent.address, name="worker",
            extra={EXT: "advisory"},
        )
        card.verify()  # unknown extension, not critical -> still fine

    def test_critical_is_inside_the_signed_payload(self, agent):
        """Stripping the marker must break the signature — otherwise an
        attacker could downgrade a must-understand card to an ignorable one."""
        card = make_critical_card(agent)
        stripped = card.model_dump(mode="json")
        del stripped["critical"]
        with pytest.raises(SignatureError):
            AgentCard.model_validate(stripped).verify(understood_extensions={EXT})

    def test_critical_must_name_a_present_extension(self, agent):
        with pytest.raises(ValueError, match="not present"):
            AgentCard.create(
                keys=agent.keys, address=agent.address, name="worker",
                critical=("x-ghost",),
            )

    def test_round_trips_through_wire_form(self, agent):
        card = make_critical_card(agent)
        revived = AgentCard.model_validate(card.model_dump(mode="json"))
        assert revived.critical == (EXT,)
        revived.verify(understood_extensions={EXT})

    def test_cards_without_critical_serialize_without_the_field(self, agent):
        """Backward compatibility: pre-marker cards stay byte-identical."""
        card = agent.card()
        assert "critical" not in card.model_dump(mode="json")


def make_critical_delegation(owner, agent) -> Delegation:
    return Delegation.grant(
        owner.keys, owner.address, agent.address, {"read"},
        ttl_seconds=3600,
        extra={EXT: "strict"},
        critical=(EXT,),
    )


class TestDelegationCriticality:
    def test_verifier_that_understands_accepts(self, owner, agent):
        make_critical_delegation(owner, agent).verify(understood_extensions={EXT})

    def test_verifier_that_does_not_understand_rejects(self, owner, agent):
        with pytest.raises(DelegationError, match="critical"):
            make_critical_delegation(owner, agent).verify()

    def test_chain_verification_applies_criticality_per_link(self, owner, agent):
        chain = DelegationChain(links=(make_critical_delegation(owner, agent),))
        with pytest.raises(DelegationError, match="critical"):
            chain.verify(agent.address)
        assert chain.verify(agent.address, understood_extensions={EXT}) == {"read"}

    def test_extra_is_inside_the_signed_payload(self, owner, agent):
        delegation = make_critical_delegation(owner, agent)
        tampered = delegation.model_copy(update={"extra": {EXT: "lenient"}})
        with pytest.raises(DelegationError):
            tampered.verify(understood_extensions={EXT})

    def test_stripping_the_marker_breaks_the_signature(self, owner, agent):
        delegation = make_critical_delegation(owner, agent)
        stripped = delegation.model_dump(mode="json")
        del stripped["critical"]
        with pytest.raises(DelegationError):
            Delegation.model_validate(stripped).verify(understood_extensions={EXT})

    def test_round_trips_through_wire_form(self, owner, agent):
        delegation = make_critical_delegation(owner, agent)
        revived = Delegation.model_validate(delegation.model_dump(mode="json"))
        assert revived == delegation
        assert revived.extra == {EXT: "strict"}
        revived.verify(understood_extensions={EXT})

    def test_plain_delegations_serialize_without_the_field(self, owner, agent):
        delegation = Delegation.grant(
            owner.keys, owner.address, agent.address, {"read"}, ttl_seconds=3600
        )
        wire = delegation.model_dump(mode="json")
        assert "critical" not in wire

    def test_extra_cannot_shadow_known_fields(self, owner, agent):
        with pytest.raises(ValueError, match="shadow"):
            Delegation.grant(
                owner.keys, owner.address, agent.address, {"read"},
                ttl_seconds=3600, extra={"issuer": "amp:key:evil"},
            )

    def test_owner_recall_is_not_blocked_by_criticality(self, owner, agent):
        """A revocation proof chain is evidence, not authority: a registry
        that can't evaluate an extension must still honor the recall."""
        delegation = make_critical_delegation(owner, agent)
        chain = DelegationChain(links=(delegation,))
        recall = KeyRevocation.create(owner.keys, owner.address, agent.address, chain)
        recall.verify()  # verifier passed no understood extensions
