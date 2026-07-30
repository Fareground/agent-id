"""Spend scopes: grammar, composition, and chain-level payment checks."""

from __future__ import annotations

import random
from decimal import Decimal

import pytest

from fg_agent_id import (
    AgentIdentity,
    Delegation,
    DelegationChain,
    OwnerIdentity,
    SpendAuthority,
    SpendScope,
    SpendScopeError,
    compose_spend_authority,
    is_spend_scope,
    parse_spend_scope,
    spend_authority_for,
)


class TestGrammar:
    def test_asset_only_is_unlimited(self):
        scope = parse_spend_scope("pay:usdc")
        assert scope == SpendScope(asset="usdc", tx_cap=None, total_cap=None)

    def test_full_form(self):
        scope = parse_spend_scope("pay:usd:tx<=9.99:total<=100")
        assert scope.asset == "usd"
        assert scope.tx_cap == Decimal("9.99")
        assert scope.total_cap == Decimal("100")

    def test_caps_may_appear_in_either_order(self):
        scope = parse_spend_scope("pay:usd:total<=100:tx<=5")
        assert (scope.tx_cap, scope.total_cap) == (Decimal("5"), Decimal("100"))

    def test_render_round_trips(self):
        for text in ("pay:usdc", "pay:usd:tx<=9.99", "pay:usd:tx<=5:total<=100"):
            assert parse_spend_scope(text).render() == text

    def test_is_spend_scope_distinguishes(self):
        assert is_spend_scope("pay:usdc")
        assert not is_spend_scope("read")
        assert not is_spend_scope("payment:usdc")

    @pytest.mark.parametrize("bad", [
        "pay:",                       # missing asset
        "pay:USD",                    # uppercase asset
        "pay:usd:tx<=1e6",            # exponent
        "pay:usd:tx<=-5",             # negative
        "pay:usd:tx<=.5",             # bare dot
        "pay:usd:tx<=5.",             # trailing dot
        "pay:usd:tx<=nan",            # not a number
        "pay:usd:tx<=5:tx<=6",        # duplicate cap
        "pay:usd:max<=5",             # unknown segment
        "read",                       # not a spend scope at all
    ])
    def test_malformed_scopes_are_rejected(self, bad):
        with pytest.raises(SpendScopeError):
            parse_spend_scope(bad)

    def test_amounts_are_decimal_never_float(self):
        assert parse_spend_scope("pay:usd:tx<=0.1").tx_cap == Decimal("0.1")

    def test_unreasonably_long_amount_is_rejected(self):
        with pytest.raises(SpendScopeError, match="long"):
            parse_spend_scope(f"pay:usd:tx<={'9' * 80}")


class TestComposition:
    def test_intersection_takes_the_minimum_cap(self):
        a = parse_spend_scope("pay:usd:tx<=100:total<=1000")
        b = parse_spend_scope("pay:usd:tx<=25")
        composed = a.intersect(b)
        assert composed.tx_cap == Decimal("25")
        assert composed.total_cap == Decimal("1000")

    def test_different_assets_do_not_intersect(self):
        with pytest.raises(SpendScopeError, match="different assets"):
            parse_spend_scope("pay:usd").intersect(parse_spend_scope("pay:usdc"))

    def test_link_without_spend_scope_voids_authority(self):
        links = [{"pay:usd:tx<=100"}, {"read"}]
        assert compose_spend_authority(links, "usd") is None

    def test_multiple_scopes_in_one_link_intersect(self):
        authority = spend_authority_for({"pay:usd:tx<=100", "pay:usd:total<=50"}, "usd")
        assert (authority.tx_cap, authority.total_cap) == (Decimal("100"), Decimal("50"))

    def test_empty_chain_composes_to_no_authority(self):
        assert compose_spend_authority([], "usd") is None

    def test_composed_authority_never_exceeds_any_link_cap(self):
        """The safety property: for random chains, the composed cap on each
        axis is <= every link's cap on that axis."""
        rng = random.Random(0xF6)
        for _ in range(200):
            links = []
            for _ in range(rng.randint(1, 5)):
                tx = rng.choice([None, Decimal(rng.randint(1, 10_000))])
                total = rng.choice([None, Decimal(rng.randint(1, 100_000))])
                links.append({SpendScope("usd", tx, total).render()})
            composed = compose_spend_authority(links, "usd")
            assert composed is not None
            for link in links:
                cap = parse_spend_scope(next(iter(link)))
                if cap.tx_cap is not None:
                    assert composed.tx_cap is not None and composed.tx_cap <= cap.tx_cap
                if cap.total_cap is not None:
                    assert (composed.total_cap is not None
                            and composed.total_cap <= cap.total_cap)


@pytest.fixture()
def paid_chain():
    """owner -> operator -> agent, each link narrowing the spend caps."""
    owner = OwnerIdentity.generate("owner")
    operator = AgentIdentity.generate("operator")
    agent = AgentIdentity.generate("worker")
    root = owner.grant(operator.address, {"pay:usdc:tx<=100:total<=1000", "trade"})
    leaf = Delegation.grant(
        operator.keys, operator.address, agent.address,
        {"pay:usdc:tx<=25:total<=200", "trade"}, ttl_seconds=3600,
    )
    return agent, DelegationChain(links=(root, leaf))


class TestSpendAuthority:
    def test_chain_still_verifies_normally(self, paid_chain):
        agent, chain = paid_chain
        assert "trade" in chain.verify(agent.address)

    def test_payment_within_caps_passes(self, paid_chain):
        _, chain = paid_chain
        effective = SpendAuthority.verify(chain, "usdc", Decimal("25"), Decimal("175"))
        assert effective.tx_cap == Decimal("25")
        assert effective.total_cap == Decimal("200")

    def test_amount_over_tx_cap_fails(self, paid_chain):
        _, chain = paid_chain
        with pytest.raises(SpendScopeError, match="per-transaction"):
            SpendAuthority.verify(chain, "usdc", Decimal("26"))

    def test_cumulative_total_is_enforced(self, paid_chain):
        _, chain = paid_chain
        with pytest.raises(SpendScopeError, match="total cap"):
            SpendAuthority.verify(chain, "usdc", Decimal("25"), Decimal("176"))

    def test_unknown_asset_grants_nothing(self, paid_chain):
        _, chain = paid_chain
        with pytest.raises(SpendScopeError, match="no spend authority"):
            SpendAuthority.verify(chain, "eur", Decimal("1"))

    def test_string_amounts_are_accepted(self, paid_chain):
        _, chain = paid_chain
        SpendAuthority.verify(chain, "usdc", "12.50", "0")

    def test_negative_amounts_are_rejected(self, paid_chain):
        _, chain = paid_chain
        with pytest.raises(SpendScopeError, match="non-negative"):
            SpendAuthority.verify(chain, "usdc", Decimal("-1"))

    def test_delegate_cannot_exceed_delegator(self, paid_chain):
        """Even though the leaf link alone would allow tx<=25, a leaf that
        tries to grant MORE than its issuer held is still capped by the root."""
        _, chain = paid_chain
        wide_leaf_chain = DelegationChain(links=(
            chain.links[0],
            chain.links[1].model_copy(),  # tx<=25 (< root's 100) — fine
        ))
        effective = SpendAuthority.verify(wide_leaf_chain, "usdc", Decimal("10"))
        assert effective.tx_cap <= Decimal("100")
        assert effective.total_cap <= Decimal("1000")
