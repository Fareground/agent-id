"""Spend scopes: a grammar for monetary authority in delegation chains.

A spend scope caps what a delegate may pay, per transaction and in total::

    pay:<asset>[:tx<=<amount>][:total<=<amount>]

    pay:usdc                      unlimited authority over usdc
    pay:usdc:tx<=25               at most 25 usdc per transaction
    pay:usd:tx<=9.99:total<=100   per-tx and cumulative caps

Amounts are non-negative decimals rendered as strings — never floats — so the
grammar survives canonical JSON (§3) and cross-language parsing. ``<asset>``
is an opaque lowercase token (a currency code, a token symbol, a chain-scoped
identifier); this standard compares it for equality and nothing else.

Composition down a chain is intersection, like every other scope: the
effective cap on each axis is the minimum across links, and a link with no
spend scope for the asset contributes no authority at all. A delegate can
therefore never spend more than ANY of its delegators allowed.

This module is pure grammar and verification math. It does not move money,
track a ledger, or settle anything — settlement belongs to the payment
protocol (e.g. x402); the caller supplies ``spent_so_far`` from its own books.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal

from .delegation import DelegationChain
from .errors import SpendScopeError

SPEND_PREFIX = "pay"
TX_CAP_PREFIX = "tx<="
TOTAL_CAP_PREFIX = "total<="

# Opaque asset token: lowercase alphanumerics with ._- separators inside.
_ASSET_RE = re.compile(r"^[a-z0-9]+([._-][a-z0-9]+)*$")
# Non-negative decimal, optional fraction; no sign, exponent, or bare dot.
_AMOUNT_RE = re.compile(r"^[0-9]+(\.[0-9]+)?$")
# Enough for any real currency amount; bounds hostile megabyte-long numerals.
_MAX_AMOUNT_CHARS = 40


@dataclass(frozen=True)
class SpendScope:
    """Parsed spend authority for one asset. ``None`` caps mean unlimited."""

    asset: str
    tx_cap: Decimal | None = None
    total_cap: Decimal | None = None

    def render(self) -> str:
        """The scope string this authority spells as."""
        parts = [SPEND_PREFIX, self.asset]
        if self.tx_cap is not None:
            parts.append(f"{TX_CAP_PREFIX}{self.tx_cap}")
        if self.total_cap is not None:
            parts.append(f"{TOTAL_CAP_PREFIX}{self.total_cap}")
        return ":".join(parts)

    def intersect(self, other: SpendScope) -> SpendScope:
        """Compose two grants over the same asset: min of each cap."""
        if self.asset != other.asset:
            raise SpendScopeError(
                f"cannot intersect spend scopes for different assets: "
                f"{self.asset!r} vs {other.asset!r}"
            )
        return SpendScope(
            asset=self.asset,
            tx_cap=_min_cap(self.tx_cap, other.tx_cap),
            total_cap=_min_cap(self.total_cap, other.total_cap),
        )


def _min_cap(a: Decimal | None, b: Decimal | None) -> Decimal | None:
    """Minimum of two caps where ``None`` means unlimited."""
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


def parse_amount(text: str) -> Decimal:
    """Parse a currency-decimal amount, rejecting anything a float touched."""
    if not isinstance(text, str):
        raise SpendScopeError(f"amount must be a string, got {type(text).__name__}")
    if len(text) > _MAX_AMOUNT_CHARS:
        raise SpendScopeError("amount is unreasonably long")
    if not _AMOUNT_RE.match(text):
        raise SpendScopeError(
            f"amount must be a non-negative decimal like '25' or '9.99', "
            f"got {text!r}"
        )
    return Decimal(text)


def is_spend_scope(scope: str) -> bool:
    """True when a scope string is in the spend grammar (``pay:...``)."""
    return isinstance(scope, str) and scope.split(":", 1)[0] == SPEND_PREFIX


def parse_spend_scope(scope: str) -> SpendScope:
    """Parse ``pay:<asset>[:tx<=<amount>][:total<=<amount>]`` or raise."""
    if not is_spend_scope(scope):
        raise SpendScopeError(f"not a spend scope: {scope!r}")
    segments = scope.split(":")
    if len(segments) < 2 or not segments[1]:
        raise SpendScopeError(f"spend scope is missing an asset: {scope!r}")
    asset = segments[1]
    if not _ASSET_RE.match(asset):
        raise SpendScopeError(f"invalid asset token: {asset!r}")
    tx_cap: Decimal | None = None
    total_cap: Decimal | None = None
    for segment in segments[2:]:
        if segment.startswith(TX_CAP_PREFIX):
            if tx_cap is not None:
                raise SpendScopeError(f"duplicate tx cap in scope: {scope!r}")
            tx_cap = parse_amount(segment.removeprefix(TX_CAP_PREFIX))
        elif segment.startswith(TOTAL_CAP_PREFIX):
            if total_cap is not None:
                raise SpendScopeError(f"duplicate total cap in scope: {scope!r}")
            total_cap = parse_amount(segment.removeprefix(TOTAL_CAP_PREFIX))
        else:
            raise SpendScopeError(f"unknown spend scope segment: {segment!r}")
    return SpendScope(asset=asset, tx_cap=tx_cap, total_cap=total_cap)


def spend_authority_for(scopes: Iterable[str], asset: str) -> SpendScope | None:
    """One grant's authority over ``asset``, or None if it grants none.

    Several spend scopes for the same asset within a single grant intersect —
    the narrower reading is always the safe one.
    """
    authority: SpendScope | None = None
    for scope in scopes:
        if not is_spend_scope(scope):
            continue
        parsed = parse_spend_scope(scope)
        if parsed.asset != asset:
            continue
        authority = parsed if authority is None else authority.intersect(parsed)
    return authority


def compose_spend_authority(
    links_scopes: Iterable[Iterable[str]], asset: str
) -> SpendScope | None:
    """Effective authority over ``asset`` down a chain of grants.

    Each element of ``links_scopes`` is one link's scope set, root first. The
    result caps at the minimum across links; ANY link without a spend scope
    for the asset voids the authority entirely (you cannot delegate what you
    were not granted). Empty input composes to no authority.
    """
    effective: SpendScope | None = None
    saw_link = False
    for scopes in links_scopes:
        saw_link = True
        link_authority = spend_authority_for(scopes, asset)
        if link_authority is None:
            return None
        effective = (
            link_authority if effective is None else effective.intersect(link_authority)
        )
    return effective if saw_link else None


class SpendAuthority:
    """Chain-level spend verification: may this chain pay this amount now?"""

    @staticmethod
    def verify(
        chain: DelegationChain,
        asset: str,
        amount: Decimal | str,
        spent_so_far: Decimal | str = Decimal(0),
    ) -> SpendScope:
        """Check one prospective payment against a chain's composed caps.

        This is authority math only: the caller MUST have verified the chain
        itself first (:meth:`DelegationChain.verify` — signatures, topology,
        expiry, revocation), and supplies ``spent_so_far`` from its own
        ledger. Raises :class:`SpendScopeError` when the chain grants no
        authority over the asset, the amount exceeds the per-transaction cap,
        or the cumulative total would exceed the total cap. Returns the
        effective (composed) scope on success.
        """
        amount = amount if isinstance(amount, Decimal) else parse_amount(amount)
        spent_so_far = (
            spent_so_far if isinstance(spent_so_far, Decimal) else parse_amount(spent_so_far)
        )
        if amount < 0 or spent_so_far < 0:
            raise SpendScopeError("amounts must be non-negative")
        effective = compose_spend_authority(
            (link.scopes for link in chain.links), asset
        )
        if effective is None:
            raise SpendScopeError(f"chain grants no spend authority over {asset!r}")
        if effective.tx_cap is not None and amount > effective.tx_cap:
            raise SpendScopeError(
                f"amount {amount} exceeds per-transaction cap {effective.tx_cap} "
                f"for {asset!r}"
            )
        if effective.total_cap is not None and spent_so_far + amount > effective.total_cap:
            raise SpendScopeError(
                f"amount {amount} on top of {spent_so_far} already spent exceeds "
                f"total cap {effective.total_cap} for {asset!r}"
            )
        return effective
