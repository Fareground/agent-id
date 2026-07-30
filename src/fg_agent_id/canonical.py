"""Canonical JSON serialization for signing.

Deterministic bytes for any JSON-compatible structure: sorted keys, no
insignificant whitespace, UTF-8, no NaN/Infinity. Every signature in AMP is
computed over this form so independent implementations agree byte-for-byte.
"""

from __future__ import annotations

import json
import unicodedata
from typing import Any


def _reject_floats(data: Any) -> None:
    """Signed/salt payloads must contain no floats: float formatting differs
    across languages and would break cross-implementation signature agreement.
    Use ints (e.g. milliseconds) or strings instead. bool is fine (it's int)."""
    if isinstance(data, float):
        raise ValueError(
            "floats are not allowed in canonical (signed) payloads — "
            "use an integer (e.g. milliseconds) or a string"
        )
    if isinstance(data, dict):
        for v in data.values():
            _reject_floats(v)
    elif isinstance(data, (list, tuple)):
        for v in data:
            _reject_floats(v)


def canonical_json(data: Any) -> bytes:
    """Deterministic bytes for signing.

    Sorted keys, no insignificant whitespace, no NaN/Infinity, no floats, and
    NFC Unicode normalization so that two semantically identical inputs encoded
    differently (e.g. by a non-Python signer) still produce identical bytes —
    a precondition for cross-implementation signature agreement.
    """
    _reject_floats(data)
    text = json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return unicodedata.normalize("NFC", text).encode("utf-8")
