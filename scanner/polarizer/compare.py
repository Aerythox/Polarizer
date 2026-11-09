"""Measures how alike two JSON responses are."""

from __future__ import annotations

from typing import Any

# Two responses at or above this score count as the same object. Set below 1 so
# a field that legitimately differs between viewers (a status, a timestamp) does
# not hide an object that is otherwise clearly the same record.
SAME_OBJECT_THRESHOLD = 0.7


def flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    """Turns nested JSON into {"a.b.0": leaf} pairs."""
    if isinstance(value, dict):
        items = value.items()
    elif isinstance(value, list):
        items = enumerate(value)
    else:
        return {prefix: value}

    flat: dict[str, Any] = {}
    for key, child in items:
        flat.update(flatten(child, f"{prefix}.{key}" if prefix else str(key)))
    return flat


def similarity(a: Any, b: Any) -> float:
    """Share of keys present in both responses with equal values, from 0 to 1."""
    if a is None or b is None:
        return 0.0
    if a == b:
        return 1.0

    flat_a, flat_b = flatten(a), flatten(b)
    keys = flat_a.keys() | flat_b.keys()
    if not keys:
        return 0.0
    same = sum(1 for key in keys if key in flat_a and key in flat_b and flat_a[key] == flat_b[key])
    return same / len(keys)


def looks_like_same_object(owner_view: Any, other_view: Any) -> bool:
    return similarity(owner_view, other_view) >= SAME_OBJECT_THRESHOLD
