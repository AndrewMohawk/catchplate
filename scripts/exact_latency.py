"""Exact decimal millisecond input with an integer nanosecond result.

Shared by the completion verifier and its readiness runner. This module has no
application imports and never converts through binary floating point.
"""
from __future__ import annotations

import re


MAX_NANOSECONDS = (1 << 63) - 1
NANOSECONDS_PER_MILLISECOND = 1_000_000
# The largest accepted text is 9223372036854.775807 (20 ASCII characters).
MAX_MILLISECOND_TOKEN_CHARS = 20
_MILLISECONDS_RE = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?\Z", re.ASCII)


def milliseconds_to_nanoseconds(
    value: int | str,
    *,
    label: str,
    positive: bool = False,
) -> int:
    if type(value) is bool:
        raise ValueError(f"{label} must be an exact decimal millisecond value")
    if type(value) is int:
        if value < 0:
            raise ValueError(f"{label} must not be negative")
        if value > MAX_NANOSECONDS // NANOSECONDS_PER_MILLISECOND:
            raise ValueError(f"{label} exceeds the canonical signed 64-bit nanosecond maximum")
        nanoseconds = value * NANOSECONDS_PER_MILLISECOND
    else:
        if isinstance(value, str) and len(value) > MAX_MILLISECOND_TOKEN_CHARS:
            raise ValueError(f"{label} decimal millisecond token is too long")
        if not isinstance(value, str) or _MILLISECONDS_RE.fullmatch(value) is None:
            raise ValueError(f"{label} must be canonical decimal milliseconds with at most six fractional digits")
        whole, separator, fractional = value.partition(".")
        nanoseconds = int(whole) * NANOSECONDS_PER_MILLISECOND
        if separator:
            nanoseconds += int(fractional.ljust(6, "0"))
    if nanoseconds > MAX_NANOSECONDS:
        raise ValueError(f"{label} exceeds the canonical signed 64-bit nanosecond maximum")
    if positive and nanoseconds == 0:
        raise ValueError(f"{label} must be positive")
    return nanoseconds
