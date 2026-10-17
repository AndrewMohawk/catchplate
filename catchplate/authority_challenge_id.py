"""Fresh-source challenge IDs with the producers' exact text ordering.

This is an explicit source-contract restriction, not a migration codec. Older
custom IDs must not be rewritten, adopted, or represented by a hashed tie key.
Fresh installation refuses populated challenge/reference tables separately.
UUID and policy-authority SHA IDs retain their real primary BusinessKey.
"""
from __future__ import annotations

import re


UUID_PATTERN = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
SHA_PATTERN = r"sha256:[0-9a-f]{64}"
_UUID = re.compile(UUID_PATTERN + r"\Z")
_SHA = re.compile(SHA_PATTERN + r"\Z")


def require_generated(value: object) -> str:
    """Admit only canonical forms emitted by the source-owned producers."""
    if type(value) is not str or not (
        (len(value) == 36 and _UUID.fullmatch(value) is not None)
        or (len(value) == 71 and _SHA.fullmatch(value) is not None)
    ):
        raise ValueError("fresh challenge source requires canonical UUID36 or sha256 ID; legacy adoption is forbidden")
    return value


def order_suffix(value: object) -> str:
    """Forty-byte order tail: class1, payload32, zero7 (no hash)."""
    value = require_generated(value)
    if len(value) == 36:
        # Fixed lowercase UUID punctuation does not affect text tie order.
        payload = "00" + value.replace("-", "") + "0" * 32
    else:
        # Every UUID starts with a hex digit, before the literal 's'.
        payload = "01" + value[7:]
    return payload + "0" * 14
