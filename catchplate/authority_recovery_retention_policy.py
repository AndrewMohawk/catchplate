"""Explicit signed recovery retention settings, never an ambient default.

The optional recovery configuration owns this mandatory nested selection.
Bounds are those of the real recovery terminal/native engines, not challenge
maintenance. Shape validation and projection do not admit signed provenance,
open a clock, create an allowance or enable an operation.
"""
from __future__ import annotations

from catchplate.authority_query_read_work import _ValidationWork


FIELD = "retentionPolicy"
SCHEMA = "catchplate.policyAuthorityRecoveryRetentionPolicy/v1"
_BOUNDS = {"terminalRetentionSeconds": (86_400, 31_536_000),
    "maximumRetained": (100, 1_000_000)}
_FIELDS = frozenset({"schema", *_BOUNDS})
_MAX_KEY_LENGTH = max(map(len, _FIELDS))


class RecoveryRetentionPolicyError(ValueError):
    pass


def _require(value):
    if not value:
        raise RecoveryRetentionPolicyError("recovery retention selection is not exact")


def _shape(value):
    """Bounded scalar checks for the actual Service6/source admission gate."""
    _require(type(value) is dict and len(value) == len(_FIELDS)
        and all(type(key) is str and len(key) <= _MAX_KEY_LENGTH
            and key in _FIELDS for key in value))
    _require(type(value["schema"]) is str and len(value["schema"]) == len(SCHEMA)
        and value["schema"] == SCHEMA)
    for name, (minimum, maximum) in _BOUNDS.items():
        selected = value[name]
        _require(type(selected) is int and minimum <= selected <= maximum)


def project_policy(*, terminal_retention_seconds, maximum_retained):
    """Project explicitly configured scalars; there are deliberately no defaults.

    Offline configuration generation can use this before signing. Existing
    signed originals must only be compared with the projection, not rewritten.
    """
    result = {"schema": SCHEMA, "terminalRetentionSeconds": terminal_retention_seconds,
        "maximumRetained": maximum_retained}
    _shape(result)
    return result


def capture_policy(value, *, work):
    """Own the admitted scalar selection on the caller's actual original work."""
    _require(type(work) is _ValidationWork)
    _shape(value)
    work.prepare_copy(value)
    return value.copy()
