"""Closed signed challenge limits; validation alone grants no authority.

The admitting Service6 owner supplies this optional policy and its original
work meter. There are no request-derived limits, defaults, environment reads,
clock grants, or activation effects here. Bounds match the existing config
contract; a detached value is not evidence that its signature was admitted.
"""
from __future__ import annotations

from catchplate.authority_query_read_work import _ValidationWork


FIELD = "webauthnChallengeMaintenance"
SCHEMA = "catchplate.policyAuthorityChallengeMaintenancePolicy/v1"
_BOUNDS = {
    "globalLiveMaximum": (100, 1_000_000),
    "userLiveMaximum": (4, 10_000),
    "userRateMaximum": (10, 100_000),
    "globalRateMaximum": (100, 1_000_000),
    "rateWindowSeconds": (10, 3600),
    "terminalRetentionSeconds": (60, 604_800),
    "maximumRetained": (100, 1_000_000),
}
_FIELDS = frozenset({"schema", *_BOUNDS})
_MAX_KEY_LENGTH = max(map(len, _FIELDS))


class ChallengePolicyError(ValueError):
    pass


def _require(value):
    if not value:
        raise ChallengePolicyError("challenge maintenance policy is not the closed signed configuration")


def _shape(value):
    """Fixed scalar shape for existing configuration admission; no copy."""
    _require(type(value) is dict and len(value) == len(_FIELDS))
    # Reject arbitrary graph shapes before the bounded copy. Exact string
    # keys and scalar values prevent custom equality or conversion callbacks.
    _require(all(type(key) is str and len(key) <= _MAX_KEY_LENGTH
        and key in _FIELDS for key in value))
    _require(type(value["schema"]) is str and len(value["schema"]) == len(SCHEMA)
        and value["schema"] == SCHEMA)
    for name, (minimum, maximum) in _BOUNDS.items():
        selected = value[name]
        _require(type(selected) is int and minimum <= selected <= maximum)


def validate_policy(value, *, work):
    """Return an exact detached policy using only the supplied shared meter."""
    _require(type(work) is _ValidationWork)
    _shape(value)
    work.prepare_copy(value)
    return value.copy()


def maintenance_context(policy, *, work):
    """Derive retention inputs from that policy, never from a request/env."""
    selected = validate_policy(policy, work=work)
    result = {"retentionUs": selected["terminalRetentionSeconds"] * 1_000_000,
        "maximumRetained": selected["maximumRetained"]}
    work.prepare_copy(result)
    return result.copy()
