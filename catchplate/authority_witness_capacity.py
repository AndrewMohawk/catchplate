"""Pure accounting for the existing witness's journal completion capacity.

Each open reservation holds one future record and the maximum record byte size.
These are logical limits, not filesystem allocation, physical disk reservation,
durability, authorization, or independent anti-rollback authority. The caller
must derive usage and transition kinds from its fully validated journal and
protocol state; these immutable values are data, never verification tokens.

Replay checks actual historical usage without demanding completion capacity at
every old prefix. A recovered current state must separately pass
``require_completion_capacity`` before the witness becomes ready.
"""
from __future__ import annotations

from dataclasses import dataclass


MAX_INTEGER = 2**63 - 1
_KINDS = frozenset({"generation-activation", "reservation", "terminal"})


class WitnessCapacityError(ValueError):
    pass


def _integer(value: int, *, minimum: int, field: str) -> None:
    if type(value) is not int or not minimum <= value <= MAX_INTEGER:
        raise WitnessCapacityError("witness capacity " + field + " is invalid")


@dataclass(frozen=True, slots=True)
class WitnessCapacityLimits:
    byte_limit: int
    record_limit: int
    max_record_bytes: int

    def __post_init__(self) -> None:
        for field in ("byte_limit", "record_limit", "max_record_bytes"):
            _integer(getattr(self, field), minimum=1, field=field)


@dataclass(frozen=True, slots=True)
class WitnessCapacityUsage:
    records: int
    bytes: int
    open_reservations: int

    def __post_init__(self) -> None:
        for field in ("records", "bytes", "open_reservations"):
            _integer(getattr(self, field), minimum=0, field=field)


def _snapshots(
    usage: WitnessCapacityUsage, limits: WitnessCapacityLimits,
) -> tuple[WitnessCapacityUsage, WitnessCapacityLimits]:
    if type(usage) is not WitnessCapacityUsage or type(limits) is not WitnessCapacityLimits:
        raise WitnessCapacityError("witness capacity context has the wrong type")
    try:
        accepted_usage = WitnessCapacityUsage(usage.records, usage.bytes, usage.open_reservations)
        accepted_limits = WitnessCapacityLimits(limits.byte_limit, limits.record_limit, limits.max_record_bytes)
    except AttributeError as exc:
        raise WitnessCapacityError("witness capacity context is incomplete") from exc
    return accepted_usage, accepted_limits


def _require_actual(usage: WitnessCapacityUsage, limits: WitnessCapacityLimits) -> None:
    if usage.records > limits.record_limit or usage.bytes > limits.byte_limit:
        raise WitnessCapacityError("witness actual journal usage exceeds its limits")


def _require_completion(usage: WitnessCapacityUsage, limits: WitnessCapacityLimits) -> None:
    # Actual usage has already been checked, so both subtractions are bounded
    # and nonnegative. Division avoids overflowing an open-count * record-size
    # intermediate, while enforcing exactly the same full worst-case hold.
    if (usage.open_reservations > limits.record_limit - usage.records
            or usage.open_reservations > (limits.byte_limit - usage.bytes) // limits.max_record_bytes):
        raise WitnessCapacityError("witness completion capacity exceeds its limits")


def _append(
    usage: WitnessCapacityUsage, limits: WitnessCapacityLimits, *, kind: str, record_bytes: int,
) -> tuple[WitnessCapacityUsage, WitnessCapacityLimits]:
    accepted, bounded = _snapshots(usage, limits)
    _require_actual(accepted, bounded)
    if type(kind) is not str or kind not in _KINDS:
        raise WitnessCapacityError("witness capacity record kind is invalid")
    _integer(record_bytes, minimum=1, field="record_bytes")
    if record_bytes > bounded.max_record_bytes:
        raise WitnessCapacityError("witness record exceeds its maximum byte size")
    opened = accepted.open_reservations
    if kind == "generation-activation":
        if opened != 0:
            raise WitnessCapacityError("witness generation activation has open reservations")
    elif kind == "terminal":
        if opened == 0:
            raise WitnessCapacityError("witness terminal record has no open reservation")
        opened -= 1
    else:
        if opened == MAX_INTEGER:
            raise WitnessCapacityError("witness reservation count overflows signed64")
        opened += 1
    if accepted.records == MAX_INTEGER or record_bytes > MAX_INTEGER - accepted.bytes:
        raise WitnessCapacityError("witness journal usage overflows signed64")
    projected = WitnessCapacityUsage(accepted.records + 1, accepted.bytes + record_bytes, opened)
    _require_actual(projected, bounded)
    return projected, bounded


def plan_append(
    usage: WitnessCapacityUsage, limits: WitnessCapacityLimits, *, kind: str, record_bytes: int,
) -> WitnessCapacityUsage:
    """Plan a new record with worst-case capacity held for every remaining open reservation.

    This has no side effects. The caller must publish and accept the exact
    record under its existing lock before adopting the new usage.
    """
    projected, bounded = _append(usage, limits, kind=kind, record_bytes=record_bytes)
    _require_completion(projected, bounded)
    return projected


def replay_append(
    usage: WitnessCapacityUsage, limits: WitnessCapacityLimits, *, kind: str, record_bytes: int,
) -> WitnessCapacityUsage:
    """Account one validated historical record, enforcing actual limits only."""
    projected, _ = _append(usage, limits, kind=kind, record_bytes=record_bytes)
    return projected


def require_completion_capacity(usage: WitnessCapacityUsage, limits: WitnessCapacityLimits) -> None:
    """Reject recovered current usage lacking room to complete every open reservation."""
    accepted, bounded = _snapshots(usage, limits)
    _require_actual(accepted, bounded)
    _require_completion(accepted, bounded)
