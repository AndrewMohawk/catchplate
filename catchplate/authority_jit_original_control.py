"""Exact JIT original-page control bytes; shape is not authorization.

The independent signed role request owns this control and its original clock.
Raw read responses still require the actual parent manifest and whole replay.
No signer, transport, storage, clock or allowance is created by this codec.
"""
from __future__ import annotations

from catchplate import authority_revocation_wire as wire
from catchplate.authority_store import jit_original_pages as store


SCHEMA = "catchplate.policyAuthorityJitOriginalPageControl/v1"
MAX_CONTROL_BYTES = 4096
MAX_CONTROL_NODES = 128
MAX_CONTROL_DEPTH = 4
FIELDS = frozenset({"schema", "action", "context", "originalDeadlineNs", "descriptor"})
ACTIONS = frozenset({"persist", "read"})


class JitOriginalControlError(ValueError):
    pass


def _require(value):
    if not value:
        raise JitOriginalControlError("JIT original control differs from the source shape")


def _binding(value, work):
    descriptor = value["descriptor"]
    _require(type(descriptor) is dict and len(descriptor) == 2
        and all(type(name) is str for name in descriptor)
        and set(descriptor) == {"digest", "byteCount"})
    work.charge(input_bytes=2048, json_nodes=32)
    return store._binding({**value["context"], "body_digest": descriptor["digest"],
        "body_byte_count": descriptor["byteCount"]}, work)


def _validate(value, *, expected_action, work):
    wire.batch._SharedLedger(work)
    _require(type(expected_action) is str and expected_action in ACTIONS
        and type(value) is dict and len(value) == len(FIELDS)
        and all(type(name) is str for name in value) and set(value) == FIELDS
        and type(value["schema"]) is str and value["schema"] == SCHEMA
        and type(value["action"]) is str and value["action"] == expected_action
        and type(value["originalDeadlineNs"]) is int and 0 < value["originalDeadlineNs"] < 2**63)
    value["context"] = store._context(value["context"], work)
    if expected_action == "persist":
        _binding(value, work)
    else:
        _require(value["descriptor"] is None)
    return value


def _encode(value, work):
    return wire.plan.retained._bounded_wire(value, wire.batch._SharedLedger(work),
        maximum_bytes=MAX_CONTROL_BYTES, maximum_nodes=MAX_CONTROL_NODES)


def encode_control(*, action, context, original_deadline_ns, descriptor, work):
    ledger = wire.batch._SharedLedger(work)
    work.charge(input_bytes=4096, json_nodes=128)
    value = wire.batch._JSONCapture(ledger, maximum_bytes=MAX_CONTROL_BYTES).visit({
        "schema": SCHEMA, "action": action, "context": context,
        "originalDeadlineNs": original_deadline_ns, "descriptor": descriptor})
    return _encode(_validate(value, expected_action=action, work=work), work)


def decode_control(control_bytes, *, expected_action, work):
    value = wire._decode_object(control_bytes, work=work, maximum_bytes=MAX_CONTROL_BYTES,
        maximum_nodes=MAX_CONTROL_NODES, maximum_depth=MAX_CONTROL_DEPTH)
    result = _validate(value, expected_action=expected_action, work=work)
    canonical = _encode(result, work)
    work.charge(input_bytes=len(canonical) + len(control_bytes))
    _require(canonical == control_bytes)
    return result


def _body(value, body_bytes, work):
    """Compare a persist descriptor with actual bytes, never a proof result."""
    _require(value["action"] == "persist")
    return store._body(body_bytes, _binding(value, work), work)
