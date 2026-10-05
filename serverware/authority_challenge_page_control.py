"""Closed maintenance-page controls for the existing opaque page framing.

This codec admits data shape only. The parent, peer, key, original deadline,
writer custody and proof replay still require their actual independent owners.
Persist descriptors are claims about a detached body, not verified digests;
the real binding/store consumer must compare them with the original bytes.
No clock is sampled, connection opened, store called or authority dispatched.
"""
from __future__ import annotations

from serverware import authority_challenge_page_binding as binding
from serverware import authority_recovery_history_transport as transport
from serverware import authority_revocation_wire as wire


SCHEMA = "serverware.policyAuthorityChallengeMaintenancePageControl/v1"
MAX_CONTROL_BYTES = 32 * 1024
MAX_CONTROL_NODES = 2048
MAX_CONTROL_DEPTH = 12
FIELDS = frozenset({"schema", "action", "parentPlanDigest", "maintenanceManifestDigest",
    "context", "phaseOrdinal", "pageKind", "indexId", "pageOrdinal", "descriptor"})
ACTIONS = frozenset({"persist", "read"})


class ChallengePageControlError(ValueError):
    pass


def _require(value):
    if not value:
        raise ChallengePageControlError("maintenance page control is not source exact")


def _capture(value, work):
    ledger = wire.batch._SharedLedger(work)
    return wire.batch._JSONCapture(ledger, maximum_bytes=MAX_CONTROL_BYTES).visit(value)


def _validate(value, *, expected_action, work):
    _require(type(expected_action) is str and expected_action in ACTIONS
        and type(value) is dict and len(value) == len(FIELDS)
        and all(type(name) is str for name in value) and set(value) == FIELDS
        and type(value["schema"]) is str and value["schema"] == SCHEMA
        and type(value["action"]) is str and value["action"] == expected_action)
    context = value["context"]
    _require(type(context) is dict and set(context) == binding.manifests.CONTEXT_FIELDS)
    owned, selected = binding._prepare(parent_plan_digest=value["parentPlanDigest"],
        maintenance_manifest_digest=value["maintenanceManifestDigest"], context=context,
        phase_ordinal=value["phaseOrdinal"], page_kind=value["pageKind"], index_id=value["indexId"],
        page_ordinal=value["pageOrdinal"], original_deadline_ns=context["originalDeadlineNs"], work=work)
    value["context"] = owned
    descriptor = value["descriptor"]
    if expected_action == "read":
        _require(descriptor is None)
    else:
        _require(type(descriptor) is dict and len(descriptor) == 2
            and all(type(name) is str for name in descriptor)
            and set(descriptor) == {"digest", "byteCount"})
        # Real source descriptor/coordinate rules, without a body or verdict.
        binding.store._binding({**selected, "body_digest": descriptor["digest"],
            "body_byte_count": descriptor["byteCount"]}, work)
    return value


def _encode(value, work):
    ledger = wire.batch._SharedLedger(work)
    raw = wire.plan.retained._bounded_wire(value, ledger,
        maximum_bytes=MAX_CONTROL_BYTES, maximum_nodes=MAX_CONTROL_NODES)
    transport._lengths(value["action"], len(raw),
        value["descriptor"]["byteCount"] if value["action"] == "persist" else 0)
    return raw


def encode_control(*, action, parent_plan_digest, maintenance_manifest_digest, context,
        phase_ordinal, page_kind, index_id, page_ordinal, descriptor, work) -> bytes:
    owned = _capture({"schema": SCHEMA, "action": action, "parentPlanDigest": parent_plan_digest,
        "maintenanceManifestDigest": maintenance_manifest_digest, "context": context,
        "phaseOrdinal": phase_ordinal, "pageKind": page_kind, "indexId": index_id,
        "pageOrdinal": page_ordinal, "descriptor": descriptor}, work)
    return _encode(_validate(owned, expected_action=action, work=work), work)


def decode_control(control_bytes, *, expected_action, work) -> dict:
    value = wire._decode_object(control_bytes, work=work, maximum_bytes=MAX_CONTROL_BYTES,
        maximum_nodes=MAX_CONTROL_NODES, maximum_depth=MAX_CONTROL_DEPTH)
    owned = _validate(value, expected_action=expected_action, work=work)
    actual = _encode(owned, work)
    work.charge(input_bytes=len(actual) + len(control_bytes))
    _require(actual == control_bytes)
    return owned
