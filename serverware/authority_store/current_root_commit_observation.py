"""Observe one protected marker and complete roots on the caller transaction.

The exact pending-decision digest is only a lookup locator. This module neither
authenticates a supplied decision nor opens/commits a transaction. The caller
must admit its actual PostgreSQL 16 SERIALIZABLE connection, role/TLS/ACL and
original deadlines, and compare the returned marker/vector to genuine original
execution admission. No missing-row proof, retry or execution authority follows
from absence, errors, a marker dictionary or a matching root digest.

The fixed private mode in current_root_observation uses one cursor, one physical
acquisition and the original work for tx/marker/tx/primary/tx/heads/tx. All four
actual virtual-XID/settings samples must agree; the marker's after-vector digest
is independently recomputed from the complete canonical observations before the
last sample. Both cursor and caller connection lifecycle checks remain real.
These are unsigned observations, not proof of outer commit or rollback safety.
"""
from __future__ import annotations

import re

from serverware import authority_contract as authority
from serverware import authority_current_root_vector as vector


TABLE = authority.CURRENT_ROOT_COMMIT_MARKER_TABLE
FIELDS = authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS
PROFILE = "serverware.policyAuthorityCurrentRootCommitMarkerRead/v1"
_TAG = "current-root-commit-marker"
_DIGEST_FIELDS = frozenset(name for name in FIELDS if name.endswith("_digest")) | {"operation_id"}
_COUNTERS = frozenset({"pending_sequence", "predecessor_sequence", "fence"})
_OPERATIONS = authority.CURRENT_ROOT_COMMIT_MARKER_CONTRACT["operations"]
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SCALAR_BYTES = {
    **{name: 71 for name in _DIGEST_FIELDS},
    **{name: 19 for name in _COUNTERS},
    "source_revision": len(authority.SOURCE_REVISION), "database_id": 128,
    "operation": max(len(operation) for operation in _OPERATIONS),
}
_SELECT = ", ".join(
    "marker." + name if name in _COUNTERS else
    f"CASE WHEN pg_catalog.octet_length(marker.{name}) <= {_SCALAR_BYTES[name]} "
    f"THEN marker.{name} ELSE NULL END AS {name}"
    for name in FIELDS)
SQL = (f"SELECT {_SELECT} FROM serverware_metadata.{TABLE} AS marker "
    "WHERE marker.pending_decision_digest = %s LIMIT %s")
# The genuine acquisition uses two parameter frames: canonical digest + 2.
# Returned bytes are 19 ordered scalar frames (tag + exact18), not wire RSS.
PARAMETER_BYTES = 2 * 8 + 71 + 1
TRANSPORT_BYTES = (len(FIELDS) + 1) * 8 + len(_TAG) + sum(_SCALAR_BYTES.values())


class CurrentRootCommitObservationError(ValueError):
    pass


def _scope_on_work(pending_decision_digest, work):
    vector.capture._SharedLedger(work)
    vector.counted._digest(pending_decision_digest, "pending decision lookup")
    work.prepare_utf8(pending_decision_digest)
    return pending_decision_digest


def _owned_marker(raw, pending_decision_digest, acquisition, work):
    if (type(raw) is not dict or len(raw) != len(FIELDS)
            or any(type(name) is not str or len(name) > 64 for name in raw)
            or set(raw) != set(FIELDS)):
        raise CurrentRootCommitObservationError("current-root marker is not an exact18 record")
    for name in FIELDS:
        value = raw[name]
        if name in _COUNTERS:
            if type(value) is not int or not 0 <= value <= vector.counted.I64_MAX:
                raise CurrentRootCommitObservationError("current-root marker counter is not exact int64")
        elif (type(value) is not str or not 1 <= len(value) <= _SCALAR_BYTES[name]
                or not value.isascii() or "\x00" in value):
            raise CurrentRootCommitObservationError("current-root marker scalar is not bounded ASCII")
        elif name in _DIGEST_FIELDS:
            vector.counted._digest(value, "current-root marker " + name)
    if (raw["source_revision"] != authority.SOURCE_REVISION
            or raw["operation"] not in _OPERATIONS
            or _TOKEN.fullmatch(raw["database_id"]) is None
            or raw["pending_sequence"] != raw["predecessor_sequence"] + 1
            or raw["fence"] < 1):
        raise CurrentRootCommitObservationError("current-root marker source or sequence binding differs")
    acquisition.charge(_TAG, raw, FIELDS)
    work.prepare_comparison(raw["pending_decision_digest"], pending_decision_digest)
    if raw["pending_decision_digest"] != pending_decision_digest:
        raise CurrentRootCommitObservationError("current-root marker lookup identity differs")
    work.prepare_copy(raw)
    return raw.copy()


def _bind_after_on_work(marker, encoded, work):
    actual = vector._digest_on_work(encoded, work=work)
    work.prepare_comparison(actual, marker["after_vector_digest"])
    if actual != marker["after_vector_digest"]:
        raise CurrentRootCommitObservationError("observed complete roots differ from the marker after-vector")


def _observe_on_work(connection, *, pending_decision_digest, work):
    """Return detached exact marker + full vector after normal cursor closure."""
    from serverware.authority_store import current_root_observation

    return current_root_observation._observe_with_marker_on_work(connection,
        pending_decision_digest=pending_decision_digest, work=work)
