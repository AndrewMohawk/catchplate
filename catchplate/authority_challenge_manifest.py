"""Compact commitments to raw maintenance pages, never proof or authority.

The independent owner must replay every raw original through its real source
schedule and chain before comparing this manifest with an admitted parent.
This component retains 89 bounded summaries, not raw bodies or page DTOs. It
creates no work allowance, clock, database connection, or successful verdict.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
import threading

from catchplate import authority_challenge_compound as compound
from catchplate import authority_challenge_maintenance as maintenance
from catchplate import authority_challenge_retention as retention
from catchplate import authority_contract as contract
from catchplate import authority_index_projection as projection
from catchplate import authority_transition_core as core
from catchplate.authority_query_read_work import _ValidationWork


SCHEMA = "catchplate.policyAuthorityChallengeMaintenanceManifest/v1"
DOMAIN = "catchplate.policyAuthorityChallengeMaintenanceBodyChain/v1"
MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
CONTEXT_FIELDS = frozenset({"sourceRevision", "operation", "operationId", "requestDigest",
    "configurationDigest", "cutoffUs", "retentionUs", "maximumRetained", "challengeType",
    "userId", "scopeKey", "replaceScope", "primaryRoot", "indexHeads", "originalDeadlineNs"})
GROUP_FIELDS = frozenset({"phaseOrdinal", "kind", "indexId", "pageCount", "byteCount", "chainDigest"})
WRITE_IDS = tuple(sorted(compound.WRITE_IDS))
GROUPS = tuple((phase, kind, index_id) for phase in range(len(compound.PHASES))
    for kind, index_id in (([("count", ""), ("candidate", ""), ("primary", ""), ("range", "")]
        if phase == 3 else [("count", "")] if phase == 7 else
        [("count", ""), ("candidate", ""), ("primary", ""), ("range", ""), ("rank", "")]
        + [("write", identity) for identity in WRITE_IDS])))
_GROUP_POSITIONS = {group: index for index, group in enumerate(GROUPS)}


class ChallengeManifestError(ValueError):
    pass


def _require(value):
    if not value:
        raise ChallengeManifestError("challenge maintenance manifest differs from its fixed source originals")


def _integer(value, maximum, minimum=0):
    _require(type(value) is int and minimum <= value <= maximum)


def _digest(value):
    _require(type(value) is str)
    core.require_digest(value, "challenge maintenance manifest")


def _own(value, work):
    _require(type(work) is _ValidationWork)
    raw = work.wire(value)
    _require(len(raw) <= MAX_MANIFEST_BYTES)
    work.charge(input_bytes=len(raw))
    # The preceding exact lossless traversal charges and bounds the decode's
    # graph too; reserve its actual size before constructing another owner.
    work.prepare_copy(value)
    return json.loads(raw)


def _context(value, work):
    _require(type(value) is dict and len(value) == len(CONTEXT_FIELDS)
        and all(type(key) is str for key in value) and set(value) == CONTEXT_FIELDS)
    value = _own(value, work)
    _require(value["sourceRevision"] == contract.SOURCE_REVISION
        and value["operation"] in ("webauthn.challenge.create", "webauthn.challenge.maintain")
        and type(value["replaceScope"]) is bool)
    for name in ("operationId", "requestDigest", "configurationDigest"):
        _digest(value[name])
    _integer(value["cutoffUs"], 2**63 - 1)
    _integer(value["retentionUs"], 2**63 - 1, 1)
    _integer(value["maximumRetained"], 1_000_000, 1)
    _integer(value["originalDeadlineNs"], 2**63 - 1, 1)
    for name in ("challengeType", "userId", "scopeKey"):
        if name == "scopeKey" and value[name] is None:
            continue
        retention._text(value[name], "manifest " + name)
    work.charge(hashes=contract.TREE_DEPTH + 1)
    root = maintenance._root(value["primaryRoot"])
    raw_heads = value["indexHeads"]
    _require(type(raw_heads) is list and len(raw_heads) == len(WRITE_IDS))
    for index_id, head in zip(WRITE_IDS, raw_heads, strict=True):
        _require(type(head) is dict and head.get("indexId") == index_id)
        work.charge(hashes=projection.PROFILE_HASH_WORK)
        maintenance._head(head, projection.profile_for(index_id), root, work)
    return value


def _maximum(group):
    phase, kind, _index = group
    if kind == "count":
        return 3 if phase == 7 else 1
    if kind == "candidate":
        return compound.MAX_CANDIDATE_PAGES
    if kind == "primary":
        return compound.MAX_ROWS - int(phase == 3)
    if kind == "rank":
        return int(phase in (2, 6))
    if kind == "write":
        return compound.MAX_WRITE_PAGES
    return 1


def _chain(value, work):
    raw = work.wire(value)
    work.charge(hashes=1, input_bytes=len(DOMAIN) + 9 + len(raw))
    return core.framed_digest(DOMAIN, raw)


def _seed(context, schedule, group, work):
    phase, kind, index_id = group
    return _chain({"context": context, "schedule": schedule, "phaseOrdinal": phase,
        "kind": kind, "indexId": index_id}, work)


def _validate(value, work):
    _require(type(value) is dict and len(value) == 4
        and all(type(key) is str for key in value)
        and set(value) == {"schema", "context", "schedule", "groups"})
    owned = _own(value, work)
    _require(owned["schema"] == SCHEMA)
    context = _context(owned["context"], work)
    schedule = compound.schedule_binding()
    actual_schedule, expected_schedule = work.wire(owned["schedule"]), work.wire(schedule)
    work.charge(input_bytes=len(actual_schedule) + len(expected_schedule))
    _require(actual_schedule == expected_schedule)
    groups = owned["groups"]
    _require(type(groups) is list and len(groups) == len(GROUPS))
    for group, row in zip(GROUPS, groups, strict=True):
        _require(type(row) is dict and set(row) == GROUP_FIELDS
            and type(row["phaseOrdinal"]) is int and type(row["kind"]) is str
            and type(row["indexId"]) is str
            and (row["phaseOrdinal"], row["kind"], row["indexId"]) == group)
        pages, size = row["pageCount"], row["byteCount"]
        _integer(pages, _maximum(group))
        _integer(size, pages * MAX_BODY_BYTES, pages)
        _digest(row["chainDigest"])
        if pages == 0:
            expected = _seed(context, schedule, group, work)
            work.prepare_comparison(row["chainDigest"], expected)
            _require(row["chainDigest"] == expected)
    return owned


class MaintenanceManifest:
    """One monotonic source-group transcript; errors poison this owner."""

    def __init__(self, *, context, work):
        _require(type(work) is _ValidationWork and len(GROUPS) == 89)
        self._context = _context(context, work)
        self._schedule = _own(compound.schedule_binding(), work)
        self._original = work.wire({"context": self._context, "schedule": self._schedule})
        self._process = os.getpid(), threading.get_ident()
        self._rows = []
        for group in GROUPS:
            phase, kind, index_id = group
            self._rows.append({"phaseOrdinal": phase, "kind": kind, "indexId": index_id,
                "pageCount": 0, "byteCount": 0,
                "chainDigest": _seed(self._context, self._schedule, group, work)})
        self._position = 0
        self._busy = self._failed = self._closed = False

    @contextmanager
    def _using(self, work):
        try:
            _require(type(work) is _ValidationWork and not self._busy and not self._failed
                and not self._closed and (os.getpid(), threading.get_ident()) == self._process)
            original = work.wire({"context": self._context, "schedule": self._schedule})
            work.charge(input_bytes=len(original) + len(self._original))
            _require(original == self._original)
            self._busy = True
            yield
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False

    def append(self, *, phase_ordinal, kind, index_id, ordinal, body_bytes, work):
        with self._using(work):
            _require(type(phase_ordinal) is int and type(kind) is str and type(index_id) is str
                and type(ordinal) is int and type(body_bytes) is bytes
                and 1 <= len(body_bytes) <= MAX_BODY_BYTES)
            group = phase_ordinal, kind, index_id
            position = _GROUP_POSITIONS.get(group)
            _require(position is not None and position >= self._position)
            row = self._rows[position]
            _require(ordinal == row["pageCount"] and ordinal < _maximum(group))
            work.charge(hashes=1, input_bytes=len(body_bytes))
            digest = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
            chain = _chain({"previous": row["chainDigest"], "ordinal": ordinal,
                "byteCount": len(body_bytes), "digest": digest}, work)
            row["pageCount"] += 1
            row["byteCount"] += len(body_bytes)
            row["chainDigest"] = chain
            self._position = position
            result = {"byteCount": len(body_bytes), "digest": digest}
            work.prepare_copy(result)
            return result.copy()

    def finish(self, *, work):
        with self._using(work):
            result = _validate({"schema": SCHEMA, "context": self._context,
                "schedule": self._schedule, "groups": self._rows}, work)
            self._closed = True
            return result

    def close(self):
        self._closed = True


def compare_manifest(*, expected, actual, work):
    """Compare two closed bounded wires; only the caller supplies admission."""
    _require(type(work) is _ValidationWork)
    first = work.wire(_validate(expected, work))
    second = work.wire(_validate(actual, work))
    work.charge(input_bytes=len(first) + len(second))
    _require(first == second)
