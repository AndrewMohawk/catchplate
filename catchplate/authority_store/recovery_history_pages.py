"""Immutable raw recovery-history pages, never parent-plan authority.

The caller independently verifies the parent and owns its original snapshot,
deadline and outer SERIALIZABLE planner-writer transaction. These functions
admit that genuine facade, preserve its physical handle, and retain/read exact
bounded bytes. A digest or successful store call is not a proof verdict.
Nothing here opens a connection, commits, retries or renews authority. A
returned body remains subject to the caller's outer transaction and replay.
"""
from __future__ import annotations

import hashlib
import re
import time

from catchplate import authority_contract as authority
from catchplate.authority_query_read_work import _ValidationWork
from catchplate.authority_store import webauthn_evidence_retention as lifecycle

TABLE = "catchplate_metadata.policy_authority_recovery_history_pages"
MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_ROW_PAGES = 10000
OPERATIONS = frozenset({"webauthn.recovery.create", "webauthn.recovery.candidate",
    "webauthn.recovery.finalize"})
CONTEXT_FIELDS = ("parent_plan_digest", "history_manifest_digest", "source_revision",
    "operation", "operation_id", "request_digest", "configuration_digest", "page_kind", "page_ordinal")
BINDING_FIELDS = CONTEXT_FIELDS + ("body_digest", "body_byte_count")
COLUMNS = BINDING_FIELDS + ("body_bytes", "retained_at_epoch_ns")
_DIGEST_FIELDS = ("parent_plan_digest", "history_manifest_digest", "operation_id",
    "request_digest", "configuration_digest", "body_digest")
_KEY_FIELDS = ("parent_plan_digest", "history_manifest_digest", "page_kind", "page_ordinal")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SELECT = "SELECT " + ", ".join(COLUMNS) + " FROM " + TABLE + " WHERE " + " AND ".join(
    name + "=%s" for name in _KEY_FIELDS)
_INSERT = ("INSERT INTO " + TABLE + " (" + ", ".join(COLUMNS) + ") VALUES ("
    + ", ".join(("%s",) * len(COLUMNS)) + ") ON CONFLICT ("
    + ", ".join(_KEY_FIELDS) + ") DO NOTHING")


class RecoveryHistoryPageError(ValueError):
    pass


def _require(value):
    if not value:
        raise RecoveryHistoryPageError("recovery history page custody differs")


def installation_sql():
    """Source DDL only; installation and narrowly scoped ACLs belong elsewhere."""
    return f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    parent_plan_digest TEXT NOT NULL,
    history_manifest_digest TEXT NOT NULL,
    source_revision TEXT NOT NULL CHECK (source_revision = '{authority.SOURCE_REVISION}'),
    operation TEXT NOT NULL CHECK (operation IN
        ('webauthn.recovery.create', 'webauthn.recovery.candidate', 'webauthn.recovery.finalize')),
    operation_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    configuration_digest TEXT NOT NULL,
    page_kind TEXT NOT NULL CHECK (page_kind IN ('count', 'row')),
    page_ordinal BIGINT NOT NULL,
    body_digest TEXT NOT NULL,
    body_byte_count BIGINT NOT NULL CHECK (body_byte_count BETWEEN 1 AND {MAX_BODY_BYTES}),
    body_bytes BYTEA NOT NULL CHECK (octet_length(body_bytes) = body_byte_count),
    retained_at_epoch_ns BIGINT NOT NULL CHECK (retained_at_epoch_ns > 0),
    PRIMARY KEY (parent_plan_digest, history_manifest_digest, page_kind, page_ordinal),
    CHECK ((page_kind = 'count' AND page_ordinal = 0)
        OR (page_kind = 'row' AND page_ordinal BETWEEN 0 AND {MAX_ROW_PAGES - 1}))
);
"""


def _binding(binding, work):
    _require(type(work) is _ValidationWork and type(binding) is dict
        and len(binding) == len(BINDING_FIELDS)
        and all(type(name) is str for name in binding) and set(binding) == set(BINDING_FIELDS))
    for name in _DIGEST_FIELDS:
        value = binding[name]
        _require(type(value) is str and len(value) == 71 and _DIGEST.fullmatch(value) is not None)
    _require(type(binding["source_revision"]) is str and binding["source_revision"] == authority.SOURCE_REVISION
        and type(binding["operation"]) is str and binding["operation"] in OPERATIONS
        and type(binding["page_kind"]) is str and binding["page_kind"] in {"count", "row"}
        and type(binding["page_ordinal"]) is int
        and (binding["page_ordinal"] == 0 if binding["page_kind"] == "count"
            else 0 <= binding["page_ordinal"] < MAX_ROW_PAGES)
        and type(binding["body_byte_count"]) is int and 1 <= binding["body_byte_count"] <= MAX_BODY_BYTES)
    work.prepare_copy(binding)
    return binding.copy()


def _body(body_bytes, binding, work):
    _require(type(body_bytes) is bytes and len(body_bytes) == binding["body_byte_count"]
        and 1 <= len(body_bytes) <= MAX_BODY_BYTES)
    work.charge(hashes=1, input_bytes=len(body_bytes))
    actual = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
    work.prepare_comparison(actual, binding["body_digest"])
    _require(actual == binding["body_digest"])
    return body_bytes


def _readback(row, binding, work, *, original=None):
    _require(type(row) is dict and len(row) == len(COLUMNS)
        and all(type(name) is str for name in row) and set(row) == set(COLUMNS))
    for name, value in binding.items():
        actual = row[name]
        # Type/size admission precedes variable comparison accounting.
        _require(type(actual) is type(value)
            and (len(actual) == len(value) if type(actual) is str else True))
        work.prepare_comparison(actual, value)
        _require(actual == value)
    _require(type(row["retained_at_epoch_ns"]) is int and 0 < row["retained_at_epoch_ns"] < 2**63)
    body = _body(row["body_bytes"], binding, work)
    if original is not None:
        work.charge(input_bytes=len(original) + len(body))
        _require(body == original)
    return body


def _live(original_deadline_ns, check, work):
    _require(type(original_deadline_ns) is int and 0 < original_deadline_ns < 2**63
        and callable(check) and type(work) is _ValidationWork)
    before = time.monotonic_ns()
    _require(type(before) is int and 0 <= before < original_deadline_ns)
    # The callback is an additional actual-owner check, never DB admission.
    # The existing finally guard refuses a replaced/changed work allowance.
    lifecycle._guard(work, check)
    after = time.monotonic_ns()
    _require(type(after) is int and before <= after < original_deadline_ns)


def _call(connection, raw, identity, work, original_deadline_ns, check, action):
    _live(original_deadline_ns, check, work)
    try:
        result = lifecycle._call(connection, raw, identity, work, action)
    except BaseException:
        # Preserve the first failure/cancellation while checking continuity.
        try:
            _live(original_deadline_ns, check, work)
        except BaseException:
            pass
        raise
    _live(original_deadline_ns, check, work)
    return result


def _store(*, binding, body_bytes, connection, original_deadline_ns, check, work):
    owned = _binding(binding, work)
    original_body = None if body_bytes is None else _body(body_bytes, owned, work)
    _live(original_deadline_ns, check, work)
    raw, identity, guarded = lifecycle._admit(connection, work)
    _live(original_deadline_ns, check, work)

    def call(action):
        return _call(connection, raw, identity, work, original_deadline_ns, check, action)

    manager = call(lambda: guarded.transaction())
    with lifecycle._scope(manager, connection, raw, identity, work):
        cursor_manager = call(lambda: guarded.cursor())
        with lifecycle._scope(cursor_manager, connection, raw, identity, work) as cursor:
            if original_body is not None:
                retained_at = call(time.time_ns)
                _require(type(retained_at) is int and 0 < retained_at < 2**63)
                parameters = tuple(owned[name] for name in BINDING_FIELDS) + (original_body, retained_at)
                call(lambda: cursor.execute(_INSERT, parameters))
            result = call(lambda: cursor.execute(_SELECT, tuple(owned[name] for name in _KEY_FIELDS)))
            row = call(result.fetchone)
            body = _readback(row, owned, work, original=original_body)
            call(lambda: None)
        call(lambda: None)
    call(lambda: None)
    return body


def persist_page(*, binding, body_bytes, connection, original_deadline_ns, check, work):
    """Retain exact bytes once; savepoint exit is not outer commit/durability."""
    _require(type(body_bytes) is bytes)
    return _store(binding=binding, body_bytes=body_bytes, connection=connection,
        original_deadline_ns=original_deadline_ns, check=check, work=work)


def read_page(*, binding, connection, original_deadline_ns, check, work):
    """Return raw bytes only; missing/conflicting pages never prove absence."""
    return _store(binding=binding, body_bytes=None, connection=connection,
        original_deadline_ns=original_deadline_ns, check=check, work=work)
