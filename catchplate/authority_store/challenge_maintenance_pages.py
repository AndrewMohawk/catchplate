"""Immutable raw challenge-maintenance pages, never parent-plan authority.

The caller verifies the parent, owns its original SERIALIZABLE planner-writer
transaction/deadline, and enforces the complete phase/geometry schedule. This
store admits the real facade and preserves its physical handle while retaining
or returning exact bounded bytes. It does not connect, commit, retry, renew a
clock, interpret a proof verdict, or make a pending outer transaction durable.
"""
from __future__ import annotations

import hashlib
import re
import time

from catchplate import authority_contract as authority
from catchplate.authority_query_read_work import _ValidationWork
from catchplate.authority_store import webauthn_evidence_retention as lifecycle


TABLE = "catchplate_metadata.policy_authority_challenge_maintenance_pages"
MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_WRITE_ORDINAL = 5120
MAX_CANDIDATE_ORDINAL = 24
PHASES = ("pre-expire", "pre-old", "pre-overflow", "scope",
    "post-expire", "post-old", "post-overflow", "admission")
OPERATIONS = frozenset({"webauthn.challenge.create", "webauthn.challenge.maintain"})
PAGE_KINDS = frozenset({"count", "range", "rank", "primary", "write", "candidate"})
INDEX_IDS = (
    "webauthn_registration_unused_global", "webauthn_registration_unused_user",
    "webauthn_challenge_created_global", "webauthn_challenge_created_user",
    "webauthn_challenge_unused_global", "webauthn_challenge_unused_user",
    "webauthn_challenge_terminal_unreferenced_global",
    "webauthn_challenge_scope_unused", "webauthn_challenge_value",
)
CONTEXT_FIELDS = ("parent_plan_digest", "maintenance_manifest_digest", "source_revision",
    "operation", "operation_id", "request_digest", "configuration_digest",
    "phase_ordinal", "page_kind", "index_id", "page_ordinal")
BINDING_FIELDS = CONTEXT_FIELDS + ("body_digest", "body_byte_count")
COLUMNS = BINDING_FIELDS + ("body_bytes", "retained_at_epoch_ns")
_DIGEST_FIELDS = ("parent_plan_digest", "maintenance_manifest_digest", "operation_id",
    "request_digest", "configuration_digest", "body_digest")
_KEY_FIELDS = ("parent_plan_digest", "maintenance_manifest_digest", "phase_ordinal",
    "page_kind", "index_id", "page_ordinal")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SELECT = "SELECT " + ", ".join(COLUMNS) + " FROM " + TABLE + " WHERE " + " AND ".join(
    name + "=%s" for name in _KEY_FIELDS)
_INSERT = ("INSERT INTO " + TABLE + " (" + ", ".join(COLUMNS) + ") VALUES ("
    + ", ".join(("%s",) * len(COLUMNS)) + ") ON CONFLICT ("
    + ", ".join(_KEY_FIELDS) + ") DO NOTHING")


class ChallengeMaintenancePageError(ValueError):
    pass


def _require(value):
    if not value:
        raise ChallengeMaintenancePageError("challenge maintenance page custody differs")


def installation_sql():
    """PostgreSQL DDL only; source installation and ACLs belong elsewhere."""
    index_names = ", ".join("'" + name + "'" for name in INDEX_IDS)
    return f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    parent_plan_digest TEXT NOT NULL,
    maintenance_manifest_digest TEXT NOT NULL,
    source_revision TEXT NOT NULL CHECK (source_revision = '{authority.SOURCE_REVISION}'),
    operation TEXT NOT NULL CHECK (operation IN ('webauthn.challenge.create', 'webauthn.challenge.maintain')),
    operation_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    configuration_digest TEXT NOT NULL,
    phase_ordinal BIGINT NOT NULL CHECK (phase_ordinal BETWEEN 0 AND 7),
    page_kind TEXT NOT NULL CHECK (page_kind IN ('count', 'range', 'rank', 'primary', 'write', 'candidate')),
    index_id TEXT NOT NULL,
    page_ordinal BIGINT NOT NULL,
    body_digest TEXT NOT NULL,
    body_byte_count BIGINT NOT NULL CHECK (body_byte_count BETWEEN 1 AND {MAX_BODY_BYTES}),
    body_bytes BYTEA NOT NULL CHECK (octet_length(body_bytes) = body_byte_count),
    retained_at_epoch_ns BIGINT NOT NULL CHECK (retained_at_epoch_ns > 0),
    PRIMARY KEY (parent_plan_digest, maintenance_manifest_digest, phase_ordinal, page_kind, index_id, page_ordinal),
    CHECK ((page_kind = 'write' AND index_id IN ({index_names}) AND page_ordinal BETWEEN 0 AND {MAX_WRITE_ORDINAL})
        OR (page_kind <> 'write' AND index_id = '' AND (
            (page_kind = 'primary' AND page_ordinal BETWEEN 0 AND 255)
            OR (page_kind = 'candidate' AND page_ordinal BETWEEN 0 AND {MAX_CANDIDATE_ORDINAL})
            OR (page_kind = 'count' AND page_ordinal BETWEEN 0 AND 2)
            OR (page_kind IN ('range', 'rank') AND page_ordinal = 0)))),
    CHECK (page_kind <> 'write' OR phase_ordinal NOT IN (3, 7)),
    CHECK (phase_ordinal <> 7 OR page_kind = 'count'),
    CHECK (page_kind <> 'rank' OR phase_ordinal IN (2, 6))
);
"""


def _context_values(binding):
    for name in _DIGEST_FIELDS[:-1]:
        value = binding[name]
        _require(type(value) is str and len(value) == 71 and _DIGEST.fullmatch(value) is not None)
    _require(type(binding["source_revision"]) is str and binding["source_revision"] == authority.SOURCE_REVISION
        and type(binding["operation"]) is str and binding["operation"] in OPERATIONS
        and type(binding["phase_ordinal"]) is int and 0 <= binding["phase_ordinal"] < len(PHASES)
        and type(binding["page_kind"]) is str and binding["page_kind"] in PAGE_KINDS
        and type(binding["index_id"]) is str and type(binding["page_ordinal"]) is int)
    phase, kind, index_id, ordinal = (binding[name] for name in
        ("phase_ordinal", "page_kind", "index_id", "page_ordinal"))
    if kind == "write":
        _require(index_id in INDEX_IDS and 0 <= ordinal <= MAX_WRITE_ORDINAL and phase not in (3, 7))
    else:
        maximum = (255 if kind == "primary" else MAX_CANDIDATE_ORDINAL if kind == "candidate"
                   else 2 if kind == "count" else 0)
        _require(index_id == "" and 0 <= ordinal <= maximum)
    _require((phase != 7 or kind == "count") and (kind != "rank" or phase in (2, 6)))


def _context(context, work):
    _require(type(work) is _ValidationWork and type(context) is dict
        and len(context) == len(CONTEXT_FIELDS)
        and all(type(name) is str for name in context) and set(context) == set(CONTEXT_FIELDS))
    _context_values(context)
    work.prepare_copy(context)
    return context.copy()


def _binding(binding, work):
    _require(type(work) is _ValidationWork and type(binding) is dict
        and len(binding) == len(BINDING_FIELDS)
        and all(type(name) is str for name in binding) and set(binding) == set(BINDING_FIELDS))
    _context_values(binding)
    digest = binding["body_digest"]
    _require(type(digest) is str and len(digest) == 71 and _DIGEST.fullmatch(digest) is not None
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


def _readback(row, binding, work, *, original=None, original_context=False):
    _require(type(row) is dict and len(row) == len(COLUMNS)
        and all(type(name) is str for name in row) and set(row) == set(COLUMNS))
    for name, value in binding.items():
        actual = row[name]
        _require(type(actual) is type(value)
            and (len(actual) == len(value) if type(actual) is str else True))
        work.prepare_comparison(actual, value)
        _require(actual == value)
    _require(type(row["retained_at_epoch_ns"]) is int and 0 < row["retained_at_epoch_ns"] < 2**63)
    # A context-only read learns these framing fields from storage, not from
    # the parent. They are checked for corruption but confer no proof authority.
    body_binding = _binding({name: row[name] for name in BINDING_FIELDS}, work) if original_context else binding
    body = _body(row["body_bytes"], body_binding, work)
    if original is not None:
        work.charge(input_bytes=len(original) + len(body))
        _require(body == original)
    return body


def _live(original_deadline_ns, check, work):
    _require(type(original_deadline_ns) is int and 0 < original_deadline_ns < 2**63
        and callable(check) and type(work) is _ValidationWork)
    before = time.monotonic_ns()
    _require(type(before) is int and 0 <= before < original_deadline_ns)
    lifecycle._guard(work, check)
    after = time.monotonic_ns()
    _require(type(after) is int and before <= after < original_deadline_ns)


def _call(connection, raw, identity, work, original_deadline_ns, check, action):
    _live(original_deadline_ns, check, work)
    try:
        result = lifecycle._call(connection, raw, identity, work, action)
    except BaseException:
        try:
            _live(original_deadline_ns, check, work)
        except BaseException:
            pass
        raise
    _live(original_deadline_ns, check, work)
    return result


def _store(*, binding, body_bytes, connection, original_deadline_ns, check, work, original_context=False):
    _require(not original_context or body_bytes is None)
    owned = _context(binding, work) if original_context else _binding(binding, work)
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
            body = _readback(row, owned, work, original=original_body, original_context=original_context)
            call(lambda: None)
        call(lambda: None)
    call(lambda: None)
    return body


def persist_page(*, binding, body_bytes, connection, original_deadline_ns, check, work):
    """Retain literal bytes; savepoint exit is not outer commit/durability."""
    _require(type(body_bytes) is bytes)
    return _store(binding=binding, body_bytes=body_bytes, connection=connection,
        original_deadline_ns=original_deadline_ns, check=check, work=work)


def read_page(*, binding, connection, original_deadline_ns, check, work):
    """Return only raw evidence; absent/conflicting rows fail closed."""
    return _store(binding=binding, body_bytes=None, connection=connection,
        original_deadline_ns=original_deadline_ns, check=check, work=work)


def read_original(*, context, connection, original_deadline_ns, check, work):
    """Read untrusted raw evidence under exact original context and custody.

    The stored digest/length only check framing integrity. The caller must
    independently recompute the complete raw-page group chain and join its
    original parent manifest before any admission; this returns bytes only.
    """
    return _store(binding=context, body_bytes=None, connection=connection,
        original_deadline_ns=original_deadline_ns, check=check, work=work, original_context=True)
