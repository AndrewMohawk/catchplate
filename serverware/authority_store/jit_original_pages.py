"""Immutable bounded JIT originals, not proof or parent-plan authority.

The caller owns the actual admitted SERIALIZABLE planner-writer connection,
original absolute deadline and complete parent/descriptor-chain replay. This
store retains or returns opaque immutable bytes under an exact closed context.
The source kind/ordinal bounds do not establish schedule coverage or ordering.
No connection, commit, retry, replacement work or renewed clock is created.
Normal nested savepoint exit is not outer-transaction durability. Observable
handle/status checks cannot detect a hostile driver's hidden commit-and-BEGIN.

This module supplies source DDL only. Its source installer and exact role ACL
joins are separate; their presence is not deployed/native admission evidence.
"""
from __future__ import annotations

import hashlib
import re
import time

from serverware import authority_contract as authority
from serverware.authority_query_read_work import _ValidationWork
from serverware.authority_store import webauthn_evidence_retention as lifecycle


TABLE = "serverware_metadata.policy_authority_jit_original_pages"
OPERATION = "jit.assertion.issue"
MAX_CHUNK_BYTES = 2 * 128 * 1024 + 256
MAX_PROOF_BYTES = 128 * 1024
MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_CHUNK_ORDINAL = 7 * 33 - 1
MAX_PROOF_ORDINAL = 7
MAX_INDEX_ORDINAL = 11
PAGE_KINDS = frozenset({"primary-chunk", "primary-proof", "index-frontier"})
CONTEXT_FIELDS = ("parent_plan_digest", "original_manifest_digest", "source_revision",
    "operation", "operation_id", "request_digest", "configuration_digest", "page_kind", "page_ordinal")
BINDING_FIELDS = CONTEXT_FIELDS + ("body_digest", "body_byte_count")
COLUMNS = BINDING_FIELDS + ("body_bytes", "retained_at_epoch_ns")
_DIGEST_FIELDS = ("parent_plan_digest", "original_manifest_digest", "operation_id",
    "request_digest", "configuration_digest", "body_digest")
_KEY_FIELDS = ("parent_plan_digest", "original_manifest_digest", "page_kind", "page_ordinal")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SELECT = "SELECT " + ", ".join(COLUMNS) + " FROM " + TABLE + " WHERE " + " AND ".join(
    name + "=%s" for name in _KEY_FIELDS)
_INSERT = ("INSERT INTO " + TABLE + " (" + ", ".join(COLUMNS) + ") VALUES ("
    + ", ".join(("%s",) * len(COLUMNS)) + ") ON CONFLICT ("
    + ", ".join(_KEY_FIELDS) + ") DO NOTHING")


class JitOriginalPageError(ValueError):
    pass


def _require(value):
    if not value:
        raise JitOriginalPageError("JIT original page custody differs")


def installation_sql():
    """PostgreSQL DDL only; neither installation nor role grants occur here."""
    return f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    parent_plan_digest TEXT NOT NULL,
    original_manifest_digest TEXT NOT NULL,
    source_revision TEXT NOT NULL CHECK (source_revision = '{authority.SOURCE_REVISION}'),
    operation TEXT NOT NULL CHECK (operation = '{OPERATION}'),
    operation_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    configuration_digest TEXT NOT NULL,
    page_kind TEXT NOT NULL CHECK (page_kind IN ('primary-chunk', 'primary-proof', 'index-frontier')),
    page_ordinal BIGINT NOT NULL,
    body_digest TEXT NOT NULL,
    body_byte_count BIGINT NOT NULL CHECK (body_byte_count BETWEEN 2 AND {MAX_BODY_BYTES}),
    body_bytes BYTEA NOT NULL CHECK (octet_length(body_bytes) = body_byte_count),
    retained_at_epoch_ns BIGINT NOT NULL CHECK (retained_at_epoch_ns > 0),
    PRIMARY KEY (parent_plan_digest, original_manifest_digest, page_kind, page_ordinal),
    CHECK ((page_kind = 'primary-chunk' AND page_ordinal BETWEEN 0 AND {MAX_CHUNK_ORDINAL}
            AND body_byte_count <= {MAX_CHUNK_BYTES})
        OR (page_kind = 'primary-proof' AND page_ordinal BETWEEN 0 AND {MAX_PROOF_ORDINAL}
            AND body_byte_count <= {MAX_PROOF_BYTES})
        OR (page_kind = 'index-frontier' AND page_ordinal BETWEEN 0 AND {MAX_INDEX_ORDINAL}))
);
"""


def _kind_limits(kind):
    if kind == "primary-chunk":
        return MAX_CHUNK_ORDINAL, MAX_CHUNK_BYTES
    if kind == "primary-proof":
        return MAX_PROOF_ORDINAL, MAX_PROOF_BYTES
    _require(kind == "index-frontier")
    return MAX_INDEX_ORDINAL, MAX_BODY_BYTES


def _context_values(value):
    for name in _DIGEST_FIELDS[:-1]:
        scalar = value[name]
        _require(type(scalar) is str and len(scalar) == 71 and _DIGEST.fullmatch(scalar) is not None)
    _require(type(value["source_revision"]) is str and value["source_revision"] == authority.SOURCE_REVISION
        and type(value["operation"]) is str and value["operation"] == OPERATION
        and type(value["page_kind"]) is str and value["page_kind"] in PAGE_KINDS
        and type(value["page_ordinal"]) is int)
    maximum, _ = _kind_limits(value["page_kind"])
    _require(0 <= value["page_ordinal"] <= maximum)


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
    _, maximum = _kind_limits(binding["page_kind"])
    _require(type(digest) is str and len(digest) == 71 and _DIGEST.fullmatch(digest) is not None
        and type(binding["body_byte_count"]) is int and 2 <= binding["body_byte_count"] <= maximum)
    work.prepare_copy(binding)
    return binding.copy()


def _body(body_bytes, binding, work):
    _, maximum = _kind_limits(binding["page_kind"])
    _require(type(body_bytes) is bytes and len(body_bytes) == binding["body_byte_count"]
        and 2 <= len(body_bytes) <= maximum)
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
    if original_context:
        # These storage-supplied framing values are untrusted, not the parent's
        # descriptor. Reserve the small closed projection before allocating it.
        work.charge(input_bytes=2048, json_nodes=32)
        body_binding = _binding({name: row[name] for name in BINDING_FIELDS}, work)
    else:
        body_binding = binding
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
    _require(lifecycle._guard(work, check) is None)
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
    _require(type(original_context) is bool and (not original_context or body_bytes is None))
    owned = _context(binding, work) if original_context else _binding(binding, work)
    original_body = None if body_bytes is None else _body(body_bytes, owned, work)
    # Context and immutable body are owned before the first owner/native callback.
    work.charge(input_bytes=2048, json_nodes=32)
    key_parameters = tuple(owned[name] for name in _KEY_FIELDS)
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
                work.charge(input_bytes=2048, json_nodes=32)
                parameters = tuple(owned[name] for name in BINDING_FIELDS) + (original_body, retained_at)
                call(lambda: cursor.execute(_INSERT, parameters))
            result = call(lambda: cursor.execute(_SELECT, key_parameters))
            row = call(result.fetchone)
            body = _readback(row, owned, work, original=original_body, original_context=original_context)
            call(lambda: None)
        call(lambda: None)
    call(lambda: None)
    return body


def persist_page(*, binding, body_bytes, connection, original_deadline_ns, check, work):
    """Retain literal bytes; savepoint success is not outer commit or authority."""
    _require(type(body_bytes) is bytes)
    return _store(binding=binding, body_bytes=body_bytes, connection=connection,
        original_deadline_ns=original_deadline_ns, check=check, work=work)


def read_original(*, context, connection, original_deadline_ns, check, work):
    """Return untrusted raw bytes; independent parent-chain/proof replay is required."""
    return _store(binding=context, body_bytes=None, connection=connection,
        original_deadline_ns=original_deadline_ns, check=check, work=work, original_context=True)
