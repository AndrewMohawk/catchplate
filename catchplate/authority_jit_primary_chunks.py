"""Bounded native-row transport for the seven source JIT primary queries.

PostgreSQL JSON text is transport, never authenticated hash material. The
caller reads each fixed chunk on its actual snapshot and original physical
collector, reconstructs the row here, then performs genuine primary membership
before that row may choose another query. This module creates no cursor, clock,
work allowance, proof, successful observation, or operation-wide budget.

The parent must independently enforce the original aggregate selected-envelope
limit, MAX_TOTAL_NATIVE_BYTES and MAX_TOTAL_DATA_CHUNKS across all seven slots.
The derived eighth receipt query remains a separate authenticated absence read.
"""
from __future__ import annotations

from dataclasses import dataclass
from json.decoder import scanstring

from catchplate import authority_contract as authority
from catchplate import authority_transition_core as core
from catchplate.authority_query_read_work import _ValidationWork


OPERATION = "jit.assertion.issue"
CHUNK_BYTES = 128 * 1024
MAX_ROW_NATIVE_BYTES = authority.MAX_PLAN_SELECTED_BYTES + 53
MAX_ROW_DATA_CHUNKS = 33
MAX_TOTAL_NATIVE_BYTES = authority.MAX_PLAN_SELECTED_BYTES + 7 * 53
MAX_TOTAL_DATA_CHUNKS = 40
_HEX = frozenset("0123456789abcdef")
_JSON_SPACE = frozenset(" \t\r\n")
_ESCAPES = {'"': 34, "\\": 92, "/": 47, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9}
_RECORD_FIELDS = frozenset({"total_bytes", "chunk_ordinal", "chunk_offset", "chunk_hex"})

# Exact effective metadata_schema_source PostgreSQL column types. JSON- and
# timestamp-named columns are TEXT, not driver-decoded structures/datetimes.
# The suffix is nullability; all integer widths are native signed widths.
_COLUMNS = {
    "approval_requests": (
        ("id", "s!"), ("route_id", "s?"), ("method", "s!"), ("url", "s!"),
        ("status", "s!"), ("requested_at", "s!"), ("expires_at", "s!"),
        ("approved_until", "s?"), ("decision_note", "s?"), ("principal_id", "s?"),
        ("credential_id", "s?"), ("credential_version", "i32?"), ("policy_hash", "s?"),
        ("request_digest", "s?"), ("operation_digest", "s?"), ("canonical_request", "s?"),
        ("redacted_display", "s?"), ("grant_ttl_seconds", "i32?"), ("grant_max_uses", "i32?"),
        ("approver_policy_json", "s?"), ("approver_policy_digest", "s?"), ("approved_by", "s?"),
        ("approval_authn", "s?"), ("approver_webauthn_credential_id", "s?"),
        ("verified_assertion_receipt_digest", "s?"), ("approval_challenge_id", "s?"),
        ("pending_key", "s?"),
    ),
    "webauthn_challenges": (
        ("id", "s!"), ("challenge", "s!"), ("challenge_type", "s!"), ("user_id", "s!"),
        ("scope_key", "s?"), ("approval_request_id", "s?"), ("payload_json", "s!"),
        ("expires_at", "s!"), ("used_at", "s?"), ("created_at", "s!"),
        ("retention_recovery_id", "s?"), ("retention_recovery_row_digest", "s?"),
        ("retention_jit_receipt_digest", "s?"), ("retention_jit_row_digest", "s?"),
        ("retention_activation_receipt_digest", "s?"), ("retention_activation_row_digest", "s?"),
        ("retention_reference_mask", "i64!"),
    ),
    "webauthn_credentials": (
        ("id", "s!"), ("credential_id", "s!"), ("user_id", "s!"), ("label", "s!"),
        ("public_key_cose", "s!"), ("sign_count", "i32!"), ("aaguid", "s?"),
        ("authenticator_class", "s!"), ("attestation_fmt", "s?"), ("attestation_trusted", "i32!"),
        ("attestation_trust_path", "s!"), ("attestation_leaf_sha256", "s?"),
        ("attestation_root_sha256", "s?"), ("attestation_trust_bundle_digest", "s?"),
        ("attestation_trust_bundle_sequence", "i32?"), ("attestation_verified_at", "s?"),
        ("transports", "s!"), ("dev_private_key_pem", "s?"), ("created_at", "s!"),
        ("updated_at", "s!"), ("last_used_at", "s?"), ("revoked_at", "s?"),
        ("revoked_by", "s?"), ("revocation_reason", "s?"), ("revocation_source", "s?"),
    ),
    "webauthn_trust_publication_high_water": (
        ("authority_scope", "s!"), ("rollback_epoch", "i64!"), ("publication_sequence", "i64!"),
        ("publication_digest", "s!"), ("metadata_blob_digest", "s!"), ("revocation_set_digest", "s!"),
        ("witness_receipt_digest", "s!"), ("witness_sequence", "i64!"), ("updated_at_epoch_ns", "i64!"),
    ),
    "webauthn_trust_publications": (
        ("id", "s!"), ("scope", "s!"), ("previous_bundle_digest", "s?"), ("bundle_digest", "s!"),
        ("sequence", "i64!"), ("rollback_epoch", "i64!"), ("signing_key_id", "s!"),
        ("bundle_json", "s!"), ("payload_digest", "s!"), ("actor_id", "s!"),
        ("withdrawn_credential_ids_json", "s!"), ("audit_event_json", "s!"), ("status", "s!"),
        ("attempts", "i64!"), ("last_error", "s?"), ("created_at", "s!"), ("published_at", "s?"),
    ),
    "rbac_role_bindings": (
        ("subject_id", "s!"), ("roles_json", "s!"), ("status", "s!"), ("generation", "i64!"),
        ("binding_digest", "s!"), ("updated_at", "s!"), ("updated_by", "s!"), ("reason", "s?"),
        ("deprovisioned_at", "s?"), ("deprovisioned_by", "s?"),
    ),
    "policy_high_water": (
        ("scope", "s!"), ("policy_id", "s!"), ("sequence", "i64!"), ("rollback_epoch", "i64!"),
        ("policy_hash", "s!"), ("updated_at", "s!"),
    ),
}
_QUERIES = {
    "approval_requests": ("approval", "id", None),
    "webauthn_challenges": ("challenge", "id", None),
    "webauthn_credentials": ("credential", "id", None),
    "webauthn_trust_publication_high_water": ("trust_high_water", "authority_scope", "webauthn-metadata"),
    "webauthn_trust_publications": ("trust_publication", "id", None),
    "rbac_role_bindings": ("approver_role", "subject_id", None),
    "policy_high_water": ("policy_high_water", "scope", "global"),
}


class JitPrimaryChunkError(ValueError):
    pass


def _require(condition):
    if not condition:
        raise JitPrimaryChunkError("JIT native chunk differs from its fixed source row schedule")


def _work(work):
    _require(type(work) is _ValidationWork)


@dataclass(frozen=True, slots=True)
class _QueryIdentity:
    query_id: str
    table: str
    key_column: str
    key_value: str


def _query(query, work):
    _work(work)
    _require(type(query) is core.BoundedQuery and type(query.table) is str
        and query.table in _QUERIES)
    name, column, fixed = _QUERIES[query.table]
    _require(type(query.query_id) is str and len(query.query_id) <= 256
        and type(query.predicates) is tuple and len(query.predicates) == 1
        and type(query.order_by) is tuple and len(query.order_by) == 1
        and type(query.absent_key) is dict and len(query.absent_key) == 1
        and set(query.absent_key) == {column}
        and type(query.maximum_rows) is int and query.maximum_rows == 1
        and query.require_absence is False and type(query.proof_primitive) is str
        and query.proof_primitive == "primary-key-row"
        and type(query.work_units) is int and query.work_units == 1 and query.exact_page is False
        and query.page_size is None and query.continuation_token_digest is None
        and query.secondary_index_name is None)
    predicate, ordering = query.predicates[0], query.order_by[0]
    value = query.absent_key[column]
    _require(type(predicate) is core.QueryPredicate and type(predicate.column) is str
        and predicate.column == column and type(predicate.operator) is str
        and predicate.operator == "eq" and type(ordering) is core.QueryOrder
        and type(ordering.column) is str and ordering.column == column and ordering.descending is False
        and type(value) is str and 1 <= len(value) <= 1024 and "\x00" not in value
        and type(predicate.value) is str and len(predicate.value) <= 1024)
    _require(work.prepare_utf8(value) <= 1024)
    work.prepare_scan(value)
    _require(value == value.strip() and all(ord(character) >= 32 and ord(character) != 127
        for character in value))
    work.prepare_comparison(predicate.value, value)
    work.prepare_copy((query.query_id, query.table, column, value))
    _require(predicate.value == value and (fixed is None or fixed == value)
        and query.query_id == core.query_program_id(OPERATION, name, query.table))
    return _QueryIdentity(query.query_id, query.table, column, value)


def chunk_query(query, *, ordinal, work):
    """Return only fixed parameterized SQL; caller owns its real read accounting."""
    owned = _query(query, work)
    return _chunk_query(owned, ordinal, work)


def _chunk_query(owned, ordinal, work):
    _require(type(ordinal) is int and 0 <= ordinal < MAX_ROW_DATA_CHUNKS)
    offset = ordinal * CHUNK_BYTES
    # MATERIALIZED evaluates the exact row once. Only built-in pg_catalog
    # functions are used; no metadata serializer EXECUTE privilege is needed.
    # Limit 2 exposes a broken uniqueness/row contract instead of hiding it.
    work.charge(input_bytes=3072, json_nodes=8)
    sql = (
        "WITH native_row AS MATERIALIZED (SELECT pg_catalog.convert_to("
        "pg_catalog.to_jsonb(target)::pg_catalog.text, 'UTF8') AS body "
        f"FROM catchplate_metadata.{owned.table} AS target "
        f"WHERE target.{owned.key_column} IS NOT DISTINCT FROM %s LIMIT 2), "
        "framed AS (SELECT body, pg_catalog.octet_length(body) AS total_bytes FROM native_row) "
        f"SELECT total_bytes, {ordinal}::pg_catalog.int4 AS chunk_ordinal, "
        f"{offset}::pg_catalog.int4 AS chunk_offset, "
        f"CASE WHEN total_bytes BETWEEN 2 AND {MAX_ROW_NATIVE_BYTES} AND total_bytes > {offset} "
        f"THEN pg_catalog.encode(pg_catalog.substring(body, {offset + 1}, {CHUNK_BYTES}), 'hex') "
        "ELSE NULL END AS chunk_hex FROM framed"
    )
    _require(len(sql) <= 3072)
    work.prepare_copy((owned.key_value,))
    return sql, (owned.key_value,)


def _space(text, offset):
    while offset < len(text) and text[offset] in _JSON_SPACE:
        offset += 1
    return offset


def _ascii_size(point):
    return (2 if point in (8, 9, 10, 12, 13, 34, 92) else 6 if point < 32
        or 127 <= point <= 65535 else 12 if point > 65535 else 1)


def _string(text, offset, *, maximum, work):
    """Preflight one scalar before scanstring allocates it; never decode a graph."""
    _require(offset < len(text) and text[offset] == '"')
    position, size = offset + 1, 2
    while position < len(text):
        character = text[position]
        if character == '"':
            work.charge(input_bytes=size, json_nodes=1)
            value, end = scanstring(text, offset + 1, True)
            _require(end == position + 1)
            return value, end, size
        point = ord(character)
        if character == "\\":
            position += 1
            _require(position < len(text))
            escape = text[position]
            if escape == "u":
                _require(position + 4 < len(text))
                digits = text[position + 1:position + 5]
                _require(all(c in "0123456789abcdefABCDEF" for c in digits))
                point = int(digits, 16)
                position += 4
                if 0xD800 <= point <= 0xDBFF:
                    _require(text[position + 1:position + 3] == "\\u" and position + 6 < len(text))
                    digits = text[position + 3:position + 7]
                    _require(all(c in "0123456789abcdefABCDEF" for c in digits))
                    low = int(digits, 16)
                    _require(0xDC00 <= low <= 0xDFFF)
                    point = 0x10000 + ((point - 0xD800) << 10) + low - 0xDC00
                    position += 6
                _require(point != 0 and not 0xD800 <= point <= 0xDFFF)
            else:
                _require(escape in '"\\/bfnrt')
                point = _ESCAPES[escape]
        else:
            _require(point >= 32 and not 0xD800 <= point <= 0xDFFF)
        size += _ascii_size(point)
        _require(size <= maximum)
        position += 1
    raise JitPrimaryChunkError("JIT native text scalar is truncated")


def _flat_row(text, owned, work):
    columns = _COLUMNS[owned.table]
    work.prepare_copy(columns)
    expected = dict(columns)
    work.charge(input_bytes=2 + 2 * len(columns), json_nodes=1)
    result, size = {}, 2
    position = _space(text, 0)
    _require(position < len(text) and text[position] == "{")
    position = _space(text, position + 1)
    for index in range(len(columns)):
        key, position, key_size = _string(text, position, maximum=256, work=work)
        _require(key in expected and key not in result)
        position = _space(text, position)
        _require(position < len(text) and text[position] == ":")
        position = _space(text, position + 1)
        _require(position < len(text))
        kind = expected[key]
        size += key_size + 1 + int(index > 0)
        remaining = authority.MAX_PLAN_SELECTED_BYTES - size
        _require(remaining >= 2)
        if text.startswith("null", position):
            _require(kind.endswith("?") and remaining >= 4)
            work.charge(input_bytes=4, json_nodes=1)
            value, position, value_size = None, position + 4, 4
        elif kind.startswith("s"):
            value, position, value_size = _string(text, position, maximum=remaining, work=work)
        else:
            start = position
            if text[position] == "-":
                position += 1
            _require(position < len(text) and "0" <= text[position] <= "9")
            while position < len(text) and "0" <= text[position] <= "9":
                position += 1
                _require(position - start <= 20)
            token = text[start:position]
            _require(token != "-0" and (token == "0" or token.lstrip("-")[0] != "0"))
            work.charge(input_bytes=len(token), json_nodes=1)
            value = int(token)
            bits = 32 if kind.startswith("i32") else 64
            _require(-(1 << (bits - 1)) <= value < (1 << (bits - 1)))
            value_size = len(token)
        size += value_size
        _require(size <= authority.MAX_PLAN_SELECTED_BYTES)
        result[key] = value
        position = _space(text, position)
        ending = "}" if index + 1 == len(columns) else ","
        _require(position < len(text) and text[position] == ending)
        position = _space(text, position + 1)
    _require(position == len(text) and len(result) == len(columns))
    measured, _ = work.measure(result)
    _require(measured == size and measured <= authority.MAX_PLAN_SELECTED_BYTES)
    work.prepare_comparison(result[owned.key_column], owned.key_value)
    _require(result[owned.key_column] == owned.key_value)
    return result, measured


class JitPrimaryRowChunks:
    """Sequential source-row bytes, not authenticated selected-row authority."""

    __slots__ = ("_query", "_held", "_chunks", "_total", "_native_bytes", "_data_chunks", "_complete",
        "_failed", "_finished", "_active")

    def __init__(self, query, *, work):
        self._query = _query(query, work)
        work.charge(input_bytes=32, json_nodes=6)
        self._held = (self._query.query_id, self._query.table,
            self._query.key_column, self._query.key_value)
        self._chunks, self._total, self._native_bytes, self._data_chunks = [], None, 0, 0
        self._complete = self._failed = self._finished = self._active = False

    def _local(self):
        _require(not self._failed and type(self._query) is _QueryIdentity
            and all(actual is original for actual, original in zip((self._query.query_id,
                self._query.table, self._query.key_column, self._query.key_value), self._held)))

    @property
    def native_bytes(self):
        self._local()
        return self._native_bytes

    @property
    def data_chunks(self):
        self._local()
        return self._data_chunks

    @property
    def complete(self):
        self._local()
        return self._complete

    @property
    def next_ordinal(self):
        self._local()
        return None if self._complete else len(self._chunks)

    def _next_query(self, *, work):
        """Private actual-reader seam; no caller query or ordinal override."""
        try:
            self._local()
            _work(work)
            _require(not self._active and not self._complete and not self._finished)
            ordinal = len(self._chunks)
            sql, parameters = _chunk_query(self._query, ordinal, work)
            work.prepare_copy((self._query.table, self._query.query_id,
                self._query.key_column, self._query.key_value, ordinal))
            return (sql, parameters, self._query.table, self._query.query_id,
                self._query.key_column, self._query.key_value, ordinal)
        except BaseException:
            self._failed = True
            raise

    def accept(self, rows, *, work):
        try:
            self._local()
            _work(work)
            _require(not self._active and not self._finished and not self._complete
                and type(rows) is list and len(rows) <= 1)
            self._active = True
            ordinal = len(self._chunks)
            _require(ordinal < MAX_ROW_DATA_CHUNKS)
            if not rows:
                _require(ordinal == 0 and self._total is None)
                work.charge(input_bytes=2, json_nodes=1)
                self._total, self._complete = 0, True
                return
            record = rows[0]
            _require(type(record) is dict and len(record) == 4 and set(record) == _RECORD_FIELDS)
            total, received, offset, raw = (record["total_bytes"], record["chunk_ordinal"],
                record["chunk_offset"], record["chunk_hex"])
            _require(type(total) is int and 2 <= total <= MAX_ROW_NATIVE_BYTES
                and type(received) is int and received == ordinal
                and type(offset) is int and offset == ordinal * CHUNK_BYTES and offset < total
                and type(raw) is str and len(raw) == 2 * min(CHUNK_BYTES, total - offset)
                and (self._total is None or total == self._total))
            work.prepare_scan(record)
            _require(all(character in _HEX for character in raw))
            work.charge(input_bytes=len(raw) // 2, json_nodes=2)
            chunk = bytes.fromhex(raw)
            self._chunks.append(chunk)
            self._data_chunks += 1
            self._total = total
            self._native_bytes += len(chunk)
            self._complete = self._native_bytes == total
            _require(self._native_bytes == offset + len(chunk))
        except BaseException:
            self._failed = True
            raise
        finally:
            self._active = False

    def finish(self, *, work):
        try:
            self._local()
            _work(work)
            _require(not self._active and not self._finished and self._complete)
            self._active = True
            if self._total == 0:
                work.charge(input_bytes=4, json_nodes=1)
                result = None
            else:
                _require(self._total == self._native_bytes and 1 <= len(self._chunks) <= MAX_ROW_DATA_CHUNKS)
                # Join, strict UTF-8 decode, then one bounded flat-parser scan.
                # Individual decoded scalars are additionally precharged at
                # their actual canonical ASCII sizes before allocation.
                work.charge(input_bytes=3 * self._native_bytes, json_nodes=len(self._chunks) + 2)
                native = b"".join(self._chunks)
                _require(len(native) == self._native_bytes)
                text = native.decode("utf-8", "strict")
                result, canonical_size = _flat_row(text, self._query, work)
                _require(self._native_bytes <= canonical_size + 2 * len(_COLUMNS[self._query.table]) - 1)
            self._finished = True
            self._chunks.clear()
            return result
        except BaseException:
            self._failed = True
            raise
        finally:
            self._active = False
