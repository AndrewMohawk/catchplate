"""Purpose-fixed native-review row transport, never current-state authority.

The actual reader owns its PostgreSQL snapshot, source-fixed read stages and
their original work allowances. This codec creates none of those. Each chunk
and final decode consumes the particular stage's supplied work; callers must
also close the operation-wide selected/native/chunk limits below. A detached
row (including None) is not a membership proof or an authenticated absence.

This is deliberately independent of the seven-row jit.assertion.issue codec.
It neither changes that profile nor widens any existing global work limit.
"""
from __future__ import annotations

from dataclasses import dataclass
from json.decoder import scanstring
from types import MappingProxyType

from catchplate import authority_transition_core as core
from catchplate.authority_query_read_work import _ValidationWork


AUTHORIZE_OPERATION = "jit.review-open.authorize"
RECEIPT_OPERATION = "jit.review-open.receipt.issue"
CHUNK_BYTES = 128 * 1024
MAX_TOTAL_SELECTED_BYTES = 32 * 1024 * 1024
MAX_TOTAL_NATIVE_BYTES = MAX_TOTAL_SELECTED_BYTES + 13 * 53
MAX_TOTAL_DATA_CHUNKS = (MAX_TOTAL_NATIVE_BYTES + CHUNK_BYTES - 1) // CHUNK_BYTES + 12
_HEX = frozenset("0123456789abcdef")
_JSON_SPACE = frozenset(" \t\r\n")
_ESCAPES = {'"': 34, "\\": 92, "/": 47, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9}
_RECORD_FIELDS = frozenset({"total_bytes", "chunk_ordinal", "chunk_offset", "chunk_hex"})

# Full effective PostgreSQL rows. Timestamp/JSON names remain TEXT; i32/i64
# preserve actual signed widths. !/? mark NOT NULL/nullable, not semantics.
_COLUMNS = MappingProxyType({
    "oidc_browser_sessions": (
        ("id", "s!"), ("token_digest", "s!"), ("oidc_token_digest", "s!"),
        ("user_id", "s!"), ("roles_json", "s!"), ("status", "s!"),
        ("provider_expires_at", "s!"), ("expires_at", "s!"), ("pending_expires_at", "s?"),
        ("created_at", "s!"), ("updated_at", "s!"), ("activated_at", "s?"),
        ("revoked_at", "s?"), ("bound_webauthn_credential_id", "s?"),
        ("activation_trust_bundle_digest", "s?"), ("activation_trust_bundle_sequence", "i64?"),
        ("activation_authenticator_class", "s?"), ("revocation_reason", "s?"),
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
    "rbac_authority_state": (
        ("authority_id", "i32!"), ("generation", "i64!"), ("state_digest", "s!"),
        ("binding_table_revision", "i64!"), ("verified_binding_table_revision", "i64!"),
        ("updated_at", "s!"),
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
    "policy_authority_native_jit_review_pairs": (
        ("approval_request_id", "s!"), ("parent_request_digest", "s!"), ("parent_operation_id", "s!"),
        ("child_request_digest", "s!"), ("child_operation_id", "s!"),
        ("parent_request_original", "s!"), ("child_request_original", "s!"),
        ("pair_original", "s!"), ("proof_original", "s!"), ("pair_sha256", "s!"),
        ("proof_sha256", "s!"), ("source_contract_digest", "s!"),
        ("control_plane_configuration_digest", "s!"), ("owner_scope_digest", "s!"),
        ("secret_kek_id", "s!"), ("issued_at_epoch_ns", "i64!"),
        ("seal_expires_at_epoch_ns", "i64!"), ("document_expires_at_epoch_ns", "i64!"),
        ("recorded_at_epoch_ns", "i64!"), ("source_revision", "s!"),
    ),
    "approval_review_receipts": (
        ("id", "s!"), ("approval_request_id", "s!"), ("reviewer_id", "s!"),
        ("review_digest", "s!"), ("expires_at", "s!"), ("used_at", "s?"), ("created_at", "s!"),
    ),
    "policy_authority_bounded_aggregate_states": (
        ("aggregate_id", "s!"), ("aggregate_kind", "s!"), ("partition_digest", "s!"),
        ("revision", "i64!"), ("live_count", "i64!"), ("active_count", "i64!"),
        ("capacity_limit", "i64!"), ("reserved_units_json", "s!"), ("committed_units_json", "s!"),
        ("next_sequence", "i64!"), ("minimum_expiry_epoch_ns", "i64?"),
        ("expiry_index_root_digest", "s!"), ("work_page_id", "s?"), ("state_json", "s!"),
        ("state_digest", "s!"), ("updated_at_epoch_ns", "i64!"), ("source_revision", "s!"),
    ),
    "metadata_audit_outbox": (
        ("id", "s!"), ("event_type", "s!"), ("actor_type", "s!"), ("actor_id", "s?"),
        ("event_json", "s!"), ("event_digest", "s!"), ("storage_format_version", "i64?"),
        ("status", "s!"), ("claim_id", "s?"), ("claimed_at", "s?"), ("attempts", "i64!"),
        ("audited_at", "s?"), ("audit_event_hash", "s?"), ("last_error", "s?"), ("created_at", "s!"),
    ),
})
_QUERIES = MappingProxyType({
    "session": ("oidc_browser_sessions", "id", None),
    "credential": ("webauthn_credentials", "id", None),
    "trust_high_water": ("webauthn_trust_publication_high_water", "authority_scope", "webauthn-metadata"),
    "trust_publication": ("webauthn_trust_publications", "id", None),
    "rbac_authority": ("rbac_authority_state", "authority_id", 1),
    "reviewer_role": ("rbac_role_bindings", "subject_id", None),
    "policy_high_water": ("policy_high_water", "scope", "global"),
    "approval": ("approval_requests", "id", None),
    "retained_pair": ("policy_authority_native_jit_review_pairs", "approval_request_id", None),
    "receipt": ("approval_review_receipts", "id", None),
    "receipt_capacity": ("policy_authority_bounded_aggregate_states", "aggregate_id", None),
    "audit": ("metadata_audit_outbox", "id", None),
    "audit_capacity": ("policy_authority_bounded_aggregate_states", "aggregate_id", None),
})
_BASE_NAMES = tuple(_QUERIES)[:9]
_ROW_MAX_CANONICAL_BYTES = MappingProxyType({
    table: (2 * 2176 * 1024 + 16 * 1024 if table == "policy_authority_native_jit_review_pairs"
        else 12 * 1024 * 1024 + 16 * 1024 if table == "webauthn_trust_publications"
        else 1024 * 1024)
    for table in _COLUMNS
})
_ORIGINAL_LIMITS = MappingProxyType({
    "policy_authority_native_jit_review_pairs": MappingProxyType({
        "parent_request_original": 512 * 1024, "child_request_original": 512 * 1024,
        "pair_original": 1024 * 1024, "proof_original": 128 * 1024,
    }),
    "webauthn_trust_publications": MappingProxyType({
        "bundle_json": 2 * 1024 * 1024, "withdrawn_credential_ids_json": 2 * 1024 * 1024,
        "audit_event_json": 2 * 1024 * 1024,
    }),
})


class NativeJitReviewChunkError(ValueError):
    pass


def _require(condition):
    if not condition:
        raise NativeJitReviewChunkError("Native review chunk differs from its fixed source row schedule")


def _work(work):
    _require(type(work) is _ValidationWork)


@dataclass(frozen=True, slots=True)
class _QueryIdentity:
    operation: str
    query_id: str
    table: str
    key_column: str
    key_value: str | int

    @property
    def canonical_cap(self):
        return _ROW_MAX_CANONICAL_BYTES[self.table]

    @property
    def native_cap(self):
        return self.canonical_cap + 2 * len(_COLUMNS[self.table]) - 1

    @property
    def chunk_cap(self):
        return (self.native_cap + CHUNK_BYTES - 1) // CHUNK_BYTES


def _query(operation, query, work):
    _work(work)
    _require(type(operation) is str and operation in (AUTHORIZE_OPERATION, RECEIPT_OPERATION)
        and type(query) is core.BoundedQuery and type(query.table) is str
        and query.table in _COLUMNS and type(query.query_id) is str and len(query.query_id) <= 256)
    candidates = tuple((name, column, fixed) for name, (table, column, fixed) in _QUERIES.items()
        if table == query.table and (operation == RECEIPT_OPERATION or name in _BASE_NAMES)
        and query.query_id == core.query_program_id(operation, name, table))
    _require(len(candidates) == 1)
    _, column, fixed = candidates[0]
    _require(type(query.predicates) is tuple and len(query.predicates) == 1
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
        and type(ordering.column) is str and ordering.column == column and ordering.descending is False)
    if column == "authority_id":
        _require(type(value) is int and value == 1 and type(predicate.value) is int)
    else:
        _require(type(value) is str and 1 <= len(value) <= 1024 and "\x00" not in value
            and type(predicate.value) is str and len(predicate.value) <= 1024)
        _require(work.prepare_utf8(value) <= 1024)
        work.prepare_scan(value)
        _require(value == value.strip() and all(ord(c) >= 32 and ord(c) != 127 for c in value))
    work.prepare_comparison(predicate.value, value)
    work.prepare_copy((operation, query.query_id, query.table, column, value))
    _require(predicate.value == value and (fixed is None or fixed == value))
    return _QueryIdentity(operation, query.query_id, query.table, column, value)


def chunk_query(operation, query, *, ordinal, work):
    """Fixed parameterized SQL only; no database call, proof or read allowance."""
    return _chunk_query(_query(operation, query, work), ordinal, work)


def _chunk_query(owned, ordinal, work):
    _require(type(ordinal) is int and 0 <= ordinal < owned.chunk_cap)
    offset = ordinal * CHUNK_BYTES
    work.charge(input_bytes=3072, json_nodes=8)
    sql = (
        "WITH native_row AS MATERIALIZED (SELECT pg_catalog.convert_to("
        "pg_catalog.to_jsonb(target)::pg_catalog.text, 'UTF8') AS body "
        f"FROM catchplate_metadata.{owned.table} AS target "
        f"WHERE target.{owned.key_column} IS NOT DISTINCT FROM %s LIMIT 2), "
        "framed AS (SELECT body, pg_catalog.octet_length(body) AS total_bytes FROM native_row) "
        f"SELECT total_bytes, {ordinal}::pg_catalog.int4 AS chunk_ordinal, "
        f"{offset}::pg_catalog.int4 AS chunk_offset, "
        f"CASE WHEN total_bytes BETWEEN 2 AND {owned.native_cap} AND total_bytes > {offset} "
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


def _string(text, offset, *, maximum, original_limit, work):
    """Preflight one scalar before allocating it; never decode a JSON graph."""
    _require(offset < len(text) and text[offset] == '"')
    position, size, original_size = offset + 1, 2, 0
    while position < len(text):
        character = text[position]
        if character == '"':
            _require(size <= maximum and (original_limit is None or 2 <= original_size <= original_limit))
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
        original_size += 1
        _require(size <= maximum)
        if original_limit is not None:
            _require(32 <= point <= 126 and original_size <= original_limit)
        position += 1
    raise NativeJitReviewChunkError("Native review text scalar is truncated")


def _flat_row(text, owned, work):
    columns = _COLUMNS[owned.table]
    work.prepare_copy(columns)
    expected = dict(columns)
    original_limits = _ORIGINAL_LIMITS.get(owned.table, {})
    # Exactly the braces, commas and colons. Keys/scalars are charged by their
    # preflight below; no second whole-row measurement/encoding is performed.
    work.charge(input_bytes=2 * len(columns) + 1, json_nodes=1)
    result, size = {}, 2
    position = _space(text, 0)
    _require(position < len(text) and text[position] == "{")
    position = _space(text, position + 1)
    for index in range(len(columns)):
        key, position, key_size = _string(text, position, maximum=256, original_limit=None, work=work)
        _require(key in expected and key not in result)
        position = _space(text, position)
        _require(position < len(text) and text[position] == ":")
        position = _space(text, position + 1)
        _require(position < len(text))
        kind = expected[key]
        size += key_size + 1 + int(index > 0)
        remaining = owned.canonical_cap - size
        _require(remaining >= 2)
        if text.startswith("null", position):
            _require(kind.endswith("?") and remaining >= 4)
            work.charge(input_bytes=4, json_nodes=1)
            value, position, value_size = None, position + 4, 4
        elif kind.startswith("s"):
            value, position, value_size = _string(text, position, maximum=remaining,
                original_limit=original_limits.get(key), work=work)
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
        _require(size <= owned.canonical_cap)
        result[key] = value
        position = _space(text, position)
        ending = "}" if index + 1 == len(columns) else ","
        _require(position < len(text) and text[position] == ending)
        position = _space(text, position + 1)
    _require(position == len(text) and len(result) == len(columns))
    work.prepare_comparison(result[owned.key_column], owned.key_value)
    _require(type(result[owned.key_column]) is type(owned.key_value)
        and result[owned.key_column] == owned.key_value)
    return result, size


class NativeJitReviewRowChunks:
    """One detached source-row reconstruction, not an authorization token."""

    __slots__ = ("_query", "_held", "_chunks", "_total", "_native_bytes", "_data_chunks",
        "_canonical_bytes", "_complete", "_failed", "_finished", "_active")

    def __init__(self, operation, query, *, work):
        self._query = _query(operation, query, work)
        work.charge(input_bytes=32, json_nodes=6)
        self._held = (self._query.operation, self._query.query_id, self._query.table,
            self._query.key_column, self._query.key_value)
        self._chunks, self._total, self._native_bytes, self._data_chunks = [], None, 0, 0
        self._canonical_bytes = None
        self._complete = self._failed = self._finished = self._active = False

    def _local(self):
        _require(not self._failed and type(self._query) is _QueryIdentity
            and all(actual is original for actual, original in zip((self._query.operation,
                self._query.query_id, self._query.table, self._query.key_column,
                self._query.key_value), self._held)))

    @property
    def native_bytes(self):
        self._local()
        return self._native_bytes

    @property
    def data_chunks(self):
        self._local()
        return self._data_chunks

    @property
    def canonical_bytes(self):
        self._local()
        return self._canonical_bytes

    @property
    def complete(self):
        self._local()
        return self._complete

    @property
    def next_ordinal(self):
        self._local()
        return None if self._complete else len(self._chunks)

    def _next_query(self, *, work):
        """Actual-reader seam with no caller table/key/ordinal override."""
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
            _require(ordinal < self._query.chunk_cap)
            if not rows:
                _require(ordinal == 0 and self._total is None)
                work.charge(input_bytes=2, json_nodes=1)
                self._total, self._complete = 0, True
                return
            record = rows[0]
            _require(type(record) is dict and len(record) == 4 and set(record) == _RECORD_FIELDS)
            total, received, offset, raw = (record["total_bytes"], record["chunk_ordinal"],
                record["chunk_offset"], record["chunk_hex"])
            _require(type(total) is int and 2 <= total <= self._query.native_cap
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
                result, canonical_size = None, 4
            else:
                _require(self._total == self._native_bytes and 1 <= len(self._chunks) <= self._query.chunk_cap)
                # Prior hex validation/decoding was paid by the original chunk
                # stages. Here join + strict UTF-8 decode cost 2*native bytes;
                # flat scalar preflights account one complete canonical row.
                work.charge(input_bytes=2 * self._native_bytes, json_nodes=len(self._chunks) + 2)
                native = b"".join(self._chunks)
                _require(len(native) == self._native_bytes)
                text = native.decode("utf-8", "strict")
                result, canonical_size = _flat_row(text, self._query, work)
                _require(self._native_bytes <= canonical_size + 2 * len(_COLUMNS[self._query.table]) - 1)
            self._canonical_bytes = canonical_size
            self._finished = True
            self._chunks.clear()
            return result
        except BaseException:
            self._failed = True
            raise
        finally:
            self._active = False
