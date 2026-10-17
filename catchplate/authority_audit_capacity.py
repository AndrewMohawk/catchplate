"""Pure, compact global audit-capacity transition contract.

This is an inductive OLD/NEW count check, not a proof of the initial population,
root currentness, audit delivery, or permission to perform a business mutation.
The production planner and executor must both enforce it. A missing counter is
never bootstrapped here, and the older policy/quota counters are not reused.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Mapping

from catchplate import authority_contract
from catchplate import authority_complete_query
from catchplate import authority_transition_core as core
from catchplate.audit_outbox_contract import MAX_PENDING
from catchplate.authority_primary_contract import PRIMARY_KEY_COLUMNS
from catchplate.authority_query_read_work import QueryReadWorkError, _ValidationWork


AGGREGATE_TABLE = "policy_authority_bounded_aggregate_states"
OUTBOX_TABLE = "metadata_audit_outbox"
AGGREGATE_KIND = "metadata-audit-outbox-global-capacity-v1"
PARTITION_DIGEST = core.framed_digest(
    "catchplate.metadataAuditOutboxCapacityPartition/v1", b"global"
)
AGGREGATE_ID = f"{AGGREGATE_KIND}:{PARTITION_DIGEST}"
EMPTY_EXPIRY_DIGEST = core.framed_digest(
    "catchplate.policyAuthorityAggregateExpiryIndex/v1", b"[]"
)
STATE_SCHEMA = "catchplate.policyAuthorityAggregateState/v1"
STATE_DOMAIN = STATE_SCHEMA
MAX_INTEGER = 2**63 - 1
# Includes the full row and its embedded canonical state, not the surrounding
# selected-row envelope. Even maximum-width bigint fields fit this fixed bound.
MAX_COUNTER_BYTES = 4096
QUERY_NAME = "global_audit_capacity_before_v1"
_STATUSES = frozenset({"pending", "claimed", "audited"})
_SELECTED_FIELDS = frozenset({
    "table", "key", "keyDigest", "present", "row", "contractSelector",
})
_MUTATION_FIELDS = frozenset({
    "templateId", "operation", "table", "key", "keyDigest", "expectedRow", "row",
})
_AGGREGATE_FIELDS = frozenset({
    "aggregate_id", "aggregate_kind", "partition_digest", "revision",
    "live_count", "active_count", "capacity_limit", "reserved_units_json",
    "committed_units_json", "next_sequence", "minimum_expiry_epoch_ns",
    "expiry_index_root_digest", "work_page_id", "state_json", "state_digest",
    "updated_at_epoch_ns", "source_revision",
})


class AuditCapacityError(core.TransitionKernelError):
    """The supplied transition does not preserve the source capacity contract."""


def _fail(message: str) -> None:
    raise AuditCapacityError(message)


def _require_work(work: _ValidationWork | None) -> None:
    if work is not None and type(work) is not _ValidationWork:
        _fail("audit capacity work is not the exact shared meter")


def _canonical_parts(value: Any, *, work: _ValidationWork | None) -> tuple[bytes, int]:
    # The surrounding primary-root profile has the same depth/node limits.
    # Validate before serialization; never accept lossy float/Decimal coercion.
    # With work, this existing walk is the measurement pass, not a second
    # uncharged walk after work.measure. Fixed traversal scaffolding is not a
    # Python allocation metric; canonical bytes and keys/values are charged.
    _require_work(work)
    stack = [(value, 0)]
    nodes = byte_count = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > 128 or nodes > 1_000_000:
            _fail("audit capacity JSON exceeds its structural bound")
        if work is not None:
            work.charge(json_nodes=1)
        previous_bytes = byte_count
        if item is None:
            byte_count += 4
        elif type(item) is bool:
            byte_count += 4 if item else 5
        elif type(item) is int:
            if work is not None:
                # A necessary decimal-length bound, not a new integer cap.
                # log10(2) > 0.3, so a failing bound cannot reject a fitting
                # encoding. Preserve the legacy str/encoder integer behavior.
                minimum = max(1, (item.bit_length() - 1) * 3 // 10 + 1) + int(item < 0)
                if minimum > work.limits.max_input_bytes - work.input_bytes:
                    raise QueryReadWorkError("audit capacity JSON integer exceeds remaining work")
            try:
                byte_count += len(str(item))
            except ValueError as exc:
                raise AuditCapacityError("audit capacity JSON integer exceeds its bound") from exc
        elif type(item) is str:
            if work is not None and len(item) + 2 > work.limits.max_input_bytes - work.input_bytes:
                raise QueryReadWorkError("audit capacity JSON string exceeds remaining work")
            byte_count += 2
            if work is not None:
                work.charge(input_bytes=2)
            for character in item:
                scalar = ord(character)
                # PostgreSQL text/JSONB cannot retain NUL; accepting it here
                # would produce a plan that cannot reach the SQL validator.
                if scalar == 0 or 0xD800 <= scalar <= 0xDFFF:
                    _fail("audit capacity JSON is not lossless")
                size = (
                    2 if character in '"\\\b\f\n\r\t' else
                    12 if scalar > 0xFFFF else
                    6 if scalar < 32 or scalar >= 127 else 1
                )
                byte_count += size
                if work is not None:
                    work.charge(input_bytes=size)
                if byte_count > authority_contract.MAX_RESULT_BYTES:
                    _fail("audit capacity JSON exceeds its byte bound")
        elif type(item) is list:
            if len(item) > 1_000_000 - nodes - len(stack):
                _fail("audit capacity JSON exceeds its structural bound")
            if (work is not None
                    and len(item) > work.limits.max_json_nodes - work.json_nodes - len(stack)):
                raise QueryReadWorkError("audit capacity JSON exceeds remaining structure work")
            byte_count += 2 + max(0, len(item) - 1)
            if work is not None:
                work.charge(input_bytes=byte_count - previous_bytes)
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is dict:
            if len(item) > (1_000_000 - nodes - len(stack)) // 2:
                _fail("audit capacity JSON is not lossless")
            if (work is not None
                    and len(item) > (work.limits.max_json_nodes - work.json_nodes - len(stack)) // 2):
                raise QueryReadWorkError("audit capacity JSON exceeds remaining structure work")
            if any(type(key) is not str for key in item):
                _fail("audit capacity JSON is not lossless")
            byte_count += 2 + max(0, len(item) - 1) + len(item)
            if work is not None:
                work.charge(input_bytes=byte_count - previous_bytes)
            stack.extend((child, depth + 1) for pair in item.items() for child in pair)
        else:
            _fail("audit capacity JSON is not lossless")
        if byte_count > authority_contract.MAX_RESULT_BYTES:
            _fail("audit capacity JSON exceeds its byte bound")
        if work is not None and type(item) not in (str, list, dict):
            work.charge(input_bytes=byte_count - previous_bytes)
    if work is not None:
        work.charge(input_bytes=byte_count, json_nodes=nodes)
    try:
        result = core.canonical_bytes(value)
    except (core.TransitionKernelError, RecursionError) as exc:
        raise AuditCapacityError("audit capacity JSON is not lossless") from exc
    if len(result) != byte_count:
        _fail("audit capacity JSON byte measurement changed")
    return result, nodes


def _canonical(value: Any, *, work: _ValidationWork | None = None) -> bytes:
    return _canonical_parts(value, work=work)[0]


def _copy(value: Any, *, work: _ValidationWork | None = None) -> Any:
    if work is None:
        return json.loads(_canonical(value))
    encoded, nodes = _canonical_parts(value, work=work)
    # json.loads(bytes) actually decodes before parsing: L/0 plus L/N,
    # in addition to the existing measurement and encoder's 2L/2N.
    work.charge(input_bytes=2 * len(encoded), json_nodes=nodes)
    return json.loads(encoded)


def _canonical_equal(left: Any, right: Any, *, work: _ValidationWork | None) -> bool:
    left_bytes = _canonical(left, work=work)
    right_bytes = _canonical(right, work=work)
    if work is not None:
        work.charge(input_bytes=len(left_bytes) + len(right_bytes))
    return left_bytes == right_bytes


def _decode_state(encoded: bytes, *, work: _ValidationWork | None) -> str:
    if work is not None:
        work.charge(input_bytes=len(encoded))
    return encoded.decode("ascii")


def canonical_audit_json(value: Any) -> bytes:
    """Bound an audit proof's lossless JSON graph before making an owned copy.

    This checks representation and resource limits only, not row semantics,
    signatures, original transport bytes or authority to initialize a counter.
    """
    return _canonical(value)


def _spec(operation: str) -> Mapping[str, Any]:
    if type(operation) is not str:
        _fail("audit capacity operation is not source declared")
    try:
        return authority_contract.operation_spec(operation)
    except ValueError as exc:
        raise AuditCapacityError("audit capacity operation is not source declared") from exc


def _participates(spec: Mapping[str, Any]) -> bool:
    return OUTBOX_TABLE in spec["businessWrites"]


def _require_counter_permission(spec: Mapping[str, Any]) -> None:
    if (AGGREGATE_TABLE not in spec["businessWrites"]
            or "aggregate-high-water" not in spec["proofPrimitives"]
            or not any(template["table"] == AGGREGATE_TABLE
                       and template["mutation"] == "UPDATE"
                       for template in spec["mutationTemplates"])):
        _fail("audit capacity operation lacks the shared counter contract")


def add_capacity_query(
    operation: str, queries: tuple[core.Query, ...]
) -> tuple[core.Query, ...]:
    """Add one source-owned selection, before rows/proofs are read.

    Do not require absence: the global row must exist, including on whole-operation
    replay. Caller aggregate queries must be exact other identities, never a scan
    or deferred selector that could alias this framework-owned row.
    """
    spec = _spec(operation)
    if (type(queries) is not tuple
            or len(queries) > spec["maximumBusinessQueryRows"]
            or any(type(q) not in (core.BoundedQuery, authority_complete_query.CompleteIndexQuery)
                   for q in queries)):
        _fail("audit capacity query inventory is invalid")
    # Revalidate complete declarations before consulting their source-derived
    # table/bounds; a constructed object is not an admission token.
    try:
        queries = tuple(
            authority_complete_query.snapshot_query(query)
            if type(query) is authority_complete_query.CompleteIndexQuery else query
            for query in queries
        )
    except authority_complete_query.CompleteQueryError as exc:
        raise AuditCapacityError("audit capacity complete query declaration is invalid") from exc
    query_id = core.query_program_id(operation, QUERY_NAME, AGGREGATE_TABLE)
    for query in queries:
        if query.query_id == query_id:
            _fail("audit capacity query identity is caller supplied")
        if query.table == AGGREGATE_TABLE and any(
                predicate.column == "aggregate_id" and predicate.value == AGGREGATE_ID
                for predicate in query.predicates):
            _fail("audit capacity query identity is caller supplied")
        if query.table == AGGREGATE_TABLE and _participates(spec):
            if (len(query.predicates) != 1
                    or query.predicates[0].column != "aggregate_id"
                    or query.predicates[0].operator != "eq"
                    or type(query.predicates[0].value) is not str
                    or query.predicates[0].value == AGGREGATE_ID):
                _fail("audit capacity query identity is caller supplied")
    if not _participates(spec):
        return core.close_queries(operation, queries)
    _require_counter_permission(spec)
    if (sum(query.maximum_rows for query in queries) > spec["maximumBusinessQueryRows"]
            or sum(query.work_units for query in queries) > spec["maximumBusinessWorkUnits"]):
        _fail("audit capacity query inventory exceeds its business bound")
    capacity_query = core.BoundedQuery(
        query_id=query_id, table=AGGREGATE_TABLE,
        predicates=(core.QueryPredicate("aggregate_id", "eq", AGGREGATE_ID),),
        order_by=(core.QueryOrder("aggregate_id"),), maximum_rows=1,
        absent_key={"aggregate_id": AGGREGATE_ID},
    )
    return core.close_queries(operation, (*queries, capacity_query))


def _key(table: str, key: Any, *, work: _ValidationWork | None = None) -> bytes:
    columns = PRIMARY_KEY_COLUMNS.get(table)
    if (columns is None or type(key) is not dict or len(key) != len(columns) or set(key) != set(columns)
            or any(type(value) not in (str, int, bool) for value in key.values())):
        _fail("audit capacity mutation key is not exact")
    if work is not None and table == OUTBOX_TABLE and type(key["id"]) is str:
        if not 1 <= len(key["id"]) <= 256:
            _fail("audit capacity outbox identity is not a bounded string")
        work.prepare_utf8(key["id"])
    if table == OUTBOX_TABLE and (
            type(key["id"]) is not str or not 1 <= len(key["id"].encode("utf-8")) <= 256):
        _fail("audit capacity outbox identity is not a bounded string")
    return _canonical(key, work=work)


def _row_key(row: Any, key: Mapping[str, Any], *, work: _ValidationWork | None = None) -> None:
    if type(row) is not dict or any(column not in row for column in key):
        _fail("audit capacity mutation moved its original key")
    if work is not None:
        # Conservative full-row units cover the actual key projection without
        # constructing a separate uncharged projected graph for the meter.
        work.prepare_copy(row)
        work.prepare_copy(key)
    if not _canonical_equal({column: row[column] for column in key}, dict(key), work=work):
        _fail("audit capacity mutation moved its original key")


def _global_identity(value: Mapping[str, Any]) -> bool:
    key = value.get("key")
    if type(key) is dict and key.get("aggregate_id") == AGGREGATE_ID:
        return True
    return any(type(row) is dict and (
        row.get("aggregate_id") == AGGREGATE_ID
        or row.get("aggregate_kind") == AGGREGATE_KIND
        or row.get("partition_digest") == PARTITION_DIGEST
    ) for row in (value.get("expectedRow"), value.get("row")))


def _exact_counter_address(value: Any) -> bool:
    return (type(value) is dict and value.get("table") == AGGREGATE_TABLE
            and value.get("key") == {"aggregate_id": AGGREGATE_ID})


def _inventory(
    operation: str, selected_rows: Any, mutations: Any, *, work: _ValidationWork | None = None,
) -> tuple[Mapping[str, Any], dict[tuple[str, bytes], dict[str, Any]], tuple[dict[str, Any], ...]]:
    if work is not None and (type(operation) is not str or not 1 <= len(operation) <= 128):
        _fail("audit capacity operation is not source declared")
    spec = _spec(operation)
    if (type(selected_rows) not in (list, tuple) or type(mutations) not in (list, tuple)
            or len(selected_rows) > spec["maximumQueryRows"]
            or len(mutations) > spec["maximumMutations"]):
        _fail("audit capacity inventory exceeds its operation bound")
    if work is not None:
        work.prepare_copy(selected_rows)
        work.prepare_copy(mutations)
    _canonical([list(selected_rows), list(mutations)], work=work)
    # Extra space belongs only to the exact framework address. The row's
    # presence/profile/commitment are checked separately below; aliases never
    # earn a business allowance merely by carrying a matching kind or partition.
    if work is not None:
        work.prepare_copy(selected_rows)
        work.prepare_copy(mutations)
    business_selected = [item for item in selected_rows if not _exact_counter_address(item)]
    business_mutations = [item for item in mutations if not _exact_counter_address(item)]
    if (len(business_selected) > spec["maximumBusinessQueryRows"]
            or len(business_mutations) > spec["maximumBusinessMutations"]
            or len(_canonical(business_selected, work=work)) > authority_contract.MAX_REQUEST_BYTES):
        _fail("audit capacity inventory exceeds its business bound")
    if work is not None:
        work.prepare_copy(selected_rows)
    if len(_canonical(list(selected_rows), work=work)) > authority_contract.MAX_PLAN_SELECTED_BYTES:
        _fail("audit capacity inventory exceeds its business bound")
    allowed_reads = set(spec["businessReads"]) | set(spec["businessWrites"]) | set(spec["authorizationReads"])
    selected: dict[tuple[str, bytes], dict[str, Any]] = {}
    for item in selected_rows:
        if (type(item) is not dict or len(item) != len(_SELECTED_FIELDS) or set(item) != _SELECTED_FIELDS
                or type(item["table"]) is not str or item["table"] not in allowed_reads
                or type(item["present"]) is not bool
                or (item["present"] and type(item["row"]) is not dict)
                or (not item["present"] and item["row"] is not None)
                or (item["contractSelector"] is not None and type(item["contractSelector"]) is not str)):
            _fail("audit capacity selected row is not closed")
        key_bytes = _key(item["table"], item["key"], work=work)
        address = (item["table"], key_bytes)
        if address in selected:
            _fail("audit capacity selected identity is duplicated or changed")
        if work is not None:
            work.prepare_utf8(item["table"])
            work.charge(hashes=1)
        key_digest = core.framed_digest(
            "catchplate.policyAuthorityBusinessKey/v1", item["table"].encode("ascii"), key_bytes)
        if work is not None:
            work.prepare_comparison(item["keyDigest"], key_digest)
        if item["keyDigest"] != key_digest:
            _fail("audit capacity selected identity is duplicated or changed")
        if item["present"]:
            _row_key(item["row"], item["key"], work=work)
        selected[address] = item
    seen = set()
    for item in mutations:
        if (type(item) is not dict or len(item) != len(_MUTATION_FIELDS) or set(item) != _MUTATION_FIELDS
                or type(item["table"]) is not str or item["table"] not in spec["businessWrites"]
                or type(item["operation"]) is not str or item["operation"] not in {"INSERT", "UPDATE", "DELETE"}
                or type(item["templateId"]) is not str):
            _fail("audit capacity mutation is not source declared")
        try:
            template = authority_contract.mutation_template(operation, item["templateId"])
        except ValueError as exc:
            raise AuditCapacityError("audit capacity mutation template changed") from exc
        if (template["table"] != item["table"] or template["mutation"] != item["operation"]
                or template["predicate"] != "exact-primary-key-and-full-row-cas-v1"
                or template["cardinality"] != 1):
            _fail("audit capacity mutation template changed")
        address = (item["table"], _key(item["table"], item["key"], work=work))
        before = selected.get(address)
        if address in seen or before is None:
            _fail("audit capacity mutation has no unique selected identity")
        if work is not None:
            work.prepare_comparison(item["keyDigest"], before["keyDigest"])
        if item["keyDigest"] != before["keyDigest"]:
            _fail("audit capacity mutation has no unique selected identity")
        seen.add(address)
        inserting, deleting = item["operation"] == "INSERT", item["operation"] == "DELETE"
        if (before["present"] is inserting
                or (inserting and item["expectedRow"] is not None)
                or (not inserting and type(item["expectedRow"]) is not dict)
                or not _canonical_equal(item["expectedRow"], before["row"], work=work)
                or (deleting and item["row"] is not None)
                or (not deleting and type(item["row"]) is not dict)):
            _fail("audit capacity mutation before or after image changed")
        if not deleting:
            _row_key(item["row"], item["key"], work=work)
    if work is not None and type(mutations) is list:
        work.prepare_copy(mutations)
    return spec, selected, tuple(mutations)


def _state(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": STATE_SCHEMA, "aggregateId": row["aggregate_id"],
        "aggregateKind": row["aggregate_kind"], "partitionDigest": row["partition_digest"],
        "revision": row["revision"], "liveCount": row["live_count"],
        "activeCount": row["active_count"], "capacityLimit": row["capacity_limit"],
        "reservedUnits": {}, "committedUnits": {}, "nextSequence": row["next_sequence"],
        "minimumExpiryEpochNs": None, "expiryIndexRootDigest": EMPTY_EXPIRY_DIGEST,
        "workPageId": None,
    }


def _integer(value: Any, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= MAX_INTEGER


def _counter(selected: Mapping[tuple[str, bytes], dict[str, Any]], *, work: _ValidationWork | None = None) -> dict[str, Any]:
    candidates = [item for item in selected.values()
                  if item["table"] == AGGREGATE_TABLE and _global_identity(item)]
    if len(candidates) != 1:
        _fail("global audit capacity before row is missing or ambiguous")
    item = candidates[0]
    row = item["row"]
    if (item["key"] != {"aggregate_id": AGGREGATE_ID} or item["present"] is not True
            or item["contractSelector"] is not None
            or len(_canonical(item, work=work)) > authority_contract.MAX_PLAN_SELECTED_BYTES - authority_contract.MAX_REQUEST_BYTES
            or type(row) is not dict or len(row) != len(_AGGREGATE_FIELDS) or set(row) != _AGGREGATE_FIELDS
            or len(_canonical(row, work=work)) > MAX_COUNTER_BYTES):
        _fail("global audit capacity before row is not exact")
    if (row["aggregate_id"] != AGGREGATE_ID or row["aggregate_kind"] != AGGREGATE_KIND
            or row["partition_digest"] != PARTITION_DIGEST
            or not _integer(row["revision"], 1)
            or not _integer(row["live_count"]) or not _integer(row["active_count"])
            or not row["live_count"] == row["active_count"] <= MAX_PENDING
            or type(row["capacity_limit"]) is not int or row["capacity_limit"] != MAX_PENDING
            or row["reserved_units_json"] != "{}" or row["committed_units_json"] != "{}"
            or not _integer(row["next_sequence"])
            or row["minimum_expiry_epoch_ns"] is not None or row["work_page_id"] is not None
            or row["expiry_index_root_digest"] != EMPTY_EXPIRY_DIGEST
            or not _integer(row["updated_at_epoch_ns"])
            or row["source_revision"] != authority_contract.SOURCE_REVISION):
        _fail("global audit capacity before state violates its compact profile")
    state_bytes = _canonical(_state(row), work=work)
    state_json = _decode_state(state_bytes, work=work)
    if work is not None:
        work.prepare_comparison(row["state_json"], state_json)
    if row["state_json"] != state_json:
        _fail("global audit capacity before commitment changed")
    if work is not None:
        work.charge(hashes=1)
    state_digest = core.framed_digest(STATE_DOMAIN, state_bytes)
    if work is not None:
        work.prepare_comparison(row["state_digest"], state_digest)
    if row["state_digest"] != state_digest:
        _fail("global audit capacity before commitment changed")
    return row


def _counted(row: dict[str, Any] | None) -> int:
    if row is None:
        return 0
    status = row.get("status")
    if type(status) is not str or status not in _STATUSES:
        _fail("audit capacity outbox status is invalid")
    return int(status in {"pending", "claimed"})


def _delta(mutations: tuple[dict[str, Any], ...]) -> tuple[int, int]:
    delta = inserted = 0
    for item in mutations:
        before, after = item["expectedRow"], item["row"]
        old_count, new_count = _counted(before), _counted(after)
        if item["operation"] == "INSERT" and after["status"] != "pending":
            _fail("audit capacity fresh outbox must be pending")
        if before is not None and before["status"] == "audited" and new_count:
            _fail("audit capacity cannot reopen a terminal outbox")
        delta += new_count - old_count
        inserted += int(item["operation"] == "INSERT") * new_count
    return delta, inserted


def _after(before: dict[str, Any], delta: int, inserted: int, timestamp: Any, *, work: _ValidationWork | None = None) -> dict[str, Any]:
    if not _integer(timestamp) or timestamp < before["updated_at_epoch_ns"]:
        _fail("global audit capacity update time is invalid")
    count = before["live_count"] + delta
    if (not 0 <= count <= MAX_PENDING or before["revision"] == MAX_INTEGER
            or before["next_sequence"] + inserted > MAX_INTEGER):
        _fail("global audit capacity transition exceeds its bound")
    if work is not None:
        work.prepare_copy(before)
    row = {**before, "revision": before["revision"] + 1,
           "live_count": count, "active_count": count,
           "next_sequence": before["next_sequence"] + inserted,
           "updated_at_epoch_ns": timestamp}
    state_bytes = _canonical(_state(row), work=work)
    state_json = _decode_state(state_bytes, work=work)
    if work is not None:
        work.charge(hashes=1)
    row.update(state_json=state_json, state_digest=core.framed_digest(STATE_DOMAIN, state_bytes))
    if len(_canonical(row, work=work)) > MAX_COUNTER_BYTES:
        _fail("global audit capacity row exceeds its byte bound")
    return row


def _parts(mutations: tuple[dict[str, Any], ...]) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    return (
        tuple(item for item in mutations if item["table"] == OUTBOX_TABLE),
        tuple(item for item in mutations if item["table"] == AGGREGATE_TABLE and _global_identity(item)),
    )


def _before_for_operation(
    spec: Mapping[str, Any], selected: Mapping[tuple[str, bytes], dict[str, Any]],
    *, work: _ValidationWork | None = None,
) -> dict[str, Any] | None:
    if _participates(spec):
        _require_counter_permission(spec)
        return _counter(selected, work=work)
    if any(item["table"] == AGGREGATE_TABLE and _global_identity(item)
           for item in selected.values()):
        _fail("global audit capacity selection is outside its source operation")
    return None


def finalize_capacity(context: core.KernelContext, mutations: tuple[dict[str, Any], ...]) -> tuple[dict[str, Any], ...]:
    """Append the framework-owned counter CAS before root derivation/signing."""
    return _finalize_capacity(context, mutations, work=None)


def _copied_entries(entries: tuple[dict[str, Any], ...], *, work: _ValidationWork | None) -> tuple[dict[str, Any], ...]:
    if work is not None:
        work.prepare_copy(entries)
    copied = _copy(list(entries), work=work)
    if work is not None:
        work.prepare_copy(copied)
    return tuple(copied)


def _finalize_capacity(
    context: core.KernelContext, mutations: tuple[dict[str, Any], ...], *, work: _ValidationWork | None,
) -> tuple[dict[str, Any], ...]:
    """Actual finalizer with optional cumulative accounting, not input ownership.

    A measured composer must first own the context/row/mutation graphs and pass
    its one shared exact work object. Shared-meter validation and exhaustion
    propagate unchanged; capacity-contract failures remain AuditCapacityError.
    No counter is initialized here, and a measured result is not an admission token.
    """
    _require_work(work)
    spec, selected, entries = _inventory(context.operation, context.selected_rows, mutations, work=work)
    before = _before_for_operation(spec, selected, work=work)
    outbox, supplied = _parts(entries)
    if supplied:
        _fail("global audit capacity mutation is kernel supplied")
    if not outbox:
        return _copied_entries(entries, work=work)
    if before is None:
        _fail("global audit capacity mutation is outside its source operation")
    instant = context.database_now
    if not isinstance(instant, datetime) or instant.tzinfo is None or instant.utcoffset() is None:
        _fail("global audit capacity producer time is not explicit")
    elapsed = instant.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    timestamp = (elapsed.days * 86400 + elapsed.seconds) * 1_000_000_000 + elapsed.microseconds * 1000
    row = _after(before, *_delta(outbox), timestamp, work=work)
    if len(entries) >= spec["maximumMutations"]:
        _fail("audit capacity inventory exceeds its operation bound")
    capacity_selected = selected[(AGGREGATE_TABLE, _canonical({"aggregate_id": AGGREGATE_ID}, work=work))]
    if work is not None:
        # These are the three actual dict copies in core.mutation; retain its
        # real source-template body rather than synthesize a second recipe.
        work.prepare_copy(capacity_selected["key"])
        work.prepare_copy(capacity_selected["row"])
        work.prepare_copy(row)
    counter_mutation = core.mutation(operation=context.operation, selected=capacity_selected, row=row)
    business_entries = _copied_entries(entries, work=work)
    if work is not None:
        work.prepare_copy(business_entries)
        work.prepare_copy(counter_mutation)
    result = (*business_entries, counter_mutation)
    if work is None:
        # Preserve the public named observer route for existing callers.
        validate_capacity_transition(operation=context.operation, selected_rows=context.selected_rows, mutations=result)
    else:
        _validate_capacity_transition(operation=context.operation, selected_rows=context.selected_rows,
                                      mutations=result, work=work)
    return result


def _framework_work(operation: str, mutations: Any) -> tuple[Mapping[str, Any], int, int]:
    spec = _spec(operation)
    if (type(mutations) not in (list, tuple)
            or any(type(item) is not dict for item in mutations)):
        _fail("audit capacity work inventory is not exact")
    participates = _participates(spec)
    touches_outbox = any(item.get("table") == OUTBOX_TABLE for item in mutations)
    if touches_outbox and not participates:
        _fail("audit capacity work is outside its source operation")
    return (
        spec,
        authority_contract.AUDIT_CAPACITY_QUERY_WORK_UNITS if participates else 0,
        authority_contract.AUDIT_CAPACITY_MUTATION_WORK_UNITS if touches_outbox else 0,
    )


def validate_transition_work_units(operation: str, work_units: Any, mutations: Any) -> None:
    """Bound the signed total using only the framework work actually present.

    This is not proof of kernel execution cost. The measured producer separately
    computes business query plus kernel work and independently signs that total.
    """
    spec, query_work, mutation_work = _framework_work(operation, mutations)
    if (type(work_units) is not int
            or not 1 + query_work + mutation_work <= work_units
                <= spec["maximumBusinessWorkUnits"] + query_work + mutation_work):
        _fail("audit capacity transition work exceeds its business/framework bound")


def transition_work_units(
    operation: str, query_work_units: Any, kernel_work_units: Any, mutations: Any,
) -> int:
    """Charge one composed query and, only when present, one counter mutation."""
    spec, query_work, mutation_work = _framework_work(operation, mutations)
    if (type(query_work_units) is not int or query_work_units < query_work
            or type(kernel_work_units) is not int or kernel_work_units < 1
            or query_work_units - query_work + kernel_work_units > spec["maximumBusinessWorkUnits"]):
        _fail("audit capacity transition work exceeds its business/framework bound")
    total = query_work_units + kernel_work_units + mutation_work
    validate_transition_work_units(operation, total, mutations)
    return total


def validate_capacity_transition(*, operation: str, selected_rows: Any, mutations: Any) -> None:
    """Independently rederive the exact counter CAS; supplied time is not trusted time."""
    return _validate_capacity_transition(operation=operation, selected_rows=selected_rows,
                                         mutations=mutations, work=None)


def _validate_capacity_transition(
    *, operation: str, selected_rows: Any, mutations: Any, work: _ValidationWork | None,
) -> None:
    """The genuine validator; measured callers retain ownership responsibility."""
    _require_work(work)
    spec, selected, entries = _inventory(operation, selected_rows, mutations, work=work)
    before = _before_for_operation(spec, selected, work=work)
    outbox, counters = _parts(entries)
    if not outbox:
        if counters:
            _fail("global audit capacity mutation has no outbox mutations")
        return
    if before is None:
        _fail("global audit capacity mutation is outside its source operation")
    if len(counters) != 1:
        _fail("global audit capacity mutation is missing or duplicated")
    counter = counters[0]
    if (counter["operation"] != "UPDATE" or counter["key"] != {"aggregate_id": AGGREGATE_ID}
            or type(counter["row"]) is not dict):
        _fail("global audit capacity mutation identity changed")
    expected = _after(before, *_delta(outbox), counter["row"].get("updated_at_epoch_ns"), work=work)
    if not _canonical_equal(counter["row"], expected, work=work):
        _fail("global audit capacity mutation differs from the complete outbox delta")
