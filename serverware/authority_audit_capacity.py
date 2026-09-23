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

from serverware import authority_contract
from serverware import authority_complete_query
from serverware import authority_transition_core as core
from serverware.audit_outbox_contract import MAX_PENDING
from serverware.authority_primary_contract import PRIMARY_KEY_COLUMNS


AGGREGATE_TABLE = "policy_authority_bounded_aggregate_states"
OUTBOX_TABLE = "metadata_audit_outbox"
AGGREGATE_KIND = "metadata-audit-outbox-global-capacity-v1"
PARTITION_DIGEST = core.framed_digest(
    "serverware.metadataAuditOutboxCapacityPartition/v1", b"global"
)
AGGREGATE_ID = f"{AGGREGATE_KIND}:{PARTITION_DIGEST}"
EMPTY_EXPIRY_DIGEST = core.framed_digest(
    "serverware.policyAuthorityAggregateExpiryIndex/v1", b"[]"
)
STATE_SCHEMA = "serverware.policyAuthorityAggregateState/v1"
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


def _canonical(value: Any) -> bytes:
    # The surrounding primary-root profile has the same depth/node limits.
    # Validate before serialization; never accept lossy float/Decimal coercion.
    stack = [(value, 0)]
    nodes = byte_count = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > 128 or nodes > 1_000_000:
            _fail("audit capacity JSON exceeds its structural bound")
        if item is None:
            byte_count += 4
        elif type(item) is bool:
            byte_count += 4 if item else 5
        elif type(item) is int:
            try:
                byte_count += len(str(item))
            except ValueError as exc:
                raise AuditCapacityError("audit capacity JSON integer exceeds its bound") from exc
        elif type(item) is str:
            byte_count += 2
            for character in item:
                scalar = ord(character)
                # PostgreSQL text/JSONB cannot retain NUL; accepting it here
                # would produce a plan that cannot reach the SQL validator.
                if scalar == 0 or 0xD800 <= scalar <= 0xDFFF:
                    _fail("audit capacity JSON is not lossless")
                byte_count += (
                    2 if character in '"\\\b\f\n\r\t' else
                    12 if scalar > 0xFFFF else
                    6 if scalar < 32 or scalar >= 127 else 1
                )
                if byte_count > authority_contract.MAX_RESULT_BYTES:
                    _fail("audit capacity JSON exceeds its byte bound")
        elif type(item) is list:
            if len(item) > 1_000_000 - nodes - len(stack):
                _fail("audit capacity JSON exceeds its structural bound")
            byte_count += 2 + max(0, len(item) - 1)
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is dict:
            if (len(item) > (1_000_000 - nodes - len(stack)) // 2
                    or any(type(key) is not str for key in item)):
                _fail("audit capacity JSON is not lossless")
            byte_count += 2 + max(0, len(item) - 1) + len(item)
            stack.extend((child, depth + 1) for pair in item.items() for child in pair)
        else:
            _fail("audit capacity JSON is not lossless")
        if byte_count > authority_contract.MAX_RESULT_BYTES:
            _fail("audit capacity JSON exceeds its byte bound")
    try:
        result = core.canonical_bytes(value)
    except (core.TransitionKernelError, RecursionError) as exc:
        raise AuditCapacityError("audit capacity JSON is not lossless") from exc
    if len(result) != byte_count:
        _fail("audit capacity JSON byte measurement changed")
    return result


def _copy(value: Any) -> Any:
    return json.loads(_canonical(value))


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


def _key(table: str, key: Any) -> bytes:
    columns = PRIMARY_KEY_COLUMNS.get(table)
    if (columns is None or type(key) is not dict or set(key) != set(columns)
            or any(type(value) not in (str, int, bool) for value in key.values())):
        _fail("audit capacity mutation key is not exact")
    if table == OUTBOX_TABLE and (
            type(key["id"]) is not str or not 1 <= len(key["id"].encode("utf-8")) <= 256):
        _fail("audit capacity outbox identity is not a bounded string")
    return _canonical(key)


def _row_key(row: Any, key: Mapping[str, Any]) -> None:
    if (type(row) is not dict or any(column not in row for column in key)
            or _canonical({column: row[column] for column in key}) != _canonical(dict(key))):
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
    operation: str, selected_rows: Any, mutations: Any
) -> tuple[Mapping[str, Any], dict[tuple[str, bytes], dict[str, Any]], tuple[dict[str, Any], ...]]:
    spec = _spec(operation)
    if (type(selected_rows) not in (list, tuple) or type(mutations) not in (list, tuple)
            or len(selected_rows) > spec["maximumQueryRows"]
            or len(mutations) > spec["maximumMutations"]):
        _fail("audit capacity inventory exceeds its operation bound")
    _canonical([list(selected_rows), list(mutations)])
    # Extra space belongs only to the exact framework address. The row's
    # presence/profile/commitment are checked separately below; aliases never
    # earn a business allowance merely by carrying a matching kind or partition.
    business_selected = [item for item in selected_rows if not _exact_counter_address(item)]
    business_mutations = [item for item in mutations if not _exact_counter_address(item)]
    if (len(business_selected) > spec["maximumBusinessQueryRows"]
            or len(business_mutations) > spec["maximumBusinessMutations"]
            or len(_canonical(business_selected)) > authority_contract.MAX_REQUEST_BYTES
            or len(_canonical(list(selected_rows))) > authority_contract.MAX_PLAN_SELECTED_BYTES):
        _fail("audit capacity inventory exceeds its business bound")
    allowed_reads = set(spec["businessReads"]) | set(spec["businessWrites"]) | set(spec["authorizationReads"])
    selected: dict[tuple[str, bytes], dict[str, Any]] = {}
    for item in selected_rows:
        if (type(item) is not dict or set(item) != _SELECTED_FIELDS
                or type(item["table"]) is not str or item["table"] not in allowed_reads
                or type(item["present"]) is not bool
                or (item["present"] and type(item["row"]) is not dict)
                or (not item["present"] and item["row"] is not None)
                or (item["contractSelector"] is not None and type(item["contractSelector"]) is not str)):
            _fail("audit capacity selected row is not closed")
        key_bytes = _key(item["table"], item["key"])
        address = (item["table"], key_bytes)
        if (address in selected or item["keyDigest"] != core.framed_digest(
                "serverware.policyAuthorityBusinessKey/v1", item["table"].encode("ascii"), key_bytes)):
            _fail("audit capacity selected identity is duplicated or changed")
        if item["present"]:
            _row_key(item["row"], item["key"])
        selected[address] = item
    seen = set()
    for item in mutations:
        if (type(item) is not dict or set(item) != _MUTATION_FIELDS
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
        address = (item["table"], _key(item["table"], item["key"]))
        before = selected.get(address)
        if address in seen or before is None or item["keyDigest"] != before["keyDigest"]:
            _fail("audit capacity mutation has no unique selected identity")
        seen.add(address)
        inserting, deleting = item["operation"] == "INSERT", item["operation"] == "DELETE"
        if (before["present"] is inserting
                or (inserting and item["expectedRow"] is not None)
                or (not inserting and type(item["expectedRow"]) is not dict)
                or _canonical(item["expectedRow"]) != _canonical(before["row"])
                or (deleting and item["row"] is not None)
                or (not deleting and type(item["row"]) is not dict)):
            _fail("audit capacity mutation before or after image changed")
        if not deleting:
            _row_key(item["row"], item["key"])
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


def _counter(selected: Mapping[tuple[str, bytes], dict[str, Any]]) -> dict[str, Any]:
    candidates = [item for item in selected.values()
                  if item["table"] == AGGREGATE_TABLE and _global_identity(item)]
    if len(candidates) != 1:
        _fail("global audit capacity before row is missing or ambiguous")
    item = candidates[0]
    row = item["row"]
    if (item["key"] != {"aggregate_id": AGGREGATE_ID} or item["present"] is not True
            or item["contractSelector"] is not None
            or len(_canonical(item)) > authority_contract.MAX_PLAN_SELECTED_BYTES - authority_contract.MAX_REQUEST_BYTES
            or type(row) is not dict or set(row) != _AGGREGATE_FIELDS
            or len(_canonical(row)) > MAX_COUNTER_BYTES):
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
    state_bytes = _canonical(_state(row))
    if (row["state_json"] != state_bytes.decode("ascii")
            or row["state_digest"] != core.framed_digest(STATE_DOMAIN, state_bytes)):
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


def _after(before: dict[str, Any], delta: int, inserted: int, timestamp: Any) -> dict[str, Any]:
    if not _integer(timestamp) or timestamp < before["updated_at_epoch_ns"]:
        _fail("global audit capacity update time is invalid")
    count = before["live_count"] + delta
    if (not 0 <= count <= MAX_PENDING or before["revision"] == MAX_INTEGER
            or before["next_sequence"] + inserted > MAX_INTEGER):
        _fail("global audit capacity transition exceeds its bound")
    row = {**before, "revision": before["revision"] + 1,
           "live_count": count, "active_count": count,
           "next_sequence": before["next_sequence"] + inserted,
           "updated_at_epoch_ns": timestamp}
    state_bytes = _canonical(_state(row))
    row.update(state_json=state_bytes.decode("ascii"),
               state_digest=core.framed_digest(STATE_DOMAIN, state_bytes))
    if len(_canonical(row)) > MAX_COUNTER_BYTES:
        _fail("global audit capacity row exceeds its byte bound")
    return row


def _parts(mutations: tuple[dict[str, Any], ...]) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    return (
        tuple(item for item in mutations if item["table"] == OUTBOX_TABLE),
        tuple(item for item in mutations if item["table"] == AGGREGATE_TABLE and _global_identity(item)),
    )


def _before_for_operation(
    spec: Mapping[str, Any], selected: Mapping[tuple[str, bytes], dict[str, Any]]
) -> dict[str, Any] | None:
    if _participates(spec):
        _require_counter_permission(spec)
        return _counter(selected)
    if any(item["table"] == AGGREGATE_TABLE and _global_identity(item)
           for item in selected.values()):
        _fail("global audit capacity selection is outside its source operation")
    return None


def finalize_capacity(context: core.KernelContext, mutations: tuple[dict[str, Any], ...]) -> tuple[dict[str, Any], ...]:
    """Append the framework-owned counter CAS before root derivation/signing."""
    spec, selected, entries = _inventory(context.operation, context.selected_rows, mutations)
    before = _before_for_operation(spec, selected)
    outbox, supplied = _parts(entries)
    if supplied:
        _fail("global audit capacity mutation is kernel supplied")
    if not outbox:
        return tuple(_copy(list(entries)))
    if before is None:
        _fail("global audit capacity mutation is outside its source operation")
    instant = context.database_now
    if not isinstance(instant, datetime) or instant.tzinfo is None or instant.utcoffset() is None:
        _fail("global audit capacity producer time is not explicit")
    elapsed = instant.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    timestamp = (elapsed.days * 86400 + elapsed.seconds) * 1_000_000_000 + elapsed.microseconds * 1000
    row = _after(before, *_delta(outbox), timestamp)
    if len(entries) >= spec["maximumMutations"]:
        _fail("audit capacity inventory exceeds its operation bound")
    capacity_selected = selected[(AGGREGATE_TABLE, _canonical({"aggregate_id": AGGREGATE_ID}))]
    counter_mutation = core.mutation(operation=context.operation, selected=capacity_selected, row=row)
    result = (*tuple(_copy(list(entries))), counter_mutation)
    validate_capacity_transition(operation=context.operation, selected_rows=context.selected_rows, mutations=result)
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
    spec, selected, entries = _inventory(operation, selected_rows, mutations)
    before = _before_for_operation(spec, selected)
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
    expected = _after(before, *_delta(outbox), counter["row"].get("updated_at_epoch_ns"))
    if _canonical(counter["row"]) != _canonical(expected):
        _fail("global audit capacity mutation differs from the complete outbox delta")
