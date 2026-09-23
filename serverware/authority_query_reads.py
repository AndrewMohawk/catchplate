"""Bounded immutable bookkeeping for observations of source query programs.

Records retain what was selected, including empty queries and exact-absence
placeholders. They prove neither SQL predicate completeness nor primary
membership, currentness, authorization or an admitted clock. No consumer may
substitute these data objects for actual proofs. The planner independently
verifies primary inputs and revalidates these associations before its kernel.

Imports of core and the primary-key inventory are deliberately lazy: core uses
these record types. No database facade, transition registry or transport parser
is imported. Canonical bytes below are produced from owned source values, not
decoded from a caller's claimed successful observation.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, fields
from typing import Any

from serverware import authority_contract
from serverware import authority_complete_query


MAX_BOOKKEEPING_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 128
MAX_JSON_NODES = 1_000_000
MAX_QUERY_ID_BYTES = 1024
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SELECTED_FIELDS = frozenset({"table", "key", "keyDigest", "present", "row", "contractSelector"})


class QueryReadError(ValueError):
    pass


def _core():
    from serverware import authority_transition_core
    return authority_transition_core


def _keys():
    from serverware.authority_primary_contract import PRIMARY_KEY_COLUMNS
    return PRIMARY_KEY_COLUMNS


def _spec(operation: str) -> dict[str, Any]:
    if type(operation) is not str:
        raise QueryReadError("query read operation is not an exact string")
    try:
        return authority_contract.operation_spec(operation)
    except ValueError as exc:
        raise QueryReadError("query read operation is not source admitted") from exc


def _identifier(value: Any) -> None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise QueryReadError("query read table or column is not an exact identifier")


def _query_id(value: Any) -> None:
    if (type(value) is not str or not value.isascii() or len(value) > MAX_QUERY_ID_BYTES
            or not value.startswith("serverware.policyAuthorityQuery/")):
        raise QueryReadError("query read identity is not a bounded exact identifier")


def _wire(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                          separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise QueryReadError("query read value is not canonical lossless JSON") from exc


class _CopyBudget:
    """Bound source-value copies without copying unreferenced full rows.

    Scalar accounting is conservative canonical ASCII JSON; each collection
    element is charged an extra separator byte. This is a finite copy profile,
    not the later retained-record metric or an external parser guarantee.
    """
    def __init__(self) -> None:
        self.bytes = 0
        self.nodes = 0

    def charge(self, count: int) -> None:
        self.bytes += count
        if self.bytes > MAX_BOOKKEEPING_BYTES:
            raise QueryReadError("query source copy byte budget exceeded")

    def copy(self, value: Any, depth: int = 0, ancestors: frozenset[int] = frozenset()) -> Any:
        self.nodes += 1
        if self.nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise QueryReadError("query source copy structure budget exceeded")
        kind = type(value)
        if value is None or kind is bool:
            self.charge(len(_wire(value)))
            return value
        if kind is int:
            # Fixed source SQL values are integral. Avoid floats, Decimal or
            # datetime coercions; integer conversion itself remains bounded.
            if value.bit_length() > 16384:
                raise QueryReadError("query integer encoding exceeds its bound")
            self.charge(len(_wire(value)))
            return value
        if kind is str:
            if len(value) > MAX_BOOKKEEPING_BYTES or "\x00" in value:
                raise QueryReadError("query text is not bounded NUL-free JSON")
            size = 2
            for character in value:
                point = ord(character)
                if 0xD800 <= point <= 0xDFFF:
                    raise QueryReadError("query text is not valid Unicode UTF-8")
                size += (2 if character in '"\\\b\f\n\r\t' else
                         6 if point < 32 or 127 <= point <= 0xFFFF else
                         12 if point > 0xFFFF else 1)
                if size > MAX_BOOKKEEPING_BYTES - self.bytes:
                    raise QueryReadError("query source copy byte budget exceeded")
            self.charge(size)
            return value
        if kind not in (dict, list, tuple):
            raise QueryReadError("query values require exact lossless JSON types")
        if id(value) in ancestors:
            raise QueryReadError("query source values contain a cycle")
        if len(value) > MAX_JSON_NODES - self.nodes:
            raise QueryReadError("query source copy structure budget exceeded")
        self.charge(2 + len(value))
        path = ancestors | {id(value)}
        if kind is dict:
            result = {}
            for key, child in value.items():
                if type(key) is not str:
                    raise QueryReadError("query JSON object key is not an exact string")
                self.charge(1)
                result[self.copy(key, depth + 1, path)] = self.copy(child, depth + 1, path)
            return result
        items = [self.copy(child, depth + 1, path) for child in value]
        return tuple(items) if kind is tuple else items


def _bytes(value: Any) -> None:
    if type(value) is not bytes or not 2 <= len(value) <= MAX_BOOKKEEPING_BYTES or not value.isascii():
        raise QueryReadError("query read canonical bytes are not bounded exact ASCII bytes")


@dataclass(frozen=True, slots=True)
class QueryReadAddress:
    table: str
    key_json: bytes
    key_digest: str
    present: bool

    def __post_init__(self) -> None:
        _identifier(self.table)
        _bytes(self.key_json)
        if type(self.key_digest) is not str or _DIGEST.fullmatch(self.key_digest) is None:
            raise QueryReadError("query read key digest is not canonical SHA-256")
        if type(self.present) is not bool:
            raise QueryReadError("query read presence is not an exact boolean")


@dataclass(frozen=True, slots=True)
class QueryRead:
    query_id: str
    declared_query_json: bytes
    resolved_query_json: bytes
    addresses: tuple[QueryReadAddress, ...]
    returned_row_count: int

    def __post_init__(self) -> None:
        _query_id(self.query_id)
        _bytes(self.declared_query_json)
        _bytes(self.resolved_query_json)
        if (type(self.addresses) is not tuple or len(self.addresses) > authority_contract.MAX_PLAN_QUERY_ROWS
                or any(type(address) is not QueryReadAddress for address in self.addresses)
                or type(self.returned_row_count) is not int
                or not 0 <= self.returned_row_count <= authority_contract.MAX_PLAN_QUERY_ROWS):
            raise QueryReadError("query read address inventory or row count is invalid")


def _fresh(value: Any, expected: type) -> Any:
    if type(value) is not expected:
        raise QueryReadError("query read record has an unexpected exact type")
    try:
        return expected(**{field.name: getattr(value, field.name) for field in fields(expected)})
    except AttributeError as exc:
        raise QueryReadError("query read record is incomplete") from exc


def _copy_read(value: Any) -> QueryRead:
    record = _fresh(value, QueryRead)
    return QueryRead(record.query_id, record.declared_query_json, record.resolved_query_json,
                     tuple(_fresh(address, QueryReadAddress) for address in record.addresses),
                     record.returned_row_count)


def _read_size(record: QueryRead) -> int:
    return (8 + len(record.query_id) + 8 + len(record.declared_query_json)
            + 8 + len(record.resolved_query_json) + 8 + len(str(record.returned_row_count))
            + sum(8 + len(item.table) + 8 + len(item.key_json) + 8 + len(item.key_digest) + 9
                  for item in record.addresses))


def validate_read_budget(operation: str, *, query_reads: tuple[QueryRead, ...]) -> None:
    """Cheap immutable-record count/byte admission, not row serialization."""
    maximum = _spec(operation)["maximumQueryRows"]
    if type(query_reads) is not tuple or len(query_reads) > maximum:
        raise QueryReadError("query read count exceeds its source operation")
    total_bytes = total_addresses = total_returned = 0
    identifiers = set()
    for value in query_reads:
        record = _copy_read(value)
        if (not record.query_id.startswith(f"serverware.policyAuthorityQuery/{operation}/")
                or record.query_id in identifiers):
            raise QueryReadError("query read identity is duplicated or outside its operation")
        identifiers.add(record.query_id)
        total_bytes += _read_size(record)
        total_addresses += len(record.addresses)
        total_returned += record.returned_row_count
        if (total_bytes > MAX_BOOKKEEPING_BYTES or total_addresses > maximum
                or total_returned > maximum):
            raise QueryReadError("query read aggregate bookkeeping budget exceeded")


def _query_copy(query: Any, budget: _CopyBudget) -> Any:
    core = _core()
    if type(query) is authority_complete_query.CompleteIndexQuery:
        try:
            owned = authority_complete_query.snapshot_query(query)
            budget.charge(len(_wire(owned.contract_value())))
            return owned
        except authority_complete_query.CompleteQueryError as exc:
            raise QueryReadError("complete query source snapshot is invalid") from exc
    if type(query) is not core.BoundedQuery:
        raise QueryReadError("query program requires an exact admitted declaration kind")
    try:
        values = {field.name: getattr(query, field.name) for field in fields(core.BoundedQuery)}
        _query_id(values["query_id"])
        _identifier(values["table"])
        predicates, ordering = values["predicates"], values["order_by"]
        if (type(predicates) is not tuple or len(predicates) > core.MAX_QUERY_PREDICATES
                or type(ordering) is not tuple or len(ordering) > core.MAX_QUERY_ORDER_COLUMNS):
            raise QueryReadError("query program predicate or order inventory is invalid")

        def value_copy(value):
            if type(value) is core.SelectedRowFieldReference:
                _identifier(value.table)
                _identifier(value.column)
                return core.SelectedRowFieldReference(value.table, budget.copy(value.key), value.column)
            return budget.copy(value)

        fresh_predicates = []
        for predicate in predicates:
            if type(predicate) is not core.QueryPredicate:
                raise QueryReadError("query predicate is not an exact source value")
            _identifier(predicate.column)
            if type(predicate.operator) is not str:
                raise QueryReadError("query predicate operator is not an exact string")
            fresh_predicates.append(core.QueryPredicate(predicate.column, predicate.operator, value_copy(predicate.value)))
        fresh_ordering = []
        for item in ordering:
            if type(item) is not core.QueryOrder or type(item.descending) is not bool:
                raise QueryReadError("query order is not an exact source value")
            _identifier(item.column)
            fresh_ordering.append(core.QueryOrder(item.column, item.descending))
        absent = values["absent_key"]
        if absent is not None:
            if (type(absent) is not dict or not absent
                    or len(absent) > core.MAX_QUERY_PREDICATES):
                raise QueryReadError("query absence key is not an exact source dictionary")
            for name in absent:
                _identifier(name)
                budget.copy(name)
            absent = {name: value_copy(value) for name, value in absent.items()}
        values.update(predicates=tuple(fresh_predicates), order_by=tuple(fresh_ordering), absent_key=absent)
        for name in ("maximum_rows", "work_units"):
            if type(values[name]) is not int:
                raise QueryReadError("query program counter is not an exact integer")
        for name in ("require_absence", "exact_page"):
            if type(values[name]) is not bool:
                raise QueryReadError("query program flag is not an exact boolean")
        if type(values["proof_primitive"]) is not str:
            raise QueryReadError("query proof primitive is not an exact string")
        for name in ("secondary_index_name", "continuation_token_digest"):
            if values[name] is not None and type(values[name]) is not str:
                raise QueryReadError("query optional identity is not an exact string")
        result = core.BoundedQuery(**values)
        budget.charge(len(_wire(result.contract_value())))
        return result
    except (AttributeError, TypeError, ValueError, core.TransitionKernelError) as exc:
        if isinstance(exc, QueryReadError):
            raise
        raise QueryReadError("query program source snapshot is invalid") from exc


def snapshot_queries(operation: str, queries: tuple[Any, ...]) -> tuple[Any, ...]:
    """Own source query values before SQL; returned models are private data.

    Nested dictionaries are detached, not frozen. The immutable retained form
    is QueryRead's canonical bytes. No SQL parameter is string-coerced.
    """
    spec = _spec(operation)
    if type(queries) is not tuple or len(queries) > spec["maximumQueryRows"]:
        raise QueryReadError("query program count exceeds its source operation")
    budget = _CopyBudget()
    owned = tuple(_query_copy(query, budget) for query in queries)
    try:
        _core().close_queries(operation, owned)
    except _core().TransitionKernelError as exc:
        raise QueryReadError("query program differs from its source operation") from exc
    return owned


def _key_bytes(table: str, key: Any, budget: _CopyBudget | None = None) -> bytes:
    columns = _keys().get(table)
    if (columns is None or type(key) is not dict or len(key) != len(columns) or set(key) != set(columns)
            or any(type(value) not in (str, int, bool) for value in key.values())):
        raise QueryReadError("query read key does not match source primary columns")
    return _wire((budget if budget is not None else _CopyBudget()).copy(key))


def _key_digest(table: str, key_json: bytes) -> str:
    digest = hashlib.sha256(b"serverware.policyAuthorityBusinessKey/v1\x00")
    for frame in (table.encode("ascii"), key_json):
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


def _address(selected: Any, budget: _CopyBudget) -> QueryReadAddress:
    if (type(selected) is not dict or len(selected) != len(_SELECTED_FIELDS) or set(selected) != _SELECTED_FIELDS
            or type(selected["table"]) is not str or type(selected["present"]) is not bool
            or (selected["present"] and type(selected["row"]) is not dict)
            or (not selected["present"] and selected["row"] is not None)
            or (selected["contractSelector"] is not None and type(selected["contractSelector"]) is not str)):
        raise QueryReadError("query selected row wrapper is not closed")
    _identifier(selected["table"])
    key_json = _key_bytes(selected["table"], selected["key"], budget)
    digest = _key_digest(selected["table"], key_json)
    if type(selected["keyDigest"]) is not str or selected["keyDigest"] != digest:
        raise QueryReadError("query selected row business-key digest changed")
    if selected["present"]:
        columns = _keys()[selected["table"]]
        row = selected["row"]
        if any(column not in row for column in columns) or _key_bytes(
                selected["table"], {column: row[column] for column in columns}, budget) != key_json:
            raise QueryReadError("query selected row omits or changes its original key")
    return QueryReadAddress(selected["table"], key_json, digest, selected["present"])


def _selection_map(operation: str, selected_rows: tuple[dict[str, Any], ...]):
    spec = _spec(operation)
    allowed = set(spec["businessReads"]) | set(spec["businessWrites"]) | set(spec["authorizationReads"])
    if type(selected_rows) is not tuple or len(selected_rows) > spec["maximumQueryRows"]:
        raise QueryReadError("query global selected inventory exceeds its source operation")
    result = {}
    budget = _CopyBudget()
    for row in selected_rows:
        address = _address(row, budget)
        identity = (address.table, address.key_json)
        if address.table not in allowed or identity in result:
            raise QueryReadError("query global selected identity is duplicated or outside its operation")
        result[identity] = (address, row)
    return result


def _associations(records: tuple[QueryRead, ...], selections):
    seen = set()
    for record in records:
        local = set()
        for address in record.addresses:
            identity = (address.table, address.key_json)
            entry = selections.get(identity)
            if identity in local or entry is None or entry[0] != address:
                raise QueryReadError("query address is duplicated, missing or conflicts with global selection")
            local.add(identity)
            seen.add(identity)
        if record.returned_row_count:
            if record.returned_row_count != len(record.addresses) or any(not a.present for a in record.addresses):
                raise QueryReadError("query returned-row count differs from its present addresses")
        elif len(record.addresses) > 1 or any(a.present for a in record.addresses):
            raise QueryReadError("empty query observation is not empty or exact absence")
    return seen


def reference_source_rows(operation: str, query: Any, *, prior_reads: tuple[QueryRead, ...],
                          selected_rows: tuple[dict[str, Any], ...]) -> tuple[dict[str, Any], ...]:
    """Select prior observed source rows for staging, without reading their values.

    This validates source query shape, address associations and field presence,
    not primary membership or authority. The original selected wrappers are
    returned in stable table/BusinessKey-digest/key-byte order. Address/key
    checks may inspect primary-key columns; requested fields are not resolved
    or copied as query parameter values here.
    A caller must genuinely verify these rows before calling resolve_query.
    """
    owned = snapshot_queries(operation, (query,))[0]
    validate_read_budget(operation, query_reads=prior_reads)
    records = tuple(_copy_read(record) for record in prior_reads)
    if any(record.query_id == owned.query_id for record in records):
        raise QueryReadError("query reference source inventory includes the current query")
    selections = _selection_map(operation, selected_rows)
    available = _associations(records, selections)
    # The initial complete roles bind only request literals, fixed source enums
    # and an explicit supplied cutoff. They contain no deferred row references.
    if type(owned) is authority_complete_query.CompleteIndexQuery:
        return ()
    core = _core()
    budget = _CopyBudget()
    sources = {}

    def include(value):
        if type(value) is not core.SelectedRowFieldReference:
            return
        key_json = _key_bytes(value.table, value.key, budget)
        identity = (value.table, key_json)
        entry = selections.get(identity)
        if (identity not in available or entry is None or not entry[0].present
                or value.column not in entry[1]["row"]):
            raise QueryReadError("query row-field reference is not an earlier present selected field")
        sources[identity] = entry[1]

    for predicate in owned.predicates:
        include(predicate.value)
    if owned.absent_key is not None:
        for value in owned.absent_key.values():
            include(value)
    return tuple(sources[identity] for identity in sorted(
        sources, key=lambda identity: (identity[0], sources[identity]["keyDigest"], identity[1]),
    ))


def _resolve(query, prior_reads: tuple[QueryRead, ...], selections):
    core = _core()
    available = _associations(prior_reads, selections)
    if type(query) is authority_complete_query.CompleteIndexQuery:
        # Do not synthesize legacy primary-key ORDER BY or SQL predicates for
        # an index declaration. This is bookkeeping, not completeness admission.
        return authority_complete_query.snapshot_query(query)
    budget = _CopyBudget()

    def resolve(value):
        if type(value) is not core.SelectedRowFieldReference:
            return budget.copy(value)
        key_json = _key_bytes(value.table, value.key, budget)
        identity = (value.table, key_json)
        entry = selections.get(identity)
        if (identity not in available or entry is None or not entry[0].present
                or value.column not in entry[1]["row"]):
            raise QueryReadError("query row-field reference is not an earlier present selected field")
        return budget.copy(entry[1]["row"][value.column])

    try:
        values = {field.name: getattr(query, field.name) for field in fields(core.BoundedQuery)}
        values["predicates"] = tuple(core.QueryPredicate(item.column, item.operator, resolve(item.value))
                                     for item in query.predicates)
        values["absent_key"] = (None if query.absent_key is None else
                                {name: resolve(value) for name, value in query.absent_key.items()})
        values["order_by"] = query.order_by or tuple(core.QueryOrder(column) for column in _keys()[query.table])
        return core.BoundedQuery(**values)
    except (KeyError, TypeError, ValueError, core.TransitionKernelError) as exc:
        if isinstance(exc, QueryReadError):
            raise
        raise QueryReadError("query resolution is outside its source definition") from exc


def resolve_query(operation: str, query: Any, *, prior_reads: tuple[QueryRead, ...],
                  selected_rows: tuple[dict[str, Any], ...]):
    owned = snapshot_queries(operation, (query,))[0]
    validate_read_budget(operation, query_reads=prior_reads)
    records = tuple(_copy_read(record) for record in prior_reads)
    return _resolve(owned, records, _selection_map(operation, selected_rows))


def _resolution_shape(query, resolved) -> None:
    core = _core()
    if (type(query) is authority_complete_query.CompleteIndexQuery
            or type(resolved) is authority_complete_query.CompleteIndexQuery):
        if (type(query) is not authority_complete_query.CompleteIndexQuery
                or type(resolved) is not authority_complete_query.CompleteIndexQuery
                or _wire(query.contract_value()) != _wire(resolved.contract_value())):
            raise QueryReadError("complete query resolution changed its bound declaration")
        return
    expected, actual = query.contract_value(), resolved.contract_value()
    expected["orderBy"] = [{"column": item.column, "descending": item.descending}
                           for item in (query.order_by or tuple(core.QueryOrder(c) for c in _keys()[query.table]))]
    if len(query.predicates) != len(resolved.predicates):
        raise QueryReadError("query resolved predicate inventory changed")
    for ordinal, (before, after) in enumerate(zip(query.predicates, resolved.predicates)):
        if type(after.value) is core.SelectedRowFieldReference:
            raise QueryReadError("query resolved definition still has a row-field reference")
        if type(before.value) is core.SelectedRowFieldReference:
            expected["predicates"][ordinal]["value"] = after.value
    if query.absent_key is not None:
        if resolved.absent_key is None or set(query.absent_key) != set(resolved.absent_key):
            raise QueryReadError("query resolved absence key changed")
        for name, value in query.absent_key.items():
            after = resolved.absent_key[name]
            if type(after) is core.SelectedRowFieldReference:
                raise QueryReadError("query resolved absence key still has a reference")
            if type(value) is core.SelectedRowFieldReference:
                expected["absentKey"][name] = after
    if _wire(expected) != _wire(actual):
        raise QueryReadError("query resolution changed non-reference source fields")


def _capture(query, resolved, ordered_selected_rows, returned_row_count) -> QueryRead:
    _resolution_shape(query, resolved)
    complete = type(query) is authority_complete_query.CompleteIndexQuery
    require_absence = False if complete else query.require_absence
    absent_key = None if complete else resolved.absent_key
    if type(ordered_selected_rows) is not tuple or len(ordered_selected_rows) > query.maximum_rows:
        raise QueryReadError("query observed address count exceeds its declared bound")
    if type(returned_row_count) is not int or not 0 <= returned_row_count <= query.maximum_rows:
        raise QueryReadError("query observed row count exceeds its declared bound")
    budget = _CopyBudget()
    declared_json = _wire(query.contract_value())
    budget.charge(len(declared_json))
    resolved_json = _wire(resolved.contract_value())
    budget.charge(len(resolved_json))
    addresses = tuple(_address(row, budget) for row in ordered_selected_rows)
    if any(address.table != query.table for address in addresses):
        raise QueryReadError("query observed address crossed its source table")
    if len({(item.table, item.key_json) for item in addresses}) != len(addresses):
        raise QueryReadError("query observed address is duplicated")
    if returned_row_count:
        if (require_absence or returned_row_count != len(addresses)
                or any(not item.present for item in addresses)):
            raise QueryReadError("query returned rows differ from its observed presence")
    elif absent_key is None:
        if addresses:
            raise QueryReadError("ordinary empty query cannot invent an absence address")
    elif (len(addresses) != 1 or addresses[0].present
          or addresses[0].key_json != _key_bytes(query.table, absent_key, budget)):
        raise QueryReadError("exact-absence query lost its resolved absent address")
    return QueryRead(query.query_id, declared_json, resolved_json,
                     addresses, returned_row_count)


def capture_query_read(operation: str, query: Any, *, resolved_query: Any,
                       ordered_selected_rows: tuple[dict[str, Any], ...], returned_row_count: int) -> QueryRead:
    """Capture actual ordered selection wrappers; final validation replays refs."""
    owned = snapshot_queries(operation, (query,))[0]
    resolved = snapshot_queries(operation, (resolved_query,))[0]
    record = _capture(owned, resolved, ordered_selected_rows, returned_row_count)
    validate_read_budget(operation, query_reads=(record,))
    return record


def validate_query_reads(operation: str, *, queries: tuple[Any, ...], query_reads: tuple[QueryRead, ...],
                         selected_rows: tuple[dict[str, Any], ...]) -> tuple[QueryRead, ...]:
    """Rebind all observations to source definitions and the exact global union.

    Global full rows are not copied or serialized: only original primary keys
    and fields actually used by a source reference are read. Primary proof
    verification and the reader's conflicting full-row guard remain separate.
    """
    owned = snapshot_queries(operation, queries)
    validate_read_budget(operation, query_reads=query_reads)
    if len(owned) != len(query_reads):
        raise QueryReadError("query read inventory omits or adds a declared query")
    records = tuple(_copy_read(record) for record in query_reads)
    selections = _selection_map(operation, selected_rows)
    _associations(records, selections)
    checked = []
    for query, record in zip(owned, records):
        resolved = _resolve(query, tuple(checked), selections)
        ordered = tuple(selections[(address.table, address.key_json)][1] for address in record.addresses)
        expected = _capture(query, resolved, ordered, record.returned_row_count)
        if expected != record:
            raise QueryReadError("query observation differs from its source definition or resolved fields")
        checked.append(expected)
    if _associations(tuple(checked), selections) != set(selections):
        raise QueryReadError("query read inventory does not exactly cover the global selection")
    return tuple(checked)


def query_rows(operation: str, *, query_reads: tuple[QueryRead, ...],
               selected_rows: tuple[dict[str, Any], ...], query_id: str) -> tuple[dict[str, Any], ...]:
    """Look up retained observed order, not a completeness/proof authority.

    The source-program validator must run separately. Selected wrappers are
    returned unchanged, including their original global contractSelector.
    """
    _query_id(query_id)
    validate_read_budget(operation, query_reads=query_reads)
    records = tuple(_copy_read(record) for record in query_reads)
    selections = _selection_map(operation, selected_rows)
    if _associations(records, selections) != set(selections):
        raise QueryReadError("query read inventory does not exactly cover the global selection")
    matching = tuple(record for record in records if record.query_id == query_id)
    if len(matching) != 1:
        raise QueryReadError("query read identity is missing or duplicated")
    return tuple(selections[(address.table, address.key_json)][1] for address in matching[0].addresses)
