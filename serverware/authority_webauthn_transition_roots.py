"""Two source-fixed metadata reads for independently observed transition roots.

The real owner admits its verifier connection, TLS/ACL and read-only snapshot.
This worker commits the request again before SQL, then observes globally sorted
primary roots and all potential source counted heads. Results are ordinary
observations, not currentness, history, cutoff, population or execution proofs.

One fresh physical ledger shares the caller's original cumulative work. Actual
parameter/returned-scalar framing, owned copies and mathematical source work are
charged; source metadata, fixed trace/DTO scaffolding and native driver work are
not whole-resource claims. No business row, SQL mutation or new work allowance
is acquired. Immutable request/source bindings survive every driver callback.
"""
from __future__ import annotations

from serverware import authority_webauthn_transition_roots_contract as contract


roots, heads, reader, batch, primary = (
    contract.roots, contract.heads, contract.reader, contract.batch, contract.primary)
PRIMARY_TABLE, PRIMARY_READ_PROFILE = contract.PRIMARY_TABLE, contract.PRIMARY_READ_PROFILE


class WebAuthnTransitionRootReadError(ValueError):
    pass


def _binding(operation, request):
    """Hold only immutable scope data; the worker separately commits originals."""
    if type(operation) is not str or operation not in contract.OPERATIONS:
        raise WebAuthnTransitionRootReadError("transition root operation is not source fixed")
    contract.proof_contract._request(request, operation)
    business, authorization, tables, identities = contract._source(operation, request["arguments"])
    limits = contract._limits(operation, request["arguments"])
    return (operation, request["requestDigest"], business, authorization, tables, identities,
        (limits.max_sql_reads, limits.max_parameter_bytes, limits.max_transport_bytes))


def _physical_stamp(acquisition, binding):
    if type(acquisition) is not reader._ReadAcquisitionBudget:
        raise WebAuthnTransitionRootReadError("transition roots require the actual physical ledger")
    identity = acquisition._identity
    if (type(identity) is not tuple or len(identity) != 3
            or any(actual is not expected for actual, expected in
                zip((acquisition.cursor, acquisition.trace, acquisition.work), identity))
            or type(acquisition.cursor) is not _RootCursor or type(acquisition.trace) is not _RootTrace):
        raise WebAuthnTransitionRootReadError("transition root physical identity changed")
    cursor, trace = acquisition.cursor, acquisition.trace
    cursor._require()
    trace._require()
    acquisition.require_active()
    limits, expected = acquisition.limits, binding[6]
    if (cursor._binding != binding or trace._binding != binding
            or cursor._acquisition is not acquisition or trace._acquisition is not acquisition
            or trace._active is not True or trace._failed is not False
            or type(limits) is not reader._ReadAcquisitionLimits
            or any(type(value) is not int or value != maximum for value, maximum in zip(
                (limits.max_sql_reads, limits.max_parameter_bytes, limits.max_transport_bytes), expected))
            or any(type(value) is not int or not 0 <= value <= maximum for value, maximum in (
                (acquisition.sql_reads, 2), (acquisition.returned_rows, len(binding[4]) + len(binding[5])),
                (acquisition.parameter_bytes, expected[1]), (acquisition.transport_bytes, expected[2])))
            or any(type(value) is not bool for value in (acquisition.active,
                acquisition.failed, acquisition._reading, acquisition._read_phase_active))
            or acquisition._read_phase_active is not True):
        raise WebAuthnTransitionRootReadError("transition root physical scope, limits or counters changed")
    return (limits, identity, cursor._identity, trace._identity,
        acquisition.sql_reads, acquisition.returned_rows, acquisition.parameter_bytes,
        acquisition.transport_bytes, acquisition.active, acquisition.failed,
        acquisition._reading, acquisition._read_phase_active)


def _same_stamp(before, after):
    return all(before[index] is after[index] for index in range(4)) and before[4:] == after[4:]


class _RootCursor:
    """Guard real owner admission first, then one request-bound acquisition."""

    __slots__ = ("_cursor", "_work", "operation", "_binding", "_identity", "_acquisition")

    def __init__(self, cursor, work, operation, request):
        batch._SharedLedger(work)
        binding = _binding(operation, request)
        self._cursor, self._work, self.operation, self._binding = cursor, work, operation, binding
        self._identity = cursor, work, binding
        self._acquisition = None

    def _require(self):
        identity = self._identity
        if (type(identity) is not tuple or len(identity) != 3
                or self._cursor is not identity[0] or self._work is not identity[1]
                or self._binding is not identity[2] or type(self.operation) is not str
                or self.operation != self._binding[0]):
            raise WebAuthnTransitionRootReadError("transition root cursor identity changed")

    def _call(self, callback):
        acquisition = self._acquisition
        try:
            self._require()
            cursor, work, binding, identity = self._cursor, self._work, self._binding, self._identity
            before = _physical_stamp(acquisition, binding) if acquisition is not None else None
            phase = acquisition.trace._phase if acquisition is not None else None
            try:
                return roots._callback(work, callback)
            finally:
                self._require()
                if (self._cursor is not cursor or self._work is not work
                        or self._binding is not binding or self._identity is not identity
                        or self._acquisition is not acquisition
                        or acquisition is not None and (type(acquisition.trace._phase) is not int
                            or acquisition.trace._phase != phase
                            or not _same_stamp(before, _physical_stamp(acquisition, binding)))):
                    raise WebAuthnTransitionRootReadError("transition root driver changed its physical ledger")
        except BaseException:
            if type(acquisition) is reader._ReadAcquisitionBudget:
                acquisition.failed = True
            raise

    def execute(self, sql, parameters=None):
        arguments = (sql,) if parameters is None else (sql, parameters)
        return roots._RootResult(self._call(lambda: self._cursor.execute(*arguments)), self)


class _RootTrace:
    """Exact primary-then-head markers, never an arbitrary planner trace."""

    __slots__ = ("operation", "_work", "_binding", "_identity", "_phase", "_active", "_failed", "_acquisition")

    def __init__(self, *, operation, request, work):
        batch._SharedLedger(work)
        binding = _binding(operation, request)
        self.operation, self._work, self._binding = operation, work, binding
        self._identity = binding, work
        self._phase, self._active, self._failed, self._acquisition = 0, False, False, None

    def _require(self):
        identity = self._identity
        if (type(identity) is not tuple or len(identity) != 2
                or self._binding is not identity[0] or self._work is not identity[1]
                or type(self.operation) is not str or self.operation != self._binding[0]):
            raise WebAuthnTransitionRootReadError("transition root trace identity changed")

    def _advance(self, table, key):
        phase = self._phase
        if type(phase) is not int or phase not in (0, 1):
            raise WebAuthnTransitionRootReadError("transition root trace exceeded its two fixed reads")
        expected_table, profile, field, names = ((PRIMARY_TABLE, PRIMARY_READ_PROFILE, "tableNames", self._binding[4])
            if phase == 0 else (heads.HEAD_TABLE, heads.READ_PROFILE, "indexIds", self._binding[5]))
        if (type(table) is not str or table != expected_table
                or type(key) is not dict or len(key) != 3
                or any(type(name) is not str or len(name) > 32 for name in key)
                or set(key) != {"profile", field, "rowLimit"}
                or type(key["profile"]) is not str or key["profile"] != profile
                or type(key[field]) is not list or len(key[field]) != len(names)
                or any(type(name) is not str or not 1 <= len(name) <= 128 for name in key[field])
                or tuple(key[field]) != names
                or type(key["rowLimit"]) is not int or key["rowLimit"] != len(names) + 1):
            raise WebAuthnTransitionRootReadError("transition root physical marker is not source exact")
        self._phase = phase + 1

    def read(self, table, key):
        acquisition = self._acquisition
        try:
            self._require()
            if (self._active is not True or self._failed is not False
                    or type(acquisition) is not reader._ReadAcquisitionBudget
                    or acquisition.work is not self._work or acquisition.trace is not self):
                raise WebAuthnTransitionRootReadError("transition root trace is not active and original")
            binding, work, identity, phase = self._binding, self._work, self._identity, self._phase
            before = _physical_stamp(acquisition, binding)
            advanced = False
            try:
                roots._callback(work, lambda: self._advance(table, key))
                advanced = True
            finally:
                self._require()
                if (self._acquisition is not acquisition or self._work is not work
                        or self._binding is not binding or self._identity is not identity
                        or self._active is not True or self._failed is not False
                        or type(self._phase) is not int or self._phase not in (phase, phase + 1)
                        or advanced and self._phase != phase + 1
                        or not _same_stamp(before, _physical_stamp(acquisition, binding))):
                    raise WebAuthnTransitionRootReadError("transition root trace changed its physical ledger")
        except BaseException:
            self._failed = True
            if type(acquisition) is reader._ReadAcquisitionBudget:
                acquisition.failed = True
            raise


def _read_root_inventory_on_work(cursor, *, operation, request,
        expected_query_manifest_digest, work, acquisition):
    """Observe complete source primary and potential counted inventories."""
    trace = acquisition.trace if type(acquisition) is reader._ReadAcquisitionBudget else None
    try:
        batch._SharedLedger(work)
        owned_request = contract._capture_request_on_work(request=request, operation=operation, work=work)
        binding = _binding(operation, owned_request)
        _operation, request_digest, business, authorization, tables, identities, expected = binding
        if (type(cursor) is not _RootCursor or type(trace) is not _RootTrace
                or cursor._binding != binding or trace._binding != binding
                or cursor._work is not work or trace._work is not work
                or cursor._acquisition is not None or trace._acquisition is not None
                or type(trace._phase) is not int or trace._phase != 0
                or trace._active is not False or trace._failed is not False
                or type(expected_query_manifest_digest) is not str or len(expected_query_manifest_digest) != 71
                or roots._DIGEST.fullmatch(expected_query_manifest_digest) is None
                or type(acquisition._identity) is not tuple or len(acquisition._identity) != 3
                or acquisition._read_phase_active is not False or acquisition._reading is not False):
            raise WebAuthnTransitionRootReadError("transition root invocation is not exact and unused")
        cursor._require()
        trace._require()
        acquisition.require_idle(cursor, trace, work)
        limits = acquisition.limits
        if (type(limits) is not reader._ReadAcquisitionLimits
                or any(type(value) is not int or value != maximum for value, maximum in zip(
                    (limits.max_sql_reads, limits.max_parameter_bytes, limits.max_transport_bytes), expected))
                or any(type(value) is not int or value != 0 for value in
                    (acquisition.sql_reads, acquisition.returned_rows, acquisition.parameter_bytes, acquisition.transport_bytes))
                or acquisition.active is not False or acquisition.failed is not False):
            raise WebAuthnTransitionRootReadError("transition root allowance is not source exact and unused")
        cursor_identity, trace_identity, physical_identity = cursor._identity, trace._identity, acquisition._identity
        cursor._acquisition = trace._acquisition = acquisition
        trace._active = True
        with acquisition.read_phase(cursor, trace, work):
            with acquisition.scope(cursor, trace, work):
                manifest = cursor._call(lambda: primary.source_query_manifest_digest())
                if manifest != expected_query_manifest_digest:
                    raise WebAuthnTransitionRootReadError("transition roots differ from the pinned global manifest")
                # This helper legitimately charges mathematical work. Its own
                # actual native callback guard preserves work; retain physical
                # identity/counters and trace phase across the complete helper.
                before, phase = _physical_stamp(acquisition, binding), trace._phase
                try:
                    empty = roots._primary_empty_root(work)
                finally:
                    if (trace._phase != phase or type(trace._phase) is not int
                            or not _same_stamp(before, _physical_stamp(acquisition, binding))):
                        raise WebAuthnTransitionRootReadError("transition root source helper changed the acquisition")
                sql = (f"SELECT {roots._PRIMARY_SELECT} FROM serverware_metadata.{PRIMARY_TABLE} AS root "
                    f"WHERE root.table_name IN ({', '.join('%s' for _ in tables)}) "
                    'ORDER BY root.table_name COLLATE "C" LIMIT %s')
                rows = acquisition.read(PRIMARY_TABLE,
                    {"profile": PRIMARY_READ_PROFILE, "tableNames": list(tables), "rowLimit": len(tables) + 1},
                    sql, (*tables, len(tables) + 1), len(tables))
                if len(rows) != len(tables):
                    raise WebAuthnTransitionRootReadError("transition primary root inventory is incomplete")
                observed = tuple(roots._owned_primary_row(raw, table, manifest, empty, acquisition, work)
                    for table, raw in zip(tables, rows))
                _physical_stamp(acquisition, binding)
            acquisition.require_idle(cursor, trace, work)
            with acquisition.scope(cursor, trace, work):
                counted_heads = heads._read_index_heads_on_scope(cursor, operation=operation,
                    identities=identities, trace=trace, work=work, acquisition=acquisition)
                _physical_stamp(acquisition, binding)
            acquisition.require_idle(cursor, trace, work)
            by_table = {item.table_name: item for item in observed}
            if any(item.index_root.count > by_table[item.table].leaf_count for item in counted_heads):
                raise WebAuthnTransitionRootReadError("transition counted head exceeds its primary population")
            cursor._require()
            trace._require()
            if (cursor._identity is not cursor_identity or trace._identity is not trace_identity
                    or acquisition._identity is not physical_identity or acquisition.limits is not limits
                    or cursor._binding != binding or trace._binding != binding
                    or cursor._work is not work or trace._work is not work
                    or cursor._acquisition is not acquisition or trace._acquisition is not acquisition
                    or type(trace._phase) is not int or trace._phase != 2
                    or trace._active is not True or trace._failed is not False
                    or type(acquisition.sql_reads) is not int or acquisition.sql_reads != 2
                    or type(acquisition.returned_rows) is not int
                    or acquisition.returned_rows != len(tables) + len(identities)
                    or type(acquisition.parameter_bytes) is not int or acquisition.parameter_bytes != expected[1]
                    or type(acquisition.transport_bytes) is not int or not 0 < acquisition.transport_bytes <= expected[2]
                    or acquisition.active is not False or acquisition.failed is not False
                    or acquisition._reading is not False or acquisition._read_phase_active is not True):
                raise WebAuthnTransitionRootReadError("transition acquisition did not complete its two physical reads")
            # SQL uses the global order, which need not concatenate the two
            # source root classes. Partition actual rows by their source class.
            result = contract._RootInventory(operation, request_digest,
                tuple(item for item in observed if item.table_name in business),
                tuple(item for item in observed if item.table_name in authorization), counted_heads)
        acquisition.require_idle(cursor, trace, work)
        batch._SharedLedger(work)
        return result
    except BaseException:
        if type(acquisition) is reader._ReadAcquisitionBudget:
            acquisition.failed = True
        if type(trace) is _RootTrace:
            trace._failed = True
        raise
    finally:
        if type(trace) is _RootTrace:
            trace._active = False
