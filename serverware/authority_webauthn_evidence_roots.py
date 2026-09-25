"""Fixed primary-root observations for the two evidence-admission operations.

The caller owns actual verifier role/TLS/schema and read-only transaction
admission. One source-selected SELECT observes the complete operation inventory
on that snapshot. There are no counted heads, caller SQL, clock, plan admission
or mutations. Observations and their projections are ordinary data, never root
currentness, historical provenance or successful-verification tokens.

One fresh physical acquisition ledger uses the original cumulative work. Its
bounds count actual parameter and ordered returned-scalar frames, not database
network allocation. Source metadata reconstruction, fixed DTO/trace scaffolding
and native SQL/driver internals remain separate boundaries. Real scalar frames,
owned copies, projection capture and the actual cold primary-empty calculation
are charged without resetting work.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_revocation_roots as roots


authority, primary, projection, reader, batch = (
    roots.authority, roots.primary, roots.projection, roots.reader, roots.batch)
PRIMARY_TABLE = roots.PRIMARY_TABLE
PRIMARY_READ_PROFILE = "serverware.policyAuthorityWebAuthnEvidencePrimaryRootRead/v1"
_REGISTRATION = "webauthn.registration.evidence.admit"
_INSTALLATION = "webauthn.trust.installation.admit"
_EVIDENCE_TABLE = "policy_authority_external_evidence_receipts"
_AUTHORIZATION_TABLES = ("webauthn_trust_publication_high_water", "webauthn_trust_publications")
_PrimaryObservation = roots._PrimaryObservation


class WebAuthnEvidenceRootReadError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _RootInventory:
    """Complete owned observations; constructing this class grants nothing."""

    operation: str
    business_roots: tuple[_PrimaryObservation, ...]
    authorization_roots: tuple[_PrimaryObservation, ...]


def _tables(operation):
    if type(operation) is not str:
        raise WebAuthnEvidenceRootReadError("evidence root operation is not exact")
    if operation == _REGISTRATION:
        return ("oidc_browser_sessions", _EVIDENCE_TABLE), ("webauthn_challenges", *_AUTHORIZATION_TABLES)
    if operation == _INSTALLATION:
        return (_EVIDENCE_TABLE,), _AUTHORIZATION_TABLES
    raise WebAuthnEvidenceRootReadError("evidence root operation is not source fixed")


def _source(operation):
    business, authorization = _tables(operation)
    contracts = primary.primary_table_contracts(operation)
    tables = business + authorization
    spec = authority.operation_spec(operation)
    if (tuple(item.table for item in contracts) != tables
            or tuple(item.table for item in contracts if item.root_class == "business") != business
            or tuple(item.table for item in contracts if item.root_class == "authorization") != authorization
            or tuple(item.table for item in contracts if item.write_access) != (_EVIDENCE_TABLE,)
            or tuple(spec["businessWrites"]) != (_EVIDENCE_TABLE,)
            or spec["globalAuditCapacity"] is not False or spec["selectors"]
            or projection.index_ids_for_table(_EVIDENCE_TABLE)
            or (authority.TREE_DEPTH, authority.TREE_RADIX) != (64, 16)):
        raise WebAuthnEvidenceRootReadError("evidence primary root inventory differs from its no-index source contract")
    return business, authorization


def _limits(operation):
    business, authorization = _tables(operation)
    tables = business + authorization
    row_limit = len(tables) + 1
    parameters = sum(8 + len(name) for name in tables) + 8 + len(str(row_limit))
    # Kind plus eight scalar frames; depth/radix are fixed two-digit values.
    returned = sum(9 * 8 + len("primary-root") + len(name) + 2 * 71 + 3 * 19 + 2 * 2
        for name in tables)
    return reader._ReadAcquisitionLimits(max_sql_reads=1,
        max_parameter_bytes=parameters, max_transport_bytes=returned)


def _physical_stamp(acquisition, operation):
    if type(acquisition) is not reader._ReadAcquisitionBudget:
        raise WebAuthnEvidenceRootReadError("evidence roots require the actual physical ledger")
    identity = acquisition._identity
    if (type(identity) is not tuple or len(identity) != 3
            or any(actual is not expected for actual, expected in
                zip((acquisition.cursor, acquisition.trace, acquisition.work), identity))):
        raise WebAuthnEvidenceRootReadError("evidence root physical identity changed")
    acquisition.require_active()
    limits, expected = acquisition.limits, _limits(operation)
    business, authorization = _tables(operation)
    if (type(limits) is not reader._ReadAcquisitionLimits
            or any(type(value) is not int or value != bound for value, bound in zip(
                (limits.max_sql_reads, limits.max_parameter_bytes, limits.max_transport_bytes),
                (expected.max_sql_reads, expected.max_parameter_bytes, expected.max_transport_bytes)))
            or any(type(value) is not int or not 0 <= value <= maximum for value, maximum in (
                (acquisition.sql_reads, 1), (acquisition.returned_rows, len(business) + len(authorization)),
                (acquisition.parameter_bytes, expected.max_parameter_bytes),
                (acquisition.transport_bytes, expected.max_transport_bytes)))
            or any(type(value) is not bool for value in (acquisition.active,
                acquisition.failed, acquisition._reading, acquisition._read_phase_active))):
        raise WebAuthnEvidenceRootReadError("evidence root physical limits or counters changed")
    return (limits, identity, acquisition.sql_reads, acquisition.returned_rows,
        acquisition.parameter_bytes, acquisition.transport_bytes, acquisition.active,
        acquisition.failed, acquisition._reading, acquisition._read_phase_active)


def _same_stamp(before, after):
    return before[0] is after[0] and before[1] is after[1] and before[2:] == after[2:]


class _RootCursor:
    """Guard owner admission unbound, then one genuine physical acquisition."""

    __slots__ = ("_cursor", "_work", "operation", "_identity", "_acquisition")

    def __init__(self, cursor, work, operation):
        batch._SharedLedger(work)
        _tables(operation)
        self._cursor, self._work, self.operation = cursor, work, operation
        self._identity = cursor, work, operation
        self._acquisition = None

    def _require(self):
        identity = self._identity
        if (type(identity) is not tuple or len(identity) != 3
                or self._cursor is not identity[0] or self._work is not identity[1]
                or type(self.operation) is not str or type(identity[2]) is not str
                or self.operation != identity[2]):
            raise WebAuthnEvidenceRootReadError("evidence root cursor identity changed")
        _tables(self.operation)

    def _call(self, callback):
        acquisition = self._acquisition
        try:
            self._require()
            cursor, work, operation, identity = self._cursor, self._work, self.operation, self._identity
            before = _physical_stamp(acquisition, operation) if acquisition is not None else None
            try:
                return roots._callback(work, callback)
            finally:
                self._require()
                if (self._cursor is not cursor or self._work is not work or self.operation != operation
                        or self._identity is not identity or self._acquisition is not acquisition
                        or acquisition is not None and not _same_stamp(before, _physical_stamp(acquisition, operation))):
                    raise WebAuthnEvidenceRootReadError("evidence root driver changed its physical ledger")
        except BaseException:
            if type(acquisition) is reader._ReadAcquisitionBudget:
                acquisition.failed = True
            raise

    def execute(self, sql, parameters=None):
        arguments = (sql,) if parameters is None else (sql, parameters)
        return roots._RootResult(self._call(lambda: self._cursor.execute(*arguments)), self)


class _RootTrace:
    """One source-exact primary-root marker; not a planner proof trace."""

    __slots__ = ("operation", "_work", "_identity", "_phase", "_active", "_failed", "_acquisition")

    def __init__(self, *, operation, work):
        batch._SharedLedger(work)
        _tables(operation)
        self.operation, self._work = operation, work
        self._identity = operation, work
        self._phase, self._active, self._failed, self._acquisition = 0, False, False, None

    def _require(self):
        if (type(self._identity) is not tuple or len(self._identity) != 2
                or type(self.operation) is not str or type(self._identity[0]) is not str
                or self.operation != self._identity[0]
                or self._work is not self._identity[1]):
            raise WebAuthnEvidenceRootReadError("evidence root trace identity changed")
        _tables(self.operation)

    def _advance(self, table, key):
        business, authorization = _tables(self.operation)
        tables = business + authorization
        fields = ("profile", "tableNames", "rowLimit")
        if (type(self._phase) is not int or self._phase != 0
                or type(table) is not str or table != PRIMARY_TABLE
                or type(key) is not dict or len(key) != 3
                or any(type(name) is not str or len(name) > 32 for name in key)
                or set(key) != set(fields)
                or type(key["profile"]) is not str or key["profile"] != PRIMARY_READ_PROFILE
                or type(key["tableNames"]) is not list or len(key["tableNames"]) != len(tables)
                or any(type(name) is not str or not 1 <= len(name) <= 128 for name in key["tableNames"])
                or tuple(key["tableNames"]) != tables
                or type(key["rowLimit"]) is not int or key["rowLimit"] != len(tables) + 1):
            raise WebAuthnEvidenceRootReadError("evidence primary root marker is not source exact")
        self._phase += 1

    def read(self, table, key):
        acquisition = self._acquisition
        try:
            self._require()
            if (self._active is not True or self._failed is not False
                    or type(acquisition) is not reader._ReadAcquisitionBudget
                    or acquisition.work is not self._work or acquisition.trace is not self):
                raise WebAuthnEvidenceRootReadError("evidence root trace is not active and original")
            operation, work, identity, phase = self.operation, self._work, self._identity, self._phase
            before = _physical_stamp(acquisition, operation)
            advanced = False
            try:
                roots._callback(work, lambda: self._advance(table, key))
                advanced = True
            finally:
                self._require()
                if (self._acquisition is not acquisition or self._work is not work
                        or self._identity is not identity or self.operation != operation
                        or self._active is not True or self._failed is not False
                        or type(self._phase) is not int or self._phase not in (phase, phase + 1)
                        or advanced and self._phase != phase + 1
                        or not _same_stamp(before, _physical_stamp(acquisition, operation))):
                    raise WebAuthnEvidenceRootReadError("evidence root trace changed its physical ledger")
        except BaseException:
            self._failed = True
            if type(acquisition) is reader._ReadAcquisitionBudget:
                acquisition.failed = True
            raise


def _read_root_inventory_on_work(cursor, *, operation, expected_query_manifest_digest, work, acquisition):
    """Read the complete five/three primary rows after actual owner admission."""
    trace = acquisition.trace if type(acquisition) is reader._ReadAcquisitionBudget else None
    try:
        batch._SharedLedger(work)
        business, authorization = _source(operation)
        tables, expected = business + authorization, _limits(operation)
        if (type(cursor) is not _RootCursor or type(trace) is not _RootTrace
                or type(cursor.operation) is not str or type(trace.operation) is not str
                or cursor.operation != operation or trace.operation != operation
                or cursor._work is not work or trace._work is not work
                or cursor._acquisition is not None or trace._acquisition is not None
                or type(trace._phase) is not int or trace._phase != 0
                or trace._active is not False or trace._failed is not False
                or type(expected_query_manifest_digest) is not str or len(expected_query_manifest_digest) != 71
                or roots._DIGEST.fullmatch(expected_query_manifest_digest) is None
                or type(acquisition._identity) is not tuple or len(acquisition._identity) != 3
                or acquisition._read_phase_active is not False or acquisition._reading is not False):
            raise WebAuthnEvidenceRootReadError("evidence root invocation is not exact and unused")
        cursor._require()
        trace._require()
        acquisition.require_idle(cursor, trace, work)
        limits = acquisition.limits
        if (type(limits) is not reader._ReadAcquisitionLimits
                or any(type(value) is not int or value != bound for value, bound in zip(
                    (limits.max_sql_reads, limits.max_parameter_bytes, limits.max_transport_bytes),
                    (1, expected.max_parameter_bytes, expected.max_transport_bytes)))
                or any(type(value) is not int or value != 0 for value in
                    (acquisition.sql_reads, acquisition.returned_rows, acquisition.parameter_bytes, acquisition.transport_bytes))
                or acquisition.active is not False or acquisition.failed is not False):
            raise WebAuthnEvidenceRootReadError("evidence root physical allowance is not source exact and unused")
        cursor_identity, trace_identity, physical_identity = cursor._identity, trace._identity, acquisition._identity
        cursor._acquisition = trace._acquisition = acquisition
        trace._active = True
        with acquisition.read_phase(cursor, trace, work):
            manifest = roots._callback(work, primary.source_query_manifest_digest)
            if manifest != expected_query_manifest_digest:
                raise WebAuthnEvidenceRootReadError("evidence roots differ from the independently pinned global manifest")
            empty = roots._primary_empty_root(work)
            sql = (f"SELECT {roots._PRIMARY_SELECT} FROM serverware_metadata.{PRIMARY_TABLE} AS root "
                f"WHERE root.table_name IN ({', '.join('%s' for _ in tables)}) "
                'ORDER BY root.table_name COLLATE "C" LIMIT %s')
            with acquisition.scope(cursor, trace, work):
                _physical_stamp(acquisition, operation)
                rows = acquisition.read(PRIMARY_TABLE,
                    {"profile": PRIMARY_READ_PROFILE, "tableNames": list(tables), "rowLimit": len(tables) + 1},
                    sql, (*tables, len(tables) + 1), len(tables))
                if len(rows) != len(tables):
                    raise WebAuthnEvidenceRootReadError("evidence primary root inventory is incomplete")
                owned = tuple(roots._owned_primary_row(raw, table, manifest, empty, acquisition, work)
                    for table, raw in zip(tables, rows))
            acquisition.require_idle(cursor, trace, work)
            cursor._require()
            trace._require()
            if (cursor._identity is not cursor_identity or trace._identity is not trace_identity
                    or acquisition._identity is not physical_identity or acquisition.limits is not limits
                    or cursor.operation != operation or trace.operation != operation
                    or cursor._work is not work or trace._work is not work
                    or cursor._acquisition is not acquisition or trace._acquisition is not acquisition
                    or trace._phase != 1 or type(trace._phase) is not int
                    or trace._active is not True or trace._failed is not False
                    or acquisition.sql_reads != 1 or acquisition.returned_rows != len(tables)
                    or acquisition.parameter_bytes != expected.max_parameter_bytes
                    or acquisition._reading is not False or acquisition._read_phase_active is not True):
                raise WebAuthnEvidenceRootReadError("evidence root acquisition did not complete its one physical read")
            result = _RootInventory(operation, owned[:len(business)], owned[len(business):])
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


def _project_on_work(inventory, *, operation, work):
    """Capture a same-call observation as exact plan-root data, not authority."""
    ledger = batch._SharedLedger(work)
    business, authorization = _source(operation)
    if (type(inventory) is not _RootInventory or type(inventory.operation) is not str
            or inventory.operation != operation or type(inventory.business_roots) is not tuple
            or type(inventory.authorization_roots) is not tuple
            or len(inventory.business_roots) != len(business)
            or len(inventory.authorization_roots) != len(authorization)):
        raise WebAuthnEvidenceRootReadError("evidence root projection requires an exact complete inventory")
    rows = []
    for table, observed in zip(business + authorization, inventory.business_roots + inventory.authorization_roots):
        if type(observed) is not _PrimaryObservation:
            raise WebAuthnEvidenceRootReadError("evidence root projection observation is not exact")
        row = {name: getattr(observed, name) for name in roots._PRIMARY_FIELDS}
        if (type(row["table_name"]) is not str or row["table_name"] != table
                or any(type(row[name]) is not int or not 0 <= row[name] <= roots.counted.I64_MAX
                    for name in roots._PRIMARY_COUNTERS)
                or type(row["tree_depth"]) is not int or row["tree_depth"] != 64
                or type(row["tree_radix"]) is not int or row["tree_radix"] != 16
                or any(type(row[name]) is not str or len(row[name]) != 71 or roots._DIGEST.fullmatch(row[name]) is None
                    for name in ("root_digest", "manifest_digest"))):
            raise WebAuthnEvidenceRootReadError("evidence root projection scalars differ from source bounds")
        rows.append(row)
    # Hold every immutable scalar in a genuinely charged owned JSON graph
    # before invoking even the fixed source-manifest/empty-root helpers.
    owned = batch._JSONCapture(ledger).visit(rows)
    manifest = roots._callback(work, primary.source_query_manifest_digest)
    empty = roots._primary_empty_root(work)
    projected = []
    for row in owned:
        if (row["manifest_digest"] != manifest
                or (row["leaf_count"] == 0) != (row["root_digest"] == empty)
                or row["root_revision"] == 0 and row["leaf_count"] != 0):
            raise WebAuthnEvidenceRootReadError("evidence root projection manifest or empty root changed")
        projected.append({"table": row["table_name"], "rootRevision": row["root_revision"],
            "rootDigest": row["root_digest"], "leafCount": row["leaf_count"]})
    captured = batch._JSONCapture(ledger).visit({
        "business": projected[:len(business)], "authorization": projected[len(business):]})
    work.prepare_copy(captured["business"])
    business_values = tuple(captured["business"])
    work.prepare_copy(captured["authorization"])
    authorization_values = tuple(captured["authorization"])
    return business_values, authorization_values
