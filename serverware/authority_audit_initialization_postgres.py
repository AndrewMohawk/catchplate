"""Real PostgreSQL snapshot reader for offline audit preparation, not installation.

The caller owns an active SERIALIZABLE read-write transaction, its independently
admitted schema/session and any external writer fence. Locks do NOT refresh an
already established snapshot. This module never begins, commits, rolls back or
retries a transaction, inserts a counter, or consumes initialization authority.
Every returned preparation remains non-actionable and snapshot-relative.
"""
from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, fields
from typing import Any

import psycopg
from psycopg import sql
from psycopg.pq import TransactionStatus
from psycopg.rows import dict_row

from serverware import authority_audit_capacity as capacity
from serverware import authority_audit_initialization as initialization
from serverware import authority_contract
from serverware import authority_radix_proof as radix
from serverware import authority_transition_core as core
from serverware.authority_primary_contract import source_query_manifest_digest
from serverware.authority_radix_mutation import PrimaryRadixMutationError, PrimaryRoot


ROOTS = "policy_authority_authenticated_table_roots"
LEAVES = "policy_authority_authenticated_leaves"
NODES = "policy_authority_authenticated_tree_nodes"
HISTORY = "policy_authority_authenticated_root_revisions"
# Base-table locks precede root locks, matching the direction of AFTER triggers.
LOCK_TABLES = (capacity.OUTBOX_TABLE, capacity.AGGREGATE_TABLE, ROOTS, LEAVES, NODES, HISTORY)


class AuditInitializationPostgresError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AuditInitializationReadLimits:
    max_rows: int
    max_total_bytes: int
    max_queries: int
    statement_timeout_ms: int
    lock_timeout_ms: int
    total_timeout_ms: int
    max_record_bytes: int

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            minimum = 0 if field.name == "max_rows" else 1
            if type(value) is not int or not minimum <= value <= capacity.MAX_INTEGER:
                raise AuditInitializationPostgresError("offline read limit is not an exact bounded integer")
        if (max(self.statement_timeout_ms, self.lock_timeout_ms, self.total_timeout_ms) > 86_400_000
                or self.max_record_bytes > authority_contract.MAX_RESULT_BYTES):
            raise AuditInitializationPostgresError("offline read timeout or record bound is excessive")


def _namespace(value: str) -> str:
    if type(value) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value) is None:
        raise AuditInitializationPostgresError("offline read namespace is not an exact PostgreSQL identifier")
    return value


def _root(value: PrimaryRoot, table: str) -> PrimaryRoot:
    if type(value) is not PrimaryRoot or value.table != table:
        raise AuditInitializationPostgresError("offline expected root has the wrong table or type")
    try:
        return PrimaryRoot(value.table, value.root_revision, value.root_digest, value.leaf_count)
    except (AttributeError, PrimaryRadixMutationError) as exc:
        raise AuditInitializationPostgresError("offline expected root is invalid") from exc


class _Budget:
    def __init__(self, limits: AuditInitializationReadLimits, control: Any) -> None:
        self.limits, self.control = limits, control
        self.deadline = time.monotonic_ns() + limits.total_timeout_ms * 1_000_000
        self.queries = 0
        self.bytes = 0
        self.rows = 0
        self.proof_reads = 0

    def check(self) -> None:
        if time.monotonic_ns() >= self.deadline:
            raise AuditInitializationPostgresError("offline preparation exceeded its total deadline")

    def data(self, value: Any, *, record: bool = False) -> None:
        self.check()
        raw = capacity.canonical_audit_json(value)
        if record and len(raw) > self.limits.max_record_bytes:
            raise AuditInitializationPostgresError("offline record exceeded its byte limit")
        self.bytes += len(raw)
        if self.bytes > self.limits.max_total_bytes:
            raise AuditInitializationPostgresError("offline preparation exceeded its total byte limit")
        self.check()

    def arm(self) -> None:
        """Charge/restrict the next command, including a named cursor FETCH.

        One timeout-setting SELECT plus the target command are charged. Cleanup
        CLOSE commands are unconditional and outside this read-command budget.
        These are server timeouts and local boundary checks, not a watchdog for
        a stuck driver/server/transport. The job owner must provide that watchdog.
        """
        self.check()
        if self.queries + 2 > self.limits.max_queries:
            raise AuditInitializationPostgresError("offline preparation exceeded its query limit")
        remaining = max(1, (self.deadline - time.monotonic_ns() + 999_999) // 1_000_000)
        timeout = min(self.limits.statement_timeout_ms, remaining)
        self.queries += 2
        self.control.execute(
            "SELECT pg_catalog.set_config('statement_timeout', %s, true) AS statement_timeout, "
            "pg_catalog.set_config('lock_timeout', %s, true) AS lock_timeout, "
            "pg_catalog.set_config('row_security', 'off', true) AS row_security",
            (str(timeout) + "ms", str(min(self.limits.lock_timeout_ms, remaining)) + "ms"),
        )
        self.data(self.control.fetchone())

    def read(self, table: str, key: Any) -> None:
        # The proof helper's logical trace is counted, never retained as a
        # population-sized graph. Actual SQL is independently charged by arm.
        self.proof_reads += 1
        if self.proof_reads > self.limits.max_queries:
            raise AuditInitializationPostgresError("offline proof read budget exceeded")
        self.check()


class _ReadCursor:
    """Budget real cursor operations; never rewrite SQL or fabricate results."""

    def __init__(self, cursor: Any, budget: _Budget, *, server: bool = False) -> None:
        self.cursor, self.budget, self.server = cursor, budget, server

    def execute(self, statement: Any, parameters: Any = None) -> _ReadCursor:
        self.budget.arm()
        self.cursor.execute(statement, parameters)
        self.budget.check()
        return self

    def fetchone(self) -> Any:
        if self.server:
            self.budget.arm()
        value = self.cursor.fetchone()
        self.budget.data(value)
        return value

    def fetchmany(self, size: int) -> list[Any]:
        if self.server:
            self.budget.arm()
        value = self.cursor.fetchmany(size)
        self.budget.data(value)
        return value


def _selected(table: str, key: dict[str, Any], row: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "table": table, "key": key,
        "keyDigest": core.framed_digest("serverware.policyAuthorityBusinessKey/v1",
            table.encode("ascii"), capacity.canonical_audit_json(key)),
        "present": row is not None, "row": row, "contractSelector": None,
    }


def _proof(cursor: _ReadCursor, budget: _Budget, selected: dict[str, Any],
           root: PrimaryRoot, namespace: str) -> dict[str, Any]:
    proofs = radix.derive_multiproofs(cursor, selected_rows=(selected,),
        roots=(root.json_projection(),), trace=budget, namespace=namespace)
    if len(proofs) != 1:
        raise AuditInitializationPostgresError("offline singleton proof was not unique")
    record = {"selectedRow": selected, "proof": proofs[0]}
    budget.data(record, record=True)
    return record


def _locked_roots(cursor: _ReadCursor, namespace: str,
                  expected: tuple[PrimaryRoot, PrimaryRoot]) -> None:
    # This is an offline six-table lock, not a measured all-writer fence or a
    # complete schema/ACL admission. The outer job must drain/coordinate writers.
    cursor.execute(sql.SQL("LOCK TABLE {} IN ACCESS EXCLUSIVE MODE").format(
        sql.SQL(", ").join(sql.Identifier(namespace, table) for table in LOCK_TABLES)))
    rows = cursor.execute(sql.SQL(
        "SELECT table_name, root_revision, leaf_count, tree_depth, tree_radix, "
        "CASE WHEN pg_catalog.octet_length(root_digest)=71 THEN root_digest END AS root_digest, "
        "CASE WHEN pg_catalog.octet_length(manifest_digest)=71 THEN manifest_digest END AS manifest_digest "
        "FROM {} WHERE table_name = ANY(%s) ORDER BY table_name COLLATE \"C\" FOR UPDATE"
    ).format(sql.Identifier(namespace, ROOTS)), ([root.table for root in expected],)).fetchmany(3)
    if len(rows) != 2:
        raise AuditInitializationPostgresError("offline root set is incomplete or duplicated")
    observed = {}
    for row in rows:
        if (row["tree_depth"] != 64 or type(row["tree_depth"]) is not int
                or row["tree_radix"] != 16 or type(row["tree_radix"]) is not int
                or row["manifest_digest"] != source_query_manifest_digest()
                or row["table_name"] in observed):
            raise AuditInitializationPostgresError("offline root profile or manifest differs")
        observed[row["table_name"]] = PrimaryRoot(
            row["table_name"], row["root_revision"], row["root_digest"], row["leaf_count"])
    if observed != {root.table: root for root in expected}:
        raise AuditInitializationPostgresError("offline roots differ from independently supplied expectations")
    # Physical leaf counts are consistency checks only. They do not authenticate
    # aggregate cardinality, root currentness or database generation.
    for root in expected:
        count = cursor.execute(sql.SQL(
            "SELECT count(*) AS count FROM {} WHERE table_name=%s"
        ).format(sql.Identifier(namespace, LEAVES)), (root.table,)).fetchone()
        if count is None or type(count["count"]) is not int or count["count"] != root.leaf_count:
            raise AuditInitializationPostgresError("offline stored leaf population differs from root descriptor")


def _outbox_records(connection: psycopg.Connection, cursor: _ReadCursor,
                    budget: _Budget, root: PrimaryRoot, namespace: str):
    # Sort only identity/key material, never the full event bodies. CASE retains
    # an oversized identity as an explicit NULL sentinel; it cannot disappear
    # from the enumeration. The database sort/detoast still needs job limits.
    with connection.cursor(name="audit_init_" + uuid.uuid4().hex, row_factory=dict_row,
                           scrollable=False, withhold=False) as raw_scan:
        raw_scan.itersize = 1
        scan = _ReadCursor(raw_scan, budget, server=True)
        scan.execute(sql.SQL(
            "SELECT scan.id, scan.tree_key FROM ("
            "SELECT CASE WHEN pg_catalog.octet_length(id)<=%s THEN id END AS id, "
            "CASE WHEN pg_catalog.octet_length(id)<=%s THEN {}("
            "'serverware.policyAuthorityAuthenticatedKey/v1', 'metadata_audit_outbox', "
            "{}(pg_catalog.jsonb_build_object('id',id))) END AS tree_key "
            "FROM {}) AS scan ORDER BY scan.tree_key COLLATE \"C\" NULLS FIRST"
        ).format(sql.Identifier(namespace, "serverware_policy_authority_framed_digest"),
                 sql.Identifier(namespace, "serverware_policy_authority_canonical_json"),
                 sql.Identifier(namespace, capacity.OUTBOX_TABLE)),
            (budget.limits.max_record_bytes, budget.limits.max_record_bytes))
        previous = None
        while True:
            page = scan.fetchmany(1)
            if not page:
                break
            budget.rows += 1
            if budget.rows > budget.limits.max_rows or budget.rows > root.leaf_count:
                raise AuditInitializationPostgresError("offline outbox exceeded its row count bound")
            identity = page[0]
            if type(identity["id"]) is not str or type(identity["tree_key"]) is not str:
                raise AuditInitializationPostgresError("offline outbox identity is oversized or malformed")
            key = {"id": identity["id"]}
            actual_key = radix.authenticated_key_digest(capacity.OUTBOX_TABLE, key)
            if (identity["tree_key"] != actual_key
                    or previous is not None and actual_key <= previous):
                raise AuditInitializationPostgresError("offline outbox key/order differs from persisted contract")
            previous = actual_key
            rows = cursor.execute(sql.SQL(
                "SELECT CASE WHEN pg_catalog.octet_length(pg_catalog.to_jsonb(target)::text)<=%s "
                "THEN pg_catalog.to_jsonb(target) END AS row FROM {} AS target WHERE id=%s"
            ).format(sql.Identifier(namespace, capacity.OUTBOX_TABLE)),
                (budget.limits.max_record_bytes, identity["id"])).fetchmany(2)
            if len(rows) != 1 or type(rows[0]["row"]) is not dict:
                raise AuditInitializationPostgresError("offline outbox full row is missing, duplicated or oversized")
            row = rows[0]["row"]
            budget.data(row, record=True)
            yield _proof(cursor, budget, _selected(capacity.OUTBOX_TABLE, key, row), root, namespace)
        if budget.rows != root.leaf_count:
            raise AuditInitializationPostgresError("offline outbox stream ended before the accepted count")


def prepare_audit_capacity_initialization_from_postgres(
    connection: psycopg.Connection, *, expected_outbox_root: PrimaryRoot,
    expected_aggregate_root: PrimaryRoot, initialized_at_epoch_ns: int,
    limits: AuditInitializationReadLimits, namespace: str = "serverware_metadata",
) -> initialization.AuditCapacityInitializationPreparation:
    """Calculate from actual locked snapshot rows/proofs without installing.

    The active transaction and locks remain owned by the caller on success AND
    error. SQL/serialization errors propagate; never retry inside this function.
    Local statement/lock timeouts and row_security=off remain until transaction
    end. Inputs are expectations, not proof that their roots/fence are current.
    A process watchdog and DB CPU/memory/spill/storage budgets remain mandatory.
    """
    accepted_namespace = _namespace(namespace)
    if type(limits) is not AuditInitializationReadLimits:
        raise AuditInitializationPostgresError("offline read limits have the wrong type")
    limits = AuditInitializationReadLimits(**{field.name: getattr(limits, field.name) for field in fields(limits)})
    outbox = _root(expected_outbox_root, capacity.OUTBOX_TABLE)
    aggregate = _root(expected_aggregate_root, capacity.AGGREGATE_TABLE)
    if outbox.leaf_count > limits.max_rows:
        raise AuditInitializationPostgresError("offline expected outbox exceeds its row limit")
    if type(initialized_at_epoch_ns) is not int or not 0 <= initialized_at_epoch_ns <= capacity.MAX_INTEGER:
        raise AuditInitializationPostgresError("offline initialization timestamp is invalid")
    if (not isinstance(connection, psycopg.Connection) or connection.closed or connection.autocommit
            or connection.info.transaction_status != TransactionStatus.INTRANS):
        raise AuditInitializationPostgresError("offline preparation requires an active caller-owned transaction")
    if not 160000 <= connection.info.server_version < 170000:
        raise AuditInitializationPostgresError("offline preparation requires PostgreSQL 16")
    try:
        with connection.cursor(row_factory=dict_row) as control, connection.cursor(row_factory=dict_row) as raw:
            budget = _Budget(limits, control)
            cursor = _ReadCursor(raw, budget)
            context = cursor.execute(
                "SELECT pg_catalog.current_setting('transaction_isolation') AS isolation, "
                "pg_catalog.current_setting('transaction_read_only') AS read_only, "
                "pg_catalog.getdatabaseencoding() AS encoding, "
                "pg_catalog.current_setting('client_encoding') AS client_encoding"
            ).fetchone()
            if (context is None or context["isolation"] != "serializable" or context["read_only"] != "off"
                    or context["encoding"] != "UTF8" or context["client_encoding"] != "UTF8"):
                raise AuditInitializationPostgresError("offline preparation requires a SERIALIZABLE read-write UTF8 session")
            _locked_roots(cursor, accepted_namespace, (outbox, aggregate))
            key = {"aggregate_id": capacity.AGGREGATE_ID}
            existing = cursor.execute(sql.SQL("SELECT aggregate_id FROM {} WHERE aggregate_id=%s")
                .format(sql.Identifier(accepted_namespace, capacity.AGGREGATE_TABLE)),
                (capacity.AGGREGATE_ID,)).fetchmany(2)
            if existing:
                raise AuditInitializationPostgresError("offline global counter is already present")
            absence = _proof(cursor, budget, _selected(capacity.AGGREGATE_TABLE, key, None),
                             aggregate, accepted_namespace)
            records = _outbox_records(connection, cursor, budget, outbox, accepted_namespace)
            try:
                result = initialization.prepare_audit_capacity_initialization(
                    outbox_root=outbox, outbox_records=records, aggregate_root=aggregate,
                    aggregate_absence=absence, initialized_at_epoch_ns=initialized_at_epoch_ns)
            finally:
                records.close()
            budget.data(result.json_projection())
            budget.check()
            return result
    except (capacity.AuditCapacityError, initialization.AuditCapacityInitializationError,
            radix.RadixProofError, PrimaryRadixMutationError) as exc:
        raise AuditInitializationPostgresError("offline snapshot preparation failed admission") from exc
