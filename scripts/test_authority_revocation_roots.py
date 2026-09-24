#!/usr/bin/env python3
"""Independent root inventory and configured read-transaction models.

The actual inventory worker, counted-head worker, work ledger and fixed catalog
query run against deterministic cursor/connection responders. These responders
are not PostgreSQL, do not authenticate a role or certificate, and establish no
root currentness, row-population proof, clock provenance or production admission.
Expected tree hashes and work follow independent recipes, never returned metrics.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_primary_contract as primary
from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_roots as roots
from serverware import authority_revocation_root_reader as configured
from serverware import authority_index_heads as heads
from serverware import authority_index_reader as reader
from serverware.authority_store import verifier_read_sql as privileges
import test_authority_index_heads as head_oracle
from test_authority_radix_mutation import IndependentTree
from test_authority_radix_proof import sql_digest, sql_json


BUSINESS_TABLES = (
    "approval_grants", "control_plane_approvals", "metadata_audit_outbox",
    "oidc_browser_sessions", "policy_authority_bounded_aggregate_states",
    "webauthn_challenges", "webauthn_credentials",
)
AUTHORIZATION_TABLES = ("webauthn_trust_publication_high_water", "webauthn_trust_publications")
TABLES = tuple(sorted(BUSINESS_TABLES + AUTHORIZATION_TABLES))
PRIMARY_TABLE = "policy_authority_authenticated_table_roots"
HEAD_TABLE = "policy_authority_counted_index_heads"
PRIMARY_FIELDS = ("table_name", "root_revision", "root_digest", "leaf_count",
    "tree_depth", "tree_radix", "manifest_digest", "updated_at_epoch_ns")
HEAD_IDS = (
    "webauthn_control_approval_approved", "webauthn_credential_id",
    "webauthn_credential_live_trust", "webauthn_credential_user_history",
    "webauthn_grant_approver_active", "webauthn_publication_status",
    "webauthn_registration_unused_global", "webauthn_registration_unused_user",
    "webauthn_session_credential_status",
)
ROLE_TABLES = frozenset({PRIMARY_TABLE, HEAD_TABLE, "webauthn_challenges", "webauthn_credentials",
    "webauthn_trust_publication_high_water", "webauthn_trust_publications"})


@lru_cache(maxsize=1)
def manifest_digest():
    # Source manifest construction is separately covered by the primary-source
    # fixture. Hash it with the independently authored persisted SQL framing.
    return sql_digest("serverware.policyAuthorityQueryManifest/v1",
        sql_json(primary.source_query_manifest()))


def primary_rows(*, populated=False):
    result = []
    empty = IndependentTree([])
    for ordinal, table in enumerate(TABLES):
        columns = (("aggregate_id",) if table == "policy_authority_bounded_aggregate_states"
            else ("authority_scope",) if table == "webauthn_trust_publication_high_water" else ("id",))
        tree = (IndependentTree([{columns[0]: "member", "value": ordinal}],
            table=table, columns=columns, revision=7) if populated else empty)
        result.append(dict(zip(PRIMARY_FIELDS, (table, tree.root.root_revision,
            tree.root.root_digest, tree.root.leaf_count, 64, 16, manifest_digest(), 100 + ordinal))))
    return result


def add(*values):
    return tuple(sum(value[index] for value in values) for index in range(3))


def graph(value):
    return 0, 2 * len(sql_json(value)), 2 * head_oracle.nodes(value)


def framed_scalars(values):
    sizes = [len(str(value).encode("utf-8")) for value in values]
    return (0, sum(8 + 2 * size for size in sizes), 2 * len(sizes)), sum(8 + size for size in sizes)


def work(limits=None):
    return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))


def counters(meter):
    return meter.hash_work, meter.input_bytes, meter.json_nodes


def independent_work(primary_values, head_values):
    """Real cold65 reservation plus literal frames/copies and counted oracle."""
    leaf_domain = "serverware.policyAuthorityAuthenticatedEmptyLeaf/v1"
    node_domain = "serverware.policyAuthorityAuthenticatedNode/v1"
    # SQL-tree normalize+encode prepares three walks. Sixteen canonical digest
    # strings always have this length and 17 graph nodes, irrespective of hash.
    child_bytes, child_nodes = 2 + 15 + 16 * (2 + 71), 17
    cold = (65, 16 + 3 * len(leaf_domain) + 3 * len("64")
        + sum(24 + 3 * len(node_domain) + 3 * len(str(depth)) + 4 * child_bytes
              for depth in range(64)), 4 + 64 * (4 + 3 * child_nodes))
    parameters, parameter_bytes = framed_scalars((*TABLES, 10))
    total, transport_bytes = add(cold, parameters), 0
    for row in primary_values:
        frames, physical = framed_scalars(("primary-root", *(row[name] for name in PRIMARY_FIELDS)))
        total = add(total, frames, graph(row))
        transport_bytes += physical
    counted = head_oracle.expected_work(head_values)
    return {"total": add(total, counted[:3]), "cold": cold,
        "physical": (2, 18, parameter_bytes + counted[3], transport_bytes + counted[4])}


def physical(acquisition):
    return (acquisition.sql_reads, acquisition.returned_rows,
        acquisition.parameter_bytes, acquisition.transport_bytes)


def inventory_fixture(*, primary_values=None, head_values=None, meter=None, callback=None, limits=None):
    raw = InventoryCursor(primary_values, head_values, callback)
    meter = work() if meter is None else meter
    cursor, trace = roots._RootCursor(raw, meter), roots._RootTrace(meter)
    acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=meter,
        limits=roots._ROOT_LIMITS if limits is None else limits)
    return raw, cursor, trace, meter, acquisition


def acquire(fixture, **changes):
    _raw, cursor, _trace, meter, acquisition = fixture
    return roots._read_revocation_root_inventory_on_work(cursor,
        **{"expected_query_manifest_digest": manifest_digest(), "work": meter,
           "acquisition": acquisition, **changes})


class InventoryCursor:
    """Bounded SQL responder returning intentionally borrowed dictionaries."""

    def __init__(self, primary_values=None, head_values=None, callback=None):
        self.primary = copy.deepcopy(primary_rows() if primary_values is None else primary_values)
        self.heads = copy.deepcopy(head_oracle.source_rows() if head_values is None else head_values)
        self.callback = callback
        self.calls, self.fetch_bounds, self.events = [], [], []
        self.selected = None

    def event(self, name):
        self.events.append(name)
        if self.callback is not None:
            self.callback(name)

    def execute(self, statement, parameters):
        if f"FROM serverware_metadata.{PRIMARY_TABLE} " in statement:
            kind, expected, fields = "primary", (*TABLES, 10), PRIMARY_FIELDS
        elif f"FROM serverware_metadata.{HEAD_TABLE} " in statement:
            kind, expected, fields = "head", (*HEAD_IDS, 10), head_oracle.FIELDS
            # Delegate to the pre-existing independent exact head SQL checker;
            # this is not a substitute for the genuine production head worker.
            head_oracle.Cursor(self.heads).execute(statement, parameters)
        else:
            raise AssertionError("inventory attempted a relation outside its two-table closure")
        if (not statement.startswith("SELECT CASE WHEN pg_catalog.pg_typeof(")
                or parameters != expected or 'COLLATE "C" LIMIT %s' not in statement
                or any(f" AS {name}" not in statement for name in fields)
                or any(token in statement for token in ("FOR UPDATE", "INSERT", "UPDATE ", "DELETE", "COMMIT"))):
            raise AssertionError("inventory SQL is not the bounded source-only projection")
        self.selected = kind
        self.calls.append((statement, parameters))
        self.event(kind + ".execute")
        return self

    def fetchmany(self, maximum):
        if maximum != 10 or self.selected not in ("primary", "head"):
            raise AssertionError("inventory fetch is not source bounded")
        self.fetch_bounds.append(maximum)
        self.event(self.selected + ".fetch")
        # Deliberately do not truncate: the real worker must reject a driver
        # returning too many rows despite both SQL LIMIT and fetchmany bound.
        return self.primary if self.selected == "primary" else self.heads


CONFIGURATION = ("postgresql://root-reader.invalid/fixture", 3, "authority_verifier_reader",
    "CN=verifier", "42", "CN=issuer", None)
IDENTITY_FIELDS = ("server_version_num", "role", "session_role", "transaction_isolation",
    "transaction_read_only", "transaction_deferrable", "ssl", "client_dn", "client_serial",
    "issuer_dn", "rolcanlogin", "rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication",
    "rolbypassrls", "schema_create", "database_create", "database_temporary")


def configuration():
    return (*CONFIGURATION[:6], manifest_digest())


def identity_row():
    return dict(zip(IDENTITY_FIELDS, (160004, CONFIGURATION[2], CONFIGURATION[2],
        "serializable", "on", "on", True, *CONFIGURATION[3:6], True, *([False] * 8))))


class Connection:
    """Connection ownership model, not a PostgreSQL authentication success."""

    def __init__(self, *, callback=None, identity=None, violation=None):
        self.callback, self.events = callback, []
        self.closed, self.autocommit = False, False
        self.pgconn, self.info = object(), SimpleNamespace(transaction_status=0)
        self.identity = identity_row() if identity is None else copy.deepcopy(identity)
        self.violation = violation
        self.commits = self.rollbacks = self.closes = self.exits = 0
        self.cursor_value = OwnerCursor(self)

    def event(self, name):
        self.events.append(name)
        if self.callback is not None:
            self.callback(name)

    def __enter__(self):
        self.event("connection.enter")
        return self

    def __exit__(self, kind, error, traceback):
        self.exits += 1
        try:
            if kind is None:
                self.commits += 1
                self.event("connection.commit")
            else:
                self.rollbacks += 1
                self.event("connection.rollback")
        finally:
            self.close()
        return False

    def close(self):
        self.closes += 1
        self.closed, self.info.transaction_status = True, 0
        self.event("connection.close")

    def cursor(self):
        self.event("cursor.open")
        return self.cursor_value


class OwnerCursor(InventoryCursor):
    def __init__(self, connection):
        super().__init__(callback=connection.event)
        self.connection = connection
        self.metadata_calls, self.fetchone_calls, self.exits = [], [], 0

    def __enter__(self):
        self.event("cursor.enter")
        return self

    def __exit__(self, kind, error, traceback):
        self.exits += 1
        self.event("cursor.exit")
        return False

    def execute(self, statement, parameters=None):
        mode = "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE"
        if statement == mode:
            if self.metadata_calls:
                raise AssertionError("transaction mode was not first SQL")
            self.connection.info.transaction_status = 2
            self.selected = "mode"
        elif "server_version_num" in statement and "pg_catalog.pg_stat_ssl" in statement:
            if len(self.metadata_calls) != 1 or parameters is not None:
                raise AssertionError("identity SQL did not follow transaction mode")
            for field in IDENTITY_FIELDS:
                if field not in statement:
                    raise AssertionError("identity SQL omitted " + field)
            self.selected = "identity"
        elif statement == privileges.VERIFIER_READ_PRIVILEGE_SQL:
            if parameters != (CONFIGURATION[2], "serverware_metadata", sorted(ROLE_TABLES)):
                raise AssertionError("catalog query parameters differ from six-table source closure")
            if len(self.metadata_calls) != 2:
                raise AssertionError("effective ACL check did not follow identity")
            self.selected = "privileges"
        else:
            if len(self.metadata_calls) != 3:
                raise AssertionError("root SQL preceded metadata admission")
            return super().execute(statement, parameters)
        self.metadata_calls.append((statement, parameters))
        self.event(self.selected + ".execute")
        return self

    def fetchone(self):
        self.fetchone_calls.append(self.selected)
        self.event(self.selected + ".fetch")
        if self.selected == "identity":
            return self.connection.identity
        if self.selected == "privileges":
            return self.connection.violation
        raise AssertionError("unexpected metadata fetch")


class RevocationRootInventoryTests(unittest.TestCase):
    def assert_inventory(self, result, primary_values, head_values):
        for actual, tables in ((result.business_roots, BUSINESS_TABLES),
                               (result.authorization_roots, AUTHORIZATION_TABLES)):
            self.assertIs(type(actual), tuple)
            self.assertEqual(tuple(row.table_name for row in actual), tables)
            self.assertEqual([tuple(getattr(row, name) for name in PRIMARY_FIELDS) for row in actual],
                [tuple(row[name] for name in PRIMARY_FIELDS) for row in primary_values if row["table_name"] in tables])
        self.assertEqual(tuple(head.index_id for head in result.counted_heads), HEAD_IDS)
        self.assertEqual([tuple((head.index_id, head.table, head.counted_profile, head.projection_digest,
            head.projection_manifest_digest, head.index_revision, head.index_root.digest, head.index_root.count))
            for head in result.counted_heads], [tuple(row[name] for name in head_oracle.FIELDS) for row in head_values])

    def test_real_two_selects_full_source_inventory_and_independent_cost(self):
        fixture = inventory_fixture()
        raw, cursor, trace, meter, acquisition = fixture
        expected = independent_work(raw.primary, raw.heads)
        actual_head_worker, actual_empty = heads.read_operation_index_heads, roots.radix.empty_digest
        with patch.object(heads, "read_operation_index_heads", wraps=actual_head_worker) as observed_heads, \
                patch.object(roots.radix, "empty_digest", wraps=actual_empty) as observed_empty:
            result = acquire(fixture)
        self.assert_inventory(result, raw.primary, raw.heads)
        self.assertEqual((observed_heads.call_count, observed_empty.call_count), (1, 1))
        self.assertEqual(observed_empty.call_args.args, (0,))
        self.assertIs(observed_heads.call_args.args[0], cursor)
        for name, value in (("trace", trace), ("work", meter), ("acquisition", acquisition)):
            self.assertIs(observed_heads.call_args.kwargs[name], value)
        self.assertEqual(counters(meter), expected["total"])
        self.assertEqual(meter.hash_work, 84)
        self.assertEqual(physical(acquisition), expected["physical"])
        self.assertEqual((raw.fetch_bounds, trace._phase, trace._active, acquisition.failed), ([10, 10], 2, False, False))
        self.assertEqual(raw.events, ["primary.execute", "primary.fetch", "head.execute", "head.fetch"])
        self.assertEqual([entry[1] for entry in raw.calls], [(*TABLES, 10), (*HEAD_IDS, 10)])
        with self.assertRaises(FrozenInstanceError):
            result.business_roots[0].root_revision = 99
        with self.assertRaises(FrozenInstanceError):
            result.counted_heads[0].index_root.count = 99

    def test_populated_and_positive_revision_empty_rows_preserve_full_observations(self):
        primary_values, head_values = primary_rows(populated=True), head_oracle.source_rows(populated=True)
        primary_values[-1] = primary_rows()[-1]
        primary_values[-1]["root_revision"] = 19
        head_values[-1] = head_oracle.source_rows()[-1]
        head_values[-1]["index_revision"] = 19
        fixture = inventory_fixture(primary_values=primary_values, head_values=head_values)
        result = acquire(fixture)
        self.assert_inventory(result, primary_values, head_values)
        self.assertEqual(counters(fixture[3]), independent_work(primary_values, head_values)["total"])
        self.assertEqual(result.authorization_roots[-1].root_revision, 19)
        self.assertEqual(result.counted_heads[-1].index_root.count, 0)

    def test_both_primary_classes_require_global_query_manifest_before_counted_read(self):
        wrong = primary.source_authorization_manifest_digest()
        self.assertNotEqual(wrong, manifest_digest())
        fixture = inventory_fixture()
        with self.assertRaisesRegex(roots.RevocationRootReadError, "independent pin"):
            acquire(fixture, expected_query_manifest_digest=wrong)
        self.assertEqual((fixture[0].calls, counters(fixture[3])), ([], (0, 0, 0)))
        for table in (BUSINESS_TABLES[0], AUTHORIZATION_TABLES[0]):
            values = primary_rows()
            next(row for row in values if row["table_name"] == table)["manifest_digest"] = wrong
            fixture = inventory_fixture(primary_values=values)
            with self.subTest(table=table), self.assertRaisesRegex(roots.RevocationRootReadError, "source binding"):
                acquire(fixture)
            self.assertEqual(len(fixture[0].calls), 1)
            self.assertTrue(fixture[4].failed)

    def test_primary_cardinality_order_duplicate_and_foreign_inventory_deny(self):
        values = primary_rows()
        variants = [values[:-1], values + [values[0]], list(reversed(values)),
            [values[0], values[0], *values[2:]], [{**values[0], "table_name": "credentials"}, *values[1:]]]
        for variant in variants:
            fixture = inventory_fixture(primary_values=variant)
            with self.subTest(rows=variant), self.assertRaises(ValueError):
                acquire(fixture)
            self.assertEqual(len(fixture[0].calls), 1)
            self.assertTrue(fixture[4].failed)
        fixture = inventory_fixture()
        fixture[0].primary = tuple(fixture[0].primary)
        with self.assertRaises(reader.IndexReadError):
            acquire(fixture)

    def test_primary_closed_scalar_tree_shape_and_empty_semantics_deny(self):
        class ForeignString(str):
            pass
        mutations = [{"extra": 1}, {"root_revision": True}, {"root_revision": -1},
            {"root_revision": 2**63}, {"leaf_count": 1.0}, {"updated_at_epoch_ns": None},
            {"updated_at_epoch_ns": 2**63}, {"tree_depth": 63}, {"tree_radix": True},
            {"root_digest": "sha256:" + "A" * 64}, {"manifest_digest": "x" * 10000},
            {"table_name": ForeignString(TABLES[0])}, {"root_digest": "sha256:" + "f" * 64},
            {"root_revision": 0, "leaf_count": 1, "root_digest": "sha256:" + "f" * 64}]
        for change in mutations:
            values = primary_rows()
            values[0].update(change)
            fixture = inventory_fixture(primary_values=values)
            with self.subTest(change=change), self.assertRaises(roots.RevocationRootReadError):
                acquire(fixture)
            self.assertEqual(len(fixture[0].calls), 1)
        for kind in ("missing", "foreign-key"):
            values = primary_rows()
            value = values[0].pop("root_revision")
            if kind == "foreign-key":
                values[0][ForeignString("root_revision")] = value
            with self.subTest(kind=kind), self.assertRaises(roots.RevocationRootReadError):
                acquire(inventory_fixture(primary_values=values))

    def test_actual_counted_worker_rejects_missing_order_profile_manifest_and_empty_changes(self):
        base = head_oracle.source_rows()
        variants = [base[:-1], base + [base[0]], list(reversed(base)), [base[0], base[0], *base[2:]]]
        for field, value in (("index_id", "webauthn_publication_generation"), ("table_name", "credentials"),
                ("counted_profile", "other"), ("projection_digest", "sha256:" + "a" * 64),
                ("projection_manifest_digest", "sha256:" + "b" * 64), ("index_revision", True),
                ("leaf_count", 1), ("root_digest", "sha256:" + "c" * 64)):
            changed = copy.deepcopy(base)
            changed[0][field] = value
            variants.append(changed)
        for values in variants:
            fixture = inventory_fixture(head_values=values)
            actual = heads.read_operation_index_heads
            with self.subTest(rows=values), patch.object(heads, "read_operation_index_heads", wraps=actual) as called:
                with self.assertRaises(reader.IndexReadError):
                    acquire(fixture)
            self.assertEqual((called.call_count, len(fixture[0].calls)), (1, 2))
            self.assertTrue(fixture[4].failed)

    def test_rows_are_owned_before_later_callbacks_and_return_is_not_a_live_alias(self):
        fixture = inventory_fixture()
        raw = fixture[0]
        before_primary, before_heads = copy.deepcopy(raw.primary), copy.deepcopy(raw.heads)
        def mutate(event):
            if event == "head.execute":
                raw.primary[0]["root_digest"] = "sha256:" + "f" * 64
                raw.primary.clear()
        raw.callback = mutate
        result = acquire(fixture)
        raw.heads[0]["leaf_count"] = 100
        raw.heads.clear()
        self.assert_inventory(result, before_primary, before_heads)

    def test_exact_preconsumed_and_each_remaining_work_dimension_minus_one(self):
        expected = independent_work(primary_rows(), head_oracle.source_rows())["total"]
        for prior in ((0, 0, 0), (3, 17, 11)):
            budget = add(prior, expected)
            meter = work(budget)
            meter.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            limits = meter.limits
            acquire(inventory_fixture(meter=meter))
            self.assertEqual(counters(meter), budget)
            self.assertIs(meter.limits, limits)
            for dimension in range(3):
                reduced = tuple(value - (index == dimension) for index, value in enumerate(budget))
                meter = work(reduced)
                meter.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                fixture = inventory_fixture(meter=meter)
                with self.subTest(prior=prior, dimension=dimension), self.assertRaises(accounting.QueryReadWorkError):
                    acquire(fixture)
                self.assertTrue(fixture[4].failed)
                self.assertTrue(all(spent <= maximum for spent, maximum in zip(counters(meter), reduced)))

    def test_repeated_reads_use_fresh_physical_ledgers_but_original_remaining_work(self):
        expected = independent_work(primary_rows(), head_oracle.source_rows())["total"]
        for deficit in (False, True):
            budget = tuple(2 * value - (deficit and index == 1) for index, value in enumerate(expected))
            meter = work(budget)
            first = inventory_fixture(meter=meter)
            acquire(first)
            spent = counters(meter)
            with self.assertRaises(roots.RevocationRootReadError):
                acquire(first)
            self.assertEqual(counters(meter), spent)
            second = inventory_fixture(meter=meter)
            if deficit:
                with self.assertRaises(accounting.QueryReadWorkError):
                    acquire(second)
            else:
                acquire(second)
                self.assertEqual(counters(meter), budget)
                self.assertEqual(physical(second[4]), physical(first[4]))

    def test_physical_source_ceilings_and_consumed_or_replaced_ledgers_are_not_inputs(self):
        expected_parameters = sum(8 + len(name) for name in (*TABLES, *HEAD_IDS)) + 20
        expected_primary = sum(72 + 12 + len(name) + 142 + 57 + 4 for name in TABLES)
        expected_heads = sum(72 + 4 + len(row["index_id"]) + len(row["table_name"])
            + len("serverware.policyAuthorityCountedIndex/v1") + 213 + 38 for row in head_oracle.source_rows())
        self.assertEqual((roots._ROOT_LIMITS.max_sql_reads, roots._ROOT_LIMITS.max_parameter_bytes,
            roots._ROOT_LIMITS.max_transport_bytes), (2, expected_parameters, expected_primary + expected_heads))
        for field in ("sql_reads", "returned_rows", "parameter_bytes", "transport_bytes"):
            fixture = inventory_fixture()
            setattr(fixture[4], field, 1)
            with self.subTest(field=field), self.assertRaises(roots.RevocationRootReadError):
                acquire(fixture)
            self.assertEqual(fixture[0].calls, [])
        for limits in (reader._ReadAcquisitionLimits(1, expected_parameters, expected_primary + expected_heads),
                reader._ReadAcquisitionLimits(2, expected_parameters - 1, expected_primary + expected_heads),
                reader._ReadAcquisitionLimits(2, expected_parameters, expected_primary + expected_heads - 1)):
            fixture = inventory_fixture(limits=limits)
            with self.assertRaises(roots.RevocationRootReadError):
                acquire(fixture)
            self.assertEqual(fixture[0].calls, [])

    def test_actual_driver_callbacks_cannot_spend_refund_retype_or_replace_work(self):
        for event in ("primary.execute", "primary.fetch", "head.execute", "head.fetch"):
            for mutation in ("spend", "refund", "float", "replace", "widen"):
                meter = work()
                meter.charge(input_bytes=1)
                fixture = inventory_fixture(meter=meter)
                observed = []
                def change(actual):
                    if actual != event:
                        return
                    if mutation == "spend": meter.charge(input_bytes=1)
                    if mutation == "refund": meter.input_bytes -= 1
                    if mutation == "float": meter.input_bytes = float(meter.input_bytes)
                    if mutation == "replace": meter.limits = accounting.QueryReadValidationLimits()
                    if mutation == "widen": object.__setattr__(meter.limits, "max_input_bytes", meter.limits.max_input_bytes + 1)
                    observed.append((meter.input_bytes, meter.limits))
                fixture[0].callback = change
                with self.subTest(event=event, mutation=mutation), self.assertRaises(ValueError):
                    acquire(fixture)
                self.assertEqual(len(observed), 1)
                self.assertEqual(meter.input_bytes, observed[0][0])
                self.assertIs(meter.limits, observed[0][1])
                self.assertTrue(fixture[4].failed)
                self.assertFalse(fixture[2]._active)

    def test_driver_physical_identity_changes_and_caught_reentry_poison_outer_read(self):
        for mutation in ("counter", "float", "limits", "cursor", "trace", "work", "reentry"):
            fixture = inventory_fixture()
            raw, cursor, trace, meter, acquisition = fixture
            caught = []
            def change(event):
                if event != "primary.fetch":
                    return
                if mutation == "counter": acquisition.parameter_bytes -= 1
                if mutation == "float": acquisition.returned_rows = float(acquisition.returned_rows)
                if mutation == "limits": acquisition.limits = reader._ReadAcquisitionLimits(
                    roots._ROOT_LIMITS.max_sql_reads, roots._ROOT_LIMITS.max_parameter_bytes,
                    roots._ROOT_LIMITS.max_transport_bytes)
                if mutation == "cursor": cursor._cursor = InventoryCursor()
                if mutation == "trace": acquisition.trace = roots._RootTrace(meter)
                if mutation == "work": acquisition.work = work()
                if mutation == "reentry":
                    try:
                        acquire(fixture)
                    except roots.RevocationRootReadError:
                        caught.append(True)
            raw.callback = change
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                acquire(fixture)
            self.assertEqual(len(raw.calls), 1)
            self.assertTrue(acquisition.failed)
            if mutation == "reentry": self.assertEqual(caught, [True])

    def test_original_cursor_exceptions_propagate_and_invalid_work_never_reads(self):
        for event in ("primary.execute", "primary.fetch", "head.execute", "head.fetch"):
            failure = RuntimeError("original driver failure")
            fixture = inventory_fixture(callback=lambda actual: (_ for _ in ()).throw(failure) if actual == event else None)
            with self.subTest(event=event), self.assertRaises(RuntimeError) as caught:
                acquire(fixture)
            self.assertIs(caught.exception, failure)
            self.assertTrue(fixture[4].failed)
        for supplied in (None, object()):
            fixture = inventory_fixture()
            with self.assertRaises(ValueError):
                acquire(fixture, work=supplied)
            self.assertEqual(fixture[0].calls, [])


class RevocationRootOwnerTests(unittest.TestCase):
    def owner(self, values=None):
        values = configuration() if values is None else values
        return configured.RevocationRootReader(**dict(zip(("dsn", "connect_timeout_seconds", "database_role",
            "tls_client_dn", "tls_client_serial", "tls_issuer_dn", "query_manifest_digest"), values)))

    def read(self, connection, *, meter=None, owner=None, opener=None):
        owner = self.owner() if owner is None else owner
        meter = work() if meter is None else meter
        def open_connection():
            connection.event("connection.open")
            return connection
        return configured._read_on_configuration(owner._snapshot_configuration(),
            work=meter, opener=open_connection if opener is None else opener)

    def assert_clean_rollback(self, connection):
        self.assertEqual((connection.commits, connection.rollbacks, connection.exits, connection.closes), (0, 1, 1, 1))
        self.assertIs(connection.closed, True)

    def test_real_owner_admission_order_worker_once_same_work_and_closed_handoff(self):
        connection, meter = Connection(), work()
        raw = connection.cursor_value
        before_primary, before_heads = copy.deepcopy(raw.primary), copy.deepcopy(raw.heads)
        expected = independent_work(before_primary, before_heads)
        actual_worker, actual_privileges = roots._read_revocation_root_inventory_on_work, configured.verifier_read_privilege_check
        with patch.object(roots, "_read_revocation_root_inventory_on_work", wraps=actual_worker) as worker_call, \
                patch.object(configured, "verifier_read_privilege_check", wraps=actual_privileges) as privilege_call:
            result = self.read(connection, meter=meter)
        self.assertEqual((worker_call.call_count, privilege_call.call_count), (1, 1))
        self.assertIs(worker_call.call_args.kwargs["work"], meter)
        RevocationRootInventoryTests().assert_inventory(result, before_primary, before_heads)
        self.assertEqual(counters(meter), expected["total"])
        self.assertEqual(physical(worker_call.call_args.kwargs["acquisition"]), expected["physical"])
        self.assertEqual(connection.events, ["connection.open", "connection.enter", "cursor.open", "cursor.enter",
            "mode.execute", "identity.execute", "identity.fetch", "privileges.execute", "privileges.fetch",
            "primary.execute", "primary.fetch", "head.execute", "head.fetch", "cursor.exit",
            "connection.commit", "connection.close"])
        self.assertEqual((connection.commits, connection.rollbacks, connection.closes, raw.exits), (1, 0, 1, 1))
        self.assertEqual(raw.metadata_calls[0], ("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE", None))
        self.assertEqual(raw.metadata_calls[2], actual_privileges(role=CONFIGURATION[2], namespace="serverware_metadata"))
        self.assertIs(connection.closed, True)

    def test_configuration_exact_scalar_bounds_timeout_and_invalid_work_precede_opener(self):
        class ForeignString(str):
            pass
        changes = [(0, ""), (0, "x" * 65537), (0, "dsn\x00suffix"),
            (2, ForeignString(CONFIGURATION[2])), (2, "r" * 64), (3, "\ud800"),
            (4, "x" * 4097), (5, "issuer\x00name"), (6, "sha256:" + "A" * 64)]
        changes += [(1, value) for value in (None, True, 0, 1, 1.25, 1.999, 2.5, 301,
            float("nan"), float("inf"), -float("inf"))]
        for index, value in changes:
            values = list(configuration())
            values[index] = value
            with self.subTest(index=index, value=value), self.assertRaises(roots.RevocationRootReadError):
                self.owner(tuple(values))
        for timeout in (2, 300):
            values = list(configuration())
            values[1] = timeout
            self.assertEqual(self.owner(tuple(values))._snapshot_configuration()[1], timeout)
        for supplied in (None, object()):
            opened = []
            with self.assertRaises(ValueError):
                configured._read_on_configuration(configuration(), work=supplied,
                    opener=lambda: opened.append(True))
            self.assertEqual(opened, [])
        for supplied in (list(configuration()), configuration()[:-1], (*configuration(), "extra")):
            opened = []
            with self.assertRaises(roots.RevocationRootReadError):
                configured._read_on_configuration(supplied, work=work(), opener=lambda: opened.append(True))
            self.assertEqual(opened, [])
        with self.assertRaises(TypeError):
            self.owner().read(work=work(), opener=lambda: Connection())
        with self.assertRaises(FrozenInstanceError):
            self.owner()._configuration = configuration()

    def test_every_identity_role_tls_mode_version_and_boolean_failure_precedes_privilege_or_root_sql(self):
        changes = [("server_version_num", value) for value in (True, "160004", 159999, 170000)]
        changes += [(name, "different") for name in ("role", "session_role", "client_dn", "client_serial",
            "issuer_dn", "transaction_isolation", "transaction_read_only", "transaction_deferrable")]
        changes += [(name, value) for name in ("ssl", "rolcanlogin") for value in (False, 1, None)]
        changes += [(name, value) for name in IDENTITY_FIELDS[11:] for value in (True, 0, None)]
        for name, value in changes:
            connection = Connection(identity={**identity_row(), name: value})
            with self.subTest(name=name, value=value), self.assertRaises(roots.RevocationRootReadError):
                self.read(connection)
            self.assertEqual((len(connection.cursor_value.metadata_calls), connection.cursor_value.calls), (2, []))
            self.assert_clean_rollback(connection)
        class ForeignString(str):
            pass
        for variant in (None, {}, {**identity_row(), "extra": False},
                {ForeignString(name) if name == "role" else name: value for name, value in identity_row().items()}):
            connection = Connection()
            connection.identity = variant
            with self.subTest(variant=variant), self.assertRaises(roots.RevocationRootReadError):
                self.read(connection)
            self.assertEqual(connection.cursor_value.calls, [])
            self.assert_clean_rollback(connection)

    def test_any_actual_catalog_violation_denies_without_root_worker_or_partial_success(self):
        for violation in ({"kind": "extra-table-select"}, {}, False, 0, "violation"):
            connection = Connection(violation=violation)
            actual = roots._read_revocation_root_inventory_on_work
            with self.subTest(violation=violation), \
                    patch.object(roots, "_read_revocation_root_inventory_on_work", wraps=actual) as called:
                with self.assertRaisesRegex(roots.RevocationRootReadError, "unexpected authority"):
                    self.read(connection)
            self.assertEqual(called.call_count, 0)
            self.assertEqual(len(connection.cursor_value.metadata_calls), 3)
            self.assertEqual(connection.cursor_value.calls, [])
            self.assert_clean_rollback(connection)
        connection = Connection()
        connection.cursor_value.primary.pop()
        with self.assertRaisesRegex(roots.RevocationRootReadError, "incomplete"):
            self.read(connection)
        self.assertEqual(len(connection.cursor_value.calls), 1)
        self.assert_clean_rollback(connection)

    def test_initial_connection_state_and_open_guard_failure_close_returned_handle_before_sql(self):
        for field, value in (("closed", True), ("closed", 0), ("autocommit", True),
                ("autocommit", 0), ("status", 2), ("status", False), ("status", 0.0), ("pgconn", None)):
            connection = Connection()
            if field == "status": connection.info.transaction_status = value
            else: setattr(connection, field, value)
            with self.subTest(field=field, value=value), self.assertRaises(roots.RevocationRootReadError):
                self.read(connection)
            self.assertEqual((connection.cursor_value.metadata_calls, connection.exits), ([], 0))
            self.assertIs(connection.closed, True)
            self.assertEqual(connection.closes, 0 if field == "closed" and value is True else 1)
        connection, meter = Connection(), work()
        def opener():
            meter.charge(input_bytes=1)
            return connection
        with self.assertRaisesRegex(roots.RevocationRootReadError, "shared work"):
            self.read(connection, meter=meter, opener=opener)
        self.assertEqual((connection.closes, connection.exits, connection.cursor_value.metadata_calls), (1, 0, []))
        self.assertEqual(counters(meter), (0, 1, 0))

    def test_configured_tuple_and_root_rows_remain_owned_across_later_callbacks(self):
        owner, connection, meter = self.owner(), Connection(), work()
        expected_primary = copy.deepcopy(connection.cursor_value.primary)
        expected_heads = copy.deepcopy(connection.cursor_value.heads)
        original = owner._snapshot_configuration()
        def change(event):
            if event == "connection.enter":
                object.__setattr__(owner, "_configuration", ("replacement",) * 7)
            if event == "privileges.execute":
                connection.identity.clear()  # no later borrowed identity comparison
            if event == "cursor.exit":
                connection.cursor_value.primary.clear()
                connection.cursor_value.heads[0]["root_digest"] = "sha256:" + "f" * 64
                connection.cursor_value.heads.clear()
        connection.callback = change
        result = self.read(connection, owner=owner, meter=meter)
        RevocationRootInventoryTests().assert_inventory(result, expected_primary, expected_heads)
        self.assertEqual(counters(meter), independent_work(expected_primary, expected_heads)["total"])
        self.assertNotEqual(owner._configuration, original)
        self.assertEqual((connection.commits, connection.rollbacks, connection.closes), (1, 0, 1))

    def test_raw_connection_drift_and_inner_cursor_replacement_deny_and_roll_back(self):
        for event in ("connection.enter", "identity.fetch", "privileges.fetch", "primary.fetch", "head.fetch", "cursor.exit"):
            for mutation in ("pgconn", "status", "autocommit"):
                connection = Connection()
                def change(actual):
                    if actual != event: return
                    if mutation == "pgconn": connection.pgconn = object()
                    if mutation == "status": connection.info.transaction_status = 0 if event != "connection.enter" else 2
                    if mutation == "autocommit": connection.autocommit = True
                connection.callback = change
                with self.subTest(event=event, mutation=mutation), self.assertRaises(roots.RevocationRootReadError):
                    self.read(connection)
                self.assert_clean_rollback(connection)
        for slot in ("_cursor", "_connection", "_identity", "_work", "_started", "_binding"):
            connection, captured = Connection(), []
            actual_constructor = configured._ConnectionCursor
            def construct(*args):
                result = actual_constructor(*args)
                captured.append(result)
                return result
            def change(event):
                if event == "primary.fetch":
                    inner = captured[0]
                    value = (False if slot == "_started" else tuple(list(inner._binding))
                        if slot == "_binding" else object())
                    setattr(inner, slot, value)
            connection.callback = change
            with self.subTest(slot=slot), patch.object(configured, "_ConnectionCursor", side_effect=construct):
                with self.assertRaisesRegex(roots.RevocationRootReadError, "inner cursor binding"):
                    self.read(connection)
            self.assertEqual(len(captured), 1)
            self.assertEqual(len(connection.cursor_value.calls), 1)
            self.assert_clean_rollback(connection)

    def test_metadata_and_scope_callbacks_cannot_change_shared_work_or_suppress_denial(self):
        for event in ("connection.enter", "cursor.open", "cursor.enter", "mode.execute", "identity.fetch",
                "privileges.fetch", "cursor.exit"):
            for mutation in ("spend", "refund", "float", "limits"):
                connection, meter = Connection(), work()
                meter.charge(input_bytes=1)
                observed = []
                def change(actual):
                    if actual != event: return
                    if mutation == "spend": meter.charge(input_bytes=1)
                    if mutation == "refund": meter.input_bytes -= 1
                    if mutation == "float": meter.input_bytes = float(meter.input_bytes)
                    if mutation == "limits": meter.limits = accounting.QueryReadValidationLimits()
                    observed.append((meter.input_bytes, meter.limits))
                connection.callback = change
                with self.subTest(event=event, mutation=mutation), self.assertRaises(ValueError):
                    self.read(connection, meter=meter)
                self.assertEqual(len(observed), 1)
                self.assertEqual(meter.input_bytes, observed[0][0])
                self.assertIs(meter.limits, observed[0][1])
                self.assert_clean_rollback(connection)
        class SuppressingCursor(OwnerCursor):
            def __exit__(self, *arguments):
                super().__exit__(*arguments)
                return True
        connection = Connection(violation={"unexpected": True})
        connection.cursor_value = SuppressingCursor(connection)
        with self.assertRaisesRegex(roots.RevocationRootReadError, "unexpected authority"):
            self.read(connection)
        self.assert_clean_rollback(connection)

    def test_driver_exceptions_context_replacement_and_entry_failure_have_honest_cleanup(self):
        for event in ("connection.enter", "cursor.open", "cursor.enter", "mode.execute", "identity.fetch",
                "privileges.fetch", "primary.fetch", "head.fetch", "cursor.exit"):
            failure, connection = RuntimeError("original driver exception"), Connection()
            def fail(actual):
                if actual == event: raise failure
            connection.callback = fail
            with self.subTest(event=event), self.assertRaises(RuntimeError) as caught:
                self.read(connection)
            self.assertIs(caught.exception, failure)
            self.assertEqual(connection.closes, 1)
            self.assertEqual(connection.rollbacks, 0 if event == "connection.enter" else 1)
            self.assertEqual(connection.exits, 0 if event == "connection.enter" else 1)
            self.assertIs(connection.closed, True)
        class DifferentConnection(Connection):
            def __enter__(self):
                super().__enter__()
                return object()
        class DifferentCursor(OwnerCursor):
            def __enter__(self):
                super().__enter__()
                return object()
        for connection in (DifferentConnection(), Connection()):
            if type(connection) is Connection:
                connection.cursor_value = DifferentCursor(connection)
            with self.assertRaisesRegex(roots.RevocationRootReadError, "replaced its handle"):
                self.read(connection)
            self.assertEqual(connection.cursor_value.metadata_calls, [])
            self.assert_clean_rollback(connection)

    def test_owner_exact_preconsumed_all_minus_one_and_repeated_allowances_do_not_reset(self):
        expected = independent_work(primary_rows(), head_oracle.source_rows())["total"]
        prior = (3, 17, 11)
        for spent in ((0, 0, 0), prior):
            total = add(spent, expected)
            meter, connection = work(total), Connection()
            meter.charge(hashes=spent[0], input_bytes=spent[1], json_nodes=spent[2])
            limits = meter.limits
            self.read(connection, meter=meter)
            self.assertEqual(counters(meter), total)
            self.assertIs(meter.limits, limits)
            for dimension in range(3):
                reduced = tuple(value - (index == dimension) for index, value in enumerate(total))
                meter, connection = work(reduced), Connection()
                meter.charge(hashes=spent[0], input_bytes=spent[1], json_nodes=spent[2])
                with self.subTest(spent=spent, dimension=dimension), self.assertRaises(accounting.QueryReadWorkError):
                    self.read(connection, meter=meter)
                self.assert_clean_rollback(connection)
                self.assertTrue(all(value <= bound for value, bound in zip(counters(meter), reduced)))
        for deficit in (False, True):
            total = tuple(2 * value - (deficit and index == 1) for index, value in enumerate(expected))
            meter = work(total)
            first, second = Connection(), Connection()
            self.read(first, meter=meter)
            if deficit:
                with self.assertRaises(accounting.QueryReadWorkError):
                    self.read(second, meter=meter)
                self.assert_clean_rollback(second)
            else:
                self.read(second, meter=meter)
                self.assertEqual(counters(meter), total)
                self.assertEqual(second.commits, 1)
            self.assertEqual((first.commits, first.closes), (1, 1))

    def test_post_exit_meter_change_or_error_denies_without_claiming_rollback(self):
        for event in ("connection.commit", "connection.close"):
            for mutation in ("meter", "exception"):
                connection, meter = Connection(), work()
                failure = RuntimeError("post-exit uncertainty")
                def change(actual):
                    if actual != event: return
                    if mutation == "meter": meter.charge(input_bytes=1)
                    else: raise failure
                connection.callback = change
                with self.subTest(event=event, mutation=mutation), self.assertRaises(
                        roots.RevocationRootReadError if mutation == "meter" else RuntimeError) as caught:
                    self.read(connection, meter=meter)
                if mutation == "exception": self.assertIs(caught.exception, failure)
                self.assertEqual((connection.commits, connection.rollbacks, connection.exits, connection.closes), (1, 0, 1, 1))
                self.assertIs(connection.closed, True)
                self.assertEqual(len(connection.cursor_value.calls), 2)


if __name__ == "__main__":
    unittest.main()
