#!/usr/bin/env python3
"""Actual counted SQL maintenance over independently seeded component stores.

An approved external harness supplies direct owned0700-socket PG16/UTF8. All
DDL, fixture rows and maintenance calls live in one SERIALIZABLE transaction
and are rolled back. Direct-dispatch cases supply explicit OLD/NEW images;
trigger cases attach the real primary trigger to synthetic business relations
and let PostgreSQL capture the images. The independent fixture owner seeds
complete trees, not accepted bootstrap heads or production business schemas.

These authored native component tests establish no installed authority, whole
transaction work bound, concurrent lock-order guarantee or production grant.
They must remain unrun until the separate prepared verification gates pass.
"""
from __future__ import annotations

import argparse
import copy
from contextlib import contextmanager
from pathlib import Path
import sys
import unittest
import uuid

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate.authority_store.counted_hash_sql import counted_hash_functions_sql
from catchplate.authority_store.counted_projection_sql import counted_projection_functions_sql
from catchplate.authority_store.counted_store_sql import counted_store_ddl
from catchplate.authority_store.counted_path_sql import counted_path_functions_sql
from catchplate.authority_store.counted_maintenance_sql import counted_maintenance_functions_sql
from catchplate.authority_store.primary_tree_sql import framed_digest_function_sql
from catchplate.authority_store import primary_tree_sql, counted_installation
from catchplate.authority_store.wire_json_sql import wire_json_function_sql
from catchplate import authority_index_mutation_reader as mutation_reader
from catchplate import authority_indexed_mutation as indexed
from catchplate.native_postgres_results import run_native_fixture
import test_authority_counted_projection_postgres as row_oracle
import test_authority_counted_store_postgres as storage_oracle
import test_authority_index_join as profile_oracle
import test_authority_index_range as tree_oracle
import test_authority_indexed_mutation as mutation_oracle
import test_authority_primary_tree_postgres as primary_oracle
from test_authority_radix_mutation import IndependentTree
from test_authority_radix_proof import sql_digest, sql_json
from test_authority_root_transition_postgres import production_digest_functions
from test_webauthn_trust_projection_postgres import local_connection_parameters


CONNECTION_PARAMETERS: dict[str, str | int] | None = None
HEADS, LEAVES, NODES = storage_oracle.TABLES
BASE_PROFILES = {
    "webauthn_credentials": "webauthn_credential_id",
    "webauthn_challenges": "webauthn_registration_unused_global",
    "oidc_browser_sessions": "webauthn_session_credential_status",
    "approval_grants": "webauthn_grant_approver_active",
    "control_plane_approvals": "webauthn_control_approval_approved",
    "webauthn_trust_publications": "webauthn_publication_generation",
}
EXPIRIES = {"1970-01-01T00:00:00+00:00": 0,
            "1970-01-01T00:00:00.000001+00:00": 1,
            "1970-01-01T00:00:00.000002+00:00": 2}
I64 = 2**63 - 1


class InstallationConnection:
    """Only adapt the actual DB driver's placeholder and row interfaces."""

    def __init__(self, connection):
        self.connection = connection

    @property
    def in_transaction(self):
        return self.connection.info.transaction_status == psycopg.pq.TransactionStatus.INTRANS

    def execute(self, statement, parameters=()):
        return self.connection.cursor(row_factory=dict_row).execute(
            statement.replace("?", "%s"), parameters)


def image(table, identity="record", **changes):
    return {**row_oracle.sample_row(BASE_PROFILES[table]), "id": identity, **changes}


def projected(index_id, row):
    if row is None:
        return None
    expiry = EXPIRIES[row["expires_at"]] if index_id.startswith("webauthn_registration_") else None
    return mutation_oracle.image_leaf(profile_oracle.expected_profile(index_id), row, expiry)


def independent_models(rows):
    result = {}
    for index_id in storage_oracle.INDEX_IDS:
        profile = profile_oracle.expected_profile(index_id)
        members, identifiers = [], {}
        for row in rows.get(profile.table, {}).values():
            value = projected(index_id, row)
            if value is not None:
                members.append(value)
                identifiers[value.key] = row["id"]
        result[index_id] = (tree_oracle.IndependentIndex(members, profile), identifiers)
    return result


class AuthorityCountedMaintenancePostgresTests(unittest.TestCase):
    def setUp(self):
        if CONNECTION_PARAMETERS is None:
            raise RuntimeError("requires an externally prepared --postgres-dsn")
        self.connection = psycopg.connect(**CONNECTION_PARAMETERS, autocommit=False)
        self.addCleanup(self.rollback_and_close)
        self.connection.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        self.connection.execute("SET LOCAL statement_timeout = '5s'")
        self.connection.execute("SET LOCAL lock_timeout = '250ms'")
        self.connection.execute("SET LOCAL idle_in_transaction_session_timeout = '10s'")
        self.connection.execute("SET LOCAL quote_all_identifiers = off")
        environment = self.connection.execute(
            "SELECT pg_catalog.inet_server_addr(), pg_catalog.getdatabaseencoding(), "
            "pg_catalog.current_setting('server_version_num')::integer, current_user = session_user, "
            "pg_catalog.current_setting('transaction_isolation')").fetchone()
        if (environment is None or environment[0] is not None or environment[1] != "UTF8"
                or not 160000 <= environment[2] < 170000 or environment[3] is not True
                or environment[4] != "serializable"):
            raise RuntimeError("requires a direct Unix-socket PG16/UTF8 serializable session")
        self.schema = "counted_maintenance_" + uuid.uuid4().hex
        self.namespace = '"' + self.schema + '"'
        self.connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(self.schema)))
        self.connection.execute(sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(sql.Identifier(self.schema)))
        for statement in counted_store_ddl(self.namespace):
            self.connection.execute(statement)
        for statement in production_digest_functions(self.namespace):
            self.connection.execute(statement)
        self.connection.execute(framed_digest_function_sql(self.namespace))
        self.connection.execute(wire_json_function_sql(self.namespace))
        for statement in (*counted_hash_functions_sql(self.namespace), *counted_projection_functions_sql(self.namespace),
                          *counted_path_functions_sql(self.namespace), *counted_maintenance_functions_sql(self.namespace)):
            self.connection.execute(statement)
        self.base, self.revisions, self.node_revisions, self.leaf_revisions = {}, {}, {}, {}

    def rollback_and_close(self):
        try:
            self.connection.rollback()
        finally:
            self.connection.close()

    def object(self, name):
        return sql.Identifier(self.schema, name)

    @contextmanager
    def variant(self):
        owned = copy.deepcopy((self.base, self.revisions, self.node_revisions, self.leaf_revisions))
        self.connection.execute("SAVEPOINT counted_maintenance_variant")
        try:
            yield
        finally:
            self.connection.execute("ROLLBACK TO SAVEPOINT counted_maintenance_variant")
            self.connection.execute("RELEASE SAVEPOINT counted_maintenance_variant")
            self.base, self.revisions, self.node_revisions, self.leaf_revisions = owned

    def insert_many(self, table, rows):
        columns = tuple(name for name, _ in storage_oracle.COLUMNS[table])
        if rows:
            with self.connection.cursor() as cursor:
                cursor.executemany(sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(self.object(table),
                    sql.SQL(",").join(sql.Identifier(name) for name in columns),
                    sql.SQL(",").join(sql.Placeholder() for _ in columns)),
                    [tuple(row[name] for name in columns) for row in rows])

    def seed(self, rows=None, *, revision=7):
        self.base = {table: {row["id"]: copy.deepcopy(row) for row in values}
                     for table, values in ({} if rows is None else rows).items()}
        models = independent_models(self.base)
        for index_id, (tree, _) in models.items():
            self.revisions[index_id] = revision
            self.node_revisions.update({(index_id, path): revision for path, (_, count) in tree.nodes.items() if path and count})
            self.leaf_revisions.update({(index_id, path): revision for path in tree.leaves})
        expected = self.expected_store()
        for table in (HEADS, LEAVES, NODES):
            self.insert_many(table, list(expected[table].values()))
        self.assert_store()

    def expected_store(self):
        result = {HEADS: {}, LEAVES: {}, NODES: {}}
        for index_id, (tree, ids) in independent_models(self.base).items():
            profile = tree.profile
            result[HEADS][index_id] = storage_oracle.head(index_id, index_revision=self.revisions[index_id],
                root_digest=tree.root.digest, leaf_count=tree.root.count)
            for key, value in tree.leaves.items():
                result[LEAVES][(index_id, key)] = {"index_id": index_id, "projection_digest": profile.projection_digest,
                    "index_key": key, "primary_id": ids[key], "primary_key_digest": value.primary_key_digest,
                    "primary_row_digest": value.primary_row_digest, "index_revision": self.leaf_revisions[(index_id, key)]}
            for path, (digest, count) in tree.nodes.items():
                if path and count:
                    result[NODES][(index_id, len(path), path)] = {"index_id": index_id,
                        "projection_digest": profile.projection_digest, "depth": len(path), "path_prefix": path,
                        "node_digest": digest, "subtree_count": count,
                        "index_revision": self.node_revisions[(index_id, path)]}
        return result

    def snapshot(self):
        result = {}
        with self.connection.cursor(row_factory=dict_row) as cursor:
            for table in (HEADS, LEAVES, NODES):
                rows = cursor.execute(sql.SQL("SELECT * FROM {}").format(self.object(table))).fetchall()
                fields = {HEADS: ("index_id",), LEAVES: ("index_id", "index_key"),
                          NODES: ("index_id", "depth", "path_prefix")}[table]
                result[table] = {(row[fields[0]] if len(fields) == 1 else tuple(row[name] for name in fields)): row for row in rows}
        return result

    def assert_store(self):
        self.assertEqual(self.snapshot(), self.expected_store())

    def call(self, table, operation, old, new):
        self.connection.execute(sql.SQL("SELECT {}(%s::text,%s::text,%s::jsonb,%s::jsonb)").format(
            self.object("catchplate_policy_authority_counted_apply_event")),
            (table, operation, None if old is None else Jsonb(old), None if new is None else Jsonb(new))).fetchone()

    def apply(self, table, operation, old, new):
        self.call(table, operation, old, new)
        self.record_event(table, old, new)

    def record_event(self, table, old, new, *, assert_current=True):
        # The independent revision oracle is separate from SQL and any Python
        # production projection or mutation evaluator.
        changes = {}
        for index_id in storage_oracle.INDEX_IDS:
            if profile_oracle.descriptor(index_id)["table"] == table:
                before, after = projected(index_id, old), projected(index_id, new)
                changes[index_id] = (before, after)
        if old is not None:
            del self.base[table][old["id"]]
        if new is not None:
            self.base.setdefault(table, {})[new["id"]] = copy.deepcopy(new)
        models = independent_models(self.base)
        for index_id, (before, after) in changes.items():
            if before is None and after is None:
                continue
            self.revisions[index_id] += 1
            revision = self.revisions[index_id]
            paths = {value.key for value in (before, after) if value is not None}
            touched = {path[:depth] for path in paths for depth in range(1, 161)}
            tree = models[index_id][0]
            self.node_revisions = {address: value for address, value in self.node_revisions.items()
                if address[0] != index_id or address[1] in tree.nodes and tree.nodes[address[1]][1] > 0}
            for path in touched:
                if path in tree.nodes and tree.nodes[path][1] > 0:
                    self.node_revisions[(index_id, path)] = revision
            if before is not None:
                self.leaf_revisions.pop((index_id, before.key), None)
            if after is not None:
                self.leaf_revisions[(index_id, after.key)] = revision
        if assert_current:
            self.assert_store()

    def create_business_relations(self):
        # Synthetic complete row shapes isolate trigger provenance/maintenance
        # from unrelated business FKs and admission. No production SQL is rewritten.
        for table in BASE_PROFILES:
            columns = []
            for name, value in image(table).items():
                kind = "jsonb" if type(value) is dict else "bigint" if type(value) is int else "text"
                columns.append(sql.SQL("{} {}{}").format(sql.Identifier(name), sql.SQL(kind),
                    sql.SQL(" PRIMARY KEY" if name == "id" else "")))
            self.connection.execute(sql.SQL("CREATE TABLE {} ({})").format(
                self.object(table), sql.SQL(",").join(columns)))

    def attach_primary_triggers(self, *, create_business=True):
        if create_business:
            self.create_business_relations()
        self.connection.execute(sql.SQL("SET LOCAL search_path TO {}, pg_catalog").format(
            sql.Identifier(self.schema)))
        for name, statement in zip(primary_oracle.ALL_TABLES, primary_oracle.production_table_statements()):
            if name in (primary_oracle.ROOTS, primary_oracle.NODES, primary_oracle.LEAVES, primary_oracle.HISTORY):
                self.connection.execute(statement)
        for statement in primary_tree_sql.authenticated_tree_functions_sql(
                self.namespace, manifest_digest=primary_oracle.MANIFEST):
            self.connection.execute(statement)
        self.primary_events = {table: [] for table in BASE_PROFILES}
        for table in BASE_PROFILES:
            empty = IndependentTree([], table=table, revision=0)
            self.connection.execute(sql.SQL(
                "INSERT INTO {} (table_name,root_revision,root_digest,leaf_count,tree_depth,tree_radix,"
                "manifest_digest,updated_at_epoch_ns) VALUES (%s,0,%s,0,64,16,%s,0)"
            ).format(self.object(primary_oracle.ROOTS)), (table, empty.root.root_digest, primary_oracle.MANIFEST))
            self.connection.execute(sql.SQL(
                "CREATE TRIGGER component_primary_tree AFTER INSERT OR UPDATE OR DELETE ON {} "
                "FOR EACH ROW EXECUTE FUNCTION {}('id')"
            ).format(self.object(table), self.object(primary_oracle.TRIGGER_FUNCTION)))
        self.assert_trigger_trees()

    def stored_root(self, table):
        return primary_oracle.AuthorityPrimaryTreePostgresTests.stored_root(self, table)

    def assert_trigger_trees(self):
        self.assert_store()
        for table in BASE_PROFILES:
            events = self.primary_events[table]
            tree = IndependentTree(list(self.base.get(table, {}).values()), table=table, revision=len(events))
            primary_oracle.AuthorityPrimaryTreePostgresTests.assert_tree(self, tree)
            rows = self.connection.execute(sql.SQL(
                "SELECT pg_catalog.to_jsonb(target) FROM {} target ORDER BY id COLLATE \"C\""
            ).format(self.object(table))).fetchall()
            self.assertEqual([row[0] for row in rows],
                [self.base[table][identity] for identity in sorted(self.base.get(table, {}))])
            journal = self.connection.execute(sql.SQL(
                "SELECT mutation_operation,mutation_key_digest,mutation_row_digest FROM {} "
                "WHERE table_name=%s ORDER BY root_revision"
            ).format(self.object(primary_oracle.HISTORY)), (table,)).fetchall()
            expected = [(operation,
                sql_digest("catchplate.policyAuthorityAuthenticatedKey/v1", table.encode("ascii"), sql_json(key)),
                None if row is None else sql_digest("catchplate.policyAuthorityAuthenticatedRow/v1",
                    table.encode("ascii"), sql_json(row))) for operation, key, row in events]
            self.assertEqual(journal, expected)

    def execute_business_event(self, table, operation, old, new):
        if operation == "INSERT":
            return self.connection.execute(sql.SQL(
                "INSERT INTO {} AS target SELECT * FROM pg_catalog.jsonb_populate_record(NULL::{},%s) "
                "RETURNING pg_catalog.to_jsonb(target)"
            ).format(self.object(table), self.object(table)), (Jsonb(new),)).fetchone()[0]
        if operation == "DELETE":
            return self.connection.execute(sql.SQL(
                "DELETE FROM {} AS target WHERE id=%s RETURNING pg_catalog.to_jsonb(target)"
            ).format(self.object(table)), (old["id"],)).fetchone()[0]
        self.assertEqual(operation, "UPDATE")
        return self.connection.execute(sql.SQL(
            "UPDATE {} AS target SET {} WHERE id=%s RETURNING pg_catalog.to_jsonb(target)"
        ).format(self.object(table), sql.SQL(",").join(sql.SQL("{}=%s").format(sql.Identifier(name))
            for name in new)), (*[Jsonb(value) if type(value) is dict else value for value in new.values()],
                               old["id"])).fetchone()[0]

    def trigger_event(self, table, operation, old, new):
        self.assertEqual(self.execute_business_event(table, operation, old, new), old if new is None else new)
        if operation == "UPDATE" and old["id"] != new["id"]:
            self.record_event(table, old, None, assert_current=False)
            self.record_event(table, None, new)
            events = (("DELETE", {"id": old["id"]}, None), ("INSERT", {"id": new["id"]}, new))
        else:
            self.record_event(table, old, new)
            events = ((operation, {"id": (new if new is not None else old)["id"]}, new),)
        self.primary_events[table].extend(copy.deepcopy(events))
        self.assert_trigger_trees()

    def trigger_snapshot(self):
        names = (*BASE_PROFILES, primary_oracle.ROOTS, primary_oracle.NODES,
                 primary_oracle.LEAVES, primary_oracle.HISTORY)
        result = self.snapshot()
        for table in names:
            result[table] = primary_oracle.AuthorityPrimaryTreePostgresTests.table_rows(self, table)
        return result

    @contextmanager
    def fresh_installation_namespace(self):
        previous = self.schema, self.namespace
        self.schema = "counted_installation_" + uuid.uuid4().hex
        self.namespace = '"' + self.schema + '"'
        try:
            self.connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(self.schema)))
            self.connection.execute(sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(sql.Identifier(self.schema)))
            self.create_business_relations()
            yield InstallationConnection(self.connection)
        finally:
            self.schema, self.namespace = previous

    def reject(self, table, operation, old, new, message=None):
        before = self.snapshot()
        with self.variant():
            context = (self.assertRaises(psycopg.errors.RaiseException) if message is None else
                       self.assertRaisesRegex(psycopg.errors.RaiseException, message))
            with context:
                self.call(table, operation, old, new)
        self.assertEqual(self.snapshot(), before)

    def change_stored(self, table, identity, **changes):
        fields = {HEADS: ("index_id",), LEAVES: ("index_id", "index_key"),
                  NODES: ("index_id", "depth", "path_prefix")}[table]
        values = (identity,) if len(fields) == 1 else identity
        where = sql.SQL(" AND ").join(sql.SQL("{}=%s").format(sql.Identifier(name)) for name in fields)
        if changes:
            statement = sql.SQL("UPDATE {} SET {} WHERE {}").format(self.object(table),
                sql.SQL(",").join(sql.SQL("{}=%s").format(sql.Identifier(name)) for name in changes), where)
            parameters = (*changes.values(), *values)
        else:
            statement = sql.SQL("DELETE FROM {} WHERE {}").format(self.object(table), where)
            parameters = values
        self.assertEqual(self.connection.execute(statement, parameters).rowcount, 1)

    def test_all_six_relations_and_eleven_profiles_insert_delete_exact_full_trees(self):
        self.seed()
        for table in BASE_PROFILES:
            with self.subTest(table=table):
                row = image(table)
                self.apply(table, "INSERT", None, row)
                self.apply(table, "DELETE", row, None)
                self.assertEqual(len(self.snapshot()[LEAVES]), 0)
                self.assertEqual(len(self.snapshot()[NODES]), 0)

    def test_fullrow_and_equal_updates_stamp_only_touched_paths_and_member_heads(self):
        table = "webauthn_credentials"
        row, untouched = image(table, "target"), image(table, "retained", credential_id="other", user_id="other")
        self.seed({table: [row, untouched]})
        changed = {**row, "sign_count": row["sign_count"] + 1}
        self.apply(table, "UPDATE", row, changed)
        self.apply(table, "UPDATE", changed, copy.deepcopy(changed))
        self.assertTrue(any(value == 7 for value in self.node_revisions.values()))
        self.assertTrue(any(value == 9 for value in self.node_revisions.values()))

    def test_credential_partition_moves_and_live_membership_exit_enter(self):
        table = "webauthn_credentials"
        row = image(table)
        self.seed({table: [row]})
        changed = {**row, "credential_id": "next-credential", "user_id": "next-user", "revoked_at": "revoked"}
        self.apply(table, "UPDATE", row, changed)
        self.assertEqual(self.revisions["webauthn_credential_live_trust"], 8)
        restored = {**changed, "revoked_at": None}
        self.apply(table, "UPDATE", changed, restored)

    def test_challenge_expiry_user_partition_and_used_membership_moves(self):
        table = "webauthn_challenges"
        row = image(table)
        self.seed({table: [row]})
        changed = {**row, "user_id": "next-user", "expires_at": "1970-01-01T00:00:00.000002+00:00"}
        self.apply(table, "UPDATE", row, changed)
        used = {**changed, "used_at": "used"}
        self.apply(table, "UPDATE", changed, used)
        self.assertEqual(len(self.snapshot()[LEAVES]), 0)
        self.assertEqual(len(self.snapshot()[NODES]), 0)

    def test_session_grant_and_control_approval_membership_transitions(self):
        self.seed()
        for table, field, excluded in (("oidc_browser_sessions", "status", "revoked"),
                                      ("approval_grants", "state", "expired"),
                                      ("control_plane_approvals", "status", "rejected")):
            with self.subTest(table=table):
                row = image(table)
                self.apply(table, "INSERT", None, row)
                changed = {**row, field: excluded}
                self.apply(table, "UPDATE", row, changed)
                self.apply(table, "UPDATE", changed, row)
                self.apply(table, "DELETE", row, None)

    def test_publication_bundle_status_and_generation_moves_all_fixed_profiles(self):
        table = "webauthn_trust_publications"
        row = image(table)
        self.seed({table: [row]})
        changed = {**row, "bundle_digest": "new-bundle", "status": "published", "rollback_epoch": 1, "sequence": -1}
        self.apply(table, "UPDATE", row, changed)
        self.assertEqual({self.revisions[name] for name in self.revisions if "publication" in name}, {8})

    def test_both_nonmember_events_verify_root_and_leave_all_records_unchanged(self):
        table = "approval_grants"
        member = image(table, "retained")
        excluded = image(table, "excluded", state="expired")
        self.seed({table: [member, excluded]})
        before = self.snapshot()
        changed = {**excluded, "fixture_payload": {"different": True}}
        self.apply(table, "UPDATE", excluded, changed)
        self.apply(table, "DELETE", changed, None)
        self.apply(table, "INSERT", None, excluded)
        self.assertEqual(self.snapshot(), before)
        index_id = "webauthn_grant_approver_active"
        with self.variant():
            self.change_stored(HEADS, index_id, root_digest="sha256:" + "f" * 64)
            self.reject(table, "UPDATE", excluded, changed)
        # Nonmembership is not permission to ignore an existing indexed PK.
        false_image = {**member, "state": "expired"}
        self.reject(table, "UPDATE", false_image, false_image)

    def test_primary_key_changes_require_explicit_delete_then_insert_events(self):
        table = "webauthn_credentials"
        old, new = image(table, "old"), image(table, "new")
        self.seed({table: [old]})
        self.reject(table, "UPDATE", old, new, "normalized delete and insert")
        self.apply(table, "DELETE", old, None)
        self.assertEqual(self.snapshot()[NODES], {})
        self.apply(table, "INSERT", None, new)
        self.assertEqual({self.revisions[name] for name in self.revisions if name.startswith("webauthn_credential_")}, {9})
        # These are two component statements, not a claimed atomic-pair API.

    def test_event_table_operation_images_and_referenced_field_types_are_closed(self):
        table, row = "webauthn_credentials", image("webauthn_credentials")
        self.seed()
        cases = ((None, "INSERT", None, row), ("unknown", "INSERT", None, row),
                 (table, None, None, row), (table, "insert", None, row),
                 (table, "UPSERT", None, row), (table, "INSERT", row, row),
                 (table, "INSERT", None, None), (table, "DELETE", None, None),
                 (table, "DELETE", row, row), (table, "UPDATE", None, row),
                 (table, "UPDATE", row, None), (table, "INSERT", None, []),
                 (table, "INSERT", None, True), (table, "INSERT", None, {**row, "id": None}),
                 (table, "INSERT", None, {**row, "attestation_trusted": True}),
                 (table, "INSERT", None, {name: value for name, value in row.items() if name != "credential_id"}))
        for ordinal, case in enumerate(cases):
            with self.subTest(case=ordinal):
                self.reject(*case)
        self.apply(table, "INSERT", None, row)

    def test_every_required_head_must_exist_even_for_an_excluded_profile(self):
        self.seed()
        table = "webauthn_credentials"
        row = image(table, revoked_at="revoked")
        for index_id in ("webauthn_credential_id", "webauthn_credential_live_trust", "webauthn_credential_user_history"):
            with self.subTest(index_id=index_id), self.variant():
                self.change_stored(HEADS, index_id)
                self.reject(table, "INSERT", None, row, "required head is absent")
        # Exact source-profile corruption is prohibited by the actual DDL;
        # this fixture never disables its constraints to bypass that boundary.
        self.apply(table, "INSERT", None, row)

    def test_old_leaf_fullrow_commitment_and_stored_primary_identity_must_match(self):
        table, row = "webauthn_credentials", image("webauthn_credentials")
        self.seed({table: [row]})
        index_id = "webauthn_credential_id"
        key = projected(index_id, row).key
        for changes in ({"primary_row_digest": "sha256:" + "f" * 64}, {"primary_id": "other"}):
            with self.subTest(changes=changes), self.variant():
                self.change_stored(LEAVES, (index_id, key), **changes)
                self.reject(table, "DELETE", row, None)
        false_old = {**row, "fixture_payload": {"not": "the stored full row"}}
        self.reject(table, "UPDATE", false_old, row)
        with self.variant():
            self.change_stored(LEAVES, (index_id, key))
            self.reject(table, "DELETE", row, None)
        self.apply(table, "DELETE", row, None)

    def test_insert_requires_absent_target_and_absent_existing_business_identity(self):
        table, row = "webauthn_credentials", image("webauthn_credentials")
        self.seed({table: [row]})
        self.reject(table, "INSERT", None, row)
        # A new partition is still an occupied BusinessKey. The source UNIQUE
        # constraint also prevents inventing two stored paths for the same PK.
        moved = {**row, "credential_id": "different", "user_id": "different"}
        self.reject(table, "INSERT", None, moved)
        fresh = {**moved, "id": "genuinely-new"}
        self.apply(table, "INSERT", None, fresh)

    def test_corrupt_or_missing_opened_cache_and_target_node_are_not_repaired(self):
        table, row = "webauthn_credentials", image("webauthn_credentials")
        self.seed({table: [row]})
        index_id, key = "webauthn_credential_id", projected("webauthn_credential_id", row).key
        for depth in (1, 80, 159, 160):
            for missing in (False, True):
                with self.subTest(depth=depth, missing=missing), self.variant():
                    self.change_stored(NODES, (index_id, depth, key[:depth]),
                                       **({} if missing else {"node_digest": "sha256:" + "f" * 64}))
                    self.reject(table, "UPDATE", row, row)
        self.apply(table, "UPDATE", row, row)

    def test_corrupt_or_missing_positive_opaque_sibling_rejects_before_root(self):
        table = "webauthn_credentials"
        row, sibling = image(table, "target"), image(table, "sibling", credential_id="another")
        self.seed({table: [row, sibling]})
        index_id = "webauthn_credential_id"
        target_key, sibling_key = projected(index_id, row).key, projected(index_id, sibling).key
        divergence = next(position for position, pair in enumerate(zip(target_key, sibling_key)) if pair[0] != pair[1])
        prefix = sibling_key[:divergence + 1]
        self.assertFalse(target_key.startswith(prefix))
        self.assertLess(len(prefix), 160)
        self.assertIn((index_id, len(prefix), prefix), self.snapshot()[NODES])
        for changes in ({"node_digest": "sha256:" + "f" * 64}, {"subtree_count": 2}, {}):
            with self.subTest(changes=changes), self.variant():
                self.change_stored(NODES, (index_id, len(prefix), prefix), **changes)
                self.reject(table, "UPDATE", row, row)
        self.apply(table, "UPDATE", row, row)

    def test_future_leaf_and_opened_or_opaque_node_revisions_are_rejected(self):
        table = "webauthn_credentials"
        row, sibling = image(table, "target"), image(table, "sibling", credential_id="another")
        self.seed({table: [row, sibling]})
        index_id = "webauthn_credential_id"
        key, other = projected(index_id, row).key, projected(index_id, sibling).key
        divergence = next(position for position, pair in enumerate(zip(key, other)) if pair[0] != pair[1])
        opaque = other[:divergence + 1]
        for target, identity in ((LEAVES, (index_id, key)), (NODES, (index_id, 80, key[:80])),
                                 (NODES, (index_id, 160, key)), (NODES, (index_id, len(opaque), opaque))):
            with self.subTest(target=target, identity=identity), self.variant():
                self.change_stored(target, identity, index_revision=8)
                self.reject(table, "UPDATE", row, row)
        self.apply(table, "UPDATE", row, row)

    def test_revision_overflow_denies_member_event_but_nonmember_does_not_increment(self):
        table = "approval_grants"
        member, excluded = image(table, "member"), image(table, "excluded", state="expired")
        self.seed({table: [member, excluded]})
        index_id = "webauthn_grant_approver_active"
        self.change_stored(HEADS, index_id, index_revision=I64)
        self.revisions[index_id] = I64
        self.assert_store()
        self.reject(table, "UPDATE", member, member)
        self.apply(table, "UPDATE", excluded, {**excluded, "fixture_payload": ["changed"]})
        self.assertEqual(self.revisions[index_id], I64)

    def test_late_profile_failure_rolls_back_all_effects_and_allows_exact_retry(self):
        table, row = "webauthn_credentials", image("webauthn_credentials")
        self.seed({table: [row]})
        ordered_ids = sorted(name for name in storage_oracle.INDEX_IDS if name.startswith("webauthn_credential_"))
        self.assertEqual(ordered_ids[-1], "webauthn_credential_user_history")
        index_id = ordered_ids[-1]
        key = projected(index_id, row).key
        before = self.snapshot()
        with self.variant():
            self.change_stored(LEAVES, (index_id, key), primary_row_digest="sha256:" + "f" * 64)
            corrupt_before = self.snapshot()
            self.reject(table, "UPDATE", row, {**row, "sign_count": row["sign_count"] + 1})
            self.assertEqual(self.snapshot(), corrupt_before)
        self.assertEqual(self.snapshot(), before)
        # Real dispatcher order reaches the last profile after earlier calls;
        # final retained state, not an instrumented timing claim, is asserted.
        self.apply(table, "UPDATE", row, {**row, "sign_count": row["sign_count"] + 1})

    def test_real_function_catalog_invoker_contract_has_no_trigger_attachment(self):
        names = ("catchplate_policy_authority_counted_apply_event", "catchplate_policy_authority_counted_apply_index")
        rows = self.connection.execute(
            "SELECT p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid), "
            "pg_catalog.pg_get_function_result(p.oid), p.provolatile, p.prosecdef, p.proconfig "
            "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname=%s AND p.proname=ANY(%s::text[]) ORDER BY p.proname COLLATE \"C\"",
            (self.schema, list(names))).fetchall()
        self.assertEqual([row[:5] for row in rows],
                         [(names[0], "authenticated_table text, mutation_operation text, old_row jsonb, new_row jsonb",
                           "void", "v", False),
                          (names[1], "index_identity text, mutation_operation text, old_row jsonb, new_row jsonb",
                           "void", "v", False)])
        for row in rows:
            self.assertEqual(row[5], ["search_path=pg_catalog, " + self.schema + ", pg_temp"])
        triggers = self.connection.execute(
            "SELECT t.tgname FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid "
            "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND NOT t.tgisinternal",
            (self.schema,)).fetchall()
        self.assertEqual(triggers, [])
        self.assertEqual({table: len(rows) for table, rows in self.snapshot().items()}, {HEADS: 0, LEAVES: 0, NODES: 0})
        for renderer in (counted_path_functions_sql, counted_maintenance_functions_sql):
            for invalid in (None, "unquoted", '"UPPER"', '"bad-name"', '"x"; SELECT 1'):
                with self.subTest(renderer=renderer.__name__, invalid=invalid), self.assertRaises(ValueError):
                    renderer(invalid)

    def test_trigger_all_six_tables_and_eleven_profiles_update_exact_stores(self):
        self.seed(revision=0)
        self.attach_primary_triggers()
        for table in BASE_PROFILES:
            with self.subTest(table=table):
                before = image(table)
                after = copy.deepcopy(before)
                after["fixture_payload"]["retained"].append("full-row update")
                self.trigger_event(table, "INSERT", None, before)
                self.trigger_event(table, "UPDATE", before, after)
                self.trigger_event(table, "DELETE", after, None)
        self.assertEqual(set(self.revisions.values()), {3})
        self.assertEqual(len(self.snapshot()[LEAVES]), 0)
        self.assertEqual(len(self.snapshot()[NODES]), 0)

    def test_trigger_same_key_row_update_and_equal_update_keep_exact_revisions(self):
        self.seed(revision=0)
        self.attach_primary_triggers()
        table = "webauthn_credentials"
        before = image(table, "credential-row")
        self.trigger_event(table, "INSERT", None, before)
        leaves = copy.deepcopy(self.snapshot()[LEAVES])
        after = {**before, "sign_count": before["sign_count"] + 1}
        self.trigger_event(table, "UPDATE", before, after)
        updated = self.snapshot()[LEAVES]
        self.assertEqual(set(updated), set(leaves))
        self.assertEqual(len(updated), 3)
        for key in updated:
            self.assertEqual(updated[key]["primary_key_digest"], leaves[key]["primary_key_digest"])
            self.assertNotEqual(updated[key]["primary_row_digest"], leaves[key]["primary_row_digest"])
            self.assertEqual(updated[key]["index_revision"], 2)
        self.trigger_event(table, "UPDATE", after, after)
        self.assertEqual(self.stored_root(table).root_revision, 3)
        self.assertEqual({row["index_revision"] for row in self.snapshot()[LEAVES].values()}, {3})

    def test_trigger_partition_and_membership_moves_match_all_source_profiles(self):
        self.seed(revision=0)
        self.attach_primary_triggers()
        moves = {
            "webauthn_credentials": {"credential_id": "other-credential", "user_id": "other-user", "revoked_at": "revoked"},
            "webauthn_challenges": {"user_id": "other-user", "expires_at": "1970-01-01T00:00:00.000002+00:00"},
            "oidc_browser_sessions": {"bound_webauthn_credential_id": "other-credential", "status": "revoked"},
            "approval_grants": {"approver_webauthn_credential_id": "other-credential", "state": "revoked"},
            "control_plane_approvals": {"approver_webauthn_credential_id": "other-credential", "status": "revoked"},
            "webauthn_trust_publications": {"bundle_digest": "other-bundle", "status": "published", "sequence": 2},
        }
        for table, changes in moves.items():
            with self.subTest(table=table):
                before = image(table)
                self.trigger_event(table, "INSERT", None, before)
                after = {**before, **changes}
                self.trigger_event(table, "UPDATE", before, after)
                self.trigger_event(table, "UPDATE", after, before)
        self.assertEqual(set(self.revisions.values()), {3})
        self.assertEqual(len(self.snapshot()[LEAVES]), 11)

    def test_trigger_primary_key_change_is_exact_delete_then_insert(self):
        self.seed(revision=0)
        self.attach_primary_triggers()
        for table in BASE_PROFILES:
            with self.subTest(table=table):
                before, after = image(table, "old-record"), image(table, "new-record")
                self.trigger_event(table, "INSERT", None, before)
                old_keys = {address for address, row in self.snapshot()[LEAVES].items()
                            if row["primary_id"] == "old-record"
                            and profile_oracle.descriptor(address[0])["table"] == table}
                self.trigger_event(table, "UPDATE", before, after)
                self.assertEqual(self.stored_root(table).root_revision, 3)
                self.assertFalse(old_keys & set(self.snapshot()[LEAVES]))
                self.assertEqual([event[0] for event in self.primary_events[table]], ["INSERT", "DELETE", "INSERT"])
        self.assertEqual(set(self.revisions.values()), {3})
        self.assertEqual({row["primary_id"] for row in self.snapshot()[LEAVES].values()}, {"new-record"})

    def test_trigger_later_failure_rolls_back_business_primary_and_counted_then_retries(self):
        self.seed(revision=0)
        self.attach_primary_triggers()
        table = "webauthn_credentials"
        before = image(table)
        self.trigger_event(table, "INSERT", None, before)
        after = {**before, "sign_count": before["sign_count"] + 1}
        snapshot = self.trigger_snapshot()
        with self.variant():
            # PostgreSQL orders same-kind triggers by name. This observer raises
            # only after the real primary/count event has advanced both stores.
            self.connection.execute(sql.SQL("""
                CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $failure$
                BEGIN
                    IF (SELECT root_revision FROM {} WHERE table_name='webauthn_credentials') IS DISTINCT FROM 2
                       OR (SELECT count(*) FROM {} WHERE table_name='webauthn_credentials'
                           AND index_revision=2) <> 3 THEN
                        RAISE EXCEPTION 'fixture did not reach both stores';
                    END IF;
                    RAISE EXCEPTION 'fixture later failure after both stores';
                END; $failure$
            """).format(self.object("component_later_failure"), self.object(primary_oracle.ROOTS), self.object(HEADS)))
            self.connection.execute(sql.SQL(
                "CREATE TRIGGER zzz_component_later_failure AFTER UPDATE ON {} "
                "FOR EACH ROW EXECUTE FUNCTION {}()"
            ).format(self.object(table), self.object("component_later_failure")))
            with self.assertRaisesRegex(psycopg.errors.RaiseException, "fixture later failure after both stores"):
                self.execute_business_event(table, "UPDATE", before, after)
        self.assertEqual(self.trigger_snapshot(), snapshot)
        self.assert_trigger_trees()
        self.trigger_event(table, "UPDATE", before, after)

    def test_trigger_missing_required_head_denies_without_inventing_genesis(self):
        self.seed(revision=0)
        self.attach_primary_triggers()
        table = "webauthn_credentials"
        absent = "webauthn_credential_user_history"
        self.change_stored(HEADS, absent)
        snapshot = self.trigger_snapshot()
        with self.variant():
            with self.assertRaisesRegex(psycopg.errors.RaiseException, "counted event required head is absent"):
                self.execute_business_event(table, "INSERT", None, image(table))
        self.assertEqual(self.trigger_snapshot(), snapshot)
        self.assertNotIn(absent, self.snapshot()[HEADS])
        self.assertEqual(len(self.snapshot()[HEADS]), 10)
        self.assertEqual(self.stored_root(table).root_revision, 0)

    def test_installation_fresh_empty_genesis_and_populated_repeat_preserve_exact_store(self):
        with self.fresh_installation_namespace() as connection:
            counted_installation.prepare_counted_store(connection, self.namespace)
            self.revisions = {name: 0 for name in storage_oracle.INDEX_IDS}
            self.assert_store()
            for statement in (*production_digest_functions(self.namespace),
                              framed_digest_function_sql(self.namespace), wire_json_function_sql(self.namespace),
                              *counted_installation.counted_functions_sql(self.namespace)):
                self.connection.execute(statement)
            self.attach_primary_triggers(create_business=False)
            row = image("webauthn_credentials")
            self.trigger_event("webauthn_credentials", "INSERT", None, row)
            snapshot = self.trigger_snapshot()
            counted_installation.prepare_counted_store(connection, self.namespace)
            self.assertEqual(self.trigger_snapshot(), snapshot)
            self.assert_trigger_trees()

    def test_installation_populated_fresh_and_missing_existing_head_are_never_repaired(self):
        with self.fresh_installation_namespace() as connection:
            row = image("webauthn_credentials")
            self.assertEqual(self.execute_business_event("webauthn_credentials", "INSERT", None, row), row)
            with self.assertRaisesRegex(counted_installation.CountedInstallationError,
                    "counted genesis requires empty source tables"):
                counted_installation.prepare_counted_store(connection, self.namespace)
            found = self.connection.execute(
                "SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname=%s AND c.relname=ANY(%s::text[])",
                (self.schema, [HEADS, LEAVES, NODES])).fetchall()
            self.assertEqual(found, [])
            actual = self.connection.execute(sql.SQL("SELECT pg_catalog.to_jsonb(target) FROM {} target").format(
                self.object("webauthn_credentials"))).fetchall()
            self.assertEqual(actual, [(row,)])
        self.seed(revision=0)
        self.create_business_relations()
        self.change_stored(HEADS, "webauthn_credential_user_history")
        snapshot = self.snapshot()
        with self.assertRaisesRegex(counted_installation.CountedInstallationError,
                "counted installation requires the complete eleven-head inventory"):
            counted_installation.prepare_counted_store(InstallationConnection(self.connection), self.namespace)
        self.assertEqual(self.snapshot(), snapshot)
        self.assertEqual(len(snapshot[HEADS]), 10)

    def require_absent_reader_namespace(self):
        # This native reader uses the exact production-qualified SQL unchanged.
        # A prepared disposable cluster is necessary but does not authorize
        # adopting even an empty pre-existing canonical namespace.
        row = self.connection.execute(
            "SELECT oid FROM pg_catalog.pg_namespace WHERE nspname=%s",
            ("catchplate_metadata",)).fetchone()
        if row is not None:
            raise RuntimeError("reader fixture canonical namespace already exists")

    def create_reader_store(self):
        self.require_absent_reader_namespace()
        self.connection.execute('CREATE SCHEMA "catchplate_metadata"')
        self.connection.execute('REVOKE ALL ON SCHEMA "catchplate_metadata" FROM PUBLIC')
        for statement in counted_store_ddl('"catchplate_metadata"'):
            self.connection.execute(statement)

    def seed_reader_store(self, fixture):
        self.create_reader_store()
        # Reuse the independent complete population oracle, not any successful
        # production projection, reader, maintenance or proof result.
        self.seed(fixture.tables, revision=29)
        expected = self.expected_store()
        for table in (HEADS, LEAVES, NODES):
            columns = tuple(name for name, _ in storage_oracle.COLUMNS[table])
            rows = list(expected[table].values())
            if rows:
                with self.connection.cursor() as cursor:
                    cursor.executemany(sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                        sql.Identifier("catchplate_metadata", table),
                        sql.SQL(",").join(sql.Identifier(name) for name in columns),
                        sql.SQL(",").join(sql.Placeholder() for _ in columns)),
                        [tuple(row[name] for name in columns) for row in rows])

    def reader_store_snapshot(self):
        return {table: tuple(row[0] for row in self.connection.execute(
            sql.SQL('SELECT pg_catalog.to_jsonb(t) FROM {} AS t '
                    'ORDER BY pg_catalog.to_jsonb(t)::text COLLATE "C"').format(
                        sql.Identifier("catchplate_metadata", table))).fetchall())
            for table in (HEADS, LEAVES, NODES)}

    def acquire_reader(self, fixture):
        arguments = fixture.arguments()
        before = arguments.pop("index_inputs")
        arguments["index_before_heads"] = tuple(indexed.IndexedMutationHead(
            item.index_id, item.index_revision, item.index_root) for item in before)
        self.reader_trace = []
        entries = self.reader_trace

        class Trace:
            # This observes every actual reader SELECT. It intentionally grants
            # no production PlannerTrace or operation-manifest admission.
            def read(self, table, key):
                entries.append((table, copy.deepcopy(key)))

        with self.connection.cursor(row_factory=dict_row) as cursor:
            return mutation_reader.acquire_indexed_primary_batch(cursor, trace=Trace(), **arguments)

    def assert_reader(self, fixture):
        before = self.reader_store_snapshot()
        actual = self.acquire_reader(fixture)
        self.assertEqual(actual.index_inputs, fixture.arguments()["index_inputs"])
        self.assertEqual(actual.result.primary.business_after_roots,
            tuple(fixture.after_trees[table].root for table in sorted(fixture.after_trees)))
        self.assertEqual(actual.result.after_heads, tuple(indexed.IndexedMutationHead(
            name, info["revision_before"] + info["revision_delta"], info["after"].root)
            for name, info in sorted(fixture.indexes.items())))
        self.assertTrue(self.reader_trace)
        self.assertEqual(self.reader_store_snapshot(), before)
        return actual

    def reader_credential_fixture(self, *, move=False):
        first = mutation_oracle.credential("credential")
        other = mutation_oracle.credential("opaque", user_id="other-user", credential_id="other-id")
        after = {**first, "sign_count": 4}
        if move:
            after.update(user_id="moved-user", credential_id="moved-id")
        return mutation_oracle.MutationFixture({"webauthn_credentials": [first, other]},
            (("webauthn_credentials", "credential", "UPDATE", after),))

    def test_reader_all_eleven_profiles_execute_exact_sql_without_store_writes(self):
        tables = {table: [image(table, "same-id")] for table in BASE_PROFILES}
        tables["webauthn_challenges"][0]["expires_at"] = "1970-01-01T00:00:00+00:00"
        actions = tuple((table, "same-id", "UPDATE", {**rows[0], "nonselector": "new-雪"})
            for table, rows in sorted(tables.items()))
        fixture = mutation_oracle.MutationFixture(tables, actions, expiry_before={"same-id": 0})
        self.seed_reader_store(fixture)
        actual = self.assert_reader(fixture)
        self.assertEqual(len(actual.index_inputs), 11)
        self.assertEqual({table for table, _ in self.reader_trace}, {LEAVES, NODES})

    def test_reader_partition_moves_prove_new_absence_with_real_parameter_batches(self):
        fixture = self.reader_credential_fixture(move=True)
        self.seed_reader_store(fixture)
        self.assertEqual({name: len(info["targets"]) for name, info in fixture.indexes.items()}, {
            "webauthn_credential_id": 2,
            "webauthn_credential_user_history": 2,
            "webauthn_credential_live_trust": 1,
        })
        actual = self.assert_reader(fixture)
        self.assertEqual(len(actual.result.after_heads), 3)
        self.assertTrue(all(item.index_revision == 30 for item in actual.result.after_heads))

    def test_reader_nonmember_paths_still_acquire_root_children_and_fold_populated_roots(self):
        excluded = image("webauthn_challenges", "excluded", challenge_type="authentication",
            expires_at="1970-01-01T00:00:00+00:00")
        retained = {**excluded, "id": "retained", "challenge_type": "registration"}
        fixture = mutation_oracle.MutationFixture({"webauthn_challenges": [excluded, retained]},
            (("webauthn_challenges", "excluded", "UPDATE", {**excluded, "used_at": "used"}),),
            expiry_before={"excluded": 0, "retained": 0})
        self.seed_reader_store(fixture)
        actual = self.assert_reader(fixture)
        self.assertEqual(actual.result.before_heads, actual.result.after_heads)
        self.assertEqual([table for table, _ in self.reader_trace], [NODES, NODES])
        for _, metrics in actual.result.metrics.indexes:
            self.assertEqual((metrics.changes, metrics.opened_nodes, metrics.child_slots), (0, 1, 32))

    def test_reader_future_records_and_wrong_primary_identity_remain_visible_and_deny(self):
        fixture = self.reader_credential_fixture()
        self.seed_reader_store(fixture)
        self.assert_reader(fixture)
        name, info = next(iter(sorted(fixture.indexes.items())))
        target = next(iter(info["targets"]))
        for assignment, value in (("index_revision", 30), ("primary_id", "wrong-primary-id")):
            with self.subTest(field=assignment), self.variant():
                self.connection.execute(sql.SQL("UPDATE {} SET {}=%s WHERE index_id=%s AND index_key=%s").format(
                    sql.Identifier("catchplate_metadata", LEAVES), sql.Identifier(assignment)), (value, name, target))
                with self.assertRaises(ValueError):
                    self.acquire_reader(fixture)
                self.assertTrue(self.reader_trace)
            self.assert_reader(fixture)

    def test_reader_missing_leaf_and_corrupt_opaque_sibling_fail_then_repair_replays(self):
        fixture = self.reader_credential_fixture()
        self.seed_reader_store(fixture)
        self.assert_reader(fixture)
        name, info = next(iter(sorted(fixture.indexes.items())))
        target = next(iter(info["targets"]))
        opaque = next(item for item in info["frontier"] if hasattr(item, "prefix"))
        for area in ("leaf", "opaque"):
            with self.subTest(area=area), self.variant():
                if area == "leaf":
                    self.connection.execute(sql.SQL("DELETE FROM {} WHERE index_id=%s AND index_key=%s").format(
                        sql.Identifier("catchplate_metadata", LEAVES)), (name, target))
                else:
                    self.connection.execute(sql.SQL(
                        "UPDATE {} SET node_digest=%s WHERE index_id=%s AND depth=%s AND path_prefix=%s").format(
                            sql.Identifier("catchplate_metadata", NODES)),
                        ("sha256:" + "f" * 64, name, len(opaque.prefix), opaque.prefix))
                with self.assertRaises(ValueError):
                    self.acquire_reader(fixture)
                self.assertTrue(self.reader_trace)
            self.assert_reader(fixture)

    def test_reader_namespace_refusal_preserves_existing_empty_and_sentinel_schemas(self):
        self.require_absent_reader_namespace()
        self.connection.execute('CREATE SCHEMA "catchplate_metadata"')
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            self.create_reader_store()
        self.connection.execute('CREATE TABLE "catchplate_metadata".reader_fixture_sentinel (value text NOT NULL)')
        self.connection.execute('INSERT INTO "catchplate_metadata".reader_fixture_sentinel VALUES (%s)', ("keep",))
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            self.create_reader_store()
        self.assertEqual(self.connection.execute(
            'SELECT value FROM "catchplate_metadata".reader_fixture_sentinel').fetchall(), [("keep",)])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--postgres-dsn", required=True)
    parser.add_argument("--prepared-result")
    arguments, test_arguments = parser.parse_known_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    run_native_fixture("scripts/test_authority_counted_maintenance_postgres.py",
                       argv=[sys.argv[0], *test_arguments], result_path=arguments.prepared_result)
