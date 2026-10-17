#!/usr/bin/env python3
"""Actual counted-store DDL in a rollback-owned, prepared PG16 schema.

The externally approved harness provides a direct owned0700 Unix socket and a
PG16/UTF8 session. This fixture starts no engine and commits nothing. It installs
the real three fresh table declarations, then uses explicit fixture-owner data
to test their structural constraints. These rows are not an authenticated
bootstrap or a maintained population. No primary/index trigger, maintenance
entrypoint, current head authority, runtime grant or kernel is installed.

Catalog/constraint observations do not supply production catalog admission.
The future writer must still verify before roots and record/head revisions;
DDL alone does not establish either relationship. All tests remain authored
until the separate approved prepared verification phase executes them.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from pathlib import Path
import sys
import unittest
import uuid

import psycopg
from psycopg import sql


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate.authority_store import counted_store_sql as store
from catchplate.native_postgres_results import run_native_fixture
import test_authority_index_join as profile_oracle
import test_authority_index_range as tree_oracle
from test_webauthn_trust_projection_postgres import local_connection_parameters


CONNECTION_PARAMETERS: dict[str, str | int] | None = None
HEADS = "policy_authority_counted_index_heads"
LEAVES = "policy_authority_counted_index_leaves"
NODES = "policy_authority_counted_index_nodes"
TABLES = (HEADS, LEAVES, NODES)
INDEX_IDS = (
    "webauthn_credential_id", "webauthn_credential_user_history", "webauthn_credential_live_trust",
    "webauthn_registration_unused_global", "webauthn_registration_unused_user",
    "webauthn_session_credential_status", "webauthn_grant_approver_active",
    "webauthn_control_approval_approved", "webauthn_publication_bundle_digest",
    "webauthn_publication_status", "webauthn_publication_generation",
)
COLUMNS = {
    HEADS: (("index_id", "text"), ("table_name", "text"), ("counted_profile", "text"),
            ("projection_digest", "text"), ("projection_manifest_digest", "text"),
            ("index_revision", "int8"), ("root_digest", "text"), ("leaf_count", "int8")),
    LEAVES: (("index_id", "text"), ("projection_digest", "text"), ("index_key", "text"),
             ("primary_id", "text"), ("primary_key_digest", "text"), ("primary_row_digest", "text"),
             ("index_revision", "int8")),
    NODES: (("index_id", "text"), ("projection_digest", "text"), ("depth", "int4"),
            ("path_prefix", "text"), ("node_digest", "text"), ("subtree_count", "int8"),
            ("index_revision", "int8")),
}
I64 = 2**63 - 1


def head(source_index="webauthn_credential_id", **changes):
    profile = profile_oracle.expected_profile(source_index)
    manifest = profile_oracle.framed("catchplate.policyAuthorityIndexProjectionManifest/v1",
        profile_oracle.utf8_json([profile_oracle.descriptor(name) for name in INDEX_IDS]))
    return {"index_id": source_index, "table_name": profile.table,
            "counted_profile": "catchplate.policyAuthorityCountedIndex/v1",
            "projection_digest": profile.projection_digest, "projection_manifest_digest": manifest,
            "index_revision": 0, "root_digest": tree_oracle.empty(profile, "")[0], "leaf_count": 0, **changes}


def leaf(source_index="webauthn_credential_id", **changes):
    profile = profile_oracle.expected_profile(source_index)
    key_digest = tree_oracle.digest("fixture-business-key")
    return {"index_id": source_index, "projection_digest": profile.projection_digest,
            "index_key": "a" * 96 + key_digest[7:], "primary_id": "fixture-id",
            "primary_key_digest": key_digest, "primary_row_digest": tree_oracle.digest("fixture-full-row"),
            "index_revision": 1, **changes}


def node(source_index="webauthn_credential_id", **changes):
    profile = profile_oracle.expected_profile(source_index)
    return {"index_id": source_index, "projection_digest": profile.projection_digest,
            "depth": 1, "path_prefix": "a", "node_digest": tree_oracle.digest("fixture-node"),
            "subtree_count": 1, "index_revision": 1, **changes}


class AuthorityCountedStorePostgresTests(unittest.TestCase):
    def setUp(self):
        if CONNECTION_PARAMETERS is None:
            raise RuntimeError("requires an externally prepared --postgres-dsn")
        self.connection = psycopg.connect(**CONNECTION_PARAMETERS, autocommit=False)
        self.addCleanup(self.rollback_and_close)
        self.connection.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        self.connection.execute("SET LOCAL statement_timeout = '5s'")
        self.connection.execute("SET LOCAL lock_timeout = '250ms'")
        self.connection.execute("SET LOCAL idle_in_transaction_session_timeout = '10s'")
        environment = self.connection.execute(
            "SELECT pg_catalog.inet_server_addr(), pg_catalog.getdatabaseencoding(), "
            "pg_catalog.current_setting('server_version_num')::integer, current_user = session_user, "
            "pg_catalog.current_setting('transaction_isolation')").fetchone()
        if (environment is None or environment[0] is not None or environment[1] != "UTF8"
                or not 160000 <= environment[2] < 170000 or environment[3] is not True
                or environment[4] != "serializable"):
            raise RuntimeError("requires a direct Unix-socket PG16/UTF8 serializable session")
        self.schema = "counted_store_" + uuid.uuid4().hex
        self.namespace = '"' + self.schema + '"'
        self.connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(self.schema)))
        self.connection.execute(sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(sql.Identifier(self.schema)))
        for statement in store.counted_store_ddl(self.namespace):
            self.connection.execute(statement)

    def rollback_and_close(self):
        try:
            self.connection.rollback()
        finally:
            self.connection.close()

    def object(self, name):
        return sql.Identifier(self.schema, name)

    @contextmanager
    def variant(self):
        self.connection.execute("SAVEPOINT counted_store_variant")
        try:
            yield
        finally:
            self.connection.execute("ROLLBACK TO SAVEPOINT counted_store_variant")
            self.connection.execute("RELEASE SAVEPOINT counted_store_variant")

    def insert(self, table, row):
        columns = tuple(name for name, _ in COLUMNS[table])
        return self.connection.execute(sql.SQL("INSERT INTO {} ({}) VALUES ({}) RETURNING *").format(
            self.object(table), sql.SQL(",").join(sql.Identifier(name) for name in columns),
            sql.SQL(",").join(sql.Placeholder() for _ in columns)), tuple(row[name] for name in columns)).fetchone()

    def rows(self, table):
        return self.connection.execute(sql.SQL("SELECT pg_catalog.to_jsonb(target) FROM {} AS target "
            'ORDER BY pg_catalog.to_jsonb(target)::text COLLATE "C"').format(self.object(table))).fetchall()

    def reject(self, table, row, error=psycopg.errors.CheckViolation):
        before = self.rows(table)
        with self.assertRaises(error), self.variant():
            self.insert(table, row)
        self.assertEqual(self.rows(table), before)

    def test_actual_catalog_has_exact_columns_collations_and_bounded_unique_keys(self):
        self.assertEqual(store.COUNTED_STORE_TABLES, TABLES)
        for names, table in ((store.COUNTED_HEAD_COLUMNS, HEADS), (store.COUNTED_LEAF_COLUMNS, LEAVES),
                             (store.COUNTED_NODE_COLUMNS, NODES)):
            self.assertEqual(names, tuple(name for name, _ in COLUMNS[table]))
        relations = self.connection.execute(
            "SELECT c.relname,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity,c.relispartition "
            "FROM pg_catalog.pg_class AS c JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace "
            "WHERE n.nspname=%s AND c.relkind<>'i' ORDER BY c.relname COLLATE \"C\"", (self.schema,)).fetchall()
        self.assertEqual(relations, [(name, "r", "p", False, False, False) for name in sorted(TABLES)])
        for table in TABLES:
            columns = self.connection.execute(
                "SELECT a.attname,t.typname,a.attnotnull,coll.collname,a.atthasdef,a.attidentity,a.attgenerated "
                "FROM pg_catalog.pg_attribute AS a JOIN pg_catalog.pg_class AS c ON c.oid=a.attrelid "
                "JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace "
                "JOIN pg_catalog.pg_type AS t ON t.oid=a.atttypid "
                "LEFT JOIN pg_catalog.pg_collation AS coll ON coll.oid=a.attcollation "
                "WHERE n.nspname=%s AND c.relname=%s AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum",
                (self.schema, table)).fetchall()
            self.assertEqual(columns, [(name, kind, True, "C" if kind == "text" else None, False, "", "")
                                       for name, kind in COLUMNS[table]])
        indexes = self.connection.execute(
            "SELECT c.relname,i.indisunique,i.indisvalid,i.indisready,i.indimmediate,am.amname, "
            "ARRAY(SELECT a.attname FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY AS k(num,ord) "
            "JOIN pg_catalog.pg_attribute AS a ON a.attrelid=i.indrelid AND a.attnum=k.num ORDER BY k.ord), "
            "i.indexprs IS NULL,i.indpred IS NULL, "
            "ARRAY(SELECT coll.collname FROM pg_catalog.unnest(i.indcollation) WITH ORDINALITY AS k(oid,ord) "
            "LEFT JOIN pg_catalog.pg_collation AS coll ON coll.oid=k.oid ORDER BY k.ord), "
            "ARRAY(SELECT ns.nspname::text||'.'||op.opcname::text "
            "FROM pg_catalog.unnest(i.indclass) WITH ORDINALITY AS k(oid,ord) "
            "JOIN pg_catalog.pg_opclass AS op ON op.oid=k.oid "
            "JOIN pg_catalog.pg_namespace AS ns ON ns.oid=op.opcnamespace ORDER BY k.ord) "
            "FROM pg_catalog.pg_index AS i JOIN pg_catalog.pg_class AS c ON c.oid=i.indrelid "
            "JOIN pg_catalog.pg_class AS ix ON ix.oid=i.indexrelid "
            "JOIN pg_catalog.pg_am AS am ON am.oid=ix.relam "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace WHERE n.nspname=%s",
            (self.schema,)).fetchall()
        expected_keys = {(HEADS, ("index_id",)), (HEADS, ("index_id", "projection_digest")),
                         (LEAVES, ("index_id", "index_key")), (LEAVES, ("index_id", "primary_key_digest")),
                         (NODES, ("index_id", "depth", "path_prefix"))}
        self.assertEqual(len(indexes), 5)
        self.assertEqual({(item[0], tuple(item[6])) for item in indexes}, expected_keys)
        for item in indexes:
            self.assertEqual(item[1:6], (True, True, True, True, "btree"))
            self.assertEqual(item[7:9], (True, True))
            kinds = dict(COLUMNS[item[0]])
            self.assertEqual(item[9], ["C" if kinds[name] == "text" else None for name in item[6]])
            self.assertEqual(item[10], ["pg_catalog.text_ops" if kinds[name] == "text" else "pg_catalog.int4_ops"
                                       for name in item[6]])

    def test_fresh_ddl_has_no_seed_defaults_functions_or_application_triggers(self):
        self.assertEqual(len(store.counted_store_ddl(self.namespace)), 3)
        for table in TABLES:
            self.assertEqual(self.rows(table), [])
        self.assertEqual(self.connection.execute(
            "SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc AS p "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid=p.pronamespace WHERE n.nspname=%s",
            (self.schema,)).fetchone(), (0,))
        self.assertEqual(self.connection.execute(
            "SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger AS t "
            "JOIN pg_catalog.pg_class AS c ON c.oid=t.tgrelid "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace "
            "WHERE n.nspname=%s AND NOT t.tgisinternal", (self.schema,)).fetchone(), (0,))
        # Fresh DDL must not silently become an idempotent installer.
        with self.assertRaises(psycopg.errors.DuplicateTable), self.variant():
            self.connection.execute(store.counted_store_ddl(self.namespace)[0])
        for namespace in (None, "catchplate_metadata", '"Upper"', '"bad-name"', '"a"; SELECT 1', '"' + "a" * 64 + '"'):
            with self.subTest(namespace=namespace), self.assertRaises(ValueError):
                store.counted_store_ddl(namespace)

    def test_all_eleven_heads_accept_independent_empty_roots_at_genesis_and_later_revisions(self):
        for index_id in INDEX_IDS:
            expected = head(index_id)
            self.assertEqual(self.insert(HEADS, expected), tuple(expected[name] for name, _ in COLUMNS[HEADS]))
        self.assertEqual(len(self.rows(HEADS)), 11)
        self.assertEqual(self.rows(LEAVES), [])
        self.assertEqual(self.rows(NODES), [])
        for revision in (1, I64):
            with self.variant():
                self.connection.execute(sql.SQL("UPDATE {} SET index_revision=%s").format(self.object(HEADS)), (revision,))
                self.assertTrue(all(record[0]["index_revision"] == revision for record in self.rows(HEADS)))
        self.reject(HEADS, head(), psycopg.errors.UniqueViolation)

    def test_head_source_identity_empty_equivalence_and_signed_bounds_are_closed(self):
        changed = tree_oracle.digest("different")
        cases = ({"index_id": "not_a_source_index"}, {"table_name": "webauthn_challenges"},
                 {"projection_digest": changed}, {"counted_profile": "catchplate.policyAuthorityCountedIndex/v2"},
                 {"projection_manifest_digest": changed}, {"index_revision": -1}, {"leaf_count": -1},
                 {"index_revision": 0, "leaf_count": 1, "root_digest": changed},
                 {"root_digest": changed}, {"index_revision": 1, "leaf_count": 1},
                 {"root_digest": "SHA256:" + "0" * 64}, {"root_digest": "sha256:" + "g" * 64},
                 {"root_digest": "sha256:" + "0" * 63}, {"root_digest": "sha256:" + "0" * 63 + "\n"})
        for delta in cases:
            with self.subTest(delta=delta):
                self.reject(HEADS, head(**delta))
        for field in ("index_revision", "leaf_count"):
            self.reject(HEADS, head(**{field: I64 + 1}), psycopg.errors.NumericValueOutOfRange)
        for field, _ in COLUMNS[HEADS]:
            self.reject(HEADS, head(**{field: None}), psycopg.errors.NotNullViolation)
        # Well-formed nonempty descriptors are only data; no population is
        # established by accepting their scalar representation here.
        self.insert(HEADS, head(index_revision=1, leaf_count=I64, root_digest=changed))

    def test_leaf_unique_path_and_business_commitment_keys_do_not_index_raw_ids(self):
        self.insert(HEADS, head(index_revision=7))
        original = leaf()
        self.assertEqual(self.insert(LEAVES, original), tuple(original[name] for name, _ in COLUMNS[LEAVES]))
        self.reject(LEAVES, original, psycopg.errors.UniqueViolation)
        self.reject(LEAVES, leaf(index_key="b" * 96 + original["primary_key_digest"][7:]), psycopg.errors.UniqueViolation)
        other_digest = tree_oracle.digest("another-business-key")
        another = leaf(index_key="a" * 96 + other_digest[7:], primary_key_digest=other_digest)
        self.insert(LEAVES, another)
        # DDL stores raw lookup material without asserting its hash relation.
        # The same raw ID is not a uniqueness key; maintenance must bind it.
        self.assertEqual(len(self.rows(LEAVES)), 2)

    def test_foreign_keys_require_exact_heads_and_never_cascade_or_defer(self):
        for table, record in ((LEAVES, leaf()), (NODES, node())):
            self.reject(table, record, psycopg.errors.ForeignKeyViolation)
        self.insert(HEADS, head(index_revision=7))
        for table, factory in ((LEAVES, leaf), (NODES, node)):
            self.reject(table, factory(projection_digest=tree_oracle.digest("crossed-profile")), psycopg.errors.ForeignKeyViolation)
            self.insert(table, factory())
        constraints = self.connection.execute(
            "SELECT c.relname,k.confupdtype,k.confdeltype,k.confmatchtype,k.condeferrable,k.condeferred,k.convalidated, "
            "ref.relname, ARRAY(SELECT a.attname FROM pg_catalog.unnest(k.conkey) WITH ORDINALITY AS s(num,ord) "
            "JOIN pg_catalog.pg_attribute AS a ON a.attrelid=k.conrelid AND a.attnum=s.num ORDER BY s.ord), "
            "ARRAY(SELECT a.attname FROM pg_catalog.unnest(k.confkey) WITH ORDINALITY AS s(num,ord) "
            "JOIN pg_catalog.pg_attribute AS a ON a.attrelid=k.confrelid AND a.attnum=s.num ORDER BY s.ord) "
            "FROM pg_catalog.pg_constraint AS k JOIN pg_catalog.pg_class AS c ON c.oid=k.conrelid "
            "JOIN pg_catalog.pg_class AS ref ON ref.oid=k.confrelid "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace "
            "WHERE n.nspname=%s AND k.contype='f' ORDER BY c.relname COLLATE \"C\"", (self.schema,)).fetchall()
        self.assertEqual(constraints, [(table, "a", "a", "s", False, False, True, HEADS,
                                       ["index_id", "projection_digest"], ["index_id", "projection_digest"])
                                      for table in (LEAVES, NODES)])
        with self.assertRaises(psycopg.errors.ForeignKeyViolation), self.variant():
            self.connection.execute(sql.SQL("DELETE FROM {}").format(self.object(HEADS)))
        self.assertEqual((len(self.rows(HEADS)), len(self.rows(LEAVES)), len(self.rows(NODES))), (1, 1, 1))

    def test_raw_primary_id_accepts_exact_utf8_byte_limit_without_btree_width_failure(self):
        self.insert(HEADS, head(index_revision=1))
        for identity in ("", "x" * 4096, "é" * 2048, "🙂" * 1024):
            with self.subTest(bytes=len(identity.encode("utf-8"))), self.variant():
                record = leaf(primary_id=identity)
                self.assertEqual(self.insert(LEAVES, record)[3], identity)
        for identity in ("x" * 4097, "é" * 2048 + "x", "🙂" * 1024 + "x"):
            self.reject(LEAVES, leaf(primary_id=identity))
        self.reject(LEAVES, leaf(primary_id=None), psycopg.errors.NotNullViolation)

    def test_leaf_commitment_syntax_suffix_and_positive_revision_are_enforced(self):
        self.insert(HEADS, head(index_revision=7))
        cases = ({"index_key": "a" * 159}, {"index_key": "A" * 160}, {"index_key": "a" * 161},
                 {"index_key": "a" * 159 + "\n"}, {"index_key": "b" * 160},
                 {"primary_key_digest": "SHA256:" + "0" * 64}, {"primary_key_digest": "sha256:" + "g" * 64},
                 {"primary_row_digest": "sha256:" + "0" * 63}, {"primary_row_digest": "sha256:" + "0" * 63 + "\n"},
                 {"index_revision": 0}, {"index_revision": -1})
        for delta in cases:
            with self.subTest(delta=delta):
                self.reject(LEAVES, leaf(**delta))
        self.reject(LEAVES, leaf(index_revision=I64 + 1), psycopg.errors.NumericValueOutOfRange)
        for field, _ in COLUMNS[LEAVES]:
            self.reject(LEAVES, leaf(**{field: None}), psycopg.errors.NotNullViolation)
        # Cross-row <=head revision admission is explicitly outside the DDL.
        self.insert(LEAVES, leaf(index_revision=I64))

    def test_node_depth_prefix_count_capacity_and_digest_bounds_are_exact(self):
        self.insert(HEADS, head(index_revision=7))
        for depth, capacity in ((1, I64), (144, I64), (145, 2**60), (159, 16), (160, 1)):
            with self.subTest(depth=depth), self.variant():
                self.insert(NODES, node(depth=depth, path_prefix="a" * depth, subtree_count=capacity))
            if capacity < I64:
                self.reject(NODES, node(depth=depth, path_prefix="a" * depth, subtree_count=capacity + 1))
        for delta in ({"depth": 0, "path_prefix": ""}, {"depth": 161, "path_prefix": "a" * 161},
                      {"depth": -1, "path_prefix": ""}, {"depth": 2, "path_prefix": "a"},
                      {"path_prefix": "A"}, {"path_prefix": "g"}, {"path_prefix": "\n"},
                      {"subtree_count": 0}, {"subtree_count": -1},
                      {"node_digest": "SHA256:" + "0" * 64}, {"node_digest": "sha256:" + "g" * 64}):
            with self.subTest(delta=delta):
                self.reject(NODES, node(**delta))
        self.reject(NODES, node(subtree_count=I64 + 1), psycopg.errors.NumericValueOutOfRange)
        self.reject(NODES, node(depth=2**31), psycopg.errors.NumericValueOutOfRange)

    def test_node_key_uniqueness_revisions_and_nulls_preserve_transaction_state(self):
        self.insert(HEADS, head(index_revision=7))
        self.insert(NODES, node())
        self.reject(NODES, node(), psycopg.errors.UniqueViolation)
        for revision in (0, -1):
            self.reject(NODES, node(path_prefix="b", index_revision=revision))
        self.reject(NODES, node(path_prefix="b", index_revision=I64 + 1), psycopg.errors.NumericValueOutOfRange)
        for field, _ in COLUMNS[NODES]:
            self.reject(NODES, node(**{field: None}), psycopg.errors.NotNullViolation)
        self.insert(NODES, node(path_prefix="b", index_revision=I64))
        self.assertEqual(len(self.rows(NODES)), 2)
        self.assertEqual(self.connection.info.transaction_status, psycopg.pq.TransactionStatus.INTRANS)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--postgres-dsn", required=True)
    parser.add_argument("--prepared-result")
    arguments, test_arguments = parser.parse_known_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    run_native_fixture("scripts/test_authority_counted_store_postgres.py",
                       argv=[sys.argv[0], *test_arguments], result_path=arguments.prepared_result)
