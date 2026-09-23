#!/usr/bin/env python3
"""Native counted-hash parity in an externally prepared PG16 transaction.

Only a direct owned0700 Unix socket is accepted. The real source functions are
installed into a random private schema inside SERIALIZABLE and always rolled
back. No engine, extension, commit, trigger, table/index installer or authority
is substituted. Independent framing/tree fixtures and actual Python hashes
provide separate expectations. These tests are authored, not execution claims.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import sys
import unittest
import uuid
from pathlib import Path

import psycopg
from psycopg import sql


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_index_contract as contract
from serverware import authority_index_projection as projection
from serverware.authority_store import counted_hash_sql
from serverware.native_postgres_results import run_native_fixture
from test_webauthn_trust_projection_postgres import local_connection_parameters
import test_authority_index_range as oracle
import test_authority_index_join as profile_oracle


CONNECTION_PARAMETERS = None
PREFIX = "serverware_policy_authority_"
EXPECTED_NAMES = tuple(PREFIX + name for name in (
    "counted_profile", "counted_frame_digest", "counted_empty", "counted_leaf", "counted_branch"))
I64 = 2**63 - 1
EMPTY_DOMAIN = "serverware.policyAuthorityCountedIndexEmpty/v1"
LEAF_DOMAIN = "serverware.policyAuthorityCountedIndexLeaf/v1"
BRANCH_DOMAIN = "serverware.policyAuthorityCountedIndexNode/v1"


class CountedHashPostgresTests(unittest.TestCase):
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
        self.schema = "counted_hash_" + uuid.uuid4().hex
        self.namespace = '"' + self.schema + '"'
        self.connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(self.schema)))
        self.connection.execute(sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(sql.Identifier(self.schema)))
        for statement in counted_hash_sql.counted_hash_functions_sql(self.namespace):
            self.connection.execute(statement)
        self.profile = profile_oracle.expected_profile("webauthn_credential_id")

    def rollback_and_close(self):
        try:
            self.connection.rollback()
        finally:
            self.connection.close()

    @contextmanager
    def variant(self):
        self.connection.execute("SAVEPOINT counted_hash_variant")
        try:
            yield
        finally:
            self.connection.execute("ROLLBACK TO SAVEPOINT counted_hash_variant")
            self.connection.execute("RELEASE SAVEPOINT counted_hash_variant")

    def call(self, name, arguments, casts):
        statement = sql.SQL("SELECT * FROM {}({})").format(
            sql.Identifier(self.schema, PREFIX + name),
            sql.SQL(", ").join(sql.SQL("%s::" + cast) for cast in casts))
        return self.connection.execute(statement, arguments).fetchone()

    def empty(self, index_id, prefix):
        return self.call("counted_empty", (index_id, prefix), ("text", "text"))[0]

    def leaf(self, index_id, value):
        return self.call("counted_leaf", (index_id, value.key, value.primary_key_digest, value.primary_row_digest),
                         ("text", "text", "text", "text"))[0]

    def branch(self, index_id, prefix, children):
        return self.call("counted_branch", (index_id, prefix,
            [None if child is None else child.digest for child in children],
            [None if child is None else child.count for child in children]), ("text", "text", "text[]", "bigint[]"))

    def reject(self, name, arguments, casts, reason):
        with self.assertRaisesRegex(psycopg.errors.RaiseException, reason), self.variant():
            self.call(name, arguments, casts)

    def test_all_eleven_source_profiles_match_independent_literal_descriptors(self):
        expected_ids = tuple(sorted(profile_oracle.descriptor(index_id)["indexId"] for index_id in projection.INDEX_IDS))
        self.assertEqual(len(expected_ids), 11)
        for index_id in expected_ids:
            with self.subTest(index=index_id):
                expected = profile_oracle.expected_profile(index_id)
                self.assertEqual(projection.profile_for(index_id), expected)
                self.assertEqual(self.call("counted_profile", (index_id,), ("text",)),
                                 (expected.table, expected.projection_digest))
        for unknown in (None, "", "not_an_index", expected_ids[0].upper(), "x" * 129):
            with self.subTest(index=unknown):
                self.reject("counted_profile", (unknown,), ("text",), "counted index identity")

    def test_empty_hashes_bind_profile_depth_and_prefix_at_all_boundary_depths(self):
        seen = set()
        for index_id in projection.INDEX_IDS:
            profile = profile_oracle.expected_profile(index_id)
            for prefix in ("", "0", "f" * 159, "a" * 160):
                with self.subTest(index=index_id, depth=len(prefix)):
                    expected = oracle.empty(profile, prefix)
                    actual = self.empty(index_id, prefix)
                    self.assertEqual(actual, expected[0])
                    self.assertEqual(contract.empty_node(profile, prefix), contract.CountedNode(*expected))
                    self.assertNotIn(actual, seen)
                    seen.add(actual)

    def test_leaf_hashes_match_python_and_independent_framing_for_every_profile(self):
        value = oracle.leaf("a5" * 80, "native-leaf")
        for index_id in projection.INDEX_IDS:
            with self.subTest(index=index_id):
                profile = profile_oracle.expected_profile(index_id)
                expected = oracle.member(profile, value)
                self.assertEqual(self.leaf(index_id, value), expected[0])
                self.assertEqual(contract.leaf_node(profile, value), contract.CountedNode(*expected))
                self.assertNotEqual(expected[0], oracle.empty(profile, value.key)[0])

    def test_empty_sparse_dense_and_terminal_branches_match_independent_ordered_slots(self):
        for index_id in projection.INDEX_IDS:
            profile = profile_oracle.expected_profile(index_id)
            for prefix, slots in (("", ()), ("ab", (0, 5, 15)), ("f" * 159, tuple(range(16)))):
                children = tuple(contract.CountedNode(oracle.digest(f"child-{ordinal}"), 1)
                                 if ordinal in slots else None for ordinal in range(16))
                with self.subTest(index=index_id, prefix=prefix):
                    expected = oracle.parent(profile, prefix,
                        [None if child is None else (child.digest, child.count) for child in children])
                    self.assertEqual(self.branch(index_id, prefix, children), expected)
                    self.assertEqual(contract.branch_node(profile, prefix, children), contract.CountedNode(*expected))
                    if slots:
                        reversed_children = tuple(reversed(children))
                        if children != reversed_children:
                            self.assertNotEqual(self.branch(index_id, prefix, reversed_children)[0], expected[0])

    def test_native_leaf_and_branch_folds_rebuild_one_independent_full_counted_tree(self):
        leaves = [oracle.leaf("a" * 159 + digit, "native-" + digit) for digit in ("0", "7", "f")]
        tree = oracle.IndependentIndex(leaves, self.profile)
        nodes = {leaf.key: contract.CountedNode(self.leaf(self.profile.index_id, leaf), 1) for leaf in leaves}
        opened = {leaf.key[:depth] for leaf in leaves for depth in range(160)}
        for prefix in sorted(opened, key=lambda value: (-len(value), value)):
            children = tuple(nodes.get(prefix + digit) for digit in "0123456789abcdef")
            actual = self.branch(self.profile.index_id, prefix, children)
            self.assertEqual(actual, tree.nodes[prefix])
            nodes[prefix] = contract.CountedNode(*actual)
        self.assertEqual(nodes[""], tree.root)
        self.assertEqual(self.connection.info.transaction_status, psycopg.pq.TransactionStatus.INTRANS)

    def test_null_oversize_nonhex_and_noncanonical_key_commitments_reject(self):
        for prefix in (None, "g", "A", "0\n", "é", "0" * 161):
            with self.subTest(prefix=prefix):
                self.reject("counted_empty", (self.profile.index_id, prefix), ("text", "text"), "empty prefix")
        valid = oracle.leaf("0" * 160)
        for field, value in ((1, None), (1, "0" * 159), (1, "f" * 161), (1, "A" * 160),
                             (2, None), (2, "SHA256:" + "0" * 64), (2, "sha256:" + "g" * 64),
                             (3, None), (3, "sha256:" + "0" * 63), (3, "sha256:" + "0" * 63 + "\n")):
            arguments = [self.profile.index_id, valid.key, valid.primary_key_digest, valid.primary_row_digest]
            arguments[field] = value
            with self.subTest(field=field, value=value):
                self.reject("counted_leaf", tuple(arguments), ("text",) * 4, "counted leaf")

    def test_branch_arrays_require_one_based_one_dimensional_paired_null_slots(self):
        digest = oracle.digest("child")
        empty = [None] * 16
        arrays = ((None, empty), (empty, None), ([], []), ([None] * 15, empty),
                  (empty, [None] * 17), ([[None] * 4 for _ in range(4)], empty),
                  (empty, [[None] * 4 for _ in range(4)]))
        for digests, counts in arrays:
            with self.subTest(digests=digests, counts=counts):
                self.reject("counted_branch", (self.profile.index_id, "", digests, counts),
                            ("text", "text", "text[]", "bigint[]"), "branch arrays")
        for digests, counts in (([digest] + empty[1:], empty), (empty, [1] + empty[1:]),
                                ([digest] + empty[1:], [0] + empty[1:]),
                                ([digest] + empty[1:], [-1] + empty[1:])):
            with self.subTest(digests=digests, counts=counts):
                self.reject("counted_branch", (self.profile.index_id, "", digests, counts),
                            ("text", "text", "text[]", "bigint[]"), "child commitment or count")
        function = sql.Identifier(self.schema, PREFIX + "counted_branch")
        for lower_slot in ("digests", "counts"):
            digest_sql = "pg_catalog.array_fill(NULL::text, ARRAY[16], ARRAY[0])" if lower_slot == "digests" else "%s::text[]"
            count_sql = "pg_catalog.array_fill(NULL::bigint, ARRAY[16], ARRAY[0])" if lower_slot == "counts" else "%s::bigint[]"
            with self.subTest(lower_slot=lower_slot), self.assertRaisesRegex(psycopg.errors.RaiseException, "branch arrays"), self.variant():
                self.connection.execute(sql.SQL("SELECT * FROM {}(%s::text, ''::text, " + digest_sql + ", " + count_sql + ")")
                    .format(function), (self.profile.index_id, empty)).fetchone()
        for prefix in (None, "g", "a\n", "0" * 160):
            with self.subTest(prefix=prefix):
                self.reject("counted_branch", (self.profile.index_id, prefix, empty, empty),
                            ("text", "text", "text[]", "bigint[]"), "branch prefix")

    def test_branch_depth_capacity_and_signed64_sum_boundaries_are_exact(self):
        digest = oracle.digest("bounded-child")
        for depth, capacity in ((159, 1), (158, 16), (144, 2**60), (143, I64), (0, I64)):
            prefix = "a" * depth
            children = (contract.CountedNode(digest, capacity),) + (None,) * 15
            with self.subTest(depth=depth, capacity=capacity):
                expected = contract.branch_node(self.profile, prefix, children)
                independent = oracle.parent(self.profile, prefix, [(digest, capacity)] + [None] * 15)
                self.assertEqual(self.branch(self.profile.index_id, prefix, children), independent)
                self.assertEqual(expected, contract.CountedNode(*independent))
                if capacity < I64:
                    self.reject("counted_branch", (self.profile.index_id, prefix,
                        [digest] + [None] * 15, [capacity + 1] + [None] * 15),
                        ("text", "text", "text[]", "bigint[]"), "child commitment or count")
        self.reject("counted_branch", (self.profile.index_id, "", [digest, digest] + [None] * 14,
                    [I64, 1] + [None] * 14), ("text", "text", "text[]", "bigint[]"), "overflows int64")
        with self.assertRaises(psycopg.errors.NumericValueOutOfRange), self.variant():
            self.call("counted_branch", (self.profile.index_id, "", [digest] + [None] * 15,
                      [I64 + 1] + [None] * 15), ("text", "text", "text[]", "bigint[]"))
        self.assertEqual(self.empty(self.profile.index_id, ""), oracle.empty(self.profile, "")[0])

    def test_closed_frame_helper_rejects_domains_arity_null_nonascii_and_array_aliases(self):
        frames = ["serverware.policyAuthorityCountedIndex/v1", self.profile.index_id,
                  self.profile.table, self.profile.projection_digest, "160", "0", "", "0"]
        actual = self.call("counted_frame_digest", (EMPTY_DOMAIN, frames), ("text", "text[]"))[0]
        self.assertEqual(actual, oracle.framed(EMPTY_DOMAIN, *frames))
        cases = ((None, frames), ("serverware.policyAuthorityAuthenticatedNode/v1", frames),
                 (EMPTY_DOMAIN, None), (EMPTY_DOMAIN, []), (EMPTY_DOMAIN, frames[:-1]),
                 (LEAF_DOMAIN, frames), (BRANCH_DOMAIN, frames),
                 (EMPTY_DOMAIN, [None] + frames[1:]), (EMPTY_DOMAIN, ["x" * 161] + frames[1:]),
                 (EMPTY_DOMAIN, ["é"] + frames[1:]),
                 (EMPTY_DOMAIN, [frames[:4], frames[4:]]))
        for domain, supplied in cases:
            with self.subTest(domain=domain, supplied=supplied):
                self.reject("counted_frame_digest", (domain, supplied), ("text", "text[]"), "counted fram")
        with self.assertRaisesRegex(psycopg.errors.RaiseException, "array shape"), self.variant():
            self.connection.execute(sql.SQL(
                "SELECT {}(%s::text, pg_catalog.array_fill('x'::text, ARRAY[8], ARRAY[0]))"
            ).format(sql.Identifier(self.schema, PREFIX + "counted_frame_digest")), (EMPTY_DOMAIN,)).fetchone()

    def test_exact_function_catalog_contract_and_renderer_namespace_are_closed(self):
        self.assertEqual(counted_hash_sql.COUNTED_HASH_FUNCTION_NAMES, EXPECTED_NAMES)
        self.assertEqual(len(counted_hash_sql.counted_hash_functions_sql(self.namespace)), 5)
        expected_arguments = {
            PREFIX + "counted_profile": "index_identity text",
            PREFIX + "counted_frame_digest": "digest_domain text, digest_frames text[]",
            PREFIX + "counted_empty": "index_identity text, path_prefix text",
            PREFIX + "counted_leaf": "index_identity text, index_key text, primary_key_digest text, primary_row_digest text",
            PREFIX + "counted_branch": "index_identity text, path_prefix text, child_digests text[], child_counts bigint[]",
        }
        records = self.connection.execute(
            "SELECT p.proname, p.provolatile, p.prosecdef, p.proisstrict, p.proretset, "
            "pg_catalog.pg_get_function_identity_arguments(p.oid), pg_catalog.pg_get_function_result(p.oid), "
            "p.proconfig, language.lanname FROM pg_catalog.pg_proc AS p "
            "JOIN pg_catalog.pg_namespace AS ns ON ns.oid=p.pronamespace "
            "JOIN pg_catalog.pg_language AS language ON language.oid=p.prolang "
            "WHERE ns.nspname=%s ORDER BY p.proname COLLATE \"C\"", (self.schema,)).fetchall()
        self.assertEqual([row[0] for row in records], sorted(EXPECTED_NAMES))
        for name, volatility, definer, strict, returns_set, arguments, result, settings, language in records:
            with self.subTest(function=name):
                self.assertEqual((volatility, definer, strict, language), ("i", False, False, "plpgsql"))
                self.assertEqual(arguments, expected_arguments[name])
                expected_result = {PREFIX + "counted_profile": "TABLE(table_name text, projection_digest text)",
                                   PREFIX + "counted_branch": "TABLE(node_digest text, subtree_count bigint)"}.get(name, "text")
                self.assertEqual(result, expected_result)
                self.assertEqual(returns_set, name in (PREFIX + "counted_profile", PREFIX + "counted_branch"))
                self.assertEqual(settings, [f"search_path=pg_catalog, {self.schema}, pg_temp"])
        for namespace in (None, "serverware_metadata", '"Upper"', '"bad-name"', '"a"; SELECT 1', '"' + "a" * 64 + '"'):
            with self.subTest(namespace=namespace), self.assertRaises(ValueError):
                counted_hash_sql.counted_hash_functions_sql(namespace)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--postgres-dsn", required=True)
    parser.add_argument("--prepared-result")
    arguments, test_arguments = parser.parse_known_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    run_native_fixture("scripts/test_authority_counted_hash_postgres.py",
        argv=[sys.argv[0], *test_arguments], result_path=arguments.prepared_result)
