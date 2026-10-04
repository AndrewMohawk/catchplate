#!/usr/bin/env python3
"""Pure renderer and source-linkage controls, never SQL execution evidence."""
from __future__ import annotations

import ast
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract
from serverware.authority_store import primary_tree_sql as tree_sql
from serverware.authority_store.wire_json_sql import WIRE_JSON_MAX_BYTES


NAMESPACE = '"serverware_metadata"'
MANIFEST = "sha256:" + "a" * 64
PREFIX = "serverware_policy_authority_"
FUNCTIONS = ("canonical_json", "framed_digest", "authenticated_empty",
             "authenticated_apply", "authenticated_trigger")


def sources() -> tuple[str, str]:
    result = []
    for relative, maximum in (("serverware/db.py", 16 * 1024 * 1024),
                              ("serverware/authority_store/primary_tree_sql.py", 128 * 1024)):
        path = ROOT / relative
        if path.stat().st_size > maximum:
            raise AssertionError("primary tree source fixture exceeded its read bound")
        result.append(path.read_text(encoding="utf-8"))
    return tuple(result)


def statements(namespace=NAMESPACE, manifest=MANIFEST) -> tuple[str, ...]:
    return (tree_sql.canonical_json_function_sql(namespace),
            tree_sql.framed_digest_function_sql(namespace),
            *tree_sql.authenticated_tree_functions_sql(namespace, manifest_digest=manifest))


class AuthorityPrimaryTreeSourceTests(unittest.TestCase):
    def test_exact_function_order_bound_and_source_tree_dimensions(self) -> None:
        rendered = statements()
        self.assertEqual(len(rendered), 5)
        for text, function in zip(rendered, FUNCTIONS):
            self.assertIs(type(text), str)
            self.assertEqual(re.findall(r"CREATE OR REPLACE FUNCTION\s+\"serverware_metadata\"\.\s*"
                                       r"(serverware_[a-z_]+)\(", text), [PREFIX + function])
            self.assertIn("SET search_path = pg_catalog, " + NAMESPACE + ", pg_temp", text)
            self.assertNotRegex(text, r"\{(?:guard_namespace|_POLICY_|authority_query_manifest)")
        self.assertEqual(tree_sql.TREE_JSON_MAX_BYTES, 72 * 1024 * 1024)
        self.assertEqual(tree_sql.TREE_JSON_MAX_BYTES, WIRE_JSON_MAX_BYTES)
        self.assertEqual((authority_contract.TREE_DEPTH, authority_contract.TREE_RADIX), (64, 16))
        self.assertIn("'" + MANIFEST + "'", rendered[3])
        self.assertIn("63..0", rendered[3])
        self.assertIn("1,\n                    16", rendered[2])

    def test_namespace_validation_rejects_sql_fragments_and_truncation_aliases(self) -> None:
        class StringSubclass(str):
            pass
        for namespace in (None, True, b'"a"', StringSubclass('"a"'), "a", '""',
                          '"A"', '"a-b"', '"a"; SELECT 1', '"a"."b"',
                          '"' + "a" * 64 + '"', '"a\x00"', '"é"'):
            with self.subTest(namespace=namespace), self.assertRaises(ValueError):
                statements(namespace)
        self.assertEqual(len(statements('"' + "a" * 63 + '"')), 5)

    def test_manifest_is_exact_digest_not_sql_or_non_string(self) -> None:
        for manifest in (None, True, MANIFEST.encode(), "a" * 64, "sha256:" + "A" * 64,
                         "sha256:" + "a" * 63, MANIFEST + "'", MANIFEST + "\n"):
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                tree_sql.authenticated_tree_functions_sql(NAMESPACE, manifest_digest=manifest)
        first, second = statements(), statements(manifest="sha256:" + "b" * 64)
        self.assertEqual(first[:3], second[:3])
        self.assertEqual(first[4], second[4])
        self.assertEqual(first[3].replace(MANIFEST, "sha256:" + "b" * 64), second[3])

    def test_tree_hash_framing_and_full_row_mutation_guards_are_retained(self) -> None:
        canonical, framed, empty, apply, trigger = statements()
        self.assertIn("input_value::text", canonical)
        self.assertIn('ORDER BY member.key COLLATE "C"', canonical)
        self.assertIn("pg_catalog.int8send(\n                    pg_catalog.octet_length(encoded_domain)::bigint", framed)
        self.assertNotIn("decode('00'", framed)
        self.assertIn("AuthenticatedEmptyLeaf/v1", empty)
        for fragment in ("FOR UPDATE", "existing_leaf.key_json IS DISTINCT FROM canonical_key",
                         "current_root.root_revision + 1", "current_root.leaf_count",
                         "new_leaf_count := new_leaf_count + 1", "new_leaf_count := new_leaf_count - 1",
                         "root_revision = current_root.root_revision", "authenticated-tree root CAS failed",
                         "policy_authority_authenticated_root_revisions", "pg_catalog.txid_current()"):
            self.assertIn(fragment, apply)
        self.assertIn("pg_catalog.to_jsonb(NEW)", trigger)
        self.assertIn("IF TG_OP = 'UPDATE' AND old_key <> new_key THEN", trigger)
        self.assertIn("old_key, NULL, 'DELETE'", trigger)
        self.assertIn("new_key, new_row, 'INSERT'", trigger)

    def test_apply_rolls_one_empty_digest_per_depth_including_pruned_nodes(self) -> None:
        apply = statements()[3]
        compact = " ".join(re.sub(r"--[^\n]*", "", apply).split())
        helper = PREFIX + "authenticated_empty("
        self.assertEqual(compact.count(helper), 1)
        before, remaining = compact.split("FOR current_depth IN REVERSE 63..0 LOOP", 1)
        loop, after = remaining.split("END LOOP;", 1)
        self.assertIn("empty_child := " + NAMESPACE + ". " + helper + " 64 );", before)
        self.assertNotIn(helper, loop)
        self.assertIn("COALESCE( node.node_digest, empty_child )", loop)
        # The ladder must advance even when DELETE takes the pruning branch.
        self.assertIn("IF child_count = 0 AND current_depth > 0 THEN", loop)
        self.assertIn("END IF; SELECT pg_catalog.jsonb_agg( empty_child ORDER BY ordinal ) "
                      "INTO empty_children FROM pg_catalog.generate_series( 1, 16 ) AS ordinal;", loop)
        self.assertEqual(loop.count("empty_child :="), 1)
        self.assertIn("empty_child := " + NAMESPACE + ". " + PREFIX + "framed_digest( "
                      "'serverware.policyAuthorityAuthenticatedNode/v1', current_depth::text, "
                      + NAMESPACE + ". " + PREFIX + "canonical_json( empty_children ) );", loop)
        self.assertIn("parent_digest := COALESCE( parent_digest, empty_child );", after)

    def test_real_installer_executes_shared_functions_at_existing_dependency_positions(self) -> None:
        source, shared = sources()
        parsed = ast.parse(source)
        installer = next(node for node in parsed.body if isinstance(node, ast.FunctionDef)
                         and node.name == "_install_policy_candidate_authority_guards")
        segment = ast.get_source_segment(source, installer)
        canonical = "conn.execute(_primary_tree_sql.canonical_json_function_sql(guard_namespace))"
        framed = "conn.execute(_primary_tree_sql.framed_digest_function_sql(guard_namespace))"
        for marker in (canonical, framed, "_primary_tree_sql.authenticated_tree_functions_sql("):
            self.assertEqual(segment.count(marker), 1)
        self.assertLess(segment.index(canonical), segment.index(PREFIX + "domain_digest("))
        self.assertLess(segment.index(PREFIX + "domain_digest("), segment.index(framed))
        self.assertLess(segment.index(framed), segment.index("wire_json_function_sql(guard_namespace)"))
        loops = [node for node in ast.walk(installer) if isinstance(node, ast.For)
                 and isinstance(node.iter, ast.Call) and isinstance(node.iter.func, ast.Attribute)
                 and node.iter.func.attr == "authenticated_tree_functions_sql"]
        self.assertEqual(len(loops), 1)
        self.assertEqual(ast.unparse(loops[0].iter),
                         "_primary_tree_sql.authenticated_tree_functions_sql(guard_namespace, manifest_digest=authority_query_manifest_digest)")
        self.assertEqual(ast.unparse(loops[0].body[0]), "conn.execute(statement)")
        self.assertIn("_primary_tree_sql.TREE_JSON_MAX_BYTES", segment)
        for function in FUNCTIONS:
            self.assertEqual(len(re.findall(r"CREATE OR REPLACE FUNCTION\s+\{guard_namespace\}\.\s*"
                                            + PREFIX + function + r"\(", source)), 0)
            self.assertEqual(len(re.findall(r"CREATE OR REPLACE FUNCTION\s+\{guard_namespace\}\.\s*"
                                            + PREFIX + function + r"\(", shared)), 1)

    def test_all_epoch_calls_use_qualified_numeric_function_grammar(self) -> None:
        source, shared = sources()
        combined = source + shared
        self.assertEqual(len(re.findall(r"pg_catalog\.extract\(", combined)), 11)
        calls = re.findall(r"pg_catalog\.extract\(\s*'epoch',\s*"
                           r"(pg_catalog\.clock_timestamp\(\)|webauthn_challenge\.expires_at::timestamptz)\s*\)", combined)
        self.assertEqual(len(calls), 11)
        self.assertEqual(calls.count("pg_catalog.clock_timestamp()"), 10)
        self.assertEqual(calls.count("webauthn_challenge.expires_at::timestamptz"), 1)
        self.assertNotRegex(combined, r"pg_catalog\.extract\(\s*epoch\s+FROM")


if __name__ == "__main__":
    unittest.main()
