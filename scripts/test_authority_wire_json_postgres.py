#!/usr/bin/env python3
"""Real-engine wire JSON component checks; no authority/startup substitute.

An external prepared runner owns the private Unix-socket database lifecycle.
Only a fresh random schema is created/dropped here. Actual shared SQL is tested
against Python's independent json.dumps oracle and the unchanged tree serializer.
No database facade/registry is imported or patched. JSONB parsing limits, full
executor admission, migration and whole-process memory are separate boundaries.
"""
from __future__ import annotations

import argparse
import json
import sys
import unittest
import uuid
from pathlib import Path

import psycopg
from psycopg import sql


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware.native_postgres_results import run_native_fixture

from serverware.authority_store.wire_json_sql import (
    WIRE_JSON_FUNCTION_NAMES,
    WIRE_JSON_MAX_BYTES,
    WIRE_JSON_MAX_DEPTH,
    WIRE_JSON_MAX_NODES,
    wire_json_function_sql,
)
from test_authority_root_transition_postgres import digest, production_digest_functions
from test_webauthn_trust_projection_postgres import local_connection_parameters


CONNECTION_PARAMETERS: dict[str, str | int] | None = None


def oracle(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))


def nodes(value: object) -> int:
    if isinstance(value, dict):
        return 1 + sum(1 + nodes(child) for child in value.values())
    if isinstance(value, list):
        return 1 + sum(nodes(child) for child in value)
    return 1


class AuthorityWireJsonPostgresTests(unittest.TestCase):
    @classmethod
    def connection(cls) -> psycopg.Connection:
        if CONNECTION_PARAMETERS is None:
            raise RuntimeError("this real-engine component requires --postgres-dsn")
        return psycopg.connect(**CONNECTION_PARAMETERS, autocommit=True)

    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = "serverware_wire_json_" + uuid.uuid4().hex
        cls.namespace = '"' + cls.schema + '"'
        with cls.connection() as connection:
            if connection.execute("SELECT inet_server_addr(), getdatabaseencoding()").fetchone() != (None, "UTF8"):
                raise RuntimeError("component fixture requires a UTF8 database over a Unix socket")
            connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(cls.schema)))
        cls.addClassCleanup(cls.drop_schema)
        with cls.connection() as connection:
            for statement in production_digest_functions(cls.namespace):
                connection.execute(statement)
            connection.execute(wire_json_function_sql(cls.namespace))

    @classmethod
    def drop_schema(cls) -> None:
        with cls.connection() as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(cls.schema)))

    def render_raw(self, raw: str) -> str:
        with self.connection() as connection:
            return connection.execute(
                f"SELECT {self.namespace}.serverware_policy_authority_wire_json(%s::jsonb)", (raw,)
            ).fetchone()[0]

    def assert_oracle(self, value: object) -> None:
        expected = oracle(value)
        self.assertEqual(self.render_raw(expected), expected)
        self.assertTrue(expected.isascii())

    def walk(self, value: object, *, depth: int, maximum_nodes: int,
             maximum_bytes: int, render: bool) -> tuple:
        with self.connection() as connection:
            return connection.execute(
                f"SELECT * FROM {self.namespace}.serverware_policy_authority_wire_walk(%s::jsonb,%s,%s,%s,%s)",
                (oracle(value), depth, maximum_nodes, maximum_bytes, render),
            ).fetchone()

    def test_primitives_and_exact_integers_beyond_machine_word_ranges(self) -> None:
        for value in (None, False, True, 0, 1, -1, 2**53 + 1, 2**63, -(2**63) - 1,
                      10**100 + 7, -(10**100 + 7), "", [], {}):
            with self.subTest(value=value):
                self.assert_oracle(value)

    def test_ascii_controls_del_quote_backslash_and_slash_match_python(self) -> None:
        values = [chr(codepoint) for codepoint in range(1, 128)]
        values.extend(["".join(values), 'quote"slash/backslash\\', "line\nreturn\rtab\tback\bform\f"])
        for value in values:
            with self.subTest(value=repr(value)):
                self.assert_oracle(value)
        self.assertEqual(self.render_raw(oracle("\x7f")), '"\\u007f"')
        self.assertEqual(self.render_raw(oracle("/")), '"/"')

    def test_bmp_astral_edges_and_surrogate_pair_input_are_exact(self) -> None:
        for codepoint in (128, 255, 0x7FF, 0x800, 0xD7FF, 0xE000, 0xFFFF,
                          0x10000, 0x1F642, 0x10FFFF):
            with self.subTest(codepoint=codepoint):
                self.assert_oracle(chr(codepoint))
        self.assertEqual(self.render_raw('"\\uD83D\\uDE42"'), '"\\ud83d\\ude42"')
        self.assertEqual(self.render_raw(oracle(chr(0x10FFFF))), '"\\udbff\\udfff"')

    def test_object_keys_sort_by_scalar_not_utf16_locale_or_jsonb_storage_order(self) -> None:
        value = {key: index for index, key in enumerate(
            ("aa", "b", "a", "A", "é", "e\u0301", "\x7f", "\x80", "\ue000", "\U00010000", "雪"))}
        self.assert_oracle(value)
        encoded = self.render_raw(oracle(value))
        self.assertLess(encoded.index('"aa"'), encoded.index('"b"'))
        self.assertLess(encoded.index('"\\ue000"'), encoded.index('"\\ud800\\udc00"'))
        self.assertIn('"e\\u0301"', encoded)
        self.assertIn('"\\u00e9"', encoded)

    def test_nested_lossless_values_preserve_types_and_compact_separators(self) -> None:
        value = {"雪": [True, 1, False, 0, None, {"é": "🙂", "quote": '"', "empty": []}],
                 "spaces": " a b ", "object": {}}
        self.assert_oracle(value)
        for render in (False, True):
            actual = self.walk(value, depth=128, maximum_nodes=nodes(value),
                               maximum_bytes=len(oracle(value)), render=render)
            self.assertEqual(actual, (oracle(value) if render else None, nodes(value), len(oracle(value))))

    def test_fractional_and_scale_bearing_jsonb_numbers_are_denied(self) -> None:
        for raw in ("1.0", "-0.0", "1.000", "0.25", "1e-2", "1.230e-5", "[1,2.0]", '{"n":1.0}'):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(psycopg.errors.RaiseException, "requires lossless integer numbers"):
                    self.render_raw(raw)

    def test_jsonb_numeric_token_normalization_is_not_raw_integer_admission(self) -> None:
        # JSONB has irreversibly discarded these original lexemes. A wire
        # serializer cannot establish that the received JSON token was an int;
        # the caller's exact raw-byte/parser admission must enforce that rule.
        for raw, normalized in (("1e2", "100"), ("-0", "0")):
            with self.connection() as connection:
                self.assertEqual(connection.execute("SELECT (%s::jsonb)::text", (raw,)).fetchone()[0], normalized)
            self.assertEqual(self.render_raw(raw), normalized)

    def test_jsonb_rejects_nul_unpaired_surrogates_and_invalid_utf8_before_serializer(self) -> None:
        for raw in ('"\\u0000"', '"\\ud800"', '"\\udfff"', '"\\ud800x"'):
            with self.subTest(raw=raw):
                with self.assertRaises(psycopg.DataError):
                    self.render_raw(raw)
        with self.connection() as connection:
            with self.assertRaises(psycopg.DataError):
                connection.execute(
                    f"SELECT {self.namespace}.serverware_policy_authority_wire_json(convert_from(%s,'UTF8')::jsonb)",
                    (b'"\xff"',),
                )
            # STRICT preserves SQL absence instead of relabeling it JSON null.
            self.assertIsNone(connection.execute(
                f"SELECT {self.namespace}.serverware_policy_authority_wire_json(NULL::jsonb)"
            ).fetchone()[0])
        self.assertEqual(self.render_raw("null"), "null")

    def test_string_byte_measurement_checks_both_exact_boundary_and_escape_expansion(self) -> None:
        for value in ("a" * 1024, "🙂" * 8, "\x7f" * 8, '"\\\n' * 8):
            expected = oracle(value)
            for render in (False, True):
                with self.connection() as connection:
                    actual = connection.execute(
                        f"SELECT * FROM {self.namespace}.serverware_policy_authority_wire_string(%s,%s,%s)",
                        (value, render, len(expected)),
                    ).fetchone()
                    self.assertEqual(actual, (expected if render else None, len(expected)))
                    with self.assertRaisesRegex(psycopg.errors.RaiseException, "byte bound exceeded"):
                        connection.execute(
                            f"SELECT * FROM {self.namespace}.serverware_policy_authority_wire_string(%s,%s,%s)",
                            (value, render, len(expected) - 1),
                        )

    def test_recursive_node_key_depth_and_byte_budgets_do_not_reset_per_child(self) -> None:
        value = {"k": [1, 2], "second": {"inner": "雪"}}
        for render in (False, True):
            self.assertEqual(self.walk(value, depth=3, maximum_nodes=nodes(value),
                                       maximum_bytes=len(oracle(value)), render=render),
                             (oracle(value) if render else None, nodes(value), len(oracle(value))))
            for arguments, message in (
                ({"depth": 1, "maximum_nodes": nodes(value), "maximum_bytes": len(oracle(value))}, "depth bound exceeded"),
                ({"depth": 3, "maximum_nodes": nodes(value) - 1, "maximum_bytes": len(oracle(value))}, "node bound exceeded"),
                ({"depth": 3, "maximum_nodes": nodes(value), "maximum_bytes": len(oracle(value)) - 1}, "byte bound exceeded"),
            ):
                with self.assertRaisesRegex(psycopg.errors.RaiseException, message):
                    self.walk(value, render=render, **arguments)

    def test_fixed_profiles_cannot_be_increased_by_direct_helper_call(self) -> None:
        self.assertEqual((WIRE_JSON_MAX_DEPTH, WIRE_JSON_MAX_NODES, WIRE_JSON_MAX_BYTES),
                         (128, 1_000_000, 72 * 1024 * 1024))
        base = {"depth": 128, "maximum_nodes": 1_000_000, "maximum_bytes": WIRE_JSON_MAX_BYTES}
        for field, value, message in (
            ("depth", 129, "depth bound exceeded"), ("depth", -1, "depth bound exceeded"),
            ("maximum_nodes", 1_000_001, "node bound exceeded"), ("maximum_nodes", 0, "node bound exceeded"),
            ("maximum_bytes", WIRE_JSON_MAX_BYTES + 1, "byte bound exceeded"), ("maximum_bytes", 0, "byte bound exceeded"),
        ):
            with self.assertRaisesRegex(psycopg.errors.RaiseException, message):
                self.walk(None, render=False, **{**base, field: value})

    def test_public_entry_checks_exact_depth_boundary(self) -> None:
        value = None
        for _ in range(WIRE_JSON_MAX_DEPTH):
            value = [value]
        self.assert_oracle(value)
        with self.assertRaisesRegex(psycopg.errors.RaiseException, "depth bound exceeded"):
            self.render_raw(oracle([value]))

    def test_existing_tree_json_remains_utf8_while_wire_and_domain_digest_match_python(self) -> None:
        key = {"id": "clé-雪"}
        row = {**key, "label": "🙂\x7f", "sign_count": 2}
        with self.connection() as connection:
            tree, wire = connection.execute(
                f"SELECT {self.namespace}.serverware_policy_authority_canonical_json(%s::jsonb), "
                f"{self.namespace}.serverware_policy_authority_wire_json(%s::jsonb)",
                (oracle(row), oracle(row)),
            ).fetchone()
            self.assertEqual(tree, json.dumps(row, ensure_ascii=False, allow_nan=False,
                                             sort_keys=True, separators=(",", ":")))
            self.assertEqual(wire, oracle(row))
            self.assertNotEqual(tree, wire)
            actual = connection.execute(
                f"SELECT {self.namespace}.serverware_policy_authority_domain_digest("
                "'serverware.policyAuthorityAuthorizationRow/v1','webauthn_credentials',"
                f"{self.namespace}.serverware_policy_authority_wire_json(%s::jsonb),'present',"
                f"{self.namespace}.serverware_policy_authority_wire_json(%s::jsonb))",
                (oracle(key), oracle(row)),
            ).fetchone()[0]
        self.assertEqual(actual, digest("serverware.policyAuthorityAuthorizationRow/v1", b"webauthn_credentials",
                                        oracle(key).encode("ascii"), b"present", oracle(row).encode("ascii")))

    def test_installed_helper_inventory_modes_and_renderer_namespace_are_closed(self) -> None:
        self.assertEqual(len(WIRE_JSON_FUNCTION_NAMES), 3)
        self.assertEqual(len(set(WIRE_JSON_FUNCTION_NAMES)), 3)
        self.assertTrue(all(len(name.encode("ascii")) <= 63 for name in WIRE_JSON_FUNCTION_NAMES))
        with self.connection() as connection:
            actual = connection.execute(
                "SELECT p.proname,p.provolatile,p.proisstrict,p.prosecdef,p.proconfig "
                "FROM pg_catalog.pg_proc AS p JOIN pg_catalog.pg_namespace AS n ON n.oid=p.pronamespace "
                "WHERE n.nspname=%s AND p.proname=ANY(%s::text[]) ORDER BY p.proname",
                (self.schema, list(WIRE_JSON_FUNCTION_NAMES)),
            ).fetchall()
        self.assertEqual(actual, [(name, "i", True, False, ["search_path=pg_catalog"])
                                  for name in sorted(WIRE_JSON_FUNCTION_NAMES)])
        for namespace in ("public", '"Public"', '"a.b"', '"a";DROP SCHEMA public', '""', None):
            with self.assertRaisesRegex(ValueError, "exact quoted identifier"):
                wire_json_function_sql(namespace)
        rendered = wire_json_function_sql(self.namespace)
        self.assertNotIn("GRANT", rendered)
        self.assertNotIn("serverware_policy_authority_canonical_json(", rendered)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--postgres-dsn", required=True)
    parser.add_argument("--prepared-result")
    arguments, test_arguments = parser.parse_known_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    run_native_fixture("scripts/test_authority_wire_json_postgres.py",
        argv=[sys.argv[0], *test_arguments], result_path=arguments.prepared_result)
