#!/usr/bin/env python3
"""Source partition controls for the SQL wire/tree serializer migration.

These inspect Python AST locations and SQL literal text without importing db,
evaluating f-strings, running Git or executing SQL. They are drift controls, not
a SQL parser or a substitute for the real-engine serializer/consumer tests.
"""
from __future__ import annotations

import ast
import hashlib
import re
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TREE = "catchplate_policy_authority_canonical_json"
WIRE = "catchplate_policy_authority_wire_json"
CALL = re.compile(r"\b(" + TREE + "|" + WIRE + r")\s*\(")
PREFIX = "catchplate_policy_authority_"
WIRE_COUNTS = {
    PREFIX + "issue_capability": 2,
    PREFIX + "issue_writer_capability": 3,
    PREFIX + "record_witness_receipt": 1,
    PREFIX + "apply_verified": 39,
    PREFIX + "begin_controlled_writer": 7,
    PREFIX + "finish_controlled_writer": 4,
    PREFIX + "issue_webauthn_challenge": 4,
    PREFIX + "reserve_credential_lease_nonce": 5,
    "{qualified_function}": 6,
}
TREE_ARGUMENTS = {
    PREFIX + "authenticated_empty": ("empty_children",),
    PREFIX + "authenticated_apply": (
        "authenticated_key", "authenticated_row", "child_digests", "empty_children",
    ),
    PREFIX + "apply_verified": (
        "projected.key_value", "key_value", "current_value", "key_value", "key_value",
        "authenticated_child_digests", "selector.value->'key'",
    ),
}
MIXED_TREE_DOMAINS = (
    "catchplate.policyAuthorityAuthenticatedKey/v1",
    "catchplate.policyAuthorityAuthenticatedKey/v1",
    "catchplate.policyAuthorityAuthenticatedRow/v1",
    "catchplate.policyAuthorityAuthenticatedLeaf/v1",
    "catchplate.policyAuthorityAuthenticatedLeaf/v1",  # stored leaf key_json comparison
    "catchplate.policyAuthorityAuthenticatedNode/v1",
    "catchplate.policyAuthorityAuthenticatedKey/v1",
)
# SHA-256 of the exact original source lines, including indentation/newlines,
# from CREATE OR REPLACE FUNCTION through its closing dollar-quote delimiter.
# Recorded read-only from committed 984ca5c, db.py:7296-7355,8671-8722.
# No runtime Git lookup or automatic fingerprint refresh is permitted here.
# Extraction to primary_tree_sql.py preserves these canonical/empty templates.
# The apply function has an explicitly approved optimization, pinned separately.
UNCHANGED_SQL_SHA256 = {
    TREE: "416f18a283f701b94e9be7046fb10d4b708d795a38a523bde253e67293682708",
    PREFIX + "authenticated_empty": "9ae84436a40e8d5e34ae4cda1042b110b830464b1265c4423169b5fa438c97ef",
}
# Exact reviewed apply template with the rolling empty-digest ladder and the
# earlier qualified EXTRACT grammar repair; not byte-identical to 984ca5c.
APPROVED_ROLLING_EMPTY_APPLY_SQL_SHA256 = "3ccce1ed53fb88e5e87f89e311fbe6aeaedb1de922f7b225d20a6124f4f77e36"


def database_source() -> str:
    path = ROOT / "catchplate/db.py"
    if path.stat().st_size > 16 * 1024 * 1024:
        raise AssertionError("database source exceeded the bounded source fixture")
    return path.read_text(encoding="utf-8")


def shared_tree_source() -> str:
    path = ROOT / "catchplate/authority_store/primary_tree_sql.py"
    if path.stat().st_size > 128 * 1024:
        raise AssertionError("shared tree source exceeded its bounded fixture")
    return path.read_text(encoding="utf-8")


def serializer_sql_literals(source: str) -> dict[str, str]:
    """Locate SQL template spans in db and shared renderers, without evaluation."""
    result = {}
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.JoinedStr):
            continue
        static_text = "".join(value.value for value in node.values
                              if isinstance(value, ast.Constant) and type(value.value) is str)
        if not CALL.search(static_text):
            continue
        literal = ast.get_source_segment(source, node)
        if literal is None:
            raise AssertionError("serializer literal source span is unavailable")
        header = re.search(
            r"(?m)^ +CREATE OR REPLACE FUNCTION\s+"
            r"(?:\{guard_namespace\}\.\s*)?"
            r"(?P<name>catchplate_[a-z0-9_]+|\{qualified_function\})\s*\(", literal,
        )
        if header is None:
            raise AssertionError("serializer use is outside a classified SQL function literal")
        tag = re.search(r"\bAS (\$[a-z0-9_]+\$)", literal[header.end():])
        if tag is None:
            raise AssertionError("SQL function dollar-quote boundary changed")
        body_start = header.end() + tag.end()
        end = literal.find(tag.group(1), body_start)
        if end < 0 or literal[end + len(tag.group(1)):end + len(tag.group(1)) + 1] != "\n":
            raise AssertionError("SQL function closing delimiter changed")
        sql = literal[header.start():end + len(tag.group(1)) + 1]
        if len(CALL.findall(sql)) != len(CALL.findall(literal)):
            raise AssertionError("serializer use escapes its classified function body")
        if header.group("name") in result:
            raise AssertionError("SQL function literal identity is duplicated")
        result[header.group("name")] = sql
    return result


def assert_partition(source: str, shared_source: str | None = None) -> dict[str, str]:
    shared_source = shared_tree_source() if shared_source is None else shared_source
    literals = serializer_sql_literals(source)
    shared_literals = serializer_sql_literals(shared_source)
    if set(literals) & set(shared_literals):
        raise AssertionError("serializer SQL function identity is duplicated across sources")
    literals.update(shared_literals)
    expected_functions = set(WIRE_COUNTS) | set(TREE_ARGUMENTS) | {TREE}
    if set(literals) != expected_functions:
        raise AssertionError("serializer SQL function inventory changed")
    actual_calls = Counter(name for sql in literals.values() for name in CALL.findall(sql))
    if (actual_calls != Counter({TREE: 15, WIRE: 71})
            or actual_calls != Counter(CALL.findall(source + shared_source))):
        raise AssertionError("serializer call inventory changed or has an unclassified call")
    for name, sql in literals.items():
        if len(re.findall(r"\b" + WIRE + r"\s*\(", sql)) != WIRE_COUNTS.get(name, 0):
            raise AssertionError("wire call count differs from the reviewed function partition")
        if name == TREE:
            if len(re.findall(r"\b" + TREE + r"\s*\(", sql)) != 3:
                raise AssertionError("tree serializer definition or recursion changed")
            continue
        arguments = []
        domains = []
        for call in re.finditer(r"\b" + TREE + r"\s*\(", sql):
            argument = re.match(r"\s*([a-z_][a-z0-9_.]*(?:->'key')?)\s*\)", sql[call.end():])
            if argument is None:
                raise AssertionError("tree serializer argument is outside its reviewed allowlist")
            arguments.append(argument.group(1))
            if name == PREFIX + "apply_verified":
                preceding = re.findall(
                    r"catchplate_policy_authority_(?:framed|domain)_digest\(\s*'([^']+)'", sql[:call.start()],
                )
                domains.append(preceding[-1] if preceding else None)
        if tuple(arguments) != TREE_ARGUMENTS.get(name, ()):
            raise AssertionError("tree serializer argument is outside its reviewed allowlist")
        if name == PREFIX + "apply_verified" and tuple(domains) != MIXED_TREE_DOMAINS:
            raise AssertionError("mixed router tree digest domains changed")
    return literals


def replace_call(source: str, name: str, argument: str, replacement: str) -> str:
    pattern = r"\b" + name + r"(\s*\(\s*" + re.escape(argument) + r"\s*\))"
    changed, count = re.subn(pattern, lambda match: replacement + match.group(1), source)
    if count != 1:
        raise AssertionError("negative control did not identify one exact call")
    return changed


class AuthorityWireJsonSourceTests(unittest.TestCase):
    def test_every_database_serializer_call_has_an_explicit_partition(self) -> None:
        literals = assert_partition(database_source())
        self.assertEqual(sum(WIRE_COUNTS.values()), 71)
        self.assertEqual(sum(len(arguments) for arguments in TREE_ARGUMENTS.values()), 12)
        self.assertEqual(len(literals), 12)

    def test_unchanged_canonical_and_empty_source_match_committed_baseline(self) -> None:
        literals = assert_partition(database_source())
        for name, expected in UNCHANGED_SQL_SHA256.items():
            with self.subTest(name=name):
                literal = literals[name]
                self.assertEqual(hashlib.sha256(literal.encode("utf-8")).hexdigest(), expected)

    def test_apply_source_matches_approved_rolling_empty_optimization(self) -> None:
        literal = assert_partition(database_source())[PREFIX + "authenticated_apply"]
        self.assertEqual(hashlib.sha256(literal.encode("utf-8")).hexdigest(),
                         APPROVED_ROLLING_EMPTY_APPLY_SQL_SHA256)

    def test_shared_renderer_changes_remain_inside_the_same_partition(self) -> None:
        source, shared = database_source(), shared_tree_source()
        assert_partition(source, shared)
        changed = replace_call(shared, TREE, "authenticated_row", WIRE)
        with self.assertRaisesRegex(AssertionError, "call inventory changed"):
            assert_partition(source, changed)
        duplicate = serializer_sql_literals(shared)[PREFIX + "authenticated_empty"]
        with self.assertRaisesRegex(AssertionError, "duplicated across sources"):
            assert_partition(source + '\nDUPLICATE_SQL = f"""\n' + duplicate + '"""\n', shared)

    def test_missing_or_extra_wire_migration_is_detected(self) -> None:
        source = database_source()
        assert_partition(source)
        for changed in (
            replace_call(source, WIRE, "plan_value", TREE),
            replace_call(source, TREE, "projected.key_value", WIRE),
        ):
            with self.assertRaisesRegex(AssertionError, "call inventory changed"):
                assert_partition(changed)

    def test_count_preserving_tree_wire_swap_is_rejected(self) -> None:
        source = database_source()
        assert_partition(source)
        changed = replace_call(source, TREE, "projected.key_value", WIRE)
        changed = replace_call(changed, WIRE, "plan_value", TREE)
        self.assertEqual(Counter(CALL.findall(changed)), Counter(CALL.findall(source)))
        with self.assertRaisesRegex(AssertionError, "tree serializer argument"):
            assert_partition(changed)

    def test_mixed_tree_domain_change_is_detected_without_changing_counts(self) -> None:
        source = database_source()
        assert_partition(source)
        old = "'catchplate.policyAuthorityAuthenticatedRow/v1',\n                                            manifest_entry.table_name,"
        self.assertEqual(source.count(old), 1)
        changed = source.replace(old, old.replace("AuthenticatedRow", "BusinessRow"))
        with self.assertRaisesRegex(AssertionError, "mixed router tree digest domains changed"):
            assert_partition(changed)

    def test_unclassified_serializer_use_is_rejected(self) -> None:
        source = database_source()
        assert_partition(source)
        changed = source + "\nUNCLASSIFIED_SQL = 'SELECT " + WIRE + "(value)'\n"
        with self.assertRaisesRegex(AssertionError, "unclassified call"):
            assert_partition(changed)


if __name__ == "__main__":
    unittest.main()
