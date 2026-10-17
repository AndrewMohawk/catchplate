#!/usr/bin/env python3
"""SQL-compatible radix fixtures; no DB, root authority, or registry substitute.

The fixture hashes below independently implement the stored SQL tree protocol.
They never call the production key/leaf/empty/node helpers to build expected
data, so a shared wrong domain cannot make both fixture and verifier agree.
Cursor cases check emitted SQL and Python rejection, not native SQL execution
or proof that PostgreSQL applies a projection before network transport.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from decimal import Decimal
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_radix_proof as radix


def sql_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def wire_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def sql_digest(domain: str, *frames: bytes) -> str:
    domain_bytes = domain.encode("ascii")
    material = len(domain_bytes).to_bytes(8, "big") + domain_bytes
    for frame in frames:
        material += len(frame).to_bytes(8, "big") + frame
    return "sha256:" + hashlib.sha256(material).hexdigest()


def wire_digest(domain: str, *frames: bytes) -> str:
    material = domain.encode("ascii") + b"\0"
    for frame in frames:
        material += len(frame).to_bytes(8, "big") + frame
    return "sha256:" + hashlib.sha256(material).hexdigest()


class TreeFixture:
    """Small independently reconstructed persisted radix16 tree, depth64."""

    def __init__(self, *, wrong_business_path: bool = False, wrong_tree_framing: bool = False, rows: dict | None = None) -> None:
        self.table = "webauthn_credentials"
        self.rows = rows if rows is not None else {"record-a": {"id": "record-a", "sign_count": 2}, "record-b": {"id": "record-b", "sign_count": 4}}
        self.tree_digest = wire_digest if wrong_tree_framing else sql_digest
        self.empty = {64: self.tree_digest("catchplate.policyAuthorityAuthenticatedEmptyLeaf/v1", b"64")}
        for depth in range(63, -1, -1):
            self.empty[depth] = self.tree_digest(
                "catchplate.policyAuthorityAuthenticatedNode/v1", str(depth).encode(), sql_json([self.empty[depth + 1]] * 16),
            )
        self.leaves: dict[str, dict] = {}
        self.nodes: dict[tuple[int, str], str] = {}
        domain = "catchplate.policyAuthorityBusinessKey/v1" if wrong_business_path else "catchplate.policyAuthorityAuthenticatedKey/v1"
        for revision, (item_id, row) in enumerate(self.rows.items(), 1):
            key = {"id": item_id}
            tree_key = self.tree_digest(domain, self.table.encode(), sql_json(key))
            row_digest = self.tree_digest("catchplate.policyAuthorityAuthenticatedRow/v1", self.table.encode(), sql_json(row))
            leaf_digest = self.tree_digest(
                "catchplate.policyAuthorityAuthenticatedLeaf/v1", self.table.encode(), tree_key.encode(), sql_json(key), row_digest.encode(),
            )
            self.leaves[tree_key] = {
                "key_json": sql_json(key).decode(), "row_digest": row_digest,
                "leaf_digest": leaf_digest, "root_revision": revision,
            }
            self.nodes[(64, tree_key[7:])] = leaf_digest
        for depth in range(63, -1, -1):
            prefixes = {path[:depth] for node_depth, path in self.nodes if node_depth == depth + 1}
            for prefix in prefixes:
                children = [self.nodes.get((depth + 1, prefix + format(index, "x")), self.empty[depth + 1]) for index in range(16)]
                self.nodes[(depth, prefix)] = self.tree_digest("catchplate.policyAuthorityAuthenticatedNode/v1", str(depth).encode(), sql_json(children))
        self.root = {"table": self.table, "rootRevision": len(self.rows), "rootDigest": self.nodes.get((0, ""), self.empty[0]), "leafCount": len(self.rows)}

    def selected(self, item_id: str, *, absent: bool = False) -> dict:
        key = {"id": item_id}
        row = None if absent else self.rows[item_id]
        return {
            "table": self.table, "key": key,
            "keyDigest": wire_digest("catchplate.policyAuthorityBusinessKey/v1", self.table.encode(), wire_json(key)),
            "present": row is not None, "row": copy.deepcopy(row), "contractSelector": None,
        }

    def proof(self, selected: dict, *, wrong_business_path: bool = False) -> dict:
        domain = "catchplate.policyAuthorityBusinessKey/v1" if wrong_business_path else "catchplate.policyAuthorityAuthenticatedKey/v1"
        tree_key = self.tree_digest(domain, self.table.encode(), sql_json(selected["key"]))
        path = tree_key[7:]
        leaf = self.leaves.get(tree_key)
        proof = {
            "schema": "catchplate.policyAuthorityRadixMultiproof/v3", "table": self.table,
            "key": selected["key"], "keyDigest": selected["keyDigest"], "present": selected["present"],
            "rowDigest": leaf["row_digest"] if selected["present"] else None,
            "leafDigest": leaf["leaf_digest"] if selected["present"] else self.empty[64],
            "rootRevision": self.root["rootRevision"], "rootDigest": self.root["rootDigest"],
            "siblings": [
                {
                    "depth": depth, "pathPrefix": path[:depth], "selectedNibble": path[depth],
                    "childDigests": [self.nodes.get((depth + 1, path[:depth] + format(index, "x")), self.empty[depth + 1]) for index in range(16)],
                }
                for depth in range(64)
            ],
        }
        proof["proofDigest"] = wire_digest("catchplate.policyAuthorityRadixMultiproof/v3", wire_json(proof))
        return proof


class FixtureCursor:
    """Read-only SQL responder, not a PostgreSQL transaction or acceptance mock."""

    def __init__(self, tree: TreeFixture, *, namespace: str = "catchplate_metadata") -> None:
        self.tree = tree
        self.namespace = namespace
        self.calls: list[tuple[str, tuple]] = []
        self.result: list[dict] = []

    def execute(self, statement: str, parameters: tuple) -> FixtureCursor:
        self.calls.append((statement, parameters))
        if f'FROM "{self.namespace}".policy_authority_authenticated_leaves ' in statement:
            table, key_digest = parameters
            if table != self.tree.table:
                raise AssertionError("unexpected table")
            leaf = self.tree.leaves.get(key_digest)
            self.result = [] if leaf is None else [copy.deepcopy(leaf)]
        elif f'FROM "{self.namespace}".policy_authority_authenticated_tree_nodes ' in statement:
            table, depth, expected_paths, limit = parameters
            if table != self.tree.table:
                raise AssertionError("unexpected table")
            if len(expected_paths) != 16 or limit != 17 or len(set(expected_paths)) != 16:
                raise AssertionError("unbounded child lookup")
            if "path_prefix = ANY(%s) LIMIT %s" not in statement:
                raise AssertionError("child query is not exact and bounded")
            self.result = [
                {"path_prefix": prefix, "node_digest": digest, "root_revision": self.tree.root["rootRevision"]}
                for (node_depth, prefix), digest in self.tree.nodes.items()
                if node_depth == depth and prefix in expected_paths
            ]
        else:
            raise AssertionError("unexpected SQL or write")
        return self

    def fetchone(self) -> dict | None:
        if len(self.result) > 1:
            raise AssertionError("ambiguous exact fixture leaf")
        return self.result[0] if self.result else None

    def fetchmany(self, size: int) -> list[dict]:
        if size != 17:
            raise AssertionError("child result read is not bounded")
        return self.result[:size]


class FixtureTrace:
    def __init__(self) -> None:
        self.reads: list[tuple[str, dict]] = []

    def read(self, table: str, key: dict) -> None:
        self.reads.append((table, copy.deepcopy(key)))


class AuthorityRadixProofTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = TreeFixture()

    def test_producer_and_verifier_match_independent_sql_tree(self) -> None:
        cursor = FixtureCursor(self.tree)
        trace = FixtureTrace()
        rows = (self.tree.selected("record-a"), self.tree.selected("record-b"))
        proofs = radix.derive_multiproofs(cursor, selected_rows=rows, roots=(self.tree.root,), trace=trace)
        by_id = {item["key"]["id"]: item for item in proofs}
        for row in rows:
            proof = by_id[row["key"]["id"]]
            expected = self.tree.proof(row)
            self.assertEqual(proof, expected)
            self.assertEqual(radix.reconstruct_multiproof_root(proof, selected=row), self.tree.root["rootDigest"])
            tree_key = sql_digest("catchplate.policyAuthorityAuthenticatedKey/v1", self.tree.table.encode(), sql_json(row["key"]))
            self.assertNotEqual(tree_key, row["keyDigest"])
            self.assertEqual(proof["keyDigest"], row["keyDigest"])
            self.assertIn(("policy_authority_authenticated_leaves", {"tableName": self.tree.table, "keyDigest": tree_key}), trace.reads)
        self.assertEqual(len(cursor.calls), 2 * 65)
        self.assertEqual(len(trace.reads), 2 * 65)

    def test_explicit_namespace_preserves_proof_bytes_parameters_and_read_count(self) -> None:
        row = self.tree.selected("record-a")
        for namespace in ("catchplate_metadata", "radix_fixture_a9", "a" * 63, "select"):
            with self.subTest(namespace=namespace):
                cursor = FixtureCursor(self.tree, namespace=namespace)
                trace = FixtureTrace()
                proof, = radix.derive_multiproofs(
                    cursor, selected_rows=(row,), roots=(self.tree.root,), trace=trace,
                    namespace=namespace,
                )
                self.assertEqual(proof, self.tree.proof(row))
                self.assertEqual(len(cursor.calls), 65)
                self.assertEqual(len(trace.reads), 65)
                self.assertEqual(len(cursor.calls[0][1]), 2)
                self.assertTrue(all(len(parameters) == 4 for _, parameters in cursor.calls[1:]))
                self.assertTrue(all(f'FROM "{namespace}".' in statement for statement, _ in cursor.calls))

    def test_invalid_namespace_denies_before_any_cursor_or_trace_access(self) -> None:
        class StringSubclass(str):
            pass

        for namespace in (None, False, 7, b"metadata", StringSubclass("metadata"), "", "a" * 64,
                          "Metadata", "métadata", "_metadata", "1metadata", "metadata.other",
                          'metadata"', "metadata;SELECT", "metadata\n", "metadata\0"):
            cursor = FixtureCursor(self.tree)
            trace = FixtureTrace()
            with self.subTest(namespace=namespace), self.assertRaisesRegex(radix.RadixProofError, "namespace"):
                radix.derive_multiproofs(
                    cursor, selected_rows=(self.tree.selected("record-a"),),
                    roots=(self.tree.root,), trace=trace, namespace=namespace,
                )
            self.assertEqual(cursor.calls, [])
            self.assertEqual(trace.reads, [])

    def test_sql_text_bounds_are_case_projections_not_omission_predicates(self) -> None:
        cursor = FixtureCursor(self.tree)
        radix.derive_multiproofs(
            cursor, selected_rows=(self.tree.selected("record-a"),),
            roots=(self.tree.root,), trace=FixtureTrace(),
        )
        leaf_sql, leaf_parameters = cursor.calls[0]
        self.assertIn(
            "CASE WHEN pg_catalog.octet_length(key_json) BETWEEN 1 AND "
            f"{radix.authority_contract.MAX_RESULT_BYTES} THEN key_json ELSE NULL END AS key_json",
            leaf_sql,
        )
        for field in ("row_digest", "leaf_digest"):
            self.assertIn(
                f"CASE WHEN pg_catalog.octet_length({field}) = 71 THEN {field} ELSE NULL END AS {field}",
                leaf_sql,
            )
        self.assertEqual(leaf_sql.split("WHERE ", 1)[1], "table_name = %s AND key_digest = %s")
        self.assertEqual(leaf_parameters[0], self.tree.table)
        for node_sql, parameters in cursor.calls[1:]:
            self.assertIn(
                "CASE WHEN pg_catalog.octet_length(path_prefix) BETWEEN 1 AND 64 "
                "THEN path_prefix ELSE NULL END AS path_prefix", node_sql,
            )
            self.assertIn(
                "CASE WHEN pg_catalog.octet_length(node_digest) = 71 "
                "THEN node_digest ELSE NULL END AS node_digest", node_sql,
            )
            self.assertEqual(
                node_sql.split("WHERE ", 1)[1],
                "table_name = %s AND depth = %s AND path_prefix = ANY(%s) LIMIT %s",
            )
            self.assertEqual(len(parameters[2]), 16)
            self.assertEqual(parameters[3], 17)

    def test_leaf_projection_sentinels_malformed_json_and_exact_types_deny(self) -> None:
        row = self.tree.selected("record-a")
        tree_key = sql_digest("catchplate.policyAuthorityAuthenticatedKey/v1", self.tree.table.encode(), sql_json(row["key"]))
        original = copy.deepcopy(self.tree.leaves[tree_key])

        class StringSubclass(str):
            pass

        changes = (
            ("key_json", None), ("key_json", False), ("key_json", b'{}'),
            ("key_json", StringSubclass(original["key_json"])), ("key_json", ""),
            ("key_json", "{"), ("key_json", "\ud800"),
            ("row_digest", None), ("row_digest", False), ("row_digest", "sha256:" + "0" * 65),
            ("row_digest", "sha256:" + "g" * 64), ("leaf_digest", None),
            ("leaf_digest", StringSubclass(original["leaf_digest"])),
            ("root_revision", None), ("root_revision", True),
        )
        for field, value in changes:
            self.tree.leaves[tree_key] = {**original, field: value}
            cursor = FixtureCursor(self.tree)
            with self.subTest(field=field, value=value), self.assertRaises(radix.RadixProofError):
                radix.derive_multiproofs(cursor, selected_rows=(row,), roots=(self.tree.root,), trace=FixtureTrace())
            self.assertEqual(len(cursor.calls), 1)
        self.tree.leaves[tree_key] = original

    def test_oversized_driver_key_json_and_utf8_byte_bounds_deny(self) -> None:
        row = self.tree.selected("record-a")
        tree_key = sql_digest("catchplate.policyAuthorityAuthenticatedKey/v1", self.tree.table.encode(), sql_json(row["key"]))
        # Deliberately bypass the SQL projection as a hostile responder control.
        # This bounded allocation is not a simulation of native PostgreSQL IO.
        self.tree.leaves[tree_key]["key_json"] = " " * (radix.authority_contract.MAX_RESULT_BYTES + 1)
        cursor = FixtureCursor(self.tree)
        with self.assertRaisesRegex(radix.RadixProofError, "key JSON is not bounded"):
            radix.derive_multiproofs(cursor, selected_rows=(row,), roots=(self.tree.root,), trace=FixtureTrace())
        self.assertEqual(len(cursor.calls), 1)
        self.assertEqual(radix._database_text("éé", maximum_bytes=4, label="fixture"), "éé")
        with self.assertRaisesRegex(radix.RadixProofError, "not bounded"):
            radix._database_text("ééé", maximum_bytes=4, label="fixture")

    def test_child_projection_sentinels_oversize_and_exact_types_deny(self) -> None:
        class StringSubclass(str):
            pass

        for field, value in (
            ("path_prefix", None), ("path_prefix", False), ("path_prefix", []),
            ("path_prefix", "a" * 65), ("path_prefix", StringSubclass("a")),
            ("node_digest", None), ("node_digest", False), ("node_digest", "sha256:" + "0" * 65),
            ("node_digest", "sha256:" + "g" * 64),
            ("node_digest", StringSubclass("sha256:" + "0" * 64)),
        ):
            class ChangedCursor(FixtureCursor):
                def fetchmany(self, size: int) -> list[dict]:
                    rows = copy.deepcopy(super().fetchmany(size))
                    if not rows:
                        raise AssertionError("fixture expected its selected branch")
                    rows[0][field] = value
                    return rows

            cursor = ChangedCursor(self.tree)
            with self.subTest(field=field, value=value), self.assertRaises(radix.RadixProofError):
                radix.derive_multiproofs(
                    cursor, selected_rows=(self.tree.selected("record-a"),),
                    roots=(self.tree.root,), trace=FixtureTrace(),
                )
            self.assertEqual(len(cursor.calls), 2)

    def test_invalid_retained_leaf_never_becomes_nonmembership(self) -> None:
        selected = self.tree.selected("record-a", absent=True)
        tree_key = sql_digest("catchplate.policyAuthorityAuthenticatedKey/v1", self.tree.table.encode(), sql_json(selected["key"]))
        self.tree.leaves[tree_key]["key_json"] = None
        with self.assertRaisesRegex(radix.RadixProofError, "key JSON is not bounded"):
            radix.derive_multiproofs(
                FixtureCursor(self.tree), selected_rows=(selected,),
                roots=(self.tree.root,), trace=FixtureTrace(),
            )

    def test_nonmembership_uses_authenticated_path_in_nonempty_tree(self) -> None:
        row = self.tree.selected("missing-record", absent=True)
        proof, = radix.derive_multiproofs(FixtureCursor(self.tree), selected_rows=(row,), roots=(self.tree.root,), trace=FixtureTrace())
        self.assertEqual(proof, self.tree.proof(row))
        self.assertIsNone(proof["rowDigest"])
        self.assertEqual(radix.reconstruct_multiproof_root(proof, selected=row), self.tree.root["rootDigest"])
        with self.assertRaisesRegex(radix.RadixProofError, "nonmembership"):
            radix.derive_multiproofs(FixtureCursor(self.tree), selected_rows=(self.tree.selected("record-a", absent=True),), roots=(self.tree.root,), trace=FixtureTrace())

    def test_business_domain_tree_is_not_accepted_as_persisted_tree(self) -> None:
        wrong = TreeFixture(wrong_business_path=True)
        row = wrong.selected("record-a")
        with self.assertRaisesRegex(radix.RadixProofError, "authenticated leaf"):
            radix.derive_multiproofs(FixtureCursor(wrong), selected_rows=(row,), roots=(wrong.root,), trace=FixtureTrace())
        with self.assertRaises(radix.RadixProofError):
            radix.reconstruct_multiproof_root(wrong.proof(row, wrong_business_path=True), selected=row)

    def test_wire_framing_cannot_replace_sql_tree_framing(self) -> None:
        wrong = TreeFixture(wrong_tree_framing=True)
        row = wrong.selected("record-a")
        with self.assertRaisesRegex(radix.RadixProofError, "authenticated leaf"):
            radix.derive_multiproofs(FixtureCursor(wrong), selected_rows=(row,), roots=(wrong.root,), trace=FixtureTrace())
        with self.assertRaises(radix.RadixProofError):
            radix.reconstruct_multiproof_root(wrong.proof(row), selected=row)
        for depth in (0, 1, 63, 64):
            with self.subTest(depth=depth):
                self.assertEqual(radix.empty_digest(depth), self.tree.empty[depth])
                self.assertNotEqual(radix.empty_digest(depth), wrong.empty[depth])

    def test_unicode_tree_values_use_utf8_without_changing_wire_addresses(self) -> None:
        tree = TreeFixture(rows={"record-é": {"id": "record-é", "label": "☃", "é": ["雪", True, None, 7]}})
        row = tree.selected("record-é")
        proof, = radix.derive_multiproofs(FixtureCursor(tree), selected_rows=(row,), roots=(tree.root,), trace=FixtureTrace())
        self.assertEqual(proof, tree.proof(row))
        self.assertEqual(radix.reconstruct_multiproof_root(proof, selected=row), tree.root["rootDigest"])
        self.assertEqual(radix.tree_json_bytes(row["row"]), sql_json(row["row"]))
        self.assertNotEqual(sql_json(row["row"]), wire_json(row["row"]))
        self.assertEqual(row["keyDigest"], wire_digest("catchplate.policyAuthorityBusinessKey/v1", tree.table.encode(), wire_json(row["key"])))
        # This tree fixture distinguishes the two representations; the separate
        # SQL wire serializer and actual byte admission need real-engine proof.
        self.assertNotEqual(row["keyDigest"], wire_digest("catchplate.policyAuthorityBusinessKey/v1", tree.table.encode(), sql_json(row["key"])))

    def test_unsupported_numeric_representation_is_rejected_not_rounded(self) -> None:
        for value in (1.5, 1.0, float("inf"), float("nan"), Decimal("1.20")):
            with self.subTest(value=value), self.assertRaisesRegex(radix.RadixProofError, "lossless scalar"):
                radix.tree_json_bytes({"nested": [value]})
        row = self.tree.selected("record-a")
        row["row"]["sign_count"] = 2.0
        with self.assertRaises(radix.RadixProofError):
            radix.derive_multiproofs(FixtureCursor(self.tree), selected_rows=(row,), roots=(self.tree.root,), trace=FixtureTrace())
        with self.assertRaises(radix.RadixProofError):
            radix.reconstruct_multiproof_root(self.tree.proof(row), selected=row)

    def test_empty_tree_nonmembership_and_exact_proof_shape(self) -> None:
        tree = TreeFixture(rows={})
        row = tree.selected("missing", absent=True)
        proof, = radix.derive_multiproofs(FixtureCursor(tree), selected_rows=(row,), roots=(tree.root,), trace=FixtureTrace())
        self.assertEqual(radix.reconstruct_multiproof_root(proof, selected=row), tree.empty[0])
        self.assertEqual(proof["rootRevision"], 0)
        for count in (63, 65):
            changed = copy.deepcopy(proof)
            changed["siblings"] = (changed["siblings"] * 2)[:count]
            with self.subTest(levels=count), self.assertRaises(radix.RadixProofError):
                radix.reconstruct_multiproof_root(changed, selected=row)
        for count in (15, 17):
            changed = copy.deepcopy(proof)
            changed["siblings"][0]["childDigests"] = [tree.empty[1]] * count
            with self.subTest(children=count), self.assertRaises(radix.RadixProofError):
                radix.reconstruct_multiproof_root(changed, selected=row)
        for field, value in (("present", 0), ("rootRevision", False)):
            with self.subTest(field=field), self.assertRaises(radix.RadixProofError):
                radix.reconstruct_multiproof_root({**proof, field: value}, selected=row)
        for depth in (0, 1):
            changed = copy.deepcopy(proof)
            changed["siblings"][depth]["depth"] = bool(depth)
            with self.subTest(depth=depth), self.assertRaises(radix.RadixProofError):
                radix.reconstruct_multiproof_root(changed, selected=row)

    def test_child_reads_reject_overflow_duplicate_unexpected_and_future_rows(self) -> None:
        for mode in ("overflow", "duplicate", "unexpected", "future", "boolean_revision"):
            tree = self.tree

            class ChangedCursor(FixtureCursor):
                def fetchmany(self, size: int) -> list[dict]:
                    rows = super().fetchmany(size)
                    if not rows:
                        raise AssertionError("fixture expected its selected branch")
                    rows = copy.deepcopy(rows)
                    if mode == "overflow":
                        return [rows[0]] * 17
                    if mode == "duplicate":
                        return rows + [copy.deepcopy(rows[0])]
                    if mode == "unexpected":
                        rows[0]["path_prefix"] = "not-an-expected-child"
                    elif mode == "future":
                        rows[0]["root_revision"] = 3
                    else:
                        rows[0]["root_revision"] = True
                    return rows

            with self.subTest(mode=mode), self.assertRaises(radix.RadixProofError):
                radix.derive_multiproofs(ChangedCursor(tree), selected_rows=(tree.selected("record-a"),), roots=(tree.root,), trace=FixtureTrace())

    def test_exact_address_row_path_and_root_controls(self) -> None:
        row = self.tree.selected("record-a")
        proof = self.tree.proof(row)
        changed_row = copy.deepcopy(row)
        changed_row["row"]["sign_count"] += 1
        with self.assertRaisesRegex(radix.RadixProofError, "leaf binding"):
            radix.reconstruct_multiproof_root(proof, selected=changed_row)
        for field, value in (("keyDigest", "sha256:" + "0" * 64), ("rootDigest", "sha256:" + "0" * 64)):
            changed = {**proof, field: value}
            with self.subTest(field=field), self.assertRaises(radix.RadixProofError):
                radix.reconstruct_multiproof_root(changed, selected=row)
        changed = copy.deepcopy(proof)
        changed["siblings"][63]["pathPrefix"] = row["keyDigest"][7:70]
        with self.assertRaisesRegex(radix.RadixProofError, "path reconstruction"):
            radix.reconstruct_multiproof_root(changed, selected=row)
        changed = copy.deepcopy(proof)
        index = (int(changed["siblings"][0]["selectedNibble"], 16) + 1) % 16
        changed["siblings"][0]["childDigests"][index] = "sha256:" + "0" * 64
        with self.assertRaises(radix.RadixProofError):
            radix.reconstruct_multiproof_root(changed, selected=row)

    def test_selected_business_identity_cannot_be_replaced_by_tree_identity(self) -> None:
        row = self.tree.selected("record-a")
        row["keyDigest"] = sql_digest("catchplate.policyAuthorityAuthenticatedKey/v1", self.tree.table.encode(), sql_json(row["key"]))
        with self.assertRaisesRegex(radix.RadixProofError, "business key digest"):
            radix.derive_multiproofs(FixtureCursor(self.tree), selected_rows=(row,), roots=(self.tree.root,), trace=FixtureTrace())
        proof = self.tree.proof(row)
        with self.assertRaisesRegex(radix.RadixProofError, "business key digest"):
            radix.reconstruct_multiproof_root(proof, selected=row)

    def test_missing_root_and_changed_stored_leaf_deny(self) -> None:
        row = self.tree.selected("record-a")
        with self.assertRaisesRegex(radix.RadixProofError, "relation root"):
            radix.derive_multiproofs(FixtureCursor(self.tree), selected_rows=(row,), roots=(), trace=FixtureTrace())
        tree_key = sql_digest("catchplate.policyAuthorityAuthenticatedKey/v1", self.tree.table.encode(), sql_json(row["key"]))
        self.tree.leaves[tree_key]["row_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(radix.RadixProofError, "authenticated leaf"):
            radix.derive_multiproofs(FixtureCursor(self.tree), selected_rows=(row,), roots=(self.tree.root,), trace=FixtureTrace())

    def test_source_wiring_preserves_stored_domain_and_active_proof_calls(self) -> None:
        database = (ROOT / "catchplate/db.py").read_text()
        tree_path = ROOT / "catchplate/authority_store/primary_tree_sql.py"
        self.assertLess(tree_path.stat().st_size, 128 * 1024)
        tree_source = tree_path.read_text(encoding="utf-8")
        self.assertIn("conn.execute(_primary_tree_sql.framed_digest_function_sql(guard_namespace))", database)
        self.assertIn("_primary_tree_sql.authenticated_tree_functions_sql(", database)
        framed_body = tree_source.split("AS $catchplate_framed_digest$", 1)[1].split("$catchplate_framed_digest$", 1)[0]
        self.assertIn("digest_material := pg_catalog.int8send(", framed_body)
        self.assertIn("pg_catalog.octet_length(encoded_domain)::bigint", framed_body)
        self.assertIn(") || encoded_domain;", framed_body)
        apply_body = tree_source.split("AS $catchplate_authenticated_apply$", 1)[1].split("$catchplate_authenticated_apply$", 1)[0]
        self.assertIn("'catchplate.policyAuthorityAuthenticatedKey/v1'", apply_body)
        self.assertNotIn("policyAuthorityBusinessKey/v1", apply_body)
        planner = (ROOT / "catchplate/authority_planner.py").read_text()
        self.assertIn("counter_proofs = authority_radix_proof.derive_multiproofs(", planner)
        self.assertIn("business_proofs = authority_radix_proof.derive_multiproofs_batched(", planner)
        self.assertIn("return authority_radix_proof.reconstruct_multiproof_root(", planner)
        executor = (ROOT / "catchplate/authority_store/executor_v9.py").read_text()
        self.assertIn("'catchplate.policyAuthorityBusinessKey/v1'", executor)
        # Do not import the blocked registry or substitute success for it.
        registry = (ROOT / "catchplate/authority_transition_registry.py").read_text()
        self.assertNotIn("authority_transition_webauthn", registry)


if __name__ == "__main__":
    unittest.main()
