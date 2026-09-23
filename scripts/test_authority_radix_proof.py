#!/usr/bin/env python3
"""SQL-compatible radix fixtures; no DB, root authority, or registry substitute.

The fixture hashes below independently implement the stored SQL tree protocol.
They never call the production key/leaf/empty/node helpers to build expected
data, so a shared wrong domain cannot make both fixture and verifier agree.
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

from serverware import authority_radix_proof as radix


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
        self.empty = {64: self.tree_digest("serverware.policyAuthorityAuthenticatedEmptyLeaf/v1", b"64")}
        for depth in range(63, -1, -1):
            self.empty[depth] = self.tree_digest(
                "serverware.policyAuthorityAuthenticatedNode/v1", str(depth).encode(), sql_json([self.empty[depth + 1]] * 16),
            )
        self.leaves: dict[str, dict] = {}
        self.nodes: dict[tuple[int, str], str] = {}
        domain = "serverware.policyAuthorityBusinessKey/v1" if wrong_business_path else "serverware.policyAuthorityAuthenticatedKey/v1"
        for revision, (item_id, row) in enumerate(self.rows.items(), 1):
            key = {"id": item_id}
            tree_key = self.tree_digest(domain, self.table.encode(), sql_json(key))
            row_digest = self.tree_digest("serverware.policyAuthorityAuthenticatedRow/v1", self.table.encode(), sql_json(row))
            leaf_digest = self.tree_digest(
                "serverware.policyAuthorityAuthenticatedLeaf/v1", self.table.encode(), tree_key.encode(), sql_json(key), row_digest.encode(),
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
                self.nodes[(depth, prefix)] = self.tree_digest("serverware.policyAuthorityAuthenticatedNode/v1", str(depth).encode(), sql_json(children))
        self.root = {"table": self.table, "rootRevision": len(self.rows), "rootDigest": self.nodes.get((0, ""), self.empty[0]), "leafCount": len(self.rows)}

    def selected(self, item_id: str, *, absent: bool = False) -> dict:
        key = {"id": item_id}
        row = None if absent else self.rows[item_id]
        return {
            "table": self.table, "key": key,
            "keyDigest": wire_digest("serverware.policyAuthorityBusinessKey/v1", self.table.encode(), wire_json(key)),
            "present": row is not None, "row": copy.deepcopy(row), "contractSelector": None,
        }

    def proof(self, selected: dict, *, wrong_business_path: bool = False) -> dict:
        domain = "serverware.policyAuthorityBusinessKey/v1" if wrong_business_path else "serverware.policyAuthorityAuthenticatedKey/v1"
        tree_key = self.tree_digest(domain, self.table.encode(), sql_json(selected["key"]))
        path = tree_key[7:]
        leaf = self.leaves.get(tree_key)
        proof = {
            "schema": "serverware.policyAuthorityRadixMultiproof/v3", "table": self.table,
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
        proof["proofDigest"] = wire_digest("serverware.policyAuthorityRadixMultiproof/v3", wire_json(proof))
        return proof


class FixtureCursor:
    """Read-only SQL responder, not a PostgreSQL transaction or acceptance mock."""

    def __init__(self, tree: TreeFixture) -> None:
        self.tree = tree
        self.calls: list[tuple[str, tuple]] = []
        self.result: list[dict] = []

    def execute(self, statement: str, parameters: tuple) -> FixtureCursor:
        self.calls.append((statement, parameters))
        if "FROM serverware_metadata.policy_authority_authenticated_leaves " in statement:
            table, key_digest = parameters
            if table != self.tree.table:
                raise AssertionError("unexpected table")
            leaf = self.tree.leaves.get(key_digest)
            self.result = [] if leaf is None else [copy.deepcopy(leaf)]
        elif "FROM serverware_metadata.policy_authority_authenticated_tree_nodes " in statement:
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
            tree_key = sql_digest("serverware.policyAuthorityAuthenticatedKey/v1", self.tree.table.encode(), sql_json(row["key"]))
            self.assertNotEqual(tree_key, row["keyDigest"])
            self.assertEqual(proof["keyDigest"], row["keyDigest"])
            self.assertIn(("policy_authority_authenticated_leaves", {"tableName": self.tree.table, "keyDigest": tree_key}), trace.reads)
        self.assertEqual(len(cursor.calls), 2 * 65)
        self.assertEqual(len(trace.reads), 2 * 65)

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
        self.assertEqual(row["keyDigest"], wire_digest("serverware.policyAuthorityBusinessKey/v1", tree.table.encode(), wire_json(row["key"])))
        # The separate executor SQL business-address Unicode mismatch is not
        # repaired or presented as runtime compatibility by this tree fixture.
        self.assertNotEqual(row["keyDigest"], wire_digest("serverware.policyAuthorityBusinessKey/v1", tree.table.encode(), sql_json(row["key"])))

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
        row["keyDigest"] = sql_digest("serverware.policyAuthorityAuthenticatedKey/v1", self.tree.table.encode(), sql_json(row["key"]))
        with self.assertRaisesRegex(radix.RadixProofError, "business key digest"):
            radix.derive_multiproofs(FixtureCursor(self.tree), selected_rows=(row,), roots=(self.tree.root,), trace=FixtureTrace())
        proof = self.tree.proof(row)
        with self.assertRaisesRegex(radix.RadixProofError, "business key digest"):
            radix.reconstruct_multiproof_root(proof, selected=row)

    def test_missing_root_and_changed_stored_leaf_deny(self) -> None:
        row = self.tree.selected("record-a")
        with self.assertRaisesRegex(radix.RadixProofError, "relation root"):
            radix.derive_multiproofs(FixtureCursor(self.tree), selected_rows=(row,), roots=(), trace=FixtureTrace())
        tree_key = sql_digest("serverware.policyAuthorityAuthenticatedKey/v1", self.tree.table.encode(), sql_json(row["key"]))
        self.tree.leaves[tree_key]["row_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(radix.RadixProofError, "authenticated leaf"):
            radix.derive_multiproofs(FixtureCursor(self.tree), selected_rows=(row,), roots=(self.tree.root,), trace=FixtureTrace())

    def test_source_wiring_preserves_stored_domain_and_active_proof_calls(self) -> None:
        database = (ROOT / "serverware/db.py").read_text()
        framed_body = database.split("AS $serverware_framed_digest$", 1)[1].split("$serverware_framed_digest$", 1)[0]
        self.assertIn("digest_material := pg_catalog.int8send(", framed_body)
        self.assertIn("pg_catalog.octet_length(encoded_domain)::bigint", framed_body)
        self.assertIn(") || encoded_domain;", framed_body)
        apply_body = database.split("AS $serverware_authenticated_apply$", 1)[1].split("$serverware_authenticated_apply$", 1)[0]
        self.assertIn("'serverware.policyAuthorityAuthenticatedKey/v1'", apply_body)
        self.assertNotIn("policyAuthorityBusinessKey/v1", apply_body)
        planner = (ROOT / "serverware/authority_planner.py").read_text()
        self.assertIn("return authority_radix_proof.derive_multiproofs(", planner)
        self.assertIn("return authority_radix_proof.reconstruct_multiproof_root(", planner)
        executor = (ROOT / "serverware/authority_store/executor_v9.py").read_text()
        self.assertIn("'serverware.policyAuthorityBusinessKey/v1'", executor)
        # Do not import the blocked registry or substitute success for it.
        registry = (ROOT / "serverware/authority_transition_registry.py").read_text()
        self.assertNotIn("authority_transition_webauthn", registry)


if __name__ == "__main__":
    unittest.main()
