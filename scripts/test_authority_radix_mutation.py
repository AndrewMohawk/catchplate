#!/usr/bin/env python3
"""Pure radix batch tests against independently rebuilt small SQL-format trees.

No database, registry, live authority, witness, clock or signing is substituted.
The independent fixture uses SQL and wire serializers from the existing radix
test, not the evaluator's tree/key/leaf/node helpers. These are component tests,
not execution of PostgreSQL triggers or authenticated root-currentness proof.
"""
from __future__ import annotations

import copy
import dataclasses
import sys
import unittest
from decimal import Decimal
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_radix_mutation as radix_mutation
from serverware.authority_radix_mutation import (
    PrimaryRadixBatchResult,
    PrimaryRadixLimits,
    PrimaryRadixMembershipResult,
    PrimaryRadixMutationError,
    PrimaryRoot,
    PrimaryTableContract,
    evaluate_primary_radix_batch,
    evaluate_primary_radix_memberships,
)
from test_authority_radix_proof import sql_digest, sql_json, wire_digest, wire_json


LIMITS = PrimaryRadixLimits(256, 512, 16384, 262144, 34882, 64 * 1024 * 1024, 128, 1_000_000)


class IndependentTree:
    def __init__(self, rows: list[dict], *, table: str = "items", columns: tuple[str, ...] = ("id",),
                 revision: int | None = None) -> None:
        self.table, self.columns = table, columns
        self.rows = {sql_json(self.key(row)): copy.deepcopy(row) for row in rows}
        if len(self.rows) != len(rows):
            raise AssertionError("fixture duplicate key")
        self.empty = {64: sql_digest("serverware.policyAuthorityAuthenticatedEmptyLeaf/v1", b"64")}
        for depth in range(63, -1, -1):
            self.empty[depth] = sql_digest("serverware.policyAuthorityAuthenticatedNode/v1",
                                           str(depth).encode(), sql_json([self.empty[depth + 1]] * 16))
        self.leaves, self.nodes = {}, {}
        for row in self.rows.values():
            key = self.key(row)
            tree_key = sql_digest("serverware.policyAuthorityAuthenticatedKey/v1", table.encode(), sql_json(key))
            row_digest = sql_digest("serverware.policyAuthorityAuthenticatedRow/v1", table.encode(), sql_json(row))
            leaf = sql_digest("serverware.policyAuthorityAuthenticatedLeaf/v1", table.encode(),
                              tree_key.encode(), sql_json(key), row_digest.encode())
            self.leaves[tree_key] = (row_digest, leaf)
            self.nodes[(64, tree_key[7:])] = leaf
        for depth in range(63, -1, -1):
            prefixes = {prefix[:depth] for node_depth, prefix in self.nodes if node_depth == depth + 1}
            for prefix in prefixes:
                children = [self.nodes.get((depth + 1, prefix + format(index, "x")), self.empty[depth + 1])
                            for index in range(16)]
                self.nodes[(depth, prefix)] = sql_digest("serverware.policyAuthorityAuthenticatedNode/v1",
                                                       str(depth).encode(), sql_json(children))
        self.root = PrimaryRoot(table, len(rows) if revision is None else revision,
                                self.nodes.get((0, ""), self.empty[0]), len(rows))

    def key(self, row: dict) -> dict:
        return {column: row[column] for column in self.columns}

    def contract(self, *, writable: bool = True, root_class: str = "business") -> PrimaryTableContract:
        return PrimaryTableContract(self.table, self.columns, writable, root_class)

    def selected(self, key: dict) -> dict:
        row = self.rows.get(sql_json(key))
        return {"table": self.table, "key": copy.deepcopy(key),
                "keyDigest": wire_digest("serverware.policyAuthorityBusinessKey/v1", self.table.encode(), wire_json(key)),
                "present": row is not None, "row": copy.deepcopy(row), "contractSelector": None}

    def proof(self, selected: dict) -> dict:
        tree_key = sql_digest("serverware.policyAuthorityAuthenticatedKey/v1", self.table.encode(), sql_json(selected["key"]))
        path = tree_key[7:]
        row_digest, leaf = self.leaves.get(tree_key, (None, self.empty[64]))
        proof = {"schema": "serverware.policyAuthorityRadixMultiproof/v3", "table": self.table,
                 "key": copy.deepcopy(selected["key"]), "keyDigest": selected["keyDigest"],
                 "present": selected["present"], "rowDigest": row_digest, "leafDigest": leaf,
                 "rootRevision": self.root.root_revision, "rootDigest": self.root.root_digest,
                 "siblings": [{"depth": depth, "pathPrefix": path[:depth], "selectedNibble": path[depth],
                               "childDigests": [self.nodes.get((depth + 1, path[:depth] + format(index, "x")),
                                                               self.empty[depth + 1]) for index in range(16)]}
                              for depth in range(64)]}
        refresh_proof_digest(proof)
        return proof


def refresh_proof_digest(proof: dict) -> None:
    proof["proofDigest"] = wire_digest("serverware.policyAuthorityRadixMultiproof/v3",
                                      wire_json({key: value for key, value in proof.items() if key != "proofDigest"}))


def change(selected: dict, operation: str, after: dict | None) -> dict:
    return {"templateId": "component-template-not-authority", "operation": operation,
            "table": selected["table"], "key": copy.deepcopy(selected["key"]),
            "keyDigest": selected["keyDigest"], "expectedRow": copy.deepcopy(selected["row"]),
            "row": copy.deepcopy(after)}


def batch(tree: IndependentTree, selected: tuple[dict, ...], mutations: tuple[dict, ...]) -> dict:
    return {"table_contracts": (tree.contract(),), "business_before_roots": (tree.root,),
            "authorization_before_roots": (), "selected_rows": selected,
            "before_proofs": tuple(tree.proof(row) for row in selected), "mutations": mutations, "limits": LIMITS}


class AuthorityRadixMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = IndependentTree([{"id": "a", "value": 1}, {"id": "b", "value": 2}])
        self.selected = self.tree.selected({"id": "a"})
        self.mutation = change(self.selected, "UPDATE", {"id": "a", "value": 3})
        self.arguments = batch(self.tree, (self.selected,), (self.mutation,))
        self.assertEqual(evaluate_primary_radix_batch(**self.arguments).business_after_roots,
                         (IndependentTree([{"id": "a", "value": 3}, {"id": "b", "value": 2}], revision=3).root,))

    def test_insert_update_same_value_and_delete_match_independent_rebuild(self) -> None:
        for rows, key, operation, after in (
            ([], {"id": "a"}, "INSERT", {"id": "a", "value": None}),
            ([{"id": "b", "value": 2}], {"id": "a"}, "INSERT", {"id": "a", "value": 1}),
            ([{"id": "a", "value": 1}], {"id": "a"}, "UPDATE", {"id": "a", "value": 2}),
            ([{"id": "a", "value": 1}], {"id": "a"}, "UPDATE", {"id": "a", "value": 1}),
            ([{"id": "a", "value": 1}], {"id": "a"}, "DELETE", None),
        ):
            with self.subTest(operation=operation, rows=rows, after=after):
                tree = IndependentTree(rows)
                selected = tree.selected(key)
                result = evaluate_primary_radix_batch(**batch(tree, (selected,), (change(selected, operation, after),)))
                expected_rows = [row for row in rows if tree.key(row) != key]
                if after is not None:
                    expected_rows.append(after)
                expected = IndependentTree(expected_rows, revision=tree.root.root_revision + 1)
                self.assertEqual(result.business_after_roots, (expected.root,))
                self.assertEqual(result.metrics.recomputed_ancestors, 64)
                self.assertEqual(result.metrics.proof_vectors, 64)
                self.assertEqual(result.metrics.proof_child_slots, 1024)
                self.assertEqual(result.metrics.hash_work, 66 + (70 if selected["present"] else 68)
                                 + (2 if after is not None else 0) + 64)
                if rows == [after]:
                    self.assertEqual(result.business_after_roots[0].root_digest, tree.root.root_digest)
                    self.assertEqual(result.business_after_roots[0].root_revision, tree.root.root_revision + 1)
                if not expected_rows:
                    self.assertEqual(result.business_after_roots[0].root_digest, tree.empty[0])
                    self.assertGreater(result.business_after_roots[0].root_revision, 0)

    def test_mixed_shared_prefix_batch_preserves_every_changed_and_opaque_branch(self) -> None:
        # Bounded deterministic fixture construction: 513 paths guarantee three
        # sharing a two-nibble prefix. This is not fuzzing or a hash collision.
        groups = {}
        shared = None
        for index in range(513):
            identifier = f"shared-{index}"
            path = sql_digest("serverware.policyAuthorityAuthenticatedKey/v1", b"items", sql_json({"id": identifier}))[7:]
            group = groups.setdefault(path[:2], [])
            group.append(identifier)
            if len(group) == 3:
                shared = group
                break
        self.assertIsNotNone(shared)
        updated, deleted, inserted = shared
        rows = [{"id": updated, "value": 1}, {"id": deleted, "value": 2},
                {"id": "read-only", "value": 4}, {"id": "opaque-unselected", "value": 5}]
        tree = IndependentTree(rows)
        selected = tuple(tree.selected({"id": identifier}) for identifier in (updated, deleted, inserted, "read-only"))
        mutations = (change(selected[0], "UPDATE", {"id": updated, "value": 7}),
                     change(selected[1], "DELETE", None),
                     change(selected[2], "INSERT", {"id": inserted, "value": 9}))
        args = batch(tree, selected, mutations)
        result = evaluate_primary_radix_batch(**args)
        expected = IndependentTree([rows[2], rows[3], {"id": updated, "value": 7}, {"id": inserted, "value": 9}], revision=7)
        self.assertEqual(result.business_after_roots, (expected.root,))
        self.assertLess(result.metrics.recomputed_ancestors, 3 * 64)
        self.assertEqual(result.business_after_roots,
                         evaluate_primary_radix_batch(**{**args, "mutations": tuple(reversed(mutations))}).business_after_roots)

    def test_complete_root_classes_and_two_tables_with_same_key_are_preserved(self) -> None:
        second = IndependentTree([{"id": "a", "value": 20}], table="second")
        untouched = IndependentTree([{"id": "opaque", "value": 8}], table="untouched")
        auth = IndependentTree([{"id": "authority", "value": 1}], table="authorization")
        selected_b, selected_auth = second.selected({"id": "a"}), auth.selected({"id": "authority"})
        args = {**self.arguments,
                "table_contracts": (self.tree.contract(), second.contract(), untouched.contract(writable=False),
                                    auth.contract(writable=False, root_class="authorization")),
                "business_before_roots": (untouched.root, second.root, self.tree.root),
                "authorization_before_roots": (auth.root,),
                "selected_rows": (self.selected, selected_b, selected_auth),
                "before_proofs": (auth.proof(selected_auth), second.proof(selected_b), self.tree.proof(self.selected)),
                "mutations": (self.mutation, change(selected_b, "UPDATE", {"id": "a", "value": 21}))}
        result = evaluate_primary_radix_batch(**args)
        self.assertEqual(result.business_after_roots,
                         (IndependentTree([{"id": "a", "value": 3}, {"id": "b", "value": 2}], revision=3).root,
                          IndependentTree([{"id": "a", "value": 21}], table="second", revision=2).root, untouched.root))
        self.assertEqual(result.authorization_after_roots, (auth.root,))
        forbidden = change(selected_auth, "UPDATE", {"id": "authority", "value": 2})
        with self.assertRaisesRegex(PrimaryRadixMutationError, "not writable business state"):
            evaluate_primary_radix_batch(**{**args, "mutations": (forbidden,)})

    def test_unicode_composite_keys_and_null_nonkey_fields_use_sql_utf8(self) -> None:
        before = {"tenant": "é雪", "sequence": 7, "enabled": True, "note": None}
        after = {**before, "note": "☃"}
        tree = IndependentTree([before], columns=("tenant", "sequence"))
        selected = tree.selected({"tenant": "é雪", "sequence": 7})
        result = evaluate_primary_radix_batch(**batch(tree, (selected,), (change(selected, "UPDATE", after),)))
        self.assertEqual(result.business_after_roots, (IndependentTree([after], columns=tree.columns, revision=2).root,))

    def test_input_graphs_are_unchanged_and_result_projection_is_fresh(self) -> None:
        before = copy.deepcopy(self.arguments)
        result = evaluate_primary_radix_batch(**self.arguments)
        self.assertEqual(self.arguments, before)
        projection = result.json_projection()
        projection["businessAfterRoots"][0]["leafCount"] = 0
        projection["businessAfterRoots"].clear()
        projection["metrics"]["hashWork"] = 0
        self.assertEqual(len(result.json_projection()["businessAfterRoots"]), 1)
        self.assertGreater(result.json_projection()["metrics"]["hashWork"], 0)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.metrics.hash_work = 0
        with self.assertRaises(PrimaryRadixMutationError):
            PrimaryRadixBatchResult([], (), result.metrics)

    def test_root_inventory_and_before_descriptor_binding_are_exact(self) -> None:
        unknown = dataclasses.replace(self.tree.root, table="unknown")
        for changes in (
            {"business_before_roots": ()},
            {"business_before_roots": (self.tree.root, self.tree.root)},
            {"business_before_roots": (unknown,)},
            {"business_before_roots": (), "authorization_before_roots": (self.tree.root,)},
            {"table_contracts": (self.tree.contract(), self.tree.contract()),
             "business_before_roots": (self.tree.root, self.tree.root)},
        ):
            with self.subTest(changes=changes), self.assertRaises(PrimaryRadixMutationError):
                evaluate_primary_radix_batch(**{**self.arguments, **changes})
        for root in (dataclasses.replace(self.tree.root, root_revision=3),
                     dataclasses.replace(self.tree.root, root_digest="sha256:" + "a" * 64)):
            with self.assertRaisesRegex(PrimaryRadixMutationError, "exact before descriptor"):
                evaluate_primary_radix_batch(**{**self.arguments, "business_before_roots": (root,)})

    def test_selected_proof_and_mutation_addresses_are_unique_and_closed(self) -> None:
        extra = self.tree.selected({"id": "b"})
        for changes in (
            {"selected_rows": (self.selected, self.selected),
             "before_proofs": (self.tree.proof(self.selected), self.tree.proof(self.selected))},
            {"before_proofs": ()},
            {"before_proofs": (self.tree.proof(extra),)},
            {"selected_rows": (self.selected, extra),
             "before_proofs": (self.tree.proof(self.selected), self.tree.proof(self.selected))},
            {"mutations": (self.mutation, self.mutation)},
            {"mutations": (change(extra, "DELETE", None),)},
        ):
            with self.subTest(changes=changes), self.assertRaises(PrimaryRadixMutationError):
                evaluate_primary_radix_batch(**{**self.arguments, **changes})
        for collection in ("selected_rows", "before_proofs", "mutations"):
            original = self.arguments[collection][0]
            missing = dict(original)
            del missing[next(iter(missing))]
            for invalid in (missing, {**original, "extra": None}):
                with self.subTest(collection=collection), self.assertRaises(PrimaryRadixMutationError):
                    evaluate_primary_radix_batch(**{**self.arguments, collection: (invalid,)})

    def test_stale_and_malformed_proofs_fail_even_after_selfdigest_refresh(self) -> None:
        original = self.tree.proof(self.selected)
        changed = copy.deepcopy(original)
        changed["siblings"][0]["childDigests"][0] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(PrimaryRadixMutationError, "proof digest changed"):
            evaluate_primary_radix_batch(**{**self.arguments, "before_proofs": (changed,)})
        mutations = (
            lambda proof: proof.update(rootRevision=True),
            lambda proof: proof.update(present=1),
            lambda proof: proof["siblings"].pop(),
            lambda proof: proof["siblings"][0].update(depth=False),
            lambda proof: proof["siblings"][1].update(pathPrefix="z"),
            lambda proof: proof["siblings"][0].update(selectedNibble="z"),
            lambda proof: proof["siblings"][0]["childDigests"].pop(),
            lambda proof: proof["siblings"][0]["childDigests"].append("sha256:" + "0" * 64),
            lambda proof: proof["siblings"][0]["childDigests"].__setitem__(0, "sha256:" + "0" * 64),
        )
        for mutate in mutations:
            changed = copy.deepcopy(original)
            mutate(changed)
            refresh_proof_digest(changed)
            with self.assertRaises(PrimaryRadixMutationError):
                evaluate_primary_radix_batch(**{**self.arguments, "before_proofs": (changed,)})
        # These are invalid before proofs, not manufactured distinct valid
        # same-root proofs claiming a SHA256 collision at the merge boundary.

    def test_business_address_cannot_be_replaced_by_tree_address(self) -> None:
        selected = copy.deepcopy(self.selected)
        selected["keyDigest"] = sql_digest("serverware.policyAuthorityAuthenticatedKey/v1", b"items", sql_json(selected["key"]))
        args = batch(self.tree, (selected,), (change(selected, "UPDATE", self.mutation["row"]),))
        with self.assertRaisesRegex(PrimaryRadixMutationError, "before proof reconstruction"):
            evaluate_primary_radix_batch(**args)

    def test_operation_lifecycle_full_cas_and_image_presence_are_strict(self) -> None:
        for invalid in (None, {}, [], False, "null", {"id": "a", "value": True}, {"id": "a", "value": 9}):
            with self.subTest(old=invalid), self.assertRaisesRegex(PrimaryRadixMutationError, "old full-row CAS"):
                evaluate_primary_radix_batch(**{**self.arguments, "mutations": ({**self.mutation, "expectedRow": invalid},)})
        for field in ("expectedRow", "row"):
            invalid = dict(self.mutation)
            del invalid[field]
            with self.assertRaisesRegex(PrimaryRadixMutationError, "mutation is not closed"):
                evaluate_primary_radix_batch(**{**self.arguments, "mutations": (invalid,)})
        for operation, after in (("INSERT", self.mutation["row"]), ("UPDATE", None), ("DELETE", {})):
            with self.assertRaises(PrimaryRadixMutationError):
                evaluate_primary_radix_batch(**{**self.arguments, "mutations": (change(self.selected, operation, after),)})
        absent = self.tree.selected({"id": "absent"})
        for operation in ("UPDATE", "DELETE"):
            with self.assertRaisesRegex(PrimaryRadixMutationError, "old full-row CAS"):
                evaluate_primary_radix_batch(**batch(self.tree, (absent,), (change(absent, operation, None),)))
        for invalid in ({}, [], False, "null"):
            proposed = change(absent, "INSERT", {"id": "absent", "value": 1})
            proposed["expectedRow"] = invalid
            with self.assertRaisesRegex(PrimaryRadixMutationError, "INSERT lifecycle"):
                evaluate_primary_radix_batch(**batch(self.tree, (absent,), (proposed,)))

    def test_original_primary_key_fields_cannot_move_or_coerce(self) -> None:
        for key in ({}, {"id": "a", "extra": None}, {"id": None}, {"id": []}):
            selected = {**self.selected, "key": key}
            with self.assertRaises(PrimaryRadixMutationError):
                evaluate_primary_radix_batch(**{**self.arguments, "selected_rows": (selected,)})
        for after in ({"value": 1}, {"id": "moved", "value": 1}, {"id": None, "value": 1}):
            with self.assertRaisesRegex(PrimaryRadixMutationError, "primary key|original key"):
                evaluate_primary_radix_batch(**{**self.arguments, "mutations": ({**self.mutation, "row": after},)})
        tree = IndependentTree([{"id": 1, "value": 2}])
        selected = tree.selected({"id": 1})
        args = batch(tree, (selected,), (change(selected, "UPDATE", {"id": True, "value": 2}),))
        with self.assertRaisesRegex(PrimaryRadixMutationError, "original key changed"):
            evaluate_primary_radix_batch(**args)
        # A forged derived projection must not pass Python's True == 1 equality.
        changed_proof = copy.deepcopy(args["before_proofs"][0])
        changed_proof["key"]["id"] = True
        refresh_proof_digest(changed_proof)
        with self.assertRaisesRegex(PrimaryRadixMutationError, "before descriptor or key"):
            evaluate_primary_radix_batch(**{**args, "before_proofs": (changed_proof,)})

    def test_exact_counter_types_overflow_and_proved_count_consistency(self) -> None:
        for field in ("root_revision", "leaf_count"):
            for invalid in (True, "2", -1, 2**63, 2.0):
                with self.subTest(field=field, invalid=invalid), self.assertRaisesRegex(PrimaryRadixMutationError, "int64"):
                    dataclasses.replace(self.tree.root, **{field: invalid})
        for same_value in (False, True):
            tree = IndependentTree(list(self.tree.rows.values()), revision=2**63 - 1)
            selected = tree.selected({"id": "a"})
            after = selected["row"] if same_value else self.mutation["row"]
            with self.assertRaisesRegex(PrimaryRadixMutationError, "after root revision"):
                evaluate_primary_radix_batch(**batch(tree, (selected,), (change(selected, "UPDATE", after),)))
        absent = self.tree.selected({"id": "absent"})
        args = batch(self.tree, (absent,), (change(absent, "INSERT", {"id": "absent"}),))
        args["business_before_roots"] = (dataclasses.replace(self.tree.root, leaf_count=2**63 - 1),)
        with self.assertRaisesRegex(PrimaryRadixMutationError, "after root leaf count"):
            evaluate_primary_radix_batch(**args)
        other = self.tree.selected({"id": "b"})
        args = batch(self.tree, (self.selected, other), (change(self.selected, "DELETE", None), change(other, "DELETE", None)))
        args["business_before_roots"] = (dataclasses.replace(self.tree.root, leaf_count=1),)
        with self.assertRaisesRegex(PrimaryRadixMutationError, "proved membership exceeds"):
            evaluate_primary_radix_batch(**args)

    def test_lossless_json_rejects_numeric_scale_mutable_buffers_and_cycles(self) -> None:
        for invalid in (1.0, Decimal("1.00"), float("nan"), b"bytes", bytearray(b"bytes"), ("tuple",), "\ud800"):
            mutation = copy.deepcopy(self.mutation)
            mutation["row"]["value"] = invalid
            with self.subTest(kind=type(invalid)), self.assertRaises(PrimaryRadixMutationError):
                evaluate_primary_radix_batch(**{**self.arguments, "mutations": (mutation,)})
        cyclic = []
        cyclic.append(cyclic)
        mutation = {**self.mutation, "row": {"id": "a", "value": cyclic}}
        with self.assertRaisesRegex(PrimaryRadixMutationError, "cyclic"):
            evaluate_primary_radix_batch(**{**self.arguments, "mutations": (mutation,)})

    def test_each_explicit_budget_is_enforced_without_changing_old_work_units(self) -> None:
        metrics = evaluate_primary_radix_batch(**self.arguments).metrics
        for field, bound, message in (
            ("max_proof_vectors", metrics.proof_vectors - 1, "vector budget"),
            ("max_proof_child_slots", metrics.proof_child_slots - 1, "vector budget"),
            ("max_hashes", metrics.hash_work - 1, "hash budget"),
            ("max_input_bytes", metrics.input_bytes - 1, "byte budget"),
            ("max_json_nodes", metrics.json_nodes - 1, "structure budget"),
            ("max_json_depth", 1, "structure budget"),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(PrimaryRadixMutationError, message):
                evaluate_primary_radix_batch(**{**self.arguments, "limits": dataclasses.replace(LIMITS, **{field: bound})})
        exact = dataclasses.replace(LIMITS, max_proof_vectors=metrics.proof_vectors,
                                    max_proof_child_slots=metrics.proof_child_slots, max_hashes=metrics.hash_work,
                                    max_input_bytes=metrics.input_bytes, max_json_nodes=metrics.json_nodes)
        self.assertEqual(evaluate_primary_radix_batch(**{**self.arguments, "limits": exact}).metrics, metrics)
        other = self.tree.selected({"id": "b"})
        args = batch(self.tree, (self.selected, other), (self.mutation, change(other, "DELETE", None)))
        for field in ("max_selected_rows", "max_mutations"):
            with self.assertRaisesRegex(PrimaryRadixMutationError, "inventory count"):
                evaluate_primary_radix_batch(**{**args, "limits": dataclasses.replace(LIMITS, **{field: 1})})
        for invalid in (True, 0, -1, 1.0):
            with self.assertRaisesRegex(PrimaryRadixMutationError, "budget profile"):
                dataclasses.replace(LIMITS, max_hashes=invalid)

    def test_empty_mutation_batch_preserves_all_roots_without_inventing_authority(self) -> None:
        result = evaluate_primary_radix_batch(**{**self.arguments, "selected_rows": (), "before_proofs": (), "mutations": ()})
        self.assertEqual(result.business_after_roots, (self.tree.root,))
        self.assertEqual(result.metrics.recomputed_ancestors, 0)
        self.assertEqual(result.metrics.hash_work, 66)
        self.assertFalse(hasattr(result, "signature"))
        self.assertFalse(hasattr(result, "witness_receipt"))
        for invalid in (("id", "id"), (), ["id"], ([],)):
            with self.assertRaises(PrimaryRadixMutationError):
                PrimaryTableContract("items", invalid, True, "business")
        with self.assertRaises(PrimaryRadixMutationError):
            PrimaryTableContract("items", ("id",), True, "authorization")


    def test_memberships_retain_verified_owned_graphs_without_extra_copy_or_hash_metrics(self) -> None:
        tree = IndependentTree([{"id": "é雪", "value": {"nested": [1, None, "☃"]}}])
        selected = (tree.selected({"id": "é雪"}), tree.selected({"id": "absent"}))
        arguments = batch(tree, selected, ())
        # Matching uses exact addresses, not the caller's independent tuple order.
        arguments["before_proofs"] = tuple(reversed(arguments["before_proofs"]))
        pristine = copy.deepcopy(arguments)
        expected = evaluate_primary_radix_batch(**arguments)
        membership_arguments = {name: value for name, value in arguments.items() if name != "mutations"}
        observed = evaluate_primary_radix_memberships(**membership_arguments)
        self.assertIs(type(observed), PrimaryRadixMembershipResult)
        self.assertEqual(observed.result, expected)
        self.assertEqual(observed.result.metrics.hash_work, 66 + 70 + 68)
        self.assertEqual(observed.selected_rows, selected)
        self.assertEqual(observed.before_proofs, arguments["before_proofs"])
        self.assertEqual(arguments, pristine)
        self.assertIsNot(observed.selected_rows[0], selected[0])
        self.assertIsNot(observed.selected_rows[0]["key"], selected[0]["key"])
        self.assertIsNot(observed.selected_rows[0]["row"]["value"]["nested"],
                         selected[0]["row"]["value"]["nested"])
        self.assertIsNot(observed.before_proofs[0]["siblings"][0]["childDigests"],
                         arguments["before_proofs"][0]["siblings"][0]["childDigests"])
        by_address = {(proof["table"], proof["keyDigest"]): proof for proof in observed.before_proofs}
        present = observed.selected_rows[0]
        self.assertEqual(by_address[(present["table"], present["keyDigest"])]["rowDigest"],
                         sql_digest("serverware.policyAuthorityAuthenticatedRow/v1", b"items", sql_json(present["row"])))
        self.assertEqual(present["keyDigest"], wire_digest(
            "serverware.policyAuthorityBusinessKey/v1", b"items", wire_json(present["key"])))
        selected[0]["row"]["value"]["nested"].append("caller change")
        arguments["before_proofs"][0]["siblings"][0]["childDigests"][0] = "sha256:" + "0" * 64
        self.assertEqual(observed.selected_rows, pristine["selected_rows"])
        self.assertEqual(observed.before_proofs, pristine["before_proofs"])
        with self.assertRaises(dataclasses.FrozenInstanceError):
            observed.selected_rows = ()
        # Inner dictionaries are owned, not frozen or reusable verification tokens.
        observed.selected_rows[0]["row"]["value"]["nested"].append("owned change")
        again = evaluate_primary_radix_memberships(**{
            name: value for name, value in pristine.items() if name != "mutations"
        })
        self.assertEqual(again.selected_rows, pristine["selected_rows"])

    def test_memberships_reverify_proofs_and_never_accept_a_caller_created_result(self) -> None:
        arguments = {name: value for name, value in self.arguments.items() if name != "mutations"}
        observation = evaluate_primary_radix_memberships(**arguments)
        for changed in (observation, PrimaryRadixMembershipResult(
                observation.result, observation.selected_rows, observation.before_proofs)):
            with self.assertRaises(PrimaryRadixMutationError):
                evaluate_primary_radix_memberships(**{**arguments, "selected_rows": changed})
        bad_selected = copy.deepcopy(self.selected)
        bad_selected["row"]["value"] = 999
        with self.assertRaisesRegex(PrimaryRadixMutationError, "before proof reconstruction"):
            evaluate_primary_radix_memberships(**{**arguments, "selected_rows": (bad_selected,)})
        bad_proof = copy.deepcopy(arguments["before_proofs"][0])
        bad_proof["rowDigest"] = "sha256:" + "a" * 64
        refresh_proof_digest(bad_proof)
        with self.assertRaisesRegex(PrimaryRadixMutationError, "before proof reconstruction"):
            evaluate_primary_radix_memberships(**{**arguments, "before_proofs": (bad_proof,)})
        with self.assertRaises(TypeError):
            evaluate_primary_radix_memberships(**arguments, mutations=())
        empty = evaluate_primary_radix_memberships(**{**arguments, "selected_rows": (), "before_proofs": ()})
        self.assertEqual((empty.selected_rows, empty.before_proofs), ((), ()))
        self.assertEqual(empty.result.business_after_roots, (self.tree.root,))
        self.assertEqual(empty.result.metrics.hash_work, 66)

    def test_both_evaluator_paths_revalidate_bypassed_and_incomplete_contexts(self) -> None:
        def changed(instance, **updates):
            owned = object.__new__(type(instance))
            for field in dataclasses.fields(instance):
                object.__setattr__(owned, field.name, updates.get(field.name, getattr(instance, field.name)))
            return owned

        contract = self.tree.contract()
        root = self.tree.root
        cases = (
            {"limits": changed(LIMITS, max_hashes=True)},
            {"limits": changed(LIMITS, max_input_bytes=2**63)},
            {"limits": object.__new__(PrimaryRadixLimits)},
            {"limits": {}},
            {"table_contracts": (changed(contract, write_access=1),)},
            {"table_contracts": (changed(contract, key_columns=["id"]),)},
            {"table_contracts": (changed(contract, table="Upper"),)},
            {"table_contracts": (object.__new__(PrimaryTableContract),)},
            {"table_contracts": ({},)},
            {"business_before_roots": (changed(root, root_revision=True),)},
            {"business_before_roots": (changed(root, leaf_count=True),)},
            {"business_before_roots": (changed(root, root_revision=-1),)},
            {"business_before_roots": (changed(root, root_digest="not-a-digest"),)},
            {"business_before_roots": (object.__new__(PrimaryRoot),)},
            {"business_before_roots": ({},)},
        )
        for selected, proofs in (((), ()), ((self.selected,), self.arguments["before_proofs"])):
            base = {**self.arguments, "selected_rows": selected, "before_proofs": proofs, "mutations": ()}
            for case_number, changes in enumerate(cases):
                with self.subTest(case=case_number, populated=bool(selected)):
                    with self.assertRaises(PrimaryRadixMutationError):
                        evaluate_primary_radix_batch(**{**base, **changes})
                    with self.assertRaises(PrimaryRadixMutationError):
                        evaluate_primary_radix_memberships(**{
                            name: value for name, value in {**base, **changes}.items() if name != "mutations"
                        })

    def test_engine_uses_fresh_context_snapshots_after_copy_entry(self) -> None:
        original_snapshot = radix_mutation._Budget.snapshot
        for memberships in (False, True):
            arguments = copy.deepcopy({**self.arguments, "mutations": ()})
            expected = evaluate_primary_radix_batch(**arguments)
            observed = []

            def snapshot(budget, value, depth=0, ancestors=frozenset()):
                if depth == 0:
                    observed.append(True)
                    object.__setattr__(arguments["limits"], "max_hashes", 1)
                    object.__setattr__(arguments["table_contracts"][0], "table", "changed")
                    object.__setattr__(arguments["business_before_roots"][0], "root_digest", "sha256:" + "a" * 64)
                # This is a controlled caller-input mutation, not a successful
                # verifier substitute: every real snapshot call still runs.
                return original_snapshot(budget, value, depth, ancestors)

            with mock.patch.object(radix_mutation._Budget, "snapshot", snapshot):
                if memberships:
                    result = evaluate_primary_radix_memberships(**{
                        name: value for name, value in arguments.items() if name != "mutations"
                    }).result
                else:
                    result = evaluate_primary_radix_batch(**arguments)
            self.assertEqual(observed, [True])
            self.assertEqual(result, expected)
            self.assertEqual(arguments["limits"].max_hashes, 1)


if __name__ == "__main__":
    unittest.main()
