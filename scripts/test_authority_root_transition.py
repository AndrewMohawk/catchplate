#!/usr/bin/env python3
"""Pure root-transition profile tests using real source operation/key contracts.

IndependentTree rebuilds the SQL-format tree without production hash helpers.
Rows are small component values, not complete admitted operation inputs. No
registry patch, database, signer, witness or current-root authority is supplied.
Source-wiring checks do not import the deliberately blocked planner/executor or
claim that SQL, signatures, transaction admission or a full operation ran.
"""
from __future__ import annotations

import ast
import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract
from serverware import authority_primary_contract as primary
from serverware import authority_root_transition as transition
from serverware.authority_radix_mutation import PrimaryRadixMutationError
from test_authority_radix_mutation import IndependentTree, change
from test_authority_radix_proof import sql_json, wire_digest, wire_json


COUNTER = "webauthn.counter.cas"
CHALLENGE = "webauthn.challenge.consume"


def fixture(operation: str = COUNTER) -> tuple[dict, dict[str, IndependentTree]]:
    """Use the actual source closure, with no inferred/caller-supplied keys."""
    rows = {
        "webauthn_credentials": [{"id": "credential-a", "sign_count": 1, "label": "hardware"}],
        "webauthn_challenges": [{"id": "challenge-a", "used_at": None}],
    }
    trees = {
        contract.table: IndependentTree(rows.get(contract.table, []), table=contract.table,
                                        columns=contract.key_columns)
        for contract in primary.primary_table_contracts(operation)
    }
    target = "webauthn_credentials" if operation == COUNTER else "webauthn_challenges"
    selected = []
    proofs = []
    for contract in primary.primary_table_contracts(operation):
        tree = trees[contract.table]
        key = tree.key(rows[contract.table][0]) if rows.get(contract.table) else {
            column: "absent-" + column for column in contract.key_columns
        }
        entry = tree.selected(key)
        selected.append(entry)
        proofs.append(tree.proof(entry))
    target_row = next(row for row in selected if row["table"] == target)
    after = ({**target_row["row"], "sign_count": 2} if operation == COUNTER
             else {**target_row["row"], "used_at": "2026-01-01T00:00:00Z"})
    return {
        "operation": operation,
        "business_before_roots": [trees[contract.table].root.json_projection()
                                  for contract in primary.primary_table_contracts(operation)
                                  if contract.root_class == "business"],
        "authorization_before_roots": [trees[contract.table].root.json_projection()
                                       for contract in primary.primary_table_contracts(operation)
                                       if contract.root_class == "authorization"],
        "selected_rows": selected,
        "before_proofs": proofs,
        "mutations": [change(target_row, "UPDATE", after)],
    }, trees


def verify(value: dict, arguments: dict) -> dict:
    return transition.verify_primary_root_transition(
        operation=arguments["operation"], value=value,
        selected_rows=arguments["selected_rows"], before_proofs=arguments["before_proofs"],
        mutations=arguments["mutations"],
    )


def source_module(relative: str, *, maximum: int = 2 * 1024 * 1024) -> tuple[str, ast.Module]:
    path = ROOT / relative
    if path.stat().st_size > maximum:
        raise AssertionError("source-wiring fixture exceeded its bounded file size")
    source = path.read_text(encoding="utf-8")
    return source, ast.parse(source)


def function(tree: ast.AST, name: str) -> ast.FunctionDef:
    matches = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(matches) != 1:
        raise AssertionError(f"source function is not unique: {name}")
    return matches[0]


def calls(tree: ast.AST, name: str) -> list[ast.Call]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and ((isinstance(node.func, ast.Name) and node.func.id == name)
                 or (isinstance(node.func, ast.Attribute) and node.func.attr == name))]


class AuthorityRootTransitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.arguments, self.trees = fixture()
        self.value = transition.derive_primary_root_transition(**self.arguments)
        self.assertEqual(verify(self.value, self.arguments), self.value)

    def test_real_operation_contract_and_independent_after_tree_agree(self) -> None:
        self.assertEqual(primary.PRIMARY_KEY_COLUMNS["webauthn_credentials"], ("id",))
        expected = IndependentTree([self.arguments["mutations"][0]["row"]],
                                   table="webauthn_credentials", revision=2)
        self.assertEqual(self.value["businessAfterRoots"], [expected.root.json_projection()])
        self.assertEqual(self.value["authorizationBeforeRoots"], [])
        self.assertEqual(self.value["authorizationAfterRoots"], [])
        self.assertEqual(self.value["metrics"]["selectedRows"], 1)
        self.assertEqual(self.value["metrics"]["mutations"], 1)
        self.assertEqual(self.value["metrics"]["proofVectors"], 64)
        self.assertEqual(self.value["metrics"]["proofChildSlots"], 1024)
        self.assertEqual(self.value["metrics"]["recomputedAncestors"], 64)
        self.assertEqual(self.value["metrics"]["hashWork"], 66 + 70 + 2 + 64)
        self.assertNotIn("workUnits", self.value["metrics"])

    def test_same_value_update_changes_revision_not_hash_or_count(self) -> None:
        arguments = copy.deepcopy(self.arguments)
        arguments["mutations"][0]["row"] = copy.deepcopy(arguments["mutations"][0]["expectedRow"])
        result = transition.derive_primary_root_transition(**arguments)
        before = result["businessBeforeRoots"][0]
        self.assertEqual(result["businessAfterRoots"], [{**before, "rootRevision": before["rootRevision"] + 1}])
        self.assertEqual(verify(result, arguments), result)

    def test_authorization_inventory_stays_unchanged_with_real_source_classes(self) -> None:
        arguments, trees = fixture(CHALLENGE)
        result = transition.derive_primary_root_transition(**arguments)
        spec = authority_contract.operation_spec(CHALLENGE)
        self.assertEqual([root["table"] for root in result["authorizationBeforeRoots"]],
                         list(spec["authorizationReads"]))
        self.assertEqual(result["authorizationBeforeRoots"], result["authorizationAfterRoots"])
        expected = IndependentTree([arguments["mutations"][0]["row"]],
                                   table="webauthn_challenges", revision=2)
        self.assertEqual(result["businessAfterRoots"], [expected.root.json_projection()])
        auth_row = next(row for row in arguments["selected_rows"] if row["table"] == "webauthn_credentials")
        self.assertEqual(trees["webauthn_credentials"].root.json_projection(),
                         next(root for root in result["authorizationAfterRoots"] if root["table"] == auth_row["table"]))
        with self.assertRaisesRegex(PrimaryRadixMutationError, "not writable business state"):
            transition.derive_primary_root_transition(**{
                **arguments, "mutations": [change(auth_row, "UPDATE", {**auth_row["row"], "sign_count": 2})],
            })

    def test_root_digest_uses_independent_wire_framing_and_every_closed_field(self) -> None:
        expected = wire_digest(transition.TRANSITION_SCHEMA, wire_json(self.value))
        self.assertEqual(transition.primary_root_transition_digest(self.value), expected)
        changed = copy.deepcopy(self.value)
        changed["businessAfterRoots"][0]["rootRevision"] += 1
        # A new valid profile digest does not make the claimed delta correct.
        self.assertNotEqual(transition.primary_root_transition_digest(changed), expected)
        with self.assertRaisesRegex(PrimaryRadixMutationError, "recomputed complete delta"):
            verify(changed, self.arguments)
        with self.assertRaisesRegex(PrimaryRadixMutationError, "profile is not closed"):
            transition.primary_root_transition_digest({**self.value, "digest": expected})

    def test_well_formed_after_and_metrics_substitutions_fail_recomputation(self) -> None:
        for section, field, value in (
            ("root", "rootDigest", "sha256:" + "1" * 64),
            ("root", "rootRevision", 3), ("root", "leafCount", 2),
            ("metrics", "recomputedAncestors", 63), ("metrics", "hashWork", 203),
            ("metrics", "inputBytes", self.value["metrics"]["inputBytes"] + 1),
            ("metrics", "jsonNodes", self.value["metrics"]["jsonNodes"] + 1),
        ):
            with self.subTest(section=section, field=field):
                changed = copy.deepcopy(self.value)
                target = changed["businessAfterRoots"][0] if section == "root" else changed["metrics"]
                target[field] = value
                self.assertEqual(transition.validate_primary_root_transition(changed), changed)
                with self.assertRaisesRegex(PrimaryRadixMutationError, "recomputed complete delta"):
                    verify(changed, self.arguments)

    def test_before_descriptor_and_proof_digest_substitutions_are_rejected(self) -> None:
        for field, value in (("rootRevision", 2), ("rootDigest", "sha256:" + "2" * 64)):
            changed = copy.deepcopy(self.value)
            changed["businessBeforeRoots"][0][field] = value
            with self.assertRaisesRegex(PrimaryRadixMutationError, "exact before descriptor or key"):
                verify(changed, self.arguments)
        arguments = copy.deepcopy(self.arguments)
        arguments["before_proofs"][0]["proofDigest"] = "sha256:" + "3" * 64
        with self.assertRaisesRegex(PrimaryRadixMutationError, "proof digest changed"):
            verify(self.value, arguments)
        arguments = copy.deepcopy(self.arguments)
        arguments["mutations"][0]["keyDigest"] = "sha256:" + "4" * 64
        with self.assertRaisesRegex(PrimaryRadixMutationError, "address is unselected or duplicated"):
            verify(self.value, arguments)

    def test_source_key_inventory_and_root_class_cannot_be_caller_selected(self) -> None:
        arguments = copy.deepcopy(self.arguments)
        arguments["selected_rows"][0]["key"] = {"caller_key": "credential-a"}
        with self.assertRaisesRegex(PrimaryRadixMutationError, "key columns are not exact"):
            transition.derive_primary_root_transition(**arguments)
        for changed, message in (
            ({"business_before_roots": []}, "inventory count is not closed"),
            ({"business_before_roots": [], "authorization_before_roots": self.arguments["business_before_roots"]},
             "root inventory identity or class changed"),
            ({"business_before_roots": [{**self.arguments["business_before_roots"][0], "table": "unknown"}]},
             "root inventory identity or class changed"),
        ):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(PrimaryRadixMutationError, message):
                    transition.derive_primary_root_transition(**{**self.arguments, **changed})
        with self.assertRaisesRegex(ValueError, "closed authority contract"):
            transition.derive_primary_root_transition(**{**self.arguments, "operation": "unknown.operation"})

    def test_closed_wire_types_bounds_and_relationships_remain_exact(self) -> None:
        for field in ("schema", "profile"):
            with self.assertRaisesRegex(PrimaryRadixMutationError, "profile is not closed"):
                transition.validate_primary_root_transition({**self.value, field: "legacy"})
        for malformed in (True, "1", 1.0, -1, 2**63):
            changed = copy.deepcopy(self.value)
            changed["businessBeforeRoots"][0]["rootRevision"] = malformed
            with self.assertRaisesRegex(PrimaryRadixMutationError, "exact nonnegative int64"):
                transition.validate_primary_root_transition(changed)
        for field, bound in transition.metric_bounds().items():
            for malformed in (True, "1", 1.0, -1, bound + 1):
                changed = copy.deepcopy(self.value)
                changed["metrics"][field] = malformed
                with self.subTest(field=field, malformed=malformed):
                    with self.assertRaisesRegex(PrimaryRadixMutationError, "bounded integers"):
                        transition.validate_primary_root_transition(changed)
        for field, malformed in (("proofVectors", 63), ("proofChildSlots", 1023),
                                 ("recomputedAncestors", 65), ("hashWork", 65),
                                 ("inputBytes", 0), ("jsonNodes", 0)):
            changed = copy.deepcopy(self.value)
            changed["metrics"][field] = malformed
            with self.assertRaisesRegex(PrimaryRadixMutationError, "metric relationships changed"):
                transition.validate_primary_root_transition(changed)
        changed = copy.deepcopy(self.value)
        changed["businessBeforeRoots"].append(copy.deepcopy(changed["businessBeforeRoots"][0]))
        with self.assertRaisesRegex(PrimaryRadixMutationError, "sorted and unique"):
            transition.validate_primary_root_transition(changed)

    def test_operation_capacity_is_checked_before_repeated_proof_work(self) -> None:
        spec = authority_contract.operation_spec(COUNTER)
        for changed in (
            {"selected_rows": self.arguments["selected_rows"] * (spec["maximumQueryRows"] + 1)},
            {"before_proofs": []},
            {"mutations": self.arguments["mutations"] * (spec["maximumMutations"] + 1)},
        ):
            with self.assertRaisesRegex(PrimaryRadixMutationError, "inventory exceeds operation bounds"):
                transition.derive_primary_root_transition(**{**self.arguments, **changed})
        with self.assertRaisesRegex(PrimaryRadixMutationError, "inventory is not an array"):
            transition.derive_primary_root_transition(**{**self.arguments, "selected_rows": iter(())})

    def test_unicode_primary_tree_and_fresh_profile_projections(self) -> None:
        row = {"id": "clé-雪", "label": "café", "sign_count": 1}
        tree = IndependentTree([row], table="webauthn_credentials")
        selected = tree.selected({"id": row["id"]})
        after = {**row, "sign_count": 2, "label": "☃"}
        arguments = {**self.arguments, "business_before_roots": [tree.root.json_projection()],
                     "selected_rows": [selected], "before_proofs": [tree.proof(selected)],
                     "mutations": [change(selected, "UPDATE", after)]}
        original = copy.deepcopy(arguments)
        result = transition.derive_primary_root_transition(**arguments)
        self.assertEqual(result["businessAfterRoots"],
                         [IndependentTree([after], table=tree.table, revision=2).root.json_projection()])
        self.assertEqual(arguments, original)
        fresh = transition.validate_primary_root_transition(result)
        fresh["businessAfterRoots"][0]["leafCount"] = 0
        fresh["metrics"]["hashWork"] = 0
        self.assertEqual(verify(result, arguments), result)
        limits = transition.metric_bounds()
        limits["hashWork"] = 0
        self.assertEqual(transition.metric_bounds()["hashWork"], 34882)

    def test_actual_authorization_sources_bind_present_and_absent_primary_rows(self) -> None:
        arguments, _ = fixture(CHALLENGE)
        # Authenticate all selected rows first; the projection is not itself a
        # membership verifier or a substitute for this complete delta check.
        result = transition.derive_primary_root_transition(**arguments)
        self.assertEqual(verify(result, arguments), result)
        sources = transition.derive_authorization_sources(operation=CHALLENGE,
                                                         selected_rows=arguments["selected_rows"])
        self.assertEqual([entry["table"] for entry in sources],
                         list(authority_contract.operation_spec(CHALLENGE)["authorizationReads"]))
        self.assertEqual({entry["present"] for entry in sources}, {True, False})
        for source in sources:
            self.assertEqual(set(source), {"table", "selector", "present", "row", "rowDigest"})
            self.assertEqual(set(source["selector"]), set(primary.PRIMARY_KEY_COLUMNS[source["table"]]))
            expected = wire_digest("serverware.policyAuthorityAuthorizationRow/v1", source["table"].encode("ascii"),
                                   wire_json(source["selector"]), b"present" if source["present"] else b"absent",
                                   wire_json(source["row"]))
            self.assertEqual(source["rowDigest"], expected)
            self.assertNotIn("authenticatedRelation", source["selector"])
        self.assertEqual(transition.derive_authorization_sources(operation=COUNTER,
                                                               selected_rows=self.arguments["selected_rows"]), [])

    def test_authorization_query_coverage_is_separate_and_fail_closed(self) -> None:
        arguments, _ = fixture(CHALLENGE)
        business_only = [entry for entry in arguments["selected_rows"] if entry["table"] == "webauthn_challenges"]
        # An unchanged supplied auth root is valid delta input, but never means
        # an authorization query actually selected its required source row.
        delta_only = {**arguments, "selected_rows": business_only,
                      "before_proofs": [proof for proof in arguments["before_proofs"]
                                        if proof["table"] == "webauthn_challenges"]}
        transition.derive_primary_root_transition(**delta_only)
        with self.assertRaisesRegex(PrimaryRadixMutationError, "do not cover declared relations"):
            transition.derive_authorization_sources(operation=CHALLENGE, selected_rows=business_only)
        auth = next(row for row in arguments["selected_rows"] if row["table"] == "webauthn_credentials")
        with self.assertRaisesRegex(PrimaryRadixMutationError, "identity is duplicated"):
            transition.derive_authorization_sources(operation=CHALLENGE,
                                                   selected_rows=arguments["selected_rows"] + [auth])
        malformed = copy.deepcopy(arguments["selected_rows"])
        next(row for row in malformed if row["table"] == auth["table"])["present"] = 1
        with self.assertRaisesRegex(PrimaryRadixMutationError, "key or presence is not exact"):
            transition.derive_authorization_sources(operation=CHALLENGE, selected_rows=malformed)

    def test_unicode_authorization_wire_sql_interoperability_is_explicitly_unresolved(self) -> None:
        arguments, _ = fixture(CHALLENGE)
        row = next(entry for entry in arguments["selected_rows"] if entry["table"] == "webauthn_credentials")
        row["row"]["label"] = "café-雪"
        tree = IndependentTree([row["row"]], table=row["table"])
        arguments["authorization_before_roots"] = [
            tree.root.json_projection() if root["table"] == tree.table else root
            for root in arguments["authorization_before_roots"]
        ]
        arguments["before_proofs"] = [tree.proof(row) if proof["table"] == tree.table else proof
                                     for proof in arguments["before_proofs"]]
        transition.derive_primary_root_transition(**arguments)
        source = next(entry for entry in transition.derive_authorization_sources(
            operation=CHALLENGE, selected_rows=arguments["selected_rows"]) if entry["table"] == tree.table)
        domain = "serverware.policyAuthorityAuthorizationRow/v1"
        self.assertEqual(source["rowDigest"], wire_digest(domain, tree.table.encode(), wire_json(source["selector"]),
                                                        b"present", wire_json(source["row"])))
        # Existing executor canonical_json renders literal UTF-8 here. This
        # expected INEQUALITY records the open interoperability defect, not an
        # accepted release or permission to change the persisted tree protocol.
        self.assertNotEqual(source["rowDigest"], wire_digest(domain, tree.table.encode(), sql_json(source["selector"]),
                                                           b"present", sql_json(source["row"])))

    def test_source_wiring_recomputes_before_persistence_and_binds_snapshot_nine(self) -> None:
        _, planner = source_module("serverware/authority_planner.py")
        constants = {target.id: node.value.value for node in planner.body if isinstance(node, ast.Assign)
                     and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
                     for target in node.targets if isinstance(target, ast.Name)}
        self.assertEqual(constants["PLANNER_RESPONSE_SCHEMA"], "serverware.policyAuthorityPlannerResponse/v3")
        self.assertEqual(constants["MEASURED_PLAN_SCHEMA"], "serverware.policyAuthorityMeasuredPlan/v3")
        self.assertEqual(constants["SIGNED_MEASURED_PLAN_SCHEMA"], "serverware.signedPolicyAuthorityMeasuredPlan/v3")
        validator = function(planner, "validate_measured_plan_payload")
        closed_sets = {target.id: ast.literal_eval(node.value) for node in validator.body
                       if isinstance(node, ast.Assign) and isinstance(node.value, ast.Set)
                       for target in node.targets if isinstance(target, ast.Name)}
        self.assertIn("rootTransition", closed_sets["required"])
        self.assertIn("rootTransitionDigest", closed_sets["plan_fields"])
        self.assertEqual(len(calls(validator, "verify_primary_root_transition")), 1)
        self.assertEqual(len(calls(validator, "derive_authorization_sources")), 1)
        derive = function(planner, "derive")
        self.assertEqual(len(calls(derive, "derive_primary_root_transition")), 1)
        self.assertEqual(len(calls(derive, "validate_measured_plan_payload")), 1)
        snapshot = [call for call in calls(validator, "framed_digest")
                    if call.args and isinstance(call.args[0], ast.Constant)
                    and call.args[0].value == "serverware.policyAuthoritySnapshot/v3"]
        self.assertEqual(len(snapshot), 1)
        self.assertEqual(len(snapshot[0].args), 10)  # domain plus nine frames
        self.assertIn("rootTransitionDigest", ast.unparse(snapshot[0].args[-1]))
        _, executor = source_module("serverware/authority_store/executor_v9.py")
        compute = function(executor, "compute_authority_v9_snapshot_digest")
        self.assertIn("root_transition_digest", [argument.arg for argument in compute.args.kwonlyargs])
        frames = calls(compute, "_digest")
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].args[0].value, "serverware.policyAuthoritySnapshot/v3")
        self.assertEqual(len(frames[0].args), 10)
        self.assertIn("root_transition_digest", ast.unparse(frames[0].args[-1]))
        persistence = function(executor, "complete_authority_planner_transaction")
        validation = calls(persistence, "validate_primary_root_transition")
        writer = calls(persistence, "_require_planner_writer")
        self.assertEqual(len(validation), 1)
        self.assertEqual(len(writer), 1)
        self.assertLess(validation[0].lineno, writer[0].lineno)
        self.assertEqual(len(calls(persistence, "primary_root_transition_digest")), 1)
        # Actual SQL execution of this narrow exception is covered separately
        # by the real-engine component, not by this source assertion.
        database_path = ROOT / "serverware/db.py"
        self.assertLess(database_path.stat().st_size, 16 * 1024 * 1024)
        database = database_path.read_text(encoding="utf-8")
        begin = database.index("                serverware_policy_authority_domain_digest(")
        end = database.index("$serverware_digest$", database.index("AS $serverware_digest$", begin) + 4)
        digest_body = database[begin:end]
        self.assertIn("'serverware.policyAuthoritySnapshot/v3'", digest_body)
        self.assertIn("pg_catalog.cardinality(digest_frames) <> 9", digest_body)
        self.assertIn("NOT BETWEEN 1 AND 8 END", digest_body)


if __name__ == "__main__":
    unittest.main()
