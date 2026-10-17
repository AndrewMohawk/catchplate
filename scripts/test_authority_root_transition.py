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
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_contract
from catchplate import authority_audit_capacity as capacity
from catchplate import authority_primary_contract as primary
from catchplate import authority_radix_mutation as radix_mutation
from catchplate import authority_root_transition as transition
from catchplate import authority_transition_core as core
from catchplate import authority_transition_policy as policy
from catchplate.authority_radix_mutation import PrimaryRadixMutationError
from test_authority_radix_mutation import IndependentTree, change, refresh_proof_digest
from test_authority_radix_proof import sql_json, wire_digest, wire_json
import test_authority_global_audit_capacity as capacity_fixture


COUNTER = "webauthn.counter.cas"
REGISTRATION = "webauthn.registration.create"


def fixture(operation: str = COUNTER) -> tuple[dict, dict[str, IndependentTree]]:
    """Use the actual source closure, with no inferred/caller-supplied keys."""
    rows = {
        "webauthn_credentials": [{"id": "credential-a", "sign_count": 1, "label": "hardware"}],
        "webauthn_challenges": [{"id": "challenge-a", "used_at": None}],
    }
    if operation == REGISTRATION:
        # This real source operation also requires a proven capacity counter;
        # the fixture remains a component transition, not credential issuance.
        rows[capacity_fixture.TABLE] = [capacity_fixture.counter_row()]
    trees = {
        contract.table: IndependentTree(rows.get(contract.table, []), table=contract.table,
                                        columns=contract.key_columns)
        for contract in primary.primary_table_contracts(operation)
    }
    target = "webauthn_credentials"
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
    after = {**target_row["row"], "sign_count": 2}
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


def input_fixture(operation=COUNTER, rows_by_table=None, selected_keys=None):
    """Real source table closure and independent hashes; no caller key policy."""
    rows_by_table = {} if rows_by_table is None else rows_by_table
    contracts = primary.primary_table_contracts(operation)
    trees = {contract.table: IndependentTree(rows_by_table.get(contract.table, []),
             table=contract.table, columns=contract.key_columns) for contract in contracts}
    selected = []
    proofs = []
    for contract in contracts:
        tree = trees[contract.table]
        keys = ([tree.key(row) for row in rows_by_table.get(contract.table, [])]
                if selected_keys is None else selected_keys.get(contract.table, []))
        for key in keys:
            value = tree.selected(key)
            selected.append(value)
            proofs.append(tree.proof(value))
    return {
        "operation": operation,
        "business_before_roots": [trees[contract.table].root.json_projection()
                                  for contract in contracts if contract.root_class == "business"],
        "authorization_before_roots": [trees[contract.table].root.json_projection()
                                       for contract in contracts if contract.root_class == "authorization"],
        "selected_rows": selected, "before_proofs": proofs,
    }, trees


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
        arguments, trees = fixture(REGISTRATION)
        result = transition.derive_primary_root_transition(**arguments)
        spec = authority_contract.operation_spec(REGISTRATION)
        self.assertEqual(tuple(spec["authorizationReads"]),
                         ("webauthn_challenges", "webauthn_trust_publications"))
        self.assertEqual([root["table"] for root in result["authorizationBeforeRoots"]],
                         list(spec["authorizationReads"]))
        self.assertEqual(result["authorizationBeforeRoots"], result["authorizationAfterRoots"])
        expected = IndependentTree([arguments["mutations"][0]["row"]],
                                   table="webauthn_credentials", revision=2)
        self.assertEqual(result["businessAfterRoots"], [
            expected.root.json_projection() if root["table"] == expected.table else root
            for root in arguments["business_before_roots"]
        ])
        auth_row = next(row for row in arguments["selected_rows"] if row["table"] == "webauthn_challenges")
        self.assertEqual(trees["webauthn_challenges"].root.json_projection(),
                         next(root for root in result["authorizationAfterRoots"] if root["table"] == auth_row["table"]))
        with self.assertRaisesRegex(PrimaryRadixMutationError, "not writable business state"):
            transition.derive_primary_root_transition(**{
                **arguments, "mutations": [change(auth_row, "UPDATE", {
                    **auth_row["row"], "used_at": "2026-01-01T00:00:00Z"})],
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
        self.assertEqual(transition.metric_bounds()["hashWork"], 35018)

    def test_actual_authorization_sources_bind_present_and_absent_primary_rows(self) -> None:
        arguments, _ = fixture(REGISTRATION)
        # Authenticate all selected rows first; the projection is not itself a
        # membership verifier or a substitute for this complete delta check.
        result = transition.derive_primary_root_transition(**arguments)
        self.assertEqual(verify(result, arguments), result)
        sources = transition.derive_authorization_sources(operation=REGISTRATION,
                                                         selected_rows=arguments["selected_rows"])
        self.assertEqual([entry["table"] for entry in sources],
                         list(authority_contract.operation_spec(REGISTRATION)["authorizationReads"]))
        self.assertEqual({entry["present"] for entry in sources}, {True, False})
        for source in sources:
            self.assertEqual(set(source), {"table", "selector", "present", "row", "rowDigest"})
            self.assertEqual(set(source["selector"]), set(primary.PRIMARY_KEY_COLUMNS[source["table"]]))
            expected = wire_digest("catchplate.policyAuthorityAuthorizationRow/v1", source["table"].encode("ascii"),
                                   wire_json(source["selector"]), b"present" if source["present"] else b"absent",
                                   wire_json(source["row"]))
            self.assertEqual(source["rowDigest"], expected)
            self.assertNotIn("authenticatedRelation", source["selector"])
        self.assertEqual(transition.derive_authorization_sources(operation=COUNTER,
                                                               selected_rows=self.arguments["selected_rows"]), [])

    def test_framework_allowance_requires_new_profile_without_changing_business_caps(self) -> None:
        self.assertEqual(transition.TRANSITION_PROFILE,
                         "catchplate.policyAuthorityPrimaryRootTransitionProfile/v2")
        bounds = transition.metric_bounds()
        self.assertEqual((bounds["selectedRows"], bounds["mutations"], bounds["proofVectors"],
                          bounds["proofChildSlots"], bounds["hashWork"]), (257, 513, 16448, 263168, 35018))
        self.assertEqual((authority_contract.MAX_QUERY_PROOFS, authority_contract.MAX_MUTATIONS), (256, 512))
        result = transition.derive_primary_root_transition(**self.arguments)
        result["profile"] = "catchplate.policyAuthorityPrimaryRootTransitionProfile/v1"
        with self.assertRaisesRegex(PrimaryRadixMutationError, "profile is not closed"):
            transition.validate_primary_root_transition(result)

    def test_authorization_query_coverage_is_separate_and_fail_closed(self) -> None:
        arguments, _ = fixture(REGISTRATION)
        business_tables = {entry["table"] for entry in arguments["business_before_roots"]}
        business_only = [entry for entry in arguments["selected_rows"] if entry["table"] in business_tables]
        # An unchanged supplied auth root is valid delta input, but never means
        # an authorization query actually selected its required source row.
        delta_only = {**arguments, "selected_rows": business_only,
                      "before_proofs": [proof for proof in arguments["before_proofs"]
                                        if proof["table"] in business_tables]}
        transition.derive_primary_root_transition(**delta_only)
        with self.assertRaisesRegex(PrimaryRadixMutationError, "do not cover declared relations"):
            transition.derive_authorization_sources(operation=REGISTRATION, selected_rows=business_only)
        auth = next(row for row in arguments["selected_rows"] if row["table"] == "webauthn_challenges")
        with self.assertRaisesRegex(PrimaryRadixMutationError, "identity is duplicated"):
            transition.derive_authorization_sources(operation=REGISTRATION,
                                                   selected_rows=arguments["selected_rows"] + [auth])
        malformed = copy.deepcopy(arguments["selected_rows"])
        next(row for row in malformed if row["table"] == auth["table"])["present"] = 1
        with self.assertRaisesRegex(PrimaryRadixMutationError, "key or presence is not exact"):
            transition.derive_authorization_sources(operation=REGISTRATION, selected_rows=malformed)

    def test_unicode_authorization_wire_remains_distinct_from_persisted_tree_json(self) -> None:
        arguments, _ = fixture(REGISTRATION)
        row = next(entry for entry in arguments["selected_rows"] if entry["table"] == "webauthn_challenges")
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
            operation=REGISTRATION, selected_rows=arguments["selected_rows"]) if entry["table"] == tree.table)
        domain = "catchplate.policyAuthorityAuthorizationRow/v1"
        self.assertEqual(source["rowDigest"], wire_digest(domain, tree.table.encode(), wire_json(source["selector"]),
                                                        b"present", wire_json(source["row"])))
        # The live SQL wire helper has a separate real-engine component oracle.
        # This pure INEQUALITY proves why the unchanged UTF-8 tree serializer
        # must not be substituted into the ASCII authorization wire domain.
        self.assertNotEqual(source["rowDigest"], wire_digest(domain, tree.table.encode(), sql_json(source["selector"]),
                                                           b"present", sql_json(source["row"])))

    def test_source_wiring_recomputes_before_persistence_and_binds_snapshot_nine(self) -> None:
        _, planner = source_module("catchplate/authority_planner.py")
        constants = {target.id: node.value.value for node in planner.body if isinstance(node, ast.Assign)
                     and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
                     for target in node.targets if isinstance(target, ast.Name)}
        self.assertEqual(constants["PLANNER_RESPONSE_SCHEMA"], "catchplate.policyAuthorityPlannerResponse/v3")
        self.assertEqual(constants["MEASURED_PLAN_SCHEMA"], "catchplate.policyAuthorityMeasuredPlan/v3")
        self.assertEqual(constants["SIGNED_MEASURED_PLAN_SCHEMA"], "catchplate.signedPolicyAuthorityMeasuredPlan/v3")
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
                    and call.args[0].value == "catchplate.policyAuthoritySnapshot/v3"]
        self.assertEqual(len(snapshot), 1)
        self.assertEqual(len(snapshot[0].args), 10)  # domain plus nine frames
        self.assertIn("rootTransitionDigest", ast.unparse(snapshot[0].args[-1]))
        _, executor = source_module("catchplate/authority_store/executor_v9.py")
        compute = function(executor, "compute_authority_v9_snapshot_digest")
        self.assertIn("root_transition_digest", [argument.arg for argument in compute.args.kwonlyargs])
        frames = calls(compute, "_digest")
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].args[0].value, "catchplate.policyAuthoritySnapshot/v3")
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
        database_path = ROOT / "catchplate/db.py"
        self.assertLess(database_path.stat().st_size, 16 * 1024 * 1024)
        database = database_path.read_text(encoding="utf-8")
        begin = database.index("                catchplate_policy_authority_domain_digest(")
        end = database.index("$catchplate_digest$", database.index("AS $catchplate_digest$", begin) + 4)
        digest_body = database[begin:end]
        self.assertIn("'catchplate.policyAuthoritySnapshot/v3'", digest_body)
        self.assertIn("pg_catalog.cardinality(digest_frames) <> 9", digest_body)
        self.assertIn("NOT BETWEEN 1 AND 8 END", digest_body)


class PrimaryPlanInputTests(unittest.TestCase):
    """Pre-kernel component composition; not imported planner/startup proof."""

    def setUp(self):
        self.row = {"id": "credential-雪", "credential_id": "public-雪", "sign_count": 1,
                    "revoked_at": None, "last_used_at": None, "updated_at": "old",
                    "metadata": {"flags": [True, None], "note": "☃"}}
        self.inputs, self.trees = input_fixture(COUNTER, {"webauthn_credentials": [self.row]})
        self.now = datetime(2031, 2, 3, 4, 5, 6, tzinfo=timezone.utc)
        self.request_digest = wire_digest("component-pre-kernel-request", b"counter-cas")
        values = {"recordId": self.row["id"], "credentialId": self.row["credential_id"],
                  "expectedSignCount": 1, "newSignCount": 2}
        self.arguments = {**values, "businessIntent": authority_contract.synthesize_business_intent(COUNTER, values)}

    def test_actual_membership_inputs_feed_real_counter_kernel_and_final_delta(self):
        pristine = copy.deepcopy(self.inputs)
        verified = transition.verify_primary_plan_inputs(**self.inputs)
        self.assertIs(type(verified), radix_mutation.PrimaryRadixMembershipResult)
        self.assertEqual(verified.selected_rows, tuple(self.inputs["selected_rows"]))
        self.assertEqual(verified.before_proofs, tuple(self.inputs["before_proofs"]))
        self.assertEqual(verified.result.metrics.hash_work, 136)
        self.assertEqual(verified.result.metrics.mutations, 0)
        self.assertEqual(verified.result.metrics.recomputed_ancestors, 0)
        kernel = policy.KERNELS[COUNTER]
        queries = kernel.queries(arguments=self.arguments, database_now=self.now, request_digest=self.request_digest)
        self.assertEqual(len(queries), 1)
        self.assertEqual(queries[0].table, "webauthn_credentials")
        self.assertEqual(queries[0].absent_key, {"id": self.row["id"]})
        context = core.KernelContext(operation=COUNTER, arguments=self.arguments,
            selected_rows=verified.selected_rows, database_now=self.now, request_digest=self.request_digest)
        actual = kernel.transition(context)
        self.assertIs(actual.result, True)
        self.assertEqual(actual.work_units, 8)
        self.assertEqual(len(actual.mutations), 1)
        expected_row = {**self.row, "sign_count": 2, "last_used_at": self.now.isoformat(),
                        "updated_at": self.now.isoformat()}
        mutation = actual.mutations[0]
        self.assertEqual(mutation["row"], expected_row)
        self.assertEqual(mutation["expectedRow"], self.row)
        templates = authority_contract.operation_spec(COUNTER)["mutationTemplates"]
        self.assertEqual(mutation["templateId"], next(item["templateId"] for item in templates
                         if item["table"] == "webauthn_credentials" and item["mutation"] == "UPDATE"))
        result = transition.derive_primary_root_transition(**{
            **self.inputs, "selected_rows": verified.selected_rows, "before_proofs": verified.before_proofs,
        }, mutations=actual.mutations)
        expected_tree = IndependentTree([expected_row], table="webauthn_credentials", revision=2)
        self.assertEqual(result["businessAfterRoots"], [expected_tree.root.json_projection()])
        self.assertEqual(result["metrics"]["hashWork"], 202)
        self.assertEqual(self.inputs, pristine)

    def test_changed_row_key_proof_and_root_context_reject_before_inputs_are_returned(self):
        cases = []
        for field, value in (("rootRevision", 2), ("rootRevision", True), ("leafCount", True),
                             ("leafCount", 0), ("rootDigest", "sha256:" + "a" * 64)):
            changed = copy.deepcopy(self.inputs)
            changed["business_before_roots"][0][field] = value
            cases.append(changed)
        for field, value in (("rowDigest", "sha256:" + "b" * 64), ("rootRevision", 2)):
            changed = copy.deepcopy(self.inputs)
            changed["before_proofs"][0][field] = value
            refresh_proof_digest(changed["before_proofs"][0])
            cases.append(changed)
        changed = copy.deepcopy(self.inputs)
        changed["before_proofs"][0]["siblings"][12]["childDigests"][4] = "sha256:" + "c" * 64
        refresh_proof_digest(changed["before_proofs"][0])
        cases.append(changed)
        for field, value in (("row", {**self.row, "sign_count": 9}),
                             ("key", {"caller_key": self.row["id"]}),
                             ("keyDigest", "sha256:" + "d" * 64), ("present", 1)):
            changed = copy.deepcopy(self.inputs)
            changed["selected_rows"][0][field] = value
            cases.append(changed)
        understated, _ = input_fixture(COUNTER, {"webauthn_credentials": [self.row, {**self.row, "id": "second"}]})
        understated["business_before_roots"][0]["leafCount"] = 1
        cases.append(understated)
        for index, changed in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(PrimaryRadixMutationError):
                transition.verify_primary_plan_inputs(**changed)

    def test_source_root_classes_and_primary_inventories_are_closed(self):
        for updates in (
            {"business_before_roots": []},
            {"business_before_roots": [], "authorization_before_roots": self.inputs["business_before_roots"]},
            {"business_before_roots": [{**self.inputs["business_before_roots"][0], "table": "unknown"}]},
            {"business_before_roots": self.inputs["business_before_roots"] * 2},
            {"before_proofs": []}, {"before_proofs": self.inputs["before_proofs"] * 2},
            {"selected_rows": self.inputs["selected_rows"] * 2, "before_proofs": self.inputs["before_proofs"] * 2},
            {"selected_rows": iter(())},
        ):
            with self.subTest(fields=tuple(updates)), self.assertRaises(PrimaryRadixMutationError):
                transition.verify_primary_plan_inputs(**{**self.inputs, **updates})
        with self.assertRaises(ValueError):
            transition.verify_primary_plan_inputs(**{**self.inputs, "operation": "unknown.operation"})
        # Exact absence remains genuine evidence, not a missing proof. The real
        # CAS kernel can decide its source-declared no-op from that owned row.
        absent, _ = input_fixture(COUNTER, selected_keys={"webauthn_credentials": [{"id": self.row["id"]}]})
        verified = transition.verify_primary_plan_inputs(**absent)
        self.assertIs(verified.selected_rows[0]["present"], False)
        self.assertEqual(verified.result.metrics.hash_work, 134)
        actual = policy.KERNELS[COUNTER].transition(core.KernelContext(
            operation=COUNTER, arguments=self.arguments, selected_rows=verified.selected_rows,
            database_now=self.now, request_digest=self.request_digest))
        self.assertEqual((actual.mutations, actual.result), ((), False))

    def test_owned_inputs_are_detached_and_reverification_never_accepts_an_observation(self):
        pristine = copy.deepcopy(self.inputs)
        verified = transition.verify_primary_plan_inputs(**self.inputs)
        self.assertIsNot(verified.selected_rows[0], self.inputs["selected_rows"][0])
        self.assertIsNot(verified.selected_rows[0]["row"]["metadata"]["flags"],
                         self.inputs["selected_rows"][0]["row"]["metadata"]["flags"])
        self.inputs["selected_rows"][0]["row"]["metadata"]["flags"].append("caller")
        self.inputs["before_proofs"][0]["siblings"][0]["childDigests"].clear()
        self.inputs["business_before_roots"][0]["rootRevision"] = 999
        self.assertEqual(verified.selected_rows, tuple(pristine["selected_rows"]))
        self.assertEqual(verified.before_proofs, tuple(pristine["before_proofs"]))
        self.assertEqual(verified.result.business_after_roots[0].root_revision, 1)
        with self.assertRaises(FrozenInstanceError):
            verified.selected_rows = ()
        # Nested dictionaries are detached data, not immutable authority tokens.
        verified.selected_rows[0]["row"]["metadata"]["flags"].append("owned")
        again = transition.verify_primary_plan_inputs(**pristine)
        self.assertEqual(again.selected_rows, tuple(pristine["selected_rows"]))
        for value in (verified, radix_mutation.PrimaryRadixMembershipResult(
                verified.result, verified.selected_rows, verified.before_proofs)):
            with self.assertRaises(PrimaryRadixMutationError):
                transition.verify_primary_plan_inputs(**{**pristine, "selected_rows": value})
        with self.assertRaises(TypeError):
            transition.verify_primary_plan_inputs(**pristine, mutations=())

    def test_authorization_rows_share_genuine_before_root_context_without_changing_heads(self):
        arguments, _ = fixture(REGISTRATION)
        inputs = {name: value for name, value in arguments.items() if name != "mutations"}
        verified = transition.verify_primary_plan_inputs(**inputs)
        self.assertEqual([root.json_projection() for root in verified.result.business_after_roots],
                         inputs["business_before_roots"])
        self.assertEqual([root.json_projection() for root in verified.result.authorization_after_roots],
                         inputs["authorization_before_roots"])
        sources = transition.derive_authorization_sources(operation=REGISTRATION,
                                                          selected_rows=verified.selected_rows)
        self.assertEqual({source["present"] for source in sources}, {True, False})
        changed = copy.deepcopy(inputs)
        proof = next(item for item in changed["before_proofs"] if item["table"] == "webauthn_challenges")
        proof["rootRevision"] += 1
        refresh_proof_digest(proof)
        with self.assertRaises(PrimaryRadixMutationError):
            transition.verify_primary_plan_inputs(**changed)

    def test_consistently_rebound_descriptor_still_does_not_prove_currentness(self):
        changed = copy.deepcopy(self.inputs)
        changed["business_before_roots"][0].update(rootRevision=999, leafCount=17)
        changed["before_proofs"][0]["rootRevision"] = 999
        refresh_proof_digest(changed["before_proofs"][0])
        verified = transition.verify_primary_plan_inputs(**changed)
        self.assertEqual(verified.result.business_after_roots[0].root_revision, 999)
        self.assertEqual(verified.result.business_after_roots[0].leaf_count, 17)
        self.assertEqual(verified.selected_rows, tuple(self.inputs["selected_rows"]))
        # The operation-bound wrapper verifies membership, not descriptor
        # provenance, predicate completeness or fresh signed checkpoint authority.

    def test_source_phase_limits_are_exact_and_oversized_inventory_denies_before_engine(self):
        for operation in (COUNTER, "rbac.binding.mutate", "webauthn.registration.create"):
            spec = authority_contract.operation_spec(operation)
            count = spec["maximumQueryRows"]
            expected = {"selectedRows": count, "proofVectors": 257 * 64,
                        "proofChildSlots": 257 * 64 * 16, "rootDescriptorHashAllowance": 66,
                        "membershipHashWork": 66 + 70 * count,
                        "auditCapacityHashAllowance": count + int(spec["globalAuditCapacity"]),
                        "totalHashWork": 132 + 71 * count + int(spec["globalAuditCapacity"]),
                        "inputBytes": 64 * 1024 * 1024, "jsonNodes": 1_000_000}
            with self.subTest(operation=operation):
                self.assertEqual(transition.primary_plan_input_metric_bounds(operation), expected)
                changed = transition.primary_plan_input_metric_bounds(operation)
                changed["membershipHashWork"] = 0
                self.assertEqual(transition.primary_plan_input_metric_bounds(operation), expected)
        actual_engine = transition.evaluate_primary_radix_memberships
        actual_capacity = capacity.validate_capacity_transition
        with mock.patch.object(transition, "evaluate_primary_radix_memberships", wraps=actual_engine) as engine, \
                mock.patch.object(capacity, "validate_capacity_transition", wraps=actual_capacity) as final:
            observed = transition.verify_primary_plan_inputs(**self.inputs)
        self.assertEqual((engine.call_count, final.call_count), (1, 1))
        arguments = engine.call_args.kwargs
        self.assertEqual(arguments["table_contracts"], primary.primary_table_contracts(COUNTER))
        limits = arguments["limits"]
        self.assertEqual((limits.max_selected_rows, limits.max_mutations, limits.max_proof_vectors,
                          limits.max_proof_child_slots, limits.max_hashes, limits.max_input_bytes,
                          limits.max_json_depth, limits.max_json_nodes),
                         (256, 512, 16448, 263168, 17986, 64 * 1024 * 1024, 128, 1_000_000))
        self.assertEqual(set(arguments), {"table_contracts", "business_before_roots", "authorization_before_roots",
                                          "selected_rows", "before_proofs", "limits"})
        self.assertIs(final.call_args.kwargs["selected_rows"], observed.selected_rows)
        self.assertEqual(final.call_args.kwargs["mutations"], ())
        maximum = authority_contract.operation_spec(COUNTER)["maximumQueryRows"]
        with mock.patch.object(transition, "evaluate_primary_radix_memberships", wraps=actual_engine) as engine:
            with self.assertRaisesRegex(PrimaryRadixMutationError, "inventory exceeds operation bounds"):
                transition.verify_primary_plan_inputs(**{
                    **self.inputs, "selected_rows": self.inputs["selected_rows"] * (maximum + 1),
                    "before_proofs": self.inputs["before_proofs"] * (maximum + 1)})
            self.assertEqual(engine.call_count, 0)
        with self.assertRaises(TypeError):
            transition.verify_primary_plan_inputs(**self.inputs, limits=limits)

    def test_authenticated_counter_profile_is_required_without_bootstrap_or_mutation(self):
        operation = "rbac.binding.mutate"
        counter_table, outbox = capacity_fixture.TABLE, capacity_fixture.OUTBOX
        compact = capacity_fixture.counter_row(live_count=100_000, active_count=100_000)
        spec = authority_contract.operation_spec(operation)
        self.assertEqual((spec["maximumBusinessQueryRows"], spec["maximumQueryRows"]), (5, 6))
        business = [capacity_fixture.outbox_row(f"component-{index}") for index in range(5)]
        inputs, _ = input_fixture(operation, {counter_table: [compact], outbox: business})
        observed = transition.verify_primary_plan_inputs(**inputs)
        self.assertEqual((len(observed.selected_rows), observed.result.metrics.hash_work), (6, 486))
        self.assertEqual(observed.result.metrics.mutations, 0)
        actual_counter = next(row["row"] for row in observed.selected_rows if row["table"] == counter_table)
        self.assertEqual(actual_counter, compact)
        self.assertEqual((actual_counter["live_count"], actual_counter["revision"]), (100_000, 7))
        counter_only, _ = input_fixture(operation, {counter_table: [compact]})
        self.assertEqual(len(transition.verify_primary_plan_inputs(**counter_only).selected_rows), 1)
        missing, _ = input_fixture(operation)
        absent, _ = input_fixture(operation, selected_keys={counter_table: [{"aggregate_id": capacity_fixture.IDENTITY}]})
        malformed = []
        for row in (capacity_fixture.counter_row(capacity_limit=99_999),
                    capacity_fixture.counter_row(live_count=100_001, active_count=100_001),
                    capacity_fixture.counter_row(revision=True),
                    capacity_fixture.counter_row(source_revision="not-the-source-revision")):
            invalid, _ = input_fixture(operation, {counter_table: [row]})
            malformed.append(invalid)
        for label, invalid in [("missing", missing), ("absent", absent),
                               *((f"compact-{index}", item) for index, item in enumerate(malformed))]:
            with self.subTest(case=label), self.assertRaisesRegex(
                    PrimaryRadixMutationError, "audit capacity inputs changed") as caught:
                transition.verify_primary_plan_inputs(**invalid)
            self.assertIsInstance(caught.exception.__cause__, capacity.AuditCapacityError)
        # Six business rows cannot spend the framework's sixth slot simply by
        # leaving the authenticated counter head present but unselected.
        excessive, _ = input_fixture(operation, {counter_table: [compact],
            outbox: [capacity_fixture.outbox_row(f"extra-{index}") for index in range(6)]},
            selected_keys={outbox: [{"id": f"extra-{index}"} for index in range(6)]})
        with self.assertRaisesRegex(PrimaryRadixMutationError, "audit capacity inputs changed") as caught:
            transition.verify_primary_plan_inputs(**excessive)
        self.assertIn("business bound", str(caught.exception.__cause__))

    def test_business_selected_byte_limit_is_checked_after_genuine_full_row_proofs(self):
        row = {**self.row, "padding": ""}
        initial, _ = input_fixture(COUNTER, {"webauthn_credentials": [row]})
        row["padding"] = "x" * (4 * 1024 * 1024 - len(wire_json(initial["selected_rows"])))
        inputs, _ = input_fixture(COUNTER, {"webauthn_credentials": [row]})
        self.assertEqual(len(wire_json(inputs["selected_rows"])), 4 * 1024 * 1024)
        accepted = transition.verify_primary_plan_inputs(**inputs)
        self.assertEqual(accepted.selected_rows[0]["row"], row)
        # Rebuild both row commitment and proof: this rejection is the real
        # selected-envelope cap, not a stale row hash or an artificial byte spy.
        excessive, _ = input_fixture(COUNTER, {"webauthn_credentials": [{**row, "padding": row["padding"] + "x"}]})
        self.assertEqual(len(wire_json(excessive["selected_rows"])), 4 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(PrimaryRadixMutationError, "audit capacity inputs changed") as caught:
            transition.verify_primary_plan_inputs(**excessive)
        self.assertIsInstance(caught.exception.__cause__, capacity.AuditCapacityError)
        self.assertIn("business bound", str(caught.exception.__cause__))


if __name__ == "__main__":
    unittest.main()
