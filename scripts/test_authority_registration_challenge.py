#!/usr/bin/env python3
"""Pure registration dispatch/planner joins; no live principal, SQL or admission.

The challenge-reader controls use scripted synthetic SQL responses, not a SQL
engine. Membership proofs are independently built and genuinely verified; this
does not prove predicate completeness, legacy retention parity or live admission.
"""
import ast
import copy
from datetime import datetime, timedelta
import inspect
import os
from pathlib import Path
import sys
import textwrap
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
with patch.dict(os.environ, {"SERVERWARE_PROCESS_MODE": "serverware-control-plane"}):
    from serverware import authority_service as service
from test_authority_radix_mutation import IndependentTree


OPERATION = "webauthn.challenge.create"
NOW = 1_900_000_000_123_456_789
IDENTITY = uuid.UUID("01234567-89ab-4def-8123-456789abcdef")


def fixture():
    return dict(schema="serverware.policyAuthorityControlledWriterInput/v1",
        handler="create_webauthn_challenge",
        operationManifestDigest=service.authority_contract.OPERATION_MANIFEST_DIGEST,
        arguments=dict(challenge="A" * 43, challenge_type="registration", user_id="synthetic-operator",
            payload=dict(type="registration", user_id="synthetic-operator", label="synthetic-key",
                nonce="B" * 43, authorization=dict(mode="development-bootstrap",
                    payload_digest="sha256:" + "1" * 64, existing_credential_count=0)),
            approval_request_id=None, scope_key="sha256:" + "2" * 64, ttl_seconds=300))


def prepare(value):
    with patch.object(service.time, "time_ns", return_value=NOW), \
            patch.object(service.uuid, "uuid4", return_value=IDENTITY):
        return service.AuthorityProcess._prepare_registration_challenge_writer(None, value)


class SyntheticChallengeCursor:
    """A closed recording cursor: only the declared synthetic read script exists."""

    def __init__(self, steps):
        self.steps = list(steps)
        self.pending = None
        self.statements = []

    def execute(self, statement, parameters=()):
        if self.pending is not None or not self.steps:
            raise AssertionError("unexpected synthetic SQL execution")
        prefix, expected_parameters, rows = self.steps.pop(0)
        if not statement.startswith(prefix) or parameters != expected_parameters:
            raise AssertionError("synthetic SQL predicate or parameters changed")
        if statement.count("serverware_metadata.") != int(bool(parameters)):
            raise AssertionError("synthetic SQL relation closure changed")
        if parameters and "serverware_metadata.webauthn_challenges" not in statement:
            raise AssertionError("synthetic SQL read an undeclared relation")
        self.statements.append(statement)
        self.pending = copy.deepcopy(rows)
        return self

    def fetchall(self):
        if self.pending is None:
            raise AssertionError("synthetic SQL result already consumed")
        rows, self.pending = self.pending, None
        return rows

    def fetchone(self):
        rows = self.fetchall()
        if len(rows) > 1:
            raise AssertionError("synthetic SQL expected one row")
        return rows[0] if rows else None


class ChallengeReaderProjectionControls(unittest.TestCase):
    def component(self, operation):
        planner = service.authority_planner
        arguments = prepare(fixture())["arguments"]
        now = datetime.fromisoformat(arguments["created_at"])
        row = {name: arguments[name] for name in (
            "challenge", "challenge_type", "user_id", "scope_key",
            "approval_request_id", "expires_at", "created_at")}
        row.update(id=arguments["challenge_id"], used_at=None,
            payload_json=planner.canonical_bytes(arguments["payload"]).decode("ascii"))
        steps = [("SELECT pg_catalog.clock_timestamp() AS database_now", (),
            [{"database_now": now}])]
        select = ("SELECT pg_catalog.to_jsonb(target) AS row_value "
            "FROM serverware_metadata.webauthn_challenges AS target WHERE ")
        if operation == OPERATION:
            rows = []
            steps.extend([
                ("SELECT COUNT(*) AS row_count FROM (",
                    (planner.WEBAUTHN_CHALLENGE_PLANNING_SCAN_MAX + 1,), [{"row_count": 0}]),
                (select + "target.id = %s OR target.challenge = %s ORDER BY target.id LIMIT %s",
                    (row["id"], row["challenge"], 2), []),
                (select + "target.challenge_type = %s AND target.user_id = %s "
                    "AND target.scope_key = %s AND target.used_at IS NULL ORDER BY target.id LIMIT %s",
                    (row["challenge_type"], row["user_id"], row["scope_key"],
                        planner.WEBAUTHN_CHALLENGE_SELECTOR_OVERFLOW_LIMIT), []),
                ("WITH normalized AS (", (now, now,
                    now - timedelta(seconds=planner.WEBAUTHN_CHALLENGE_TERMINAL_RETENTION_SECONDS),
                    planner.WEBAUTHN_CHALLENGE_MAX_RETAINED - 1, row["user_id"],
                    now - timedelta(seconds=planner.WEBAUTHN_CHALLENGE_RATE_WINDOW_SECONDS),
                    now - timedelta(seconds=planner.WEBAUTHN_CHALLENGE_RATE_WINDOW_SECONDS), row["user_id"]),
                    [{name: 0 for name in ("user_recent", "global_recent", "global_live", "user_live", "retained")}]),
            ])
        else:
            rows = [row]
            if operation == "webauthn.challenge.claim":
                arguments = {name: row[name] for name in (
                    "challenge", "challenge_type", "user_id", "approval_request_id")}
                predicate, value = "target.challenge = %s", row["challenge"]
            else:
                arguments = {"challenge_id": row["id"]}
                predicate, value = "target.id = %s", row["id"]
            steps.append((select + predicate + " ORDER BY target.id LIMIT %s",
                (value, 2), [{"row_value": row}]))
        request = {"arguments": service._synthesize_business_arguments(operation, arguments)}
        manifest = tuple(entry for entry in planner.authority_primary_contract.source_query_manifest()
            if entry["operation"] == operation)
        program = planner.PLANNING_PROGRAMS[operation]
        cursor = SyntheticChallengeCursor(steps)
        trace = planner.PlannerTrace(operation=operation)
        selected, state = planner._read_planning_inputs(cursor, operation=operation,
            request=request, manifest=manifest, trace=trace, program=program)
        self.assertEqual(cursor.steps, [])
        self.assertIsNone(cursor.pending)
        contracts = planner.authority_primary_contract.primary_table_contracts(operation)
        trees = {contract.table: IndependentTree(rows if contract.table == "webauthn_challenges" else [],
            table=contract.table, columns=contract.key_columns) for contract in contracts}
        inputs = dict(operation=operation,
            business_before_roots=[trees[item.table].root.json_projection()
                for item in contracts if item.root_class == "business"],
            authorization_before_roots=[trees[item.table].root.json_projection()
                for item in contracts if item.root_class == "authorization"],
            selected_rows=selected, before_proofs=tuple(trees[item["table"]].proof(item) for item in selected))
        verified = planner.authority_root_transition.verify_primary_plan_inputs(**inputs)
        transition = program(operation=operation,
            handler=service.authority_contract.operation_spec(operation)["handler"],
            request=request, manifest=manifest, selected_rows=verified.selected_rows, state=state)
        self.assertEqual(len(transition.mutation_plan), 1)
        for mutation in transition.mutation_plan:
            trace.write(mutation["table"], mutation["key"])
        closed_trace = trace.close(selected_rows=verified.selected_rows, mutation_plan=transition.mutation_plan)
        self.assertEqual({entry["table"] for entry in closed_trace}, {"webauthn_challenges"})
        delta = planner.authority_root_transition.derive_primary_root_transition(
            **{**inputs, "selected_rows": verified.selected_rows, "before_proofs": verified.before_proofs},
            mutations=transition.mutation_plan)
        expected = IndependentTree([transition.mutation_plan[0]["row"]], table="webauthn_challenges",
            revision=trees["webauthn_challenges"].root.root_revision + 1)
        self.assertEqual(delta["businessAfterRoots"], [expected.root.json_projection()])
        request_digest = service._controlled_writer_request_digest(operation, arguments)
        projection_inputs = dict(operation=operation,
            operation_identifier=planner.operation_id(operation, request_digest), request_digest=request_digest,
            capability_id="sha256:" + "a" * 64, planner_transaction_id="sha256:" + "b" * 64,
            roots=tuple(inputs["authorization_before_roots"]), selected_rows=verified.selected_rows,
            approver_policy_digest=None, assertion_evidence_digest=None,
            verifier_identity={name: "sha256:" + "c" * 64 for name in (
                "sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")},
            created_at_epoch_ns=NOW, expires_at_epoch_ns=NOW + 1_000_000_000)
        # On the old source the reader returns only challenge rows, and this
        # actual call fails with "authorization query coverage is incomplete".
        projection = planner._authorization_projection(**projection_inputs)
        self.assertEqual(projection["authorizationReads"], [])
        self.assertEqual(projection["sourceRows"], [])
        self.assertEqual({item["table"] for item in selected}, {"webauthn_challenges"})
        return inputs, projection_inputs

    def test_actual_challenge_reader_proof_and_projection_join(self):
        for operation in (OPERATION, "webauthn.challenge.claim", "webauthn.challenge.consume"):
            with self.subTest(operation=operation):
                self.component(operation)

    def test_create_membership_and_projection_guards_still_refuse_unrelated_inputs(self):
        planner = service.authority_planner
        inputs, projection_inputs = self.component(OPERATION)
        changed = copy.deepcopy(inputs)
        changed["selected_rows"][0]["key"]["id"] = "different-synthetic-challenge"
        with self.assertRaises(planner.authority_root_transition.PrimaryRadixMutationError):
            planner.authority_root_transition.verify_primary_plan_inputs(**changed)
        unrelated = IndependentTree([], table="webauthn_credentials").root.json_projection()
        with self.assertRaisesRegex(planner.AuthorityPlannerError, "root inventory differs"):
            planner._authorization_projection(**{**projection_inputs, "roots": (unrelated,)})


class RegistrationChallengeControls(unittest.TestCase):
    def test_seven_application_fields_join_actual_eleven_field_planner(self):
        original = fixture()
        snapshot = copy.deepcopy(original)
        prepared = prepare(original)
        self.assertEqual(original, snapshot)
        self.assertEqual(len(original["arguments"]), 7)
        self.assertEqual(len(prepared["arguments"]), 10)
        for name, value in original["arguments"].items():
            self.assertEqual(prepared["arguments"][name], value)
        self.assertEqual(prepared["arguments"]["challenge_id"], str(IDENTITY))
        created = datetime.fromisoformat(prepared["arguments"]["created_at"])
        expires = datetime.fromisoformat(prepared["arguments"]["expires_at"])
        self.assertEqual(created.microsecond, 123000)
        self.assertEqual((expires - created).total_seconds(), 300)
        arguments = service._synthesize_business_arguments(OPERATION, prepared["arguments"])
        self.assertEqual(len(arguments), 11)
        planner = service.authority_planner
        selected = planner._selected_business_row(table="webauthn_challenges",
            key={"id": str(IDENTITY)}, row=None)
        transition = planner.WebAuthnChallengePlanningProgram(OPERATION, original["handler"])._create(
            arguments=arguments, selected_rows=(selected,),
            state=planner.PlanningState(database_now=created, webauthn_admission={"replacementCount": 0}))
        self.assertEqual(transition.result["payload"], original["arguments"]["payload"])
        self.assertEqual(transition.result["challenge"], original["arguments"]["challenge"])
        self.assertEqual(transition.result["id"], str(IDENTITY))

    def test_source_owned_fields_and_business_intent_cannot_be_overridden(self):
        for name in ("challenge_id", "created_at", "expires_at", "businessIntent"):
            value = fixture()
            value["arguments"][name] = "caller-value"
            with self.subTest(name=name), self.assertRaises(service.AuthorityServiceError):
                prepare(value)

    def test_wrong_branch_envelope_and_payload_refused(self):
        for target, name, other in (("outer", "schema", "other"), ("outer", "handler", "other"),
                ("outer", "operationManifestDigest", "sha256:" + "3" * 64),
                ("arguments", "challenge_type", "policy_authority"),
                ("arguments", "approval_request_id", "other"),
                ("payload", "type", "authentication"), ("payload", "user_id", "another-operator"),
                ("payload", "extra", True)):
            value = fixture()
            row = value if target == "outer" else value["arguments"]
            if target == "payload": row = row["payload"]
            row[name] = other
            with self.subTest(target=target, name=name), self.assertRaises(service.AuthorityServiceError):
                prepare(value)

    def test_original_ttl_bound_is_exact_and_not_renewed(self):
        for ttl in (30, 300):
            value = fixture(); value["arguments"]["ttl_seconds"] = ttl
            arguments = prepare(value)["arguments"]
            self.assertEqual((datetime.fromisoformat(arguments["expires_at"])
                - datetime.fromisoformat(arguments["created_at"])).total_seconds(), ttl)
        for ttl in (29, 301, True, 30.0, "30"):
            value = fixture(); value["arguments"]["ttl_seconds"] = ttl
            with self.subTest(ttl=ttl), self.assertRaises(service.AuthorityServiceError): prepare(value)

    def test_runtime_create_has_only_two_source_prepared_branches(self):
        tree = ast.parse(textwrap.dedent(inspect.getsource(service.AuthorityProcess._handle_runtime)))
        body = tree.body[0].body
        selected = next(node for node in body if isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name)
            and node.test.left.id == "operation" and isinstance(node.test.comparators[0], ast.Constant)
            and node.test.comparators[0].value == OPERATION)
        self.assertEqual(len(selected.body), 1)
        branch = selected.body[0]
        self.assertIsInstance(branch, ast.If)
        self.assertEqual(branch.body[0].value.func.attr, "_prepare_webauthn_challenge_writer")
        self.assertEqual(branch.orelse[0].value.func.attr, "_prepare_registration_challenge_writer")
        execution = next(node for node in body if isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == "_execute_v9_operation")
        self.assertLess(selected.lineno, execution.lineno)


if __name__ == "__main__": unittest.main()
