#!/usr/bin/env python3
"""Pure registration dispatch/planner joins; no live principal, SQL or admission."""
import ast
import copy
from datetime import datetime
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
