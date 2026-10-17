"""Focused resource-profile controls, not native activation acceptance.

Shape checks never claim enrollment admission. The release enrollment control
uses genuine Ed25519 originals and source admission. Dynamic whole-policy and
old historical joins are source checked, not replaced by successful DTOs. No
database, listener, private descriptor, worker or new processing window is used.
"""
from __future__ import annotations

import ast
import base64
from dataclasses import fields
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from catchplate import control_plane_oidc_session_activation_consume_execution_bootstrap as consume
from catchplate import control_plane_oidc_session_activation_release_intent_bootstrap as intent
from catchplate import control_plane_oidc_session_activation_request_issuance_bootstrap as requested
from catchplate.authority_query_read_work import QueryReadValidationLimits, QueryReadWorkError, _ValidationWork

PIN = "sha256:" + "1" * 64
OTHER = "sha256:" + "2" * 64


def work(**limits):
    return _ValidationWork(QueryReadValidationLimits(**limits))


def wrapped(raw):
    return dict(base64Url=base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"), byteCount=len(raw))


def endpoint(path):
    return dict(socketPath=path, requestTimeoutSeconds=10, listenerUid=0, listenerGid=0)


def consume_shape(schema):
    # Deliberately not signed enrollments; this exercises only the closed wire
    # shape and never passes the values to an admission success fixture.
    value = dict(schema=schema, callerPrivateKeyFd=206, grantEnrollment=wrapped(b"{}"),
        authorizationEnrollment=wrapped(b"{}"), authorizerEndpoint=endpoint(consume.AUTHORIZER_SOCKET_PATH))
    if schema != consume.SCHEMA:
        value.update(reservationEndpoint=endpoint(consume.RESERVATION_SOCKET_PATH),
            sqlEndpoint=endpoint(consume.SQL_SOCKET_PATH))
        if schema != consume.V5_SCHEMA:
            value["reservationPredecessor"] = dict(sequence=0, headDigest=PIN, nextFence=1)
    if schema in (consume.V3_SCHEMA, consume.V4_SCHEMA, consume.V5_SCHEMA):
        value["completionEndpoint"] = endpoint(consume.COMPLETION_SOCKET_PATH)
    return value


def scope():
    return dict(configurationDigest=PIN, databaseId="fixture-database", generationDigest=PIN,
        runtimeClosureDigest=PIN, callerId="fixture-release-caller",
        receiverIdentity={name: PIN for name in intent.shape.IDENTITY_FIELDS})


def release_shape(schema=intent.V2_SCHEMA):
    return dict(schema=schema, callerPrivateKeyFd=207, intentEnrollment=wrapped(b"{}"), expectedScope=scope())


def cold_arguments():
    return dict(configuration_payload=None, configuration_digest=None, generation=None,
        runtime_role_identities=None, runtime_root_public_key=None, activation_execution=None,
        activation_planning=None, issuer_public_key=None, execution_caller_public_key=None,
        finalization_caller_public_key=None)


def body(module, function):
    raw = (ROOT / "catchplate" / (module + ".py")).read_text("utf-8")
    rows = [item for item in ast.parse(raw).body if isinstance(item, ast.FunctionDef) and item.name == function]
    if len(rows) != 1:
        raise AssertionError(function)
    return ast.get_source_segment(raw, rows[0])


class ResourceBootstrapControls(unittest.TestCase):
    def test_01_exact_old_profiles_and_new_predecessor_free_resource_shapes(self):
        for schema in (consume.SCHEMA, consume.V2_SCHEMA, consume.V3_SCHEMA, consume.V4_SCHEMA, consume.V5_SCHEMA):
            with self.subTest(schema=schema):
                self.assertIsNone(consume._shape(consume_shape(schema)))
        self.assertEqual(consume._V5_FIELDS, consume._V3_FIELDS - {"reservationPredecessor"})
        self.assertFalse(next(item for item in fields(consume._ConsumeExecutionMaterial)
            if item.name == "request_bound").default)
        for schema in (intent.SCHEMA, intent.V2_SCHEMA):
            self.assertIsNone(intent._shape(release_shape(schema)))
        for field, value in (("reservationPredecessor", dict(sequence=0, headDigest=PIN, nextFence=1)),
                ("request_bound", True), ("completeRootVector", {}), ("callerPrivateKeyFd", 205)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                consume._shape(dict(consume_shape(consume.V5_SCHEMA), **{field: value}))
        old = consume_shape(consume.V4_SCHEMA)
        del old["reservationPredecessor"]
        with self.assertRaises(ValueError):
            consume._shape(old)
        changed = consume_shape(consume.V5_SCHEMA)
        changed["reservationEndpoint"] = endpoint(consume.SQL_SOCKET_PATH)
        with self.assertRaises(ValueError):
            consume._shape(changed)
        with self.assertRaises(ValueError):
            intent._shape(dict(release_shape(), plannerBootstrap=wrapped(b"{}")))

    def test_02_resource_material_type_and_complete_original_bounds_refuse_before_verification(self):
        # Unverified dictionaries and missing originals are refusals, not
        # successful stand-ins for either genuine cold material class.
        with patch.object(requested.policy, "_verify_on_work", side_effect=AssertionError("unexpected policy call")) as verify:
            with self.assertRaises(consume.OidcSessionActivationConsumeExecutionBootstrapError):
                consume._request_policy_on_work(planned={"policy_bytes": b"{}"}, parent=None,
                    configured=None, launch=None, runtime=None, digest=PIN, root=None,
                    work=work(), live_window=None, transport_deadline_ns=None)
            for selected in (None, (1, 2, 2, 10, 10, 8, 0)):
                deadline = 9 if selected is None else None
                with self.subTest(window=selected), self.assertRaisesRegex(ValueError, "complete original processing pair"):
                    consume._admit_on_work(consume_execution=consume_shape(consume.V5_SCHEMA),
                        **cold_arguments(), work=work(), live_window=selected, transport_deadline_ns=deadline)
                with self.subTest(intent_window=selected), self.assertRaisesRegex(ValueError, "complete original processing pair"):
                    intent._admit_on_work(release_intent=release_shape(), consume_execution=None,
                        **cold_arguments(), work=work(), live_window=selected, transport_deadline_ns=deadline)
            verify.assert_not_called()

    def test_03_genuine_release_enrollment_signature_scope_key_and_budget_guards(self):
        enrolled = intent.enrollment
        root_private = Ed25519PrivateKey.from_private_bytes(b"\x31" * 32)
        caller_private = Ed25519PrivateKey.from_private_bytes(b"\x32" * 32)
        forbidden = Ed25519PrivateKey.from_private_bytes(b"\x33" * 32).public_key()
        root, public = root_private.public_key(), caller_private.public_key()
        expected = scope()
        payload = dict(expected, schema=enrolled.PAYLOAD_SCHEMA, sourceRevision=enrolled.authority.SOURCE_REVISION,
            purpose=enrolled.PURPOSE, callerKey={"publicKeyPem": public.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii"),
                "spkiDigest": enrolled.keys._spki_on_work(public, work()), "measurementDigest": OTHER},
            maximumAgeNs=1_000_000_000, maximumClockSkewNs=0)
        raw = enrolled._produce_on_work(payload=payload, root_private_key=root_private,
            root_public_key=root, forbidden_public_keys=(forbidden,), work=work())
        actual = enrolled._admit_on_work(enrollment_bytes=raw, root_public_key=root,
            expected_scope=expected, forbidden_public_keys=(forbidden,), work=work())
        self.assertEqual(actual.payload, payload)
        scope_raw = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("ascii")
        self.assertEqual(intent._scope_on_work(scope_raw, work()), expected)
        for changed_scope, changed_root, keys in ((dict(expected, generationDigest=OTHER), root, (forbidden,)),
                (expected, forbidden, (forbidden,)), (expected, root, (public,))):
            with self.subTest(scope=changed_scope["generationDigest"]), self.assertRaises(ValueError):
                enrolled._admit_on_work(enrollment_bytes=raw, root_public_key=changed_root,
                    expected_scope=changed_scope, forbidden_public_keys=keys, work=work())
        with self.assertRaises(QueryReadWorkError):
            enrolled._admit_on_work(enrollment_bytes=raw, root_public_key=root,
                expected_scope=expected, forbidden_public_keys=(forbidden,), work=work(max_input_bytes=32))

    def test_04_dynamic_policy_source_joins_are_real_and_have_no_future_predecessor(self):
        prefix = "control_plane_oidc_session_activation_consume_execution_bootstrap"
        helper = body(prefix, "_request_policy_on_work")
        self.assertIn("type(planned) is not requested._RequestPlanningMaterial", helper)
        self.assertIn("requested.policy._verify_on_work(policy_bytes=planned.policy_bytes", helper)
        self.assertIn("root_public_key=root, live_window=live_window", helper)
        self.assertIn("transport_deadline_ns=transport_deadline_ns, work=work", helper)
        for marker in ("admitted.resource_facts", "runtime_policy, runtime", "parent.current_root_enrollment_bytes",
                "parent.authorization_enrollment_bytes", "parent.grant_enrollment_bytes",
                "parent.planner_public_key", "parent.caller_public_key", "parent.operation_public_key"):
            self.assertIn(marker, helper)
        self.assertLess(helper.index("requested.policy._verify_on_work"), helper.index("planning._same_configuration"))
        self.assertLess(helper.index("admitted.live()"), helper.index("return admitted"))
        source = body(prefix, "_admit_on_work")
        self.assertIn("caller._admit_enrollment_on_work(", source)
        self.assertIn("caller.authorization._admit_enrollment_on_work(", source)
        self.assertIn("forbidden = activation._purpose_pins(", source)
        self.assertIn("if not request_bound:\n                reservation_predecessor = _predecessor", source)
        self.assertNotIn("parent.reservation_predecessor", source)
        self.assertIn("value[\"schema\"] in (V4_SCHEMA, V5_SCHEMA), request_bound)", source)
        for forbidden in ("_ValidationWork(", "QueryReadValidationLimits(", "completeRootVector", "secrets."):
            self.assertNotIn(forbidden, helper + source)

    def test_05_release_resource_scope_and_unchanged_historical_planner_are_distinct(self):
        source = body("control_plane_oidc_session_activation_release_intent_bootstrap", "_admit")
        for marker in ("consumed.request_bound is not request_bound", "consumed.reservation_predecessor is not None",
                "consume._request_policy_on_work(", 'resources.payload["plannerResources"]["runtimeClosureDigest"]',
                "original_current != current_raw", "enrollment.authorization._admit_enrollment_on_work(",
                "consume.caller.enrollments._admit_enrollment_on_work(", "enrollment._admit_on_work(",
                "expected_scope=expected, forbidden_public_keys=forbidden", "activation._purpose_pins("):
            self.assertIn(marker, source)
        self.assertIn("planner_raw = None if request_bound else planned.planner_bootstrap_bytes", source)
        self.assertIn("planning.planner._verify_historical_on_work(", source)
        self.assertIn("planner.attestation_interval[0] < historical_interval[0]", source)
        self.assertIn("planner.attestation_interval[1] > historical_interval[1]", source)
        self.assertIn('expected["runtimeClosureDigest"], runtime_closure_digest', source)
        self.assertLess(source.index("enrollment._admit_on_work("), source.rindex("resources.live()"))
        self.assertLess(source.rindex("resources.live()"), source.index("return result"))
        self.assertNotIn("_ValidationWork(", source)

    def test_06_dynamic_historical_refuses_before_policy_or_processing(self):
        # Existing v1 historical verification remains a distinct actual source
        # path. There is deliberately no claimed v2 historical success here.
        with patch.object(requested.policy, "_verify_on_work", side_effect=AssertionError("unexpected policy call")) as verify, \
                patch.object(intent.planning.planner, "_processing", side_effect=AssertionError("unexpected window")) as processing:
            with self.assertRaisesRegex(intent.OidcSessionActivationReleaseIntentBootstrapError,
                    "historical request-bound policy admission is not provisioned"):
                intent._admit_historical_on_work(release_intent=release_shape(), consume_execution=None,
                    **cold_arguments(), historical_interval=(1, 3), live_window=(1, 2, 2, 10, 10, 8, 0),
                    transport_deadline_ns=9, work=work())
            verify.assert_not_called()
            processing.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
