#!/usr/bin/env python3
"""New-release privacy boundaries, not signed/native authority admission.

Installed facade, service extraction and executor retention entrypoints are
real; transport/writer sentinels stop before external effects. The persistence
orchestration control explicitly substitutes its prior signature/full-plan
validation boundary, not a successful database operation. Historical typed
request validation is real and remains distinct from permission to retain anew.
No database, service, provider, native owner or durable plan is created.
"""
from __future__ import annotations

import base64
import copy
import inspect
import json
import os
from pathlib import Path
import sys
import time
from types import MappingProxyType
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def no_external_effects(event, _arguments):
    if event.startswith(("socket.", "sqlite3.")) or event in {"subprocess.Popen", "os.system"}:
        raise AssertionError("release privacy components forbid external effects")


if __name__ == "__main__":
    os.environ["SERVERWARE_PROCESS_MODE"] = "metadata-bootstrap"
    os.environ["SERVERWARE_RELEASE_CHANNEL"] = "dev"
    sys.addaudithook(no_external_effects)

from serverware import authority_contract as contract
from serverware import authority_planner as planner
from serverware import authority_release_private_input as privacy
from serverware import authority_request_commitment as commitment
from serverware import authority_service as service
from serverware import db
from serverware.authority_store import authority_dispatch, executor_v9


OPERATIONS = ("release.reserve", "release.v1.reserve")
ERROR = "Private JIT release input requires its explicit private profile"
PIN = "sha256:" + "a" * 64
CANARIES = ("private-release-url-721", "private-release-canonical-853", "private-release-display-964")
PRIVATE = {"method": "POST", "url": "https://synthetic.invalid/" + CANARIES[0],
    "canonical_request": {"private": CANARIES[1]}, "redacted_display": {"label": CANARIES[2]}}
NON_NULL = (PRIVATE, {}, [], False, 0, "", CANARIES[0])
_ABSENT = object()


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


class BoundaryReached(Exception):
    """Terminal observation, never a successful dispatch or SQL response."""


def values(operation, private=_ABSENT, *, require_jit=False):
    result = {"attempt_id": PIN, "flow_id": "synthetic-flow", "principal_id": "synthetic-principal",
        "route_id": "synthetic-route", "credential_id": "synthetic-credential", "credential_version": 1,
        "policy_hash": PIN, "request_digest": PIN, "operation_digest": None,
        "operation_context": {"public": "unchanged"}, "shared_quotas": [],
        "require_jit_grant": require_jit, "reservation_ttl_seconds": 5}
    if operation == "release.reserve":
        result["durable_policy_binding"] = {"fixture": "not a policy admission"}
    if private is not _ABSENT:
        result["jit_approval_request"] = copy.deepcopy(private)
    return result


def request(operation, arguments):
    typed = service._synthesize_business_arguments(operation, arguments)
    digest = service._controlled_writer_request_digest(operation, arguments)
    return {"schema": "serverware.policyAuthorityV9Request/v1", "operation": operation,
        "handler": contract.operation_spec(operation)["handler"],
        "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": typed, "requestDigest": digest,
        "operationId": commitment.operation_id(operation, digest)}


def payload(operation, private, *, allowed=False):
    # Deliberately partial plan: only the early privacy check is under test.
    return {"typedRequest": request(operation, values(operation, private)),
        "measuredPlan": {"operation": operation}, "expectedResult": {"allowed": allowed},
        "expectedResultDigest": PIN}


def reserve(typed, connection):
    now_epoch, now_mono = time.time_ns(), time.monotonic_ns()
    return executor_v9.reserve_authority_execution_envelope(
        envelope_id=PIN, parent_envelope_id=None, operation=typed["operation"],
        operation_id=typed["operationId"], request_digest=typed["requestDigest"],
        capability_id=PIN, planner_transaction_id=PIN, authorization_projection_digest=PIN,
        exact_request_bytes=canonical(typed), deadline_monotonic_ns=now_mono + 1_000_000_000,
        deadline_epoch_ns=now_epoch + 1_000_000_000, fence=1,
        reserved_at_epoch_ns=now_epoch, connection=connection)


def complete(document, connection):
    return executor_v9.complete_authority_planner_transaction(
        planner_transaction_id=PIN, authorization_projection_digest=PIN,
        exact_plan_bytes=canonical(document), planned_at_epoch_ns=time.time_ns(), connection=connection)


class ReleasePrivateInputTests(unittest.TestCase):
    def refused(self, error, callback):
        with self.assertRaises(error) as caught:
            callback()
        self.assertEqual(str(caught.exception), ERROR)
        self.assertIsNone(caught.exception.__cause__)
        for canary in CANARIES:
            self.assertNotIn(canary, str(caught.exception))

    def test_leaf_is_nonmutating_narrow_refusal_not_a_new_profile(self):
        self.assertEqual(privacy.OPERATIONS, frozenset(OPERATIONS))
        self.assertEqual(privacy.ERROR, ERROR)
        for operation in OPERATIONS:
            for require_jit in (False, True):
                for private in NON_NULL:
                    arguments = values(operation, private, require_jit=require_jit)
                    before = canonical(arguments)
                    self.refused(privacy.PrivateReleaseInputError,
                        lambda: privacy.require_public_arguments(operation, MappingProxyType(arguments)))
                    self.assertEqual(canonical(arguments), before)
                for private in (_ABSENT, None):
                    arguments = values(operation, private, require_jit=require_jit)
                    before = canonical(arguments)
                    self.assertIsNone(privacy.require_public_arguments(operation, arguments))
                    self.assertEqual(canonical(arguments), before)
        # Other operations and malformed outer shapes remain their existing
        # validator's job. Returning None is not authorization or admission.
        for operation in ("jit.request", "release.dispatch", "unknown", None):
            self.assertIsNone(privacy.require_public_arguments(operation, {"jit_approval_request": PRIVATE}))
        self.assertIsNone(privacy.require_public_request(None))

    def test_inner_or_enclosing_operation_cannot_hide_private_input(self):
        for operation in OPERATIONS:
            for inner, outer in ((operation, "other"), ("other", operation), (operation, operation)):
                original = {"operation": inner, "arguments": {"jit_approval_request": PRIVATE}}
                before = canonical(original)
                self.refused(privacy.PrivateReleaseInputError,
                    lambda: privacy.require_public_request(original, operation=outer))
                self.assertEqual(canonical(original), before)

    def test_installed_facades_refuse_before_dispatch_or_database_for_both_jit_flags(self):
        for operation in OPERATIONS:
            handler = getattr(db, contract.operation_spec(operation)["handler"])
            for require_jit in (False, True):
                for private in NON_NULL:
                    original = values(operation, private, require_jit=require_jit)
                    before = canonical(original)
                    with patch.object(db, "dispatch_policy_authority_operation", side_effect=BoundaryReached) as dispatch, \
                            patch.object(db, "connect", side_effect=BoundaryReached) as connect:
                        self.refused(db.MetadataStoreError, lambda: handler(**original))
                        dispatch.assert_not_called()
                        connect.assert_not_called()
                    self.assertEqual(canonical(original), before)

    def test_no_jit_facade_defaults_and_exact_marshaled_bytes_are_unchanged(self):
        for operation in OPERATIONS:
            handler = getattr(db, contract.operation_spec(operation)["handler"])
            for require_jit in (False, True):
                for private in (_ABSENT, None):
                    original = values(operation, private, require_jit=require_jit)
                    bound = inspect.signature(handler).bind(**original)
                    bound.apply_defaults()
                    expected = authority_dispatch._authority_marshal_value({key: value for key, value in bound.arguments.items()
                        if not key.startswith("_") and key != "authority_verifier_response"})
                    before = canonical(original)
                    with patch.object(db, "dispatch_policy_authority_operation", side_effect=BoundaryReached) as dispatch, \
                            patch.object(db, "connect", side_effect=BoundaryReached) as connect:
                        with self.assertRaises(BoundaryReached):
                            handler(**original)
                        dispatch.assert_called_once_with(operation, {
                            "schema": "serverware.policyAuthorityControlledWriterInput/v1",
                            "handler": contract.operation_spec(operation)["handler"],
                            "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST, "arguments": expected})
                        connect.assert_not_called()
                    self.assertEqual(canonical(original), before)

    def test_actual_service_both_envelope_shapes_refuse_and_preserve_no_jit_originals(self):
        for operation in OPERATIONS:
            handler = contract.operation_spec(operation)["handler"]
            for require_jit in (False, True):
                for private in (*NON_NULL, _ABSENT, None):
                    arguments = values(operation, private, require_jit=require_jit)
                    for wrapped in (False, True):
                        authorization = {"fixture": "original explicit authorization, not admitted"}
                        envelope = ({"input": arguments, "webauthnAuthorization": authorization} if wrapped else {
                            "schema": "serverware.policyAuthorityControlledWriterInput/v1", "handler": handler,
                            "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST, "arguments": arguments})
                        before = canonical(envelope)
                        call = lambda: service._extract_v9_runtime_input(operation, handler, envelope)
                        if private is _ABSENT or private is None:
                            self.assertEqual(call(), (arguments, authorization if wrapped else None, None))
                        else:
                            self.refused(service.AuthorityServiceError, call)
                        self.assertEqual(canonical(envelope), before)

    def test_new_plan_retention_refuses_private_input_independent_of_result(self):
        for operation in OPERATIONS:
            for allowed in (False, True):
                for private in NON_NULL:
                    document = payload(operation, private, allowed=allowed)
                    before = canonical(document)
                    connection = Mock()
                    with patch.object(executor_v9, "_require_planner_writer", side_effect=BoundaryReached) as writer:
                        self.refused(ValueError, lambda: complete(document, connection))
                        writer.assert_not_called()
                    self.assertEqual(connection.mock_calls, [])
                    self.assertEqual(canonical(document), before)
            document = payload(operation, PRIVATE)
            document["typedRequest"]["operation"] = "other"
            with patch.object(executor_v9, "_require_planner_writer", side_effect=BoundaryReached) as writer:
                self.refused(ValueError, lambda: complete(document, Mock()))
                writer.assert_not_called()

    def test_new_execution_envelope_refuses_before_writer_but_none_reaches_old_boundary(self):
        for operation in OPERATIONS:
            for private in (*NON_NULL, _ABSENT, None):
                typed = request(operation, values(operation, private))
                before = canonical(typed)
                connection = Mock()
                with patch.object(executor_v9, "_require_planner_writer", side_effect=BoundaryReached) as writer:
                    if private is _ABSENT or private is None:
                        with self.assertRaises(BoundaryReached):
                            reserve(typed, connection)
                        writer.assert_called_once_with(connection)
                    else:
                        self.refused(ValueError, lambda: reserve(typed, connection))
                        writer.assert_not_called()
                self.assertEqual(connection.mock_calls, [])
                self.assertEqual(canonical(typed), before)

    def test_no_jit_incomplete_plan_still_gets_original_full_validation_not_admission(self):
        for operation in OPERATIONS:
            for private in (_ABSENT, None):
                document = payload(operation, private)
                before = canonical(document)
                with patch.object(executor_v9, "_require_planner_writer", side_effect=BoundaryReached) as writer:
                    with self.assertRaisesRegex(ValueError, "^authority measured plan binding is not exact$"):
                        complete(document, Mock())
                    writer.assert_not_called()
                self.assertEqual(canonical(document), before)

    def test_persistence_orchestration_blocks_before_sql_after_explicit_validation_double(self):
        # This one test isolates the actual post-validation persistence code.
        # Its signature/full-plan callbacks are doubles, never native approval.
        import psycopg
        for operation in OPERATIONS:
            for allowed in (False, True):
                for private in (PRIVATE, None):
                    document = payload(operation, private, allowed=allowed)
                    envelope = {"schema": planner.SIGNED_MEASURED_PLAN_SCHEMA, "payload": document,
                        "signatureBase64Url": base64.urlsafe_b64encode(bytes(64)).decode().rstrip("=")}
                    before = canonical(envelope)
                    verify = Mock()
                    identity = object()
                    persistence = planner.PlannerPersistence(persistence_dsn="synthetic-unreachable",
                        connect_timeout_seconds=1, planner_public_key_verify=verify, expected_planner_identity=identity)
                    with patch.object(planner, "validate_measured_plan_payload") as validate, \
                            patch.object(psycopg, "connect", side_effect=BoundaryReached) as connect, \
                            patch.object(db, "compute_authority_v9_result_digest", side_effect=BoundaryReached) as downstream:
                        if private is None:
                            with self.assertRaises(BoundaryReached):
                                persistence.persist(envelope)
                            downstream.assert_called_once_with(canonical(document["expectedResult"]))
                        else:
                            self.refused(planner.AuthorityPlannerError, lambda: persistence.persist(envelope))
                            downstream.assert_not_called()
                        verify.assert_called_once_with(bytes(64), planner.measured_plan_signature_message(document))
                        validate.assert_called_once_with(document, expected_identity=identity)
                        connect.assert_not_called()
                    self.assertEqual(canonical(envelope), before)

    def test_historical_typed_validation_and_commitments_remain_valid_without_new_retention(self):
        for operation in OPERATIONS:
            for require_jit in (False, True):
                typed = request(operation, values(operation, PRIVATE, require_jit=require_jit))
                before = canonical(typed)
                # Historical structural/digest validation is not permission for
                # a new private release request, plan or execution envelope.
                self.assertEqual(planner.typed_request_digest(typed), typed["requestDigest"])
                self.assertEqual(typed["arguments"]["businessIntent"], contract.synthesize_business_intent(
                    operation, values(operation, PRIVATE, require_jit=require_jit)))
                self.refused(privacy.PrivateReleaseInputError, lambda: privacy.require_public_request(typed))
                self.assertEqual(canonical(typed), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
