#!/usr/bin/env python3
"""Connected private release projection, not native or writer admission.

These tests call the actual installed DB facade, service extractor and service
execution method. Dispatch is intercepted by a terminal sentinel; the execution
method receives only a synthetic operation-allowlist configuration and must stop
at its explicit unavailable guard. Its measured-process constructor is not run.
No native identity, custody proof, successful signature, SQL or plan is supplied.
The unchanged retention guards also reject projected public compound requests.
"""
from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def no_external_effects(event, _arguments):
    if event.startswith(("socket.", "sqlite3.")) or event in {"subprocess.Popen", "os.system"}:
        raise AssertionError("private release ingress tests forbid external effects")


if __name__ == "__main__":
    os.environ["CATCHPLATE_PROCESS_MODE"] = "metadata-bootstrap"
    os.environ["CATCHPLATE_RELEASE_CHANNEL"] = "dev"
    sys.addaudithook(no_external_effects)

from catchplate import authority_contract as contract
from catchplate import authority_jit_private_request as child
from catchplate import authority_planner as planner
from catchplate import authority_release_private_input as privacy
from catchplate import authority_release_private_request as ingress
from catchplate import authority_request_commitment as commitment
from catchplate import authority_service as service
from catchplate import db
from catchplate import release_authorization_profiles as profiles
from catchplate.authority_store import authority_dispatch, executor_v9

OPERATION = "release.reserve"
HANDLER = "reserve_release_authorization_v2"
INPUT_SCHEMA = "catchplate.policyAuthorityPrivateReleaseWriterInput/v1"
PUBLIC_SCHEMA = "catchplate.releaseReserveCommitments/v1"
UNAVAILABLE = "Private JIT release custody and atomic retention are unavailable"
PRIVATE_ERROR = "Private JIT release input requires its explicit private profile"
PIN = "sha256:" + "a" * 64
CANARIES = ("release-url-private-418", "release-document-private-529", "release-display-private-630")
CHILD_INHERITED = frozenset({"route_id", "principal_id", "credential_id", "credential_version",
    "policy_hash", "request_digest", "operation_digest", "required_approver_roles",
    "allowed_approver_ids", "require_approver_webauthn", "approval_threshold", "approver_credential_policy"})
NESTED_FIELDS = frozenset({"method", "url", "canonical_request", "redacted_display",
    "pending_ttl_seconds", "grant_ttl_seconds", "grant_max_uses"})
PRIVATE_FIELDS = frozenset({"url", "canonical_request", "redacted_display"})
_ABSENT = object()


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii")


def sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def values():
    # The real route helper, with synthetic local RP/origin settings only.
    # These settings do not establish an admitted WebAuthn or native owner.
    with patch.object(db, "WEBAUTHN_RP_ID", "synthetic.invalid"), \
            patch.object(db, "WEBAUTHN_ORIGIN", "https://synthetic.invalid"):
        approvers = db.jit_approver_policy_arguments({"approvers": {
            "users": ["oidc:beta", "oidc:alpha"], "quorum": 2,
            "authn": {"maxAssertionAgeSeconds": 30}}})
    return {"attempt_id": PIN, "flow_id": PIN, "principal_id": "agent:synthetic",
        "route_id": "route:synthetic", "credential_id": "credential:synthetic",
        "credential_version": 7, "policy_hash": "sha256:" + "b" * 64,
        "request_digest": "sha256:" + "c" * 64, "operation_digest": "sha256:" + "d" * 64,
        "operation_context": {"operation": "synthetic-read"}, "shared_quotas": [],
        "require_jit_grant": True, "reservation_ttl_seconds": 5,
        "durable_policy_binding": {"fixture": "grammar only, not durable policy admission"},
        "actor_id": "data-plane:synthetic", **approvers,
        "jit_approval_request": {"method": "POST",
            "url": "https://synthetic.invalid/" + CANARIES[0],
            "canonical_request": {"private": CANARIES[1], "finite": 1.25},
            "redacted_display": {"private": CANARIES[2], "finite": -0.5,
                "literal": {"$authorityType": "bytes", "base64Url": "literal-not-decoded"}},
            "pending_ttl_seconds": 300, "grant_ttl_seconds": 30, "grant_max_uses": 1}}


def marshaled(original, operation=OPERATION):
    handler = getattr(db, contract.operation_spec(operation)["handler"])
    bound = inspect.signature(handler).bind(**original)
    bound.apply_defaults()
    return authority_dispatch._authority_marshal_value({key: value for key, value in bound.arguments.items()
        if not key.startswith("_") and key != "authority_verifier_response"})


class DispatchReached(Exception):
    """Terminal interception, never a successful writer response."""


def capture(original, operation=OPERATION):
    seen = []

    def stop(selected_operation, document):
        seen.append((selected_operation, copy.deepcopy(document)))
        raise DispatchReached()

    with patch.object(db, "dispatch_policy_authority_operation", side_effect=stop), \
            patch.object(db, "connect", side_effect=AssertionError("unexpected database connection")):
        try:
            getattr(db, contract.operation_spec(operation)["handler"])(**original)
        except DispatchReached:
            pass
        else:
            raise AssertionError("actual installed facade did not reach dispatch")
    if len(seen) != 1:
        raise AssertionError("private ingress changed dispatch count")
    return seen[0]


def typed_request(arguments, operation=OPERATION):
    typed = service._synthesize_business_arguments(operation, arguments)
    digest = service._controlled_writer_request_digest(operation, arguments)
    return {"schema": "catchplate.policyAuthorityV9Request/v1", "operation": operation,
        "handler": contract.operation_spec(operation)["handler"],
        "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": typed, "requestDigest": digest,
        "operationId": commitment.operation_id(operation, digest)}


def reserve_envelope(typed, connection):
    now_epoch, now_mono = time.time_ns(), time.monotonic_ns()
    return executor_v9.reserve_authority_execution_envelope(
        envelope_id=PIN, parent_envelope_id=None, operation=typed["operation"],
        operation_id=typed["operationId"], request_digest=typed["requestDigest"], capability_id=PIN,
        planner_transaction_id=PIN, authorization_projection_digest=PIN,
        exact_request_bytes=canonical(typed), deadline_monotonic_ns=now_mono + 1_000_000_000,
        deadline_epoch_ns=now_epoch + 1_000_000_000, fence=1,
        reserved_at_epoch_ns=now_epoch, connection=connection)


class PrivateReleaseIngressTests(unittest.TestCase):
    def refused(self, error, message, callback):
        with self.assertRaises(error) as caught:
            callback()
        self.assertEqual(str(caught.exception), message)
        self.assertIsNone(caught.exception.__cause__)
        for canary in CANARIES:
            self.assertNotIn(canary, str(caught.exception))

    def test_actual_installed_facade_projects_exact_defaults_and_child_originals(self):
        original = values()
        raw = marshaled(original)
        before = canonical(raw)
        selected, document = capture(original)
        self.assertEqual(selected, OPERATION)
        self.assertEqual(len(raw), 27)
        self.assertEqual(set(document), {"schema", "handler", "operationManifestDigest", "arguments", "privateDocuments"})
        self.assertEqual((document["schema"], document["handler"]), (INPUT_SCHEMA, HANDLER))
        self.assertEqual(document["operationManifestDigest"], contract.OPERATION_MANIFEST_DIGEST)
        public = document["arguments"]
        self.assertEqual(set(public), set(raw) | {"schema", "original_arguments_digest"})
        self.assertEqual(public["schema"], PUBLIC_SCHEMA)
        self.assertEqual(public["original_arguments_digest"], sha(before))
        for name in set(raw) - {"jit_approval_request"}:
            self.assertEqual(canonical(public[name]), canonical(raw[name]))
        raw_child = {name: raw[name] for name in CHILD_INHERITED}
        raw_child.update(raw["jit_approval_request"])
        self.assertEqual(len(raw_child), 19)
        self.assertEqual(public["jit_approval_request"], child.prepare(raw_child)["arguments"])
        self.assertEqual(public["jit_approval_request"]["original_arguments_digest"], sha(canonical(raw_child)))
        self.assertEqual(document["privateDocuments"], {name: raw["jit_approval_request"][name] for name in PRIVATE_FIELDS})
        for canary in CANARIES:
            self.assertNotIn(canary.encode(), canonical(public))
        self.assertEqual(canonical(marshaled(original)), before)

    def test_real_service_extraction_roundtrips_owned_private_values(self):
        _, document = capture(values())
        before = canonical(document)
        public, authorization, private = service._extract_v9_runtime_input(OPERATION, HANDLER, document)
        self.assertEqual((public, authorization, private), (document["arguments"], None, document["privateDocuments"]))
        self.assertEqual(ingress.public_arguments(public), public)
        self.assertNotIn("businessIntent", public)
        self.assertNotIn("businessIntent", public["jit_approval_request"])
        private["canonical_request"]["private"] = "changed returned copy"
        public["operation_context"]["operation"] = "changed returned copy"
        self.assertEqual(canonical(document), before)

    def test_actual_service_execution_stops_before_commitments_signing_planning_or_sql(self):
        _, document = capture(values())
        before = canonical(document)
        process = object.__new__(service.AuthorityProcess)
        # Deliberately bypass constructor admission: only this allowlist is
        # needed to reach the real early refusal. No native identity is made.
        role = Mock(return_value={"enabledOperations": [OPERATION]})
        process.configuration = SimpleNamespace(role=role)
        process._witness_transition = Mock(side_effect=AssertionError("witness reached"))
        process._sign_internal = Mock(side_effect=AssertionError("signer reached"))
        process.signing_key = Mock()
        with patch.object(service, "_extract_v9_runtime_input", wraps=service._extract_v9_runtime_input) as extract, \
                patch.object(service, "_synthesize_business_arguments", side_effect=AssertionError("commitment reached")) as synthesize, \
                patch.object(service, "_domain_digest", side_effect=AssertionError("digest reached")) as digest, \
                patch.object(service, "_socket_request", side_effect=AssertionError("transport reached")) as transport, \
                patch.object(planner, "reject_authoritative_input", side_effect=AssertionError("planner reached")) as reject, \
                patch.object(db, "connect", side_effect=AssertionError("database reached")) as connect:
            self.refused(service.AuthorityServiceError, UNAVAILABLE, lambda: process._execute_v9_operation(
                operation=OPERATION, handler_name=HANDLER, runtime_input=document,
                deadline_monotonic_ns=time.monotonic_ns() + 1_000_000_000))
            extract.assert_called_once_with(OPERATION, HANDLER, document)
            for sentinel in (synthesize, digest, transport, reject, connect,
                    process._witness_transition, process._sign_internal):
                sentinel.assert_not_called()
            self.assertEqual(process.signing_key.mock_calls, [])
        role.assert_called_once_with("planner")
        self.assertEqual(canonical(document), before)

    def test_mutated_private_and_public_originals_refuse_in_real_extractor(self):
        _, original = capture(values())
        variants = []
        for name in PRIVATE_FIELDS:
            document = copy.deepcopy(original)
            document["privateDocuments"][name] = "changed" if name == "url" else {"changed": True}
            variants.append(document)
        for name, value in (("actor_id", "different actor"), ("now_epoch_ms", 1),
                ("original_arguments_digest", PIN), ("require_jit_grant", False)):
            document = copy.deepcopy(original)
            document["arguments"][name] = value
            variants.append(document)
        for place in ("arguments", "privateDocuments"):
            document = copy.deepcopy(original)
            document[place]["unexpected"] = CANARIES[0]
            variants.append(document)
        document = copy.deepcopy(original)
        document["arguments"]["jit_approval_request"]["businessIntent"] = {"forged": True}
        variants.append(document)
        for document in variants:
            with self.subTest(document_keys=sorted(document["arguments"])):
                before = canonical(document)
                self.refused(service.AuthorityServiceError, "authority private release input refused",
                    lambda: service._extract_v9_runtime_input(OPERATION, HANDLER, document))
                self.assertEqual(canonical(document), before)

    def test_new_profile_cannot_relabel_legacy_operation_handler_or_manifest(self):
        _, document = capture(values())
        self.refused(service.AuthorityServiceError, "authority v9 accepts only semantic typed input",
            lambda: service._extract_v9_runtime_input("release.v1.reserve", "reserve_release_authorization", document))
        self.refused(service.AuthorityServiceError, "typed authority handler binding changed",
            lambda: service._extract_v9_runtime_input(OPERATION, "ensure_jit_approval_request", document))
        for field, value in (("handler", "ensure_jit_approval_request"), ("operationManifestDigest", PIN)):
            changed = copy.deepcopy(document)
            changed[field] = value
            self.refused(service.AuthorityServiceError, "authority private release input refused",
                lambda: service._extract_v9_runtime_input(OPERATION, HANDLER, changed))

    def test_malformed_nested_or_false_jit_never_dispatches_or_reads_database(self):
        variants = []
        for value in ({}, [], False, 0, "", CANARIES[0]):
            original = values()
            original["jit_approval_request"] = value
            variants.append(original)
        for field in NESTED_FIELDS:
            original = values()
            del original["jit_approval_request"][field]
            variants.append(original)
        original = values()
        original["require_jit_grant"] = False
        variants.append(original)
        for original in variants:
            with patch.object(db, "dispatch_policy_authority_operation", side_effect=AssertionError("dispatch reached")) as dispatch, \
                    patch.object(db, "connect", side_effect=AssertionError("database reached")) as connect:
                self.refused(db.MetadataStoreError, PRIVATE_ERROR, lambda: db.reserve_release_authorization_v2(**original))
                dispatch.assert_not_called()
                connect.assert_not_called()

    def test_absent_and_null_nested_preserve_exact_old_facade_bytes_for_both_operations(self):
        for operation in (OPERATION, "release.v1.reserve"):
            for require_jit in (False, True):
                for private in (_ABSENT, None):
                    original = values()
                    original["require_jit_grant"] = require_jit
                    if operation != OPERATION:
                        del original["durable_policy_binding"]
                    if private is _ABSENT:
                        del original["jit_approval_request"]
                    else:
                        original["jit_approval_request"] = None
                    expected = marshaled(original, operation)
                    selected, envelope = capture(original, operation)
                    self.assertEqual(selected, operation)
                    self.assertEqual(envelope, {"schema": "catchplate.policyAuthorityControlledWriterInput/v1",
                        "handler": contract.operation_spec(operation)["handler"],
                        "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST, "arguments": expected})
                    self.assertEqual(service._extract_v9_runtime_input(operation, envelope["handler"], envelope),
                        (expected, None, None))

    def test_valid_nested_legacy_v1_is_still_refused_without_dispatch(self):
        original = values()
        del original["durable_policy_binding"]
        with patch.object(db, "dispatch_policy_authority_operation") as dispatch, patch.object(db, "connect") as connect:
            self.refused(db.MetadataStoreError, PRIVATE_ERROR, lambda: db.reserve_release_authorization(**original))
            dispatch.assert_not_called()
            connect.assert_not_called()

    def test_parent_attempt_changes_do_not_relabel_child_identity_or_add_nested_intent(self):
        original = values()
        _, first = capture(original)
        original["attempt_id"] = original["flow_id"] = "sha256:" + "e" * 64
        _, second = capture(original)
        first_public, second_public = first["arguments"], second["arguments"]
        self.assertEqual(first_public["jit_approval_request"], second_public["jit_approval_request"])
        self.assertNotEqual(first_public["original_arguments_digest"], second_public["original_arguments_digest"])
        parent_one, parent_two = typed_request(first_public), typed_request(second_public)
        self.assertNotEqual(parent_one["requestDigest"], parent_two["requestDigest"])
        child_one = typed_request(first_public["jit_approval_request"], "jit.request")
        child_two = typed_request(second_public["jit_approval_request"], "jit.request")
        self.assertEqual(child_one, child_two)
        self.assertEqual(planner.typed_request_digest(parent_one), parent_one["requestDigest"])
        self.assertEqual(planner.typed_request_digest(child_one), child_one["requestDigest"])
        self.assertNotEqual(parent_one["requestDigest"], child_one["requestDigest"])
        with self.assertRaises(ValueError):
            contract.synthesize_business_intent(OPERATION, {**first_public, "jit_approval_request": child_one["arguments"]})

    def test_raw_and_projected_public_inputs_still_cannot_retain_a_new_envelope_or_plan(self):
        original = values()
        _, document = capture(original)
        for arguments in (marshaled(original), document["arguments"]):
            typed = typed_request(arguments)
            self.refused(privacy.PrivateReleaseInputError, PRIVATE_ERROR,
                lambda: privacy.require_public_request(typed))
            for allowed in (False, True):
                plan = {"typedRequest": typed, "measuredPlan": {"operation": OPERATION},
                    "expectedResult": {"allowed": allowed}}
                connection = Mock()
                with patch.object(executor_v9, "_require_planner_writer", side_effect=AssertionError("writer reached")) as writer:
                    self.refused(ValueError, PRIVATE_ERROR, lambda: executor_v9.complete_authority_planner_transaction(
                        planner_transaction_id=PIN, authorization_projection_digest=PIN,
                        exact_plan_bytes=canonical(plan), planned_at_epoch_ns=time.time_ns(), connection=connection))
                    self.refused(ValueError, PRIVATE_ERROR, lambda: reserve_envelope(typed, connection))
                    writer.assert_not_called()
                self.assertEqual(connection.mock_calls, [])

    def test_old_generic_envelope_cannot_smuggle_the_new_projection_into_service(self):
        _, document = capture(values())
        for envelope in ({"schema": "catchplate.policyAuthorityControlledWriterInput/v1",
                "handler": HANDLER, "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
                "arguments": document["arguments"]},
                {"input": document["arguments"], "webauthnAuthorization": {"not": "authority"}}):
            self.refused(service.AuthorityServiceError, PRIVATE_ERROR,
                lambda: service._extract_v9_runtime_input(OPERATION, HANDLER, envelope))

    def test_versioned_policy_binding_is_checked_without_native_admission(self):
        original = values()
        _, baseline = capture(original)
        normalized = child.public_arguments(baseline["arguments"]["jit_approval_request"])
        original["native_profile"] = True
        original["expected_approver_policy_sha256"] = profiles.approver_policy_sha256(normalized["approver_policy"])
        _, envelope = capture(original)
        self.assertIs(service._extract_v9_runtime_input(OPERATION, HANDLER, envelope)[0]["native_profile"], True)
        original["expected_approver_policy_sha256"] = PIN
        with patch.object(db, "dispatch_policy_authority_operation") as dispatch:
            self.refused(db.MetadataStoreError, PRIVATE_ERROR, lambda: db.reserve_release_authorization_v2(**original))
            dispatch.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
