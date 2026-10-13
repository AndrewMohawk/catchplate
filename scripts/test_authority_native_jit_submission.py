#!/usr/bin/env python3
"""Native-JIT service/planner component admission, not runtime acceptance.

Actual Ed25519/P-384/COSE/AES validators use local synthetic keys and clocks.
Real service/planner methods stop at terminal witness, persisted-read or SQL
connection sentinels. Process startup, measured identity, SQL, commit, native
owners, HTTP and deployment are NOT established. No successful custody result
is mocked. Object construction bypasses measured startup explicitly; owned
configuration is synthetic input to these component boundaries only.
"""
from __future__ import annotations

import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_external = []


def no_external_effects(event, _arguments):
    if event.startswith(("socket.", "sqlite3.")) or event in {
            "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}:
        _external.append(event)
        raise AssertionError("native submission controls forbid external effects")


if __name__ == "__main__":
    os.environ["SERVERWARE_PROCESS_MODE"] = "metadata-bootstrap"
    os.environ["SERVERWARE_RELEASE_CHANNEL"] = "dev"
    sys.addaudithook(no_external_effects)

import psycopg
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scripts import test_authority_native_jit_review_custody as crypto
from scripts import test_authority_release_private_input as legacy
from serverware import authority_contract as contract
from serverware import authority_native_jit_review_custody as custody
from serverware import authority_native_jit_submission as submission
from serverware import authority_planner as planner
from serverware import authority_primary_contract as primary
from serverware import authority_service as service
from serverware import native_jit_review_material as material

NOW, MONO, SECOND = crypto.NOW, crypto.MONO, crypto.SECOND
PIN = "sha256:" + "a" * 64
IDENTITY = planner.PlannerIdentity("synthetic-reader", "CN=synthetic", "1", "CN=synthetic-root",
    "sha256:" + "b" * 64, "sha256:" + "c" * 64, "sha256:" + "d" * 64)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii")


def original_channel(fixture):
    return {"schema": "serverware.nativeJitPendingSubmission/v1",
        "runtimeOriginal": canonical(fixture.runtime).decode("ascii"),
        "parentOriginal": canonical(fixture.parent).decode("ascii"),
        "childOriginal": canonical(fixture.child).decode("ascii"),
        "pairOriginal": canonical(fixture.pair).decode("ascii"),
        "evidenceOriginal": canonical(fixture.proof).decode("ascii")}


def planner_request(fixture, channel=None, *, typed=None, deadline=20):
    typed = copy.deepcopy(fixture.parent if typed is None else typed)
    return {"schema": planner.PLANNER_REQUEST_SCHEMA,
        "plannerTransactionId": planner.framed_digest("serverware.policyAuthorityPlannerTransaction/v1",
            typed["operationId"].encode("ascii"), typed["requestDigest"].encode("ascii"), PIN.encode("ascii")),
        "operation": typed["operation"], "operationId": typed["operationId"],
        "requestDigest": typed["requestDigest"], "capabilityId": PIN,
        "typedRequest": typed, "approverPolicyDigest": None, "webauthnEvidence": None,
        "verifierIdentity": {"sessionIdentityDigest": PIN, "measurementDigest": PIN,
            "attestationReceiptDigest": PIN}, "queryManifestDigest": primary.source_query_manifest_digest(),
        "deadlineMonotonicNs": MONO + deadline * SECOND, "deadlineEpochNs": NOW + deadline * SECOND,
        "fence": 1, "reservedAtEpochNs": NOW,
        **({"nativeJitSubmission": original_channel(fixture) if channel is None else channel}
            if submission.selected(typed) else {})}


def extended_configuration(fixture):
    """Resign real synthetic originals after adding service-context fields."""
    raw_role = fixture.role.public_key().public_bytes(serialization.Encoding.Raw,
        serialization.PublicFormat.Raw)
    fixture.configuration["roles"]["planner"].update(databaseConnectTimeoutSeconds=1,
        maximumInternalAgeNs=30 * SECOND, enabledOperations=["release.reserve"])
    fixture.configuration["roles"]["verifier"] = {
        "signingPublicKeyBase64Url": crypto.encoded(raw_role), "measurementDigest": PIN,
        "attestationReceiptDigest": PIN}
    fixture.configuration["roles"]["planner-writer"] = {
        "socketPath": "/synthetic-never-opened.sock", "requestTimeoutSeconds": 1,
        "serviceUid": 1000, "serviceGid": 1000}
    fixture.configuration["webauthn"] = {"maximumChallengeAgeNs": 30 * SECOND}
    fixture.configuration_digest = crypto.framed("serverware.policyAuthorityServiceConfiguration/v6",
        canonical(fixture.configuration))
    fixture.assignment_payload["controlPlaneConfigurationDigest"] = fixture.configuration_digest
    fixture.assignment_original = fixture.sign_assignment()
    broker = {"apiVersion": "serverware.nativeJitReviewConfiguration/v1",
        "sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
        "controlPlaneConfigurationDigest": fixture.configuration_digest,
        "deploymentId": fixture.policy["deploymentId"], "instanceId": fixture.target["instanceId"],
        "secretKekId": crypto.KEY_ID, "attemptCapacity": fixture.policy["attemptCapacity"],
        "identity": {name: fixture.selected[name] for name in crypto.IDENTITY_FIELDS}}
    fixture.scope.update(controlPlaneConfigurationDigest=fixture.configuration_digest,
        ownerScopeDigest=crypto.sha256(canonical(broker)))
    fixture.pair = material.seal_release_pair(fixture.scope, fixture.runtime["privateDocuments"],
        key_id=crypto.KEY_ID, kek=AESGCM(crypto.KEY), now_epoch_ns=NOW)
    fixture.statement.update(controlPlaneConfigurationDigest=fixture.configuration_digest,
        ownerScopeDigest=fixture.scope["ownerScopeDigest"], pairSha256=crypto.sha256(canonical(fixture.pair)))
    fixture.proof = fixture.sign_proof()


class WitnessReached(Exception):
    """Terminal before witness reservation, never a successful witness."""


class SqlReached(Exception):
    """Terminal before opening a DB connection, never successful SQL."""


class PersistedReadReached(Exception):
    """Terminal before requesting a durable replay, never its success."""


class NativeJitSubmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = crypto.SyntheticNitro()

    def setUp(self):
        self.fixture = crypto.Fixture(self.pki)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.wall = self.stack.enter_context(patch.object(service.time, "time_ns", return_value=NOW))
        self.mono = self.stack.enter_context(patch.object(service.time, "monotonic_ns", return_value=MONO))
        self.sql = self.stack.enter_context(patch.object(psycopg, "connect", side_effect=SqlReached()))

    def tearDown(self):
        self.assertEqual(_external, [], "external effect refusals cannot count as passing controls")

    def verifier(self, configuration=None):
        process = object.__new__(service.AuthorityProcess)
        configured = self.fixture.configuration if configuration is None else configuration
        process.configuration = SimpleNamespace(payload=configured, root_key=self.fixture.root.public_key(),
            role=lambda name: configured["roles"][name])
        process._witness_transition = Mock(side_effect=WitnessReached())
        process._sign_internal = Mock(side_effect=AssertionError("unexpected signer"))
        return process

    def execute(self, process, channel=None, *, deadline=60):
        return process._execute_v9_operation(operation="release.reserve",
            handler_name="reserve_release_authorization_v2",
            runtime_input=original_channel(self.fixture) if channel is None else channel,
            deadline_monotonic_ns=MONO + deadline * SECOND)

    def measured(self, *, configured=True, configuration=None, enabled=("release.reserve",)):
        return planner.MeasuredPlanner(read_dsn="postgresql://synthetic-never-opened",
            identity=IDENTITY, connect_timeout_seconds=1, enabled_operations=enabled,
            **({"native_jit_configuration": self.fixture.configuration if configuration is None else configuration,
                "native_jit_root_key": self.fixture.root.public_key()} if configured else {}))

    def planner_process(self, *, enabled=("release.reserve",)):
        process = object.__new__(service.AuthorityProcess)
        process.role_name = "planner"
        process.signing_key = self.fixture.role
        process.role_config = {**self.fixture.configuration["roles"]["planner"], "enabledOperations": list(enabled)}
        process.configuration = SimpleNamespace(payload=self.fixture.configuration,
            root_key=self.fixture.root.public_key(), digest=self.fixture.configuration_digest,
            role=lambda name: self.fixture.configuration["roles"][name])
        process._planner_identity = lambda: IDENTITY
        return process

    def corrupt_signature(self):
        changed = original_channel(self.fixture)
        proof = copy.deepcopy(self.fixture.proof)
        proof["signature"] = "ed25519:" + crypto.encoded(b"x" * 64)
        changed["evidenceOriginal"] = canonical(proof).decode("ascii")
        return changed

    def refused_service(self, process, channel=None, **kwargs):
        with self.assertRaisesRegex(service.AuthorityServiceError, "^" + submission.ERROR + "$") as error:
            self.execute(process, channel, **kwargs)
        self.assertIsNone(error.exception.__cause__)
        process._witness_transition.assert_not_called()
        process._sign_internal.assert_not_called()
        self.sql.assert_not_called()

    def test_original_projection_retains_only_public_sealed_literals(self):
        channel = original_channel(self.fixture)
        before = canonical(channel)
        parent = submission.public_request_from_submission(channel)
        retained = submission.retained_from_submission(channel)
        self.assertEqual(parent, self.fixture.parent)
        self.assertEqual(set(parent), set(self.fixture.parent))
        self.assertEqual(set(retained), {"parentOriginal", "childOriginal", "pairOriginal", "evidenceOriginal"})
        self.assertNotIn("runtimeOriginal", retained)
        self.assertNotIn("privateDocuments", canonical(retained).decode("ascii"))
        self.assertNotIn(self.fixture.runtime["privateDocuments"]["url"], canonical(retained).decode("ascii"))
        self.assertEqual(canonical(channel), before)

    def test_missing_or_extra_original_fields_are_closed(self):
        channel = original_channel(self.fixture)
        for field in channel:
            changed = dict(channel); del changed[field]
            with self.subTest(missing=field), self.assertRaises(submission.SubmissionError):
                submission.parse_submission(changed)
        for field in ("verified", "admitted", "nativeJitPending"):
            with self.subTest(extra=field), self.assertRaises(submission.SubmissionError):
                submission.parse_submission({**channel, field: True})

    def test_policy_boolean_name_projection_is_exact_and_does_not_rewrite_signed_input(self):
        typed = copy.deepcopy(self.fixture.parent)
        before = canonical(typed)
        with self.assertRaises(planner.AuthorityPlannerError):
            planner.reject_authoritative_input(typed)
        projected = submission.name_guard_arguments(typed["arguments"], typed=True)
        expected = copy.deepcopy(typed["arguments"])
        for parent in (expected, expected["businessIntent"]["arguments"]):
            for candidate in (parent, parent["jit_approval_request"]):
                self.assertIs(type(candidate["approver_credential_policy"].pop("requireAttestationTrusted")), bool)
        self.assertEqual(projected, expected)
        self.assertIsNone(planner.reject_typed_authoritative_input("release.reserve", typed))
        self.assertEqual(canonical(typed), before)

    def test_policy_name_projection_does_not_accept_wrong_types_or_extra_authority_fields(self):
        for change in ({"requireAttestationTrusted": {"verified": True}},
                {"requireAttestationTrusted": 1}, {"attestation": {"verified": True}},
                {"nativeVerified": True}):
            arguments = copy.deepcopy(self.fixture.runtime["arguments"])
            arguments["approver_credential_policy"].update(change)
            arguments["jit_approval_request"]["approver_credential_policy"].update(change)
            with self.subTest(fields=sorted(change)), self.assertRaises(submission.SubmissionError):
                submission.name_guard_arguments(arguments)

    def test_policy_name_projection_keeps_arbitrary_public_json_under_generic_guard(self):
        for context in ({"attestation": {"verified": True}},
                {"nested": {"approver_credential_policy": {"requireAttestationTrusted": True}}},
                {"expectedResult": {"allowed": True}}):
            arguments = copy.deepcopy(self.fixture.runtime["arguments"])
            arguments["operation_context"] = context
            typed = legacy.request("release.reserve", arguments)
            with self.subTest(context=list(context)), self.assertRaises(planner.AuthorityPlannerError):
                planner.reject_typed_authoritative_input("release.reserve", typed)

    def test_policy_name_projection_refuses_mismatched_child_intent_and_other_profiles(self):
        child = copy.deepcopy(self.fixture.parent["arguments"])
        child["jit_approval_request"]["approver_credential_policy"]["requireAttestationTrusted"] = False
        intent = copy.deepcopy(self.fixture.parent["arguments"])
        intent["businessIntent"]["arguments"]["approver_credential_policy"]["requireAttestationTrusted"] = False
        other = copy.deepcopy(self.fixture.runtime["arguments"])
        other.update(native_profile=False, policy_aware_profile=True)
        for value, typed in ((child, True), (intent, True), (other, False)):
            with self.subTest(typed=typed), self.assertRaises(submission.SubmissionError):
                submission.name_guard_arguments(value, typed=typed)

    def test_verifier_genuine_crypto_precedes_witness_and_clips_seal_deadline(self):
        process = self.verifier()
        with patch.object(custody, "verify_original", wraps=custody.verify_original) as verified:
            with self.assertRaises(WitnessReached):
                self.execute(process)
        verified.assert_called_once()
        self.assertEqual(verified.call_args.kwargs["deadline_monotonic_ns"], MONO + 60 * SECOND)
        self.assertIs(verified.call_args.kwargs["configuration_payload"], process.configuration.payload)
        self.assertEqual(process._witness_transition.call_args.kwargs["deadline_monotonic_ns"], MONO + 30 * SECOND)
        process._sign_internal.assert_not_called(); self.sql.assert_not_called()

    def test_verifier_does_not_extend_shorter_original_deadline(self):
        process = self.verifier()
        with self.assertRaises(WitnessReached):
            self.execute(process, deadline=7)
        self.assertEqual(process._witness_transition.call_args.kwargs["deadline_monotonic_ns"], MONO + 7 * SECOND)

    def test_verifier_missing_evidence_never_reaches_witness(self):
        channel = original_channel(self.fixture); del channel["evidenceOriginal"]
        self.refused_service(self.verifier(), channel)

    def test_verifier_altered_real_signature_never_reaches_witness(self):
        self.refused_service(self.verifier(), self.corrupt_signature())

    def test_verifier_altered_private_original_never_reaches_witness(self):
        channel = original_channel(self.fixture)
        runtime = copy.deepcopy(self.fixture.runtime)
        runtime["privateDocuments"]["url"] += "?different-private-value"
        channel["runtimeOriginal"] = canonical(runtime).decode("ascii")
        self.refused_service(self.verifier(), channel)

    def test_verifier_expired_seal_never_reaches_witness(self):
        self.wall.return_value = NOW + 30 * SECOND
        self.refused_service(self.verifier())

    def test_verifier_expired_original_monotonic_deadline_never_reaches_witness(self):
        self.refused_service(self.verifier(), deadline=0)

    def test_verifier_without_own_optional_policy_cannot_admit_native_submission(self):
        configuration = copy.deepcopy(self.fixture.configuration); del configuration[custody.FIELD]
        self.refused_service(self.verifier(configuration))

    def test_legacy_private_profile_remains_refused_without_new_channel(self):
        process = self.verifier()
        with self.assertRaisesRegex(service.AuthorityServiceError,
                "^Private JIT release custody and atomic retention are unavailable$"):
            self.execute(process, copy.deepcopy(self.fixture.runtime))
        process._witness_transition.assert_not_called(); self.sql.assert_not_called()

    def test_measured_planner_genuine_verification_returns_no_verdict(self):
        owner = self.measured()
        with patch.object(custody, "verify_original", wraps=custody.verify_original) as verified:
            self.assertIsNone(owner.verify_native_jit_evidence(planner_request(self.fixture)))
        verified.assert_called_once()
        self.assertIs(verified.call_args.kwargs["configuration_payload"], owner.native_jit_configuration)
        self.assertIsNot(owner.native_jit_configuration, self.fixture.configuration)
        self.sql.assert_not_called()

    def test_actual_derive_independently_verifies_before_sql_connection(self):
        owner = self.measured()
        with patch.object(custody, "verify_original", wraps=custody.verify_original) as verified:
            with self.assertRaises(SqlReached):
                owner.derive(planner_request(self.fixture))
        verified.assert_called_once(); self.sql.assert_called_once()

    def test_actual_derive_bad_signature_refuses_before_sql(self):
        with self.assertRaisesRegex(planner.AuthorityPlannerError, "^" + submission.ERROR + "$"):
            self.measured().derive(planner_request(self.fixture, self.corrupt_signature()))
        self.sql.assert_not_called()

    def test_actual_derive_cannot_extend_execution_past_seal(self):
        with self.assertRaisesRegex(planner.AuthorityPlannerError, "^" + submission.ERROR + "$"):
            self.measured().derive(planner_request(self.fixture, deadline=31))
        self.sql.assert_not_called()

    def test_actual_derive_expired_seal_refuses_before_sql(self):
        self.wall.return_value = NOW + 30 * SECOND
        with self.assertRaisesRegex(planner.AuthorityPlannerError, "^" + submission.ERROR + "$"):
            self.measured().derive(planner_request(self.fixture))
        self.sql.assert_not_called()

    def test_planner_requires_its_own_configuration_not_verifier_success(self):
        process = self.verifier()
        with self.assertRaises(WitnessReached):
            self.execute(process)
        changed = copy.deepcopy(self.fixture.configuration)
        changed[custody.FIELD]["attemptCapacity"] += 1
        with self.assertRaisesRegex(planner.AuthorityPlannerError, "^" + submission.ERROR + "$"):
            self.measured(configuration=changed).derive(planner_request(self.fixture))
        self.sql.assert_not_called()

    def test_planner_without_optional_policy_preserves_legacy_constructor(self):
        owner = self.measured(configured=False)
        self.assertIsNone(owner.native_jit_configuration)
        self.assertIsNone(owner.native_jit_root_key)
        with self.assertRaisesRegex(planner.AuthorityPlannerError, "^" + submission.ERROR + "$"):
            owner.derive(planner_request(self.fixture))
        self.sql.assert_not_called()

    def test_native_configuration_cannot_enable_unrelated_planner(self):
        with self.assertRaisesRegex(planner.AuthorityPlannerError,
                "^Native JIT planner lacks its admitted configuration root$"):
            self.measured(enabled=("release.v1.reserve",))
        self.sql.assert_not_called()

    def test_real_planner_service_verifies_before_persisted_lookup(self):
        extended_configuration(self.fixture)
        process = self.planner_process()
        with patch.object(service, "_read_dsn_descriptor", return_value="postgresql://never-opened"), \
                patch.object(service, "_socket_request", side_effect=PersistedReadReached()) as transport, \
                patch.object(custody, "verify_original", wraps=custody.verify_original) as verified:
            with self.assertRaises(PersistedReadReached):
                process._handle_plan({"plannerRequest": planner_request(self.fixture)})
        verified.assert_called_once(); transport.assert_called_once(); self.sql.assert_not_called()
        envelope = transport.call_args.args[1]
        self.assertEqual(envelope["purpose"], "read-persisted-plan")
        self.assertNotIn("runtimeOriginal", canonical(envelope).decode("ascii"))

    def test_real_planner_service_bad_proof_never_attempts_persisted_lookup(self):
        extended_configuration(self.fixture)
        process = self.planner_process()
        with patch.object(service, "_read_dsn_descriptor", return_value="postgresql://never-opened"), \
                patch.object(service, "_socket_request", side_effect=PersistedReadReached()) as transport:
            with self.assertRaisesRegex(planner.AuthorityPlannerError, "^" + submission.ERROR + "$"):
                process._handle_plan({"plannerRequest": planner_request(self.fixture, self.corrupt_signature())})
        transport.assert_not_called(); self.sql.assert_not_called()

    def test_real_service_omits_optional_native_policy_for_unrelated_enabled_operations(self):
        extended_configuration(self.fixture)
        process = self.planner_process(enabled=("release.v1.reserve",))
        typed = legacy.request("release.v1.reserve", legacy.values("release.v1.reserve", None))
        with patch.object(service, "_read_dsn_descriptor", return_value="postgresql://never-opened"), \
                patch.object(service, "_socket_request", side_effect=PersistedReadReached()) as transport, \
                patch.object(planner, "MeasuredPlanner", wraps=planner.MeasuredPlanner) as constructor:
            with self.assertRaises(PersistedReadReached):
                process._handle_plan({"plannerRequest": planner_request(self.fixture, typed=typed)})
        self.assertIsNone(constructor.call_args.kwargs["native_jit_configuration"])
        self.assertIsNone(constructor.call_args.kwargs["native_jit_root_key"])
        transport.assert_called_once(); self.sql.assert_not_called()

    def test_planner_channel_rejects_missing_evidence_and_extra_private_plan_field(self):
        request = planner_request(self.fixture); del request[submission.PLANNER_FIELD]
        with self.assertRaisesRegex(planner.AuthorityPlannerError, "^" + submission.ERROR + "$"):
            planner.validate_planner_request(request)
        # Deliberately incomplete payload cannot assert a successful plan. The
        # closed-field guard must reject transient plaintext in retained data.
        partial = {"typedRequest": self.fixture.parent,
            "nativeJitPending": {**submission.retained_from_submission(original_channel(self.fixture)),
                "runtimeOriginal": original_channel(self.fixture)["runtimeOriginal"]},
            "measuredPlan": {"operation": "release.reserve", "deadlineEpochNs": NOW + 20 * SECOND}}
        with self.assertRaisesRegex(planner.AuthorityPlannerError, "^" + submission.ERROR + "$"):
            planner.validate_measured_plan_payload(partial, expected_identity=IDENTITY)
        self.sql.assert_not_called()


if __name__ == "__main__":
    unittest.main()
