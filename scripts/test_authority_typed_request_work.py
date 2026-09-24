#!/usr/bin/env python3
"""Actual typed-request commitment under shared work; no planner admission.

Expected canonical documents, framing and pass arithmetic are independent.
Manifest/handler identifiers are source inputs, not successful verifier results.
All controls are authored source-only and unrun.
"""
from __future__ import annotations

import copy
import hashlib
import importlib
import json
from pathlib import Path
import sys
from types import MappingProxyType
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract as contract
from serverware import authority_request_commitment as commitment
from serverware import authority_query_read_work as accounting
import test_authority_revocation_query_program as recipe


OPERATION = "webauthn.credential.revoke"
EXCLUDED = {"authn", "authn_evidence", "webauthn_authorization", "challenge_id"}
REGISTRY_IMPORT_DIAGNOSTIC = (
    "authority transition registry is not closed: missing transition kernels=["
    "webauthn.credential.revoke, webauthn.registration.finalize, "
    "webauthn.trust.complete, webauthn.trust.stage]"
)


def assert_registry_import_denial(case):
    """Real source-era import denial, not a callable planner-facade result."""
    for name in ("serverware.authority_transition_registry", "serverware.authority_planner"):
        with case.subTest(module=name), case.assertRaises(RuntimeError) as caught:
            importlib.import_module(name)
        case.assertEqual(str(caught.exception), REGISTRY_IMPORT_DIAGNOSTIC)


def wire(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def nodes(value):
    if type(value) is dict:
        return 1 + sum(1 + nodes(child) for child in value.values())
    if type(value) in (tuple, list):
        return 1 + sum(nodes(child) for child in value)
    return 1


def framed(domain, *frames):
    payload = domain.encode("ascii") + b"\0"
    return "sha256:" + hashlib.sha256(payload + b"".join(
        len(frame).to_bytes(8, "big") + frame for frame in frames)).hexdigest()


def authorization(request):
    return {"schema": "serverware.policyAuthorityV9Authorization/v1",
        "operation": request["operation"], "handler": request["handler"],
        "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": {key: value for key, value in request["arguments"].items() if key not in EXCLUDED}}


def expected_digest(request):
    return framed("serverware.policyAuthorityV9Request/v1", wire(authorization(request)))


def request_fixture(*, operation=OPERATION, values=None):
    values = copy.deepcopy(recipe.source_values() if values is None else values)
    excluded = EXCLUDED - ({"challenge_id"} if operation in {
        "webauthn.challenge.create", "webauthn.challenge.consume"} else set())
    spec = contract.operation_spec(operation)
    intent = {"schema": "serverware.policyAuthorityBusinessIntent/v2", "operation": operation,
        "planningAdapterId": spec["planningAdapterId"],
        "arguments": {key: copy.deepcopy(value) for key, value in values.items() if key not in excluded}}
    result = {"schema": "serverware.policyAuthorityV9Request/v1", "operation": operation,
        "operationId": "sha256:" + "0" * 64, "requestDigest": "sha256:" + "0" * 64,
        "handler": spec["handler"], "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": {**values, "businessIntent": intent}}
    result["requestDigest"] = expected_digest(result)
    result["operationId"] = framed("serverware.policyAuthorityOperation/v2",
        operation.encode("utf-8"), result["requestDigest"].encode("utf-8"))
    return result


class ExpectedWork:
    def __init__(self):
        self.hashes = 1
        self.input_bytes = self.json_nodes = 0

    def graph(self, value, byte_passes=2, node_passes=2):
        self.input_bytes += byte_passes * len(wire(value))
        self.json_nodes += node_passes * nodes(value)

    def compare(self, left, right):
        self.graph(left)
        self.graph(right)

    @property
    def total(self):
        return self.hashes, self.input_bytes, self.json_nodes


def expected_work(request):
    work = ExpectedWork()
    arguments = request["arguments"]
    intent = arguments["businessIntent"]
    caller = {key: value for key, value in arguments.items() if key != "businessIntent"}
    work.graph(request)
    for field in ("schema", "handler", "operationManifestDigest"):
        work.compare(request[field], request[field])
    work.graph(arguments, 4, 4)  # actual sorted items and filtered caller dict
    work.graph(intent)  # actual four-key set
    for field in ("schema", "operation", "planningAdapterId"):
        work.compare(intent[field], intent[field])
    work.graph(caller, 4, 4)  # genuine synthesis scan and its filtered copy
    work.graph(intent["arguments"], 4, 3)  # canonical, ASCII decode, json.loads
    work.graph(intent)
    work.compare(intent, intent)
    work.graph(intent["arguments"])
    work.compare(intent["arguments"], intent["arguments"])
    work.graph(arguments, 4, 4)  # actual authorization sorted items and filtered dict
    work.graph(authorization(request))
    return work


def meter(**changes):
    return accounting._ValidationWork(accounting.QueryReadValidationLimits(**changes))


def metrics(work):
    return work.hash_work, work.input_bytes, work.json_nodes


class TypedRequestWorkTests(unittest.TestCase):
    def test_actual_digest_and_independent_schedule_for_candidate_and_registered_operations(self):
        for operation in (OPERATION, "webauthn.counter.cas", "webauthn.challenge.create"):
            request = request_fixture(operation=operation)
            expected = expected_work(request)
            shared = meter(max_hashes=expected.hashes, max_input_bytes=expected.input_bytes,
                           max_json_nodes=expected.json_nodes)
            before = copy.deepcopy(request)
            with self.subTest(operation=operation):
                self.assertEqual(commitment._typed_request_digest(request, work=shared), expected_digest(request))
                self.assertEqual(metrics(shared), expected.total)
                self.assertEqual(commitment._typed_request_digest(request, work=None), expected_digest(request))
                self.assertEqual(request, before)
                self.assertEqual(commitment.operation_id(operation, expected_digest(request)), request["operationId"])
                # Actual registered-operation public calls are retained in
                # TypedRequestPlannerIntegrationTests, behind real startup.

    def test_public_registry_gate_is_not_removed_by_private_candidate_commitment(self):
        request = request_fixture()
        self.assertEqual(commitment._typed_request_digest(request, work=meter()), expected_digest(request))
        # The current real registry raises before a public planner can be
        # imported. This proves that boundary, not callable-facade rejection.
        assert_registry_import_denial(self)

    def test_genuine_one_hash_two_encoders_and_one_parser(self):
        request = request_fixture()
        expected = expected_digest(request)
        real_hash, real_dumps, real_loads = hashlib.sha256, json.dumps, json.loads
        shared = meter()
        with patch.object(hashlib, "sha256", wraps=real_hash) as hashes, \
                patch.object(json, "dumps", wraps=real_dumps) as encoders, \
                patch.object(json, "loads", wraps=real_loads) as parsers:
            self.assertEqual(commitment._typed_request_digest(request, work=shared), expected)
        self.assertEqual((hashes.call_count, encoders.call_count, parsers.call_count), (1, 2, 1))
        self.assertEqual(shared.hash_work, 1)

    def test_exclusions_preserve_original_authentication_and_challenge_semantics(self):
        baseline = request_fixture()
        values = {**recipe.source_values(), **{field: {"untrusted": field} for field in EXCLUDED}}
        request = request_fixture(values=values)
        self.assertEqual(expected_digest(request), expected_digest(baseline))
        shared = meter()
        self.assertEqual(commitment._typed_request_digest(request, work=shared), expected_digest(baseline))
        self.assertEqual(metrics(shared), expected_work(request).total)
        # Challenge create/consume intentionally preserve challenge_id inside
        # businessIntent even though the outer authorization filter excludes it.
        first = request_fixture(operation="webauthn.challenge.create", values={"challenge_id": "first"})
        second = request_fixture(operation="webauthn.challenge.create", values={"challenge_id": "second"})
        self.assertNotEqual(expected_digest(first), expected_digest(second))
        self.assertEqual(commitment._typed_request_digest(first, work=meter()), expected_digest(first))

    def test_unicode_semantics_and_nested_values_have_independent_sizes(self):
        values = recipe.source_values(reason="reason 雪😀", audit_event={"note": "audit 雪😀", "nested": [None, True, 7]})
        request = request_fixture(values=values)
        expected = expected_work(request)
        shared = meter(max_input_bytes=expected.input_bytes, max_json_nodes=expected.json_nodes)
        self.assertEqual(commitment._typed_request_digest(request, work=shared), expected_digest(request))
        self.assertEqual(metrics(shared), expected.total)

    def test_exact_one_less_preconsumed_and_repeated_work_never_reset(self):
        request = request_fixture()
        expected = expected_work(request)
        for field, value in (("max_input_bytes", expected.input_bytes - 1),
                             ("max_json_nodes", expected.json_nodes - 1)):
            with self.subTest(field=field), self.assertRaises(accounting.QueryReadWorkError):
                commitment._typed_request_digest(request, work=meter(**{field: value}))
        shared = meter(max_hashes=2, max_input_bytes=2 * expected.input_bytes,
                       max_json_nodes=2 * expected.json_nodes)
        for _ in range(2):
            self.assertEqual(commitment._typed_request_digest(request, work=shared), expected_digest(request))
        self.assertEqual(metrics(shared), tuple(2 * value for value in expected.total))
        with self.assertRaises(accounting.QueryReadWorkError):
            commitment._typed_request_digest(request, work=shared)
        blocked = meter(max_hashes=1)
        blocked.charge(hashes=1)
        real_hash = hashlib.sha256
        with patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
            with self.assertRaises(accounting.QueryReadWorkError):
                commitment._typed_request_digest(request, work=blocked)
        self.assertEqual(hashes.call_count, 0)

    def test_closed_fields_source_identity_and_business_intent_are_not_bypassed(self):
        for field, value in (("schema", "other"), ("handler", "other"),
                             ("operation", "unknown.operation"), ("operationManifestDigest", "sha256:" + "1" * 64)):
            request = request_fixture()
            request[field] = value
            with self.subTest(field=field), self.assertRaises(commitment.AuthorityPlannerError):
                commitment._typed_request_digest(request, work=meter())
        for extra in (True, False):
            request = request_fixture()
            if extra:
                request["extra"] = None
            else:
                del request["requestDigest"]
            with self.assertRaises(commitment.AuthorityPlannerError):
                commitment._typed_request_digest(request, work=meter())
        for field in ("schema", "operation", "planningAdapterId", "arguments"):
            request = request_fixture()
            request["arguments"]["businessIntent"][field] = {} if field == "arguments" else "other"
            with self.subTest(field=field), self.assertRaises(commitment.AuthorityPlannerError):
                commitment._typed_request_digest(request, work=meter())

    def test_digest_fields_require_separate_composer_binding(self):
        request = request_fixture()
        expected = expected_digest(request)
        request["operationId"] = "not an operation commitment"
        request["requestDigest"] = "not a request commitment"
        # These two fields were never hash inputs. The semantic composer must
        # compare both to recomputation; digest return alone cannot admit them.
        self.assertEqual(commitment._typed_request_digest(request, work=meter()), expected)

    def test_public_mapping_compatibility_and_private_exact_meter_boundary(self):
        request = request_fixture(operation="webauthn.counter.cas")
        # Retain the legacy method ID; public facade mapping compatibility is
        # additionally exercised in the real startup-dependent suite.
        self.assertEqual(commitment._typed_request_digest(MappingProxyType(request), work=None), expected_digest(request))
        with self.assertRaises(commitment.AuthorityPlannerError):
            commitment._typed_request_digest(MappingProxyType(request), work=meter())
        for invalid in (object(), accounting.QueryReadValidationLimits()):
            with self.assertRaises(accounting.QueryReadWorkError):
                commitment._typed_request_digest(request, work=invalid)
        for limits in ({"max_input_bytes": 1}, {"max_json_nodes": 1}):
            real_hash, real_dumps, real_loads = hashlib.sha256, json.dumps, json.loads
            with patch.object(hashlib, "sha256", wraps=real_hash) as hashes, \
                    patch.object(json, "dumps", wraps=real_dumps) as encoders, \
                    patch.object(json, "loads", wraps=real_loads) as parsers:
                with self.assertRaises(accounting.QueryReadWorkError):
                    commitment._typed_request_digest(request, work=meter(**limits))
            self.assertEqual((hashes.call_count, encoders.call_count, parsers.call_count), (0, 0, 0))


if __name__ == "__main__":
    unittest.main()
