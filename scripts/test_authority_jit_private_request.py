#!/usr/bin/env python3
"""Private JIT ingress components, not encryption or authority admission.

The actual installed facade stops at a terminal transport sentinel. Actual
service extraction, public commitment codecs and kernel queries then run on
that captured input. Writer controls stop before any connection/cursor access;
there is no database, custody receipt, signed admission, native owner or grant.
Local signing proves byte binding only, not a trusted authority signature.
"""
from __future__ import annotations

import copy
import inspect
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def no_network(event, _args):
    if event.startswith("socket."):
        raise AssertionError("private JIT component tests forbid sockets and DNS")


if __name__ == "__main__":
    sys.addaudithook(no_network)

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import test_authority_jit_request as original
from serverware import authority_contract as contract
from serverware import authority_jit_private_request as private
from serverware import authority_planner as planner
from serverware import authority_request_commitment as commitment
from serverware import authority_service as service
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as quota
from serverware import db
from serverware.authority_store import authority_dispatch, executor_v9


PRIVATE_FIELDS = {"url", "canonical_request", "redacted_display"}
PUBLIC_FIELDS = (original.PUBLIC_FIELDS - PRIVATE_FIELDS) | {
    "schema", "url_commitment", "canonical_request_digest",
    "redacted_display_digest", "original_arguments_digest"}
CANARIES = ("private-url-canary-721", "private-document-canary-853",
    "private-display-canary-964")
PIN = "sha256:" + "a" * 64


def source_values():
    values = original.public_arguments()
    values["url"] = "https://synthetic.invalid/" + CANARIES[0] + "?secret=private"
    values["canonical_request"] = {"private": CANARIES[1], "literal": {
        "$authorityType": "bytes", "base64Url": "JSON-not-an-authority-tag"}}
    values["redacted_display"] = {"label": CANARIES[2], "unicode": "caf\u00e9"}
    return values


def raw_arguments():
    return authority_dispatch._authority_marshal_value(source_values())


def captured():
    operation, envelope = original.dispatch_input(source_values())
    if operation != "jit.request":
        raise AssertionError("facade operation changed")
    return envelope


def extracted(envelope=None):
    return service._extract_v9_runtime_input("jit.request",
        "ensure_jit_approval_request", captured() if envelope is None else envelope)


def typed_request(arguments):
    typed = service._synthesize_business_arguments("jit.request", arguments)
    authorization = {"schema": "serverware.policyAuthorityV9Authorization/v1",
        "operation": "jit.request", "handler": "ensure_jit_approval_request",
        "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": typed}
    digest = original.framed("serverware.policyAuthorityV9Request/v1", authorization)
    return {"schema": "serverware.policyAuthorityV9Request/v1", "operation": "jit.request",
        "handler": "ensure_jit_approval_request", "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": typed, "requestDigest": digest,
        "operationId": commitment.operation_id("jit.request", digest)}


class PrivateJitIngressTests(unittest.TestCase):
    def assert_no_private(self, value):
        encoded = original.canonical(value)
        for canary in CANARIES:
            self.assertNotIn(canary.encode("ascii"), encoded)
        return encoded

    def assert_runtime_refused(self, envelope):
        for call, error in ((lambda: private.validate_runtime_input(envelope), core.TransitionKernelError),
                (lambda: extracted(envelope), service.AuthorityServiceError)):
            with self.assertRaises(error) as caught:
                call()
            self.assertIsNone(caught.exception.__cause__)
            for canary in CANARIES:
                self.assertNotIn(canary, str(caught.exception))

    def test_actual_facade_extraction_matches_independent_original_commitments(self):
        values = source_values()
        before = copy.deepcopy(values)
        _operation, envelope = original.dispatch_input(values)
        raw = authority_dispatch._authority_marshal_value(values)
        expected = {key: copy.deepcopy(value) for key, value in raw.items() if key not in PRIVATE_FIELDS}
        expected.update(schema="serverware.jitRequestCommitments/v2",
            url_commitment=original.sha(raw["url"].encode("utf-8")),
            canonical_request_digest=original.sha(original.canonical(raw["canonical_request"])),
            redacted_display_digest=original.sha(original.canonical(raw["redacted_display"])),
            original_arguments_digest=original.sha(original.canonical(raw)))
        self.assertEqual(envelope, {"schema": "serverware.policyAuthorityPrivateJitWriterInput/v2",
            "handler": "ensure_jit_approval_request", "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
            "arguments": expected, "privateDocuments": {key: raw[key] for key in PRIVATE_FIELDS}})
        self.assertEqual(set(expected), PUBLIC_FIELDS)
        public, authorization, documents = extracted(envelope)
        self.assertEqual(public, expected)
        self.assertIsNone(authorization)
        self.assertEqual(documents, envelope["privateDocuments"])
        self.assertEqual(values, before)
        self.assertNotIn("businessIntent", envelope["arguments"])
        self.assert_no_private(public)
        # Both returned channels are deep owned copies, including tagged-looking
        # ordinary JSON in the private documents.
        public["approver_credential_policy"]["origins"].append("https://changed.invalid")
        documents["canonical_request"]["literal"]["base64Url"] = "changed"
        self.assertEqual(extracted(envelope)[0], expected)
        self.assertEqual(values, before)

    def test_only_public_arguments_enter_real_intent_digest_and_typed_codec(self):
        public, _, _ = extracted()
        request = typed_request(public)
        digest = request["requestDigest"]
        self.assertEqual(service._controlled_writer_request_digest("jit.request", public), digest)
        self.assertEqual(planner.typed_request_digest(request), digest)
        self.assertEqual(request["arguments"]["businessIntent"]["arguments"], public)
        authorization = {"schema": "serverware.policyAuthorityV9Authorization/v1",
            "operation": request["operation"], "handler": request["handler"],
            "operationManifestDigest": request["operationManifestDigest"], "arguments": request["arguments"]}
        wire = self.assert_no_private(authorization)
        self.assert_no_private(request)
        self.assertTrue(PRIVATE_FIELDS.isdisjoint(request["arguments"]))
        key = Ed25519PrivateKey.generate()
        signature = key.sign(wire)
        key.public_key().verify(signature, wire)
        altered = copy.deepcopy(authorization)
        altered["arguments"]["original_arguments_digest"] = PIN
        with self.assertRaises(InvalidSignature):
            key.public_key().verify(signature, original.canonical(altered))
        with self.assertRaises(core.TransitionKernelError):
            private.public_arguments(altered["arguments"], typed=True)
        for field in ("requestDigest", "operationId"):
            changed = copy.deepcopy(request)
            changed[field] = PIN
            with self.subTest(field=field), self.assertRaises(planner.AuthorityPlannerError):
                planner.typed_request_digest(changed)

    def test_kernel_uses_public_envelope_ids_but_still_refuses_absent_custody(self):
        public, _, _ = extracted()
        request = typed_request(public)
        arguments, digest = request["arguments"], request["requestDigest"]
        kernel = quota.KERNELS["jit.request"]
        first = kernel.queries(arguments=arguments, database_now=original.NOW, request_digest=digest)
        self.assertEqual(first, kernel.queries(arguments=copy.deepcopy(arguments),
            database_now=original.NOW, request_digest=digest))
        self.assertEqual([row.table for row in first], ["approval_requests", "routes",
            "policy_authority_opaque_values", "policy_authority_external_evidence_receipts",
            "policy_authority_opaque_values", "policy_authority_external_evidence_receipts",
            "policy_authority_bounded_aggregate_states", "metadata_audit_outbox"])
        for index, purpose in ((0, "jit-approval-request"), (2, "jit-canonical-request"),
                (4, "jit-redacted-display")):
            self.assertEqual(list(first[index].absent_key.values()), [original.identity(digest, purpose)])
            self.assertNotEqual(list(first[index].absent_key.values()),
                [original.identity(public["original_arguments_digest"], purpose)])
        without_ids = private.public_arguments(public)
        self.assertNotIn("canonical_request_opaque_id", without_ids)
        normalized = private.public_arguments(arguments, typed=True, request_digest=digest)
        self.assertEqual(normalized["canonical_request_opaque_id"], original.identity(digest, "jit-canonical-request"))
        context = core.KernelContext(operation="jit.request", arguments=arguments,
            selected_rows=(), database_now=original.NOW, request_digest=digest)
        with patch.object(core, "mutation", side_effect=AssertionError("premature mutation")) as mutation:
            with self.assertRaisesRegex(core.TransitionKernelError, "exact row is absent or ambiguous"):
                kernel.transition(context)
            mutation.assert_not_called()

    def test_runtime_rejects_tampered_originals_digests_metadata_and_closed_fields(self):
        envelope = captured()
        changes = []
        for field in envelope:
            value = copy.deepcopy(envelope)
            del value[field]
            changes.append(value)
        changes += [{**envelope, "extra": None}, {**envelope, "schema": "other"},
            {**envelope, "handler": "approve_request"}, {**envelope, "operationManifestDigest": PIN}]
        for field in PRIVATE_FIELDS:
            value = copy.deepcopy(envelope)
            value["privateDocuments"][field] = "changed" if field == "url" else {"changed": True}
            changes.append(value)
        for field in ("url_commitment", "canonical_request_digest", "redacted_display_digest", "original_arguments_digest"):
            value = copy.deepcopy(envelope)
            value["arguments"][field] = PIN
            changes.append(value)
        for target, field, replacement in (("arguments", "grant_max_uses", 2),
                ("arguments", "credential_version", True), ("arguments", "businessIntent", {}),
                ("arguments", "url", envelope["privateDocuments"]["url"]),
                ("privateDocuments", "extra", None)):
            value = copy.deepcopy(envelope)
            value[target][field] = replacement
            changes.append(value)
        for index, value in enumerate(changes):
            with self.subTest(control=index):
                self.assert_runtime_refused(value)

    def test_private_bound_types_and_legacy_default_policy_fail_before_transport(self):
        raw = raw_arguments()
        changes = [{**raw, "businessIntent": {}}, {**raw, "canonical_request": []},
            {**raw, "redacted_display": {"nan": float("nan")}},
            {**raw, "credential_version": True}, {**raw, "approver_credential_policy": None},
            {**raw, "canonical_request": {"padding": "x" * (33 * 1024)},
                "redacted_display": {"padding": "y" * (33 * 1024)}}]
        for field in ("rpId", "origins"):
            value = copy.deepcopy(raw)
            del value["approver_credential_policy"][field]
            changes.append(value)
        deep = {"leaf": "value"}
        for _ in range(18):
            deep = {"nested": deep}
        changes.append({**raw, "canonical_request": deep})
        for index, value in enumerate(changes):
            with self.subTest(control=index), self.assertRaises(core.TransitionKernelError):
                private.prepare(value)
        below = {**raw, "canonical_request": {"padding": "x" * (15 * 1024)},
            "redacted_display": {"padding": "y" * (15 * 1024)}}
        self.assertEqual(private.validate_runtime_input(private.prepare(below))[1]["canonical_request"], below["canonical_request"])
        values = source_values()
        values.pop("approver_credential_policy")
        with patch.object(db, "dispatch_policy_authority_operation") as send, \
                patch.object(db, "connect", side_effect=AssertionError("unexpected database access")):
            with self.assertRaises(db.MetadataStoreError) as caught:
                db.ensure_jit_approval_request(**values)
            send.assert_not_called()
            for canary in CANARIES:
                self.assertNotIn(canary, str(caught.exception))

    def test_public_validation_is_closed_and_does_not_claim_private_possession(self):
        public, _, _ = extracted()
        for field in PUBLIC_FIELDS:
            value = copy.deepcopy(public)
            del value[field]
            with self.subTest(missing=field), self.assertRaises(core.TransitionKernelError):
                private.public_arguments(value)
        for field in PRIVATE_FIELDS | {"privateDocuments", "businessIntent", "unknown"}:
            with self.subTest(extra=field), self.assertRaises(core.TransitionKernelError):
                private.public_arguments({**public, field: "unexpected"})
        for field, invalid in (("schema", "other"), ("credential_version", True),
                ("original_arguments_digest", "sha256:" + "A" * 64), ("grant_ttl_seconds", 0)):
            with self.subTest(field=field), self.assertRaises(core.TransitionKernelError):
                private.public_arguments({**public, field: invalid})
        for invalid in (1, None, "true"):
            with self.assertRaises(core.TransitionKernelError):
                private.public_arguments(public, typed=invalid)
        # A public-only validator has no original documents. Substituting a
        # well-shaped commitment changes the new signed request; only runtime
        # reconstruction rejects it against the actual originals.
        altered = {**public, "original_arguments_digest": PIN}
        self.assertEqual(private.public_arguments(altered)["original_arguments_digest"], PIN)
        self.assertNotEqual(typed_request(altered)["requestDigest"], typed_request(public)["requestDigest"])
        envelope = captured()
        envelope["arguments"] = altered
        self.assert_runtime_refused(envelope)

    def test_raw_or_extra_private_typed_requests_refuse_before_durable_writer_access(self):
        public, _, _ = extracted()
        requests = [typed_request(raw_arguments()), typed_request({**public, "privateDocuments": captured()["privateDocuments"]})]
        for request in requests:
            with self.subTest(raw="url" in request["arguments"]):
                with self.assertRaisesRegex(planner.AuthorityPlannerError,
                        "^JIT planning requires commitment-only private ingress$"):
                    planner.typed_request_digest(request)
                now_epoch, now_mono = time.time_ns(), time.monotonic_ns()
                with patch.object(executor_v9, "_require_planner_writer",
                        side_effect=AssertionError("durable writer reached")) as writer:
                    with self.assertRaisesRegex(ValueError,
                            "^JIT retention requires commitment-only private ingress$") as rejected:
                        executor_v9.reserve_authority_execution_envelope(
                            envelope_id=PIN, parent_envelope_id=None, operation="jit.request",
                            operation_id=request["operationId"], request_digest=request["requestDigest"],
                            capability_id=PIN, planner_transaction_id=PIN,
                            authorization_projection_digest=PIN, exact_request_bytes=original.canonical(request),
                            deadline_monotonic_ns=now_mono + 1_000_000_000,
                            deadline_epoch_ns=now_epoch + 1_000_000_000, fence=1,
                            reserved_at_epoch_ns=now_epoch, connection=object())
                    self.assertIsNone(rejected.exception.__cause__)
                    writer.assert_not_called()
                    # This is intentionally not a fabricated admitted plan:
                    # the early privacy guard owns refusal before plan validation.
                    with self.assertRaisesRegex(ValueError,
                            "^JIT retention requires commitment-only private ingress$") as rejected:
                        executor_v9.complete_authority_planner_transaction(
                            planner_transaction_id=PIN, authorization_projection_digest=PIN,
                            exact_plan_bytes=original.canonical({"typedRequest": request}),
                            planned_at_epoch_ns=now_epoch, connection=object())
                    self.assertIsNone(rejected.exception.__cause__)
                    writer.assert_not_called()

    def test_actual_service_extraction_precedes_synthesis_and_other_profiles_are_unchanged(self):
        source = inspect.getsource(service.AuthorityProcess._execute_v9_operation)
        self.assertLess(source.index("_extract_v9_runtime_input("), source.index("_synthesize_business_arguments("))
        self.assertLess(source.index("_extract_v9_runtime_input("), source.index("authorization_material ="))
        raw = raw_arguments()
        legacy = {"schema": "serverware.policyAuthorityControlledWriterInput/v1",
            "handler": "ensure_jit_approval_request", "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
            "arguments": raw}
        self.assert_runtime_refused(legacy)
        self.assert_runtime_refused({"input": raw, "webauthnAuthorization": {}})
        operation = "webauthn.counter.cas"
        handler = contract.operation_spec(operation)["handler"]
        ordinary = {**legacy, "handler": handler, "arguments": {"component": "unchanged"}}
        self.assertEqual(service._extract_v9_runtime_input(operation, handler, ordinary),
            ({"component": "unchanged"}, None, None))
        self.assertEqual(service._extract_v9_runtime_input(operation, handler,
            {"input": {"component": "unchanged"}, "webauthnAuthorization": {"assertion": "original"}}),
            ({"component": "unchanged"}, {"assertion": "original"}, None))


if __name__ == "__main__":
    unittest.main(verbosity=2)
