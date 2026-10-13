#!/usr/bin/env python3
"""Real private-release projection controls, not custody or native admission.

Actual codecs, original argument marshaling, intent/digest functions and service
extraction run on synthetic unsigned fixture inputs. Expected commitments are
computed independently. No authority root, database, provider, transport, opaque
receipt, signed approval, durable plan or successful release is manufactured.
"""
from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
from types import MappingProxyType
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def no_external_effects(event, _arguments):
    if event.startswith(("socket.", "sqlite3.")) or event in {"subprocess.Popen", "os.system"}:
        raise AssertionError("private-release projection tests forbid external effects")


if __name__ == "__main__":
    # Import-only offline mode, not startup. Importing this fixture from another
    # suite preserves that caller's process selection.
    os.environ["SERVERWARE_PROCESS_MODE"] = "metadata-bootstrap"
    os.environ["SERVERWARE_RELEASE_CHANNEL"] = "dev"
    sys.addaudithook(no_external_effects)

from scripts import test_authority_jit_request as jit_fixture
from serverware import authority_contract as contract
from serverware import authority_jit_private_request as child
from serverware import authority_release_private_request as private
from serverware import authority_request_commitment as commitment
from serverware import authority_service as service
from serverware import authority_transition_core as core
from serverware import db, release_authorization_profiles as profiles
from serverware.authority_store import authority_dispatch


OPERATION = "release.reserve"
HANDLER = "reserve_release_authorization_v2"
INPUT_SCHEMA = "serverware.policyAuthorityPrivateReleaseWriterInput/v1"
PUBLIC_SCHEMA = "serverware.releaseReserveCommitments/v1"
ERROR = "Private release input is invalid"
PIN = "sha256:" + "8" * 64
OTHER = "sha256:" + "9" * 64
PRIVATE_FIELDS = {"url", "canonical_request", "redacted_display"}
NESTED_FIELDS = PRIVATE_FIELDS | {"method", "pending_ttl_seconds", "grant_ttl_seconds", "grant_max_uses"}
INHERITED_FIELDS = {"route_id", "principal_id", "credential_id", "credential_version", "policy_hash",
    "request_digest", "operation_digest", "required_approver_roles", "allowed_approver_ids",
    "require_approver_webauthn", "approval_threshold", "approver_credential_policy"}
FIELDS = INHERITED_FIELDS | {"attempt_id", "flow_id", "operation_context", "shared_quotas",
    "require_jit_grant", "reservation_ttl_seconds", "durable_policy_binding", "jit_approval_request",
    "now_epoch_ms", "actor_id", "authority_policy_hash", "authority_route_id", "native_profile",
    "policy_aware_profile", "expected_approver_policy_sha256"}
CANARIES = ("private-release-url-721", "private-release-document-853", "private-release-display-964")


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def framed(domain, *values):
    return sha(domain.encode("ascii") + b"\0" + b"".join(len(value).to_bytes(8, "big") + value for value in values))


def source_values():
    original = jit_fixture.public_arguments()
    original.update(url="https://synthetic.invalid/" + CANARIES[0] + "/caf\u00e9",
        canonical_request={"private": CANARIES[1], "literal": {
            "$authorityType": "bytes", "base64Url": "literal-review-JSON-not-a-type-tag"}},
        redacted_display={"label": CANARIES[2], "unicode": "caf\u00e9"})
    return {**{key: original[key] for key in INHERITED_FIELDS},
        "attempt_id": PIN, "flow_id": PIN, "operation_context": {"public": "unchanged"},
        "shared_quotas": [], "require_jit_grant": True, "reservation_ttl_seconds": 5,
        "durable_policy_binding": {"fixture": "public claim, not admitted policy"},
        "jit_approval_request": {key: original[key] for key in NESTED_FIELDS},
        "now_epoch_ms": None, "actor_id": "oidc:synthetic-actor", "authority_policy_hash": None,
        "authority_route_id": None, "native_profile": False, "policy_aware_profile": False,
        "expected_approver_policy_sha256": None}


def raw_arguments():
    return authority_dispatch._authority_marshal_value(source_values())


def child_original(raw):
    return {**{key: copy.deepcopy(raw[key]) for key in INHERITED_FIELDS}, **copy.deepcopy(raw["jit_approval_request"])}


def expected_envelope(raw):
    original = child_original(raw)
    projected = {key: value for key, value in original.items() if key not in PRIVATE_FIELDS}
    projected.update(schema="serverware.jitRequestCommitments/v2",
        original_arguments_digest=sha(canonical(original)), url_commitment=sha(original["url"].encode("utf-8")),
        canonical_request_digest=sha(canonical(original["canonical_request"])),
        redacted_display_digest=sha(canonical(original["redacted_display"])))
    return {"schema": INPUT_SCHEMA, "handler": HANDLER, "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": {**copy.deepcopy(raw), "schema": PUBLIC_SCHEMA, "original_arguments_digest": sha(canonical(raw)),
            "jit_approval_request": projected}, "privateDocuments": {key: original[key] for key in PRIVATE_FIELDS}}


def typed_request(public):
    spec = contract.operation_spec(OPERATION)
    arguments = {**copy.deepcopy(public), "businessIntent": {
        "schema": "serverware.policyAuthorityBusinessIntent/v2", "operation": OPERATION,
        "planningAdapterId": spec["planningAdapterId"], "arguments": copy.deepcopy(public)}}
    authorization = {"schema": "serverware.policyAuthorityV9Authorization/v1", "operation": OPERATION,
        "handler": HANDLER, "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST, "arguments": arguments}
    digest = framed("serverware.policyAuthorityV9Request/v1", canonical(authorization))
    return {**authorization, "schema": "serverware.policyAuthorityV9Request/v1", "requestDigest": digest,
        "operationId": framed("serverware.policyAuthorityOperation/v2", OPERATION.encode("ascii"), digest.encode("ascii"))}


def document(wrappers):
    value = {"leaf": "fixed"}
    for _ in range(wrappers):
        value = {"nested": value}
    return value


class PrivateReleaseProjectionTests(unittest.TestCase):
    def refused(self, call):
        with self.assertRaises(core.TransitionKernelError) as caught:
            call()
        self.assertEqual(str(caught.exception), ERROR)
        self.assertIsNone(caught.exception.__cause__)
        for canary in CANARIES:
            self.assertNotIn(canary, str(caught.exception))

    def no_private(self, value):
        result = canonical(value)
        for canary in CANARIES:
            self.assertNotIn(canary.encode(), result)
        return result

    def test_exact_original_facade_projection_and_owned_roundtrip(self):
        self.assertEqual((private.OPERATION, private.HANDLER, private.INPUT_SCHEMA, private.PUBLIC_SCHEMA),
            (OPERATION, HANDLER, INPUT_SCHEMA, PUBLIC_SCHEMA))
        self.assertEqual(set(inspect.signature(db.reserve_release_authorization_v2).parameters), FIELDS)
        self.assertEqual((len(FIELDS), len(NESTED_FIELDS), len(INHERITED_FIELDS)), (27, 7, 12))
        raw = raw_arguments()
        before = canonical(raw)
        expected = expected_envelope(raw)
        actual = private.prepare(MappingProxyType(raw))
        self.assertEqual(canonical(actual), canonical(expected))
        public, documents = private.validate_runtime_input(actual)
        self.assertEqual(canonical(public), canonical(expected["arguments"]))
        self.assertEqual(canonical(documents), canonical(expected["privateDocuments"]))
        self.assertEqual(service._extract_v9_runtime_input(OPERATION, HANDLER, actual), (public, None, documents))
        self.no_private(public)
        public["operation_context"]["public"] = "changed"
        public["jit_approval_request"]["approver_credential_policy"]["origins"].append("https://changed.invalid")
        documents["canonical_request"]["literal"]["base64Url"] = "changed"
        self.assertEqual(private.validate_runtime_input(actual), (expected["arguments"], expected["privateDocuments"]))
        self.assertEqual(canonical(raw), before)
        self.assertEqual(canonical(actual), canonical(expected))

    def test_only_public_parent_and_child_enter_actual_typed_commitment(self):
        envelope = private.prepare(raw_arguments())
        public = envelope["arguments"]
        request = typed_request(public)
        self.assertEqual(private.public_arguments(request["arguments"], typed=True), request["arguments"])
        self.assertEqual(commitment._typed_request_digest(request, work=None), request["requestDigest"])
        self.assertEqual(service._controlled_writer_request_digest(OPERATION, public), request["requestDigest"])
        self.no_private(request)
        self.assertNotIn("businessIntent", public["jit_approval_request"])
        self.assertTrue(PRIVATE_FIELDS.isdisjoint(public["jit_approval_request"]))
        self.assertNotEqual(public["original_arguments_digest"], public["jit_approval_request"]["original_arguments_digest"])
        self.assertNotEqual(request["requestDigest"], public["request_digest"])
        for field in ("requestDigest", "operationId", "canonical_request_opaque_id", "redacted_display_opaque_id"):
            self.assertNotIn(field, public)
            self.assertNotIn(field, public["jit_approval_request"])
        changed = copy.deepcopy(request["arguments"])
        changed["businessIntent"]["arguments"]["reservation_ttl_seconds"] = 6
        self.refused(lambda: private.public_arguments(changed, typed=True))

    def test_each_original_parent_child_field_must_join_without_normalization(self):
        public = private.prepare(raw_arguments())["arguments"]
        replacements = {"route_id": "route:other", "principal_id": "agent:other", "credential_id": "credential:other",
            "credential_version": 8, "policy_hash": OTHER, "request_digest": OTHER, "operation_digest": OTHER,
            "required_approver_roles": {"$authorityType": "set", "items": ["admin"]},
            "allowed_approver_ids": {"$authorityType": "set", "items": ["oidc:delta", "oidc:gamma"]},
            "require_approver_webauthn": False, "approval_threshold": 1,
            "approver_credential_policy": {**copy.deepcopy(public["approver_credential_policy"]), "maxAssertionAgeSeconds": 29}}
        self.assertEqual(set(replacements), INHERITED_FIELDS)
        for field, value in replacements.items():
            changed_raw = raw_arguments()
            changed_raw[field] = copy.deepcopy(value)
            with self.subTest(field=field):
                if field == "require_approver_webauthn":
                    # Stored approver policy requires True even when both
                    # parent and child would agree on the replacement.
                    self.refused(lambda: private.prepare(changed_raw))
                else:
                    # These replacements remain valid when legitimately
                    # derived into both views, not merely well-typed tampering.
                    private.validate_runtime_input(private.prepare(changed_raw))
            for target in ("parent", "child"):
                changed = copy.deepcopy(public)
                selected = changed if target == "parent" else changed["jit_approval_request"]
                selected[field] = copy.deepcopy(value)
                with self.subTest(field=field, target=target):
                    self.refused(lambda: private.public_arguments(changed))

    def test_runtime_reconstructs_every_private_and_whole_parent_original(self):
        envelope = private.prepare(raw_arguments())
        changes = []
        for field in PRIVATE_FIELDS:
            changed = copy.deepcopy(envelope)
            changed["privateDocuments"][field] = "changed" if field == "url" else {"changed": True}
            changes.append(changed)
        for field in ("original_arguments_digest", "url_commitment", "canonical_request_digest", "redacted_display_digest"):
            changed = copy.deepcopy(envelope)
            changed["arguments"]["jit_approval_request"][field] = OTHER
            changes.append(changed)
        for field, value in (("original_arguments_digest", OTHER), ("reservation_ttl_seconds", 6),
                ("now_epoch_ms", 1), ("actor_id", "oidc:other"), ("operation_context", {"public": "different"}),
                ("shared_quotas", [{"public": "unadmitted claim"}]), ("durable_policy_binding", {"other": True})):
            changed = copy.deepcopy(envelope)
            changed["arguments"][field] = value
            changes.append(changed)
        for index, changed in enumerate(changes):
            with self.subTest(control=index):
                self.refused(lambda: private.validate_runtime_input(changed))

    def test_missing_extra_and_private_fields_are_closed_at_every_channel(self):
        raw = raw_arguments()
        for field in FIELDS:
            changed = copy.deepcopy(raw); del changed[field]
            with self.subTest(raw_missing=field): self.refused(lambda: private.prepare(changed))
        envelope = private.prepare(raw)
        paths = ((), ("arguments",), ("arguments", "jit_approval_request"), ("privateDocuments",))
        for path in paths:
            original = envelope
            for part in path: original = original[part]
            for field in (*original, "unexpected"):
                changed = copy.deepcopy(envelope)
                target = changed
                for part in path: target = target[part]
                if field == "unexpected": target[field] = None
                else: del target[field]
                with self.subTest(path=path, field=field): self.refused(lambda: private.validate_runtime_input(changed))
        for field in (*PRIVATE_FIELDS, "privateDocuments", "businessIntent"):
            for path in (("arguments",), ("arguments", "jit_approval_request")):
                changed = copy.deepcopy(envelope); target = changed
                for part in path: target = target[part]
                target[field] = CANARIES[0]
                self.refused(lambda: private.validate_runtime_input(changed))
        for field in NESTED_FIELDS:
            changed = copy.deepcopy(raw); del changed["jit_approval_request"][field]
            self.refused(lambda: private.prepare(changed))

    def test_original_types_lifetimes_quotas_and_parent_size_remain_bounded(self):
        raw = raw_arguments()
        invalid = (("require_jit_grant", False), ("require_jit_grant", 1), ("flow_id", OTHER),
            ("attempt_id", "attempt"), ("actor_id", None), ("actor_id", ""), ("operation_digest", None),
            ("credential_version", True), ("reservation_ttl_seconds", True), ("reservation_ttl_seconds", 0),
            ("reservation_ttl_seconds", 301), ("now_epoch_ms", True), ("now_epoch_ms", -1),
            ("now_epoch_ms", 2**63), ("operation_context", []), ("durable_policy_binding", None),
            ("shared_quotas", {}), ("shared_quotas", [None]), ("shared_quotas", [{}] * 13),
            ("operation_context", {"padding": "x" * 65536}),
            ("durable_policy_binding", {"padding": "x" * contract.MAX_REQUEST_BYTES}))
        for field, value in invalid:
            with self.subTest(field=field, type=type(value).__name__):
                self.refused(lambda: private.prepare({**raw, field: value}))
        for field, value in (("reservation_ttl_seconds", 1), ("reservation_ttl_seconds", 300),
                ("now_epoch_ms", 0), ("now_epoch_ms", 2**63-1), ("shared_quotas", [{}] * 12)):
            private.validate_runtime_input(private.prepare({**raw, field: value}))
        for value in (None, False, [], 0, "", child.prepare(child_original(raw))["arguments"]):
            self.refused(lambda: private.prepare({**raw, "jit_approval_request": value}))

    def test_exact_original_child_byte_and_depth_bounds_are_not_shifted(self):
        raw = raw_arguments()
        raw["jit_approval_request"]["canonical_request"] = {"padding": ""}
        original = child_original(raw)
        payload_size = sum(len((original[name] or "").encode("utf-8")) for name in (
            "route_id", "method", "url", "principal_id", "credential_id", "policy_hash", "request_digest", "operation_digest"))
        payload_size += sum(len(canonical(original[name])) for name in ("canonical_request", "redacted_display"))
        payload_size += len(canonical(jit_fixture.policy()))
        raw["jit_approval_request"]["canonical_request"]["padding"] = "x" * (65536 - payload_size)
        child.validate_runtime_input(child.prepare(child_original(raw)))
        private.validate_runtime_input(private.prepare(raw))
        raw["jit_approval_request"]["canonical_request"]["padding"] += "x"
        with self.assertRaises(core.TransitionKernelError): child.prepare(child_original(raw))
        self.refused(lambda: private.prepare(raw))
        for field in ("canonical_request", "redacted_display"):
            raw = raw_arguments(); raw["jit_approval_request"][field] = document(core.MAX_ARGUMENT_DEPTH - 1)
            child.validate_runtime_input(child.prepare(child_original(raw)))
            private.validate_runtime_input(private.prepare(raw))
            raw["jit_approval_request"][field] = document(core.MAX_ARGUMENT_DEPTH)
            with self.assertRaises(core.TransitionKernelError): child.prepare(child_original(raw))
            self.refused(lambda: private.prepare(raw))
        raw = raw_arguments(); raw["operation_context"] = document(core.MAX_ARGUMENT_DEPTH - 1)
        public = private.prepare(raw)["arguments"]
        typed = typed_request(public)["arguments"]
        self.assertEqual(private.public_arguments(typed, typed=True), typed)
        changed = copy.deepcopy(typed); changed["businessIntent"]["arguments"]["operation_context"] = {}
        self.refused(lambda: private.public_arguments(changed, typed=True))

    def test_profile_flags_policy_digest_and_aliases_are_not_admission(self):
        raw = raw_arguments()
        policy_digest = profiles.approver_policy_sha256(jit_fixture.policy())
        for flag in ("native_profile", "policy_aware_profile"):
            selected = {**raw, flag: True, "expected_approver_policy_sha256": policy_digest}
            public, _documents = private.validate_runtime_input(private.prepare(selected))
            self.assertIs(public[flag], True)  # Grammar only: no native owner exists.
            for value in (None, OTHER):
                self.refused(lambda: private.prepare({**selected, "expected_approver_policy_sha256": value}))
        for changes in ({"native_profile": 1}, {"policy_aware_profile": 1},
                {"native_profile": True, "policy_aware_profile": True},
                {"expected_approver_policy_sha256": policy_digest},
                {"authority_policy_hash": raw["policy_hash"]}, {"authority_route_id": raw["route_id"]},
                {"authority_policy_hash": OTHER, "authority_route_id": raw["route_id"]}):
            self.refused(lambda: private.prepare({**raw, **changes}))
        alias = {**raw, "authority_policy_hash": raw["policy_hash"], "authority_route_id": raw["route_id"]}
        self.assertEqual(private.prepare(alias), expected_envelope(alias))

    def test_public_hash_claims_cannot_reconstruct_other_originals(self):
        envelope = private.prepare(raw_arguments())
        changed = copy.deepcopy(envelope["arguments"])
        changed["original_arguments_digest"] = OTHER
        # No originals are available here. A valid digest is only a public claim;
        # changing it changes the committed request, never proves possession.
        self.assertEqual(private.public_arguments(changed)["original_arguments_digest"], OTHER)
        self.assertNotEqual(typed_request(changed)["requestDigest"], typed_request(envelope["arguments"])["requestDigest"])
        self.refused(lambda: private.validate_runtime_input({**envelope, "arguments": changed}))
        changed = copy.deepcopy(envelope["arguments"])
        changed["jit_approval_request"]["url_commitment"] = OTHER
        self.assertEqual(private.public_arguments(changed)["jit_approval_request"]["url_commitment"], OTHER)
        self.refused(lambda: private.validate_runtime_input({**envelope, "arguments": changed}))

    def test_versions_operations_and_typed_inputs_never_silently_upgrade(self):
        raw = raw_arguments(); envelope = private.prepare(raw)
        for field, value in (("schema", "serverware.policyAuthorityControlledWriterInput/v1"),
                ("schema", "serverware.policyAuthorityPrivateReleaseWriterInput/v2"),
                ("handler", "reserve_release_authorization"), ("operationManifestDigest", OTHER)):
            self.refused(lambda: private.validate_runtime_input({**envelope, field: value}))
        for schema in ("serverware.releaseReserveCommitments/v2", "serverware.jitRequestCommitments/v2"):
            self.refused(lambda: private.public_arguments({**envelope["arguments"], "schema": schema}))
        for value in (1, None, "true"):
            self.refused(lambda: private.public_arguments(envelope["arguments"], typed=value))
        self.refused(lambda: private.prepare(envelope["arguments"]))
        self.refused(lambda: private.prepare({**raw, "businessIntent": {}}))
        self.refused(lambda: private.prepare(typed_request(envelope["arguments"])))
        for operation, handler in (("release.v1.reserve", "reserve_release_authorization"), ("jit.request", "ensure_jit_approval_request")):
            with self.assertRaises(service.AuthorityServiceError):
                service._extract_v9_runtime_input(operation, handler, envelope)
        generic = {"schema": "serverware.policyAuthorityControlledWriterInput/v1", "handler": HANDLER,
            "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST, "arguments": raw}
        with self.assertRaises(service.AuthorityServiceError):
            service._extract_v9_runtime_input(OPERATION, HANDLER, generic)
        for method in (private.prepare, private.validate_runtime_input, private.public_arguments):
            for value in (None, False, [], CANARIES[0]): self.refused(lambda: method(value))


if __name__ == "__main__":
    unittest.main(verbosity=2)
