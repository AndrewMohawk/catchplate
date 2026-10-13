#!/usr/bin/env python3
"""Real private-release projection controls, not custody or native admission.

Actual codecs, original argument marshaling, intent/digest functions and service
extraction run on synthetic unsigned fixture inputs. Expected commitments are
computed independently. No authority root, database, provider, transport, opaque
receipt, signed approval, durable plan or successful release is manufactured.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, fields as dataclass_fields
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
# Independent fixed vectors, not values obtained from the derivation under test.
# The manifest is the target in operator_authority_contract_migration_x_quota_pins.json;
# its authority_contract.py pin is 45cccd774573b20592ac4075161e47debb70a2886fc6de619cbaa31380bec3f4.
NATIVE_MANIFEST = "sha256:9fa8ca9ea0aa5c37e94ca5344eb1b4b62ae7f46c06843907a5bd3fb0baf4f9e2"
NATIVE_POLICY_DIGEST = "sha256:ca91d87c21f8706949a6b06c3d7c3dcdd6120dac6b2f5caa788e25b9155fc454"
NATIVE_PARENT_ORIGINAL = "sha256:befb9c29e1e9d770ed834444468a9d785723b0db9aee84bca19ff831422a67ff"
NATIVE_CHILD_ORIGINAL = "sha256:cdbdeb4e8c8ef15eea1e394d500bdbf211357fb3271f53bb9bc4cd887f9a92b3"
NATIVE_IDENTITIES = {
    "release.reserve": (
        "sha256:baf90ca55fb61c292108404b2470d8dbb9da75825de7bbdfb40312a35085e50a",
        "sha256:bad401085c38d2ea27ce1d9fd839eaa98eb86d8f8bfcd08d50731472b7025e70"),
    "jit.request": (
        "sha256:34e9dcac76e77e6c7421ca10f444632e53d399aa16538e9534b08b8a6e95ac2f",
        "sha256:138181e8a5ae9640d7653987671ca9c7f6f7675454e1c38b42f56363b17a33fb"),
}


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


def native_raw_arguments():
    return {**raw_arguments(), "native_profile": True,
        "expected_approver_policy_sha256": NATIVE_POLICY_DIGEST}


def native_request_oracle(operation, public):
    # All domains, handlers and adapters are literals. The oracle intentionally
    # does not call contract synthesis, shared framing, or the implementation.
    handler, adapter = {
        "release.reserve": ("reserve_release_authorization_v2",
            "serverware.policyAuthorityPlanningAdapter/reserve_release_authorization_v2/v1"),
        "jit.request": ("ensure_jit_approval_request",
            "serverware.policyAuthorityPlanningAdapter/ensure_jit_approval_request/v1"),
    }[operation]
    arguments = {**copy.deepcopy(public), "businessIntent": {
        "schema": "serverware.policyAuthorityBusinessIntent/v2", "operation": operation,
        "planningAdapterId": adapter, "arguments": copy.deepcopy(public)}}
    authorization = {"schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": handler, "operationManifestDigest": NATIVE_MANIFEST, "arguments": arguments}
    digest = framed("serverware.policyAuthorityV9Request/v1", canonical(authorization))
    return {**authorization, "schema": "serverware.policyAuthorityV9Request/v1", "requestDigest": digest,
        "operationId": framed("serverware.policyAuthorityOperation/v2", operation.encode("ascii"), digest.encode("ascii"))}


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

    def test_native_derivation_matches_literal_parent_and_child_v9_vectors(self):
        self.assertEqual(tuple(inspect.signature(private.derive_native_requests).parameters), ("runtime_input",))
        self.assertEqual(contract.OPERATION_MANIFEST_DIGEST, NATIVE_MANIFEST)
        self.assertEqual(sha(canonical(jit_fixture.policy())), NATIVE_POLICY_DIGEST)
        raw = native_raw_arguments()
        expected = expected_envelope(raw)
        self.assertEqual(expected["arguments"]["original_arguments_digest"], NATIVE_PARENT_ORIGINAL)
        self.assertEqual(expected["arguments"]["jit_approval_request"]["original_arguments_digest"], NATIVE_CHILD_ORIGINAL)
        result = private.derive_native_requests(MappingProxyType(private.prepare(raw)))
        self.assertIs(type(result), private.ReleaseJitRequests)
        self.assertEqual(tuple(field.name for field in dataclass_fields(result)), ("parent_request", "child_request"))
        self.assertFalse(hasattr(result, "__dict__"))
        with self.assertRaises(FrozenInstanceError): result.parent_request = {}
        with self.assertRaises(FrozenInstanceError): result.child_request = {}
        for operation, request, public, count in (
                ("release.reserve", result.parent_request, expected["arguments"], 29),
                ("jit.request", result.child_request, expected["arguments"]["jit_approval_request"], 21)):
            with self.subTest(operation=operation):
                self.assertEqual(len(public), count)
                self.assertIs(type(request), dict)
                self.assertEqual(set(request), {"schema", "operation", "handler", "operationManifestDigest",
                    "arguments", "requestDigest", "operationId"})
                self.assertEqual(canonical(request), canonical(native_request_oracle(operation, public)))
                self.assertEqual((request["requestDigest"], request["operationId"]), NATIVE_IDENTITIES[operation])
                self.assertEqual(commitment._typed_request_digest(request, work=None), request["requestDigest"])
                self.assertEqual(service._controlled_writer_request_digest(operation, public), request["requestDigest"])
                self.assertEqual(request["arguments"]["businessIntent"]["arguments"], public)
                self.assertEqual({key: value for key, value in request["arguments"].items()
                    if key != "businessIntent"}, public)
                self.no_private(request)
                for key in ("privateDocuments", "canonical_request_opaque_id", "redacted_display_opaque_id",
                        "approver_policy", "approver_policy_digest"):
                    self.assertNotIn(key, request["arguments"])
        parent_child = result.parent_request["arguments"]["jit_approval_request"]
        self.assertEqual(parent_child, expected["arguments"]["jit_approval_request"])
        self.assertNotIn("businessIntent", parent_child)
        self.assertNotEqual(result.parent_request["requestDigest"], result.child_request["requestDigest"])
        self.assertNotEqual(result.parent_request["operationId"], result.child_request["operationId"])
        self.assertNotEqual(result.child_request["requestDigest"], parent_child["request_digest"])

    def test_native_parent_only_substitutions_preserve_the_entire_child_request(self):
        raw = native_raw_arguments()
        baseline = private.derive_native_requests(private.prepare(raw))
        substitutions = (
            {"attempt_id": OTHER, "flow_id": OTHER}, {"operation_context": {"public": "different"}},
            {"shared_quotas": [{"public": "unadmitted quota claim"}]}, {"reservation_ttl_seconds": 6},
            {"durable_policy_binding": {"public": "unadmitted policy claim"}}, {"now_epoch_ms": 0},
            {"actor_id": "oidc:other"},
            {"authority_policy_hash": raw["policy_hash"], "authority_route_id": raw["route_id"]},
        )
        for replacement in substitutions:
            with self.subTest(fields=tuple(replacement)):
                changed = private.derive_native_requests(private.prepare({**raw, **replacement}))
                self.assertEqual(canonical(changed.child_request), canonical(baseline.child_request))
                for key in ("requestDigest", "operationId"):
                    self.assertNotEqual(changed.parent_request[key], baseline.parent_request[key])
                self.assertNotEqual(changed.parent_request["arguments"]["original_arguments_digest"],
                    baseline.parent_request["arguments"]["original_arguments_digest"])

    def test_native_inherited_and_nested_original_changes_bind_both_requests(self):
        raw = native_raw_arguments()
        baseline = private.derive_native_requests(private.prepare(raw))
        replacements = {"route_id": "route:other", "principal_id": "agent:other", "credential_id": "credential:other",
            "credential_version": 8, "policy_hash": OTHER, "request_digest": OTHER, "operation_digest": OTHER,
            "required_approver_roles": {"$authorityType": "set", "items": ["admin"]},
            "allowed_approver_ids": {"$authorityType": "set", "items": ["oidc:delta", "oidc:gamma"]},
            "approval_threshold": 1,
            "approver_credential_policy": {**copy.deepcopy(raw["approver_credential_policy"]), "maxAssertionAgeSeconds": 29}}
        self.assertEqual(set(replacements), INHERITED_FIELDS - {"require_approver_webauthn"})
        policy_fields = {"required_approver_roles": "requiredRoles", "allowed_approver_ids": "allowedApproverIds",
            "approval_threshold": "threshold", "approver_credential_policy": "credentialPolicy"}
        originals = []
        for name, value in replacements.items():
            changed = copy.deepcopy(raw); changed[name] = copy.deepcopy(value)
            if name in policy_fields:
                policy = jit_fixture.policy()
                policy[policy_fields[name]] = copy.deepcopy(value["items"] if name in (
                    "required_approver_roles", "allowed_approver_ids") else value)
                changed["expected_approver_policy_sha256"] = sha(canonical(policy))
            originals.append((name, changed))
        for name, value in (("method", "POST"), ("pending_ttl_seconds", 299), ("grant_ttl_seconds", 29),
                ("grant_max_uses", 2), ("url", "https://synthetic.invalid/other"),
                ("canonical_request", {"changed": True}), ("redacted_display", {"changed": True})):
            changed = copy.deepcopy(raw); changed["jit_approval_request"][name] = value
            originals.append((name, changed))
        for field, changed_raw in originals:
            with self.subTest(field=field):
                changed = private.derive_native_requests(private.prepare(changed_raw))
                for actual, previous in ((changed.parent_request, baseline.parent_request),
                        (changed.child_request, baseline.child_request)):
                    for key in ("requestDigest", "operationId"):
                        self.assertNotEqual(actual[key], previous[key])
                    self.assertNotEqual(actual["arguments"]["original_arguments_digest"],
                        previous["arguments"]["original_arguments_digest"])
                self.assertEqual(changed.parent_request["arguments"]["jit_approval_request"],
                    changed.child_request["arguments"]["businessIntent"]["arguments"])
        changed = copy.deepcopy(raw); changed["require_approver_webauthn"] = False
        self.refused(lambda: private.derive_native_requests(expected_envelope(changed)))

    def test_native_derivation_refuses_unjoined_originals_before_returning_ids(self):
        envelope = private.prepare(native_raw_arguments())
        changes = []
        for field in PRIVATE_FIELDS:
            changed = copy.deepcopy(envelope)
            changed["privateDocuments"][field] = CANARIES[0] if field == "url" else {"private": CANARIES[1]}
            changes.append(("private:" + field, changed))
        for path, names in (((), ("original_arguments_digest",)), (("jit_approval_request",),
                ("original_arguments_digest", "url_commitment", "canonical_request_digest", "redacted_display_digest"))):
            for field in names:
                changed = copy.deepcopy(envelope); target = changed["arguments"]
                for part in path: target = target[part]
                target[field] = OTHER
                # A grammar-valid public claim is insufficient for derivation.
                private.public_arguments(changed["arguments"])
                changes.append(("hash:" + field, changed))
        for target in ("parent", "child", "both"):
            changed = copy.deepcopy(envelope)
            if target != "child": changed["arguments"]["credential_id"] = "credential:other"
            if target != "parent": changed["arguments"]["jit_approval_request"]["credential_id"] = "credential:other"
            changes.append(("inherited:" + target, changed))
        for field, value in (("reservation_ttl_seconds", 6), ("now_epoch_ms", 1), ("actor_id", "oidc:other"),
                ("operation_context", {"public": "changed"}), ("durable_policy_binding", {"public": "changed"}),
                ("shared_quotas", [{"public": "changed"}])):
            changed = copy.deepcopy(envelope); changed["arguments"][field] = value
            changes.append(("parent:" + field, changed))
        for name, changed in changes:
            with self.subTest(control=name): self.refused(lambda: private.derive_native_requests(changed))

    def test_native_derivation_rejects_profiles_without_changing_old_projection(self):
        raw = raw_arguments()
        for name, selected in (("legacy", raw), ("policy-aware", {**raw, "policy_aware_profile": True,
                "expected_approver_policy_sha256": NATIVE_POLICY_DIGEST})):
            with self.subTest(profile=name):
                envelope = private.prepare(selected)
                self.assertEqual(envelope, expected_envelope(selected))
                public, documents = private.validate_runtime_input(envelope)
                self.assertEqual((public, documents), (envelope["arguments"], envelope["privateDocuments"]))
                self.assertEqual(service._extract_v9_runtime_input(OPERATION, HANDLER, envelope), (public, None, documents))
                self.refused(lambda: private.derive_native_requests(envelope))
        for replacement in ({"native_profile": 1}, {"native_profile": "true"}, {"policy_aware_profile": True},
                {"policy_aware_profile": 0}, {"expected_approver_policy_sha256": None},
                {"expected_approver_policy_sha256": OTHER}):
            # Recompute original hashes independently, so profile rejection is
            # not accidentally covered only by a stale original-hash failure.
            with self.subTest(fields=tuple(replacement)):
                envelope = expected_envelope({**native_raw_arguments(), **replacement})
                self.refused(lambda: private.derive_native_requests(envelope))

    def test_native_derivation_closed_channels_and_sanitized_invalid_inputs(self):
        envelope = private.prepare(native_raw_arguments())
        for path in ((), ("arguments",), ("arguments", "jit_approval_request"), ("privateDocuments",)):
            original = envelope
            for part in path: original = original[part]
            for field in (*original, "unexpected"):
                changed = copy.deepcopy(envelope); target = changed
                for part in path: target = target[part]
                if field == "unexpected": target[field] = CANARIES[0]
                else: del target[field]
                with self.subTest(path=path, field=field): self.refused(lambda: private.derive_native_requests(changed))
        for field, value in (("schema", "serverware.policyAuthorityPrivateReleaseWriterInput/v2"),
                ("schema", "serverware.policyAuthorityControlledWriterInput/v1"),
                ("handler", "reserve_release_authorization"), ("handler", "ensure_jit_approval_request"),
                ("operationManifestDigest", OTHER)):
            self.refused(lambda: private.derive_native_requests({**envelope, field: value}))
        for value in (None, False, [], CANARIES[0], native_raw_arguments(), envelope["arguments"],
                native_request_oracle(OPERATION, envelope["arguments"])):
            self.refused(lambda: private.derive_native_requests(value))
        for path in (("arguments",), ("arguments", "jit_approval_request")):
            for field in (*PRIVATE_FIELDS, "privateDocuments", "businessIntent", "canonical_request_opaque_id"):
                changed = copy.deepcopy(envelope); target = changed
                for part in path: target = target[part]
                target[field] = CANARIES[0]
                self.refused(lambda: private.derive_native_requests(changed))
        for value in (float("nan"), b"private bytes", object(), document(core.MAX_ARGUMENT_DEPTH + 1)):
            changed = copy.deepcopy(envelope); changed["privateDocuments"]["canonical_request"] = {"private": value}
            self.refused(lambda: private.derive_native_requests(changed))
        changed = copy.deepcopy(envelope)
        changed["privateDocuments"]["canonical_request"]["cycle"] = changed["privateDocuments"]["canonical_request"]
        self.refused(lambda: private.derive_native_requests(changed))

    def test_native_requests_own_every_graph_and_never_retain_private_documents(self):
        raw = native_raw_arguments(); envelope = private.prepare(raw)
        original_raw = canonical(raw); original_envelope = canonical(envelope)
        first = private.derive_native_requests(envelope)
        second = private.derive_native_requests(envelope)
        second_bytes = canonical((second.parent_request, second.child_request))
        graphs = (
            first.parent_request["arguments"]["jit_approval_request"]["approver_credential_policy"],
            first.parent_request["arguments"]["businessIntent"]["arguments"]["jit_approval_request"]["approver_credential_policy"],
            first.child_request["arguments"]["approver_credential_policy"],
            first.child_request["arguments"]["businessIntent"]["arguments"]["approver_credential_policy"],
        )
        self.assertEqual(len({id(graph) for graph in graphs}), len(graphs))
        for index, graph in enumerate(graphs):
            graph["origins"].append("https://owned-" + str(index) + ".invalid")
            for other in graphs[index + 1:]: self.assertEqual(other["origins"], ["https://synthetic.invalid"])
        first.parent_request["arguments"]["operation_context"]["public"] = "changed"
        self.assertEqual(first.parent_request["arguments"]["businessIntent"]["arguments"]["operation_context"],
            {"public": "unchanged"})
        self.assertEqual(canonical(raw), original_raw)
        self.assertEqual(canonical(envelope), original_envelope)
        self.assertEqual(canonical((second.parent_request, second.child_request)), second_bytes)
        envelope["arguments"]["operation_context"]["public"] = "changed input"
        envelope["privateDocuments"]["canonical_request"]["literal"]["base64Url"] = "changed private input"
        self.assertEqual(canonical((second.parent_request, second.child_request)), second_bytes)
        self.no_private((second.parent_request, second.child_request))

    def test_native_original_byte_and_depth_bounds_do_not_shift(self):
        raw = native_raw_arguments(); raw["jit_approval_request"]["canonical_request"] = {"padding": ""}
        original = child_original(raw)
        payload_size = sum(len((original[name] or "").encode("utf-8")) for name in (
            "route_id", "method", "url", "principal_id", "credential_id", "policy_hash", "request_digest", "operation_digest"))
        payload_size += sum(len(canonical(original[name])) for name in ("canonical_request", "redacted_display"))
        payload_size += len(canonical(jit_fixture.policy()))
        raw["jit_approval_request"]["canonical_request"]["padding"] = "x" * (65536 - payload_size)
        private.derive_native_requests(private.prepare(raw))
        raw["jit_approval_request"]["canonical_request"]["padding"] += "x"
        self.refused(lambda: private.derive_native_requests(expected_envelope(raw)))
        for field in ("canonical_request", "redacted_display", "operation_context"):
            raw = native_raw_arguments()
            target = raw if field == "operation_context" else raw["jit_approval_request"]
            target[field] = document(core.MAX_ARGUMENT_DEPTH - 1)
            private.derive_native_requests(private.prepare(raw))
            target[field] = document(core.MAX_ARGUMENT_DEPTH)
            self.refused(lambda: private.derive_native_requests(expected_envelope(raw)))

    def test_native_full_v9_envelope_size_is_bounded_separately_from_private_input(self):
        self.assertEqual(contract.MAX_REQUEST_BYTES, 4 * 1024 * 1024)
        raw = native_raw_arguments(); raw["durable_policy_binding"] = {"padding": ""}
        empty_request = native_request_oracle(OPERATION, expected_envelope(raw)["arguments"])
        padding_size = (4 * 1024 * 1024 - len(canonical(empty_request))) // 2
        self.assertGreater(padding_size, 0)
        raw["durable_policy_binding"]["padding"] = "x" * padding_size
        envelope = private.prepare(raw)
        self.assertLess(len(canonical(envelope)), 4 * 1024 * 1024)
        result = private.derive_native_requests(envelope)
        self.assertIn(4 * 1024 * 1024 - len(canonical(result.parent_request)), (0, 1))
        raw["durable_policy_binding"]["padding"] += "x"
        oversized = private.prepare(raw)
        private.validate_runtime_input(oversized)
        self.assertLess(len(canonical(oversized)), 4 * 1024 * 1024)
        self.assertGreater(len(canonical(native_request_oracle(OPERATION, oversized["arguments"]))), 4 * 1024 * 1024)
        self.refused(lambda: private.derive_native_requests(oversized))


if __name__ == "__main__":
    unittest.main(verbosity=2)
