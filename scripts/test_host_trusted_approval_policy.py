#!/usr/bin/env python3
"""Focused offline policy/schema checks; never approvals, custody or network.

Reuse existing provider document factories and annotation-only HTTP fixtures;
their suites are not run. The fixture refuses sockets and SQLite connections.
"""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import test_npm_metadata as fixture
import test_alchemy_rpc_read as alchemy
import test_buffered_passthrough_response as generic
import test_github_issues as github
import test_gmail_read_bundle as gmail
import test_npm_install as install
import test_npm_publish as publish
import test_x_app_read as x_read
import test_x_post as x_post
from jsonschema import Draft202012Validator
from serverware import host_trusted_approval_policy as approval, policy_bundle as pb, policy_engine as engine

MARKER = {"type": "hostTrustedApproval", "schema": "serverware.hostTrustedApprovalPolicy/v1",
    "pendingTtlSeconds": 300, "approvalTtlSeconds": 60}
PROVIDERS = {
    "generic": generic.bundle, "github": github.document, "gmail": gmail.document,
    "alchemy": alchemy.document, "x-read": x_read.document, "x-post": x_post.document,
    "npm-metadata": fixture.document, "npm-publish": publish.document,
    "npm-window": lambda: publish.document(window={"start": "09:00", "end": "17:00"}),
    **{"npm-install-" + mode: lambda mode=mode: install.document(mode) for mode in install.npm.MODES},
}


def with_approval(factory=generic.bundle):
    value = factory()
    value["routes"][0]["constraints"].append(deepcopy(MARKER))
    return value


def compile_policy(value):
    return pb.compile_policy_bundle(value, validate_schema=True, enforce_signed_policy_constraints=True)


class HostTrustedApprovalPolicyTests(unittest.TestCase):
    def test_provider_contracts_retain_all_original_constraints(self):
        for name, factory in PROVIDERS.items():
            with self.subTest(provider=name):
                original = factory()
                baseline = compile_policy(original)
                value = with_approval(factory)
                admitted = compile_policy(value)
                self.assertNotEqual(baseline.hash, admitted.hash)
                self.assertEqual(admitted.routes[0].constraints[-1], MARKER)
                self.assertEqual(approval.provider_constraints(admitted.routes[0].constraints),
                    baseline.routes[0].constraints)
                self.assertEqual(compile_policy(original).hash, baseline.hash)
                # Removing the envelope is still refused with the marker present.
                value["routes"][0]["constraints"] = [deepcopy(MARKER)]
                with self.assertRaises(pb.PolicyBundleError):
                    compile_policy(value)

    def test_marker_schema_and_semantic_bounds_are_closed(self):
        schema = json.loads((ROOT / "schemas/policy-bundle.v1.schema.json").read_text())
        validator = Draft202012Validator(schema["$defs"]["hostTrustedApproval"])
        for pending, approved in ((30, 1), (300, 60), (3600, 300)):
            marker = {**MARKER, "pendingTtlSeconds": pending, "approvalTtlSeconds": approved}
            self.assertTrue(validator.is_valid(marker))
            self.assertEqual(pb._validate_constraints("fixture", [marker]), (marker,))
        bad = [{**MARKER, name: value} for name, values in {
            "pendingTtlSeconds": (29, 3601, True, 30.5, "300"),
            "approvalTtlSeconds": (0, 301, False, 1.5, "60"),
            "schema": ("serverware.hostTrustedApprovalPolicy/v2",),
            "id": ("not-allowed",), "phase": ("request",), "extra": (True,),
        }.items() for value in values]
        bad += [{key: value for key, value in MARKER.items() if key != missing} for missing in MARKER]
        for marker in bad:
            with self.subTest(marker=marker):
                self.assertFalse(validator.is_valid(marker))
                with self.assertRaises((pb.PolicyBundleError, ValueError)):
                    pb._validate_constraints("fixture", [marker])
        for duplicate in (deepcopy(MARKER), {**MARKER, "approvalTtlSeconds": 61}):
            value = with_approval()
            value["routes"][0]["constraints"].append(duplicate)
            with self.assertRaises(pb.PolicyBundleError):
                compile_policy(value)
            with self.assertRaises(ValueError):
                approval.provider_constraints([MARKER, duplicate])

    def test_stronger_authority_and_unbound_routes_are_not_downgraded(self):
        options = dict(adapter="generic.rest", credential_ref="fixture", jit={}, constraints=[MARKER])
        for changes in ({"credential_ref": None}, {"jit": {"required": True}},
                {"response_observation": True}, *({"adapter": name} for name in ("gmail.v1", "x.v2", "npm.registry")),
                *({"constraints": [MARKER, {"type": name}]} for name in approval.DURABLE_CONSTRAINTS),
                {"constraints": [MARKER, {"type": "rateLimit", "store": "shared"}]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                approval.validate_route(**{**options, **changes})
        approval.validate_route(**{**options, "constraints": [MARKER,
            {"type": "rateLimit", "store": "local"}]})
        for change in (lambda route: route.pop("credentialRef"),
                lambda route: route.update(responseObservation={"version": "v1"}),
                lambda route: route["constraints"].append({"id": "quota", "type": "rateLimit",
                    "max": 10, "windowSeconds": 60, "store": "shared", "key": {"scope": ["principal"]}})):
            value = with_approval()
            change(value["routes"][0])
            with self.assertRaises(pb.PolicyBundleError):
                compile_policy(value)
        # Existing X quota remains valid, but cannot silently become host trusted.
        compile_policy(x_post.document(True))
        with self.assertRaises(pb.PolicyBundleError):
            compile_policy(with_approval(lambda: x_post.document(True)))

    def test_provider_cardinality_is_not_widened(self):
        for marker in (False, True):
            value = publish.document(window={"start": "09:00", "end": "17:00"})
            duplicate = deepcopy(value["routes"][0]["constraints"][-1])
            duplicate["id"] = "second.window"
            value["routes"][0]["constraints"].append(duplicate)
            if marker:
                value["routes"][0]["constraints"].append(deepcopy(MARKER))
            with self.assertRaises(pb.PolicyBundleError):
                compile_policy(value)
        value = with_approval(gmail.document)
        value["routes"][0]["constraints"][0]["statusCodes"].append(418)
        with self.assertRaises(pb.PolicyBundleError):
            compile_policy(value)

    def test_python_forwarding_denies_before_credentials_or_leases(self):
        snapshot = compile_policy(with_approval(fixture.document))
        flow = fixture.request(headers=[(b"X-Serverware-Agent", b"fixture")])
        forbidden = AssertionError("unsupported Python approval path touched external authority")
        with patch.object(engine, "get_policy_snapshot", return_value=snapshot), \
                patch.object(engine.db, "get_credential", side_effect=forbidden), \
                patch.object(engine.runtime, "atomic_release_authorization_enabled", side_effect=forbidden), \
                patch.object(engine.runtime, "log_request", side_effect=forbidden):
            result = engine.evaluate_request(flow)
        self.assertFalse(result.decision.allowed)
        self.assertEqual(result.decision.status_code, 503)
        self.assertEqual(result.decision.payload["error"], "python_host_trusted_approval_unsupported")


if __name__ == "__main__":
    unittest.main()
