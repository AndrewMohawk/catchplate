#!/usr/bin/env python3
"""Focused signed-route contract tests; no credential forwarding or live services.

Real compiler/schema/prototype refusal functions are used. These unsigned
fixtures do not prove Rust matching, credential release, signatures or deployment.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate.policy_bundle import (
    PolicyBundleError, _fresh_policy_snapshot, compile_policy_bundle,
    policy_hash, validate_credential_header_replacement, validate_policy_schema,
)
from catchplate.policy_route_authority import prepare_unsigned


def descriptor(value="Bearer caller-chosen-dummy"):
    return {"mode": "replaceExact", "expectedValue": value}


def bundle(*, replacement=True, custom=False):
    injection = {"type": "header", "name": "X-Api-Key"} if custom else {"type": "bearer"}
    route = {"id": "route.header-fixture", "principals": ["agent:fixture"],
        "credentialRef": "credential:fixture",
        "match": {"scheme": "https", "host": "api.example.com", "port": 443,
            "methods": ["GET"], "paths": ["/fixture"]},
        "adapter": {"type": "generic.rest", "config": {
            "credentialMode": "required", "credentialBinding": {"credentialType": "static",
                "provider": "fixture", "subjects": ["subject:fixture"],
                "secretClass": "customHeader" if custom else "bearerToken"},
            "request": {"allowedHeaders": [], "allowedQueryKeys": [], "allowedMediaTypes": [],
                "bodyMode": "none", "maxBodyBytes": 0, "valueRules": [],
                "operation": {"name": "fixture.read"}},
            "response": {"mode": "json", "maxBodyBytes": 1024,
                "contentTypes": ["application/json"], "allowedFields": ["safe"], "allowedHeaders": [],
                "error": {"mode": "json", "maxBodyBytes": 512, "allowedFields": ["error"],
                    "allowedHeaders": [], "onInvalid": "block"}}}},
        "constraints": [{"id": "fixture.response", "type": "responseEnvelope", "phase": "response",
            "statusCodes": [200], "bodyPresence": "required", "contentTypes": ["application/json"],
            "allowedResponseHeaderNames": [], "responseHeaderRules": []}]}
    if replacement:
        route["credentialHeader"] = descriptor("custom-dummy" if custom else "Bearer caller-chosen-dummy")
    return {"apiVersion": "catchplate.policy/v1", "kind": "PolicyBundle",
        "metadata": {"id": "header-fixture", "sequence": 1, "rollbackEpoch": 1},
        "defaults": {"action": "deny", "failMode": "closed", "unknownHosts": "block",
            "unknownPaths": "block", "validationFailure": "block"},
        "principals": [{"id": "agent:fixture", "sourceCidrs": ["127.0.0.1/32"],
            "requiredHeaders": {"X-Catchplate-Agent": "fixture"}}],
        "credentials": [{"id": "credential:fixture", "credentialType": "static",
            "provider": "fixture", "providerSubject": "subject:fixture", "injection": injection}],
        "routes": [route]}


def compile_fixture(document):
    return compile_policy_bundle(document, validate_schema=True)


class CredentialHeaderReplacementTests(unittest.TestCase):
    def test_valid_caller_chosen_ascii_is_exact_and_route_scoped(self):
        for custom in (False, True):
            for value in ("x", "Bearer dummy", "x  y", "!~", "x" * 1024):
                with self.subTest(custom=custom, length=len(value)):
                    document = bundle(custom=custom)
                    document["routes"][0]["credentialHeader"] = descriptor(value)
                    compiled = compile_fixture(document)
                    self.assertEqual(compiled.routes[0].credential_header, descriptor(value))
                    self.assertNotIn("existingHeader", compiled.credentials["credential:fixture"].injection)

    def test_invalid_values_and_closed_shape_fail_schema_and_semantics(self):
        invalid = (None, {}, [], "replaceExact", {"mode": "replaceExact"},
            {"expectedValue": "x"}, {"mode": "optional", "expectedValue": "x"},
            {**descriptor(), "header": "X-Other"},
            *(descriptor(value) for value in (None, True, 7, "", " " , " x", "x ", "x\t",
                "x\n", "x\r", "x\x00", "x\x7f", "caf\u00e9", "x" * 1025)))
        for value in invalid:
            with self.subTest(value=value):
                document = bundle()
                document["routes"][0]["credentialHeader"] = value
                with self.assertRaises(PolicyBundleError):
                    validate_policy_schema(document)
                with self.assertRaises(PolicyBundleError):
                    validate_credential_header_replacement(value, {"type": "bearer"})
                with self.assertRaises(PolicyBundleError):
                    compile_policy_bundle(document, validate_schema=False)

    def test_credential_reference_is_required_and_global_option_is_rejected(self):
        document = bundle()
        del document["routes"][0]["credentialRef"]
        for validate_schema in (False, True):
            with self.assertRaises(PolicyBundleError):
                compile_policy_bundle(document, validate_schema=validate_schema)
        for custom in (False, True):
            document = bundle(replacement=False, custom=custom)
            document["credentials"][0]["injection"]["existingHeader"] = descriptor()
            with self.assertRaises(PolicyBundleError):
                compile_fixture(document)
            with self.assertRaises(PolicyBundleError):
                compile_policy_bundle(document, validate_schema=False)

    def test_only_bearer_and_custom_header_targets_are_eligible(self):
        for injection, secret_class in (
            ({"type": "basic", "username": "fixture"}, "basicPassword"),
            ({"type": "cookie", "name": "session"}, "cookie"),
            ({"type": "query", "name": "token"}, "queryToken"),
        ):
            with self.subTest(injection=injection):
                document = bundle(replacement=False)
                document["credentials"][0]["injection"] = injection
                document["routes"][0]["adapter"]["config"]["credentialBinding"]["secretClass"] = secret_class
                compile_fixture(document)
                document["routes"][0]["credentialHeader"] = descriptor()
                with self.assertRaises(PolicyBundleError):
                    compile_fixture(document)
        with self.assertRaises(PolicyBundleError):
            validate_credential_header_replacement(descriptor(), {})

    def test_reserved_targets_and_underscore_aliases_are_rejected(self):
        reserved = ("Cookie", "Host", "Content-Type", "Content-Length", "Content-Encoding",
            "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
            "Proxy-Connection", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
            "X-Catchplate-Agent", "X-Catchplate-Private")
        for name in reserved:
            for alias in (name, name.lower().replace("-", "_")):
                for kind in ("bearer", "header"):
                    injection = {"type": kind, "header" if kind == "bearer" else "name": alias}
                    with self.subTest(injection=injection), self.assertRaises(PolicyBundleError):
                        validate_credential_header_replacement(descriptor(), injection)
        with self.assertRaises(PolicyBundleError):
            validate_credential_header_replacement(descriptor(), {"type": "header", "name": "Authorization"})

    def test_principal_identity_aliases_and_wildcards_fail_closed(self):
        for wildcard in (False, True):
            document = bundle(replacement=False, custom=True)
            document["credentials"][0]["injection"]["name"] = "X_API_KEY"
            document["principals"][0]["requiredHeaders"]["X-Api-Key"] = "identity-dummy"
            if wildcard:
                document["routes"][0]["principals"] = ["*"]
            compile_fixture(document)
            document["routes"][0]["credentialHeader"] = descriptor()
            with self.assertRaisesRegex(PolicyBundleError, "principal identity"):
                compile_fixture(document)

    def test_provider_header_alias_collision_is_not_a_forwarding_allowance(self):
        document = bundle(replacement=False, custom=True)
        document["routes"][0]["adapter"]["config"]["request"]["allowedHeaders"] = ["x_api_key"]
        compile_fixture(document)
        document["routes"][0]["credentialHeader"] = descriptor()
        with self.assertRaisesRegex(PolicyBundleError, "collide"):
            compile_fixture(document)

    def test_shared_credential_supports_distinct_route_input_contracts(self):
        document = bundle()
        insertion = copy.deepcopy(document["routes"][0])
        insertion["id"] = "route.insertion"
        insertion["match"]["paths"] = ["/insertion"]
        del insertion["credentialHeader"]
        document["routes"].append(insertion)
        compiled = compile_fixture(document)
        self.assertEqual(len(compiled.credentials), 1)
        routes = {route.id: route for route in compiled.routes}
        self.assertEqual(routes["route.header-fixture"].credential_header, descriptor())
        self.assertIsNone(routes["route.insertion"].credential_header)

    def test_snapshot_copy_and_hash_bind_descriptor_without_default_mutation(self):
        document = bundle()
        compiled = compile_fixture(document)
        document["routes"][0]["credentialHeader"]["expectedValue"] = "changed"
        self.assertEqual(compiled.routes[0].credential_header, descriptor())
        with self.assertRaises(TypeError):
            compiled.routes[0].credential_header["expectedValue"] = "changed"
        copied = _fresh_policy_snapshot(compiled)
        self.assertEqual(copied.routes[0].credential_header, descriptor())
        self.assertEqual(copied.hash, compiled.hash)
        self.assertNotEqual(compile_fixture(document).hash, compiled.hash)
        old = bundle(replacement=False)
        old_compiled = compile_fixture(old)
        self.assertIsNone(old_compiled.routes[0].credential_header)
        self.assertIsNone(_fresh_policy_snapshot(old_compiled).routes[0].credential_header)
        self.assertNotIn("credentialHeader", old_compiled.raw["routes"][0])
        self.assertEqual(old_compiled.hash, policy_hash(old))

    def test_v2_route_authority_pins_include_the_new_route_descriptor(self):
        document = bundle()
        document["apiVersion"] = "catchplate.policy/v2"
        declarations = [{"routeId": "route.header-fixture", "operationName": "fixture.read", "operation": "read"}]
        signed_shape = prepare_unsigned(document, declarations)
        compiled = compile_fixture(signed_shape)
        changed = copy.deepcopy(signed_shape)
        changed["routes"][0]["credentialHeader"]["expectedValue"] = "different"
        with self.assertRaises(PolicyBundleError):
            compile_fixture(changed)
        changed = prepare_unsigned(changed, declarations)
        self.assertNotEqual(compile_fixture(changed).compiled_route_authority, compiled.compiled_route_authority)

    def test_python_prototype_refuses_new_descriptor_without_transport_flag(self):
        from catchplate import policy_engine
        route = compile_fixture(bundle()).routes[0]
        for metadata in ({}, {policy_engine.LEGACY_MITM_TRANSPORT_METADATA_KEY: True}):
            denied = policy_engine._legacy_mitm_route_admission(SimpleNamespace(metadata=metadata), route)
            self.assertFalse(denied.allowed)
            self.assertEqual(denied.payload, {"error": "python_credential_header_replacement_unsupported"})
        old = compile_fixture(bundle(replacement=False)).routes[0]
        self.assertIsNone(policy_engine._legacy_mitm_route_admission(SimpleNamespace(metadata={}), old))
        denied = policy_engine._legacy_mitm_route_admission(
            SimpleNamespace(metadata={policy_engine.LEGACY_MITM_TRANSPORT_METADATA_KEY: True}), old)
        self.assertEqual(denied.payload, {"error": "legacy_mitm_credential_transport_denied"})


if __name__ == "__main__":
    unittest.main()
