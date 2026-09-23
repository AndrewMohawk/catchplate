#!/usr/bin/env python3
"""Pure provider admission/operation tests, not authority or network integration proof."""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware.policy_bundle import PolicyBundleError, compile_policy_bundle, provider_request_profile


def unavailable_dependency(name: str) -> ModuleType:
    dependency = ModuleType(name)

    def reject_access(attribute: str) -> None:
        raise AssertionError(f"pure admission test accessed {name}.{attribute}")

    dependency.__getattr__ = reject_access
    return dependency


# The real authority registry remains independently blocked. Only pure adapter
# methods are loaded here; any DB/runtime access fails instead of faking success.
SPEC = importlib.util.spec_from_file_location("provider_policy_parity_adapters_unit", ROOT / "serverware/adapters.py")
assert SPEC is not None and SPEC.loader is not None
adapters = importlib.util.module_from_spec(SPEC)
with mock.patch.dict(sys.modules, {
    "serverware.db": unavailable_dependency("serverware.db"),
    "serverware.runtime": unavailable_dependency("serverware.runtime"),
}):
    SPEC.loader.exec_module(adapters)


class HeaderFields:
    """Preserve physical repeated fields, including identical field-name casing."""

    def __init__(self, fields: list[tuple[str, str]]) -> None:
        self.fields = fields

    def __iter__(self):
        return (name for name, _ in self.fields)

    def get_all(self, name: str) -> list[str]:
        return [value for key, value in self.fields if key.lower() == name.lower()]


class ProviderPolicyParityTests(unittest.TestCase):
    PROFILES = (
        ("gmail.v1", None),
        ("x.v2", "recentSearchOnly"),
        ("x.v2", "readOnly"),
        ("x.v2", "controlledWrite"),
        ("npm.registry", None),
    )

    def bundle(self, adapter_type: str, mode: str | None = None) -> dict:
        # These are unsigned examples. Compilation proves schema and semantic
        # admission only; Rust companion coverage signs with a local fixture key.
        bundle = json.loads((ROOT / "policies/credential-limits.examples.json").read_text())
        route = next(item for item in bundle["routes"]
                     if item["adapter"]["type"] == adapter_type
                     and (mode is None or item["adapter"]["config"].get("mode") == mode))
        bundle["routes"] = [route]
        bundle["credentials"] = [item for item in bundle["credentials"]
                                 if item["id"] == route["credentialRef"]]
        bundle["principals"] = [item for item in bundle["principals"]
                                if item["id"] in route["principals"]]
        return bundle

    def compiled_route(self, adapter_type: str, mode: str | None = None):
        return compile_policy_bundle(self.bundle(adapter_type, mode), validate_schema=True).routes[0]

    def flow(self, fields: list[tuple[str, str]], body: bytes = b"{}") -> SimpleNamespace:
        return SimpleNamespace(request=SimpleNamespace(
            headers=HeaderFields(fields), raw_content=body,
            pretty_url="https://example.test/resource",
        ))

    def test_example_profiles_compile_without_reserved_header_entries(self) -> None:
        for adapter_type, mode in self.PROFILES:
            with self.subTest(adapter=adapter_type, mode=mode):
                route = self.compiled_route(adapter_type, mode)
                profile = provider_request_profile(adapter_type, mode)
                self.assertNotIn("content-type", profile["allowedHeaders"])
                self.assertEqual(route.adapter_config["request"]["allowedHeaders"], profile["allowedHeaders"])
                invalid = self.bundle(adapter_type, mode)
                invalid["routes"][0]["adapter"]["config"]["request"]["allowedHeaders"].append("content-type")
                with self.assertRaises(PolicyBundleError):
                    compile_policy_bundle(invalid, validate_schema=True)

    def test_write_profiles_mediate_media_without_opening_other_headers(self) -> None:
        for adapter_type, mode in (("x.v2", "controlledWrite"), ("npm.registry", None)):
            route = self.compiled_route(adapter_type, mode)
            adapter = adapters.get_adapter(adapter_type)
            for content_type in ("application/json", 'Application/JSON; charset="utf-8"'):
                with self.subTest(adapter=adapter_type, content_type=content_type):
                    decision = adapter._validate_provider_request_profile(
                        self.flow([("Content-Type", content_type)]), route)
                    self.assertTrue(decision.allowed, decision)
            cases = (
                ([], "request_content_type_required", 415),
                ([("content-type", "text/plain")], "request_content_type_denied", 415),
                ([("content-type", "application/json;")], "request_content_type_denied", 415),
                ([("content-type", "application/json; charset=utf-8; CHARSET=utf-8")], "request_content_type_denied", 415),
                ([("content-type", "application/json"), ("content-type", "application/json")], "request_content_type_ambiguous", 415),
                ([("Content-Type", "application/json"), ("content-type", "application/json")], "request_content_type_ambiguous", 415),
            )
            for fields, error, status in cases:
                with self.subTest(adapter=adapter_type, fields=fields):
                    decision = adapter._validate_provider_request_profile(self.flow(fields), route)
                    self.assertFalse(decision.allowed, decision)
                    self.assertEqual((decision.payload["error"], decision.status_code), (error, status))
            for name in ("x-unknown", "authorization", "cookie", "x-api-key"):
                decision = adapter._validate_provider_request_profile(
                    self.flow([("content-type", "application/json"), (name, "local-unit")]), route)
                self.assertFalse(decision.allowed, decision)
                self.assertEqual(decision.payload["error"], "request_header_not_allowed")
            oversized = b"x" * (route.adapter_config["request"]["maxBodyBytes"] + 1)
            decision = adapter._validate_provider_request_profile(
                self.flow([("content-type", "application/json")], oversized), route)
            self.assertFalse(decision.allowed, decision)
            self.assertEqual((decision.payload["error"], decision.status_code), ("request_body_too_large", 413))

    def test_bodyless_profiles_keep_absence_and_media_contract(self) -> None:
        for adapter_type, mode in self.PROFILES[:3]:
            route = self.compiled_route(adapter_type, mode)
            adapter = adapters.get_adapter(adapter_type)
            self.assertTrue(adapter._validate_provider_request_profile(self.flow([], b""), route).allowed)
            for body, error in ((b"", "request_content_type_denied"), (b"x", "request_body_not_allowed")):
                decision = adapter._validate_provider_request_profile(
                    self.flow([("content-type", "application/json")], body), route)
                self.assertFalse(decision.allowed, decision)
                self.assertEqual(decision.payload["error"], error)

    def test_gmail_operation_fields_match_list_and_get_catalogs(self) -> None:
        route = self.compiled_route("gmail.v1")
        adapter = adapters.get_adapter("gmail.v1")
        self.assertEqual(adapter.operation_fields(None, route, {"user": "me"}),
                         {"operation": "gmail.messages.list", "gmailUser": "me"})
        self.assertEqual(adapter.operation_fields(None, route, {"user": "me", "message_id": "message-1"}),
                         {"operation": "gmail.message.get", "gmailUser": "me", "messageId": "message-1"})

    def test_capture_union_is_distinct_from_operation_source_intersection(self) -> None:
        base = self.bundle("gmail.v1")
        request = base["routes"][0]["adapter"]["config"]["request"]
        self.assertEqual(request["valueRules"], [{
            "source": "pathParam", "name": "user", "predicate": {"kind": "equals", "value": "me"},
        }])
        for capture in ("gmailUser", "messageId", "operation", "providerAccount"):
            invalid = copy.deepcopy(base)
            invalid["routes"][0]["adapter"]["config"]["request"]["valueRules"][0]["capture"] = capture
            with self.subTest(capture=capture), self.assertRaisesRegex(PolicyBundleError, "collides with another operation field"):
                compile_policy_bundle(invalid, validate_schema=True)
        fresh = copy.deepcopy(base)
        fresh["routes"][0]["adapter"]["config"]["request"]["valueRules"][0]["capture"] = "approvedUser"
        compile_policy_bundle(fresh, validate_schema=True)
        for name in ("gmailUser", "messageId"):
            candidate = copy.deepcopy(base)
            candidate["routes"][0]["adapter"]["config"]["request"]["valueRules"] = [{
                "source": "operationField", "name": name,
                "predicate": {"kind": "stringLength", "minLength": 1, "maxLength": 128},
            }]
            if name == "gmailUser":
                compile_policy_bundle(candidate, validate_schema=True)
            else:
                with self.assertRaisesRegex(PolicyBundleError, "operationField messageId is not emitted"):
                    compile_policy_bundle(candidate, validate_schema=True)


if __name__ == "__main__":
    unittest.main()
