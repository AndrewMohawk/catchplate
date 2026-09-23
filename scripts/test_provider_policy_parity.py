#!/usr/bin/env python3
"""Pure provider admission/operation tests, not authority or network integration proof."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock
from urllib.parse import parse_qsl


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware.policy_bundle import (
    PolicyBundleError,
    adapter_operation_query_fields,
    compile_policy_bundle,
    demo_policy_bundle,
    provider_request_profile,
    strict_json_loads,
    valid_traversal_query_name,
    valid_traversal_request_field,
    validate_raw_absolute_target,
)


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

CONSTRAINT_SPEC = importlib.util.spec_from_file_location(
    "provider_policy_parity_constraints_unit", ROOT / "serverware/constraints.py")
assert CONSTRAINT_SPEC is not None and CONSTRAINT_SPEC.loader is not None
constraints = importlib.util.module_from_spec(CONSTRAINT_SPEC)
with mock.patch.dict(sys.modules, {
    CONSTRAINT_SPEC.name: constraints,
    "serverware.db": unavailable_dependency("serverware.db"),
}):
    CONSTRAINT_SPEC.loader.exec_module(constraints)

ENGINE_SPEC = importlib.util.spec_from_file_location(
    "provider_policy_parity_policy_engine_unit", ROOT / "serverware/policy_engine.py")
assert ENGINE_SPEC is not None and ENGINE_SPEC.loader is not None
policy_engine = importlib.util.module_from_spec(ENGINE_SPEC)
with mock.patch.dict(sys.modules, {
    ENGINE_SPEC.name: policy_engine,
    "serverware.adapters": adapters,
    "serverware.constraints": constraints,
    "serverware.db": unavailable_dependency("serverware.db"),
    "serverware.runtime": unavailable_dependency("serverware.runtime"),
}):
    ENGINE_SPEC.loader.exec_module(policy_engine)


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

    def traversal_bundle(self) -> dict:
        bundle = json.loads((ROOT / "policies/credential-limits.examples.json").read_text())
        route = next(item for item in bundle["routes"]
                     if item["id"] == "example.google_calendar.events.last_30_days")
        bundle["routes"] = [route]
        bundle["credentials"] = [item for item in bundle["credentials"]
                                 if item["id"] == route["credentialRef"]]
        bundle["principals"] = [item for item in bundle["principals"]
                                if item["id"] in route["principals"]]
        route["id"] = "route.traversal-parity"
        route["match"]["paths"] = ["/resource"]
        request = route["adapter"]["config"]["request"]
        request.update(allowedQueryKeys=["page[token]", "$.xgafv", "tweet.fields"],
                       allowedHeaders=["x-page!token"], valueRules=[],
                       operation={"name": "generic.write"})
        route["constraints"] = [item for item in route["constraints"]
                                if item["type"] in {"traversalBudget", "responseEnvelope"}]
        for item in route["constraints"]:
            item["operations"] = ["generic.write"]
            if item["type"] == "traversalBudget":
                item["id"] = "literal-selector-traversal"
                item["traversal"]["cursor"]["requestField"] = "page[token]"
                item["traversal"]["lineage"]["queryFields"] = ["$.xgafv", "tweet.fields"]
        return bundle

    def traversal_claim(self, route, *, query=None, cursors=None) -> dict:
        # Real shared claim producer, with no DB, authority, or provider access.
        claims = constraints.traversal_budget_claims(
            route, principal_id="agent:fixture", credential_ref="credential:fixture",
            credential_version=7, policy_hash="sha256:" + "0" * 64,
            operation_fields={"operation": "generic.write"},
            canonical_query_fields={"$.xgafv": "1", "tweet.fields": "id,text"}
                if query is None else query,
            request_cursor_values={} if cursors is None else cursors,
        )
        self.assertEqual(len(claims), 1)
        return claims[0]

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
            # The operation discriminator is reserved before adapter-emitted
            # field collision analysis. Keep each exact denial guard visible.
            expected = (
                "capture is invalid, reserved, or duplicated"
                if capture == "operation"
                else "collides with another operation field"
            )
            with self.subTest(capture=capture), self.assertRaisesRegex(PolicyBundleError, expected):
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

    def test_traversal_literal_selectors_compile_in_examples_and_generated_gmail(self) -> None:
        generated = demo_policy_bundle()
        gmail = next(route for route in generated["routes"] if route["adapter"]["type"] == "gmail.v1")
        generated["routes"] = [gmail]
        generated["credentials"] = [item for item in generated["credentials"]
                                    if item["id"] == gmail["credentialRef"]]
        generated["principals"] = [item for item in generated["principals"]
                                   if item["id"] in gmail["principals"]]
        for bundle in (generated, self.bundle("gmail.v1"), self.bundle("x.v2", "recentSearchOnly"),
                       self.traversal_bundle()):
            for schema in (True, False):
                with self.subTest(route=bundle["routes"][0]["id"], schema=schema):
                    route = compile_policy_bundle(bundle, validate_schema=schema).routes[0]
                    traversal = next(item["traversal"] for item in route.constraints
                                     if item["type"] == "traversalBudget")
                    fields = traversal["lineage"]["queryFields"]
                    self.assertTrue("$.xgafv" in fields or "tweet.fields" in fields)

    def test_traversal_selector_types_byte_bounds_and_header_tokens(self) -> None:
        for name in ("$.xgafv", "tweet.fields", "page[token]", "é" * 128):
            self.assertTrue(valid_traversal_query_name(name), repr(name))
            self.assertTrue(valid_traversal_request_field("query", name), repr(name))
        for name in ("", "x\x00", "x\x1f", "x\x7f", "x\x85", "é" * 129, "\ud800", None):
            self.assertFalse(valid_traversal_query_name(name), repr(name))
        self.assertTrue(valid_traversal_request_field("header", "x-page!token"))
        for name in ("X-page-token", "x page", "page[token]", "é", "x:page"):
            self.assertFalse(valid_traversal_request_field("header", name), repr(name))
        self.assertFalse(valid_traversal_request_field("jsonBody", "pageToken"))
        for name in ("é" * 128, "é" * 129, "x\x85", ""):
            bundle = self.traversal_bundle()
            route = bundle["routes"][0]
            route["adapter"]["config"]["request"]["allowedQueryKeys"][1] = name
            next(item for item in route["constraints"] if item["type"] == "traversalBudget")[
                "traversal"]["lineage"]["queryFields"][0] = name
            for schema in (True, False):
                with self.subTest(name=repr(name), schema=schema):
                    if name == "é" * 128:
                        compile_policy_bundle(bundle, validate_schema=schema)
                    else:
                        with self.assertRaises(PolicyBundleError):
                            compile_policy_bundle(bundle, validate_schema=schema)

    def test_traversal_unicode_scalar_compiler_boundary(self) -> None:
        scalar = strict_json_loads(r'"\ud83d\ude80"')
        self.assertEqual(scalar, "\U0001f680")
        for schema in (True, False):
            compile_policy_bundle(self.traversal_bundle(), validate_schema=schema)
        cases = (
            (scalar * 63 + "aaa", 255, True),
            (scalar * 64, 256, True),
            (scalar * 64 + "a", 257, False),
            (scalar * 65, 260, False),
            (strict_json_loads(r'"\ud800"'), None, False),
            (strict_json_loads(r'"\udc00"'), None, False),
        )
        for name, byte_count, accepted in cases:
            if byte_count is not None:
                self.assertEqual(len(name.encode("utf-8")), byte_count)
            self.assertEqual(valid_traversal_query_name(name), accepted)
            for source in ("cursor", "lineage"):
                bundle = self.traversal_bundle()
                route = bundle["routes"][0]
                traversal = next(item["traversal"] for item in route["constraints"]
                                 if item["type"] == "traversalBudget")
                if source == "cursor":
                    route["adapter"]["config"]["request"]["allowedQueryKeys"][0] = name
                    traversal["cursor"]["requestField"] = name
                else:
                    route["adapter"]["config"]["request"]["allowedQueryKeys"][1] = name
                    traversal["lineage"]["queryFields"][0] = name
                for schema in (True, False):
                    with self.subTest(name=repr(name), source=source, schema=schema):
                        if accepted:
                            compiled = compile_policy_bundle(bundle, validate_schema=schema).routes[0]
                            actual = next(item["traversal"] for item in compiled.constraints
                                          if item["type"] == "traversalBudget")
                            self.assertEqual(actual["cursor"]["requestField"] if source == "cursor"
                                             else actual["lineage"]["queryFields"][0], name)
                        else:
                            # Python JSON can retain lone surrogate strings.
                            # Actual semantic admission, with schema on or off,
                            # must reject them; schema-only rejection is not the oracle.
                            with self.assertRaisesRegex(PolicyBundleError, "invalid closed traversal contract"):
                                compile_policy_bundle(bundle, validate_schema=schema)

    def test_traversal_adapter_catalog_and_selector_domains_stay_closed(self) -> None:
        base = self.traversal_bundle()
        for source, name, accepted in (("header", "x-page!token", True),
                                       ("header", "x-missing", False),
                                       ("header", "X-page!token", False),
                                       ("query", "unknown", False),
                                       ("jsonBody", "pageToken", False)):
            candidate = copy.deepcopy(base)
            traversal = next(item["traversal"] for item in candidate["routes"][0]["constraints"]
                             if item["type"] == "traversalBudget")
            traversal["cursor"].update(requestSource=source, requestField=name)
            if source == "header":
                traversal["lineage"]["queryFields"].append("page[token]")
            for schema in (True, False):
                with self.subTest(source=source, name=name, schema=schema):
                    if accepted:
                        compile_policy_bundle(candidate, validate_schema=schema)
                    else:
                        with self.assertRaises(PolicyBundleError):
                            compile_policy_bundle(candidate, validate_schema=schema)
        for section, field in (("cursor", "responseField"), ("accounting", "recordCountField")):
            candidate = copy.deepcopy(base)
            traversal = next(item["traversal"] for item in candidate["routes"][0]["constraints"]
                             if item["type"] == "traversalBudget")
            traversal[section][field] = "$.xgafv"
            for schema in (True, False):
                with self.subTest(section=section, schema=schema), self.assertRaises(PolicyBundleError):
                    compile_policy_bundle(candidate, validate_schema=schema)

    def test_traversal_cursor_must_belong_to_the_exact_operation_catalog(self) -> None:
        bundle = self.bundle("gmail.v1")
        route = compile_policy_bundle(bundle, validate_schema=True).routes[0]
        flow = SimpleNamespace(request=SimpleNamespace(
            pretty_url="https://gmail.googleapis.com/gmail/v1/users/me/messages?%24.xgafv=1&pageToken=cursor-1"))
        arguments = dict(snapshot=SimpleNamespace(hash="sha256:" + "0" * 64),
                         principal=SimpleNamespace(id="agent:fixture"), credential_version=7)
        positive = policy_engine._durable_policy_claims(
            flow, route=route, operation_fields={"operation": "gmail.messages.list"}, **arguments)
        self.assertEqual(len(positive), 1)
        self.assertEqual(positive[0]["request_cursor_digest"], "sha256:" + hashlib.sha256(b"cursor-1").hexdigest())
        get_fields = adapter_operation_query_fields("gmail.v1", route.adapter_config, "gmail.message.get")
        self.assertIsNotNone(get_fields)
        self.assertNotIn("pageToken", get_fields)
        constraint = next(item for item in bundle["routes"][0]["constraints"] if item["type"] == "traversalBudget")
        constraint["operations"] = ["gmail.message.get"]
        constraint["traversal"]["lineage"]["queryFields"] = sorted(get_fields)
        for schema in (True, False):
            with self.subTest(schema=schema), self.assertRaisesRegex(
                    PolicyBundleError, "pageToken is not admitted for operation gmail.message.get"):
                compile_policy_bundle(bundle, validate_schema=schema)
        # Exercise the real producer after an explicit admission bypass. Its
        # independent operation catalog must reject the list-only cursor too.
        malformed = SimpleNamespace(id=route.id, credential_ref=route.credential_ref,
                                    adapter_type=route.adapter_type, adapter_config=route.adapter_config,
                                    constraints=(constraint,))
        with self.assertRaisesRegex(ValueError, "cursor query is not admitted for operation gmail.message.get"):
            policy_engine._durable_policy_claims(
                flow, route=malformed, operation_fields={"operation": "gmail.message.get"}, **arguments)

    def test_traversal_wire_decoding_preserves_literal_names(self) -> None:
        target = "https://example.test/resource?%24.xgafv=1&page%5Btoken%5D=cursor-1&tweet.fields=id%2Ctext"
        parsed = validate_raw_absolute_target(target)
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True, errors="strict")
        self.assertEqual(pairs, [("$.xgafv", "1"), ("page[token]", "cursor-1"), ("tweet.fields", "id,text")])
        for query in ("$.xgafv=1", "%2524.xgafv=1", "tweet.fields=id+text", "x=%FF", "x=%", "x=%2ctext"):
            with self.subTest(query=query), self.assertRaises(ValueError):
                validate_raw_absolute_target("https://example.test/resource?" + query)

    def test_traversal_shared_claim_literal_digest_matches_rust_vector(self) -> None:
        route = compile_policy_bundle(self.traversal_bundle(), validate_schema=True).routes[0]
        claim = self.traversal_claim(route, cursors={"page[token]": "cursor-1"})
        # Identical explicit canonical bytes in Rust's literal-selector test.
        material = ('{"credential":"credential:fixture","credentialVersion":7,'
                    '"operation":"generic.write","policyHash":"sha256:' + "0" * 64 + '",'
                    '"principal":"agent:fixture","query":{"$.xgafv":"1","tweet.fields":"id,text"},'
                    '"route":"route.traversal-parity"}')
        self.assertEqual(claim["lineage_digest"], "sha256:" + hashlib.sha256(material.encode()).hexdigest())
        self.assertEqual(claim["request_cursor_digest"], "sha256:" + hashlib.sha256(b"cursor-1").hexdigest())
        self.assertEqual(claim["request_cursor_field"], "page[token]")
        changed = self.traversal_claim(route, query={"$.xgafv": "2", "tweet.fields": "id,text"})
        absent = self.traversal_claim(route, query={"$.xgafv": None, "tweet.fields": "id,text"})
        self.assertNotEqual(claim["lineage_digest"], changed["lineage_digest"])
        self.assertNotEqual(claim["lineage_digest"], absent["lineage_digest"])
        self.assertIsNone(absent["request_cursor_digest"])
        for query in ({"$.xgafv": "1"}, {"$.xgafv": "1", "tweet.fields": "id,text", "other": "x"}):
            with self.assertRaisesRegex(ValueError, "traversal lineage contract is invalid"):
                self.traversal_claim(route, query=query)
        for cursor, error in (({"page[token]": ""}, "request cursor is invalid"),
                              ({"page[token]": "é" * 2049}, "request cursor is invalid"),
                              ({"unknown": "x"}, "unbound cursor")):
            with self.assertRaisesRegex(ValueError, error):
                self.traversal_claim(route, cursors=cursor)
        for source, field in (("jsonBody", "pageToken"), ("header", "X-page-token")):
            malformed = copy.deepcopy(list(route.constraints))
            next(item for item in malformed if item["type"] == "traversalBudget")[
                "traversal"]["cursor"].update(requestSource=source, requestField=field)
            with self.assertRaisesRegex(ValueError, "traversal cursor contract is invalid"):
                self.traversal_claim(SimpleNamespace(id=route.id, constraints=malformed))
        for field in ("é" * 129, "x\x85", "", "page[token]"):
            malformed = copy.deepcopy(list(route.constraints))
            next(item for item in malformed if item["type"] == "traversalBudget")[
                "traversal"]["lineage"]["queryFields"][0] = field
            with self.subTest(field=repr(field)), self.assertRaisesRegex(ValueError, "traversal lineage contract is invalid"):
                self.traversal_claim(SimpleNamespace(id=route.id, constraints=malformed),
                                     query={field: "1", "tweet.fields": "id,text"})


if __name__ == "__main__":
    unittest.main()
