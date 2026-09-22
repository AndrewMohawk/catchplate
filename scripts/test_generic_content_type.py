#!/usr/bin/env python3
"""Pure generic request admission tests, not DB or authority integration proof."""
from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware.policy_bundle import compile_policy_bundle, demo_policy_bundle, validate_policy_schema


def unavailable_dependency(name: str) -> ModuleType:
    dependency = ModuleType(name)

    def reject_access(attribute: str) -> None:
        raise AssertionError(f"pure admission test accessed {name}.{attribute}")

    dependency.__getattr__ = reject_access
    return dependency


# The real authority registry has a separately tracked startup blocker. Load
# only the pure adapter boundary; any attempted DB/runtime use fails this test.
SPEC = importlib.util.spec_from_file_location("generic_content_type_adapters_unit", ROOT / "serverware/adapters.py")
assert SPEC is not None and SPEC.loader is not None
adapters = importlib.util.module_from_spec(SPEC)
with mock.patch.dict(sys.modules, {
    "serverware.db": unavailable_dependency("serverware.db"),
    "serverware.runtime": unavailable_dependency("serverware.runtime"),
}):
    SPEC.loader.exec_module(adapters)


class GenericContentTypeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        bundle = demo_policy_bundle()
        bundle["routes"] = [item for item in bundle["routes"] if item["id"] == "demo.echo"]
        cls.route = compile_policy_bundle(bundle, validate_schema=True).routes[0]
        cls.adapter = adapters.get_adapter("generic.rest")

    def flow(self, headers: dict[str, str], body: bytes = b'{"audit_marker":"local-unit"}') -> SimpleNamespace:
        return SimpleNamespace(request=SimpleNamespace(
            headers=headers,
            pretty_url="https://demo-upstream:8443/echo",
            raw_content=body,
            get_content=lambda strict=True: body,
        ))

    def test_schema_valid_json_uses_media_contract_not_header_allowlist(self) -> None:
        config = self.route.adapter_config["request"]
        self.assertNotIn("content-type", config["allowedHeaders"])
        self.assertEqual(config["allowedMediaTypes"], ["application/json"])
        for content_type in ("application/json", "Application/JSON; charset=utf-8"):
            with self.subTest(content_type=content_type):
                flow = self.flow({"content-type": content_type})
                preflight = adapters.preflight_request_admission(flow, self.route, flow.request.headers)
                self.assertTrue(preflight.allowed, preflight)
                decision = self.adapter.validate_request(flow, self.route, {})
                self.assertTrue(decision.allowed, decision)

    def test_media_and_unknown_header_rejections_remain_closed(self) -> None:
        cases = (
            ("missing", {}, "request_content_type_required", 415),
            ("wrong", {"content-type": "text/plain"}, "request_content_type_denied", 415),
            ("malformed", {"content-type": "application/json;"}, "request_content_type_denied", 415),
            ("duplicate parameter", {"content-type": "application/json; charset=utf-8; CHARSET=utf-8"}, "request_content_type_denied", 415),
            ("duplicate header", {"content-type": "application/json", "Content-Type": "application/json"}, "request_content_type_ambiguous", 415),
            ("unknown header", {"content-type": "application/json", "x-not-allowed": "local-unit"}, "request_header_not_allowed", 403),
        )
        for label, headers, error, status in cases:
            with self.subTest(label=label):
                decision = self.adapter.validate_request(self.flow(headers), self.route, {})
                self.assertFalse(decision.allowed, decision)
                self.assertEqual(decision.payload["error"], error)
                self.assertEqual(decision.status_code, status)

    def test_empty_media_allowlist_still_rejects_present_content_type(self) -> None:
        route = copy.deepcopy(self.route)
        route.adapter_config["request"].update(bodyMode="none", maxBodyBytes=0, allowedMediaTypes=[])
        decision = self.adapter.validate_request(self.flow({"content-type": "application/json"}, b""), route, {})
        self.assertFalse(decision.allowed, decision)
        self.assertEqual(decision.payload["error"], "request_content_type_denied")

    def test_all_demo_generic_routes_keep_content_type_out_of_allowed_headers(self) -> None:
        bundle = demo_policy_bundle()
        bundle["routes"] = [item for item in bundle["routes"] if item["adapter"]["type"] == "generic.rest"]
        validate_policy_schema(bundle)
        body_routes = []
        for route in bundle["routes"]:
            with self.subTest(route=route["id"]):
                request = route["adapter"]["config"]["request"]
                self.assertNotIn("content-type", request["allowedHeaders"])
                if request["bodyMode"] != "none":
                    body_routes.append(route["id"])
                    self.assertTrue(request["allowedMediaTypes"])
        self.assertEqual(len(body_routes), 8)


if __name__ == "__main__":
    unittest.main()
