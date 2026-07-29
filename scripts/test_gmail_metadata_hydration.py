#!/usr/bin/env python3
from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _gmail_routes(document: dict[str, object]) -> list[dict[str, object]]:
    routes = document.get("routes")
    if not isinstance(routes, list):
        raise AssertionError("policy routes are unavailable")
    return [
        route
        for route in routes
        if isinstance(route, dict)
        and isinstance(route.get("adapter"), dict)
        and route["adapter"].get("type") == "gmail.v1"
    ]


class GmailMetadataHydrationTests(unittest.TestCase):
    def test_shared_policies_keep_strict_metadata_hydration(self) -> None:
        for relative_path in (
            "policies/credential-limits.examples.json",
            "policies/demo.policy.json",
        ):
            with self.subTest(policy=relative_path):
                document = json.loads(
                    (ROOT / relative_path).read_text(encoding="utf-8")
                )
                routes = _gmail_routes(document)
                self.assertTrue(routes, f"{relative_path} has no Gmail route")
                for route in routes:
                    config = route["adapter"]["config"]
                    response = config["response"]
                    metadata_fetch = response["metadataFetch"]
                    self.assertEqual(config["maxAgeDays"], 30)
                    self.assertTrue(config["forceQuery"])
                    self.assertTrue(
                        config["allowMessageGetOnlyFromPriorSearch"]
                    )
                    self.assertTrue(response["validateInternalDate"])
                    self.assertTrue(
                        response["validateListByMetadataFetch"]
                    )
                    self.assertEqual(
                        set(metadata_fetch),
                        {
                            "maxMessages",
                            "perRequestTimeoutMs",
                            "totalTimeoutMs",
                            "maxBodyBytes",
                        },
                    )
                    self.assertGreater(metadata_fetch["maxMessages"], 0)
                    self.assertLessEqual(metadata_fetch["maxMessages"], 32)
                    self.assertGreater(
                        metadata_fetch["totalTimeoutMs"],
                        metadata_fetch["perRequestTimeoutMs"],
                    )

    def test_python_legacy_denial_precedes_credential_work(self) -> None:
        policy_source = (
            ROOT / "serverware/policy_engine.py"
        ).read_text(encoding="utf-8")
        request_start = policy_source.index(
            "def evaluate_request(flow: http.HTTPFlow)"
        )
        admission = policy_source.index(
            "transport_denial = _legacy_mitm_route_admission(flow, route)",
            request_start,
        )
        adapter_lookup = policy_source.index(
            "adapter = get_adapter(route.adapter_type)",
            admission,
        )
        credential_generation = policy_source.index(
            "credential_generation = runtime.get_credential_generation(",
            adapter_lookup,
        )
        secret_load = policy_source.index(
            "bound_credential_lease = runtime.get_bound_credential_lease(",
            credential_generation,
        )
        self.assertLess(admission, adapter_lookup)
        self.assertLess(admission, credential_generation)
        self.assertLess(admission, secret_load)
        self.assertIn(
            '"legacy_mitm_credential_transport_denied"',
            policy_source[request_start:adapter_lookup],
        )

    def test_addon_marks_legacy_transport_before_evaluation(self) -> None:
        addon_source = (
            ROOT / "serverware/mitm_addon.py"
        ).read_text(encoding="utf-8")
        request_start = addon_source.index(
            "def request(self, flow: http.HTTPFlow)"
        )
        marker = addon_source.index(
            "flow.metadata[LEGACY_MITM_TRANSPORT_METADATA_KEY] = True",
            request_start,
        )
        evaluation = addon_source.index(
            "evaluation = evaluate_request(flow)",
            marker,
        )
        dispatch = addon_source.index(
            "dispatch = dispatch_release_authorization(flow)",
            evaluation,
        )
        self.assertLess(marker, evaluation)
        self.assertLess(evaluation, dispatch)
        self.assertNotIn(
            "verify_connected_provider_peer",
            addon_source,
        )

    def test_rust_gate_owns_bounded_child_authorization(self) -> None:
        rust_source = (
            ROOT / "data-plane/decision-gate-rs/src/main.rs"
        ).read_text(encoding="utf-8")
        for marker in (
            "struct GmailMetadataChildAuthorizationLedger",
            "gmail_metadata_child_authorization_replayed",
            "derive_gmail_metadata_child_authorization",
            "validate_gmail_metadata_child_authorization",
            "send_gmail_metadata_child_with_authorization",
            "execution.prepared_upstream.client",
            "gmail_metadata_child_timeout",
            "data_plane.gmail.metadata_fanout.started",
            "data_plane.gmail.metadata_fanout.completed",
        ):
            self.assertIn(marker, rust_source)


if __name__ == "__main__":
    unittest.main()
