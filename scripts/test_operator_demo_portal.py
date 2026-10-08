#!/usr/bin/env python3
"""Offline operator portal asset checks; no configured application or secrets."""
from html.parser import HTMLParser
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware import operator_demo_portal

ASSETS = ROOT / "serverware" / "operator_demo_web"


class Elements(HTMLParser):
    def __init__(self, document):
        super().__init__()
        self.items = []
        self.feed(document)

    def handle_starttag(self, tag, attrs):
        self.items.append((tag, dict(attrs)))


class OperatorPortalTests(unittest.TestCase):
    def setUp(self):
        operator_demo_portal.render.cache_clear()
        self.addCleanup(operator_demo_portal.render.cache_clear)

    def test_renderer_reads_public_assets_only(self):
        original, reads = Path.read_text, []

        def read(path, *args, **kwargs):
            self.assertEqual(path.parent, ASSETS)
            self.assertIn(path.name, {"index.html", "style.css", "app.js"})
            reads.append(path.name)
            return original(path, *args, **kwargs)

        with patch.object(Path, "read_text", read), \
                patch("socket.socket", side_effect=AssertionError("network access")), \
                patch("os.getenv", side_effect=AssertionError("configuration access")):
            rendered = operator_demo_portal.render()
            self.assertEqual(rendered, operator_demo_portal.render())
        self.assertCountEqual(reads, ["index.html", "style.css", "app.js"])
        self.assertNotIn("__OPERATOR_DEMO_", rendered)
        self.assertNotIn("serverware.app", sys.modules)
        self.assertNotIn("serverware.config", sys.modules)

    def test_missing_or_duplicate_marker_fails(self):
        original = Path.read_text
        template = (ASSETS / "index.html").read_text()
        for marker in ("__OPERATOR_DEMO_STYLE__", "__OPERATOR_DEMO_SCRIPT__"):
            for replacement in ("", marker * 2):
                with self.subTest(marker=marker, replacement=replacement):
                    operator_demo_portal.render.cache_clear()

                    def read(path, *args, **kwargs):
                        return template.replace(marker, replacement) if path.name == "index.html" else original(path, *args, **kwargs)

                    with patch.object(Path, "read_text", read), self.assertRaisesRegex(RuntimeError, "marker"):
                        operator_demo_portal.render()

    def test_structure_and_secret_inputs(self):
        items = Elements(operator_demo_portal.render()).items
        ids = [attrs["id"] for _, attrs in items if "id" in attrs]
        self.assertEqual(len(ids), len(set(ids)))
        indexed = {attrs["id"]: (tag, attrs) for tag, attrs in items if "id" in attrs}
        for view in ("overview", "credentials", "proxy", "audit"):
            self.assertEqual(indexed[view][0], "section")
        for name in ("provider-secret", "client-token"):
            self.assertEqual(indexed[name][1]["type"], "password")
            self.assertNotIn("value", indexed[name][1])
        self.assertIn("required", indexed["response-fields"][1])
        self.assertEqual(indexed["ca-download"][1]["href"], "/ca.pem")
        self.assertIn("download", indexed["ca-download"][1])

    def test_method_controls_match_the_json_response_contract(self):
        items = Elements(operator_demo_portal.render()).items
        methods = [attrs["value"] for tag, attrs in items
                   if tag == "input" and attrs.get("name") == "method"]
        self.assertEqual(methods, ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
        self.assertNotIn("HEAD", methods)

    def test_revocation_has_separate_status_and_retained_receipt_regions(self):
        items = Elements(operator_demo_portal.render()).items
        indexed = {attrs["id"]: (tag, attrs) for tag, attrs in items if "id" in attrs}
        self.assertEqual(indexed["revocation-status"][1].get("role"), "status")
        self.assertIn("revocations-list", indexed)
        # Actual confirmation, mutation payload and uncertainty behavior are
        # exercised by the separate intercepted Chromium fixtures.
        script = (ASSETS / "app.js").read_text()
        self.assertIn("/api/operator-demo/connections/revoke", script)
        self.assertIn("window.confirm", script)
        self.assertIn("expected_policy_hash", script)
        self.assertIn("revocation_policy_hash", script)

    def test_no_secret_persistence_or_unsafe_client_transport(self):
        script = (ASSETS / "app.js").read_text()
        for forbidden in ("localStorage", "sessionStorage", "indexedDB", "innerHTML", "--insecure", "--proxy-insecure", "decision-gate-rs:"):
            self.assertNotIn(forbidden, script)
        self.assertIn("--proxy-header", script)
        self.assertIn("--cacert", script)
        self.assertIn("loaded_policy_hash === status.active_policy_hash", script)
        self.assertIn("Object.hasOwn(views, view)", script)


if __name__ == "__main__":
    unittest.main(verbosity=2)
