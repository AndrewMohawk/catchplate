#!/usr/bin/env python3
"""Offline presentation/profile controls; no runtime, database or secret access."""
from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from catchplate import development_sandbox, sandbox_portal

ASSETS = ROOT / "catchplate" / "sandbox_web"


class Elements(HTMLParser):
    def __init__(self, document: str):
        super().__init__()
        self.elements = []
        self.feed(document)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class SandboxPortalTests(unittest.TestCase):
    def setUp(self):
        sandbox_portal.render.cache_clear()
        self.addCleanup(sandbox_portal.render.cache_clear)

    def test_render_reads_only_public_assets_and_embeds_each_once(self):
        original = Path.read_text
        reads = []

        def read_public_asset(path, *args, **kwargs):
            self.assertEqual(path.parent, ASSETS, "renderer read outside presentation assets")
            self.assertIn(path.name, {"index.html", "style.css", "app.js"})
            reads.append(path.name)
            return original(path, *args, **kwargs)

        with patch.object(Path, "read_text", read_public_asset), \
                patch("socket.socket", side_effect=AssertionError("renderer used network")), \
                patch("os.getenv", side_effect=AssertionError("renderer read configuration")):
            document = sandbox_portal.render()
            self.assertEqual(document, sandbox_portal.render())
        self.assertCountEqual(reads, ["index.html", "style.css", "app.js"])
        self.assertNotIn("__SANDBOX_STYLE__", document)
        self.assertNotIn("__SANDBOX_SCRIPT__", document)
        self.assertEqual(document.count("<style>"), 1)
        self.assertEqual(document.count("<script>"), 1)
        self.assertNotIn("catchplate.config", sys.modules)
        self.assertNotIn("catchplate.app", sys.modules)

    def test_missing_or_duplicate_asset_marker_is_rejected(self):
        original = Path.read_text
        template = (ASSETS / "index.html").read_text(encoding="utf-8")
        for marker in ("__SANDBOX_STYLE__", "__SANDBOX_SCRIPT__"):
            self.assertEqual(template.count(marker), 1)
            for replacement in ("", marker * 2):
                with self.subTest(marker=marker, duplicate=bool(replacement)):
                    sandbox_portal.render.cache_clear()

                    def read_fixture(path, *args, **kwargs):
                        if path.name == "index.html":
                            return template.replace(marker, replacement)
                        return original(path, *args, **kwargs)

                    with patch.object(Path, "read_text", read_fixture), \
                            self.assertRaisesRegex(RuntimeError, "marker"):
                        sandbox_portal.render()

    def test_inactive_profile_preserves_original_portal_without_reading_assets(self):
        original = "<!doctype html><html><body>ordinary production portal</body></html>"
        with patch.object(development_sandbox, "active", return_value=False), \
                patch.object(sandbox_portal, "render", side_effect=AssertionError("sandbox renderer reached")):
            self.assertEqual(development_sandbox.decorate_portal(original), original)

    def test_active_profile_uses_standalone_renderer(self):
        with patch.object(development_sandbox, "active", return_value=True), \
                patch.object(sandbox_portal, "render", return_value="synthetic presentation") as render:
            self.assertEqual(development_sandbox.decorate_portal("ordinary portal"), "synthetic presentation")
        render.assert_called_once_with()

    def test_navigation_and_forms_offer_no_production_mutations(self):
        document = sandbox_portal.render()
        elements = Elements(document).elements
        ids = [attrs["id"] for _, attrs in elements if "id" in attrs]
        self.assertEqual(len(ids), len(set(ids)), "duplicate IDs make navigation ambiguous")
        for section in ("overview", "proxy", "credentials", "access", "audit"):
            self.assertIn(("section", section), [(tag, attrs.get("id")) for tag, attrs in elements])
        ca = next(attrs for _, attrs in elements if attrs.get("id") == "ca-download")
        self.assertEqual(ca["href"], "/ca.pem")
        self.assertEqual(ca["download"], "catchplate-ca.pem")
        for tag, attrs in elements:
            if tag in {"a", "form", "button"}:
                for key in ("href", "action", "formaction"):
                    self.assertFalse(attrs.get(key, "").startswith("/api/"),
                                     f"presentation exposes an API mutation link: {attrs.get(key)}")
            if tag == "input":
                self.assertNotEqual(attrs.get("type"), "password")
                self.assertNotIn("token", attrs.get("id", ""))
        self.assertIn("Streaming request transformations are unsupported and refused.", document)
        self.assertIn("not the forward proxy", document)


if __name__ == "__main__":
    unittest.main(verbosity=2)
