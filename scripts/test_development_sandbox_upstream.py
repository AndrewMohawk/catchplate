#!/usr/bin/env python3
"""Small fixture-contract controls; no sockets, certificates, or data writes."""
from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from starlette.requests import Request
from scripts import demo_upstream


class UpstreamContractTests(unittest.TestCase):
    def request(self, *, reflection: bool = False, sensitive_headers: bool = False) -> Request:
        headers = [(b"authorization", b"Bearer demo-token-from-vault")]
        if sensitive_headers:
            headers += [(b"cookie", b"synthetic-cookie"),
                        (b"x-catchplate-data-plane-token", b"synthetic-service-token")]
        return Request({
            "type": "http", "method": "GET", "scheme": "https",
            "server": ("demo-upstream", 8443), "path": "/echo", "root_path": "",
            "query_string": b"reflectCredential=1" if reflection else b"",
            "headers": headers,
        })

    def test_normal_echo_never_reflects_credential_or_its_digest(self):
        result = asyncio.run(demo_upstream.echo(self.request()))
        self.assertNotIn("demo-token-from-vault", json.dumps(result))
        self.assertNotIn("authorization", result)
        self.assertNotIn("authorization_sha256", result)
        self.assertTrue(result["authorization_present"])
        self.assertEqual(result["authorization_scheme"], "Bearer")
        self.assertEqual(result["credential_marker"], "initial")
        self.assertFalse(result["query"]["_cookie_seen"])
        self.assertFalse(result["query"]["_data_plane_token_seen"])

    def test_reflection_remains_an_explicit_negative_fixture(self):
        result = asyncio.run(demo_upstream.echo(self.request(reflection=True)))
        self.assertEqual(result["credential_reflection"], "Bearer demo-token-from-vault")
        self.assertNotIn("authorization", result)

    def test_header_presence_controls_report_actual_arrival(self):
        result = asyncio.run(demo_upstream.echo(self.request(sensitive_headers=True)))
        self.assertTrue(result["query"]["_cookie_seen"])
        self.assertTrue(result["query"]["_data_plane_token_seen"])

    def test_nested_route_counts_actual_arrival_for_no_dispatch_control(self):
        run_id = "fixture-" + uuid.uuid4().hex
        async def receive():
            return {"type": "http.request", "body": b"{}", "more_body": False}
        request = Request({
            "type": "http", "method": "POST", "scheme": "https",
            "server": ("demo-upstream", 8443), "path": "/json-nested-redact",
            "root_path": "", "query_string": b"",
            "headers": [(b"user-agent", ("catchplate-test-run/" + run_id).encode("ascii"))],
        }, receive=receive)
        self.assertEqual(asyncio.run(demo_upstream.request_count("POST", "/json-nested-redact", run_id))["count"], 0)
        asyncio.run(demo_upstream.json_nested_redact(request))
        self.assertEqual(asyncio.run(demo_upstream.request_count("POST", "/json-nested-redact", run_id))["count"], 1)

    def test_launcher_disables_only_unspecified_semantic_defaults(self):
        # Execute the real main block with inert collaborators. Importing or
        # invoking the full launcher would create certificates or bind a port.
        source = ROOT / "scripts" / "demo_upstream.py"
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        block = next(node for node in tree.body if isinstance(node, ast.If)
                     and ast.unparse(node.test) == "__name__ == '__main__'")
        calls = []
        application = object()
        namespace = {
            "ensure_cert": lambda: calls.append(("ensure_cert",)),
            "uvicorn": SimpleNamespace(run=lambda *args, **kwargs: calls.append((args, kwargs))),
            "app": application, "KEY_PATH": Path("/synthetic/key.pem"),
            "CERT_PATH": Path("/synthetic/cert.pem"),
        }
        exec(compile(ast.Module(body=block.body, type_ignores=[]), str(source), "exec"), namespace)
        self.assertEqual(calls[0], ("ensure_cert",))
        args, kwargs = calls[1]
        self.assertEqual(args, (application,))
        self.assertEqual(kwargs, {
            "host": "0.0.0.0", "port": 8443,
            "ssl_keyfile": "/synthetic/key.pem", "ssl_certfile": "/synthetic/cert.pem",
            "date_header": False, "server_header": False,
        })


if __name__ == "__main__":
    unittest.main()
