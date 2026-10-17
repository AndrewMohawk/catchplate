#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from catchplate.http_client import HttpClientError, HttpDeadline, request_json


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: object, client_address: object) -> None:
        return


class HostileHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    counts: dict[str, int] = {}
    received_headers: dict[str, str] = {}

    def _count(self) -> None:
        type(self).counts[self.path] = type(self).counts.get(self.path, 0) + 1

    def _send_json(
        self,
        body: bytes = b'{"ok":true}',
        *,
        status: int = 200,
        content_type: str | None = "application/json; charset=UTF-8",
        content_length: str | None = None,
    ) -> None:
        self.send_response(status)
        if content_type is not None:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", content_length if content_length is not None else str(len(body)))
        self.end_headers()
        if body:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def do_GET(self) -> None:
        self._count()
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/redirect-target")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/redirect-target":
            type(self).received_headers = {name.lower(): value for name, value in self.headers.items()}
            self._send_json()
            return
        if self.path == "/status":
            self._send_json(status=503)
            return
        if self.path == "/wrong-content-type":
            self._send_json(content_type="text/plain")
            return
        if self.path == "/missing-content-type":
            self._send_json(content_type=None)
            return
        if self.path == "/duplicate-content-type":
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/bad-charset":
            self._send_json(content_type="application/json; charset=iso-8859-1")
            return
        if self.path == "/duplicate-json":
            self._send_json(body=b'{"id":"first","id":"second"}')
            return
        if self.path == "/non-finite-json":
            self._send_json(body=b'{"value":NaN}')
            return
        if self.path == "/overflowing-json-number":
            self._send_json(body=b'{"value":1e10000}')
            return
        if self.path == "/oversized-json-integer":
            self._send_json(body=b'{"value":' + b"9" * 5000 + b"}")
            return
        if self.path == "/oversized-declared":
            self._send_json(body=b"", content_length="999")
            return
        if self.path == "/oversized-stream":
            body = b'x' * 33
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/short-body":
            self._send_json(body=b"{}", content_length="10")
            self.close_connection = True
            return
        if self.path == "/duplicate-content-length":
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/ambiguous-framing":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "2")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            return
        if self.path == "/encoded-response":
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/duplicate-content-encoding":
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "identity")
            self.send_header("Content-Encoding", "identity")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/truncated-chunked":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(b"b\r\n{\"ok\":true}")
            self.wfile.flush()
            self.close_connection = True
            return
        if self.path == "/set-cookie":
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "ambient=secret; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/headers":
            type(self).received_headers = {name.lower(): value for name, value in self.headers.items()}
            self._send_json()
            return
        if self.path == "/pause":
            time.sleep(0.075)
            self._send_json()
            return
        if self.path == "/slow-headers":
            time.sleep(0.2)
            self._send_json()
            return
        if self.path == "/drip":
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            self.end_headers()
            for byte in body:
                try:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    break
                time.sleep(0.035)
            return
        self._send_json()

    def log_message(self, format: str, *args: object) -> None:
        return


class SecureHttpClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        HostileHandler.counts = {}
        HostileHandler.received_headers = {}
        cls.server = QuietThreadingHTTPServer(("127.0.0.1", 0), HostileHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, path: str, **kwargs: object) -> object:
        options = {
            "headers": {},
            "timeout": 1.0,
            "max_bytes": 128,
            "require_https": False,
        }
        options.update(kwargs)
        return request_json(f"{self.base}{path}", **options)

    def assert_client_error(self, path: str, expected: str, **kwargs: object) -> None:
        with self.assertRaisesRegex(HttpClientError, expected):
            self.request(path, **kwargs)

    def test_direct_transport_ignores_ambient_proxies(self) -> None:
        proxy_environment = {
            "http_proxy": "http://127.0.0.1:1",
            "https_proxy": "http://127.0.0.1:1",
            "all_proxy": "http://127.0.0.1:1",
            "HTTP_PROXY": "http://127.0.0.1:1",
            "HTTPS_PROXY": "http://127.0.0.1:1",
            "ALL_PROXY": "http://127.0.0.1:1",
            "no_proxy": "",
            "NO_PROXY": "",
        }
        with mock.patch.dict(os.environ, proxy_environment, clear=False):
            self.assertEqual(self.request("/ok"), {"ok": True})

    def test_redirect_is_not_followed_or_retried_with_credentials(self) -> None:
        before = HostileHandler.counts.get("/redirect", 0)
        target_before = HostileHandler.counts.get("/redirect-target", 0)
        self.assert_client_error(
            "/redirect",
            "status 302",
            headers={"Authorization": "Bearer do-not-forward"},
        )
        self.assertEqual(HostileHandler.counts.get("/redirect", 0), before + 1)
        self.assertEqual(HostileHandler.counts.get("/redirect-target", 0), target_before)

    def test_error_status_is_attempted_once(self) -> None:
        before = HostileHandler.counts.get("/status", 0)
        self.assert_client_error("/status", "status 503")
        self.assertEqual(HostileHandler.counts.get("/status", 0), before + 1)

    def test_cookie_is_neither_accepted_nor_sent(self) -> None:
        self.assertEqual(self.request("/set-cookie"), {"ok": True})
        self.assertEqual(self.request("/headers"), {"ok": True})
        self.assertNotIn("cookie", HostileHandler.received_headers)

    def test_only_explicit_safe_headers_and_client_invariants_are_sent(self) -> None:
        self.assertEqual(
            self.request(
                "/headers",
                headers={"Authorization": "Bearer controlled", "X-Test-Request": "value"},
            ),
            {"ok": True},
        )
        received = HostileHandler.received_headers
        self.assertEqual(received.get("authorization"), "Bearer controlled")
        self.assertEqual(received.get("x-test-request"), "value")
        self.assertEqual(received.get("accept"), "application/json")
        self.assertEqual(received.get("accept-encoding"), "identity")
        self.assertNotIn("user-agent", received)
        self.assertNotIn("cookie", received)
        self.assertNotIn("proxy-authorization", received)

        self.assertEqual(
            self.request("/headers", headers={"Accept": "application/json"}),
            {"ok": True},
        )
        for name in ("Cookie", "Host", "Proxy-Authorization", "Transfer-Encoding"):
            self.assert_client_error(
                "/headers",
                "not allowed",
                headers={name: "attacker-controlled"},
            )
        self.assert_client_error(
            "/headers",
            "not allowed",
            headers={"Accept": "text/plain"},
        )

    def test_https_is_required_by_default(self) -> None:
        with self.assertRaisesRegex(HttpClientError, "scheme is not allowed"):
            request_json(
                f"{self.base}/ok",
                headers={},
                timeout=1,
                max_bytes=128,
            )

    def test_status_content_type_and_charset_are_exact(self) -> None:
        self.assert_client_error("/wrong-content-type", "is not allowed")
        self.assert_client_error("/missing-content-type", "exactly one Content-Type")
        self.assert_client_error("/duplicate-content-type", "exactly one Content-Type")
        self.assert_client_error("/bad-charset", "charset must be UTF-8")

    def test_content_length_and_transfer_framing_are_strict(self) -> None:
        self.assert_client_error(
            "/oversized-declared",
            "exceeds 32 bytes",
            max_bytes=32,
        )
        self.assert_client_error(
            "/oversized-stream",
            "exceeds 32 bytes",
            max_bytes=32,
        )
        self.assert_client_error("/short-body", "does not match Content-Length")
        self.assert_client_error("/duplicate-content-length", "duplicate Content-Length")
        self.assert_client_error("/ambiguous-framing", "both Content-Length and Transfer-Encoding")
        self.assert_client_error("/truncated-chunked", "truncated|framing is invalid")

    def test_content_encoding_is_absent_or_exactly_identity(self) -> None:
        self.assert_client_error("/encoded-response", "Content-Encoding is not identity")
        self.assert_client_error(
            "/duplicate-content-encoding",
            "Content-Encoding is not identity",
        )

    def test_json_rejects_duplicate_keys_and_non_finite_numbers(self) -> None:
        self.assert_client_error("/duplicate-json", "duplicate object key: id")
        self.assert_client_error("/non-finite-json", "non-finite number: NaN")
        self.assert_client_error("/overflowing-json-number", "non-finite number")
        self.assert_client_error("/oversized-json-integer", "not valid JSON", max_bytes=8192)

    def test_per_request_timeout_bounds_header_wait(self) -> None:
        started = time.monotonic()
        self.assert_client_error("/slow-headers", "deadline exceeded", timeout=0.04)
        self.assertLess(time.monotonic() - started, 0.18)

    def test_deadline_bounds_a_trickled_body(self) -> None:
        started = time.monotonic()
        self.assert_client_error(
            "/drip",
            "deadline exceeded",
            timeout=1.0,
            deadline=HttpDeadline.after(0.11),
        )
        self.assertLess(time.monotonic() - started, 0.3)

    def test_shared_deadline_is_consumed_across_requests(self) -> None:
        deadline = HttpDeadline.after(0.12)
        self.assertEqual(self.request("/pause", deadline=deadline), {"ok": True})
        self.assert_client_error("/pause", "deadline exceeded", deadline=deadline)


if __name__ == "__main__":
    unittest.main()
