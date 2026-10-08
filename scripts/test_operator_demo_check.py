#!/usr/bin/env python3
"""Checker controls and real local TLS transport tests, not stack acceptance."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.check_operator_demo import (
    CheckFailure, Endpoint, OperatorDemoCheck, TunnelTLS, private_address, run_checks,
)


class CheckerControls(unittest.TestCase):
    def test_public_link_local_and_unspecified_addresses_are_refused(self):
        for address in ("8.8.8.8", "169.254.169.254", "0.0.0.0", "::", "fe80::1", "::ffff:127.0.0.1"):
            with self.subTest(address=address):
                self.assertFalse(private_address(address))
        for address in ("127.0.0.1", "172.16.249.18", "10.2.3.4", "192.168.2.3", "::1", "fd01::1"):
            self.assertTrue(private_address(address))

    def test_mixed_dns_addresses_fail_closed(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 3000))
                   for ip in ("127.0.0.1", "8.8.8.8")]
        with patch("socket.getaddrinfo", return_value=answers):
            with self.assertRaises(CheckFailure):
                Endpoint("http://private.example:3000")

    def test_url_credentials_and_paths_are_rejected_before_dns(self):
        for url in ("http://user:secret@127.0.0.1", "http://127.0.0.1/path", "http://127.0.0.1?secret=x"):
            with self.subTest(url=url), patch("socket.getaddrinfo") as lookup:
                with self.assertRaises(CheckFailure):
                    Endpoint(url)
                lookup.assert_not_called()

    def test_fixture_ip_override_preserves_tls_hostname(self):
        endpoint = Endpoint("https://demo-upstream:8443", address="172.16.249.18")
        self.assertEqual((endpoint.host, endpoint.address, endpoint.port), ("demo-upstream", "172.16.249.18", 8443))

    def test_untrusted_exception_detail_never_becomes_output(self):
        args = argparse.Namespace(expected_binary_sha256="sha256:" + "a" * 64, timeout_seconds=90)
        with patch("scripts.check_operator_demo.OperatorDemoCheck", side_effect=ValueError("secret-must-not-escape")):
            result = run_checks(args)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "ValueError")
        self.assertNotIn("secret-must-not-escape", json.dumps(result))

    def test_response_scan_catches_json_escaped_credentials(self):
        check = OperatorDemoCheck.__new__(OperatorDemoCheck)
        check.credential = "private-credential"
        check.admin_token = check.client_token = check.wrong_token = None

        class Response:
            status = 200
            def read(self, _limit):
                return b'{"value":"\\u0070rivate-credential"}'
            def getheaders(self):
                return []

        with self.assertRaises(CheckFailure):
            check.response(Response())


class LocalTLSControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="operator-check-tls-")
        cls.addClassCleanup(cls.directory.cleanup)
        certificate = Path(cls.directory.name) / "test-ca.pem"
        private_key = Path(cls.directory.name) / "test-key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-keyout", str(private_key), "-out", str(certificate), "-subj", "/CN=demo-upstream",
                        "-addext", "subjectAltName=DNS:demo-upstream",
                        "-addext", "basicConstraints=critical,CA:TRUE"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True, timeout=10)
        cls.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.server_context.load_cert_chain(certificate, private_key)
        cls.client_context = ssl.create_default_context(cafile=str(certificate))

    def exchange(self, nested: bool):
        client, server = socket.socketpair()
        client.settimeout(3)
        server.settimeout(3)
        failures = []

        def serve():
            outer = server
            try:
                if nested:
                    outer = self.server_context.wrap_socket(server, server_side=True)
                incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                inner = self.server_context.wrap_bio(incoming, outgoing, server_side=True)

                def operation(fn):
                    while True:
                        try:
                            result = fn()
                        except ssl.SSLWantReadError:
                            while outgoing.pending:
                                outer.sendall(outgoing.read())
                            chunk = outer.recv(16384)
                            if not chunk:
                                raise RuntimeError("test peer closed early")
                            incoming.write(chunk)
                        else:
                            while outgoing.pending:
                                outer.sendall(outgoing.read())
                            return result

                operation(inner.do_handshake)
                request = b""
                while not request.endswith(b"\r\n\r\n"):
                    request += operation(lambda: inner.read(8192))
                self.assertIn(b"Host: demo-upstream:8443\r\n", request)
                operation(lambda: inner.write(b'HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{"ok":true}'))
            except BaseException as error:
                failures.append(error)
            finally:
                outer.close()

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            transport = self.client_context.wrap_socket(client, server_hostname="demo-upstream") if nested else client
            with TunnelTLS(transport, self.client_context, lambda: 3.0) as tls:
                tls.sendall(b"GET /echo HTTP/1.1\r\nHost: demo-upstream:8443\r\n\r\n")
                response = http.client.HTTPResponse(tls)
                response.begin()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), b'{"ok":true}')
                response.close()
        finally:
            client.close()
            thread.join(timeout=4)
        self.assertFalse(thread.is_alive(), "local TLS peer did not terminate")
        if failures:
            raise failures[0]

    def test_real_origin_tls(self):
        self.exchange(False)

    def test_real_tls_inside_tls_proxy_transport(self):
        self.exchange(True)


class FixtureReceiptControls(unittest.TestCase):
    def test_exact_credential_receipt_and_wrong_digest_control(self):
        from starlette.requests import Request
        from scripts.demo_upstream import echo
        secret = "synthetic-fixture-value"
        digest = "sha256:" + hashlib.sha256(("Bearer " + secret).encode("ascii")).hexdigest()
        for expected, match, proxy in ((digest, True, False), ("sha256:" + "0" * 64, False, True)):
            headers = [(b"authorization", ("Bearer " + secret).encode("ascii"))]
            if proxy:
                headers.append((b"proxy-authorization", b"Bearer synthetic-proxy-token"))
            request = Request({"type": "http", "method": "GET", "scheme": "https",
                "server": ("demo-upstream", 8443), "path": "/echo", "root_path": "",
                "query_string": ("expectedAuthorizationSha256=" + expected).encode("ascii"), "headers": headers})
            result = asyncio.run(echo(request))
            self.assertIs(result["authorization_matches_expected"], match)
            self.assertIs(result["proxy_authorization_seen"], proxy)
            self.assertNotIn(expected, json.dumps(result))
            self.assertNotIn(digest, json.dumps(result))
            self.assertNotIn(secret, json.dumps(result))


if __name__ == "__main__":
    unittest.main()
