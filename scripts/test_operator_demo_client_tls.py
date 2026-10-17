#!/usr/bin/env python3
"""Execute the UI's generated curl command through two isolated TLS layers.

This is a local client-transport fixture, not Catchplate runtime/provider proof.
Requires curl with HTTPS-proxy support, Node, and OpenSSL. All listeners bind
127.0.0.1; only throwaway credentials and CAs are used. No system trust changes.
"""

from contextlib import ExitStack
import hmac
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import secrets
import select
import shlex
import shutil
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "catchplate/operator_demo_web/app.js"
PROXY_HOST = "proxy.operator-client.example.test"
INNER_HOST = "api.operator-client.example.test"
BODY = b'{"id":"local-client-tls-fixture","status":"ok"}\n'


def run_tool(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if result.returncode:
        # Do not expose command inputs, key material, or subprocess diagnostics.
        raise RuntimeError(f"Fixture prerequisite failed: {Path(args[0]).name}")
    return result.stdout


def make_ca(directory, name):
    key, cert = directory / f"{name}.key", directory / f"{name}.pem"
    run_tool(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
              "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
              "-subj", f"/CN=Operator client local fixture {name}",
              "-addext", "basicConstraints=critical,CA:TRUE",
              "-addext", "keyUsage=critical,keyCertSign,cRLSign",
              "-keyout", str(key), "-out", str(cert)])
    return key, cert


def server_context(directory, name, hostname, ca):
    key, csr, cert = (directory / f"{name}.{suffix}" for suffix in ("key", "csr", "pem"))
    run_tool(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt",
              "ec_paramgen_curve:prime256v1", "-nodes", "-subj", f"/CN={hostname}",
              "-addext", f"subjectAltName=DNS:{hostname}",
              "-addext", "basicConstraints=critical,CA:FALSE",
              "-addext", "extendedKeyUsage=serverAuth",
              "-keyout", str(key), "-out", str(csr)])
    run_tool(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca[1]),
              "-CAkey", str(ca[0]), "-CAcreateserial", "-days", "1",
              "-copy_extensions", "copyall", "-out", str(cert)])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    return context


class LocalTLS(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = False
    daemon_threads = False
    block_on_close = True

    def __init__(self, context, handler, token, provider_secret):
        self.context = context
        self.token = token
        self.provider_secret = provider_secret
        self.events = []
        self.logs = []
        super().__init__(("127.0.0.1", 0), handler)

    def get_request(self):
        stream, peer = super().get_request()
        stream.settimeout(5)
        try:
            return self.context.wrap_socket(stream, server_side=True), peer
        except ssl.SSLError as error:
            self.logs.append("TLS handshake rejected: " + (error.reason or "unknown TLS error"))
            stream.close()
            raise
        except OSError:
            stream.close()
            raise

    def handle_error(self, request, client_address):
        self.logs.append("unexpected fixture handler error")


class InnerHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        material = self.requestline + str(self.headers)
        self.server.events.append({
            "path": self.path,
            "proxy_authorization": "Proxy-Authorization" in self.headers,
            "authorization": "Authorization" in self.headers,
            "client_token_present": self.server.token in material,
            "provider_secret_present": self.server.provider_secret in material,
            "accept": self.headers.get("Accept"),
            "user_agent": self.headers.get("User-Agent"),
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, format, *args):
        # Fixture logs contain no request or header material.
        self.server.logs.append("inner request completed")


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            chunk = self.request.recv(1)
            if not chunk:
                return
            header.extend(chunk)
            if len(header) > 16384:
                raise ValueError("Fixture CONNECT header bound exceeded")
        lines = header.decode("iso-8859-1").split("\r\n")
        method, authority, _ = lines[0].split(" ", 2)
        headers = dict(line.split(":", 1) for line in lines[1:] if ":" in line)
        headers = {name.lower(): value.strip() for name, value in headers.items()}
        valid = hmac.compare_digest(headers.get("proxy-authorization", ""),
                                    "Bearer " + self.server.token)
        self.server.events.append({
            "method": method, "authority": authority,
            "proxy_authorization_matches": valid,
            "authorization_present": "authorization" in headers,
            "provider_secret_present": self.server.provider_secret.encode() in header,
        })
        if not valid:
            self.server.logs.append("proxy rejected client authentication")
            self.request.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                                 b"Proxy-Authenticate: Bearer\r\nContent-Length: 0\r\n"
                                 b"Connection: close\r\n\r\n")
            return
        allowed = {f"{INNER_HOST}:{self.server.inner_port}",
                   f"wrong-inner.example.test:{self.server.inner_port}"}
        if method != "CONNECT" or authority not in allowed:
            raise ValueError("Fixture only accepts its fixed local destination")
        self.server.logs.append("proxy authenticated CONNECT")
        # Destination is a fixed loopback socket, never client-controlled DNS.
        with socket.create_connection(("127.0.0.1", self.server.inner_port), timeout=5) as inner:
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            while True:
                ready = [self.request] if self.request.pending() else []
                if not ready:
                    ready, _, _ = select.select([self.request, inner], [], [], 5)
                if not ready:
                    return
                for stream in ready:
                    try:
                        data = stream.recv(65536)
                        if not data:
                            return
                        (inner if stream is self.request else self.request).sendall(data)
                    except (OSError, ssl.SSLError):
                        return  # Expected when a TLS negative control closes.


class ClientTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resources = ExitStack()
        cls.addClassCleanup(cls.resources.close)
        for binary in ("curl", "node", "openssl", "sh", "findmnt"):
            if not shutil.which(binary):
                raise RuntimeError(f"Required executable missing: {binary}")
        cls.curl_version = run_tool(["curl", "--version"])
        if "HTTPS-proxy" not in cls.curl_version:
            raise RuntimeError("This curl build lacks HTTPS-proxy support")
        scratch = Path(os.environ.get("TMPDIR") or "/srv/catchplate-fast/tmp").resolve()
        if scratch == Path("/tmp") or Path("/tmp") in scratch.parents:
            raise RuntimeError("Set TMPDIR to the approved non-root scratch filesystem")
        run_tool(["findmnt", "-n", "-T", str(scratch)])
        if shutil.disk_usage(scratch).free < 16 * 1024 * 1024:
            raise RuntimeError("Insufficient space for the bounded TLS fixture")
        cls.directory = Path(cls.resources.enter_context(tempfile.TemporaryDirectory(
            prefix="operator-client-tls.", dir=scratch)))
        cls.token = "fixture-client-" + secrets.token_urlsafe(24)
        cls.provider_secret = "fixture-provider-" + secrets.token_urlsafe(24)
        cls.outer_ca = make_ca(cls.directory, "outer-ca")
        cls.inner_ca = make_ca(cls.directory, "inner trust's CA")
        cls.wrong_ca = make_ca(cls.directory, "unrelated-ca")
        cls.inner = LocalTLS(server_context(cls.directory, "inner", INNER_HOST, cls.inner_ca),
                             InnerHandler, cls.token, cls.provider_secret)
        cls.resources.callback(cls.inner.server_close)
        cls.outer = LocalTLS(server_context(cls.directory, "outer", PROXY_HOST, cls.outer_ca),
                             ProxyHandler, cls.token, cls.provider_secret)
        cls.resources.callback(cls.outer.server_close)
        cls.outer.inner_port = cls.inner.server_address[1]
        for server in (cls.inner, cls.outer):
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
            thread.start()
            cls.resources.callback(thread.join, 6)
            cls.resources.callback(server.shutdown)

    def setUp(self):
        for server in (self.outer, self.inner):
            server.events.clear()
            server.logs.clear()

    def command(self, *, inner_ca=None, proxy_host=PROXY_HOST,
                inner_host=INNER_HOST, allowed_headers=None):
        metadata = {
            "proxyUrl": f"https://{proxy_host}:{self.outer.server_address[1]}",
            "upstreamUrl": f"https://{inner_host}:{self.inner.server_address[1]}/v1/example",
            "method": "GET", "caPath": str(inner_ca or self.inner_ca[1]),
            "allowedHeaders": ["accept", "user-agent"] if allowed_headers is None else allowed_headers,
            # Unknown fields must never enter a generated client configuration.
            "providerSecret": self.provider_secret, "clientToken": self.token,
        }
        result = subprocess.run(["node", "-e",
            "const fs=require('node:fs'); const {buildCurlCommand}=require(process.argv[1]);"
            "process.stdout.write(buildCurlCommand(JSON.parse(fs.readFileSync(0,'utf8'))));",
            str(GENERATOR)], input=json.dumps(metadata), capture_output=True, text=True, timeout=5)
        self.assert_clean(result.stdout + result.stderr)
        self.assertEqual(result.returncode, 0, "The UI command generator failed")
        self.assertIn('$CATCHPLATE_PROXY_TOKEN', result.stdout)
        for forbidden in ("--insecure", "--proxy-insecure", " -k "):
            self.assertNotIn(forbidden, result.stdout)
        return result.stdout

    def assert_clean(self, material):
        for sensitive in (self.token, self.provider_secret):
            self.assertFalse(sensitive in material, "Credential appeared in client output or fixture logs")

    def request(self, *, outer_ca=None, trust_outer=True, token=None,
                proxy_host=PROXY_HOST, **options):
        command = self.command(proxy_host=proxy_host, **options)
        harness = ["--silent", "--connect-timeout", "3", "--max-time", "8", "--resolve",
                   f"{proxy_host}:{self.outer.server_address[1]}:127.0.0.1"]
        if trust_outer:
            # Private outer CA is harness-only; public deployments use system trust.
            harness += ["--proxy-cacert", str(outer_ca or self.outer_ca[1])]
        env = {"PATH": os.environ["PATH"], "LC_ALL": "C", "CURL_HOME": str(self.directory),
               "CATCHPLATE_PROXY_TOKEN": self.token if token is None else token,
               "NO_PROXY": "*", "no_proxy": "*"}
        result = subprocess.run(["sh", "-c", command + " " + shlex.join(harness)],
                                env=env, capture_output=True, text=True, timeout=10)
        self.assert_clean(result.stdout + result.stderr)
        self.assert_clean(json.dumps(self.outer.logs + self.inner.logs))
        self.assertNotIn("unexpected fixture handler error", self.outer.logs + self.inner.logs)
        return result

    def test_valid_layers_and_credential_isolation(self):
        result = self.request()
        self.assertEqual(result.returncode, 0, "Generated curl request failed")
        self.assertEqual(result.stdout, BODY.decode())
        self.assertEqual(self.outer.events, [{
            "method": "CONNECT", "authority": f"{INNER_HOST}:{self.inner.server_address[1]}",
            "proxy_authorization_matches": True, "authorization_present": False,
            "provider_secret_present": False,
        }])
        self.assertEqual(self.inner.events, [{
            "path": "/v1/example", "proxy_authorization": False, "authorization": False,
            "client_token_present": False, "provider_secret_present": False,
            "accept": "application/json", "user_agent": None,
        }])

    def test_empty_header_policy_suppresses_implicit_curl_headers(self):
        result = self.request(allowed_headers=[])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(self.inner.events), 1)
        self.assertIsNone(self.inner.events[0]["accept"])
        self.assertIsNone(self.inner.events[0]["user_agent"])

    def test_wrong_outer_ca_stops_before_connect(self):
        result = self.request(outer_ca=self.wrong_ca[1])
        self.assertEqual(result.returncode, 60, "Outer certificate was not rejected")
        self.assertEqual(self.outer.events, [])
        self.assertEqual(self.inner.events, [])

    def test_default_trust_rejects_private_outer_ca(self):
        result = self.request(trust_outer=False)
        self.assertEqual(result.returncode, 60, "Private outer CA unexpectedly trusted")
        self.assertEqual(self.outer.events, [])
        self.assertEqual(self.inner.events, [])

    def test_wrong_outer_hostname_stops_before_connect(self):
        result = self.request(proxy_host="wrong-proxy.example.test")
        self.assertEqual(result.returncode, 60, "Outer hostname was not verified")
        self.assertEqual(self.outer.events, [])
        self.assertEqual(self.inner.events, [])

    def test_wrong_inner_ca_stops_before_http(self):
        result = self.request(inner_ca=self.wrong_ca[1])
        # Some curl/OpenSSL builds report nested TLS aborts as 35 instead of 60.
        # Require the peer's certificate-rejection alert, not just any failure.
        self.assertIn(result.returncode, (35, 60), "Inner certificate was not rejected")
        self.assertIn("TLS handshake rejected: TLSV1_ALERT_UNKNOWN_CA", self.inner.logs)
        self.assertEqual(len(self.outer.events), 1)
        self.assertTrue(self.outer.events[0]["proxy_authorization_matches"])
        self.assertEqual(self.inner.events, [])

    def test_wrong_inner_hostname_stops_before_http(self):
        result = self.request(inner_host="wrong-inner.example.test")
        self.assertEqual(result.returncode, 60, "Inner hostname was not verified")
        self.assertEqual(len(self.outer.events), 1)
        self.assertEqual(self.inner.events, [])

    def test_missing_client_token_stops_before_inner(self):
        result = self.request(token="")
        self.assertNotEqual(result.returncode, 0, "Missing client token was accepted")
        self.assertEqual(len(self.outer.events), 1)
        self.assertFalse(self.outer.events[0]["proxy_authorization_matches"])
        self.assertEqual(self.inner.events, [])


if __name__ == "__main__":
    print("Scope: local generated-client TLS fixture; no Catchplate runtime/provider acceptance.")
    unittest.main(verbosity=2)
