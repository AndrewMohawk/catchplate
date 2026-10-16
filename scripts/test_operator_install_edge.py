#!/usr/bin/env python3
"""Standalone edge contract; --runtime uses cached images, no host ports/providers.

The optional runtime check owns two disposable containers sharing a network-none
namespace. Its certificate, password and header token are synthetic test values.
"""
from __future__ import annotations

import base64
from contextlib import ExitStack
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest


REPO = Path(__file__).resolve().parent.parent
TEMPLATE = REPO / "docker/serverware-standalone/nginx.conf.template"
NGINX = "nginx@sha256:1ed1b0e1d7652937d6cbdaf4018c7b6fc009a7dd6c3047351e2eddda745de43f"
PYTHON = "sha256:ec7d6c95cd3692a2e2d228a8b1ca74e4025b54121fcc4c5da6f09cfa473315ad"
CONSOLE, PROXY = "console.example.test", "proxy.example.test"
ADMIN = "synthetic-edge-admin-not-a-real-secret"
PASSWORD = "synthetic-console-password"
BASIC = "Basic " + base64.b64encode(("operator:" + PASSWORD).encode()).decode()
RUNTIME = "--runtime" in sys.argv
if RUNTIME:
    sys.argv.remove("--runtime")


def render() -> str:
    text = TEMPLATE.read_text()
    for key, value in {
        "CONSOLE_HOST": CONSOLE, "PROXY_HOST": PROXY,
        "CONSOLE_HOST_REGEX": CONSOLE.replace(".", r"\."),
    }.items():
        text = text.replace("${" + key + "}", value)
    if "${" in text:
        raise AssertionError("unresolved installer placeholder")
    return text


class EdgeContract(unittest.TestCase):
    def test_closed_template_inputs_and_private_include(self):
        text = TEMPLATE.read_text()
        self.assertEqual(set(re.findall(r"\$\{([^}]+)\}", text)),
                         {"CONSOLE_HOST", "PROXY_HOST", "CONSOLE_HOST_REGEX"})
        stream, http = text.split("\nhttp {", 1)
        self.assertNotIn("operator-admin-header.conf", stream)
        self.assertEqual(http.count("include /run/serverware/operator-admin-header.conf;"), 1)
        self.assertIn("proxy_pass_request_headers off;", http)
        self.assertIn("auth_basic_user_file /run/serverware/htpasswd;", http)
        self.assertNotIn("access_log /", text)
        self.assertNotIn("$request_uri", text)
        self.assertNotIn("${", render())

    def test_no_cleartext_console_or_health_listener(self):
        text = render()
        self.assertIn("ssl_reject_handshake on;", text)
        for address in re.findall(r"^\s*listen ([^ ;]+)", text, re.MULTILINE):
            self.assertIn(address, {"8443", "127.0.0.1:8080", "127.0.0.1:8081"})
        self.assertIn("~^https://console\\.example\\.test$ same;", text)
        self.assertIn("~^(GET|HEAD|OPTIONS):(same|absent)$ 1;", text)


def command(args: list[str], *, timeout: int = 20, data: bytes | None = None,
            include_stderr: bool = False) -> bytes:
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode:
        # Never echo config contents, private fixture values or captured headers.
        raise AssertionError(f"isolated edge command failed ({args[0]}, exit {result.returncode})")
    return result.stdout + (result.stderr if include_stderr else b"")


@unittest.skipUnless(RUNTIME, "pass --runtime for the cached-image isolated check")
class EdgeRuntime(unittest.TestCase):
    def test_cached_nginx_tls_auth_origin_and_connect(self):
        command(["docker", "image", "inspect", NGINX])
        command(["docker", "image", "inspect", PYTHON])
        scratch = Path(os.environ.get("TMPDIR", "/srv/catchplate-fast/tmp"))
        with tempfile.TemporaryDirectory(prefix="serverware-edge-test.", dir=scratch) as temporary:
            root = Path(temporary)
            secrets = root / "secrets"
            secrets.mkdir(mode=0o755)
            certificate, key = secrets / "tls.crt", secrets / "tls.key"
            command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                     "-keyout", str(key), "-out", str(certificate), "-days", "1",
                     "-subj", "/CN=" + CONSOLE, "-addext",
                     "subjectAltName=DNS:" + CONSOLE + ",DNS:" + PROXY])
            digest = command(["openssl", "passwd", "-6", "-stdin"], data=PASSWORD.encode() + b"\n")
            (secrets / "htpasswd").write_bytes(b"operator:" + digest)
            (secrets / "operator-admin-header.conf").write_text(
                'proxy_set_header X-Serverware-Admin-Token "' + ADMIN + '";\n')
            config = root / "nginx.conf"
            config.write_text(render())
            hosts = root / "hosts"
            hosts.write_text("127.0.0.1 localhost serverware decision-gate-rs edge\n")
            for path in (config, hosts, *secrets.iterdir()):
                path.chmod(0o444)  # Synthetic only; enclosing host scratch remains0700.
            edge_mounts = ["--mount", f"type=bind,src={secrets},dst=/run/serverware,readonly",
                           "--mount", f"type=bind,src={config},dst=/etc/nginx/nginx.conf,readonly"]
            restricted = ["--read-only", "--cap-drop", "ALL", "--security-opt",
                          "no-new-privileges:true", "--pids-limit", "32", "--memory", "128m",
                          "--cpus", "0.5", "--user", "10001:10001"]
            temporary_fs = ["--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=8m,mode=0700,uid=10001,gid=10001"]
            # Syntax proof is network-none and does not require running backends.
            command(["docker", "run", "--rm", "--network", "none", *restricted, *temporary_fs,
                     "--add-host", "serverware:127.0.0.1", "--add-host", "decision-gate-rs:127.0.0.1",
                     *edge_mounts, "--entrypoint", "nginx", NGINX, "-t"])
            with ExitStack() as cleanup:
                fixture = command([
                    "docker", "run", "-d", "--network", "none", *restricted,
                    "--mount", f"type=bind,src={Path(__file__).resolve()},dst=/test.py,readonly",
                    "--mount", f"type=bind,src={certificate},dst=/test-ca.pem,readonly",
                    "--mount", f"type=bind,src={hosts},dst=/etc/hosts,readonly",
                    "--entrypoint", "python", PYTHON, "-I", "-B", "/test.py", "fixture",
                ]).decode().strip()
                cleanup.callback(command, ["docker", "rm", "-f", fixture])
                edge = command(["docker", "run", "-d", "--network", "container:" + fixture,
                                *restricted, *temporary_fs, *edge_mounts,
                                "--mount", f"type=bind,src={hosts},dst=/etc/hosts,readonly", "--entrypoint", "nginx",
                                NGINX, "-g", "daemon off;"]).decode().strip()
                cleanup.callback(command, ["docker", "rm", "-f", edge])
                for container in (fixture, edge):
                    inspection = json.loads(command(["docker", "inspect", container]))[0]
                    self.assertFalse(inspection["HostConfig"]["PortBindings"])
                report = json.loads(command(["docker", "exec", fixture, "python", "-I", "-B",
                                             "/test.py", "probe"], timeout=35))
                self.assertEqual(report, {"checks": 18, "ok": True})
                health = command(["docker", "exec", edge, "wget", "-qO-",
                                  "http://127.0.0.1:8081/edge-healthz"])
                self.assertIn(b"application readiness not asserted", health)
                logs = command(["docker", "logs", edge], include_stderr=True)
                for private in (ADMIN, PASSWORD, "query-canary", "caller-secret-canary"):
                    self.assertNotIn(private.encode(), logs)


class App(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        payload = json.dumps({"headers": dict(self.headers), "body": body.decode(),
                              "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    do_POST = do_GET


class Tunnel(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 8192:
            part = self.request.recv(4096)
            if not part:
                return
            head += part
        expected = (b"CONNECT fixture.invalid:443 HTTP/1.1\r\nHost: fixture.invalid:443\r\n"
                    b"Proxy-Authorization: Basic c3ludGhldGljOm9ubHk=\r\n\r\n")
        if head != expected:  # Also proves no private administrative header injected.
            return
        self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        data = self.request.recv(64)
        if data == b"synthetic-tunnel-bytes":
            self.request.sendall(data)


def fixture() -> None:
    with ThreadingHTTPServer(("0.0.0.0", 3000), App) as app, socketserver.ThreadingTCPServer(
            ("0.0.0.0", 9090), Tunnel) as tunnel:
        threading.Thread(target=tunnel.serve_forever, daemon=True).start()
        app.serve_forever()


def probe() -> None:
    context = ssl.create_default_context(cafile="/test-ca.pem")
    context.set_alpn_protocols(["http/1.1"])

    def connect(host: str | None = CONSOLE):
        raw = socket.create_connection(("edge", 8443), timeout=3)
        try:
            return context.wrap_socket(raw, server_hostname=host)
        except BaseException:
            raw.close()
            raise

    deadline = time.monotonic() + 8
    while True:
        try:
            with connect():
                break
        except (OSError, ssl.SSLError):
            if time.monotonic() >= deadline:
                raise AssertionError("isolated TLS edge did not start") from None
            time.sleep(0.1)

    def request(method="GET", headers=None, body=b"", path="/api/test"):
        selected = {"Host": CONSOLE, "Connection": "close", **(headers or {})}
        selected["Content-Length"] = str(len(body))
        wire = f"{method} {path} HTTP/1.1\r\n".encode()
        wire += "".join(f"{k}: {v}\r\n" for k, v in selected.items()).encode() + b"\r\n" + body
        with connect() as stream:
            stream.sendall(wire)
            response = http.client.HTTPResponse(stream)
            response.begin()
            data = response.read(16384)
            if len(data) == 16384:
                raise AssertionError("unbounded fixture response")
            return response.status, data

    checks = 0
    for hostname in ("unknown.example.test", None):
        context.check_hostname = hostname is not None
        try:
            with connect(hostname):
                raise AssertionError("unknown SNI accepted")
        except ssl.SSLError:
            checks += 1
        finally:
            context.check_hostname = True
    for headers in ({}, {"Authorization": "Basic bm9wZTpub3Bl"}):
        assert request(headers=headers)[0] == 401
        checks += 1
    for method, origin in (("GET", "https://foreign.example.test"), ("GET", "null"),
                           ("GET", "https://CONSOLE.example.test"), ("POST", None),
                           ("POST", "https://foreign.example.test")):
        headers = {"Authorization": BASIC}
        if origin is not None:
            headers["Origin"] = origin
        assert request(method, headers)[0] == 403
        checks += 1
    for host in (PROXY, CONSOLE + ":444"):
        assert request(headers={"Authorization": BASIC, "Host": host})[0] == 403
        checks += 1
    headers = {
        "Authorization": BASIC, "Proxy-Authorization": "caller-secret-canary",
        "X-Serverware-Admin-Token": "caller-secret-canary",
        "X-Serverware-Bootstrap-Token": "caller-secret-canary",
        "X-Serverware-Data-Plane-Token": "caller-secret-canary",
        "Forwarded": "host=foreign.example.test", "X-Forwarded-For": "192.0.2.1",
        "X-Forwarded-Host": "foreign.example.test", "X-Forwarded-Proto": "http",
        "X-Forwarded-Port": "1234", "Remote-User": "caller-secret-canary",
        "Cookie": "ordinary=retained", "Accept": "application/json",
    }
    status, data = request(headers=headers, path="/api/test?query-canary=1")
    assert status == 200
    observed = json.loads(data)
    received = {key.lower(): value for key, value in observed["headers"].items()}
    assert received["x-serverware-admin-token"] == ADMIN
    assert received["host"] == received["x-forwarded-host"] == CONSOLE
    assert received["x-forwarded-proto"] == "https" and received["x-forwarded-port"] == "443"
    assert received["cookie"] == "ordinary=retained"
    for name in ("authorization", "proxy-authorization", "forwarded", "x-forwarded-for",
                 "remote-user", "x-serverware-bootstrap-token", "x-serverware-data-plane-token"):
        assert name not in received
    assert "caller-secret-canary" not in data.decode()
    assert observed["path"] == "/api/test?query-canary=1"
    checks += 1
    body = b'{"synthetic":"unchanged"}'
    status, data = request("POST", {"Authorization": BASIC, "Origin": "https://" + CONSOLE,
                                   "Content-Type": "application/json", "X-Serverware-CSRF-Token": "test"}, body)
    assert status == 200 and json.loads(data)["body"].encode() == body
    checks += 1
    assert request(headers={"Authorization": BASIC, "Host": CONSOLE + ":443"})[0] == 200
    checks += 1
    assert request(path="/edge-healthz")[0] == 401
    checks += 1
    with connect(PROXY) as stream:
        stream.sendall(b"CONNECT fixture.invalid:443 HTTP/1.1\r\nHost: fixture.invalid:443\r\n"
                       b"Proxy-Authorization: Basic c3ludGhldGljOm9ubHk=\r\n\r\n")
        reply = b""
        while b"\r\n\r\n" not in reply and len(reply) < 1024:
            part = stream.recv(1024)
            assert part
            reply += part
        assert reply == b"HTTP/1.1 200 Connection Established\r\n\r\n"
        stream.sendall(b"synthetic-tunnel-bytes")
        assert stream.recv(64) == b"synthetic-tunnel-bytes"
    checks += 1
    for port in (8080, 8081):
        listeners = [row.split()[1] for row in Path("/proc/net/tcp").read_text().splitlines()[1:]
                     if row.split()[3] == "0A" and row.split()[1].endswith(f":{port:04X}")]
        assert listeners == [f"0100007F:{port:04X}"], "listener is not loopback-only"
        checks += 1
    print(json.dumps({"checks": checks, "ok": True}))


if __name__ == "__main__":
    if sys.argv[1:] == ["fixture"]:
        fixture()
    elif sys.argv[1:] == ["probe"]:
        probe()
    else:
        unittest.main()
