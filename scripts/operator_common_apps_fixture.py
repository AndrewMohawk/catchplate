"""Three fixed synthetic providers in the existing network-none test namespace.

No real DNS, provider traffic, credentials, or general-purpose echo endpoint.
The existing GitHub namespace helper owns the single public-looking loopback
address; the ordinary guided fixture still supplies the proxy and empty store.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import signal
import ssl
import time

from scripts import operator_github_fixture_network as isolated
from scripts import operator_guided_fixture_network as guided

PROVIDERS = ("api.openai.com", "api.anthropic.com", "discord.com")
HOSTS = (guided.HOSTS + (isolated.FIXTURE_IP + " api.github.com " + " ".join(PROVIDERS) + "\n").encode())
TOKEN = "synthetic-common-apps-credential-not-a-real-provider-token"
MODEL, CHANNEL = "fixture-model", "123456789012345678"
SPECS = {
    "openai": {"host": PROVIDERS[0], "path": "/v1/responses", "operation": "responses_text_v1",
        "header": "Authorization", "placeholder": "Bearer serverware-openai-placeholder-v1",
        "injected": "Bearer " + TOKEN, "body": {"model": MODEL, "input": "Hi",
            "max_output_tokens": 16, "stream": False, "store": False}},
    "anthropic": {"host": PROVIDERS[1], "path": "/v1/messages", "operation": "messages_text_v1",
        "header": "x-api-key", "placeholder": "serverware-anthropic-placeholder-v1", "injected": TOKEN,
        "body": {"model": MODEL, "messages": [{"role": "user", "content": "Hi"}],
            "max_tokens": 16, "stream": False}},
    "discord": {"host": PROVIDERS[2], "path": "/api/v10/channels/" + CHANNEL + "/messages",
        "operation": "create_message", "header": "Authorization",
        "placeholder": "Bot serverware-discord-placeholder-v1", "injected": "Bot " + TOKEN,
        "body": {"content": "Deployment completed.", "allowed_mentions": {"parse": []}}},
}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def configure_network():
    isolated.HOSTS, isolated.PROXY_HOST = HOSTS, guided.PROXY_HOST
    guided.HOSTS = HOSTS


def assert_isolated():
    configure_network()
    isolated.assert_isolated_network()
    import socket
    for host in PROVIDERS:
        assert {row[4][0] for row in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)} == {isolated.FIXTURE_IP}


def setup():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    assert os.geteuid() == 10001
    isolated.assert_isolated_network(attached=False)
    configure_network()
    guided.prepare_files()
    root = Path("/upstream-data/demo-upstream")
    assert root.is_dir() and not list(root.iterdir())
    now = datetime.now(timezone.utc)
    key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic common apps fixture CA")])
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), True).sign(key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host) for host in PROVIDERS]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False).sign(key, hashes.SHA256()))
    for name, raw in {"ca.pem": ca.public_bytes(serialization.Encoding.PEM),
        "cert.pem": leaf.public_bytes(serialization.Encoding.PEM),
        "key.pem": leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())}.items():
        guided.write_once(root / name, raw)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(4)

    def send(self, status, value):
        body = encoded(value)
        self.send_response_only(status)
        for key, value in (("Content-Type", "application/json"), ("Content-Length", str(len(body))), ("Connection", "close")):
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self):
        if self.path == "/_fixture/observations":
            return self.send(200, {"total": self.server.total, "attempts": self.server.attempts})
        self.do_POST()

    def do_POST(self):
        self.server.total += 1
        name = next((name for name, spec in SPECS.items()
            if self.headers.get("Host") == spec["host"] and self.path == spec["path"]), None)
        row = {"case": name, "accepted": False}
        if self.server.total <= 12:
            self.server.attempts.append(row)
        try:
            assert self.command == "POST" and name is not None and self.server.total <= 12
            spec = SPECS[name]
            fields = [(key.lower(), value) for key, value in self.headers.raw_items()]
            assert len(fields) <= 12 and len(dict(fields)) == len(fields)
            headers = dict(fields)
            expected = {"host", "content-type", "content-length", "accept", "user-agent", spec["header"].lower()}
            if name == "anthropic":
                expected.add("anthropic-version")
                assert headers.get("anthropic-version") == "2023-06-01"
            assert expected <= set(headers) <= expected | {"connection", "accept-encoding"}
            assert headers[spec["header"].lower()] == spec["injected"]
            assert headers["accept"] == "application/json" and headers["content-type"] == "application/json"
            assert headers.get("accept-encoding", "identity") == "identity"
            assert headers.get("connection", "close") in {"close", "keep-alive"}
            assert headers["user-agent"] == "serverware-common-apps-fixture/1"
            expected_body = encoded(spec["body"])
            assert headers["content-length"] == str(len(expected_body))
            raw = self.rfile.read(len(expected_body))
            assert raw == expected_body
            row.update(accepted=True, authStyle={"openai": "Bearer", "anthropic": "x-api-key", "discord": "Bot"}[name],
                bodySha256="sha256:" + hashlib.sha256(raw).hexdigest())
            self.send(200, {"synthetic": True, "provider": name, "result": "fixed fixture response"})
        except (AssertionError, ValueError, OSError):
            self.send(400, {"error": "synthetic_provider_rejected"})


def serve():
    assert_isolated()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/data/demo-upstream/cert.pem", "/data/demo-upstream/key.pem")
    signal.alarm(300)
    with HTTPServer((isolated.FIXTURE_IP, 443), Handler) as server:
        server.total, server.attempts, server.timeout = 0, [], 0.5
        server.socket = context.wrap_socket(server.socket, server_side=True)
        until = time.monotonic() + 290
        while time.monotonic() < until:
            server.handle_request()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("setup", "network", "edge", "provider"))
    selected = parser.parse_args().operation
    os.umask(0o077)
    configure_network()
    if selected == "setup":
        signal.alarm(20)
        setup()
    elif selected == "network":
        isolated.keep_namespace()
    elif selected == "edge":
        guided.edge()
    else:
        serve()
