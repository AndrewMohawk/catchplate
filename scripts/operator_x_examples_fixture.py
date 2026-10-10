"""Closed isolated X SDK receiver and fresh api.x.com PKI; no real provider.

Three unmodified SDK requests and five explicitly separate raw-response probes
share one exact target. Probe selection uses only fixed user-agent values, never
a mutable control endpoint or an expanded production request-header profile.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from http.server import HTTPServer
import os
from pathlib import Path
import signal
import ssl
import time

from scripts import operator_github_fixture as base
from scripts.operator_x_fixture_network import FIXTURE_IP, assert_isolated_network, prepare_network_files

SCHEMA = "serverware.privateXExampleObservations/v1"
CLIENTS = ("node", "python", "go")
CASES = ("success", "error429", "oversize", "error-oversize", "reflection", "invalid-json")
MAX_ATTEMPTS = 16
ORIGIN, USERNAME = "https://api.x.com", "example_user"
TARGET = "/2/users/by/username/" + USERNAME
TOKEN = "serverware_x_synthetic_only_8a4671d8096a47f488aad7ee207489ab"
USER = {"id": "123456789", "username": "Example_User", "name": "Synthetic X fixture user"}
MEDIA = {"node": "application/json", "python": "*/*", "go": "application/json", "probe": "application/json"}
AGENTS = {"node": "xdk-typescript/0.6.6", "python": "xdk-python/0.10.6", "go": "Go-http-client/1.1"}
ROW_KEYS = {"ordinal", "accepted", "client", "case", "method", "target", "semanticHeaders",
    "requestBodySha256", "responseBodySha256", "responseBodyBytes", "status",
    "providerCredentialMatched", "proxyAuthorizationPresent", "allParsedHeadersValidated"}


def require(condition):
    if not condition:
        raise ValueError("private X examples fixture refused")


def body(case="success"):
    require(type(case) is str and case in CASES)
    if case == "success":
        return base.encoded({"data": USER})
    if case == "error429":
        return base.encoded({"title": "Too Many Requests", "detail": "Synthetic fixture rate limit", "status": 429})
    if case in {"oversize", "error-oversize"}:
        size = 1048577 if case == "oversize" else 65537
        prefix, suffix = b'{"padding":"', b'"}'
        return prefix + b"x" * (size - len(prefix) - len(suffix)) + suffix
    if case == "reflection":
        return base.encoded({"data": USER, "unselected": {"credential": TOKEN}})
    return b'{"data":'


def status(case="success"):
    require(type(case) is str and case in CASES)
    return 429 if case in {"error429", "error-oversize"} else 200


def classify(method, raw_target, fields):
    require(method == "GET" and raw_target == TARGET)
    agents = [value for name, value in fields if name.lower() == "user-agent"]
    require(len(agents) == 1)
    for client, expected in AGENTS.items():
        if agents[0] == expected:
            return client, "success"
    for case in CASES[1:]:
        if agents[0] == "serverware-x-probe/" + case:
            return "probe", case
    raise ValueError("private X client fingerprint refused")


def validated_headers(client, fields, case="success"):
    require(client in (*CLIENTS, "probe") and type(case) is str and case in CASES
        and (case != "success") == (client == "probe") and len(fields) <= 12)
    require(all(type(name) is str and type(value) is str and name.isascii() and value.isascii()
        and 0 < len(name) <= 64 and 0 < len(value) <= 8192 for name, value in fields))
    fields = [(name.lower(), value) for name, value in fields]
    require(len({name for name, _ in fields}) == len(fields))
    headers = dict(fields)
    required = {"host", "authorization", "accept", "user-agent"}
    if client == "node":
        required.update(("content-type", "accept-language", "sec-fetch-mode"))
    require(required <= headers.keys() <= required | {"connection"}
        and headers["host"] == "api.x.com"
        and hmac.compare_digest(headers["authorization"], "Bearer " + TOKEN)
        and headers["accept"] == MEDIA[client]
        and headers["user-agent"] == ("serverware-x-probe/" + case if client == "probe" else AGENTS[client])
        and headers.get("connection", "close") in {"close", "keep-alive"})
    semantic = {"accept", "user-agent"}
    if client == "node":
        require(headers["content-type"] == "application/json"
            and headers["accept-language"] == "*" and headers["sec-fetch-mode"] == "cors")
        semantic.update(("content-type", "accept-language", "sec-fetch-mode"))
    return {name: headers[name] for name in sorted(semantic)}


def setup(root, marker):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    import json

    require(root == Path("/upstream-data/x") and not root.exists() and not root.is_symlink()
        and root.parent.is_dir() and root.parent.stat().st_uid == os.geteuid() == 10001)
    assert_isolated_network(attached=False)
    require(json.loads(marker.read_bytes()) == {"schema": "serverware.privateOperatorAuditFixture/v1", "syntheticOnly": True})
    now = datetime.now(timezone.utc)
    key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Private synthetic X fixture CA")])
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), True).sign(key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.x.com")]))
        .issuer_name(subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("api.x.com")]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False).sign(key, hashes.SHA256()))
    root.mkdir(mode=0o700)
    for name, data in {"ca.pem": ca.public_bytes(serialization.Encoding.PEM),
            "cert.pem": leaf.public_bytes(serialization.Encoding.PEM),
            "key.pem": leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption())}.items():
        descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    prepare_network_files()
    print('{"ok":true,"syntheticOnly":true,"providerContact":false}', flush=True)


class Fixture(HTTPServer):
    def __init__(self, address, context):
        super().__init__(address, Handler)
        self.socket = context.wrap_socket(self.socket, server_side=True)
        self.attempts, self.total, self.timeout = [], 0, 0.5


class Handler(base.Handler):
    def record_arrival(self):
        if getattr(self, "arrival", None) is None:
            self.server.total += 1
            self.arrival = {"ordinal": self.server.total, "accepted": False}
            if self.server.total <= MAX_ATTEMPTS:
                self.server.attempts.append(self.arrival)
        return self.arrival

    def parse_request(self):
        self.arrival = None
        row = self.record_arrival()
        parsed = super().parse_request()
        # Count before parsing/admission, including malformed requests and
        # unsupported verbs. This HTTPServer is single-threaded: only a parsed
        # private observation GET removes its own provisional final row.
        if parsed and self.command == "GET" and self.path == "/_fixture/observations":
            if row["ordinal"] <= MAX_ATTEMPTS:
                require(self.server.attempts[-1] is row)
                self.server.attempts.pop()
            self.server.total -= 1
            self.arrival = None
        return parsed

    def send_error(self, code, message=None, explain=None):
        self.send(400, b'{"message":"synthetic X fixture refused"}')

    def do_GET(self):
        if self.path == "/_fixture/observations":
            self.send(200, base.encoded({"schema": SCHEMA, "syntheticOnly": True,
                "total": self.server.total, "attempts": deepcopy(self.server.attempts)}))
            return
        self.resource()

    def resource(self):
        row = self.record_arrival()
        try:
            require(self.server.total <= MAX_ATTEMPTS)
            fields = list(self.headers.raw_items())
            client, case = classify(self.command, self.path, fields)
            semantic = validated_headers(client, fields, case)
            response = body(case)
            row.update(client=client, case=case, accepted=True, method="GET", target=TARGET,
                semanticHeaders=semantic, requestBodySha256="sha256:" + hashlib.sha256(b"").hexdigest(),
                responseBodySha256="sha256:" + hashlib.sha256(response).hexdigest(),
                responseBodyBytes=len(response), status=status(case), providerCredentialMatched=True,
                proxyAuthorizationPresent=False, allParsedHeadersValidated=True)
            self.send(status(case), response)
        except (ValueError, OSError):
            self.send(400, b'{"message":"synthetic X fixture refused"}')

    do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = resource


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--lifetime-seconds", type=int, default=300)
    args = parser.parse_args()
    if args.setup:
        signal.alarm(20)
        setup(Path("/upstream-data/x"), Path("/private-fixture.json"))
        return
    assert_isolated_network()
    require(60 <= args.lifetime_seconds <= 300)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/x/cert.pem", "/x/key.pem")
    signal.alarm(args.lifetime_seconds + 5)
    with Fixture((FIXTURE_IP, 443), context) as server:
        deadline = time.monotonic() + args.lifetime_seconds
        while time.monotonic() < deadline:
            server.handle_request()


if __name__ == "__main__":
    main()
