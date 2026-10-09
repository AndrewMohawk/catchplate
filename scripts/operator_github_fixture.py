"""Finite private GitHub REST fixture, never a GitHub service or token source.

Every resource arrival is counted before validation. Only fixed synthetic
targets, bodies and parsed header values can succeed; observations contain no
caller-supplied strings. The independent stock SDK must generate these bytes.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import time

from scripts.operator_github_fixture_network import FIXTURE_IP, assert_isolated_network, prepare_network_files

OWNER, REPO = "serverware-fixture", "operator-demo"
ORIGIN = "https://api.github.com"
BASE = f"/repos/{OWNER}/{REPO}/issues"
TOKEN = "ghp_serverware_synthetic_only_8a4671d8096a47f488aad7ee207489ab"
QUERY1 = "per_page=1&state=open&labels=fixture%2Ctriaged&page=1"
QUERY2 = "per_page=1&state=open&labels=fixture%2Ctriaged&page=2"
ISSUE_BODY = '{"title":"Synthetic fixture issue","body":"Fixture body ☃","labels":["fixture"]}'.encode()
COMMENT_BODY = b'{"body":"Synthetic fixture comment"}'
SCHEMA = "serverware.privateGithubObservations/v1"
MAX_ATTEMPTS = 24


def encoded(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def issue(number):
    return {"id": 1700 + number, "number": number, "title": f"Fixture issue {number}",
        "body": "Complete synthetic body ☃", "labels": [{"name": "fixture"}],
        "user": {"login": "fixture-user"}, "extra": {"preserved": [True, None, 7]}}


def spec(method, target, status, document, request=b"", link=None):
    return {"method": method, "target": target, "status": status, "body": encoded(document),
            "request": request, "link": link}


SPECS = {
    "page1": spec("GET", BASE + "?" + QUERY1, 200, [issue(11)],
        link=f'<{ORIGIN}/repositories/1729/issues?{QUERY2}>; rel="next"'),
    "page2": spec("GET", BASE + "?" + QUERY2, 200, [issue(12)]),
    "issue": spec("GET", BASE + "/11", 200, issue(11)),
    "comments": spec("GET", BASE + "/11/comments?per_page=1&page=1", 200,
        [{"id": 101, "body": "Fixture comment", "user": {"login": "fixture-user"}, "extra": [1, 2]}]),
    "comment": spec("GET", BASE + "/comments/101", 200,
        {"id": 101, "body": "Fixture comment", "user": {"login": "fixture-user"}, "extra": [1, 2]}),
    "create_issue": spec("POST", BASE, 201, issue(13), ISSUE_BODY),
    "create_comment": spec("POST", BASE + "/11/comments", 201,
        {"id": 103, "body": "Synthetic fixture comment", "extra": {"preserved": True}}, COMMENT_BODY),
    "not_found": spec("GET", BASE + "/404", 404,
        {"message": "Fixture issue absent", "documentation_url": "https://docs.github.com/rest/issues", "status": "404", "extra": [1, 2]}),
    "rate_limit": spec("GET", BASE + "/429", 429,
        {"message": "Fixture rate limit", "documentation_url": "https://docs.github.com/rest", "status": "429", "extra": {"retry": False}}),
    "cross_repo_link": spec("GET", BASE + "?per_page=1&labels=fixture-cross-repo&page=1", 200, [issue(11)],
        link=f'<{ORIGIN}/repos/other-owner/other-repo/issues?page=2>; rel="next"'),
    "cross_origin_link": spec("GET", BASE + "?per_page=1&labels=fixture-cross-origin&page=1", 200, [issue(11)],
        link='<https://outside.invalid/repos/serverware-fixture/operator-demo/issues?page=2>; rel="next"'),
}
RELEASE_CASES = tuple(SPECS)[:9]
BLOCK_CASES = tuple(SPECS)[9:]


def require(condition):
    if not condition:
        raise ValueError("private GitHub fixture contract refused")


def setup(root, marker):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    require(root == Path("/upstream-data/github") and not root.exists()
        and root.parent.is_dir() and root.parent.stat().st_uid == os.geteuid() == 10001)
    assert_isolated_network(attached=False)
    require(json.loads(marker.read_bytes()) == {"schema": "serverware.privateOperatorAuditFixture/v1", "syntheticOnly": True})
    now = datetime.now(timezone.utc)
    key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Private synthetic GitHub fixture CA")])
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), True).sign(key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.github.com")]))
        .issuer_name(subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("api.github.com")]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False).sign(key, hashes.SHA256()))
    ca_bytes = ca.public_bytes(serialization.Encoding.PEM)
    root.mkdir(mode=0o700)
    for name, data in {"ca.pem": ca_bytes, "cert.pem": leaf.public_bytes(serialization.Encoding.PEM),
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
        self.attempts = []
        self.total = 0
        self.timeout = 0.5


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(4)

    def send(self, status, body, extra=()):
        self.send_response_only(status)
        for name, value in (("Content-Type", "application/json; charset=utf-8"),
                ("Content-Length", str(len(body))), ("Connection", "close"), *extra):
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self):
        if self.path == "/_fixture/observations":
            self.send(200, encoded({"schema": SCHEMA, "syntheticOnly": True,
                "total": self.server.total, "attempts": deepcopy(self.server.attempts)}))
            return
        self.resource()

    def resource(self):
        self.server.total += 1
        case = next((name for name, value in SPECS.items()
                     if value["method"] == self.command and value["target"] == self.path), None)
        row = {"ordinal": self.server.total, "case": case, "accepted": False}
        if self.server.total <= MAX_ATTEMPTS:
            self.server.attempts.append(row)
        try:
            require(self.server.total <= MAX_ATTEMPTS and case is not None)
            value = SPECS[case]
            fields = [(name.lower(), content) for name, content in self.headers.raw_items()]
            require(len(fields) <= 16 and len({name for name, _ in fields}) == len(fields))
            headers = dict(fields)
            require(set(headers) <= {"host", "authorization", "accept", "user-agent", "accept-language",
                "sec-fetch-mode", "x-github-api-version", "connection", "content-length", "content-type"})
            require(headers.get("host") == "api.github.com"
                and hmac.compare_digest(headers.get("authorization", ""), "Bearer " + TOKEN)
                and headers.get("accept") == "application/vnd.github.v3+json"
                and re.fullmatch(r"serverware-test-run/operator-check-[0-9a-f]{32} octokit-rest\.js/22\.0\.1 octokit-core\.js/7\.0\.8 (?:Node\.js/25|Node\.js/25\.5\.0 \(linux; x64\))", headers.get("user-agent", ""))
                and headers.get("accept-language") == "*" and headers.get("sec-fetch-mode") == "cors"
                and headers.get("x-github-api-version", "2022-11-28") == "2022-11-28"
                and headers.get("connection", "close") in {"close", "keep-alive"})
            length = headers.get("content-length", "0")
            require(re.fullmatch(r"0|[1-9][0-9]{0,4}", length) and int(length) == len(value["request"]))
            require(headers.get("content-type") == "application/json; charset=utf-8"
                    if self.command == "POST" else "content-type" not in headers)
            body = self.rfile.read(int(length))
            require(body == value["request"])
            row.update(accepted=True, status=value["status"], requestBodySha256="sha256:" + hashlib.sha256(body).hexdigest(),
                rawTarget=value["target"], method=value["method"], allParsedHeadersValidated=True)
            extra = [("X-GitHub-Request-Id", "fixture:" + case), ("X-RateLimit-Limit", "5000"),
                ("X-RateLimit-Remaining", "0" if case == "rate_limit" else "4999"),
                ("X-RateLimit-Reset", "2000000000"), ("X-RateLimit-Resource", "core"),
                ("X-RateLimit-Used", "1"), ("ETag", '"unselected-fixture-metadata"')]
            if value["link"]:
                extra.append(("Link", value["link"]))
            if case == "rate_limit":
                extra.append(("Retry-After", "2"))
            self.send(value["status"], value["body"], extra)
        except (ValueError, OSError):
            self.send(400, b'{"message":"synthetic fixture refused"}')

    do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = resource


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--lifetime-seconds", type=int, default=240)
    args = parser.parse_args()
    if args.setup:
        signal.alarm(20)
        setup(Path("/upstream-data/github"), Path("/private-fixture.json"))
        return
    assert_isolated_network()
    require(60 <= args.lifetime_seconds <= 300)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/github/cert.pem", "/github/key.pem")
    signal.alarm(args.lifetime_seconds + 5)
    with Fixture((FIXTURE_IP, 443), context) as server:
        deadline = time.monotonic() + args.lifetime_seconds
        while time.monotonic() < deadline:
            server.handle_request()


if __name__ == "__main__":
    main()
