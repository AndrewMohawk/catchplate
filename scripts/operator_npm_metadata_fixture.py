"""Seven bounded synthetic registry responses, never an npm registry client.

Only two inert package names exist. Exact arrival order selects full/corgi
metadata and hostile responses; no mutable fixture-control API is exposed.
All arrivals count before validation, and observations exclude credentials.
"""
from __future__ import annotations

import argparse
import base64
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
import ssl
import time

from scripts.operator_npm_metadata_fixture_network import FIXTURE_IP, assert_isolated_network, prepare_network_files

ORIGIN = "https://registry.npmjs.org"
PACKAGES = ("serverware-fixture-metadata", "@serverware-fixture/metadata")
TOKEN = "npm_" + "0123456789abcdefghijklmnopqrstuvwxyz"
PLACEHOLDER = "serverware-npm-placeholder-v1"
SCHEMA = "serverware.privateNpmMetadataObservations/v1"
FULL = "application/json"
CORGI = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"
MAX_ATTEMPTS = 12


def encoded(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def path(package):
    return "/" + package.replace("/", "%2f")


def metadata(package):
    versions = {}
    for version in ("1.0.0", "2.0.0"):
        content = (package + "@" + version + ": synthetic bytes, no tarball served").encode()
        versions[version] = {"name": package, "version": version,
            "description": "Complete synthetic metadata \u2603", "main": "index.js", "license": "MIT",
            "dependencies": {"serverware-fixture-dependency": "^1.0.0"},
            "optionalDependencies": {"serverware-fixture-optional": "2.0.0"},
            "engines": {"node": ">=20"}, "fixtureExtra": {"preserved": [True, None, 7]},
            "dist": {"tarball": ORIGIN + "/" + package + "/-/metadata-" + version + ".tgz",
                "integrity": "sha512-" + base64.b64encode(hashlib.sha512(content).digest()).decode(),
                "shasum": hashlib.sha1(content).hexdigest(), "fileCount": 1, "unpackedSize": len(content)}}
    return {"_id": package, "name": package, "description": "Synthetic registry fixture",
        "dist-tags": {"latest": "2.0.0", "previous": "1.0.0"}, "versions": versions,
        "time": {"created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-02T00:00:00.000Z",
            "1.0.0": "2026-01-01T00:00:00.000Z", "2.0.0": "2026-01-02T00:00:00.000Z"},
        "maintainers": [{"name": "synthetic-maintainer"}], "license": "MIT",
        "readme": "Inert metadata fixture; installing is not supported.",
        "fixtureRootExtra": {"preserved": [False, "metadata only"]}}


def specs():
    result = []
    for client, accept in (("npm", FULL), ("pacote", CORGI)):
        for package in PACKAGES:
            result.append({"case": client + ("_scoped" if package.startswith("@") else "_unscoped"),
                "client": client, "package": package, "target": path(package), "accept": accept,
                "contentType": "application/vnd.npm.install-v1+json" if client == "pacote" else FULL,
                "status": 200, "body": encoded(metadata(package))})
    result.append({"case": "not_found", "client": "npm", "package": PACKAGES[0],
        "target": path(PACKAGES[0]), "accept": FULL, "contentType": FULL, "status": 404,
        "body": encoded({"error": "Not found", "reason": "Synthetic package temporarily absent", "fixture": True})})
    wrong = metadata(PACKAGES[0]); wrong["name"] = PACKAGES[1]
    reflection = metadata(PACKAGES[1]); reflection["fixtureReflection"] = TOKEN
    for case, package, document in (("wrong_package", PACKAGES[0], wrong),
            ("reflection", PACKAGES[1], reflection)):
        result.append({"case": case, "client": "npm", "package": package,
            "target": path(package), "accept": FULL, "contentType": FULL, "status": 200, "body": encoded(document)})
    return tuple(result)


SPECS = specs()
RELEASE_CASES = tuple(row["case"] for row in SPECS[:5])
BLOCK_CASES = ("wrong_package", "reflection")


def require(value):
    if not value:
        raise ValueError("private npm metadata fixture refused")


def validate_headers(fields, spec, *, npm_version="11.8.0", pacote_version="21.0.4"):
    require(len(fields) <= 16 and len({name for name, _ in fields}) == len(fields))
    headers = dict(fields)
    require(set(headers) <= {"host", "authorization", "accept", "user-agent", "connection",
        "content-length", "pacote-version", "pacote-req-type", "pacote-pkg-id", "npm-auth-type",
        "npm-command", "npm-scope", "npm-in-ci", "cache-control"})
    require(headers.get("host") == "registry.npmjs.org"
        and hmac.compare_digest(headers.get("authorization", ""), "Bearer " + TOKEN)
        and headers.get("accept") == spec["accept"] and headers.get("pacote-version") == pacote_version
        and headers.get("pacote-req-type") == "packument"
        and headers.get("pacote-pkg-id") == "registry:" + spec["package"]
        and headers.get("connection", "close") in {"close", "keep-alive"}
        and headers.get("content-length", "0") == "0")
    if spec["client"] == "npm":
        require(headers.get("npm-command") == "view" and headers.get("npm-auth-type") == "web"
            and re.fullmatch(r"npm/" + re.escape(npm_version) + r" node/v25\.5\.0 linux x64(?: workspaces/false)?", headers.get("user-agent", "")))
    else:
        require(headers.get("user-agent") == "pacote/" + pacote_version + " node/v25.5.0"
            and not any(key in headers for key in ("npm-command", "npm-auth-type", "npm-scope")))
    require(headers.get("cache-control") in {None, "no-cache"} and headers.get("npm-scope", "") == ""
        and headers.get("npm-in-ci") in {None, "false"})
    return {key: value for key, value in headers.items() if key not in {"authorization", "connection", "content-length"}}


def setup(root, marker):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    require(root == Path("/upstream-data/npm") and not root.exists() and not root.is_symlink()
        and root.parent.is_dir() and root.parent.stat().st_uid == os.geteuid() == 10001)
    assert_isolated_network(attached=False)
    require(json.loads(marker.read_bytes()) == {"schema": "serverware.privateOperatorAuditFixture/v1", "syntheticOnly": True})
    now = datetime.now(timezone.utc)
    key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Private synthetic npm metadata CA")])
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), True).sign(key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "registry.npmjs.org")]))
        .issuer_name(subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("registry.npmjs.org")]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False).sign(key, hashes.SHA256()))
    root.mkdir(mode=0o700)
    for name, raw in {"ca.pem": ca.public_bytes(serialization.Encoding.PEM),
            "cert.pem": leaf.public_bytes(serialization.Encoding.PEM),
            "key.pem": leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())}.items():
        descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    prepare_network_files()
    print('{"ok":true,"syntheticOnly":true,"providerContact":false}', flush=True)


class Fixture(HTTPServer):
    def __init__(self, address, context):
        super().__init__(address, Handler)
        self.socket = context.wrap_socket(self.socket, server_side=True)
        self.attempts, self.total, self.timeout = [], 0, 0.5


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def setup(self):
        super().setup(); self.connection.settimeout(4)

    def send(self, status, body, content_type=FULL):
        self.send_response_only(status)
        for name, value in (("Content-Type", content_type + "; charset=utf-8"),
                ("Content-Length", str(len(body))), ("Connection", "close"),
                ("ETag", '"discard-synthetic-metadata"'), ("Cache-Control", "max-age=600")):
            self.send_header(name, value)
        self.end_headers(); self.wfile.write(body); self.close_connection = True

    def do_GET(self):
        if self.path == "/_fixture/observations":
            self.send(200, encoded({"schema": SCHEMA, "syntheticOnly": True,
                "total": self.server.total, "attempts": deepcopy(self.server.attempts)}))
            return
        self.resource()

    def resource(self):
        self.server.total += 1
        row = {"ordinal": self.server.total, "accepted": False}
        if self.server.total <= MAX_ATTEMPTS:
            self.server.attempts.append(row)
        try:
            require(1 <= self.server.total <= len(SPECS))
            spec = SPECS[self.server.total - 1]
            require(self.command == "GET" and self.path == spec["target"])
            headers = validate_headers([(name.lower(), value) for name, value in self.headers.raw_items()], spec)
            row.update(case=spec["case"], accepted=True, method="GET", rawTarget=spec["target"],
                requestHeaders=headers, requestBodySha256=digest(b""), status=spec["status"],
                responseBodySha256=digest(spec["body"]), responseBodyBytes=len(spec["body"]),
                responseContentType=spec["contentType"],
                allParsedHeadersValidated=True)
            self.send(spec["status"], spec["body"], spec["contentType"])
        except (ValueError, OSError):
            self.send(400, b'{"error":"synthetic metadata fixture refused"}')

    do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = resource


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--lifetime-seconds", type=int, default=240)
    args = parser.parse_args()
    if args.setup:
        signal.alarm(20); setup(Path("/upstream-data/npm"), Path("/private-fixture.json")); return
    assert_isolated_network()
    require(60 <= args.lifetime_seconds <= 300)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/npm-fixture/cert.pem", "/npm-fixture/key.pem")
    signal.alarm(args.lifetime_seconds + 5)
    with Fixture((FIXTURE_IP, 443), context) as server:
        deadline = time.monotonic() + args.lifetime_seconds
        while time.monotonic() < deadline:
            server.handle_request()


if __name__ == "__main__":
    main()
