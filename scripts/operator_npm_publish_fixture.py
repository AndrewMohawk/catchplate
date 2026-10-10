"""Finite synthetic HTTPS registry for stock npm publish, with independent storage.

No external contact, mutable control endpoint, production adapter import or
tarball extraction. Every registry arrival is counted before admission. Only
two exact PUTs may store immutable versions; every other method/path refuses.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from copy import deepcopy
import gzip
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import math
import os
from pathlib import Path
import re
import signal
import ssl
import sys
import tarfile
import time

from scripts import operator_npm_metadata_fixture as metadata
from scripts.operator_npm_metadata_fixture_network import FIXTURE_IP, assert_isolated_network

ORIGIN, TOKEN, PLACEHOLDER = metadata.ORIGIN, metadata.TOKEN, metadata.PLACEHOLDER
SCHEMA = "serverware.privateNpmPublishObservations/v1"
PACKAGES = ("serverware-fixture-publish", "@serverware-fixture/publish")
TAG = "fixture"
MAX_BODY, MAX_ATTEMPTS = 65536, 16
CASES = (
    ("prerequisite", PACKAGES[0], "1.0.1", False),
    ("unscoped", PACKAGES[0], "2.0.0", True),
    ("scoped", PACKAGES[1], "3.0.0", True),
    ("wrong_package", "serverware-fixture-forbidden", "4.0.0", False),
    ("outside_window", PACKAGES[0], "5.0.0", False),
    ("wrong_placeholder", PACKAGES[0], "6.0.0", False),
    ("revoked_app", PACKAGES[1], "7.0.0", False),
)
SPECS = tuple({"case": case, "package": package, "version": version, "success": success}
    for case, package, version, success in CASES)
ARRIVALS = (("prerequisite", "GET"), ("unscoped", "GET"), ("unscoped", "PUT"),
    ("scoped", "GET"), ("scoped", "PUT"), ("outside_window", "GET"))
FULL, CORGI = metadata.FULL, metadata.CORGI
encoded, digest, path = metadata.encoded, metadata.digest, metadata.path
REFUSAL_SCHEMA = "serverware.privateNpmPublishRefusal/v1"
REFUSAL_STAGES = frozenset({"sequence", "target", "framing", "headers", "publish_identity",
    "publish_manifest", "publish_attachment", "publish_integrity", "storage", "response"})
REFUSAL_METHODS = frozenset({"GET", "PUT", "POST", "PATCH", "DELETE", "HEAD", "OPTIONS"})
REFUSAL_ERRORS = frozenset({"ValueError", "OSError", "TypeError", "KeyError"})


def _error_class(error):
    for kind in (KeyError, OSError, TypeError, ValueError):
        if isinstance(error, kind):
            return kind.__name__
    return None


class FixtureRefusal(ValueError):
    """Only a closed diagnostic stage, never a request or exception value."""
    def __init__(self, stage, error):
        self.stage, self.error_class = stage, _error_class(error)
        super().__init__("private npm publish fixture refused")


@contextmanager
def _refusal_stage(stage):
    try:
        yield
    except (ValueError, OSError, TypeError, KeyError) as error:
        raise FixtureRefusal(stage, error) from None


def refusal_observation(ordinal, expected_case, expected_method, actual_method, stage, error):
    """Bounded refusal metadata; no request strings or exception text escape."""
    if type(error) is FixtureRefusal:
        stage, error_class = error.stage, error.error_class
    else:
        error_class = _error_class(error)
    if (type(ordinal) is not int or not 1 <= ordinal <= MAX_ATTEMPTS
            or not isinstance(stage, str) or stage not in REFUSAL_STAGES
            or not isinstance(error_class, str) or error_class not in REFUSAL_ERRORS):
        return None
    expected = ARRIVALS[ordinal - 1] if ordinal <= len(ARRIVALS) else (None, None)
    if (expected_case, expected_method) != expected:
        return None
    return {"schema": REFUSAL_SCHEMA, "ordinal": ordinal, "expectedCase": expected[0],
        "expectedMethod": expected[1], "actualMethod": actual_method
            if isinstance(actual_method, str) and actual_method in REFUSAL_METHODS else "other",
        "stage": stage, "errorClass": error_class}


def emit_refusal(ordinal, expected_case, expected_method, actual_method, stage, error):
    # Diagnostics are not part of admission or storage. A broken log sink must
    # not alter the existing fixed refusal response or produce raw error text.
    try:
        record = refusal_observation(ordinal, expected_case, expected_method, actual_method, stage, error)
        if record is not None:
            sys.stderr.write(encoded(record).decode("utf-8") + "\n")
            sys.stderr.flush()
    except Exception:
        pass


def require(value):
    if not value:
        raise ValueError("private npm publish fixture refused")


def spec_for(case):
    return next(item for item in SPECS if item["case"] == case)


def tarball(spec):
    """Reproducible inert package: no scripts, dependencies or publishConfig."""
    manifest = encoded({"name": spec["package"], "version": spec["version"],
        "description": "Synthetic publication fixture", "license": "MIT", "main": "index.js"}) + b"\n"
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w", format=tarfile.USTAR_FORMAT) as stream:
        for name, body in (("package/package.json", manifest),
                ("package/index.js", b"module.exports = 'inert synthetic package';\n")):
            member = tarfile.TarInfo(name)
            member.size, member.mode, member.mtime = len(body), 0o644, 0
            stream.addfile(member, io.BytesIO(body))
    output = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as stream:
        stream.write(archive.getvalue())
    result = output.getvalue()
    require(0 < len(result) < 32768)
    return result


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    def number(value):
        result = float(value)
        require(math.isfinite(result))
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_float=number,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def validate_publish(raw, spec):
    """Independent receiver oracle, not the production publish decoder."""
    with _refusal_stage("publish_identity"):
        require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_BODY)
        document = strict_json(raw)
        package, version = spec["package"], spec["version"]
        require(isinstance(document, dict) and set(document) ==
            {"_id", "name", "description", "dist-tags", "versions", "access", "_attachments"})
        require(document["_id"] == document["name"] == package
            and document["description"] == "Synthetic publication fixture"
            and document["access"] == "public" and document["dist-tags"] == {TAG: version}
            and isinstance(document["versions"], dict) and set(document["versions"]) == {version})
    with _refusal_stage("publish_manifest"):
        manifest = document["versions"][version]
        require(isinstance(manifest, dict) and manifest.get("name") == package
            and manifest.get("version") == version and manifest.get("_id") == package + "@" + version
            and manifest.get("_nodeVersion") == "25.5.0" and manifest.get("_npmVersion") == "11.8.0"
            and not any(key in manifest for key in ("scripts", "dependencies", "publishConfig", "tag")))
    with _refusal_stage("publish_attachment"):
        name = package + "-" + version + ".tgz"
        require(isinstance(document["_attachments"], dict) and set(document["_attachments"]) == {name})
        attachment = document["_attachments"][name]
        require(isinstance(attachment, dict) and set(attachment) == {"content_type", "data", "length"}
            and attachment["content_type"] == "application/octet-stream" and isinstance(attachment["data"], str)
            and type(attachment["length"]) is int)
        payload = base64.b64decode(attachment["data"], validate=True)
        require(payload == tarball(spec) and attachment["length"] == len(payload)
            and base64.b64encode(payload).decode("ascii") == attachment["data"])
    with _refusal_stage("publish_integrity"):
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode("ascii")
        shasum = hashlib.sha1(payload).hexdigest()
        dist = manifest.get("dist")
        require(isinstance(dist, dict) and set(dist) == {"integrity", "shasum", "tarball"}
            and dist.get("integrity") == integrity and dist.get("shasum") == shasum
            and dist.get("tarball") == "http://registry.npmjs.org/" + package + "/-/" + name)
    return {"package": package, "version": version, "tag": TAG, "attachmentName": name,
        "attachmentBytes": len(payload), "tarballSha256": digest(payload),
        "tarballIntegrity": integrity, "tarballShasum": shasum}, manifest, payload


def validate_headers(fields, method, package, body_length):
    require(len(fields) <= 20 and len({name for name, _ in fields}) == len(fields))
    headers = dict(fields)
    common = {"host", "authorization", "accept", "user-agent", "connection", "content-length",
        "npm-auth-type", "npm-command", "npm-scope", "npm-in-ci"}
    allowed = common | ({"pacote-version", "pacote-req-type", "pacote-pkg-id", "cache-control"}
        if method == "GET" else {"content-type"})
    require(set(headers) <= allowed and headers.get("host") == "registry.npmjs.org"
        and hmac.compare_digest(headers.get("authorization", ""), "Bearer " + TOKEN)
        and headers.get("npm-command") == "publish" and headers.get("npm-auth-type", "web") == "web"
        and headers.get("connection", "close") in {"close", "keep-alive"}
        and headers.get("content-length", "0") == str(body_length)
        and headers.get("npm-scope", "") == "" and headers.get("npm-in-ci") in {None, "false"}
        and re.fullmatch(r"npm/11\.8\.0 node/v25\.5\.0 linux x64(?: workspaces/false)?", headers.get("user-agent", "")))
    if method == "GET":
        require(body_length == 0 and headers.get("accept") == CORGI
            and headers.get("pacote-version") == "21.0.4" and headers.get("pacote-req-type") == "packument"
            and headers.get("pacote-pkg-id") == "registry:" + package
            and headers.get("cache-control") in {None, "no-cache"})
    else:
        require(method == "PUT" and headers.get("accept") == "*/*" and headers.get("content-type") == FULL)
    # Omit receiver framing, transport and replaced credentials from this
    # projection. The checker independently reconstructs canonical-v2 PUT
    # Content-Length from the observed body bytes; empty stock GETs omit it.
    return {key: value for key, value in headers.items()
        if key not in {"authorization", "connection", "content-length", "cache-control"}}


def packument(package, stored):
    versions = {row["version"]: {"name": package, "version": row["version"]}
        for row in stored if row["package"] == package}
    return {"_id": package, "name": package, "dist-tags":
        {TAG: next(reversed(versions))} if versions else {}, "versions": versions}


def save_new(pathname, body):
    descriptor = os.open(pathname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(body); stream.flush(); os.fsync(stream.fileno())


def setup():
    metadata.setup(Path("/upstream-data/npm"), Path("/private-fixture.json"))
    packages = Path("/upstream-data/npm/packages"); packages.mkdir(mode=0o700)
    for spec in SPECS:
        save_new(packages / (spec["case"] + ".tgz"), tarball(spec))
    Path("/upstream-data/npm-publish-state").mkdir(mode=0o700)


class Fixture(HTTPServer):
    def __init__(self, address, context):
        super().__init__(address, Handler)
        self.socket = context.wrap_socket(self.socket, server_side=True)
        self.total, self.attempts, self.stored, self.timeout = 0, [], [], 0.5


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def setup(self):
        super().setup(); self.connection.settimeout(4)

    def send(self, status, body, content_type=FULL):
        self.send_response_only(status)
        for name, value in (("Content-Type", content_type), ("Content-Length", str(len(body))), ("Connection", "close")):
            self.send_header(name, value)
        self.end_headers(); self.wfile.write(body); self.close_connection = True

    def do_GET(self):
        if self.path == "/_fixture/observations":
            # Re-read committed bytes rather than echoing a client success report.
            require({item.name for item in Path("/npm-state").iterdir()} ==
                {row["case"] + suffix for row in self.server.stored for suffix in (".tgz", ".json")})
            for row in self.server.stored:
                require(digest((Path("/npm-state") / (row["case"] + ".tgz")).read_bytes()) == row["tarballSha256"]
                    and strict_json((Path("/npm-state") / (row["case"] + ".json")).read_bytes()) == row)
            self.send(200, encoded({"schema": SCHEMA, "syntheticOnly": True, "total": self.server.total,
                "attempts": deepcopy(self.server.attempts), "stored": deepcopy(self.server.stored)}))
        else:
            self.resource()

    def resource(self):
        self.server.total += 1
        row = {"ordinal": self.server.total, "accepted": False}
        if self.server.total <= MAX_ATTEMPTS:
            self.server.attempts.append(row)
        stage = "sequence"
        case, method = ARRIVALS[self.server.total - 1] if 1 <= self.server.total <= len(ARRIVALS) else (None, None)
        try:
            require(1 <= self.server.total <= len(ARRIVALS))
            case, method = ARRIVALS[self.server.total - 1]
            spec = spec_for(case)
            stage = "target"
            require(self.command == method and self.path == path(spec["package"]))
            stage = "framing"
            length = self.headers.get("content-length", "0")
            require(re.fullmatch(r"0|[1-9][0-9]{0,5}", length) and int(length) <= MAX_BODY)
            raw = self.rfile.read(int(length))
            require(len(raw) == int(length))
            stage = "headers"
            headers = validate_headers([(name.lower(), value) for name, value in self.headers.raw_items()], method, spec["package"], len(raw))
            if method == "GET":
                status, content_type = 200, "application/vnd.npm.install-v1+json"
                response = encoded(packument(spec["package"], self.server.stored))
                operation = {"operation": "npm.metadata.read", "package": spec["package"]}
            else:
                stored, _, payload = validate_publish(raw, spec)
                stage = "storage"
                require(not any(old["package"] == stored["package"] and old["version"] == stored["version"] for old in self.server.stored))
                stored.update(case=case)
                save_new(Path("/npm-state") / (case + ".tgz"), payload)
                save_new(Path("/npm-state") / (case + ".json"), encoded(stored))
                directory = os.open("/npm-state", os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                self.server.stored.append(stored)
                status, content_type = 201, FULL
                response = encoded({"ok": True, "id": spec["package"], "rev": "fixture-" + spec["version"]})
                operation = {"operation": "npm.publish", "packageName": stored["package"], "packageVersion": stored["version"],
                    "tag": TAG, "tarballIntegrity": stored["tarballIntegrity"], "tarballShasum": stored["tarballShasum"],
                    "attachmentName": stored["attachmentName"], "attachmentBytes": str(stored["attachmentBytes"])}
            row.update(case=case, method=method, rawTarget=self.path, accepted=True, requestHeaders=headers,
                requestBodySha256=digest(raw), requestBodyBytes=len(raw), operation=operation,
                status=status, responseContentType=content_type, responseBodySha256=digest(response),
                responseBodyBytes=len(response), allParsedHeadersValidated=True)
            stage = "response"
            self.send(status, response, content_type)
        except (ValueError, OSError, TypeError, KeyError) as error:
            emit_refusal(self.server.total, case, method, self.command, stage, error)
            self.send(400, b'{"error":"synthetic publish fixture refused"}')

    do_PUT = do_POST = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = resource


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--lifetime-seconds", type=int, default=300)
    args = parser.parse_args(); os.umask(0o077)
    if args.setup:
        signal.alarm(20); setup(); return
    assert_isolated_network()
    require(os.geteuid() == 10001 and 60 <= args.lifetime_seconds <= 300
        and Path("/npm-state").is_dir() and not list(Path("/npm-state").iterdir()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/npm-fixture/cert.pem", "/npm-fixture/key.pem")
    signal.alarm(args.lifetime_seconds + 5)
    with Fixture((FIXTURE_IP, 443), context) as server:
        deadline = time.monotonic() + args.lifetime_seconds
        while time.monotonic() < deadline:
            server.handle_request()


if __name__ == "__main__":
    main()
