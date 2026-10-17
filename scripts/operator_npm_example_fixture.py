"""Fixed synthetic registry scenario for the actual npm-registry example.

Reuses the separately tested metadata/publish validators, deterministic inert
tarballs, exclusive storage and isolated HTTPS setup. No registry client, SDK
rewrite or mutable control endpoint is added. The original publication phases
remain unchanged; one explicit dependency publication feeds install and cold
ci. Twenty-five arrivals are permitted, including a deliberately failed audit.
Stored tarball bytes are independently re-read, never inferred from npm exit.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import gzip
import hashlib
import hmac
from http.server import HTTPServer
import io
import os
from pathlib import Path
import re
import signal
import ssl
import sys
import tarfile
import time
import zlib

from scripts import operator_npm_metadata_fixture as metadata
from scripts import operator_npm_publish_fixture as publish
from scripts.operator_npm_metadata_fixture_network import FIXTURE_IP, assert_isolated_network


ORIGIN, TOKEN, PLACEHOLDER = publish.ORIGIN, publish.TOKEN, publish.PLACEHOLDER
PACKAGES, TAG = publish.PACKAGES, publish.TAG
FORBIDDEN_PACKAGE = publish.spec_for("wrong_package")["package"]
FULL, CORGI = metadata.FULL, metadata.CORGI
MAX_BODY, MAX_ATTEMPTS = publish.MAX_BODY, 32
SCHEMA = "catchplate.privateNpmExampleObservations/v1"
REFUSAL_SCHEMA = "catchplate.privateNpmExampleRefusal/v1"
encoded, digest, path = metadata.encoded, metadata.digest, metadata.path
require, save_new = publish.require, publish.save_new
INSTALL_CASES = ("install_published", "ci_published", "install_audit_negative")
TOP_VERSION, LEAF_VERSION = "1.0.2", "3.0.0"
AUDIT_PATH = "/-/npm/v1/security/advisories/bulk"

_PHASES = (
    ("view_unscoped", "view", PACKAGES[0], "1.0.0", True, "outside"),
    ("view_scoped", "view", PACKAGES[1], "1.0.0", True, "scoped"),
    ("manifest_unscoped", "manifest", PACKAGES[0], "1.0.0", True, "outside"),
    ("manifest_scoped", "manifest", PACKAGES[1], "1.0.0", True, "scoped"),
    ("metadata_only_publish", "publish", PACKAGES[0], "1.0.1", False, "metadata"),
    ("publish_unscoped", "publish", PACKAGES[0], "2.0.0", True, "unscoped"),
    ("publish_scoped", "publish", PACKAGES[1], "3.0.0", True, "scoped"),
    ("publish_dependency", "publish", PACKAGES[0], TOP_VERSION, True, "unscoped"),
    ("install_published", "install", PACKAGES[0], TOP_VERSION, True, "install"),
    ("ci_published", "ci", PACKAGES[0], TOP_VERSION, True, "install"),
    ("install_audit_negative", "install", PACKAGES[0], TOP_VERSION, False, "install"),
    ("outside_window_publish", "publish", PACKAGES[0], "5.0.0", False, "outside"),
    ("wrong_package_view", "view", FORBIDDEN_PACKAGE, "1.0.0", False, "unscoped"),
    ("wrong_package_manifest", "manifest", FORBIDDEN_PACKAGE, "1.0.0", False, "unscoped"),
    ("wrong_package_publish", "publish", FORBIDDEN_PACKAGE, "4.0.0", False, "unscoped"),
    ("wrong_app_view", "view", PACKAGES[0], "1.0.0", False, "unassigned"),
    ("wrong_app_manifest", "manifest", PACKAGES[0], "1.0.0", False, "unassigned"),
    ("wrong_app_publish", "publish", PACKAGES[0], "7.0.0", False, "unassigned"),
    ("wrong_outer_ca", "view", PACKAGES[0], "1.0.0", False, "unscoped"),
    ("wrong_inner_ca", "manifest", PACKAGES[0], "1.0.0", False, "unscoped"),
    ("missing_confirmation", "publish", PACKAGES[0], "7.0.0", False, "unscoped"),
    ("wrong_tarball_hash", "publish", PACKAGES[0], "7.0.0", False, "unscoped"),
    ("revoked_view", "view", PACKAGES[1], "1.0.0", False, "scoped"),
    ("revoked_manifest", "manifest", PACKAGES[1], "1.0.0", False, "scoped"),
    ("revoked_publish", "publish", PACKAGES[1], "7.0.0", False, "scoped"),
)
SPECS = tuple(dict(zip(("case", "operation", "package", "version", "success", "application"), row))
    for row in _PHASES)
ARRIVALS = (("view_unscoped", "GET"), ("view_scoped", "GET"),
    ("manifest_unscoped", "GET"), ("manifest_scoped", "GET"),
    ("metadata_only_publish", "GET"), ("publish_unscoped", "GET"), ("publish_unscoped", "PUT"),
    ("publish_scoped", "GET"), ("publish_scoped", "PUT"),
    ("publish_dependency", "GET"), ("publish_dependency", "PUT"),
    *((case, method) for case in INSTALL_CASES for method in
        (("GET", "GET", "POST") if case == "ci_published" else ("GET", "GET", "GET", "GET", "POST"))),
    ("outside_window_publish", "GET"))


def spec_for(case):
    return next(spec for spec in SPECS if spec["case"] == case)


def package_manifest(spec):
    value = {"name": spec["package"], "version": spec["version"],
        "description": "Synthetic publication fixture", "license": "MIT", "main": "index.js"}
    if spec["case"] == "publish_dependency":
        require(spec == spec_for("publish_dependency"))
        value["dependencies"] = {PACKAGES[1]: LEAF_VERSION}
    return value


def tarball(spec):
    if spec["case"] != "publish_dependency":
        return publish.tarball(spec)
    archive, output = io.BytesIO(), io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w", format=tarfile.USTAR_FORMAT) as stream:
        for name, body in (("package/package.json", encoded(package_manifest(spec)) + b"\n"),
                ("package/index.js", b"module.exports = 'inert synthetic package';\n")):
            member = tarfile.TarInfo(name)
            member.size, member.mode, member.mtime = len(body), 0o644, 0
            stream.addfile(member, io.BytesIO(body))
    with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as stream:
        stream.write(archive.getvalue())
    result = output.getvalue()
    require(0 < len(result) < 32768)
    return result


def validate_publish(raw, spec):
    """Only this explicit third publication may carry one fixed dependency."""
    if spec["case"] != "publish_dependency":
        return publish.validate_publish(raw, spec, npm_version="11.21.1")
    require(spec == spec_for("publish_dependency") and type(raw) is bytes and 0 < len(raw) <= MAX_BODY)
    value = publish.strict_json(raw)
    name, version, payload = spec["package"], spec["version"], tarball(spec)
    attachment = name + "-" + version + ".tgz"
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode("ascii")
    shasum = hashlib.sha1(payload).hexdigest()
    manifest = {**package_manifest(spec), "_id": name + "@" + version,
        "_nodeVersion": "25.5.0", "_npmVersion": "11.21.1",
        "dist": {"integrity": integrity, "shasum": shasum,
            "tarball": "http://registry.npmjs.org/" + name + "/-/" + attachment}}
    require(type(value) is dict and set(value) == {"_id", "name", "description", "dist-tags", "versions", "access", "_attachments"}
        and value["_id"] == value["name"] == name and value["description"] == "Synthetic publication fixture"
        and value["dist-tags"] == {TAG: version} and value["access"] == "public"
        and type(value["versions"]) is dict and set(value["versions"]) == {version})
    observed = value["versions"][version]
    # As in the original publish oracle, stock pacote may retain its local
    # _from/_resolved/readme metadata. It is not substituted into the archive.
    require(type(observed) is dict and all(observed.get(key) == item for key, item in manifest.items())
        and not set(observed) & {"scripts", "publishConfig", "tag"}
        and value["_attachments"] == {attachment: {"content_type": "application/octet-stream",
            "data": base64.b64encode(payload).decode("ascii"), "length": len(payload)}}
        and type(value["_attachments"][attachment]["length"]) is int)
    return {"package": name, "version": version, "tag": TAG, "attachmentName": attachment,
        "attachmentBytes": len(payload), "tarballSha256": digest(payload),
        "tarballIntegrity": integrity, "tarballShasum": shasum}, manifest, payload


def tarball_path(package, version):
    require((package, version) in ((PACKAGES[0], TOP_VERSION), (PACKAGES[1], LEAF_VERSION)))
    return "/" + package + "/-/" + package.rsplit("/", 1)[-1] + "-" + version + ".tgz"


def install_requests(case):
    """Exact phase set; parallel stock audit/download ordering is not prescribed."""
    require(case in INSTALL_CASES)
    rows = [] if case == "ci_published" else [("GET", path(package), "metadata", package, None) for package in PACKAGES]
    return tuple(rows + [("GET", tarball_path(package, version), "tarball", package, version)
        for package, version in ((PACKAGES[0], TOP_VERSION), (PACKAGES[1], LEAF_VERSION))]
        + [("POST", AUDIT_PATH, "audit", None, None)])


def validate_audit(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BODY)
    try:
        stream = zlib.decompressobj(31)
        decoded = stream.decompress(raw, 4097)
        require(len(decoded) <= 4096 and stream.eof and not stream.unused_data and not stream.unconsumed_tail)
        value = publish.strict_json(decoded)
    except (zlib.error, RecursionError):
        raise ValueError("private npm audit fixture refused") from None
    require(value == {PACKAGES[0]: [TOP_VERSION], PACKAGES[1]: [LEAF_VERSION]})
    return {"operation": "npm.install.audit.read", "packages": sorted(PACKAGES),
        "packageVersions": {package: value[package] for package in sorted(PACKAGES)}}


def install_headers(fields, spec, mode, package, version, length):
    require(len(fields) <= 20 and len({name for name, _ in fields}) == len(fields))
    headers = dict(fields)
    common = {"host", "authorization", "accept", "user-agent", "connection", "content-length",
        "npm-auth-type", "npm-command", "npm-scope", "npm-in-ci"}
    allowed = common | ({"content-type", "content-encoding"} if mode == "audit" else
        {"pacote-version", "pacote-req-type", "pacote-pkg-id", "pacote-integrity", "cache-control"})
    require(set(headers) <= allowed and headers.get("host") == "registry.npmjs.org"
        and hmac.compare_digest(headers.get("authorization", ""), "Bearer " + TOKEN)
        and headers.get("npm-command") == spec["operation"] and headers.get("npm-auth-type", "web") == "web"
        and headers.get("npm-in-ci") in {None, "false"} and headers.get("npm-scope", "") == ""
        and headers.get("connection", "close") in {"close", "keep-alive"}
        and headers.get("content-length", "0") == str(length)
        and re.fullmatch(r"npm/11\.21\.1 node/v25\.5\.0 linux x64(?: workspaces/false)?", headers.get("user-agent", "")))
    if mode == "audit":
        require(length > 0 and headers.get("accept") == "*/*" and headers.get("content-type") == FULL
            and headers.get("content-encoding") == "gzip" and headers.get("content-length") == str(length))
    else:
        require(length == 0 and headers.get("pacote-version") == "21.5.1"
            and headers.get("cache-control") in {None, "no-cache"})
        if mode == "metadata":
            # npm 11.21.1's Arborist #fetchManifest forces fullMetadata:true;
            # this differs from the standalone pacote/publish corgi requests.
            require(headers.get("accept") == FULL and headers.get("pacote-req-type") == "packument"
                and headers.get("pacote-pkg-id") == "registry:" + package and "pacote-integrity" not in headers)
        else:
            payload = tarball(spec_for("publish_dependency" if package == PACKAGES[0] else "publish_scoped"))
            integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode("ascii")
            require(headers.get("accept") == "*/*" and headers.get("pacote-req-type") == "tarball"
                and headers.get("pacote-pkg-id") == "remote:" + package + "@" + ORIGIN + tarball_path(package, version)
                and headers.get("pacote-integrity") == integrity)
    return {key: value for key, value in headers.items()
        if key not in {"authorization", "connection", "content-length", "cache-control"}}


def packument(package, stored):
    """Seed one read version; never claim a negative phase was published."""
    require(package in PACKAGES)
    document = metadata.metadata(package)
    document["versions"] = {"1.0.0": document["versions"]["1.0.0"]}
    document["dist-tags"] = {"latest": "1.0.0"}
    document["time"].pop("2.0.0")
    for row in stored:
        if row["package"] == package:
            require(row["version"] not in document["versions"])
            spec = spec_for(row["case"])
            # The registry's read URL is canonical; it is not the stock publish
            # attachment metadata URL. Only independently stored bytes feed it.
            url = ORIGIN + "/" + package + "/-/" + package.rsplit("/", 1)[-1] + "-" + row["version"] + ".tgz"
            document["versions"][row["version"]] = {**package_manifest(spec), "dist": {
                "tarball": url, "integrity": row["tarballIntegrity"], "shasum": row["tarballShasum"]}}
            document["dist-tags"][TAG] = row["version"]
    return document


def validate_headers(fields, spec, method, body_length):
    if spec["operation"] == "publish":
        return publish.validate_headers(fields, method, spec["package"], body_length,
            npm_version="11.21.1", pacote_version="21.5.1")
    require(method == "GET" and body_length == 0)
    # Keep the two existing closed header profiles separate. In particular,
    # standalone pacote must not acquire npm-command/auth-type CLI headers.
    return metadata.validate_headers(fields, {"package": spec["package"],
        "client": "npm" if spec["operation"] == "view" else "pacote",
        "accept": FULL if spec["operation"] == "view" else CORGI},
        npm_version="11.21.1", pacote_version="21.5.1")


def stored_observations(directory, rows):
    require({item.name for item in directory.iterdir()} ==
        {row["case"] + suffix for row in rows for suffix in (".tgz", ".json")})
    for row in rows:
        require(digest((directory / (row["case"] + ".tgz")).read_bytes()) == row["tarballSha256"]
            and publish.strict_json((directory / (row["case"] + ".json")).read_bytes()) == row)
    return deepcopy(rows)


def refusal_observation(ordinal, method, stage, error):
    if type(error) is publish.FixtureRefusal:
        stage, error_class = error.stage, error.error_class
    else:
        error_class = publish._error_class(error)
    if (type(ordinal) is not int or not 1 <= ordinal <= MAX_ATTEMPTS
            or type(stage) is not str or stage not in publish.REFUSAL_STAGES
            or error_class not in publish.REFUSAL_ERRORS):
        return None
    case, expected_method = ARRIVALS[ordinal - 1] if ordinal <= len(ARRIVALS) else (None, None)
    if case in INSTALL_CASES:
        expected_method = None  # This phase admits a closed set, not a fabricated parallel ordering.
    return {"schema": REFUSAL_SCHEMA, "ordinal": ordinal, "expectedCase": case,
        "expectedMethod": expected_method, "actualMethod": method
            if type(method) is str and method in publish.REFUSAL_METHODS else "other",
        "stage": stage, "errorClass": error_class}


def emit_refusal(ordinal, method, stage, error):
    try:
        record = refusal_observation(ordinal, method, stage, error)
        if record is not None:
            sys.stderr.write(encoded(record).decode("utf-8") + "\n")
            sys.stderr.flush()
    except Exception:
        pass


def setup():
    metadata.setup(Path("/upstream-data/npm"), Path("/private-fixture.json"))
    packages = Path("/upstream-data/npm/packages")
    packages.mkdir(mode=0o700)
    for spec in SPECS:
        if spec["operation"] == "publish":
            save_new(packages / (spec["case"] + ".tgz"), tarball(spec))
    Path("/upstream-data/npm-publish-state").mkdir(mode=0o700)


class Fixture(HTTPServer):
    def __init__(self, address, context):
        super().__init__(address, Handler)
        self.socket = context.wrap_socket(self.socket, server_side=True)
        self.total, self.attempts, self.stored, self.timeout = 0, [], [], 0.5


class Handler(publish.Handler):
    """Reuse the existing bounded socket, quiet handler and response writer."""

    def do_GET(self):
        if self.path == "/_fixture/observations":
            rows = stored_observations(Path("/npm-state"), self.server.stored)
            self.send(200, encoded({"schema": SCHEMA, "syntheticOnly": True, "total": self.server.total,
                "attempts": deepcopy(self.server.attempts), "stored": rows}))
        else:
            self.resource()

    def resource(self):
        self.server.total += 1
        row = {"ordinal": self.server.total, "accepted": False}
        if self.server.total <= MAX_ATTEMPTS:
            self.server.attempts.append(row)
        stage = "sequence"
        try:
            require(1 <= self.server.total <= len(ARRIVALS))
            case, method = ARRIVALS[self.server.total - 1]
            spec = spec_for(case)
            stage = "target"
            mode, package, version = None, spec["package"], spec["version"]
            if case in INSTALL_CASES:
                candidates = [item for item in install_requests(case) if item[:2] == (self.command, self.path)]
                require(len(candidates) == 1 and not any(old.get("case") == case
                    and (old.get("method"), old.get("rawTarget")) == (self.command, self.path)
                    for old in self.server.attempts[:-1]))
                method, _, mode, package, version = candidates[0]
            else:
                require(self.command == method and self.path == path(package))
            stage = "framing"
            length = self.headers.get("content-length", "0")
            require(re.fullmatch(r"0|[1-9][0-9]{0,5}", length) and int(length) <= MAX_BODY)
            raw = self.rfile.read(int(length))
            require(len(raw) == int(length))
            stage = "headers"
            fields = [(name.lower(), value) for name, value in self.headers.raw_items()]
            headers = (install_headers(fields, spec, mode, package, version, len(raw)) if mode else
                validate_headers(fields, spec, method, len(raw)))
            if mode == "audit":
                operation = validate_audit(raw)
                status, content_type = (400 if case == "install_audit_negative" else 200), FULL
                response = b'{"error":"synthetic_audit_refused"}' if status == 400 else b'{}'
            elif mode == "tarball":
                stored = next((item for item in self.server.stored
                    if (item["package"], item["version"]) == (package, version)), None)
                require(stored is not None)
                response = (Path("/npm-state") / (stored["case"] + ".tgz")).read_bytes()
                require(digest(response) == stored["tarballSha256"] and len(response) == stored["attachmentBytes"])
                status, content_type = 200, "application/octet-stream"
                operation = {"operation": "npm.install.tarball.read", "package": package, "version": version}
            elif method == "GET":
                status = 200
                content_type = FULL if mode == "metadata" or spec["operation"] == "view" else "application/vnd.npm.install-v1+json"
                response = encoded(packument(package, self.server.stored))
                operation = {"operation": "npm.install.metadata.read" if mode else "npm.metadata.read", "package": package}
            else:
                stored, _, payload = validate_publish(raw, spec)
                stage = "storage"
                require(not any(old["package"] == stored["package"] and old["version"] == stored["version"]
                    for old in self.server.stored))
                stored.update(case=case)
                save_new(Path("/npm-state") / (case + ".tgz"), payload)
                save_new(Path("/npm-state") / (case + ".json"), encoded(stored))
                descriptor = os.open("/npm-state", os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                self.server.stored.append(stored)
                status, content_type = 201, FULL
                response = encoded({"ok": True, "id": spec["package"], "rev": "fixture-" + spec["version"]})
                operation = {"operation": "npm.publish", "packageName": stored["package"],
                    "packageVersion": stored["version"], "tag": TAG,
                    "tarballIntegrity": stored["tarballIntegrity"], "tarballShasum": stored["tarballShasum"],
                    "attachmentName": stored["attachmentName"], "attachmentBytes": str(stored["attachmentBytes"])}
            row.update(case=case, method=method, rawTarget=self.path, accepted=True, requestHeaders=headers,
                requestBodySha256=digest(raw), requestBodyBytes=len(raw), operation=operation,
                status=status, responseContentType=content_type, responseBodySha256=digest(response),
                responseBodyBytes=len(response), allParsedHeadersValidated=True)
            stage = "response"
            self.send(status, response, content_type)
        except (ValueError, OSError, TypeError, KeyError) as error:
            emit_refusal(self.server.total, self.command, stage, error)
            self.send(400, b'{"error":"synthetic npm example fixture refused"}')

    do_PUT = do_POST = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = resource


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--lifetime-seconds", type=int, default=300)
    args = parser.parse_args()
    os.umask(0o077)
    if args.setup:
        signal.alarm(20)
        setup()
        return
    assert_isolated_network()
    require(os.geteuid() == 10001 and 60 <= args.lifetime_seconds <= 300
        and Path("/npm-state").is_dir() and not list(Path("/npm-state").iterdir()))
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
