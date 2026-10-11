"""Fixed synthetic registry scenario for the actual npm-registry example.

Reuses the separately tested metadata/publish validators, deterministic inert
tarballs, exclusive storage and isolated HTTPS setup. No registry client, SDK
rewrite, mutable control endpoint or tarball download is added. Only ten exact
arrivals are allowed; the other explicit example phases must stop at the gate
or locally. Successful npm output is not evidence of persisted publication:
observations independently re-read the two stored tarballs and records.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from http.server import HTTPServer
import os
from pathlib import Path
import re
import signal
import ssl
import sys
import time

from scripts import operator_npm_metadata_fixture as metadata
from scripts import operator_npm_publish_fixture as publish
from scripts.operator_npm_metadata_fixture_network import FIXTURE_IP, assert_isolated_network


ORIGIN, TOKEN, PLACEHOLDER = publish.ORIGIN, publish.TOKEN, publish.PLACEHOLDER
PACKAGES, TAG = publish.PACKAGES, publish.TAG
FORBIDDEN_PACKAGE = publish.spec_for("wrong_package")["package"]
FULL, CORGI = metadata.FULL, metadata.CORGI
MAX_BODY, MAX_ATTEMPTS = publish.MAX_BODY, 32
SCHEMA = "serverware.privateNpmExampleObservations/v1"
REFUSAL_SCHEMA = "serverware.privateNpmExampleRefusal/v1"
encoded, digest, path = metadata.encoded, metadata.digest, metadata.path
require, tarball, save_new = publish.require, publish.tarball, publish.save_new

_PHASES = (
    ("view_unscoped", "view", PACKAGES[0], "1.0.0", True, "outside"),
    ("view_scoped", "view", PACKAGES[1], "1.0.0", True, "scoped"),
    ("manifest_unscoped", "manifest", PACKAGES[0], "1.0.0", True, "outside"),
    ("manifest_scoped", "manifest", PACKAGES[1], "1.0.0", True, "scoped"),
    ("metadata_only_publish", "publish", PACKAGES[0], "1.0.1", False, "metadata"),
    ("publish_unscoped", "publish", PACKAGES[0], "2.0.0", True, "unscoped"),
    ("publish_scoped", "publish", PACKAGES[1], "3.0.0", True, "scoped"),
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
    ("publish_scoped", "GET"), ("publish_scoped", "PUT"), ("outside_window_publish", "GET"))


def spec_for(case):
    return next(spec for spec in SPECS if spec["case"] == case)


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
            # These are independently accepted/stored versions, not caller
            # success reports. The existing publication packument is minimal.
            document["versions"][row["version"]] = {"name": package, "version": row["version"]}
            document["dist-tags"][TAG] = row["version"]
    return document


def validate_headers(fields, spec, method, body_length):
    if spec["operation"] == "publish":
        return publish.validate_headers(fields, method, spec["package"], body_length)
    require(method == "GET" and body_length == 0)
    # Keep the two existing closed header profiles separate. In particular,
    # standalone pacote must not acquire npm-command/auth-type CLI headers.
    return metadata.validate_headers(fields, {"package": spec["package"],
        "client": "npm" if spec["operation"] == "view" else "pacote",
        "accept": FULL if spec["operation"] == "view" else CORGI})


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
            require(self.command == method and self.path == path(spec["package"]))
            stage = "framing"
            length = self.headers.get("content-length", "0")
            require(re.fullmatch(r"0|[1-9][0-9]{0,5}", length) and int(length) <= MAX_BODY)
            raw = self.rfile.read(int(length))
            require(len(raw) == int(length))
            stage = "headers"
            headers = validate_headers([(name.lower(), value) for name, value in self.headers.raw_items()],
                spec, method, len(raw))
            if method == "GET":
                status = 200
                content_type = FULL if spec["operation"] == "view" else "application/vnd.npm.install-v1+json"
                response = encoded(packument(spec["package"], self.server.stored))
                operation = {"operation": "npm.metadata.read", "package": spec["package"]}
            else:
                stored, _, payload = publish.validate_publish(raw, spec)
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
