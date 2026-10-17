#!/usr/bin/env python3
"""Component controls for the finite npm example receiver, not SDK acceptance.

Actual handler methods consume in-memory messages; actual exclusive writes and
observation rereads use a private TemporaryDirectory. No HTTP server, socket,
child process, npm executable, provider, install or archive extraction runs.
Expected phases, headers, package bytes and stored records are constructed here,
not obtained from the receiver's oracle or the production npm adapter.
"""
import base64
from collections import Counter
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from email.message import Message
import gzip
import hashlib
import io
from itertools import permutations
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import operator_npm_example_fixture as registry


PACKAGES = ("catchplate-fixture-publish", "@catchplate-fixture/publish")
FORBIDDEN = "catchplate-fixture-forbidden"
FULL = "application/json"
CORGI = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"
VENDOR = "application/vnd.npm.install-v1+json"
TAG = "fixture"
LEGACY_PHASES = (
    ("view_unscoped", "view", PACKAGES[0], "1.0.0", True, "outside"),
    ("view_scoped", "view", PACKAGES[1], "1.0.0", True, "scoped"),
    ("manifest_unscoped", "manifest", PACKAGES[0], "1.0.0", True, "outside"),
    ("manifest_scoped", "manifest", PACKAGES[1], "1.0.0", True, "scoped"),
    ("metadata_only_publish", "publish", PACKAGES[0], "1.0.1", False, "metadata"),
    ("publish_unscoped", "publish", PACKAGES[0], "2.0.0", True, "unscoped"),
    ("publish_scoped", "publish", PACKAGES[1], "3.0.0", True, "scoped"),
    ("outside_window_publish", "publish", PACKAGES[0], "5.0.0", False, "outside"),
    ("wrong_package_view", "view", FORBIDDEN, "1.0.0", False, "unscoped"),
    ("wrong_package_manifest", "manifest", FORBIDDEN, "1.0.0", False, "unscoped"),
    ("wrong_package_publish", "publish", FORBIDDEN, "4.0.0", False, "unscoped"),
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
ADDED_PHASES = (
    ("publish_dependency", "publish", PACKAGES[0], "1.0.2", True, "unscoped"),
    ("install_published", "install", PACKAGES[0], "1.0.2", True, "install"),
    ("ci_published", "ci", PACKAGES[0], "1.0.2", True, "install"),
    ("install_audit_negative", "install", PACKAGES[0], "1.0.2", False, "install"),
)
PHASES = LEGACY_PHASES[:7] + ADDED_PHASES + LEGACY_PHASES[7:]
SPECS = {row[0]: dict(zip(("case", "operation", "package", "version", "success", "application"), row))
    for row in PHASES}
LEGACY_ARRIVALS = (("view_unscoped", "GET"), ("view_scoped", "GET"),
    ("manifest_unscoped", "GET"), ("manifest_scoped", "GET"),
    ("metadata_only_publish", "GET"), ("publish_unscoped", "GET"), ("publish_unscoped", "PUT"),
    ("publish_scoped", "GET"), ("publish_scoped", "PUT"), ("outside_window_publish", "GET"))
INSTALL_CASES = ("install_published", "ci_published", "install_audit_negative")
AUDIT_PATH = "/-/npm/v1/security/advisories/bulk"
AUDIT_DOCUMENT = {PACKAGES[0]: ["1.0.2"], PACKAGES[1]: ["3.0.0"]}
INSTALL_ROWS = (
    ("GET", "/catchplate-fixture-publish", "metadata", PACKAGES[0], None),
    ("GET", "/@catchplate-fixture%2fpublish", "metadata", PACKAGES[1], None),
    ("GET", "/catchplate-fixture-publish/-/catchplate-fixture-publish-1.0.2.tgz", "tarball", PACKAGES[0], "1.0.2"),
    ("GET", "/@catchplate-fixture/publish/-/publish-3.0.0.tgz", "tarball", PACKAGES[1], "3.0.0"),
    ("POST", AUDIT_PATH, "audit", None, None),
)
INSTALL_REQUESTS = {case: INSTALL_ROWS[2:] if case == "ci_published" else INSTALL_ROWS for case in INSTALL_CASES}
ARRIVALS = (LEGACY_ARRIVALS[:-1] + (("publish_dependency", "GET"), ("publish_dependency", "PUT"))
    + tuple((case, row[0]) for case in INSTALL_CASES for row in INSTALL_REQUESTS[case])
    + LEGACY_ARRIVALS[-1:])
PUBLICATIONS = ("publish_unscoped", "publish_scoped", "publish_dependency")
ROW_KEYS = {"ordinal", "accepted", "case", "method", "rawTarget", "requestHeaders",
    "requestBodySha256", "requestBodyBytes", "operation", "status", "responseContentType",
    "responseBodySha256", "responseBodyBytes", "allParsedHeadersValidated"}
REFUSAL = b'{"error":"synthetic npm example fixture refused"}'
REAL_OPEN = os.open


def encoded(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def target(package):
    return "/" + package.replace("/", "%2f")


def expected_tarball(spec):
    """Independent inert USTAR/gzip construction with fixed member metadata."""
    manifest = {"name": spec["package"], "version": spec["version"],
        "description": "Synthetic publication fixture", "license": "MIT", "main": "index.js"}
    if spec["case"] == "publish_dependency":
        manifest["dependencies"] = {PACKAGES[1]: "3.0.0"}
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, content in (("package/package.json", encoded(manifest) + b"\n"),
                ("package/index.js", b"module.exports = 'inert synthetic package';\n")):
            member = tarfile.TarInfo(name)
            member.size, member.mode, member.mtime = len(content), 0o644, 0
            archive.addfile(member, io.BytesIO(content))
    result = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=result, mode="wb", mtime=0) as stream:
        stream.write(raw.getvalue())
    return result.getvalue()


def expected_stored(spec):
    blob = expected_tarball(spec)
    return {"package": spec["package"], "version": spec["version"], "tag": TAG,
        "attachmentName": spec["package"] + "-" + spec["version"] + ".tgz",
        "attachmentBytes": len(blob), "tarballSha256": digest(blob),
        "tarballIntegrity": "sha512-" + base64.b64encode(hashlib.sha512(blob).digest()).decode("ascii"),
        "tarballShasum": hashlib.sha1(blob, usedforsecurity=False).hexdigest(), "case": spec["case"]}


def publish_document(spec):
    blob, stored = expected_tarball(spec), expected_stored(spec)
    name, version = spec["package"], spec["version"]
    manifest = {"name": name, "version": version, "_id": name + "@" + version,
        "description": "Synthetic publication fixture", "license": "MIT", "main": "index.js",
        "_nodeVersion": "25.5.0", "_npmVersion": "11.21.1", "dist": {
            "integrity": stored["tarballIntegrity"], "shasum": stored["tarballShasum"],
            "tarball": "http://registry.npmjs.org/" + name + "/-/" + stored["attachmentName"]}}
    if spec["case"] == "publish_dependency":
        manifest["dependencies"] = {PACKAGES[1]: "3.0.0"}
    return {"_id": name, "name": name, "description": "Synthetic publication fixture",
        "dist-tags": {TAG: version}, "versions": {version: manifest}, "access": "public",
        "_attachments": {stored["attachmentName"]: {"content_type": "application/octet-stream",
            "data": base64.b64encode(blob).decode("ascii"), "length": len(blob)}}}


def fields(spec, method="GET", length=0):
    result = [("host", "registry.npmjs.org"), ("authorization", "Bearer " + registry.TOKEN),
        ("accept", "*/*" if method == "PUT" else FULL if spec["operation"] == "view" else CORGI),
        ("connection", "close"), ("content-length", str(length))]
    if spec["operation"] == "manifest":
        result.append(("user-agent", "pacote/21.5.1 node/v25.5.0"))
    else:
        result.extend((("user-agent", "npm/11.21.1 node/v25.5.0 linux x64 workspaces/false"),
            ("npm-command", spec["operation"]), ("npm-auth-type", "web")))
    if method == "PUT":
        result.append(("content-type", FULL))
    else:
        result.extend((("pacote-version", "21.5.1"), ("pacote-req-type", "packument"),
            ("pacote-pkg-id", "registry:" + spec["package"])))
    return result


def changed(fields_, name, value):
    return [(key, value if key == name else old) for key, old in fields_]


def compressed(raw):
    output = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as stream:
        stream.write(raw)
    return output.getvalue()


def install_fields(case, request, length=0):
    method, pathname, mode, package, version = request
    result = [("host", "registry.npmjs.org"), ("authorization", "Bearer " + registry.TOKEN),
        ("accept", FULL if mode == "metadata" else "*/*"), ("connection", "close"),
        ("content-length", str(length)), ("npm-auth-type", "web"),
        ("npm-command", SPECS[case]["operation"]),
        ("user-agent", "npm/11.21.1 node/v25.5.0 linux x64 workspaces/false")]
    if mode == "audit":
        result.extend((("content-type", FULL), ("content-encoding", "gzip")))
    else:
        result.extend((("pacote-version", "21.5.1"), ("pacote-req-type", "packument" if mode == "metadata" else "tarball"),
            ("pacote-pkg-id", "registry:" + package if mode == "metadata" else
             "remote:" + package + "@https://registry.npmjs.org" + pathname)))
        if mode == "tarball":
            publication = "publish_dependency" if package == PACKAGES[0] else "publish_scoped"
            result.append(("pacote-integrity", expected_stored(SPECS[publication])["tarballIntegrity"]))
    return result


def install_receive(state, case, request, *, body=None, headers=None, path=None, method=None):
    if body is None:
        body = compressed(encoded(AUDIT_DOCUMENT)) if request[2] == "audit" else b""
    return receive(state, SPECS[case], request[0] if method is None else method, body,
        headers=install_fields(case, request, len(body)) if headers is None else headers,
        path=request[1] if path is None else path)


def server():
    return SimpleNamespace(total=0, attempts=[], stored=[])


def receive(state, spec, method="GET", body=b"", *, headers=None, path=None, observation=False):
    handler = object.__new__(registry.Handler)
    handler.server, handler.command = state, method
    handler.path = target(spec["package"]) if path is None else path
    handler.headers, handler.rfile = Message(), io.BytesIO(body)
    for name, value in fields(spec, method, len(body)) if headers is None else headers:
        handler.headers[name] = value
    responses = []
    handler.send = lambda status, raw, content_type=FULL: responses.append((status, raw, content_type))
    (registry.Handler.do_GET if observation else registry.Handler.resource)(handler)
    if len(responses) != 1:
        raise AssertionError("component handler did not produce exactly one response")
    return responses[0]


@contextmanager
def state_directory(directory):
    """Only fixed fixture paths are redirected; actual file I/O stays real."""
    def pathname(value):
        return directory if str(value) == "/npm-state" else Path(value)
    def open_(value, flags, *args, **kwargs):
        return REAL_OPEN(directory if value == "/npm-state" else value, flags, *args, **kwargs)
    with patch.object(registry, "Path", side_effect=pathname), patch.object(registry.os, "open", side_effect=open_):
        yield


class NpmExampleFixtureTests(unittest.TestCase):
    def setUp(self):
        guard = ExitStack()
        self.addCleanup(guard.close)
        self.stderr = io.StringIO()
        guard.enter_context(patch("sys.stderr", self.stderr))
        for name in ("socket.socket", "socket.create_connection", "socket.getaddrinfo",
                "subprocess.Popen", "subprocess.run"):
            guard.enter_context(patch(name, side_effect=AssertionError("component test attempted network/process I/O")))
        self.directory = Path(guard.enter_context(tempfile.TemporaryDirectory(prefix="catchplate-npm-example-unit-")))
        guard.enter_context(state_directory(self.directory))

    def complete(self):
        state, responses = server(), []
        install_indices = Counter()
        for ordinal, (case, method) in enumerate(ARRIVALS, 1):
            spec = SPECS[case]
            if case in INSTALL_CASES:
                request = INSTALL_REQUESTS[case][install_indices[case]]
                install_indices[case] += 1
                status, raw, media = install_receive(state, case, request)
                self.assert_install_row(state, case, request, status, raw, media)
                responses.append(raw if request[2] == "tarball" else json.loads(raw))
                continue
            body = encoded(publish_document(spec)) if method == "PUT" else b""
            status, raw, media = receive(state, spec, method, body)
            self.assertEqual(status, 201 if method == "PUT" else 200)
            self.assertEqual(media, FULL if method == "PUT" or spec["operation"] == "view" else VENDOR)
            row = state.attempts[-1]
            self.assertEqual(set(row), ROW_KEYS)
            self.assertEqual((row["ordinal"], row["case"], row["method"], row["rawTarget"]),
                (ordinal, case, method, target(spec["package"])))
            self.assertIs(row["accepted"], True)
            self.assertIs(row["allParsedHeadersValidated"], True)
            self.assertEqual((row["requestBodySha256"], row["requestBodyBytes"]), (digest(body), len(body)))
            self.assertEqual((row["responseBodySha256"], row["responseBodyBytes"]), (digest(raw), len(raw)))
            headers = dict(fields(spec, method, len(body)))
            for key in ("authorization", "connection", "content-length"):
                headers.pop(key)
            self.assertEqual(row["requestHeaders"], headers)
            if method == "PUT":
                stored = expected_stored(spec)
                self.assertEqual(row["operation"], {"operation": "npm.publish", "packageName": spec["package"],
                    "packageVersion": spec["version"], "tag": TAG, "tarballIntegrity": stored["tarballIntegrity"],
                    "tarballShasum": stored["tarballShasum"], "attachmentName": stored["attachmentName"],
                    "attachmentBytes": str(stored["attachmentBytes"])})
                self.assertEqual(json.loads(raw), {"ok": True, "id": spec["package"], "rev": "fixture-" + spec["version"]})
            else:
                self.assertEqual(row["operation"], {"operation": "npm.metadata.read", "package": spec["package"]})
            responses.append(json.loads(raw))
        return state, responses

    def assert_install_row(self, state, case, request, status, raw, media):
        method, pathname, mode, package, version = request
        body = compressed(encoded(AUDIT_DOCUMENT)) if mode == "audit" else b""
        self.assertEqual(status, 400 if case == "install_audit_negative" and mode == "audit" else 200)
        self.assertEqual(media, {"metadata": FULL, "tarball": "application/octet-stream", "audit": FULL}[mode])
        row = state.attempts[-1]
        self.assertEqual(set(row), ROW_KEYS)
        self.assertEqual((row["ordinal"], row["case"], row["method"], row["rawTarget"]),
            (state.total, case, method, pathname))
        self.assertIs(row["accepted"], True)
        self.assertIs(row["allParsedHeadersValidated"], True)
        headers = dict(install_fields(case, request, len(body)))
        for key in ("authorization", "connection", "content-length"):
            headers.pop(key)
        self.assertEqual(row["requestHeaders"], headers)
        self.assertEqual((row["requestBodySha256"], row["requestBodyBytes"]), (digest(body), len(body)))
        self.assertEqual((row["responseBodySha256"], row["responseBodyBytes"]), (digest(raw), len(raw)))
        if mode == "audit":
            self.assertEqual(row["operation"], {"operation": "npm.install.audit.read", "packages": sorted(PACKAGES),
                "packageVersions": AUDIT_DOCUMENT})
            self.assertEqual(raw, b'{"error":"synthetic_audit_refused"}' if status == 400 else b'{}')
        else:
            expected = {"operation": "npm.install." + mode + ".read", "package": package}
            if mode == "tarball":
                expected["version"] = version
                self.assertEqual(raw, expected_tarball(SPECS[
                    "publish_dependency" if package == PACKAGES[0] else "publish_scoped"]))
            self.assertEqual(row["operation"], expected)

    def test_exact_twenty_five_phases_preserve_original_twenty_one_oracle(self):
        self.assertEqual(registry.SPECS, tuple(SPECS.values()))
        self.assertEqual(registry.ARRIVALS, ARRIVALS)
        self.assertEqual((len(registry.SPECS), len(registry.ARRIVALS)), (25, 25))
        added = {row[0] for row in ADDED_PHASES}
        self.assertEqual(tuple(tuple(row[key] for key in ("case", "operation", "package", "version", "success", "application"))
            for row in registry.SPECS if row["case"] not in added), LEGACY_PHASES)
        self.assertEqual(tuple(row for row in registry.ARRIVALS if row[0] not in added), LEGACY_ARRIVALS)
        self.assertEqual((registry.PACKAGES, registry.TAG, registry.FORBIDDEN_PACKAGE), (PACKAGES, TAG, FORBIDDEN))
        self.assertEqual((registry.MAX_BODY, registry.MAX_ATTEMPTS), (65536, 32))
        self.assertEqual([spec["case"] for spec in registry.SPECS if spec["success"]],
            ["view_unscoped", "view_scoped", "manifest_unscoped", "manifest_scoped", "publish_unscoped", "publish_scoped",
             "publish_dependency", "install_published", "ci_published"])
        self.assertEqual([case for case, method in ARRIVALS if method == "PUT"], list(PUBLICATIONS))
        self.assertNotIn("wrong_package_publish", dict(ARRIVALS))
        for case, spec in SPECS.items():
            self.assertEqual(registry.spec_for(case), spec)

    def test_seed_latest_is_one_without_a_publish_two_conflict(self):
        for package in PACKAGES:
            first = registry.packument(package, [])
            self.assertEqual((first["_id"], first["name"]), (package, package))
            self.assertEqual(first["dist-tags"], {"latest": "1.0.0"})
            self.assertEqual(set(first["versions"]), {"1.0.0"})
            self.assertNotIn("2.0.0", first["time"])
            self.assertNotIn("3.0.0", first["time"])
            self.assertEqual(first["versions"]["1.0.0"]["fixtureExtra"], {"preserved": [True, None, 7]})
            first["versions"].clear()
            self.assertEqual(set(registry.packument(package, [])["versions"]), {"1.0.0"})
        with self.assertRaises(ValueError):
            registry.packument(FORBIDDEN, [])

    def test_full_view_corgi_manifest_and_publish_profiles_are_distinct(self):
        for case in ("view_unscoped", "view_scoped", "manifest_unscoped", "manifest_scoped", "publish_unscoped", "publish_scoped"):
            spec = SPECS[case]
            public = registry.validate_headers(fields(spec), spec, "GET", 0)
            self.assertEqual(public["accept"], FULL if spec["operation"] == "view" else CORGI)
            if spec["operation"] == "manifest":
                self.assertNotIn("npm-command", public)
                self.assertNotIn("npm-auth-type", public)
                with self.assertRaises(ValueError):
                    registry.validate_headers(fields(spec) + [("npm-command", "view")], spec, "GET", 0)
            else:
                self.assertEqual(public["npm-command"], spec["operation"])
            with self.assertRaises(ValueError):
                registry.validate_headers(changed(fields(spec), "accept", CORGI if spec["operation"] == "view" else FULL), spec, "GET", 0)
        self.assertEqual(registry.path(PACKAGES[1]), "/@catchplate-fixture%2fpublish")

    def test_every_profile_requires_replaced_credential_and_closed_headers(self):
        for case, method in (("view_unscoped", "GET"), ("manifest_scoped", "GET"),
                ("publish_unscoped", "GET"), ("publish_scoped", "PUT")):
            spec, length = SPECS[case], 42 if method == "PUT" else 0
            original = fields(spec, method, length)
            public = registry.validate_headers(original, spec, method, length)
            self.assertNotIn(registry.TOKEN, json.dumps(public))
            self.assertNotIn(registry.PLACEHOLDER, json.dumps(public))
            for key in ("authorization", "proxy-authorization", "content-length", "connection"):
                self.assertNotIn(key, public)
            mutations = [changed(original, "authorization", value) for value in
                ("Bearer " + registry.PLACEHOLDER, "Bearer wrong", "Basic canary", "")]
            mutations += [original + [item] for item in (("authorization", "Bearer " + registry.TOKEN),
                ("host", "registry.npmjs.org"), ("x-private-canary", "secret"),
                ("proxy-authorization", "Basic canary"), ("accept-encoding", "gzip"), ("npm-session", "private"))]
            mutations += [changed(original, "host", "elsewhere.invalid"),
                changed(original, "content-length", str(length + 1)),
                [(key, value) for key, value in original if key != "authorization"]]
            for candidate in mutations:
                with self.subTest(case=case, method=method), self.assertRaises(ValueError):
                    registry.validate_headers(candidate, spec, method, length)

    def test_install_metadata_uses_stock_full_json_and_refuses_corgi(self):
        # npm's bundled Arborist requests full metadata for its dependency
        # graph. Standalone pacote/publish profiles remain covered separately.
        for case, start in (("install_published", 11), ("install_audit_negative", 19)):
            for request in INSTALL_ROWS[:2]:
                with self.subTest(case=case, package=request[3]):
                    original = install_fields(case, request)
                    self.assertEqual(dict(original)["accept"], "application/json")
                    state = SimpleNamespace(total=start, attempts=[], stored=[])
                    status, raw, media = install_receive(state, case, request, headers=original)
                    self.assertEqual((status, media), (200, "application/json"))
                    self.assertEqual(json.loads(raw)["name"], request[3])
                    self.assertEqual(state.attempts[-1]["requestHeaders"]["accept"], "application/json")
                    self.assertEqual(state.attempts[-1]["responseContentType"], "application/json")
                    refused = SimpleNamespace(total=start, attempts=[], stored=[])
                    self.assertEqual(install_receive(refused, case, request,
                        headers=changed(original, "accept", CORGI))[:2], (400, REFUSAL))
                    self.assertEqual(refused.attempts, [{"ordinal": start + 1, "accepted": False}])
                    self.assertEqual(refused.stored, [])

    def test_tarballs_are_exact_deterministic_inert_bytes(self):
        for spec in SPECS.values():
            if spec["operation"] != "publish":
                continue
            expected = expected_tarball(spec)
            self.assertEqual(registry.tarball(spec), expected)
            self.assertEqual(registry.tarball(spec), expected)
            self.assertLess(len(expected), 32768)
            self.assertEqual(expected[4:8], b"\0\0\0\0")
            with tarfile.open(fileobj=io.BytesIO(expected), mode="r:gz") as archive:
                self.assertEqual(archive.getnames(), ["package/package.json", "package/index.js"])
                for member in archive.getmembers():
                    self.assertTrue(member.isfile())
                    self.assertEqual((member.mode, member.mtime, member.uid, member.gid), (0o644, 0, 0, 0))
                self.assertEqual(json.load(archive.extractfile("package/package.json")),
                    {"name": spec["package"], "version": spec["version"], "description": "Synthetic publication fixture",
                     "license": "MIT", "main": "index.js",
                     **({"dependencies": {PACKAGES[1]: "3.0.0"}} if spec["case"] == "publish_dependency" else {})})
                self.assertEqual(archive.extractfile("package/index.js").read(), b"module.exports = 'inert synthetic package';\n")

    def test_publication_oracle_binds_two_versions_tag_tarball_and_integrity(self):
        for case in PUBLICATIONS:
            spec = SPECS[case]
            document = publish_document(spec)
            actual, manifest, blob = registry.validate_publish(encoded(document), spec)
            expected = expected_stored(spec)
            self.assertEqual(actual, {key: value for key, value in expected.items() if key != "case"})
            self.assertEqual(manifest, document["versions"][spec["version"]])
            self.assertEqual(blob, expected_tarball(spec))
            name, version = expected["attachmentName"], spec["version"]
            mutations = [lambda value: value.update(name=FORBIDDEN),
                lambda value: value.update({"dist-tags": {"latest": version}}),
                lambda value: value["versions"].update({"7.0.0": value["versions"][version]}),
                lambda value: value["_attachments"][name].update(length=True),
                lambda value: value["_attachments"][name].update(data="YQ=="),
                lambda value: value["_attachments"][name].update(data=value["_attachments"][name]["data"] + "\n"),
                lambda value: value["versions"][version]["dist"].update(shasum="0" * 40),
                lambda value: value["versions"][version]["dist"].update(integrity="sha512-AAAA"),
                lambda value: value["versions"][version]["dist"].update(tarball="https://elsewhere.invalid/archive.tgz")]
            for index, mutate in enumerate(mutations):
                candidate = deepcopy(document)
                mutate(candidate)
                with self.subTest(case=case, change=index), self.assertRaises(ValueError):
                    registry.validate_publish(encoded(candidate), spec)

    def test_actual_handler_exact_arrival_multiset_and_three_persisted_publications(self):
        state, responses = self.complete()
        self.assertEqual((state.total, len(state.attempts), len(state.stored)), (25, 25, 3))
        self.assertEqual(state.stored, [expected_stored(SPECS[case]) for case in PUBLICATIONS])
        self.assertEqual(Counter(row["operation"]["operation"] for row in state.attempts),
            {"npm.metadata.read": 9, "npm.install.metadata.read": 4, "npm.install.tarball.read": 6,
             "npm.install.audit.read": 3, "npm.publish": 3})
        self.assertEqual(Counter(row["status"] for row in state.attempts), {200: 21, 201: 3, 400: 1})
        self.assertEqual({item.name for item in self.directory.iterdir()},
            {case + suffix for case in PUBLICATIONS for suffix in (".tgz", ".json")})
        for ordinal in (0, 1, 2, 3, 4, 5, 7):
            self.assertEqual(set(responses[ordinal]["versions"]), {"1.0.0"})
            self.assertEqual(responses[ordinal]["dist-tags"], {"latest": "1.0.0"})
        self.assertEqual(set(responses[9]["versions"]), {"1.0.0", "2.0.0"})
        self.assertEqual(responses[9]["dist-tags"], {"latest": "1.0.0", "fixture": "2.0.0"})
        self.assertEqual(set(responses[24]["versions"]), {"1.0.0", "2.0.0", "1.0.2"})
        self.assertEqual(responses[24]["dist-tags"], {"latest": "1.0.0", "fixture": "1.0.2"})
        for row in state.stored:
            for suffix in (".tgz", ".json"):
                path = self.directory / (row["case"] + suffix)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
                self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual((self.directory / (row["case"] + ".tgz")).read_bytes(), expected_tarball(SPECS[row["case"]]))
            self.assertEqual((self.directory / (row["case"] + ".json")).read_bytes(), encoded(row))
        self.assertEqual(self.stderr.getvalue(), "")

    def test_observations_reread_real_storage_and_do_not_count_or_alias(self):
        state, _ = self.complete()
        before = deepcopy((state.total, state.attempts, state.stored))
        status, raw, media = receive(state, SPECS["view_unscoped"], path="/_fixture/observations", observation=True)
        self.assertEqual((status, media), (200, FULL))
        observed = json.loads(raw)
        self.assertEqual(set(observed), {"schema", "syntheticOnly", "total", "attempts", "stored"})
        self.assertEqual(observed["schema"], "catchplate.privateNpmExampleObservations/v1")
        self.assertIs(observed["syntheticOnly"], True)
        self.assertEqual((observed["total"], observed["attempts"], observed["stored"]), before)
        self.assertEqual((state.total, state.attempts, state.stored), before)
        for canary in (registry.TOKEN, registry.PLACEHOLDER, "authorization", "proxy-authorization", "_attachments"):
            self.assertNotIn(canary.encode(), raw)
        copied = registry.stored_observations(self.directory, state.stored)
        copied[0]["version"] = "changed"
        self.assertEqual(state.stored[0]["version"], "2.0.0")

    def test_storage_reread_refuses_missing_extra_corrupt_or_mismatched_records(self):
        state, _ = self.complete()
        originals = {path: path.read_bytes() for path in self.directory.iterdir()}
        tarball = self.directory / "publish_unscoped.tgz"
        record = self.directory / "publish_unscoped.json"
        for path, invalid in ((tarball, b"different bytes"), (record, b"{}"),
                (record, encoded({**state.stored[0], "version": "7.0.0"}))):
            path.chmod(0o600)
            path.write_bytes(invalid)
            with self.subTest(path=path.name), self.assertRaises(ValueError):
                registry.stored_observations(self.directory, state.stored)
            path.write_bytes(originals[path])
            path.chmod(0o400)
        tarball.rename(self.directory / "missing.tgz")
        with self.assertRaises(ValueError): registry.stored_observations(self.directory, state.stored)
        (self.directory / "missing.tgz").rename(tarball)
        extra = self.directory / "unexpected.tgz"
        extra.write_bytes(b"extra")
        with self.assertRaises(ValueError): registry.stored_observations(self.directory, state.stored)
        extra.unlink()
        claimed = deepcopy(state.stored)
        claimed[0]["tarballSha256"] = digest(b"caller claimed replacement")
        with self.assertRaises(ValueError): registry.stored_observations(self.directory, claimed)
        self.assertEqual(registry.stored_observations(self.directory, state.stored), state.stored)

    def test_exclusive_storage_never_overwrites_existing_bytes_or_follows_symlink(self):
        path = self.directory / "exclusive.tgz"
        registry.save_new(path, b"original")
        before = path.stat()
        with self.assertRaises(FileExistsError): registry.save_new(path, b"replacement")
        self.assertEqual(path.read_bytes(), b"original")
        self.assertEqual((path.stat().st_ino, path.stat().st_size, path.stat().st_mtime_ns),
            (before.st_ino, before.st_size, before.st_mtime_ns))
        link = self.directory / "alias.tgz"
        link.symlink_to(path.name)
        with self.assertRaises(OSError): registry.save_new(link, b"replacement")
        self.assertEqual(path.read_bytes(), b"original")
        self.assertTrue(link.is_symlink())

    def test_retries_downloads_wrong_methods_and_overflow_are_counted_not_accepted(self):
        state, _ = self.complete()
        stored = deepcopy(state.stored)
        before = {path: path.read_bytes() for path in self.directory.iterdir()}
        # A retry cannot silently consume the next phase, nor can a repeated
        # version bypass the independently retained publication records.
        retried = server()
        self.assertEqual(receive(retried, SPECS["view_unscoped"])[0], 200)
        self.assertEqual(receive(retried, SPECS["view_unscoped"])[:2], (400, REFUSAL))
        self.assertEqual(retried.attempts[-1], {"ordinal": 2, "accepted": False})
        duplicate = SimpleNamespace(total=6, attempts=[], stored=deepcopy(stored))
        self.assertEqual(receive(duplicate, SPECS["publish_unscoped"], "PUT",
            encoded(publish_document(SPECS["publish_unscoped"])))[:2], (400, REFUSAL))
        self.assertEqual(duplicate.stored, stored)
        for method in ("GET", "PUT", "POST", "PATCH", "DELETE", "HEAD", "OPTIONS"):
            status, raw, _ = receive(state, SPECS["publish_unscoped"], method)
            self.assertEqual((status, raw), (400, REFUSAL))
            self.assertEqual(state.attempts[-1], {"ordinal": state.total, "accepted": False})
        for wrong in ("/catchplate-fixture-publish/-/metadata-1.0.0.tgz", "/-/npm/v1/security/audits/quick",
                "/catchplate-fixture-forbidden", "/@catchplate-fixture/publish", "/@catchplate-fixture%2Fpublish",
                "/catchplate-fixture-publish?write=true", "/_fixture/control"):
            fresh = server()
            status, raw, _ = receive(fresh, SPECS["view_unscoped"], path=wrong)
            self.assertEqual((status, raw, fresh.total, fresh.attempts),
                (400, REFUSAL, 1, [{"ordinal": 1, "accepted": False}]))
        fresh = server()
        for _ in range(40):
            self.assertEqual(receive(fresh, SPECS["view_unscoped"], path="/not-the-target")[0], 400)
        self.assertEqual((fresh.total, len(fresh.attempts), fresh.stored), (40, 32, []))
        self.assertEqual(state.stored, stored)
        self.assertEqual({path: path.read_bytes() for path in self.directory.iterdir()}, before)

    def test_malformed_framing_or_private_header_is_observed_before_refusal(self):
        spec = SPECS["view_unscoped"]
        for length, body in (("-1", b""), ("01", b""), ("65537", b""), ("2", b"x"), ("1", b"x")):
            fresh = server()
            status, raw, _ = receive(fresh, spec, body=body, headers=changed(fields(spec), "content-length", length))
            self.assertEqual((status, raw, fresh.total, fresh.attempts),
                (400, REFUSAL, 1, [{"ordinal": 1, "accepted": False}]))
        canary = "private-credential-and-header-canary"
        fresh = server()
        status, raw, _ = receive(fresh, spec, headers=fields(spec) + [("proxy-authorization", canary)])
        self.assertEqual((status, raw), (400, REFUSAL))
        self.assertNotIn(canary, self.stderr.getvalue())
        self.assertNotIn(canary, json.dumps(fresh.attempts))
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_closed_refusal_records_are_bounded_and_logging_failure_is_inert(self):
        canary = "secret-body-path-error-canary"
        for kind in (ValueError, OSError, TypeError, KeyError):
            record = registry.refusal_observation(9, "PUT", "headers", kind(canary))
            self.assertEqual(record, {"schema": "catchplate.privateNpmExampleRefusal/v1", "ordinal": 9,
                "expectedCase": "publish_scoped", "expectedMethod": "PUT", "actualMethod": "PUT",
                "stage": "headers", "errorClass": kind.__name__})
            self.assertNotIn(canary, json.dumps(record))
        unknown = registry.refusal_observation(26, canary, "sequence", ValueError(canary))
        self.assertEqual((unknown["expectedCase"], unknown["expectedMethod"], unknown["actualMethod"]), (None, None, "other"))
        for ordinal in (0, 33, -1, True, 1.0, "1", None):
            self.assertIsNone(registry.refusal_observation(ordinal, "GET", "sequence", ValueError(canary)))
        for stage in (canary, [], {}, None):
            self.assertIsNone(registry.refusal_observation(1, "GET", stage, ValueError(canary)))
        for failure in ("write", "flush"):
            sink = io.StringIO()
            with patch.object(sink, failure, side_effect=OSError(canary)), patch.object(registry.sys, "stderr", sink):
                fresh = server()
                self.assertEqual(receive(fresh, SPECS["view_unscoped"], path="/wrong")[:2], (400, REFUSAL))
                self.assertEqual(fresh.attempts, [{"ordinal": 1, "accepted": False}])

    def test_packument_only_adds_matching_stored_versions_without_mutating_rows(self):
        stored = [expected_stored(SPECS[case]) for case in ("publish_unscoped", "publish_scoped")]
        before = deepcopy(stored)
        for package, version in zip(PACKAGES, ("2.0.0", "3.0.0")):
            result = registry.packument(package, stored)
            self.assertEqual(set(result["versions"]), {"1.0.0", version})
            self.assertEqual(result["dist-tags"], {"latest": "1.0.0", "fixture": version})
            published = result["versions"][version]
            stored_row = next(row for row in stored if row["package"] == package)
            self.assertEqual(published, {"name": package, "version": version,
                "description": "Synthetic publication fixture", "license": "MIT", "main": "index.js",
                "dist": {"tarball": "https://registry.npmjs.org/" + package + "/-/" + package.rsplit("/", 1)[-1] + "-" + version + ".tgz",
                    "integrity": stored_row["tarballIntegrity"], "shasum": stored_row["tarballShasum"]}})
            self.assertNotIn(FORBIDDEN, json.dumps(result))
        self.assertEqual(stored, before)
        with self.assertRaises(ValueError): registry.packument(PACKAGES[0], stored + [stored[0]])

    def test_dependency_archive_metadata_and_persisted_transitive_closure_agree(self):
        state, _ = self.complete()
        top = registry.packument(PACKAGES[0], state.stored)["versions"]["1.0.2"]
        leaf = registry.packument(PACKAGES[1], state.stored)["versions"]["3.0.0"]
        self.assertEqual(top["dependencies"], {PACKAGES[1]: "3.0.0"})
        self.assertNotIn("dependencies", leaf)
        for case, manifest in (("publish_dependency", top), ("publish_scoped", leaf)):
            original = (self.directory / (case + ".tgz")).read_bytes()
            self.assertEqual(original, expected_tarball(SPECS[case]))
            with tarfile.open(fileobj=io.BytesIO(original), mode="r:gz") as archive:
                packaged = json.load(archive.extractfile("package/package.json"))
                self.assertEqual(packaged, {key: value for key, value in manifest.items() if key != "dist"})
                self.assertNotIn("scripts", packaged)
            self.assertEqual(manifest["dist"]["integrity"], "sha512-" + base64.b64encode(hashlib.sha512(original).digest()).decode())
            self.assertEqual(manifest["dist"]["shasum"], hashlib.sha1(original, usedforsecurity=False).hexdigest())
        # Seed metadata may retain its original deliberately rich dependency
        # fields; only these two explicit installed versions define this graph.
        self.assertEqual(set(top["dependencies"]) | {top["name"]}, set(PACKAGES))
        for package, version in ((PACKAGES[0], "2.0.0"), (PACKAGES[1], "1.0.0"), (FORBIDDEN, "3.0.0")):
            with self.assertRaises(ValueError): registry.tarball_path(package, version)

    def test_dependency_publication_cannot_expand_graph_or_change_canonical_archive(self):
        spec = SPECS["publish_dependency"]
        original = publish_document(spec)
        attachment = next(iter(original["_attachments"]))
        for mutate in (
                lambda value: value["versions"]["1.0.2"].update(dependencies={}),
                lambda value: value["versions"]["1.0.2"].update(dependencies={PACKAGES[1]: "^3.0.0"}),
                lambda value: value["versions"]["1.0.2"].update(dependencies={PACKAGES[1]: "3.0.0", FORBIDDEN: "1.0.0"}),
                lambda value: value["versions"]["1.0.2"].update(scripts={"postinstall": "canary"}),
                lambda value: value["versions"]["1.0.2"]["dist"].update(tarball="https://elsewhere.invalid/changed")):
            candidate = deepcopy(original)
            mutate(candidate)
            with self.assertRaises(ValueError): registry.validate_publish(encoded(candidate), spec)
        # Identical tar members compressed under a different gzip header are
        # still different published bytes; recomputing all hashes cannot admit.
        candidate = deepcopy(original)
        blob = bytearray(expected_tarball(spec))
        blob[4] = 1
        self.assertEqual(gzip.decompress(blob), gzip.decompress(expected_tarball(spec)))
        candidate["_attachments"][attachment]["data"] = base64.b64encode(blob).decode()
        candidate["versions"]["1.0.2"]["dist"].update(
            integrity="sha512-" + base64.b64encode(hashlib.sha512(blob).digest()).decode(),
            shasum=hashlib.sha1(blob, usedforsecurity=False).hexdigest())
        with self.assertRaises(ValueError): registry.validate_publish(encoded(candidate), spec)
        # The new dependency exception does not relax either older publication.
        for case in PUBLICATIONS[:2]:
            candidate = publish_document(SPECS[case])
            candidate["versions"][SPECS[case]["version"]]["dependencies"] = {PACKAGES[1]: "3.0.0"}
            with self.assertRaises(ValueError): registry.validate_publish(encoded(candidate), SPECS[case])

    def test_all_install_phase_permutations_are_exact_sets_with_cold_ci_no_metadata(self):
        completed, _ = self.complete()
        before = {path: path.read_bytes() for path in self.directory.iterdir()}
        for case, start in (("install_published", 11), ("ci_published", 16), ("install_audit_negative", 19)):
            self.assertEqual(registry.install_requests(case), INSTALL_REQUESTS[case])
            self.assertEqual(len(set(INSTALL_REQUESTS[case])), 3 if case == "ci_published" else 5)
            for order in permutations(INSTALL_REQUESTS[case]):
                state = SimpleNamespace(total=start, attempts=[], stored=deepcopy(completed.stored))
                for request in order:
                    self.assert_install_row(state, case, request, *install_receive(state, case, request))
                self.assertEqual(Counter((row["method"], row["rawTarget"]) for row in state.attempts),
                    Counter(item[:2] for item in INSTALL_REQUESTS[case]))
                self.assertEqual(state.total, start + len(order))
                self.assertEqual(state.stored, completed.stored)
        self.assertEqual({path: path.read_bytes() for path in self.directory.iterdir()}, before)

    def test_install_duplicates_retries_and_cross_phase_requests_refuse(self):
        completed, _ = self.complete()
        for case, start in (("install_published", 11), ("ci_published", 16), ("install_audit_negative", 19)):
            for request in INSTALL_REQUESTS[case]:
                state = SimpleNamespace(total=start, attempts=[], stored=deepcopy(completed.stored))
                self.assert_install_row(state, case, request, *install_receive(state, case, request))
                self.assertEqual(install_receive(state, case, request)[:2], (400, REFUSAL))
                self.assertEqual(state.attempts[-1], {"ordinal": start + 2, "accepted": False})
        for start, request in ((0, INSTALL_ROWS[2]), (9, INSTALL_ROWS[2]), (24, INSTALL_ROWS[2]),
                (25, INSTALL_ROWS[4]), (16, INSTALL_ROWS[0]), (16, INSTALL_ROWS[1])):
            state = SimpleNamespace(total=start, attempts=[], stored=deepcopy(completed.stored))
            self.assertEqual(install_receive(state, "install_published", request)[:2], (400, REFUSAL))
            self.assertEqual(state.attempts[-1], {"ordinal": start + 1, "accepted": False})
        for case in INSTALL_CASES:
            with self.assertRaises(ValueError): registry.install_requests(case + "-retry")

    def test_install_requests_refuse_wrong_credentials_headers_paths_methods_and_body(self):
        completed, _ = self.complete()
        for request in INSTALL_ROWS:
            body = compressed(encoded(AUDIT_DOCUMENT)) if request[2] == "audit" else b""
            original = install_fields("install_published", request, len(body))
            for name, value in (("authorization", "Bearer " + registry.PLACEHOLDER),
                    ("authorization", "Bearer private-canary"), ("host", "elsewhere.invalid"),
                    ("npm-command", "ci"), ("accept", CORGI if request[2] == "metadata" else FULL),
                    ("content-length", str(len(body) + 1))):
                state = SimpleNamespace(total=11, attempts=[], stored=deepcopy(completed.stored))
                self.assertEqual(install_receive(state, "install_published", request,
                    headers=changed(original, name, value))[:2], (400, REFUSAL))
                self.assertEqual(state.attempts, [{"ordinal": 12, "accepted": False}])
            for header in (("authorization", "Bearer " + registry.TOKEN), ("proxy-authorization", "private-canary"),
                    ("x-private", "private-canary"), ("accept-encoding", "gzip"), ("npm-session", "private-canary")):
                state = SimpleNamespace(total=11, attempts=[], stored=deepcopy(completed.stored))
                self.assertEqual(install_receive(state, "install_published", request,
                    headers=original + [header])[:2], (400, REFUSAL))
            for method in ("PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                state = SimpleNamespace(total=11, attempts=[], stored=deepcopy(completed.stored))
                self.assertEqual(install_receive(state, "install_published", request, method=method)[:2], (400, REFUSAL))
            for pathname in (request[1] + "?write=true", request[1] + "/", "/" + FORBIDDEN,
                    "/-/npm/v1/security/audits/quick"):
                state = SimpleNamespace(total=11, attempts=[], stored=deepcopy(completed.stored))
                self.assertEqual(install_receive(state, "install_published", request, path=pathname)[:2], (400, REFUSAL))
        for request in INSTALL_ROWS[:4]:
            state = SimpleNamespace(total=11, attempts=[], stored=deepcopy(completed.stored))
            self.assertEqual(install_receive(state, "install_published", request, body=b"private-canary")[:2], (400, REFUSAL))
        for request, header, value in ((INSTALL_ROWS[2], "pacote-integrity", "sha512-AAAA"),
                (INSTALL_ROWS[3], "pacote-pkg-id", "remote:" + FORBIDDEN),
                (INSTALL_ROWS[4], "content-encoding", "identity")):
            body = compressed(encoded(AUDIT_DOCUMENT)) if request[2] == "audit" else b""
            state = SimpleNamespace(total=11, attempts=[], stored=deepcopy(completed.stored))
            self.assertEqual(install_receive(state, "install_published", request,
                headers=changed(install_fields("install_published", request, len(body)), header, value))[:2], (400, REFUSAL))
        self.assertNotIn("private-canary", self.stderr.getvalue())

    def test_audit_gzip_single_member_strict_json_and_both_body_bounds(self):
        raw = encoded(AUDIT_DOCUMENT)
        good = compressed(raw)
        self.assertEqual(good, compressed(raw))
        self.assertEqual(good[4:8], b"\0\0\0\0")
        expected = {"operation": "npm.install.audit.read", "packages": sorted(PACKAGES), "packageVersions": AUDIT_DOCUMENT}
        self.assertEqual(registry.validate_audit(good), expected)
        self.assertEqual(registry.validate_audit(compressed(raw + b" " * (4096 - len(raw)))), expected)
        # Wire bound can be hit without growing plaintext using a bounded gzip
        # comment; gzip header bytes are not authority or package semantics.
        header = bytearray(good[:10])
        header[3] |= 16
        maximum_wire = bytes(header) + b"x" * (65536 - len(good) - 1) + b"\0" + good[10:]
        self.assertEqual(len(maximum_wire), 65536)
        self.assertEqual(registry.validate_audit(maximum_wire), expected)
        duplicate = b'{"' + PACKAGES[0].encode() + b'":["1.0.2"],"' + PACKAGES[0].encode() + b'":["1.0.2"],"' + PACKAGES[1].encode() + b'":["3.0.0"]}'
        malformed = [b"", raw, good[:-1], good + b"junk", good + good,
            good[:-1] + bytes([good[-1] ^ 1]), maximum_wire + b"x",
            compressed(raw + b" " * (4097 - len(raw))), compressed(duplicate),
            compressed(b'{"private-canary":NaN}'), compressed(b'{"private-canary":1e999}'),
            compressed(raw + b'{}'), compressed(encoded({PACKAGES[0]: ["1.0.2"]})),
            compressed(encoded({**AUDIT_DOCUMENT, FORBIDDEN: ["1.0.0"]})),
            compressed(encoded({PACKAGES[0]: ["2.0.0"], PACKAGES[1]: ["3.0.0"]})),
            compressed(encoded({PACKAGES[0]: ["1.0.2", "1.0.2"], PACKAGES[1]: ["3.0.0"]})),
            compressed(encoded({PACKAGES[0]: "1.0.2", PACKAGES[1]: ["3.0.0"]}))]
        for index, candidate in enumerate(malformed):
            with self.subTest(index=index), self.assertRaises(ValueError): registry.validate_audit(candidate)
        with self.assertRaises(ValueError): registry.validate_audit(bytearray(good))

    def test_negative_audit_is_recorded_as_real_400_without_relaxing_refusals(self):
        completed, _ = self.complete()
        row = next(row for row in completed.attempts if row["case"] == "install_audit_negative" and row["method"] == "POST")
        self.assertTrue(row["accepted"])
        self.assertEqual((row["status"], row["operation"]["operation"]), (400, "npm.install.audit.read"))
        self.assertEqual(row["responseBodySha256"], digest(b'{"error":"synthetic_audit_refused"}'))
        state = SimpleNamespace(total=19, attempts=[], stored=deepcopy(completed.stored))
        canary = compressed(b'{"private-canary":["secret-version"]}')
        self.assertEqual(install_receive(state, "install_audit_negative", INSTALL_ROWS[4], body=canary)[:2], (400, REFUSAL))
        self.assertEqual(state.attempts, [{"ordinal": 20, "accepted": False}])
        record = json.loads(self.stderr.getvalue().splitlines()[-1])
        self.assertEqual((record["expectedCase"], record["expectedMethod"], record["actualMethod"]),
            ("install_audit_negative", None, "POST"))
        self.assertNotIn("private-canary", json.dumps(state.attempts) + self.stderr.getvalue())

    def test_download_rereads_persisted_bytes_and_never_substitutes_packument_claims(self):
        completed, _ = self.complete()
        request = INSTALL_ROWS[2]
        pathname = self.directory / "publish_dependency.tgz"
        before = pathname.read_bytes()
        pathname.chmod(0o600)
        pathname.write_bytes(b"changed-private-canary")
        state = SimpleNamespace(total=11, attempts=[], stored=deepcopy(completed.stored))
        self.assertEqual(install_receive(state, "install_published", request)[:2], (400, REFUSAL))
        self.assertEqual(state.attempts, [{"ordinal": 12, "accepted": False}])
        pathname.write_bytes(before)
        pathname.chmod(0o400)
        missing = SimpleNamespace(total=11, attempts=[], stored=deepcopy(completed.stored[:2]))
        self.assertEqual(install_receive(missing, "install_published", request)[:2], (400, REFUSAL))
        self.assertEqual(registry.stored_observations(self.directory, completed.stored), completed.stored)

    def test_dependency_publish_strict_json_and_wire_bound(self):
        spec = SPECS["publish_dependency"]
        raw = encoded(publish_document(spec))
        expected = registry.validate_publish(raw, spec)
        self.assertEqual(registry.validate_publish(raw + b" " * (65536 - len(raw)), spec), expected)
        for candidate in (raw + b" " * (65537 - len(raw)), raw + b'{}',
                b'{"name":"private-canary",' + raw[1:], b'{"private-canary":NaN}',
                b'{"private-canary":Infinity}', b'{"private-canary":1e999}', raw[:-1], b''):
            with self.assertRaises(ValueError): registry.validate_publish(candidate, spec)


if __name__ == "__main__":
    unittest.main()
