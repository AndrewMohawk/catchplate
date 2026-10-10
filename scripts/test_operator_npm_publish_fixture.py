#!/usr/bin/env python3
"""Pure independent publish-fixture controls, never runtime acceptance.

Receiver handlers use in-memory requests and an explicitly simulated file sink;
no HTTP parser, socket, container, provider, executable or durable write runs.
"""
import ast
import base64
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timezone
from email.message import Message
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import operator_npm_publish_fixture as registry
from scripts import operator_npm_metadata_fixture_network as network
from scripts import prepare_operator_npm_publish_fixture as recipe
from scripts import check_operator_npm_publish as check

SOURCE, BINARY, INITIALIZER, NODE, NPM = map(Path,
    ("/synthetic/source", "/synthetic/gate", "/synthetic/init.py", "/synthetic/node", "/synthetic/npm"))
ROOT = recipe.base.SCRATCH / "serverware-npm-publish-private.Source01"
SHA = "a" * 64
PACKAGES = ("serverware-fixture-publish", "@serverware-fixture/publish")
TAG = "fixture"
ARRIVALS = (("prerequisite", "GET"), ("unscoped", "GET"), ("unscoped", "PUT"),
    ("scoped", "GET"), ("scoped", "PUT"), ("outside_window", "GET"))


def encoded(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def build():
    return recipe.build(SOURCE, BINARY, INITIALIZER, ROOT, NODE, NPM, expected_binary_sha256=SHA)


def publish_document(spec):
    # Independent stock-shaped document, not production npm_publish helpers.
    package, version = spec["package"], spec["version"]
    blob = registry.tarball(spec)
    name = package + "-" + version + ".tgz"
    manifest = {"name": package, "version": version, "_id": package + "@" + version,
        "description": "Synthetic publication fixture", "license": "MIT", "main": "index.js",
        "_nodeVersion": "25.5.0", "_npmVersion": "11.8.0", "dist": {
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(blob).digest()).decode(),
            "shasum": hashlib.sha1(blob, usedforsecurity=False).hexdigest(),
            "tarball": "http://registry.npmjs.org/" + package + "/-/" + name}}
    return {"_id": package, "name": package, "description": "Synthetic publication fixture",
        "dist-tags": {TAG: version}, "versions": {version: manifest}, "access": "public",
        "_attachments": {name: {"content_type": "application/octet-stream",
            "data": base64.b64encode(blob).decode(), "length": len(blob)}}}


def headers(method, package, length):
    result = [("host", "registry.npmjs.org"), ("authorization", "Bearer " + registry.TOKEN),
        ("accept", "*/*" if method == "PUT" else
            "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"),
        ("npm-command", "publish"), ("npm-auth-type", "web"),
        ("user-agent", "npm/11.8.0 node/v25.5.0 linux x64 workspaces/false"),
        ("connection", "close"), ("content-length", str(length))]
    if method == "PUT":
        result.append(("content-type", "application/json"))
    else:
        result.extend((("pacote-version", "21.0.4"), ("pacote-req-type", "packument"),
            ("pacote-pkg-id", "registry:" + package)))
    return result


def receiver(server, method, package, body=b"", *, fields=None, path=None):
    handler = object.__new__(registry.Handler)
    handler.server, handler.command = server, method
    handler.path = "/" + package.replace("/", "%2f") if path is None else path
    handler.headers = Message()
    for name, value in headers(method, package, len(body)) if fields is None else fields:
        handler.headers[name] = value
    handler.rfile = io.BytesIO(body)
    responses = []
    handler.send = lambda status, value, content_type="application/json": responses.append((status, value, content_type))
    registry.Handler.resource(handler)
    assert len(responses) == 1
    return responses[0]


class NpmPublishFixtureTests(unittest.TestCase):
    def setUp(self):
        guard = ExitStack(); self.addCleanup(guard.close)
        self.receiver_stderr = io.StringIO()
        guard.enter_context(patch("sys.stderr", self.receiver_stderr))
        for target in ("socket.socket", "socket.create_connection", "socket.getaddrinfo", "subprocess.Popen",
                "subprocess.run", "os.open", "os.mkdir", "os.makedirs", "os.fsync"):
            guard.enter_context(patch(target, side_effect=AssertionError("pure publish fixture test attempted runtime I/O")))

    def test_exact_network_none_recipe_and_private_mounts(self):
        config = build(); services = config["services"]
        shared = {"serverware", "decision-gate-rs", "npm-registry", "edge", "check"}
        self.assertEqual(set(config), {"name", "services"})
        self.assertEqual(set(services), shared | {"initialize", "npm-pki", "basic-pki", "network"})
        recipe.validate(config, SOURCE, BINARY, INITIALIZER, ROOT, NODE, NPM, expected_binary_sha256=SHA)
        for name, service in services.items():
            self.assertEqual(service["network_mode"], "service:network" if name in shared else "none")
            self.assertEqual(service["pull_policy"], "never")
            self.assertEqual(service["restart"], "no")
            self.assertIs(service["read_only"], True)
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertIn("no-new-privileges:true", service["security_opt"])
            self.assertEqual(service["mem_limit"], service["memswap_limit"])
            self.assertLessEqual(service["pids_limit"], 128)
            for field in ("ports", "expose", "networks", "privileged", "devices", "pid", "ipc", "env_file", "dns"):
                self.assertNotIn(field, service)
            self.assertEqual(len(service["volumes"]), len({row["target"] for row in service["volumes"]}))
            for row in service["volumes"]:
                self.assertEqual(row["bind"], {"create_host_path": False})
                self.assertNotIn("serverware-npm-metadata-private.", row["source"])
        check = {row["target"]: row for row in services["check"]["volumes"]}
        self.assertEqual({target for target, row in check.items() if not row["read_only"]}, {"/client-work"})
        self.assertEqual(check["/client-packages"]["source"], str(ROOT / "runtime/upstream-data/npm/packages"))
        for forbidden in ("/data", "/npm-state", "/run/secrets/serverware", "/var/run/docker.sock"):
            self.assertNotIn(forbidden, check)
        mounts = {row["target"]: row for row in services["npm-registry"]["volumes"]}
        self.assertEqual({target for target, row in mounts.items() if not row["read_only"]}, {"/npm-state"})
        self.assertEqual(mounts["/npm-state"]["source"], str(ROOT / "runtime/upstream-data/npm-publish-state"))
        for name in ("serverware", "decision-gate-rs"):
            env = services[name]["environment"]
            self.assertEqual(json.loads(env["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"]), ["https://registry.npmjs.org"])
            self.assertNotIn("SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS", env)
        self.assertEqual(services["network"]["cap_add"], ["NET_ADMIN", "SETUID", "SETGID"])
        self.assertEqual(services["network"]["user"], "0:0")
        self.assertEqual(services["check"]["command"][-2:], ["--timeout-seconds", "180"])

    def test_recipe_refuses_arbitrary_network_mount_command_and_bound_changes(self):
        changes = [lambda s: s["check"].update(network_mode="host"),
            lambda s: s["npm-registry"].update(ports=["443:443"]),
            lambda s: s["check"].update(privileged=True),
            lambda s: s["serverware"]["environment"].update(SERVERWARE_OPERATOR_DEMO_UPSTREAMS='["https://real.invalid"]'),
            lambda s: s["check"]["volumes"].append(recipe.bind(Path("/private"), "/data")),
            lambda s: s["npm-registry"]["volumes"][-1].update(read_only=True),
            lambda s: s["check"].update(command=["npm", "publish"]),
            lambda s: s["network"].update(cap_add=["ALL"]),
            lambda s: s["check"].update(memswap_limit="2g"),
            lambda s: s["check"].update(pids_limit=1024)]
        for index, change in enumerate(changes):
            value = build(); change(value["services"])
            with self.subTest(index=index), self.assertRaises(ValueError):
                recipe.validate(value, SOURCE, BINARY, INITIALIZER, ROOT, NODE, NPM, expected_binary_sha256=SHA)
        for root in (Path("/tmp/serverware-npm-publish-private.Source01"), ROOT.parent,
                ROOT.with_name("serverware-npm-metadata-private.Source01"), ROOT.with_name("serverware-npm-publish-private.short")):
            with self.assertRaises(ValueError):
                recipe.build(SOURCE, BINARY, INITIALIZER, root, NODE, NPM, expected_binary_sha256=SHA)

    def test_fixed_finite_cases_inert_tarballs_and_independent_receiver_projection(self):
        self.assertEqual(registry.PACKAGES, PACKAGES)
        self.assertEqual(registry.TAG, TAG)
        self.assertEqual(registry.ARRIVALS, ARRIVALS)
        self.assertEqual((registry.MAX_BODY, registry.MAX_ATTEMPTS), (65536, 16))
        self.assertEqual([row["case"] for row in registry.SPECS],
            ["prerequisite", "unscoped", "scoped", "wrong_package", "outside_window", "wrong_placeholder", "revoked_app"])
        self.assertEqual([row["case"] for row in registry.SPECS if row["success"]], ["unscoped", "scoped"])
        for spec in registry.SPECS:
            blob = registry.tarball(spec)
            self.assertEqual(blob, registry.tarball(spec))
            self.assertLess(len(blob), 32768)
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
                self.assertEqual(archive.getnames(), ["package/package.json", "package/index.js"])
                self.assertTrue(all(item.isfile() and item.mode == 0o644 and item.mtime == 0 for item in archive.getmembers()))
                manifest = json.load(archive.extractfile("package/package.json"))
                self.assertEqual(manifest, {"name": spec["package"], "version": spec["version"],
                    "description": "Synthetic publication fixture", "license": "MIT", "main": "index.js"})
            value = publish_document(spec)
            stored, manifest, actual = registry.validate_publish(encoded(value), spec)
            name = spec["package"] + "-" + spec["version"] + ".tgz"
            self.assertEqual(stored, {"package": spec["package"], "version": spec["version"], "tag": TAG,
                "attachmentName": name, "attachmentBytes": len(blob), "tarballSha256": digest(blob),
                "tarballIntegrity": "sha512-" + base64.b64encode(hashlib.sha512(blob).digest()).decode(),
                "tarballShasum": hashlib.sha1(blob, usedforsecurity=False).hexdigest()})
            self.assertEqual(actual, blob)
            self.assertEqual(manifest, value["versions"][spec["version"]])

    def test_receiver_rejects_identity_tag_extra_attachment_and_digest_drift(self):
        spec = registry.spec_for("scoped"); version = spec["version"]
        name = spec["package"] + "-" + version + ".tgz"
        changes = [lambda v: v.update(name="other"), lambda v: v.update(_id="other"),
            lambda v: v.update(access=None), lambda v: v.update(extra=True),
            lambda v: v.update({"dist-tags": {"latest": version}}),
            lambda v: v["dist-tags"].update(other=version),
            lambda v: v["versions"].update({"8.0.0": deepcopy(v["versions"][version])}),
            lambda v: v["versions"][version].update(_id="wrong@" + version),
            lambda v: v["versions"][version].update(_npmVersion="11.7.0"),
            lambda v: v["versions"][version].update(scripts={"prepare": "never execute"}),
            lambda v: v["versions"][version]["dist"].update(integrity="sha512-AAAA"),
            lambda v: v["versions"][version]["dist"].update(shasum="0" * 40),
            lambda v: v["versions"][version]["dist"].update(tarball="http://other.invalid/archive.tgz"),
            lambda v: v["versions"][version]["dist"].update(extra=True),
            lambda v: v["_attachments"].update({"extra.sigstore": {"data": "synthetic"}}),
            lambda v: v["_attachments"][name].update(length=True),
            lambda v: v["_attachments"][name].update(length=1),
            lambda v: v["_attachments"][name].update(content_type="application/gzip"),
            lambda v: v["_attachments"][name].update(data="YQ=="),
            lambda v: v["_attachments"][name].update(data=v["_attachments"][name]["data"] + "\n")]
        for index, change in enumerate(changes):
            value = publish_document(spec); change(value)
            with self.subTest(index=index), self.assertRaises(ValueError): registry.validate_publish(encoded(value), spec)
        raw = encoded(publish_document(spec))
        for body in (b"", b"[]", b"{}", raw[:-1] + b',"name":"duplicate"}',
                raw.replace(b'"license":"MIT"', b'"license":NaN'),
                raw.replace(b'"license":"MIT"', b'"license":1e999'), raw + b" " * 65536):
            with self.assertRaises(ValueError): registry.validate_publish(body, spec)

    def test_physical_header_oracle_has_no_placeholder_or_secret_in_observations(self):
        for method in ("GET", "PUT"):
            length = 50 if method == "PUT" else 0
            fields = headers(method, PACKAGES[0], length)
            public = registry.validate_headers(fields, method, PACKAGES[0], length)
            for private in ("authorization", "connection", "content-length", "cache-control"):
                self.assertNotIn(private, public)
            self.assertNotIn(registry.TOKEN, json.dumps(public))
            for extra in (("authorization", "Bearer wrong"), ("accept-encoding", "gzip"),
                    ("npm-session", "unreviewed"), ("x-extra", "unreviewed"), ("host", "other.invalid")):
                with self.subTest(method=method, extra=extra[0]), self.assertRaises(ValueError):
                    registry.validate_headers(fields + [extra], method, PACKAGES[0], length)
            for name, bad in (("authorization", "Bearer " + registry.PLACEHOLDER), ("npm-command", "view"),
                    ("host", "other.invalid"), ("content-length", str(length + 1))):
                changed = [(key, bad if key == name else value) for key, value in fields]
                with self.assertRaises(ValueError): registry.validate_headers(changed, method, PACKAGES[0], length)

    def sequence(self):
        server = SimpleNamespace(total=0, attempts=[], stored=[])
        saved = {}
        def save(path, raw):
            self.assertEqual(path.parent, Path("/npm-state"))
            if str(path) in saved: raise FileExistsError("synthetic immutable duplicate")
            saved[str(path)] = raw
        def directory(path, flags):
            self.assertEqual((path, flags), ("/npm-state", os.O_RDONLY | os.O_DIRECTORY))
            return 314
        with patch.object(registry, "save_new", side_effect=save), \
                patch.object(registry.os, "open", side_effect=directory), \
                patch.object(registry.os, "fsync", side_effect=lambda fd: self.assertEqual(fd, 314)), \
                patch.object(registry.os, "close", side_effect=lambda fd: self.assertEqual(fd, 314)):
            for case, method in ARRIVALS:
                spec = registry.spec_for(case)
                body = encoded(publish_document(spec)) if method == "PUT" else b""
                status, response, media = receiver(server, method, spec["package"], body)
                self.assertEqual(status, 201 if method == "PUT" else 200)
                self.assertEqual(media, "application/json" if method == "PUT" else "application/vnd.npm.install-v1+json")
                row = server.attempts[-1]
                self.assertEqual((row["case"], row["method"], row["requestBodySha256"], row["responseBodySha256"]),
                    (case, method, digest(body), digest(response)))
                self.assertTrue(row["accepted"])
                self.assertEqual(row["operation"]["operation"], "npm.publish" if method == "PUT" else "npm.metadata.read")
        return server, saved

    def test_real_handler_finite_sequence_joins_two_immutable_in_memory_versions(self):
        server, saved = self.sequence()
        self.assertEqual(server.total, 6)
        self.assertEqual([(row["package"], row["version"], row["tag"]) for row in server.stored],
            [(PACKAGES[0], "2.0.0", TAG), (PACKAGES[1], "3.0.0", TAG)])
        self.assertEqual(set(saved), {"/npm-state/unscoped.tgz", "/npm-state/unscoped.json",
            "/npm-state/scoped.tgz", "/npm-state/scoped.json"})
        for row in server.stored:
            self.assertEqual(digest(saved["/npm-state/" + row["case"] + ".tgz"]), row["tarballSha256"])
            self.assertEqual(json.loads(saved["/npm-state/" + row["case"] + ".json"]), row)
        self.assertNotIn(registry.TOKEN, json.dumps(server.attempts))
        packument = registry.packument(PACKAGES[0], server.stored)
        self.assertEqual(packument["dist-tags"], {TAG: "2.0.0"})
        self.assertEqual(set(packument["versions"]), {"2.0.0"})

    def checker(self):
        server, saved = self.sequence()
        observed = {"schema": "serverware.privateNpmPublishObservations/v1", "syntheticOnly": True,
            "total": server.total, "attempts": deepcopy(server.attempts), "stored": deepcopy(server.stored)}
        instance = object.__new__(check.NpmPublishCheck)
        instance.credential_id = "synthetic-credential"
        instance.completed = ["prerequisite", "unscoped", "scoped", "outside_window"]
        instance.phase_scopes = []
        for phase in instance.completed:
            base = ("principal-" + phase, "route-" + phase, "sha256:" + SHA)
            routes = {"GET": base if phase == "prerequisite" else (base[0], base[1] + ".metadata", base[2])}
            if phase != "prerequisite": routes["PUT"] = base
            instance.phase_scopes.append({"phase": phase, "principal": base[0], "policy": base[2], "routes": routes})
        instance.expected_denial_rows, instance.cutoff, instance.baseline = [], {}, {}
        instance.revocation = None
        instance.args = SimpleNamespace(expected_binary_sha256="sha256:" + SHA)
        self.assertEqual(instance.accept_observation(observed), server.stored)
        return instance, observed, saved

    def audit_rows(self, instance, *, pooled=False):
        rows = []
        def append(kind, event):
            identifier = "synthetic-audit-" + str(len(rows))
            rows.append({"id": identifier, "event_hash": digest(identifier.encode()), "event_type": kind, "event": event})
        for index, item in enumerate(instance.wire):
            attempt = digest(("attempt-" + str(index)).encode())
            common = {"attempt_id": attempt, "flow_id": attempt, "principal_id": item["scope"][0],
                "route_id": item["scope"][1], "policy_hash": item["scope"][2],
                "credential_ref": instance.credential_id, "credential_version": 1, "method": item["method"],
                "body_sha256": item["requestBodySha256"], "request_digest": item["requestDigest"],
                "operation_digest": item["operationDigest"]}
            append(check.START, {**common, "outcome": "release_started"})
            adapter, mode = ("npm.metadata.v1", "npmMetadataJsonV1") if item["method"] == "GET" else ("npm.publish.v1", "npmPublishJsonV1")
            append(check.RELEASE, {**common, "outcome": "released", "upstream_status": item["status"],
                "response_body_sha256": item["responseBodySha256"], "response_body_bytes": item["responseBodyBytes"],
                "response_validation": {"ok": True, "mode": mode, "adapter": adapter,
                    "body_bytes_preserved": True, "allowed_fields_redacted": False}})
        for phase in instance.phase_scopes:
            if phase["phase"] == "revoked_app":
                continue
            connection = {"principal_id": phase["principal"], "policy_hash": phase["policy"],
                "target": "registry.npmjs.org:443", "method": "CONNECT", "outcome": "established",
                "status_code": 200, "client_ip": "127.0.0.1",
                "route_ids": sorted({scope[1] for scope in phase["routes"].values()})}
            append(check.CONNECT, connection)
            append(check.KEEP_ALIVE if pooled else check.CONNECT,
                {**connection, "outcome": "keep_alive", "intercepted_request_count": 2} if pooled else deepcopy(connection))
        scope = instance.wire[0]["scope"]
        append(check.LEASE, {"principal_id": scope[0], "route_id": scope[1], "policy_hash": scope[2],
            "credential_id": instance.credential_id, "status_code": 200, "outcome": "issued",
            "data_plane_binary_digest": "sha256:" + SHA, "purpose": "dispatchSecret", "expected_credential_version": 1})
        return rows

    def complete_audit_fixture(self, *, pooled=False):
        """All seven stock-invocation scopes; no client or authority executes."""
        instance, observed, _ = self.checker()
        scopes = {row["phase"]: row for row in instance.phase_scopes}
        for phase in ("wrong_package", "wrong_placeholder"):
            # The real checker deliberately reuses the unscoped application
            # across these phases; bounds must count invocations, not just IDs.
            scopes[phase] = {**deepcopy(scopes["unscoped"]), "phase": phase}
        revoked = {**deepcopy(scopes["scoped"]), "phase": "revoked_app", "policy": "sha256:" + "b" * 64}
        revoked["routes"] = {method: (*scope[:2], revoked["policy"]) for method, scope in revoked["routes"].items()}
        scopes["revoked_app"] = revoked
        instance.completed = list(check.PHASES)
        instance.phase_scopes = [scopes[phase] for phase in instance.completed]
        instance.expected_denial_rows = []
        for phase in instance.phase_scopes:
            route = phase["routes"].get("PUT", phase["routes"]["GET"])[1]
            instance.expected_denial_rows.extend(check.expected_denials(phase["phase"], {}, {"route_id": route}))
        instance.before_revoke_policy = "sha256:" + SHA
        instance.revocation = ("operator_catalog.application.revoked", "synthetic-scoped-application", revoked["policy"])
        instance.snapshot = {"policy": {"sequence": 2}}
        instance.accept_observation(observed)
        rows = self.audit_rows(instance, pooled=pooled)
        def append(kind, event):
            identifier = "synthetic-audit-" + str(len(rows))
            rows.append({"id": identifier, "event_hash": digest(identifier.encode()), "event_type": kind, "event": event})
        for method, error, route, adapter, package in instance.expected_denial_rows:
            target = "/" + package.replace("/", "%2f")
            append(check.DENIED, {"method": method, "error": error, "route_id": route, "adapter": adapter,
                "outcome": "denied", "status_code": 403, "url": {
                    "origin_sha256": digest(b"https://registry.npmjs.org"), "origin_bytes": 26,
                    "path_sha256": digest(target.encode()), "path_bytes": len(target), "query_keys": []}})
        for _ in range(2):
            append(check.CONNECT_DENIED, {"principal_id": None, "target": "registry.npmjs.org:443", "method": "CONNECT",
                "outcome": "denied", "payload": {"error": "client_principal_denied"}})
        append(check.RELOAD, {"previous_policy_hash": instance.before_revoke_policy,
            "policy_hash": revoked["policy"], "policy_sequence": 2, "routes": 5})
        append(instance.revocation[0], {"resource_id": instance.revocation[1], "policy_hash": revoked["policy"]})
        return instance, observed, rows

    def test_checker_joins_exact_receiver_inventory_and_independent_canonical_commitments(self):
        instance, observed, _ = self.checker()
        self.assertEqual(len(instance.wire), 6)
        self.assertEqual(len({(row["requestDigest"], row["operationDigest"]) for row in instance.wire}), 6)
        for row in instance.wire:
            expected_headers = dict(row["requestHeaders"])
            self.assertNotIn("content-length", expected_headers)
            if row["method"] == "PUT":
                expected_headers["content-length"] = str(row["requestBodyBytes"])
            canonical = {"v": 2, "principal": row["scope"][0], "client_ip": "127.0.0.1",
                "route_id": row["scope"][1], "credential_ref": "synthetic-credential", "credential_version": "1",
                "policy_hash": row["scope"][2], "request": {"method": row["method"], "scheme": "https",
                    "authority": "registry.npmjs.org", "path": row["rawTarget"], "query": [],
                    "headers": expected_headers, "body_sha256": row["requestBodySha256"],
                    "discard_headers": ["accept-encoding", "npm-session"]}, "operation": row["operation"]}
            encode = lambda value: json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
            self.assertEqual(row["requestDigest"], digest(encode(canonical)))
            self.assertEqual(row["operationDigest"], digest(encode({k: v for k, v in canonical.items() if k not in {"v", "client_ip"}})))
            for header, value in (("authorization", "Bearer synthetic-private"), ("npm-session", "discarded"),
                    ("accept-encoding", "gzip"), ("x-unreviewed", "unknown"), ("host", "other.invalid")):
                changed = deepcopy(row); changed["requestHeaders"][header] = value
                with self.subTest(method=row["method"], header=header), self.assertRaises(check.CheckFailure):
                    check.canonical_digests(changed, row["scope"], instance.credential_id)
        for change in ("extra-arrival", "wrong-path", "wrong-method", "wrong-tag", "response-hash", "stored-version", "stored-digest"):
            value = deepcopy(observed)
            if change == "extra-arrival": value["total"] += 1; value["attempts"].append(deepcopy(value["attempts"][-1]))
            elif change == "wrong-path": value["attempts"][0]["rawTarget"] += "?unreviewed=1"
            elif change == "wrong-method": value["attempts"][0]["method"] = "PUT"
            elif change == "wrong-tag": value["attempts"][2]["operation"]["tag"] = "latest"
            elif change == "response-hash": value["attempts"][2]["responseBodySha256"] = "sha256:" + "f" * 64
            elif change == "stored-version": value["stored"][0]["version"] = "9.9.9"
            else: value["stored"][0]["tarballSha256"] = "sha256:" + "f" * 64
            with self.subTest(change=change), self.assertRaises(check.CheckFailure): instance.accept_observation(value)

    def test_put_framing_matches_independent_literal_canonical_v2_vector(self):
        # A canonical-layer vector, not an admitted publish document. Expected
        # bytes are literal and never come from the checker or its serializer.
        body_hash = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        self.assertEqual(digest(b"{}"), body_hash)
        scope = ("principal", "route", "sha256:" + "a" * 64)
        row = {"method": "PUT", "rawTarget": "/synthetic", "requestBodyBytes": 2,
            "requestBodySha256": body_hash, "requestHeaders": {"accept": "*/*", "content-type": "application/json",
                "host": "registry.npmjs.org", "npm-command": "publish"},
            "operation": {"operation": "npm.publish", "packageName": "synthetic"}}
        expected_operation = (
            b'{"credential_ref":"credential","credential_version":"1",'
            b'"operation":{"operation":"npm.publish","packageName":"synthetic"},'
            b'"policy_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
            b'"principal":"principal","request":{"authority":"registry.npmjs.org",'
            b'"body_sha256":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",'
            b'"discard_headers":["accept-encoding","npm-session"],'
            b'"headers":{"accept":"*/*","content-length":"2","content-type":"application/json",'
            b'"host":"registry.npmjs.org","npm-command":"publish"},'
            b'"method":"PUT","path":"/synthetic","query":[],"scheme":"https"},"route_id":"route"}')
        expected_request = b'{"client_ip":"127.0.0.1",' + expected_operation[1:-1] + b',"v":2}'
        expected = digest(expected_request), digest(expected_operation)
        original = deepcopy(row)
        self.assertEqual(check.canonical_digests(row, scope, "credential"), expected)
        self.assertEqual(row, original)
        self.assertNotIn("content-length", row["requestHeaders"])
        changed = {**row, "requestBodyBytes": 3}
        changed_expected = tuple(digest(raw.replace(b'"content-length":"2"', b'"content-length":"3"'))
            for raw in (expected_request, expected_operation))
        self.assertEqual(check.canonical_digests(changed, scope, "credential"), changed_expected)
        self.assertTrue(all(left != right for left, right in zip(expected, changed_expected)))

        # Independently framed wire commitments are the audit join oracle.
        wire = {**row, "scope": scope, "requestDigest": expected[0], "operationDigest": expected[1],
            "status": 201, "responseBodySha256": body_hash, "responseBodyBytes": 2}
        instance = SimpleNamespace(wire=[wire], phase_scopes=[], credential_id="credential")
        rows = self.audit_rows(instance)
        self.assertTrue(check.joined_attempts(rows, [wire], "credential")[1])
        bodyless = tuple(digest(raw.replace(b'"content-length":"2",', b""))
            for raw in (expected_request, expected_operation))
        for label, wrong in (("old-bodyless", bodyless), ("wrong-length", changed_expected)):
            wrong_rows = deepcopy(rows)
            for event in wrong_rows:
                if event["event_type"] in {check.START, check.RELEASE}:
                    event["event"].update(request_digest=wrong[0], operation_digest=wrong[1])
            with self.subTest(commitment=label), self.assertRaises(check.CheckFailure):
                check.joined_attempts(wrong_rows, [wire], "credential")

    def test_canonical_body_lengths_are_typed_bounded_and_never_taken_from_wire_headers(self):
        instance, _, _ = self.checker()
        for method in ("GET", "PUT"):
            row = next(row for row in instance.wire if row["method"] == method)
            original = deepcopy(row)
            initial = check.canonical_digests(row, row["scope"], instance.credential_id)
            self.assertEqual(row, original)
            self.assertNotIn("content-length", row["requestHeaders"])
            bad_lengths = (None, True, False, 0.0, 2.0, "0", "2", -1, 65537)
            bad_lengths += (1, 2, 65536) if method == "GET" else (0,)
            for size in bad_lengths:
                changed = {**deepcopy(row), "requestBodyBytes": size}
                with self.subTest(method=method, size=size), self.assertRaises(check.CheckFailure):
                    check.canonical_digests(changed, row["scope"], instance.credential_id)
            for size in ((0,) if method == "GET" else (1, 65536)):
                changed = {**deepcopy(row), "requestBodyBytes": size}
                value = check.canonical_digests(changed, row["scope"], instance.credential_id)
                self.assertEqual(len(value), 2)
                if method == "GET":
                    self.assertEqual(value, initial)
            for field, value in (("content-length", str(row["requestBodyBytes"])),
                    ("content-length", str(row["requestBodyBytes"] + 1)), ("content-length", "00"),
                    ("Content-Length", str(row["requestBodyBytes"])), ("authorization", "Bearer synthetic-private"),
                    ("transfer-encoding", "chunked")):
                changed = deepcopy(row)
                changed["requestHeaders"][field] = value
                with self.subTest(method=method, header=field, value=value), self.assertRaises(check.CheckFailure):
                    check.canonical_digests(changed, row["scope"], instance.credential_id)
        # The independent receiver still refuses mismatched physical framing;
        # canonical reconstruction does not turn a claimed length into proof.
        for method, length in (("GET", 0), ("PUT", 20)):
            fields = headers(method, PACKAGES[0], length)
            for claimed in (str(length + 1), "0" + str(length), "+" + str(length), "-1", "2.0"):
                changed = [(key, claimed if key == "content-length" else value) for key, value in fields]
                with self.subTest(method=method, claimed=claimed), self.assertRaises(ValueError):
                    registry.validate_headers(changed, method, PACKAGES[0], length)

    def test_checker_audit_pairs_refuse_rebinding_duplicates_and_changed_prefix(self):
        instance, _, _ = self.checker(); rows = self.audit_rows(instance)
        pairs, complete = check.joined_attempts(list(reversed(rows)), instance.wire, instance.credential_id)
        self.assertTrue(complete); self.assertEqual(len(pairs), 6)
        self.assertFalse(check.joined_attempts(rows[1:], instance.wire, instance.credential_id)[1])
        for change in ("duplicate", "attempt", "credential", "body", "policy", "route", "response", "mode", "blocked", "generation"):
            candidate = deepcopy(rows)
            if change == "duplicate": candidate.append(deepcopy(candidate[1]))
            elif change == "attempt": candidate[3]["event"]["attempt_id"] = candidate[1]["event"]["attempt_id"]
            elif change == "credential": candidate[0]["event"]["credential_ref"] = "other"
            elif change == "body": candidate[0]["event"]["body_sha256"] = "sha256:" + "f" * 64
            elif change == "policy": candidate[0]["event"]["policy_hash"] = "sha256:" + "f" * 64
            elif change == "route": candidate[0]["event"]["route_id"] += ".metadata"
            elif change == "response": candidate[1]["event"]["response_body_bytes"] += 1
            elif change == "mode": candidate[1]["event"]["response_validation"]["mode"] = "npmPublishJsonV1"
            elif change == "blocked": candidate[1]["event_type"] = check.BLOCK
            else: candidate[0]["event"]["credential_version"] = True
            with self.subTest(change=change), self.assertRaises(check.CheckFailure):
                check.joined_attempts(candidate, instance.wire, instance.credential_id)
        complete, evidence = instance.validate_audits(rows)
        self.assertTrue(complete)
        self.assertEqual(len(evidence["auditAttemptIds"]), 6)
        for candidate in (rows[1:], [{**rows[0], "event_hash": "sha256:" + "f" * 64}, *rows[1:]]):
            with self.assertRaises(check.CheckFailure): instance.validate_audits(candidate)
        for key, bad in (("expected_credential_version", True), ("route_id", "never-forwarded"),
                ("data_plane_binary_digest", "sha256:" + "f" * 64), ("purpose", "unknown")):
            candidate = deepcopy(rows); candidate[-1]["event"][key] = bad
            with self.subTest(lease_field=key), self.assertRaises(check.CheckFailure): instance.validate_audits(candidate)

    def test_checker_accepts_separate_or_reused_tunnels_without_changing_publication_inventory(self):
        for mode in ("separate", "reused", "mixed"):
            instance, observed, rows = self.complete_audit_fixture(pooled=mode != "separate")
            if mode == "mixed":
                # One of three invocations sharing the unscoped authority uses
                # separate tunnels; the other two reuse their own tunnel.
                row = next(row for row in rows if row["event_type"] == check.KEEP_ALIVE
                    and row["event"]["principal_id"] == "principal-unscoped")
                row["event_type"] = check.CONNECT
                row["event"]["outcome"] = "established"
                row["event"].pop("intercepted_request_count")
            complete, evidence = instance.validate_audits(list(reversed(rows)))
            with self.subTest(mode=mode):
                self.assertTrue(complete)
                self.assertEqual(len(evidence["auditAttemptIds"]), 6)
                counts = evidence["namedAuditInventory"]
                self.assertEqual(counts[check.CONNECT], {"separate": 12, "reused": 6, "mixed": 7}[mode])
                self.assertEqual(counts.get(check.KEEP_ALIVE, 0), {"separate": 0, "reused": 6, "mixed": 5}[mode])
                self.assertEqual((counts[check.START], counts[check.RELEASE], counts[check.DENIED], counts[check.CONNECT_DENIED]),
                    (6, 6, 6, 2))
                self.assertEqual(observed["total"], 6)
                self.assertEqual([(row["case"], row["method"]) for row in instance.wire], list(ARRIVALS))
                self.assertEqual([row["case"] for row in instance.wire if row["method"] == "PUT"], ["unscoped", "scoped"])
                self.assertEqual([row["case"] for row in observed["stored"]], ["unscoped", "scoped"])

    def test_checker_first_prerequisite_get_then_denied_put_accepts_one_reused_tunnel(self):
        instance, observed, rows = self.complete_audit_fixture(pooled=True)
        scope = instance.phase_scopes[0]
        instance.completed, instance.phase_scopes = ["prerequisite"], [scope]
        instance.expected_denial_rows = check.expected_denials("prerequisite", {}, {"route_id": scope["routes"]["GET"][1]})
        instance.revocation = None
        first = {**observed, "total": 1, "attempts": [observed["attempts"][0]], "stored": []}
        instance.accept_observation(first)
        rows = [row for row in rows if row["event_type"] not in {check.DENIED, check.CONNECT_DENIED,
            check.RELOAD, "operator_catalog.application.revoked"} and row["event"].get("principal_id") == scope["principal"]]
        denial = instance.expected_denial_rows[0]
        target = "/" + denial[4].replace("/", "%2f")
        rows.append({"id": "synthetic-first-denial", "event_hash": digest(b"first-denial"), "event_type": check.DENIED,
            "event": {"method": denial[0], "error": denial[1], "route_id": None, "adapter": None,
                "outcome": "denied", "status_code": 403, "url": {
                    "origin_sha256": digest(b"https://registry.npmjs.org"), "origin_bytes": 26,
                    "path_sha256": digest(target.encode()), "path_bytes": len(target), "query_keys": []}}})
        complete, evidence = instance.validate_audits(rows)
        self.assertTrue(complete)
        self.assertEqual(evidence["namedAuditInventory"], {check.START: 1, check.RELEASE: 1, check.LEASE: 1,
            check.CONNECT: 1, check.KEEP_ALIVE: 1, check.DENIED: 1})
        self.assertEqual(len(instance.wire), 1)
        self.assertEqual(instance.wire[0]["method"], "GET")
        self.assertEqual(first["stored"], [])

    def test_checker_reused_tunnel_scope_types_fingerprint_and_event_bounds_are_strict(self):
        changes = [("principal_id", "not-a-completed-application"), ("policy_hash", "sha256:" + "f" * 64),
            ("target", "other.invalid:443"), ("method", "GET"), ("outcome", "established"),
            ("status_code", 403), ("status_code", 200.0), ("status_code", True),
            ("client_ip", "127.0.0.2"), ("client_ip", None), ("route_ids", ["misbound-route"])]
        changes.extend(("intercepted_request_count", value) for value in (None, True, 2.0, "2", 0, 1, 3, 100))
        for field, value in changes:
            instance, _, rows = self.complete_audit_fixture(pooled=True)
            candidate = next(row for row in rows if row["event_type"] == check.KEEP_ALIVE)
            candidate["event"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(check.CheckFailure):
                instance.validate_audits(rows)
        for change in ("unknown-event", "missing-count", "extra-public-field", "established-count", "duplicate-keepalive",
                "duplicate-established", "keepalive-without-established", "scope-not-completed"):
            instance, _, rows = self.complete_audit_fixture(pooled=True)
            kept = next(row for row in rows if row["event_type"] == check.KEEP_ALIVE)
            established = next(row for row in rows if row["event_type"] == check.CONNECT)
            if change == "unknown-event": kept["event_type"] += ".unknown"
            elif change == "missing-count": kept["event"].pop("intercepted_request_count")
            elif change == "extra-public-field": kept["event"]["unmatched_authority"] = "synthetic"
            elif change == "established-count": established["event"]["intercepted_request_count"] = 2
            elif change == "keepalive-without-established": rows.remove(established)
            elif change == "scope-not-completed": instance.completed.remove("prerequisite")
            else:
                extra = deepcopy(kept if change == "duplicate-keepalive" else established)
                extra.update(id="synthetic-excess", event_hash=digest(b"excess"))
                rows.append(extra)
            with self.subTest(change=change), self.assertRaises(check.CheckFailure):
                instance.validate_audits(rows)

    def test_checker_reused_tunnels_do_not_hide_denials_replays_or_unauthorized_puts(self):
        for change in ("missing-denial", "extra-denial", "unauthorized-dispatch", "unauthorized-put-arrival"):
            instance, observed, rows = self.complete_audit_fixture(pooled=True)
            if change == "missing-denial":
                rows.remove(next(row for row in rows if row["event_type"] == check.DENIED))
                self.assertFalse(instance.validate_audits(rows)[0])
                continue
            if change == "extra-denial":
                extra = deepcopy(next(row for row in rows if row["event_type"] == check.DENIED))
                extra.update(id="synthetic-extra-denial", event_hash=digest(b"extra-denial"))
                rows.append(extra)
            elif change == "unauthorized-dispatch":
                extra = deepcopy(next(row for row in rows if row["event_type"] == check.START))
                extra.update(id="synthetic-unauthorized-put", event_hash=digest(b"unauthorized-put"))
                extra["event"].update(method="PUT", attempt_id=digest(b"new-attempt"), flow_id=digest(b"new-attempt"))
                rows.append(extra)
            else:
                observed["total"] += 1
                row = deepcopy(observed["attempts"][2])
                row.update(ordinal=7, case="prerequisite")
                observed["attempts"].append(row)
                with self.assertRaises(check.CheckFailure): instance.accept_observation(observed)
                continue
            with self.subTest(change=change), self.assertRaises(check.CheckFailure):
                instance.validate_audits(rows)

    def test_checker_late_keepalive_receipts_are_required_and_cannot_change_retained_audit_prefix(self):
        instance, _, rows = self.complete_audit_fixture(pooled=True)
        incomplete = [row for row in rows if row["event_type"] != check.KEEP_ALIVE]
        self.assertFalse(instance.validate_audits(incomplete)[0])
        self.assertTrue(instance.validate_audits(rows)[0])
        with self.assertRaises(check.CheckFailure): instance.validate_audits(incomplete)
        changed = deepcopy(rows)
        next(row for row in changed if row["event_type"] == check.KEEP_ALIVE)["event_hash"] = "sha256:" + "f" * 64
        with self.assertRaises(check.CheckFailure): instance.validate_audits(changed)

    def test_denial_signatures_window_choice_and_fixed_failure_codec(self):
        rule = {"route_id": "route-fixture"}
        for phase in ("prerequisite", "wrong_package", "outside_window", "wrong_placeholder"):
            expected = check.expected_denials(phase, {}, rule)
            self.assertTrue(expected)
            for item in expected:
                method, error, route, adapter, package = item
                target = "/" + package.replace("/", "%2f")
                event = {"method": method, "error": error, "route_id": route, "adapter": adapter,
                    "outcome": "denied", "status_code": 403, "url": {
                        "origin_sha256": digest(b"https://registry.npmjs.org"), "origin_bytes": 26,
                        "path_sha256": digest(target.encode()), "path_bytes": len(target), "query_keys": []}}
                self.assertEqual(check.validate_denial(event, expected), item)
                for key, value in (("error", "unrelated403"), ("route_id", "wrong"), ("status_code", 502), ("url", {})):
                    with self.assertRaises(check.CheckFailure): check.validate_denial({**event, key: value}, expected)
        for hour in range(24):
            window = check.closed_window(datetime(2026, 10, 10, hour, 59, 59, tzinfo=timezone.utc))
            self.assertEqual(window, {"start": "18:00", "end": "19:00"} if hour < 12 else {"start": "06:00", "end": "07:00"})
        with self.assertRaises(check.CheckFailure): check.closed_window(datetime(2026, 10, 10))
        failure = {"schema": "serverware.privateNpmPublishClient/v1", "phase": "unscoped", "npmVersion": "11.8.0",
            "pacoteVersion": "21.0.4", "registryFetchVersion": "19.1.1", "strictSSL": True,
            "extraCaPreservesDefaultRoots": True, "configuredRetries": 0, "isolatedCache": True,
            "requestRewrite": False, "force": False, "dryRun": False, "provenance": False, "ok": False,
            "error": "stock npm publish operation failed", "stage": "npm_process", "errorCode": "E403",
            "processExitCode": 1, "stdoutBytes": 0, "stderrBytes": 40}
        self.assertEqual(set(check.client_failure_observation(failure, "unscoped")),
            {"phase", "stage", "errorCode", "processExitCode", "stdoutBytes", "stderrBytes"})
        for key, value in (("raw", "synthetic-secret"), ("error", "synthetic-secret"), ("stage", "synthetic-secret"),
                ("errorCode", "synthetic-secret"), ("processExitCode", True), ("stdoutBytes", 262145),
                ("stderrBytes", -1), ("configuredRetries", False), ("configuredRetries", 0.0),
                ("phase", "scoped"), ("force", True), ("provenance", True)):
            self.assertIsNone(check.client_failure_observation({**failure, key: value}, "unscoped"))
        for value in (None, [], {}, False): self.assertIsNone(check.client_failure_observation(failure, value))
        self.assertNotIn("E403", str(check.ClientFailure("unscoped", failure)))

    def test_positive_client_e400_is_closed_failure_diagnostic_not_a_publication_receipt(self):
        failure = {"schema": "serverware.privateNpmPublishClient/v1", "phase": "scoped", "npmVersion": "11.8.0",
            "pacoteVersion": "21.0.4", "registryFetchVersion": "19.1.1", "strictSSL": True,
            "extraCaPreservesDefaultRoots": True, "configuredRetries": 0, "isolatedCache": True,
            "requestRewrite": False, "force": False, "dryRun": False, "provenance": False, "ok": False,
            "error": "stock npm publish operation failed", "stage": "npm_process", "errorCode": "E400",
            "processExitCode": 1, "stdoutBytes": 76, "stderrBytes": 0}
        expected = {"phase": "scoped", "stage": "npm_process", "errorCode": "E400", "processExitCode": 1,
            "stdoutBytes": 76, "stderrBytes": 0}
        self.assertEqual(check.client_failure_observation(failure, "scoped"), expected)
        error = check.ClientFailure("scoped", failure)
        self.assertEqual(error.observation, expected)
        self.assertEqual(str(error), "stock npm publish failed in scoped; raw output suppressed")
        self.assertNotIn("E400", str(error))
        for key, value in (("ok", True), ("error", "synthetic-secret-body-canary"),
                ("raw", "synthetic-secret-body-canary"), ("headers", {"authorization": "Bearer " + registry.TOKEN}),
                ("stage", registry.PLACEHOLDER), ("errorCode", registry.TOKEN), ("processExitCode", True)):
            with self.subTest(field=key):
                candidate = {**failure, key: value}
                self.assertIsNone(check.client_failure_observation(candidate, "scoped"))
                self.assertIsNone(check.ClientFailure("scoped", candidate).observation)

    def test_receiver_refusal_diagnostic_has_closed_fields_labels_and_no_private_values(self):
        canary = "synthetic-private-header-body-error-canary"
        fields = {"schema", "ordinal", "expectedCase", "expectedMethod", "actualMethod", "stage", "errorClass"}
        stages = {"sequence", "target", "framing", "headers", "publish_identity", "publish_manifest",
            "publish_attachment", "publish_integrity", "storage", "response"}
        self.assertEqual(registry.REFUSAL_STAGES, stages)
        self.assertEqual(registry.REFUSAL_ERRORS, {"ValueError", "OSError", "TypeError", "KeyError"})
        self.assertEqual(registry.REFUSAL_METHODS, {"GET", "PUT", "POST", "PATCH", "DELETE", "HEAD", "OPTIONS"})
        for stage in sorted(stages):
            for kind in (ValueError, OSError, TypeError, KeyError):
                error = kind(canary + registry.TOKEN + registry.PLACEHOLDER)
                record = registry.refusal_observation(5, "scoped", "PUT", "PUT", stage, error)
                self.assertEqual(set(record), fields)
                self.assertEqual(record, {"schema": "serverware.privateNpmPublishRefusal/v1", "ordinal": 5,
                    "expectedCase": "scoped", "expectedMethod": "PUT", "actualMethod": "PUT",
                    "stage": stage, "errorClass": kind.__name__})
                output = io.StringIO()
                with patch("sys.stderr", output):
                    registry.emit_refusal(5, "scoped", "PUT", "PUT", stage, error)
                self.assertEqual(len(output.getvalue().splitlines()), 1)
                self.assertEqual(json.loads(output.getvalue()), record)
                self.assertLess(len(output.getvalue().encode()), 512)
                for private in (canary, registry.TOKEN, registry.PLACEHOLDER, "authorization", "requestHeaders", "traceback"):
                    self.assertNotIn(private, output.getvalue())
        wrapped = registry.FixtureRefusal("publish_integrity", ValueError(canary))
        self.assertEqual(str(wrapped), "private npm publish fixture refused")
        record = registry.refusal_observation(5, "scoped", "PUT", "PUT", "headers", wrapped)
        self.assertEqual((record["stage"], record["errorClass"]), ("publish_integrity", "ValueError"))
        record = registry.refusal_observation(5, "scoped", "PUT", canary, "target", ValueError(canary))
        self.assertEqual(record["actualMethod"], "other")
        self.assertNotIn(canary, json.dumps(record))
        controls = [(0, "scoped", "PUT", "headers", ValueError(canary)),
            (True, "prerequisite", "GET", "headers", ValueError(canary)),
            (5.0, "scoped", "PUT", "headers", ValueError(canary)),
            (17, None, None, "sequence", ValueError(canary)),
            (5, canary, "PUT", "headers", ValueError(canary)),
            (5, "scoped", "GET", "headers", ValueError(canary)),
            (5, "scoped", "PUT", canary, ValueError(canary)),
            (5, "scoped", "PUT", "headers", RuntimeError(canary))]
        for ordinal, case, method, stage, error in controls:
            self.assertIsNone(registry.refusal_observation(ordinal, case, method, "PUT", stage, error))
            output = io.StringIO()
            with patch("sys.stderr", output):
                registry.emit_refusal(ordinal, case, method, "PUT", stage, error)
            self.assertEqual(output.getvalue(), "")

    def test_handler_refusal_stages_keep_fixed_400_and_existing_publication_without_storage(self):
        canary = "synthetic-private-refusal-canary"
        spec = registry.spec_for("scoped")
        prior, _, _ = registry.validate_publish(encoded(publish_document(registry.spec_for("unscoped"))),
            registry.spec_for("unscoped"))
        prior["case"] = "unscoped"
        for stage in ("target", "framing", "headers", "publish_identity", "publish_manifest",
                "publish_attachment", "publish_integrity", "storage"):
            document = publish_document(spec)
            if stage == "publish_identity": document["name"] = canary
            elif stage == "publish_manifest": document["versions"][spec["version"]]["_npmVersion"] = canary
            elif stage == "publish_attachment": next(iter(document["_attachments"].values()))["data"] = canary
            elif stage == "publish_integrity": document["versions"][spec["version"]]["dist"]["tarball"] = canary
            body = encoded(document)
            fields = headers("PUT", spec["package"], len(body))
            if stage in {"framing", "headers"}:
                field = "content-length" if stage == "framing" else "authorization"
                value = "0" + str(len(body)) if stage == "framing" else "Bearer " + canary
                fields = [(key, value if key == field else old) for key, old in fields]
            server = SimpleNamespace(total=4, attempts=[], stored=[deepcopy(prior)])
            output = io.StringIO()
            fault = OSError(canary) if stage == "storage" else AssertionError("refused input reached storage")
            with patch("sys.stderr", output), patch.object(registry, "save_new", side_effect=fault) as save:
                status, response, media = receiver(server, "PUT", spec["package"], body, fields=fields,
                    path="/" + canary if stage == "target" else None)
            with self.subTest(stage=stage):
                self.assertEqual((status, response, media), (400, b'{"error":"synthetic publish fixture refused"}', "application/json"))
                self.assertEqual((server.total, server.attempts), (5, [{"ordinal": 5, "accepted": False}]))
                self.assertEqual(server.stored, [prior])
                self.assertEqual(save.call_count, 1 if stage == "storage" else 0)
                self.assertEqual(json.loads(output.getvalue()), {"schema": "serverware.privateNpmPublishRefusal/v1",
                    "ordinal": 5, "expectedCase": "scoped", "expectedMethod": "PUT", "actualMethod": "PUT",
                    "stage": stage, "errorClass": "OSError" if stage == "storage" else "ValueError"})
                self.assertNotIn(canary, output.getvalue())
                self.assertNotIn(registry.TOKEN, output.getvalue())
                self.assertNotIn(registry.PLACEHOLDER, output.getvalue())
        # Normal success remains six finite arrivals and exactly two immutable
        # in-memory publications. Diagnostics add no successful-path output.
        output = io.StringIO()
        with patch("sys.stderr", output):
            server, saved = self.sequence()
        self.assertEqual((server.total, len(server.stored), len(saved)), (6, 2, 4))
        self.assertEqual(output.getvalue(), "")

    def test_receiver_refusal_logging_is_bounded_and_broken_sink_never_changes_fixed_refusal(self):
        server = SimpleNamespace(total=0, attempts=[], stored=[])
        output = io.StringIO()
        with patch("sys.stderr", output):
            for _ in range(40):
                self.assertEqual(receiver(server, "POST", PACKAGES[0])[0], 400)
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(records), 16)
        self.assertEqual([row["ordinal"] for row in records], list(range(1, 17)))
        self.assertEqual((server.total, len(server.attempts), server.stored), (40, 16, []))
        self.assertEqual([row["stage"] for row in records], ["target"] * 6 + ["sequence"] * 10)
        self.assertTrue(all((row["expectedCase"], row["expectedMethod"]) == ARRIVALS[index]
            for index, row in enumerate(records[:6])))
        self.assertTrue(all(row["expectedCase"] is None and row["expectedMethod"] is None for row in records[6:]))
        self.assertTrue(all(row["actualMethod"] == "POST" and row["errorClass"] == "ValueError" for row in records))
        for broken in ("write", "flush"):
            sink = SimpleNamespace(write=lambda _: None, flush=lambda: None)
            def refuse(*_):
                raise OSError("synthetic-log-sink-secret-canary")
            setattr(sink, broken, refuse)
            fresh = SimpleNamespace(total=0, attempts=[], stored=[])
            with patch("sys.stderr", sink):
                response = receiver(fresh, "POST", PACKAGES[0])
            self.assertEqual(response[:2], (400, b'{"error":"synthetic publish fixture refused"}'))
            self.assertEqual((fresh.total, fresh.attempts, fresh.stored), (1, [{"ordinal": 1, "accepted": False}], []))

    def test_job_nonzero_positive_result_is_process_stage_and_e400_is_diagnostic_only(self):
        # Source-order coverage only: no Node VM, npm executable or subprocess
        # runs in this pure Python suite. Root's stock client lane is separate.
        job = (Path(__file__).parent / "operator_npm_publish_job.mjs").read_text()
        self.assertIn("new Set(['E400', 'E403'", job)
        positive = job.split("  } else {\n", 1)[1].split("} catch (error)", 1)[0]
        self.assertTrue(positive.startswith("    stage = 'npm_process';\n    assert(invocation.status === 0);\n    stage = 'npm_receipt';\n"))
        denial = job.split("  if (!['unscoped', 'scoped'].includes(phase)) {\n", 1)[1].split("  } else {\n", 1)[0]
        self.assertIn("assert(invocation.status !== 0 && ['E403', 'E407', 'ECONNRESET', 'ECONNREFUSED'].includes(errorCode));", denial)
        self.assertNotIn("E400", denial)
        failure = job.split("} catch (error) {\n", 1)[1].split("} finally", 1)[0]
        self.assertIn("error: 'stock npm publish operation failed', stage, errorCode", failure)
        for private in ("error.message", "error.stack", "invocation.stdout", "invocation.stderr", "input.token", "placeholder"):
            self.assertNotIn(private, failure)

    def test_handler_replay_unknown_routes_and_overflow_are_counted_before_refusal(self):
        spec = registry.spec_for("unscoped")
        stored, _, _ = registry.validate_publish(encoded(publish_document(spec)), spec)
        server = SimpleNamespace(total=2, attempts=[], stored=[stored])
        with patch.object(registry, "save_new", side_effect=AssertionError("duplicate version reached storage")):
            self.assertEqual(receiver(server, "PUT", spec["package"], encoded(publish_document(spec)))[0], 400)
        self.assertEqual(server.total, 3)
        self.assertEqual(server.stored, [stored])
        self.assertIs(server.attempts[-1]["accepted"], False)
        for method, path in (("POST", "/-/npm/v1/security/audits"), ("PUT", "/other"),
                ("GET", "/@serverware-fixture/publish"), ("GET", "/serverware-fixture-publish?x=1")):
            fresh = SimpleNamespace(total=0, attempts=[], stored=[])
            self.assertEqual(receiver(fresh, method, spec["package"], path=path)[0], 400)
            self.assertEqual((fresh.total, fresh.attempts), (1, [{"ordinal": 1, "accepted": False}]))
        fresh = SimpleNamespace(total=0, attempts=[], stored=[])
        for _ in range(40): self.assertEqual(receiver(fresh, "POST", spec["package"])[0], 400)
        self.assertEqual(fresh.total, 40)
        self.assertEqual(len(fresh.attempts), 16)
        self.assertEqual(fresh.stored, [])
        fresh = SimpleNamespace(total=0, attempts=[], stored=[])
        duplicate = headers("GET", spec["package"], 0) + [("Authorization", "Bearer " + registry.TOKEN)]
        self.assertEqual(receiver(fresh, "GET", spec["package"], fields=duplicate)[0], 400)

    def test_job_and_receiver_keep_stock_transport_and_no_runtime_authority_import(self):
        job = (Path(__file__).parent / "operator_npm_publish_job.mjs").read_text()
        for expected in ("spawnSync('/node', ['/npm/bin/npm-cli.js'", "'publish', tarballPath",
                "'--access=public'", "'--tag=fixture'", "'--ignore-scripts=true'", "'--provenance=false'",
                "'--force=false'", "'--dry-run=false'", "'--workspaces=false'", "'--globalconfig', '/dev/null'",
                "'strict-ssl=true'", "'fetch-retries=0'", "timeout: 15000", "maxBuffer: 262144",
                "NODE_EXTRA_CA_CERTS: extraCa", "HOME: clientHome", "SERVERWARE_PROXY_TOKEN: input.token",
                "requestRewrite: false", "configuredRetries: 0"):
            self.assertIn(expected, job)
        self.assertEqual(job.count("spawnSync('/node'"), 1)
        for bypass in ("NODE_TLS_REJECT_UNAUTHORIZED", "rejectUnauthorized", "fetch:", "agent:", "cafile=", "ca: ",
                "error.stack", "error.message", "process.env.HOME ="):
            self.assertNotIn(bypass, job)
        tree = ast.parse((Path(__file__).parent / "operator_npm_publish_fixture.py").read_text())
        imports = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        self.assertFalse(any(name and name.startswith("serverware") for name in imports))
        self.assertIn(b"93.184.216.34 registry.npmjs.org\n", network.HOSTS)
        self.assertEqual(network.RESOLV, b"nameserver 127.0.0.1\noptions attempts:1 timeout:1\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
