"""Offline npm-example checker oracles; no SDK, socket, TLS or registry run.

Phase, header, canonical-v2, archive and audit vectors are independently built
below. Synthetic successful evidence is not actual example/proxy acceptance.
"""
import base64
from contextlib import ExitStack
from copy import deepcopy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import check_operator_npm_example as checker


def uid(number):
    return "00000000-0000-4000-8000-" + format(number, "012d")


def sha(number):
    return "sha256:" + format(number, "064x")


def encode(value, *, canonical=False):
    return json.dumps(value, sort_keys=canonical, separators=(",", ":"),
        ensure_ascii=canonical, allow_nan=False).encode("utf-8")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


UNSCOPED, SCOPED = "serverware-fixture-publish", "@serverware-fixture/publish"
FORBIDDEN = "serverware-fixture-forbidden"
CORGI = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"
CREDENTIAL, POLICY = uid(1), sha(900)
START, RELEASE = "data_plane.credential.release_started", "data_plane.response.released"
BLOCK, CONNECT_DENIED = "data_plane.response.blocked", "data_plane.connect.denied"
PHASE_ROWS = (
    ("view_unscoped", "view", UNSCOPED, "1.0.0", True, "outside"),
    ("view_scoped", "view", SCOPED, "1.0.0", True, "scoped"),
    ("manifest_unscoped", "manifest", UNSCOPED, "1.0.0", True, "outside"),
    ("manifest_scoped", "manifest", SCOPED, "1.0.0", True, "scoped"),
    ("metadata_only_publish", "publish", UNSCOPED, "1.0.1", False, "metadata"),
    ("publish_unscoped", "publish", UNSCOPED, "2.0.0", True, "unscoped"),
    ("publish_scoped", "publish", SCOPED, "3.0.0", True, "scoped"),
    ("publish_dependency", "publish", UNSCOPED, "1.0.2", True, "unscoped"),
    ("install_published", "install", UNSCOPED, "1.0.2", True, "install"),
    ("ci_published", "ci", UNSCOPED, "1.0.2", True, "install"),
    ("install_audit_negative", "install", UNSCOPED, "1.0.2", False, "install"),
    ("outside_window_publish", "publish", UNSCOPED, "5.0.0", False, "outside"),
    ("wrong_package_view", "view", FORBIDDEN, "1.0.0", False, "unscoped"),
    ("wrong_package_manifest", "manifest", FORBIDDEN, "1.0.0", False, "unscoped"),
    ("wrong_package_publish", "publish", FORBIDDEN, "4.0.0", False, "unscoped"),
    ("wrong_app_view", "view", UNSCOPED, "1.0.0", False, "unassigned"),
    ("wrong_app_manifest", "manifest", UNSCOPED, "1.0.0", False, "unassigned"),
    ("wrong_app_publish", "publish", UNSCOPED, "7.0.0", False, "unassigned"),
    ("wrong_outer_ca", "view", UNSCOPED, "1.0.0", False, "unscoped"),
    ("wrong_inner_ca", "manifest", UNSCOPED, "1.0.0", False, "unscoped"),
    ("missing_confirmation", "publish", UNSCOPED, "7.0.0", False, "unscoped"),
    ("wrong_tarball_hash", "publish", UNSCOPED, "7.0.0", False, "unscoped"),
    ("revoked_view", "view", SCOPED, "1.0.0", False, "scoped"),
    ("revoked_manifest", "manifest", SCOPED, "1.0.0", False, "scoped"),
    ("revoked_publish", "publish", SCOPED, "7.0.0", False, "scoped"),
)
SPECS = [dict(zip(("case", "operation", "package", "version", "success", "application"), row)) for row in PHASE_ROWS]
PHASES = [row[0] for row in PHASE_ROWS]
INSTALL_PHASES = ("install_published", "ci_published", "install_audit_negative")
AUDIT_PATH = "/-/npm/v1/security/advisories/bulk"
ARRIVALS = (("view_unscoped", "GET"), ("view_scoped", "GET"),
    ("manifest_unscoped", "GET"), ("manifest_scoped", "GET"), ("metadata_only_publish", "GET"),
    ("publish_unscoped", "GET"), ("publish_unscoped", "PUT"),
    ("publish_scoped", "GET"), ("publish_scoped", "PUT"),
    ("publish_dependency", "GET"), ("publish_dependency", "PUT"),
    ("install_published", "GET"), ("install_published", "GET"), ("install_published", "GET"),
    ("install_published", "GET"), ("install_published", "POST"),
    ("ci_published", "GET"), ("ci_published", "GET"), ("ci_published", "POST"),
    ("install_audit_negative", "GET"), ("install_audit_negative", "GET"), ("install_audit_negative", "GET"),
    ("install_audit_negative", "GET"), ("install_audit_negative", "POST"), ("outside_window_publish", "GET"))


def spec_for(phase):
    return next(spec for spec in SPECS if spec["case"] == phase)


def package_manifest(spec):
    value = {"name": spec["package"], "version": spec["version"],
        "description": "Synthetic publication fixture", "license": "MIT", "main": "index.js"}
    if spec["case"] == "publish_dependency":
        value["dependencies"] = {SCOPED: "3.0.0"}
    return value


def archive(spec):
    manifest = encode(package_manifest(spec)) + b"\n"
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as stream:
        for name, content in (("package/package.json", manifest),
                ("package/index.js", b"module.exports = 'inert synthetic package';\n")):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.mtime = len(content), 0o644, 0
            stream.addfile(entry, io.BytesIO(content))
    packed = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=packed, mode="wb", mtime=0) as stream:
        stream.write(raw.getvalue())
    return packed.getvalue()


def stored_record(spec):
    blob = archive(spec)
    return {"case": spec["case"], "package": spec["package"], "version": spec["version"], "tag": "fixture",
        "attachmentName": spec["package"] + "-" + spec["version"] + ".tgz", "attachmentBytes": len(blob),
        "tarballSha256": digest(blob), "tarballIntegrity": "sha512-" + base64.b64encode(hashlib.sha512(blob).digest()).decode(),
        "tarballShasum": hashlib.sha1(blob).hexdigest()}


def installation_files():
    project = {"name": "serverware-fixture-consumer", "version": "1.0.0", "private": True,
        "dependencies": {UNSCOPED: "1.0.2"}}
    lock = {"name": project["name"], "version": "1.0.0", "lockfileVersion": 3,
        "packages": {"": {"name": project["name"], "version": "1.0.0", "dependencies": project["dependencies"]}}}
    files = {"package.json": encode(project) + b"\n"}
    for package, phase in ((UNSCOPED, "publish_dependency"), (SCOPED, "publish_scoped")):
        spec = spec_for(phase); record = stored_record(spec)
        location = "node_modules/" + package
        entry = {"version": spec["version"], "integrity": record["tarballIntegrity"],
            "resolved": "https://registry.npmjs.org/" + package + "/-/" + package.rsplit("/", 1)[-1] + "-" + spec["version"] + ".tgz"}
        if package == UNSCOPED:
            entry["dependencies"] = {SCOPED: "3.0.0"}
        lock["packages"][location] = entry
        files[location + "/package.json"] = encode(package_manifest(spec)) + b"\n"
        files[location + "/index.js"] = b"module.exports = 'inert synthetic package';\n"
    files["package-lock.json"] = encode(lock) + b"\n"
    files["node_modules/.package-lock.json"] = encode({"name": project["name"], "version": "1.0.0",
        "lockfileVersion": 3, "packages": {k: v for k, v in lock["packages"].items() if k}}) + b"\n"
    return files


def installation(spec, directory=None):
    files = installation_files()
    return {"directory": directory or "/tmp/serverware-npm-install-fixture1/" + spec["case"],
        "lockSha256": hashlib.sha256(files["package-lock.json"]).hexdigest(),
        "fileSha256": {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(files.items())},
        "sourcePreserved": True, "ciLockUnchanged": spec["operation"] == "ci"}


def audit_body(*, mtime=0):
    raw = encode({SCOPED: ["3.0.0"], UNSCOPED: ["1.0.2"]})
    result = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=result, mode="wb", mtime=mtime) as stream:
        stream.write(raw)
    return result.getvalue()


def client_receipt(spec):
    return {"phase": spec["case"], "operation": spec["operation"], "exitCode": 0 if spec["success"] else 1,
        "summary": summary(spec), **({"installation": installation(spec)} if spec["case"] in INSTALL_PHASES else {})}


def phase_evidence(value, phase):
    return next(row for row in value["phaseEvidence"] if row["phase"] == phase)


def summary(spec):
    if not spec["success"]:
        value = {"ok": False, "operation": spec["operation"],
            "error": "npm example failed; check configuration, permissions and Serverware audit logs."}
        if spec["operation"] == "publish":
            value["warning"] = "Publication may be unconfirmed. Inspect registry metadata and audit evidence; do not automatically retry."
        elif spec["case"] in INSTALL_PHASES:
            value.update(installationDirectory=installation(spec)["directory"], warning=
                "Partial installation retained. Inspect it and audit logs; choose a new output directory for a deliberate retry.")
        return value
    value = {"ok": True, "operation": spec["operation"], "package": spec["package"], "version": spec["version"]}
    if spec["operation"] == "publish":
        value.update(tag="fixture", tarballSha256=hashlib.sha256(archive(spec)).hexdigest(), npmReportedSuccess=True)
    elif spec["case"] in INSTALL_PHASES:
        value.update(installed=True, added=2, audited=3, defaultAuditReportedSuccess=True, vulnerabilities=0,
            lockSha256=installation(spec)["lockSha256"], installationDirectory=installation(spec)["directory"])
    else:
        value["tarballFetched"] = False
    return value


def install_requests(phase):
    metadata = (("GET", "/" + UNSCOPED, "metadata", UNSCOPED, None),
        ("GET", "/@serverware-fixture%2fpublish", "metadata", SCOPED, None))
    downloads = (("GET", "/serverware-fixture-publish/-/serverware-fixture-publish-1.0.2.tgz", "tarball", UNSCOPED, "1.0.2"),
        ("GET", "/@serverware-fixture/publish/-/publish-3.0.0.tgz", "tarball", SCOPED, "3.0.0"),
        ("POST", AUDIT_PATH, "audit", None, None))
    return (() if phase == "ci_published" else metadata) + downloads


def headers(spec, method, mode=None, package=None, version=None):
    if spec["case"] in INSTALL_PHASES:
        value = {"host": "registry.npmjs.org", "accept": "application/json" if mode == "metadata" else "*/*",
            "user-agent": "npm/11.8.0 node/v25.5.0 linux x64 workspaces/false",
            "npm-command": spec["operation"], "npm-auth-type": "web"}
        if mode == "audit":
            value.update({"content-type": "application/json", "content-encoding": "gzip"})
        else:
            value.update({"pacote-version": "21.0.4", "pacote-req-type": "packument" if mode == "metadata" else "tarball",
                "pacote-pkg-id": "registry:" + package if mode == "metadata" else
                    "remote:" + package + "@https://registry.npmjs.org/" + package + "/-/" + package.rsplit("/", 1)[-1] + "-" + version + ".tgz"})
            if mode == "tarball":
                value["pacote-integrity"] = stored_record(spec_for("publish_dependency" if package == UNSCOPED else "publish_scoped"))["tarballIntegrity"]
        return value
    result = {"host": "registry.npmjs.org", "accept": "*/*" if method == "PUT" else
        "application/json" if spec["operation"] == "view" else CORGI,
        "user-agent": "pacote/21.0.4 node/v25.5.0" if spec["operation"] == "manifest" else
            "npm/11.8.0 node/v25.5.0 linux x64 workspaces/false"}
    if spec["operation"] != "manifest":
        result.update({"npm-command": spec["operation"], "npm-auth-type": "web"})
    if method == "GET":
        result.update({"pacote-version": "21.0.4", "pacote-req-type": "packument", "pacote-pkg-id": "registry:" + spec["package"]})
    else:
        result["content-type"] = "application/json"
    return result


def packument(package, stored):
    version = "1.0.0"
    content = (package + "@" + version + ": synthetic bytes, no tarball served").encode()
    versions = {version: {"name": package, "version": version, "description": "Complete synthetic metadata \u2603",
        "main": "index.js", "license": "MIT", "dependencies": {"serverware-fixture-dependency": "^1.0.0"},
        "optionalDependencies": {"serverware-fixture-optional": "2.0.0"}, "engines": {"node": ">=20"},
        "fixtureExtra": {"preserved": [True, None, 7]}, "dist": {
            "tarball": "https://registry.npmjs.org/" + package + "/-/metadata-1.0.0.tgz",
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(content).digest()).decode(),
            "shasum": hashlib.sha1(content).hexdigest(), "fileCount": 1, "unpackedSize": len(content)}}}
    document = {"_id": package, "name": package, "description": "Synthetic registry fixture",
        "dist-tags": {"latest": version}, "versions": versions,
        "time": {"created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-02T00:00:00.000Z", "1.0.0": "2026-01-01T00:00:00.000Z"},
        "maintainers": [{"name": "synthetic-maintainer"}], "license": "MIT",
        "readme": "Inert metadata fixture; installing is not supported.", "fixtureRootExtra": {"preserved": [False, "metadata only"]}}
    for row in stored:
        if row["package"] == package:
            versions[row["version"]] = {**package_manifest(spec_for(row["case"])), "dist": {
                "tarball": "https://registry.npmjs.org/" + package + "/-/" + package.rsplit("/", 1)[-1] + "-" + row["version"] + ".tgz",
                "integrity": row["tarballIntegrity"], "shasum": row["tarballShasum"]}}
            document["dist-tags"]["fixture"] = row["version"]
    return document


def phase_scopes():
    result = {}
    for spec in SPECS:
        app = spec["application"]
        route = "synthetic-" + app
        result[spec["case"]] = {"GET": ("principal-" + app, route + (".metadata" if app != "metadata" else ""), POLICY),
            "PUT": ("principal-" + app, route, POLICY)}
        if app == "install":
            result[spec["case"]] = {mode: ("principal-install", "synthetic-install" + suffix, POLICY)
                for mode, suffix in (("metadata", ""), ("tarball", ".tarball"), ("audit", ".audit"))}
    return result


def observation(completed=PHASES):
    rows, stored, positions = [], [], {}
    for phase, method in ARRIVALS:
        if phase not in completed:
            continue
        spec = spec_for(phase)
        body, mode, package, version = b"", None, spec["package"], spec["version"]
        target = "/" + package.replace("/", "%2f")
        status, content_type = (200 if method == "GET" else 201), "application/json"
        if phase in INSTALL_PHASES:
            position = positions.get(phase, 0); positions[phase] = position + 1
            method, target, mode, package, version = install_requests(phase)[position]
        if mode == "audit":
            body = audit_body()
            status = 400 if phase == "install_audit_negative" else 200
            response = b'{"error":"synthetic_audit_refused"}' if status == 400 else b'{}'
            operation = {"operation": "npm.install.audit.read", "packages": [SCOPED, UNSCOPED],
                "packageVersions": {SCOPED: ["3.0.0"], UNSCOPED: ["1.0.2"]}}
        elif mode == "tarball":
            response = archive(spec_for("publish_dependency" if package == UNSCOPED else "publish_scoped"))
            operation = {"operation": "npm.install.tarball.read", "package": package, "version": version}
            content_type = "application/octet-stream"
        elif method == "GET":
            response = encode(packument(package, stored))
            operation = {"operation": "npm.install.metadata.read" if mode else "npm.metadata.read", "package": package}
            content_type = "application/json" if mode == "metadata" or spec["operation"] == "view" else "application/vnd.npm.install-v1+json"
        else:
            record = stored_record(spec); stored.append(record)
            blob = archive(spec)
            manifest = {"name": spec["package"], "version": spec["version"], "_id": spec["package"] + "@" + spec["version"],
                "description": "Synthetic publication fixture", "license": "MIT", "main": "index.js",
                "_nodeVersion": "25.5.0", "_npmVersion": "11.8.0", "dist": {
                    "integrity": record["tarballIntegrity"], "shasum": record["tarballShasum"],
                    "tarball": "http://registry.npmjs.org/" + spec["package"] + "/-/" + record["attachmentName"]}}
            if phase == "publish_dependency":
                manifest["dependencies"] = {SCOPED: "3.0.0"}
            body = encode({"_id": spec["package"], "name": spec["package"], "description": "Synthetic publication fixture",
                "dist-tags": {"fixture": spec["version"]}, "versions": {spec["version"]: manifest}, "access": "public",
                "_attachments": {record["attachmentName"]: {"content_type": "application/octet-stream",
                    "data": base64.b64encode(blob).decode(), "length": len(blob)}}})
            response = encode({"ok": True, "id": spec["package"], "rev": "fixture-" + spec["version"]})
            operation = {"operation": "npm.publish", "packageName": spec["package"], "packageVersion": spec["version"],
                "tag": "fixture", **{key: record[key] for key in ("tarballIntegrity", "tarballShasum", "attachmentName")},
                "attachmentBytes": str(record["attachmentBytes"])}
        rows.append({"ordinal": len(rows) + 1, "accepted": True, "case": phase, "method": method,
            "rawTarget": target, "requestHeaders": headers(spec, method, mode, package, version),
            "requestBodySha256": digest(body), "requestBodyBytes": len(body), "operation": operation,
            "status": status, "responseContentType": content_type,
            "responseBodySha256": digest(response), "responseBodyBytes": len(response), "allParsedHeadersValidated": True})
    return {"schema": "serverware.privateNpmExampleObservations/v1", "syntheticOnly": True,
        "total": len(rows), "attempts": rows, "stored": stored}


def canonical(row, scope):
    # The independent request constructor, not the checker header projection.
    spec = spec_for(row["case"])
    mode, package, version = None, None, None
    if row["case"] in INSTALL_PHASES:
        _, _, mode, package, version = next(item for item in install_requests(row["case"])
            if item[:2] == (row["method"], row["rawTarget"]))
    projected = headers(spec, row["method"], mode, package, version)
    if row["method"] in {"PUT", "POST"}:
        projected["content-length"] = str(row["requestBodyBytes"])
    return {"v": 2, "principal": scope[0], "client_ip": "127.0.0.1", "route_id": scope[1],
        "credential_ref": CREDENTIAL, "credential_version": "1", "policy_hash": scope[2],
        "request": {"method": row["method"], "scheme": "https", "authority": "registry.npmjs.org",
            "path": row["rawTarget"], "query": [], "headers": projected, "body_sha256": row["requestBodySha256"],
            "discard_headers": ["accept-encoding", "npm-session"]}, "operation": row["operation"]}


def expected_wire(document):
    result = []
    for row in document["attempts"]:
        key = row["operation"]["operation"].split(".")[2] if row["case"] in INSTALL_PHASES else row["method"]
        scope = phase_scopes()[row["case"]][key]
        value = canonical(row, scope)
        result.append({**deepcopy(row), "scope": scope, "requestDigest": digest(encode(value, canonical=True)),
            "operationDigest": digest(encode({key: item for key, item in value.items() if key not in {"v", "client_ip"}}, canonical=True))})
    return result


def audit_rows(wire):
    rows = []
    for index, item in enumerate(wire):
        common = {"principal_id": item["scope"][0], "route_id": item["scope"][1], "policy_hash": item["scope"][2],
            "credential_ref": CREDENTIAL, "credential_version": 1, "method": item["method"],
            "body_sha256": item["requestBodySha256"], "request_digest": item["requestDigest"],
            "operation_digest": item["operationDigest"], "attempt_id": sha(100 + index), "flow_id": sha(100 + index)}
        rows.append({"id": sha(200 + index * 2), "event_hash": sha(400 + index * 2), "event_type": START,
            "event": {**common, "outcome": "release_started"}})
        if item["case"] in INSTALL_PHASES:
            mode = {"metadata": "npmInstallMetadataJsonV1", "tarball": "npmInstallTarballV1", "audit": "npmInstallAuditJsonV1"}[
                item["operation"]["operation"].split(".")[2]]
            adapter = "npm.install.v1"
        else:
            mode = "npmMetadataJsonV1" if item["method"] == "GET" else "npmPublishJsonV1"
            adapter = "npm.metadata.v1" if item["method"] == "GET" else "npm.publish.v1"
        rows.append({"id": sha(201 + index * 2), "event_hash": sha(401 + index * 2), "event_type": RELEASE,
            "event": {**common, "outcome": "released", "upstream_status": item["status"],
                "response_body_sha256": item["responseBodySha256"], "response_body_bytes": item["responseBodyBytes"],
                "response_validation": {"ok": True, "mode": mode, "adapter": adapter,
                    "body_bytes_preserved": True, "allowed_fields_redacted": False}}})
    return rows


def connection_counts(spec):
    if spec["case"] in {"wrong_outer_ca", "missing_confirmation", "wrong_tarball_hash"}:
        return 0, 0
    count = len(install_requests(spec["case"])) if spec["case"] in INSTALL_PHASES else 2 if spec["operation"] == "publish" else 1
    return (0, count) if spec["case"].startswith(("wrong_app_", "revoked_")) else (count, 0)


def denial_signatures(spec):
    route = "synthetic-" + spec["application"]
    if spec["case"] == "metadata_only_publish":
        return [("PUT", "unknown_route_denied", None, None, UNSCOPED)]
    if spec["case"] == "outside_window_publish":
        return [("PUT", "request_time_daily_window_denied", route, "npm.publish.v1", UNSCOPED)]
    if spec["case"].startswith("wrong_package_"):
        result = [("GET", "npm_metadata_package_denied", route + ".metadata", "npm.metadata.v1", FORBIDDEN)]
        if spec["operation"] == "publish":
            result.append(("PUT", "npm_publish_package_denied", route, "npm.publish.v1", FORBIDDEN))
        return result
    return []


def runtime_fixture():
    """Real validator method with synthetic rows, no constructor/transport."""
    instance = checker.NpmExampleCheck.__new__(checker.NpmExampleCheck)
    instance.completed, instance.credential_id = list(PHASES), CREDENTIAL
    instance.baseline, instance.cutoff = {}, {}
    instance.accepted_policy, instance.snapshot = POLICY, {"policy": {"sequence": 12}}
    instance.args = SimpleNamespace(expected_binary_sha256=sha(901))
    instance.rules = {name: {"id": uid(20 + index), "route_id": "synthetic-" + name}
        for index, name in enumerate(("metadata", "unscoped", "scoped", "outside", "install"))}
    instance.apps = {name: ({"principal_id": "principal-" + name}, "synthetic-token")
        for name in ("metadata", "unscoped", "scoped", "outside", "unassigned", "install")}
    instance.revocation = ("operator_catalog.application.revoked", uid(12), sha(902))
    instance.phase_scopes, instance.bindings = phase_scopes(), {}
    for spec in SPECS:
        instance.bindings[spec["case"]] = {"principal": "principal-" + spec["application"],
            "policy": sha(902) if spec["case"].startswith("revoked_") else POLICY}
        if spec["application"] == "unassigned":
            instance.phase_scopes[spec["case"]] = {}
        elif spec["application"] == "metadata":
            instance.phase_scopes[spec["case"]].pop("PUT")
    instance.wire = expected_wire(observation())
    rows = audit_rows(instance.wire)
    def append(kind, event, *, control_plane=False):
        number = 1000 + len(rows)
        rows.append({"id": uid(number) if control_plane else sha(number), "event_hash": sha(number),
            "event_type": kind, "event": event})
    scope = instance.wire[0]["scope"]
    append("data_plane.credential_lease.issued", {"principal_id": scope[0], "route_id": scope[1], "policy_hash": scope[2],
        "credential_id": CREDENTIAL, "status_code": 200, "outcome": "issued", "data_plane_binary_digest": sha(901),
        "purpose": "dispatchSecret", "expected_credential_version": 1}, control_plane=True)
    for spec in SPECS:
        units, denied = connection_counts(spec)
        for _ in range(units):
            append("data_plane.connect.established", {"principal_id": instance.bindings[spec["case"]]["principal"],
                "policy_hash": POLICY, "target": "registry.npmjs.org:443", "method": "CONNECT", "client_ip": "127.0.0.1",
                "outcome": "established", "status_code": 200})
        for _ in range(denied):
            append(CONNECT_DENIED, {"principal_id": None, "policy_hash": None, "target": "registry.npmjs.org:443",
                "method": "CONNECT", "client_ip": "127.0.0.1", "outcome": "denied", "status_code": 403,
                "payload": {"error": "client_principal_denied"}})
        for method, error, route, adapter, package in denial_signatures(spec):
            target = "/" + package.replace("/", "%2f")
            append("data_plane.request.denied", {"method": method, "error": error, "route_id": route, "adapter": adapter,
                "outcome": "denied", "status_code": 403, "principal_id": None, "policy_hash": None,
                "url": {"origin_sha256": digest(b"https://registry.npmjs.org"), "origin_bytes": 26,
                    "path_sha256": digest(target.encode()), "path_bytes": len(target), "query_keys": []}})
    append("data_plane.policy.reloaded", {"previous_policy_hash": POLICY, "policy_hash": sha(902), "policy_sequence": 12, "routes": 8})
    append("operator_catalog.application.revoked", {"resource_id": uid(12), "policy_hash": sha(902)}, control_plane=True)
    return instance, rows


def success_result():
    apps = {name: uid(10 + index) for index, name in enumerate(("metadata", "unscoped", "scoped", "outside", "unassigned", "install"))}
    rules = {name: uid(20 + index) for index, name in enumerate(("metadata", "unscoped", "scoped", "outside", "install"))}
    phases, count = [], 0
    for index, spec in enumerate(SPECS):
        units, denied = connection_counts(spec)
        following = count + sum(case == spec["case"] for case, _ in ARRIVALS)
        phases.append({"phase": spec["case"], "applicationId": apps[spec["application"]],
            "policyHash": sha(902) if spec["case"].startswith("revoked_") else POLICY,
            "providerAttemptsBefore": count, "providerAttemptsAfter": following,
            "newAuditEventIds": [sha(2000 + index)] if units or denied else [], "requestDenials": len(denial_signatures(spec)),
            "connectDenials": denied, "connectRequestUnits": units,
            "localOnly": spec["case"] in {"missing_confirmation", "wrong_tarball_hash"},
            "localConcurrentLeaseEventIds": []})
        count = following
    mutations = [("operator_catalog.credential.npm_token_created", CREDENTIAL, sha(3000))]
    mutations += [("operator_catalog.application.created", app, sha(3001 + index)) for index, app in enumerate(apps.values())]
    mutations += [("operator_catalog.access_rule.npm_" + (name if name in {"metadata", "install"} else "publish") + "_created",
        rule, sha(3010 + index)) for index, (name, rule) in enumerate(rules.items())]
    mutations.append(("operator_catalog.application.revoked", apps["scoped"], sha(902)))
    return {"schema": "serverware.privateNpmExampleCheck/v1", "ok": True, "syntheticOnly": True,
        "actualExampleEntrypoint": True, "auditChainVerified": True, "stockClientTransports": True,
        "allParsedUpstreamHeadersValidated": True, "distinctOuterInnerCAs": True, "trustMode": "additiveSharedNodeRoots",
        "productionReady": False, "realNpmVerified": False, "npmInstallVerified": True, "publicDnsVerified": False,
        "coldCiVerified": True, "transitiveDependencyVerified": True, "defaultAuditSuccessVerified": True,
        "swallowedAuditFailureDetected": True,
        "hiddenWireHeaderProof": False, "defaultRetryBehaviorVerified": False, "configuredRetries": 0, "commandRetries": 0,
        "clientCommands": 25, "successfulClientCommands": 9, "expectedFailedClientCommands": 16,
        "providerAttempts": 25, "metadataReleases": 13, "tarballReleases": 6, "auditReleases": 3, "unauthorizedPuts": 0,
        "npmVersion": "11.8.0", "pacoteVersion": "21.0.4", "registryFetchVersion": "19.1.1",
        "dataPlaneBinaryDigest": sha(901), "nodeSha256": "3dc3f85ca5539ca81b7d106992ebcd82d09bce27326016873653a661ad6b2a7d",
        "nodeModulesSha256": "a" * 64, "sourceSha256": {"examples/npm-registry/" + name: format(3100 + index, "064x")
            for index, name in enumerate(("client.mjs", "core.mjs", "worker.mjs", "package.json", "package-lock.json"))},
        "credentialId": CREDENTIAL, "applicationIds": apps, "ruleIds": rules, "policyHash": POLICY,
        "revokedPolicyHash": sha(902), "publishingWindowUtc": {"start": "18:00", "end": "19:00"},
        "clients": [client_receipt(spec) for spec in SPECS], "requests": expected_wire(observation()),
        "storedPublications": observation()["stored"], "phaseEvidence": phases, "catalogMutations": mutations,
        "durableAuditEventIds": [uid(4000 + index) for index in range(13)] + [sha(200 + index) for index in range(50)],
        "auditAttemptIds": [sha(100 + index) for index in range(25)], "reusedTunnelRequestUnits": 0,
        "namedAuditInventory": {START: 25, RELEASE: 25, "data_plane.request.denied": 6, CONNECT_DENIED: 8,
            "data_plane.policy.reloaded": 1, "operator_catalog.application.revoked": 1,
            "data_plane.connect.established": 32, "data_plane.credential_lease.issued": 1}}


class NpmExampleCheckerTests(unittest.TestCase):
    def setUp(self):
        guard = ExitStack(); self.addCleanup(guard.close)
        for target in ("socket.socket", "socket.create_connection", "socket.getaddrinfo", "subprocess.Popen", "subprocess.run", "os.open"):
            guard.enter_context(patch(target, side_effect=AssertionError("offline checker test attempted runtime I/O")))

    def test_exact_twenty_five_process_results_and_redacted_failures(self):
        self.assertEqual(tuple(PHASES), checker.PHASES)
        self.assertEqual(len(PHASES), 25)
        for spec in SPECS:
            expected = summary(spec)
            installed = installation(spec) if spec["case"] in INSTALL_PHASES else None
            self.assertEqual(checker.expected_summary(spec, installed), expected)
            raw = encode(expected) + b"\n"
            code, out, err = (0, raw, b"") if spec["success"] else (1, b"", raw)
            self.assertEqual(checker.validate_client_result(spec, code, out, err, installation=installed), client_receipt(spec))
            for changed in ((True, out, err), (2, out, err), (code, out + b"secret-canary", err),
                    (code, out, err + b"secret-canary"), (code, out.rstrip(), err.rstrip())):
                with self.subTest(phase=spec["case"], change=changed[0]), self.assertRaises(checker.CheckFailure) as caught:
                    checker.validate_client_result(spec, *changed, installation=installed)
                self.assertNotIn("secret-canary", str(caught.exception))

    def test_environment_is_closed_basic_identity_without_home_or_ambient_options(self):
        with patch.dict(os.environ, {"HOME": "/secret-canary", "NPM_TOKEN": "secret-canary", "NODE_OPTIONS": "secret-canary",
                "HTTPS_PROXY": "secret-canary", "NODE_TLS_REJECT_UNAUTHORIZED": "0"}):
            for spec in SPECS:
                expected = {"LANG": "C.UTF-8", "SERVERWARE_PROXY_URL": "https://proxy.operator-basic.example.test:8443",
                    "SERVERWARE_APP_ID": uid(2), "SERVERWARE_PROXY_TOKEN": "a" * 43, "SERVERWARE_NPM_PACKAGE": spec["package"],
                    "SERVERWARE_CA_FILE": "/client-trust/inner-ca.pem", "SERVERWARE_PROXY_CA_FILE": "/client-trust/outer-ca.pem"}
                if spec["operation"] != "view":
                    expected["SERVERWARE_NPM_VERSION"] = spec["version"]
                if spec["operation"] == "publish":
                    expected.update(SERVERWARE_NPM_TAG="fixture", SERVERWARE_NPM_TARBALL="/client-packages/" + spec["case"] + ".tgz",
                        SERVERWARE_NPM_TARBALL_SHA256=hashlib.sha256(archive(spec)).hexdigest(), SERVERWARE_NPM_PUBLISH_CONFIRM="publish-publicly")
                if spec["case"] == "wrong_outer_ca":
                    del expected["SERVERWARE_PROXY_CA_FILE"]
                elif spec["case"] == "wrong_inner_ca":
                    expected["SERVERWARE_CA_FILE"] = "/client-trust/outer-ca.pem"
                elif spec["case"] == "missing_confirmation":
                    del expected["SERVERWARE_NPM_PUBLISH_CONFIRM"]
                elif spec["case"] == "wrong_tarball_hash":
                    expected["SERVERWARE_NPM_TARBALL_SHA256"] = "0" * 64
                paths = {}
                if spec["case"] in INSTALL_PHASES:
                    paths = {"project": Path("/tmp/original-project"), "output": Path(installation(spec)["directory"])}
                    expected.update(SERVERWARE_NPM_PROJECT=str(paths["project"]), SERVERWARE_NPM_OUTPUT=str(paths["output"]))
                actual = checker.client_environment(spec, uid(2), "a" * 43, **paths)
                self.assertEqual(actual, expected)
                self.assertNotIn("secret-canary", str(actual))
                self.assertNotIn("HOME", actual)
        for app, token in (("bad", "a" * 43), (uid(2), "a" * 42), (uid(2), "secret-canary/")):
            with self.assertRaises(checker.CheckFailure):
                checker.client_environment(SPECS[0], app, token)
        for project, output in ((None, None), (Path("relative"), Path("/tmp/out")),
                (Path("/tmp/project"), Path("/tmp/project")), (Path("/tmp/project"), Path("/tmp/project/out"))):
            with self.assertRaises(checker.CheckFailure):
                checker.client_environment(spec_for("install_published"), uid(2), "a" * 43, project=project, output=output)

    def test_install_process_guard_requires_exact_exit_and_redacted_summary(self):
        for phase in INSTALL_PHASES:
            spec = spec_for(phase); directory = installation(spec)["directory"]
            raw = encode(summary(spec)) + b"\n"
            code, out, err = (0, raw, b"") if spec["success"] else (1, b"", raw)
            checker.validate_installation_process(spec, code, out, err, directory)
            for changed in ((True, out, err), (2, out, err), (1 - code, out, err),
                    (code, out + b"secret-canary", err), (code, out, err + b"secret-canary"),
                    (code, out.rstrip(), err.rstrip()), (code, b"secret-canary", b"")):
                with self.subTest(phase=phase), self.assertRaises(checker.CheckFailure) as caught:
                    checker.validate_installation_process(spec, *changed, directory)
                self.assertNotIn("secret-canary", str(caught.exception))
            if spec["success"]:
                for change in (lambda v: v.pop("lockSha256"), lambda v: v.update(lockSha256="secret-canary"),
                        lambda v: v.update(audited=0), lambda v: v.update(defaultAuditReportedSuccess=False),
                        lambda v: v.update(installationDirectory=directory + "-other")):
                    value = summary(spec); change(value)
                    with self.assertRaises(checker.CheckFailure):
                        checker.validate_installation_process(spec, 0, encode(value) + b"\n", b"", directory)

    def test_install_full_metadata_keeps_standalone_manifest_and_publish_corgi(self):
        document = observation()
        for phase in ("install_published", "install_audit_negative", "manifest_unscoped", "publish_unscoped"):
            index = next(i for i, row in enumerate(document["attempts"]) if row["case"] == phase
                and row["operation"]["operation"] in {"npm.install.metadata.read", "npm.metadata.read"})
            row = document["attempts"][index]; spec = spec_for(phase)
            full = phase in INSTALL_PHASES
            self.assertEqual(row["requestHeaders"]["accept"], "application/json" if full else CORGI)
            self.assertEqual(row["responseContentType"], "application/json" if full else "application/vnd.npm.install-v1+json")
            checker.validate_header_projection(row, spec)
            changed = deepcopy(row); changed["requestHeaders"]["accept"] = CORGI if full else "application/json"
            with self.assertRaises(checker.CheckFailure):
                checker.validate_header_projection(changed, spec)
            changed = deepcopy(document)
            changed["attempts"][index]["responseContentType"] = "application/vnd.npm.install-v1+json" if full else "application/json"
            with self.assertRaises(checker.CheckFailure):
                checker.validate_observations(changed, PHASES, phase_scopes(), CREDENTIAL)

    def test_independent_canonical_v2_metadata_and_framed_publication(self):
        document = observation(); wire = expected_wire(document)
        self.assertEqual([row["method"] for row in wire].count("GET"), 19)
        self.assertEqual([row["method"] for row in wire].count("PUT"), 3)
        self.assertEqual([row["method"] for row in wire].count("POST"), 3)
        for row, expected in zip(document["attempts"], wire):
            saved = deepcopy(row)
            self.assertEqual(checker.canonical_digests(row, expected["scope"], CREDENTIAL),
                (expected["requestDigest"], expected["operationDigest"]))
            self.assertEqual(row, saved)
            self.assertNotIn("authorization", canonical(row, expected["scope"])["request"]["headers"])
            if row["method"] in {"PUT", "POST"}:
                bodyless = canonical(row, expected["scope"]); del bodyless["request"]["headers"]["content-length"]
                self.assertNotEqual(digest(encode(bodyless, canonical=True)), expected["requestDigest"])
        for index in (0, 2, 6):
            for field in ("authorization", "proxy-authorization", "content-length", "transfer-encoding", "unexpected"):
                row = deepcopy(document["attempts"][index]); row["requestHeaders"][field] = "secret-canary"
                with self.assertRaises(checker.CheckFailure):
                    checker.canonical_digests(row, wire[index]["scope"], CREDENTIAL)
        for index in (0, 6):
            for length in (True, -1, 1.0, 65537, 0 if index == 6 else 1):
                row = deepcopy(document["attempts"][index]); row["requestBodyBytes"] = length
                with self.assertRaises(checker.CheckFailure):
                    checker.canonical_digests(row, wire[index]["scope"], CREDENTIAL)

    def test_prefix_observations_bind_all_arrivals_and_three_independent_archives(self):
        for count in range(26):
            completed = PHASES[:count]; document = observation(completed)
            actual, stored = checker.validate_observations(document, completed, phase_scopes(), CREDENTIAL)
            self.assertEqual(actual, expected_wire(document))
            self.assertEqual(stored, document["stored"])
            self.assertEqual(document["total"], sum(case in completed for case, _ in ARRIVALS))
        self.assertEqual([(row["package"], row["version"]) for row in stored],
            [(UNSCOPED, "2.0.0"), (SCOPED, "3.0.0"), (UNSCOPED, "1.0.2")])
        for row in stored:
            blob = archive(spec_for(row["case"]))
            self.assertEqual(row["tarballSha256"], digest(blob))
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as packed:
                self.assertEqual(packed.getnames(), ["package/package.json", "package/index.js"])
                self.assertEqual(json.load(packed.extractfile("package/package.json"))["version"], row["version"])

    def test_observation_refuses_extra_missing_wrong_target_headers_and_storage(self):
        good = observation()
        changes = (lambda d: d.update(total=True), lambda d: d.update(total=11), lambda d: d["attempts"].pop(),
            lambda d: d["attempts"].append(deepcopy(d["attempts"][0])), lambda d: d.update(secret="secret-canary"),
            lambda d: d["attempts"][0].update(accepted=1), lambda d: d["attempts"][0].update(ordinal=True),
            lambda d: d["attempts"][1].update(rawTarget="/@serverware-fixture%2Fpublish"),
            lambda d: d["attempts"][0].update(requestBodyBytes=1), lambda d: d["attempts"][0].update(responseBodySha256=sha(999)),
            lambda d: d["attempts"][0]["requestHeaders"].update(accept="*/*"),
            lambda d: d["attempts"][2]["requestHeaders"].update({"npm-command": "view"}),
            lambda d: d["attempts"][6]["operation"].update(packageVersion="9.0.0"),
            lambda d: d["stored"].pop(), lambda d: d["stored"].append(deepcopy(d["stored"][0])),
            lambda d: d["stored"][0].update(tarballSha256=sha(999)), lambda d: d["stored"][1].update(attachmentBytes=True),
            lambda d: d["stored"][0].update(tag="latest"))
        for index, change in enumerate(changes):
            value = deepcopy(good); change(value)
            with self.subTest(case=index), self.assertRaises(checker.CheckFailure):
                checker.validate_observations(value, PHASES, phase_scopes(), CREDENTIAL)
        with self.assertRaises(checker.CheckFailure):
            checker.validate_observations(good, list(reversed(PHASES)), phase_scopes(), CREDENTIAL)

    def test_audit_joins_exact_generation_one_and_response_bytes_without_extra_releases(self):
        wire = expected_wire(observation()); rows = audit_rows(wire)
        pairs, complete = checker.joined_attempts(rows, wire, CREDENTIAL)
        self.assertTrue(complete); self.assertEqual(len(pairs), 25)
        self.assertFalse(checker.joined_attempts(rows[:-1], wire, CREDENTIAL)[1])
        changes = (lambda r: r[0]["event"].update(credential_version=True),
            lambda r: r[0]["event"].update(credential_version=2), lambda r: r[0]["event"].update(credential_ref=uid(999)),
            lambda r: r[0]["event"].update(principal_id="other"), lambda r: r[0]["event"].update(route_id="other"),
            lambda r: r[0]["event"].update(policy_hash=sha(999)), lambda r: r[0]["event"].update(body_sha256=sha(999)),
            lambda r: r[0]["event"].update(request_digest=sha(999)), lambda r: r[0].update(id=uid(999)),
            lambda r: r[1]["event"].update(response_body_bytes=True), lambda r: r[1]["event"].update(response_body_sha256=sha(999)),
            lambda r: r[1]["event"]["response_validation"].update(body_bytes_preserved=False),
            lambda r: r[13]["event"].update(upstream_status=200), lambda r: r[1].update(event_type=BLOCK),
            lambda r: r.append(deepcopy(r[0])))
        for index, change in enumerate(changes):
            value = deepcopy(rows); change(value)
            with self.subTest(case=index), self.assertRaises(checker.CheckFailure):
                checker.joined_attempts(value, wire, CREDENTIAL)

    def test_exact_six_request_denials_do_not_reclassify_connect_or_local_failures(self):
        rule = {"route_id": "synthetic-rule"}
        all_expected = []
        for spec in SPECS:
            expected = []
            if spec["case"] == "metadata_only_publish":
                expected = [("PUT", "unknown_route_denied", None, None, UNSCOPED)]
            elif spec["case"] == "outside_window_publish":
                expected = [("PUT", "request_time_daily_window_denied", "synthetic-rule", "npm.publish.v1", UNSCOPED)]
            elif spec["case"].startswith("wrong_package_"):
                expected = [("GET", "npm_metadata_package_denied", "synthetic-rule.metadata", "npm.metadata.v1", FORBIDDEN)]
                if spec["operation"] == "publish":
                    expected.append(("PUT", "npm_publish_package_denied", "synthetic-rule", "npm.publish.v1", FORBIDDEN))
            self.assertEqual(checker.expected_denials(spec, rule), expected)
            all_expected.extend(expected)
        self.assertEqual(len(all_expected), 6)
        self.assertEqual(sum(row[-1] == FORBIDDEN for row in all_expected), 4)

    def test_audit_commitments_use_original_gzip_not_decoded_json(self):
        row = next(row for row in observation()["attempts"] if row["case"] == "install_published" and row["method"] == "POST")
        scope = phase_scopes()["install_published"]["audit"]
        wire = audit_body(); decoded = gzip.decompress(wire)
        self.assertEqual(json.loads(decoded), {SCOPED: ["3.0.0"], UNSCOPED: ["1.0.2"]})
        self.assertEqual(row["requestBodySha256"], digest(wire))
        self.assertEqual(row["requestBodyBytes"], len(wire))
        original = canonical(row, scope)
        self.assertEqual(original["request"]["headers"]["content-encoding"], "gzip")
        self.assertEqual(original["request"]["headers"]["content-length"], str(len(wire)))
        expected = (digest(encode(original, canonical=True)), digest(encode(
            {key: value for key, value in original.items() if key not in {"v", "client_ip"}}, canonical=True)))
        self.assertEqual(checker.canonical_digests(row, scope, CREDENTIAL), expected)
        # Same semantic audit JSON, distinct actual compressed bytes: no decoded-body substitution.
        recompressed = audit_body(mtime=1)
        self.assertEqual(gzip.decompress(recompressed), decoded)
        changed = deepcopy(row); changed.update(requestBodySha256=digest(recompressed), requestBodyBytes=len(recompressed))
        self.assertNotEqual(checker.canonical_digests(changed, scope, CREDENTIAL), expected)
        decoded_claim = deepcopy(original); decoded_claim["request"]["body_sha256"] = digest(decoded)
        self.assertNotEqual(digest(encode(decoded_claim, canonical=True)), expected[0])
        for change in (lambda r: r["requestHeaders"].update({"content-encoding": "identity"}),
                lambda r: r["requestHeaders"].pop("content-encoding"),
                lambda r: r["requestHeaders"].update({"content-length": str(len(wire))}),
                lambda r: r.update(requestBodyBytes=True), lambda r: r.update(requestBodyBytes=0),
                lambda r: r.update(requestBodyBytes=65537)):
            bad = deepcopy(row); change(bad)
            with self.assertRaises(checker.CheckFailure):
                checker.canonical_digests(bad, scope, CREDENTIAL)
        # A receiver digest alone is an observation, not a claim that the checker decompresses it.
        # The actual gate evidence must independently commit the very same compressed bytes.
        wire_rows = expected_wire(observation()); evidence = audit_rows(wire_rows)
        index = next(i for i, item in enumerate(wire_rows) if item["case"] == "install_published" and item["method"] == "POST")
        evidence[index * 2]["event"]["body_sha256"] = digest(decoded)
        with self.assertRaises(checker.CheckFailure):
            checker.joined_attempts(evidence, wire_rows, CREDENTIAL)

    def test_unordered_install_arrivals_join_exact_response_multisets_and_distinct_attempts(self):
        document = observation()
        for phase in INSTALL_PHASES:
            positions = [i for i, row in enumerate(document["attempts"]) if row["case"] == phase]
            reordered = list(reversed([document["attempts"][i] for i in positions]))
            for index, row in zip(positions, reordered):
                document["attempts"][index] = {**row, "ordinal": index + 1}
        actual, _ = checker.validate_observations(document, PHASES, phase_scopes(), CREDENTIAL)
        self.assertEqual(actual, expected_wire(document))
        wire = expected_wire(observation()); evidence = audit_rows(wire)
        pairs, complete = checker.joined_attempts(list(reversed(evidence)), wire, CREDENTIAL)
        self.assertTrue(complete); self.assertEqual(len(pairs), 25)
        audit_indices = [i for i, row in enumerate(wire) if row["method"] == "POST"]
        first, cold, failed = audit_indices
        self.assertEqual(wire[first]["requestDigest"], wire[failed]["requestDigest"])
        self.assertNotEqual(wire[first]["requestDigest"], wire[cold]["requestDigest"])
        self.assertEqual([wire[i]["status"] for i in audit_indices], [200, 200, 400])
        self.assertNotEqual(evidence[first * 2]["event"]["attempt_id"], evidence[failed * 2]["event"]["attempt_id"])
        for change in (
                lambda rows: rows[failed * 2]["event"].update(attempt_id=sha(100 + first), flow_id=sha(100 + first)),
                lambda rows: rows[failed * 2 + 1]["event"].update(upstream_status=200,
                    response_body_sha256=digest(b'{}'), response_body_bytes=2),
                lambda rows: rows[failed * 2 + 1]["event"]["response_validation"].update(mode="npmMetadataJsonV1"),
                lambda rows: rows[failed * 2 + 1].update(event_type=BLOCK),
                lambda rows: rows.append({**deepcopy(rows[first * 2]), "id": sha(9991), "event_hash": sha(9992),
                    "event": {**rows[first * 2]["event"], "attempt_id": sha(9993), "flow_id": sha(9993)}})):
            changed = deepcopy(evidence); change(changed)
            with self.assertRaises(checker.CheckFailure):
                checker.joined_attempts(changed, wire, CREDENTIAL)
        for change in (
                lambda d: d["attempts"].__setitem__(12, {**d["attempts"][11], "ordinal": 13}),
                lambda d: d["attempts"][15]["operation"]["packageVersions"].update({SCOPED: ["9.0.0"]}),
                lambda d: d["attempts"][23].update(status=200, responseBodySha256=digest(b'{}'), responseBodyBytes=2),
                lambda d: d["attempts"][13]["requestHeaders"].update({"pacote-integrity": "sha512-forged"})):
            changed = observation(); change(changed)
            with self.assertRaises(checker.CheckFailure):
                checker.validate_observations(changed, PHASES, phase_scopes(), CREDENTIAL)
        negative = spec_for("install_audit_negative")
        with self.assertRaises(checker.CheckFailure):
            checker.validate_client_result(negative, 0, encode(summary(negative)) + b"\n", b"", installation=installation(negative))

    def test_actual_audit_validator_accounts_for_eight_connect_denials_and_no_http_phases(self):
        instance, rows = runtime_fixture()
        complete, actual = instance.validate_audits(rows)
        self.assertTrue(complete)
        self.assertEqual(actual, {"namedAuditInventory": success_result()["namedAuditInventory"],
            "auditAttemptIds": [sha(100 + index) for index in range(25)], "reusedTunnelRequestUnits": 0})
        self.assertEqual(sum(connection_counts(spec)[1] for spec in SPECS), 8)
        for spec in SPECS:
            self.assertEqual(checker.connection_units(spec), connection_counts(spec))
        for phase in ("wrong_outer_ca", "missing_confirmation", "wrong_tarball_hash"):
            self.assertEqual(checker.connection_units(spec_for(phase)), (0, 0))
        self.assertEqual(checker.connection_units(spec_for("wrong_inner_ca")), (1, 0))
        for kind in (START, RELEASE, "data_plane.connect.established", CONNECT_DENIED, "data_plane.request.denied"):
            target = next(row for row in rows if row["event_type"] == kind)
            extra = deepcopy(target); extra.update(id=sha(9990), event_hash=sha(9991))
            with self.subTest(extra=kind), self.assertRaises(checker.CheckFailure):
                runtime_fixture()[0].validate_audits(rows + [extra])
            missing = [row for row in rows if row["id"] != target["id"]]
            self.assertFalse(runtime_fixture()[0].validate_audits(missing)[0])
        for kind, changes in ((CONNECT_DENIED, {"status_code": 200}),
                (CONNECT_DENIED, {"payload": {"error": "secret-canary"}}),
                ("data_plane.request.denied", {"principal_id": "fabricated"}),
                ("data_plane.credential_lease.issued", {"expected_credential_version": True}),
                ("data_plane.credential_lease.issued", {"data_plane_binary_digest": sha(999)}),
                ("data_plane.policy.reloaded", {"policy_hash": POLICY})):
            value = deepcopy(rows); next(row for row in value if row["event_type"] == kind)["event"].update(changes)
            with self.subTest(kind=kind, fields=list(changes)), self.assertRaises(checker.CheckFailure):
                runtime_fixture()[0].validate_audits(value)
        # One two-request publish invocation may reuse its established tunnel;
        # matching all authority fields is still required.
        reused = deepcopy(rows)
        target = next(row for row in reversed(reused) if row["event_type"] == "data_plane.connect.established"
            and row["event"]["principal_id"] == "principal-metadata")
        target["event_type"] = "data_plane.connect.keep_alive"
        target["event"].update(outcome="keep_alive", intercepted_request_count=2)
        self.assertTrue(runtime_fixture()[0].validate_audits(reused)[0])
        target["event"]["intercepted_request_count"] = True
        with self.assertRaises(checker.CheckFailure):
            runtime_fixture()[0].validate_audits(reused)
        changed = deepcopy(rows); changed[0]["event_hash"] = sha(999)
        with self.assertRaises(checker.CheckFailure):
            instance.validate_audits(changed)

    def test_actual_launcher_defaults_to_view_and_preserves_single_process_boundary(self):
        class Selected:
            def __enter__(self): self.items = {}; return self
            def __exit__(self, *_): return False
            def register(self, stream, _, name): self.items[stream] = name
            def unregister(self, stream): self.items.pop(stream)
            def get_map(self): return self.items
            def select(self, _): return [(SimpleNamespace(fd=stream, fileobj=stream, data=name), None)
                for stream, name in self.items.items()]
        for phase in ("view_unscoped", "view_scoped", "missing_confirmation"):
            spec = spec_for(phase); out, err = io.BytesIO(), io.BytesIO()
            raw = encode(summary(spec)) + b"\n"
            pending = {out: [raw, b""] if spec["success"] else [b""], err: [b""] if spec["success"] else [raw, b""]}
            child = SimpleNamespace(stdout=out, stderr=err, wait=lambda **_: 0 if spec["success"] else 1,
                poll=lambda: 0, kill=lambda: self.fail("completed inert child must not be killed"))
            environment = {"LANG": "C.UTF-8"}
            with patch.object(checker.subprocess, "Popen", return_value=child) as launch, \
                    patch.object(checker.selectors, "DefaultSelector", Selected), \
                    patch.object(checker.os, "read", side_effect=lambda stream, _: pending[stream].pop(0)), \
                    patch.object(checker.time, "monotonic", return_value=10):
                result = checker.run_client(spec, environment, 20)
            self.assertEqual(result["phase"], phase)
            self.assertEqual(launch.call_count, 1)
            self.assertEqual(launch.call_args.args[0], ("/node", "/app/examples/npm-registry/client.mjs")
                + (() if phase == "view_unscoped" else (spec["operation"],)))
            self.assertEqual(launch.call_args.kwargs["env"], environment)
            self.assertIs(launch.call_args.kwargs["close_fds"], True)
            self.assertIs(launch.call_args.kwargs["start_new_session"], True)
            self.assertTrue(out.closed and err.closed)
        for seconds in (0, 26):
            with self.assertRaises(checker.CheckFailure):
                checker.run_client(SPECS[0], {}, seconds)

    def test_actual_launcher_checks_install_child_before_lock_readback(self):
        class Selected:
            def __enter__(self): self.items = {}; return self
            def __exit__(self, *_): return False
            def register(self, stream, _, name): self.items[stream] = name
            def unregister(self, stream): self.items.pop(stream)
            def get_map(self): return self.items
            def select(self, _): return [(SimpleNamespace(fd=stream, fileobj=stream, data=name), None)
                for stream, name in self.items.items()]
        cases = [(phase, None) for phase in INSTALL_PHASES] + [("install_published", "exit"), ("install_published", "summary")]
        for phase, failure in cases:
            spec = spec_for(phase); installed = installation(spec)
            raw = encode(summary(spec)) + b"\n"
            code, out_bytes, err_bytes = (0, raw, b"") if spec["success"] else (1, b"", raw)
            if failure == "exit":
                code, out_bytes, err_bytes = 1, b"", b"secret-canary"
            elif failure == "summary":
                out_bytes = b"secret-canary"
            out, err = io.BytesIO(), io.BytesIO()
            pending = {out: [out_bytes, b""] if out_bytes else [b""], err: [err_bytes, b""] if err_bytes else [b""]}
            child = SimpleNamespace(stdout=out, stderr=err, wait=lambda **_: code, poll=lambda: code,
                kill=lambda: self.fail("completed inert child must not be killed"))
            environment = {"SERVERWARE_NPM_PROJECT": "/tmp/original-project", "SERVERWARE_NPM_OUTPUT": installed["directory"]}
            with patch.object(checker.subprocess, "Popen", return_value=child) as launch, \
                    patch.object(checker.selectors, "DefaultSelector", Selected), \
                    patch.object(checker.os, "read", side_effect=lambda stream, _: pending[stream].pop(0)), \
                    patch.object(checker.time, "monotonic", return_value=10), \
                    patch.object(checker, "project_files", return_value={"package.json": checker.project_bytes()}), \
                    patch.object(Path, "exists", return_value=False), patch.object(Path, "is_symlink", return_value=False), \
                    patch.object(checker, "inspect_installation", return_value=installed) as inspect:
                if failure:
                    with self.assertRaises(checker.CheckFailure) as caught:
                        checker.run_client(spec, environment, 20, clean=lambda _: None)
                    self.assertEqual(str(caught.exception), "npm installation process " +
                        ("exit differs" if failure == "exit" else "summary differs"))
                    self.assertNotIn("secret-canary", str(caught.exception))
                    inspect.assert_not_called()
                else:
                    self.assertEqual(checker.run_client(spec, environment, 20, clean=lambda _: None), client_receipt(spec))
                    inspect.assert_called_once()
            self.assertEqual(launch.call_count, 1)
            self.assertTrue(out.closed and err.closed)

    def test_local_refusal_allows_only_explicit_validated_concurrent_lease_delta(self):
        instance, rows = runtime_fixture()
        self.assertTrue(instance.validate_audits(rows)[0])
        before = dict(instance.cutoff)
        original_kinds = {row["id"]: row["event_type"] for row in rows}
        self.assertEqual(checker.local_lease_delta(before, before, original_kinds), [])
        template = next(row for row in rows if row["event_type"] == "data_plane.credential_lease.issued")
        added = []
        for number, purpose in ((8101, "dispatchSecret"), (8100, "generationMetadata")):
            row = deepcopy(template); row.update(id=uid(number), event_hash=sha(number))
            row["event"].update(purpose=purpose, expected_credential_version=1 if purpose == "dispatchSecret" else None)
            added.append(row)
        self.assertTrue(instance.validate_audits(rows + added)[0])
        expected = [uid(8100), uid(8101)]
        self.assertEqual(checker.local_lease_delta(before, instance.cutoff, instance.audit_kinds), expected)
        self.assertEqual({key: instance.cutoff[key] for key in before}, before)
        # The classifier is used only after the existing full authority checks.
        # A lease label cannot make an invalid issued row eligible.
        for change in ({"principal_id": "other"}, {"route_id": "other"}, {"policy_hash": sha(999)},
                {"credential_id": uid(999)}, {"data_plane_binary_digest": sha(999)},
                {"expected_credential_version": 2}, {"expected_credential_version": True},
                {"status_code": 503}, {"outcome": "rejected"}, {"purpose": "secret-canary"}):
            wrong = deepcopy(added[0]); wrong["event"].update(change)
            with self.subTest(authority=list(change)), self.assertRaises(checker.CheckFailure):
                runtime_fixture()[0].validate_audits(rows + [wrong])
        for kind in (START, RELEASE, BLOCK, "data_plane.connect.established", "data_plane.connect.keep_alive",
                CONNECT_DENIED, "data_plane.request.denied", "data_plane.policy.reloaded",
                "data_plane.credential_lease.rejected", "unknown.secret-canary"):
            kinds = dict(instance.audit_kinds); kinds[uid(8100)] = kind
            with self.subTest(kind=kind), self.assertRaises(checker.CheckFailure) as caught:
                checker.local_lease_delta(before, instance.cutoff, kinds)
            self.assertNotIn("secret-canary", str(caught.exception))
        after, kinds = dict(instance.cutoff), dict(instance.audit_kinds)
        changes = (
            lambda a, k: a.update({next(iter(before)): sha(999)}),
            lambda a, k: (a.pop(next(iter(before))), k.pop(next(iter(before)))),
            lambda a, k: a.update({uid(8100): "secret-canary"}),
            lambda a, k: k.pop(uid(8100)),
            lambda a, k: k.update({uid(9999): "data_plane.credential_lease.issued"}),
            lambda a, k: (a.update({sha(8100): a.pop(uid(8100))}), k.update({sha(8100): k.pop(uid(8100))})),
        )
        for index, change in enumerate(changes):
            a, k = dict(after), dict(kinds); change(a, k)
            with self.subTest(delta=index), self.assertRaises(checker.CheckFailure):
                checker.local_lease_delta(before, a, k)
        overflow = {uid(9000 + index): sha(9000 + index) for index in range(65)}
        with self.assertRaises(checker.CheckFailure):
            checker.local_lease_delta(before, {**before, **overflow},
                {**original_kinds, **{key: "data_plane.credential_lease.issued" for key in overflow}})
        receipt = success_result()
        local = phase_evidence(receipt, "missing_confirmation")
        local.update(newAuditEventIds=expected[:], localConcurrentLeaseEventIds=expected[:])
        receipt["namedAuditInventory"]["data_plane.credential_lease.issued"] = 3
        self.assertTrue(checker.validate_success_result(receipt))
        for change in (
                lambda v: v["namedAuditInventory"].update({"data_plane.credential_lease.issued": 1}),
                lambda v: phase_evidence(v, "missing_confirmation").update(localConcurrentLeaseEventIds=[]),
                lambda v: phase_evidence(v, "missing_confirmation").update(newAuditEventIds=[]),
                lambda v: phase_evidence(v, "missing_confirmation").update(localConcurrentLeaseEventIds=[uid(8100)]),
                lambda v: phase_evidence(v, "missing_confirmation").update(newAuditEventIds=[sha(999)], localConcurrentLeaseEventIds=[sha(999)]),
                lambda v: phase_evidence(v, "missing_confirmation").update(newAuditEventIds=expected[::-1], localConcurrentLeaseEventIds=expected[::-1]),
                lambda v: phase_evidence(v, "missing_confirmation").update(providerAttemptsAfter=26),
                lambda v: phase_evidence(v, "missing_confirmation").update(connectRequestUnits=1),
                lambda v: phase_evidence(v, "missing_confirmation").update(requestDenials=1),
                lambda v: v["phaseEvidence"][0].update(localConcurrentLeaseEventIds=[uid(999)]),
                lambda v: phase_evidence(v, "wrong_tarball_hash").update(newAuditEventIds=expected[:], localConcurrentLeaseEventIds=expected[:])):
            value = deepcopy(receipt); change(value)
            with self.assertRaises(checker.CheckFailure):
                checker.validate_success_result(value)

    def test_closed_receipt_rejects_counts_pins_storage_and_local_audit_claims(self):
        good = success_result()
        self.assertTrue(checker.validate_success_result(good))
        changes = (lambda v: v.update(secret="secret-canary"), lambda v: v.pop("auditChainVerified"),
            lambda v: v.update(realNpmVerified=True), lambda v: v.update(clientCommands=True),
            lambda v: v.update(clientCommands=20), lambda v: v.update(providerAttempts=11), lambda v: v.update(unauthorizedPuts=1),
            lambda v: v.update(commandRetries=1), lambda v: v.update(trustMode="separate-exclusive-pools"),
            lambda v: v.update(nodeSha256="0" * 64), lambda v: v.update(nodeModulesSha256=sha(999)),
            lambda v: v["sourceSha256"].pop("examples/npm-registry/package-lock.json"),
            lambda v: v.update(revokedPolicyHash=POLICY), lambda v: v["applicationIds"].update(unassigned=uid(12)),
            lambda v: v["storedPublications"][0].update(tarballSha256=sha(999)),
            lambda v: v["requests"][6].update(requestDigest=sha(999)), lambda v: v["clients"][0].update(exitCode=True),
            lambda v: phase_evidence(v, "wrong_app_view").update(connectDenials=0),
            lambda v: phase_evidence(v, "wrong_outer_ca").update(connectRequestUnits=1),
            lambda v: phase_evidence(v, "missing_confirmation").update(newAuditEventIds=[sha(999)]),
            lambda v: phase_evidence(v, "wrong_tarball_hash").update(providerAttemptsAfter=26),
            lambda v: phase_evidence(v, "wrong_package_view").update(requestDenials=0),
            lambda v: v["catalogMutations"].pop(), lambda v: v["durableAuditEventIds"].pop(),
            lambda v: v["auditAttemptIds"].__setitem__(1, v["auditAttemptIds"][0]),
            lambda v: v["namedAuditInventory"].update({CONNECT_DENIED: 7}),
            lambda v: v["namedAuditInventory"].update({"data_plane.request.denied": 5}),
            lambda v: v["namedAuditInventory"].update({"data_plane.connect.established": 18}),
            lambda v: v.update(swallowedAuditFailureDetected=False),
            lambda v: v.update(tarballReleases=5), lambda v: v.update(auditReleases=2),
            lambda v: v.update(reusedTunnelRequestUnits=True),
            lambda v: v["clients"][8]["installation"].update(sourcePreserved=False),
            lambda v: v["clients"][9]["installation"].update(ciLockUnchanged=False),
            lambda v: v["clients"][10].update(exitCode=0),
            lambda v: v["clients"][10]["summary"].pop("warning"),
            lambda v: v["clients"][8]["installation"]["fileSha256"].update({"node_modules/unreviewed/index.js": "0" * 64}))
        for index, change in enumerate(changes):
            value = deepcopy(good); change(value)
            with self.subTest(case=index), self.assertRaises(checker.CheckFailure) as caught:
                checker.validate_success_result(value)
            self.assertNotIn("secret-canary", str(caught.exception))


class NpmInstallationReadbackTests(unittest.TestCase):
    """Real temporary file bytes, not an npm invocation or provider acceptance."""

    def setUp(self):
        guard = ExitStack(); self.addCleanup(guard.close)
        for target in ("socket.socket", "socket.create_connection", "socket.getaddrinfo", "subprocess.Popen", "subprocess.run"):
            guard.enter_context(patch(target, side_effect=AssertionError("installation byte test attempted network/process I/O")))
        self.temporary = tempfile.TemporaryDirectory(prefix="serverware-npm-install-", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write_tree(self, directory, files):
        directory.mkdir()
        for name, raw in files.items():
            target = directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)

    def test_actual_installed_bytes_and_original_ci_lock_are_independently_read(self):
        files = installation_files()
        for phase in INSTALL_PHASES:
            spec = spec_for(phase)
            source, output = self.root / (phase + "-source"), self.root / phase
            before = {"package.json": files["package.json"]}
            if spec["operation"] == "ci":
                before["package-lock.json"] = files["package-lock.json"]
            self.write_tree(source, before); self.write_tree(output, files)
            inspected = []
            actual = checker.inspect_installation(spec, output, source, before, inspected.append)
            self.assertEqual(actual, installation(spec, str(output)))
            self.assertCountEqual(inspected, list(files.values()))
            self.assertEqual(checker.project_files(source), before)
            for package, publication in ((UNSCOPED, "publish_dependency"), (SCOPED, "publish_scoped")):
                # Read the independent archive as well as actual installed files.
                with tarfile.open(fileobj=io.BytesIO(archive(spec_for(publication))), mode="r:gz") as packed:
                    for leaf in ("package.json", "index.js"):
                        self.assertEqual((output / "node_modules" / package / leaf).read_bytes(),
                            packed.extractfile("package/" + leaf).read())

    def test_actual_readback_refuses_lock_file_and_source_drift(self):
        files = installation_files(); spec = spec_for("install_published")
        source, output = self.root / "source", self.root / "install_published"
        before = {key: files[key] for key in ("package.json", "package-lock.json")}
        self.write_tree(source, before); self.write_tree(output, files)
        self.assertEqual(checker.inspect_installation(spec, output, source, before, lambda _: None),
            installation(spec, str(output)))
        lock_path = output / "package-lock.json"
        lock = json.loads(files["package-lock.json"])
        top, leaf = "node_modules/" + UNSCOPED, "node_modules/" + SCOPED
        changes = (lambda v: v.update(lockfileVersion=True), lambda v: v["packages"].pop(leaf),
            lambda v: v["packages"].update({"node_modules/foreign": {"version": "1.0.0"}}),
            lambda v: v["packages"][""]["dependencies"].update({UNSCOPED: "*"}),
            lambda v: v["packages"][top]["dependencies"].update({SCOPED: "^3.0.0"}),
            lambda v: v["packages"][leaf].update(resolved="https://unreviewed.invalid/blob"),
            lambda v: v["packages"][leaf].update(integrity="sha512-forged"),
            lambda v: v["packages"][leaf].update(version="4.0.0"), lambda v: v["packages"][leaf].update(link=True))
        for index, change in enumerate(changes):
            changed = deepcopy(lock); change(changed); lock_path.write_bytes(encode(changed) + b"\n")
            with self.subTest(lock=index), self.assertRaises(checker.CheckFailure):
                checker.inspect_installation(spec, output, source, before, lambda _: None)
            lock_path.write_bytes(files["package-lock.json"])
        # Valid lock semantics are insufficient for ci: its original exact bytes must survive.
        ci_output = self.root / "ci_published"
        self.write_tree(ci_output, {**files, "package-lock.json": files["package-lock.json"] + b"\n"})
        with self.assertRaises(checker.CheckFailure):
            checker.inspect_installation(spec_for("ci_published"), ci_output, source, before, lambda _: None)
        for name in ("package.json", "node_modules/" + UNSCOPED + "/package.json", "node_modules/" + SCOPED + "/index.js"):
            target = output / name; target.write_bytes(files[name] + b" ")
            with self.subTest(file=name), self.assertRaises(checker.CheckFailure):
                checker.inspect_installation(spec, output, source, before, lambda _: None)
            target.write_bytes(files[name])
        extra = output / "unexpected.js"; extra.write_bytes(b"inert")
        with self.assertRaises(checker.CheckFailure):
            checker.inspect_installation(spec, output, source, before, lambda _: None)
        extra.unlink()
        (source / "package.json").write_bytes(before["package.json"] + b" ")
        with self.assertRaises(checker.CheckFailure):
            checker.inspect_installation(spec, output, source, before, lambda _: None)
        (source / "package.json").write_bytes(before["package.json"])
        target = output / "node_modules" / SCOPED / "index.js"; target.unlink()
        with self.assertRaises(checker.CheckFailure):
            checker.inspect_installation(spec, output, source, before, lambda _: None)
        target.symlink_to(source / "package.json")
        with self.assertRaises(checker.CheckFailure):
            checker.project_files(output)


if __name__ == "__main__":
    unittest.main()
