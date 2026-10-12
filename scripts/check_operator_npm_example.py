#!/usr/bin/env python3
"""Actual checked-in npm example, once per fixed network-none fixture case.

No old client jobs, provider contact, dependency installation, HOME override,
transport replacement or retry. An uncertain child ends the entire checker;
the fixture runner then kills the container, including detached npm workers.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import check_operator_npm_metadata as metadata
from scripts import check_operator_npm_publish as publish
from scripts import operator_npm_example_fixture as fixture
from scripts.check_operator_catalog import COLLECTIONS, claim_fixture, features
from scripts.check_operator_demo import CheckFailure, SHA256, require, token_file
from scripts.check_operator_ordinary_client import BLOCK, CONNECT, DENIED, LEASE, RELEASE, RELOAD, START, digest
from scripts.run_operator_x_examples_fixture import failure_site

SCHEMA = "serverware.privateNpmExampleCheck/v1"
COMMAND = ("/node", "/app/examples/npm-registry/client.mjs")
SOURCE_FILES = tuple("examples/npm-registry/" + name for name in
    ("client.mjs", "core.mjs", "worker.mjs", "package.json", "package-lock.json"))
PHASES = ("view_unscoped", "view_scoped", "manifest_unscoped", "manifest_scoped", "metadata_only_publish",
    "publish_unscoped", "publish_scoped", "publish_dependency", "install_published", "ci_published", "install_audit_negative",
    "outside_window_publish", "wrong_package_view", "wrong_package_manifest",
    "wrong_package_publish", "wrong_app_view", "wrong_app_manifest", "wrong_app_publish", "wrong_outer_ca",
    "wrong_inner_ca", "missing_confirmation", "wrong_tarball_hash", "revoked_view", "revoked_manifest", "revoked_publish")
APPLICATIONS = ("metadata", "unscoped", "scoped", "outside", "unassigned", "install")
LOCAL_PHASES = {"missing_confirmation", "wrong_tarball_hash"}
CONNECT_DENIED, KEEP_ALIVE = metadata.CONNECT_DENIED, publish.KEEP_ALIVE
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
INNER = "/client-trust/inner-ca.pem"
OUTER = "/client-trust/outer-ca.pem"
ROW_KEYS = {"ordinal", "accepted", "case", "method", "rawTarget", "requestHeaders", "requestBodySha256",
    "requestBodyBytes", "operation", "status", "responseContentType", "responseBodySha256", "responseBodyBytes",
    "allParsedHeadersValidated"}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def expected_summary(spec, installation=None):
    if not spec["success"]:
        value = {"ok": False, "operation": spec["operation"],
            "error": "npm example failed; check configuration, permissions and Serverware audit logs."}
        if spec["operation"] == "publish":
            value["warning"] = "Publication may be unconfirmed. Inspect registry metadata and audit evidence; do not automatically retry."
        elif spec["case"] in fixture.INSTALL_CASES:
            value.update(installationDirectory=installation["directory"], warning=
                "Partial installation retained. Inspect it and audit logs; choose a new output directory for a deliberate retry.")
        return value
    value = {"ok": True, "operation": spec["operation"], "package": spec["package"], "version": spec["version"]}
    if spec["operation"] == "publish":
        value.update(tag="fixture", tarballSha256=hashlib.sha256(fixture.tarball(spec)).hexdigest(), npmReportedSuccess=True)
    elif spec["case"] in fixture.INSTALL_CASES:
        value.update(installed=True, added=2, audited=3, defaultAuditReportedSuccess=True, vulnerabilities=0,
            lockSha256=installation["lockSha256"], installationDirectory=installation["directory"])
    else:
        value["tarballFetched"] = False
    return value


def validate_client_result(spec, code, out, err, *, installation=None):
    require(type(code) is int and type(out) is bytes and type(err) is bytes, "npm example process result differs")
    if spec["case"] in fixture.INSTALL_CASES:
        validate_installation_receipt(installation, spec)
    else:
        require(installation is None, "unexpected installation receipt")
    summary = expected_summary(spec, installation)
    # Source property insertion order is part of the actual entrypoint output.
    raw = json.dumps(summary, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
    require((code == 0 and out == raw and err == b"") if spec["success"] else
        (code == 1 and out == b"" and err == raw), "npm example exact summary or fixed failure differs")
    return {"phase": spec["case"], "operation": spec["operation"], "exitCode": code, "summary": summary,
        **({"installation": installation} if installation is not None else {})}


def client_environment(spec, application, token, *, project=None, output=None):
    require(spec in fixture.SPECS and type(application) is str and UUID.fullmatch(application)
        and type(token) is str and re.fullmatch(r"[A-Za-z0-9_-]{43}", token), "npm example app identity differs")
    value = {"LANG": "C.UTF-8", "SERVERWARE_PROXY_URL": metadata.PROXY, "SERVERWARE_APP_ID": application,
        "SERVERWARE_PROXY_TOKEN": token, "SERVERWARE_NPM_PACKAGE": spec["package"], "SERVERWARE_CA_FILE": INNER,
        "SERVERWARE_PROXY_CA_FILE": OUTER}
    if spec["operation"] != "view":
        value["SERVERWARE_NPM_VERSION"] = spec["version"]
    if spec["operation"] == "publish":
        value.update(SERVERWARE_NPM_TAG="fixture", SERVERWARE_NPM_TARBALL="/client-packages/" + spec["case"] + ".tgz",
            SERVERWARE_NPM_TARBALL_SHA256=hashlib.sha256(fixture.tarball(spec)).hexdigest(),
            SERVERWARE_NPM_PUBLISH_CONFIRM="publish-publicly")
    if spec["case"] in fixture.INSTALL_CASES:
        require(isinstance(project, Path) and isinstance(output, Path) and project.is_absolute() and output.is_absolute()
            and project != output and not output.is_relative_to(project), "npm installation output overlaps source")
        value.update(SERVERWARE_NPM_PROJECT=str(project), SERVERWARE_NPM_OUTPUT=str(output))
    if spec["case"] == "wrong_outer_ca":
        value.pop("SERVERWARE_PROXY_CA_FILE")
    elif spec["case"] == "wrong_inner_ca":
        value["SERVERWARE_CA_FILE"] = OUTER
    elif spec["case"] == "missing_confirmation":
        value.pop("SERVERWARE_NPM_PUBLISH_CONFIRM")
    elif spec["case"] == "wrong_tarball_hash":
        value["SERVERWARE_NPM_TARBALL_SHA256"] = "0" * 64
    return value


def validate_header_projection(row, spec):
    headers = row["requestHeaders"]
    if spec["case"] in fixture.INSTALL_CASES:
        common = {"host", "accept", "user-agent", "npm-auth-type", "npm-command", "npm-in-ci", "npm-scope"}
        candidates = [item for item in fixture.install_requests(spec["case"])
            if item[:2] == (row["method"], row["rawTarget"])]
        require(len(candidates) == 1, "npm install target differs")
        _, _, mode, package, version = candidates[0]
        allowed = common | ({"content-type", "content-encoding"} if mode == "audit" else
            {"pacote-version", "pacote-req-type", "pacote-pkg-id", "pacote-integrity"})
        require(type(headers) is dict and set(headers) <= allowed
            and all(type(value) is str and value.isascii() and len(value) <= 8192 for value in headers.values())
            and headers.get("host") == "registry.npmjs.org" and headers.get("npm-command") == spec["operation"]
            and headers.get("npm-auth-type", "web") == "web" and headers.get("npm-in-ci") in {None, "false"}
            and headers.get("npm-scope", "") == ""
            and re.fullmatch(r"npm/11\.8\.0 node/v25\.5\.0 linux x64(?: workspaces/false)?", headers.get("user-agent", "")),
            "npm install public header projection differs")
        if mode == "audit":
            require(headers.get("accept") == "*/*" and headers.get("content-type") == "application/json"
                and headers.get("content-encoding") == "gzip", "npm install audit headers differ")
        elif mode == "metadata":
            require(headers.get("accept") == fixture.CORGI and headers.get("pacote-version") == "21.0.4"
                and headers.get("pacote-req-type") == "packument" and headers.get("pacote-pkg-id") == "registry:" + package
                and "pacote-integrity" not in headers, "npm install metadata headers differ")
        else:
            record = stored_record(fixture.spec_for("publish_dependency" if package == fixture.PACKAGES[0] else "publish_scoped"))
            require(headers.get("accept") == "*/*" and headers.get("pacote-version") == "21.0.4"
                and headers.get("pacote-req-type") == "tarball"
                and headers.get("pacote-pkg-id") == "remote:" + package + "@" + fixture.ORIGIN + fixture.tarball_path(package, version)
                and headers.get("pacote-integrity") == record["tarballIntegrity"], "npm install tarball headers differ")
        return
    allowed = {"host", "accept", "user-agent", "npm-auth-type", "npm-command", "npm-in-ci", "npm-scope",
        "pacote-pkg-id", "pacote-req-type", "pacote-version"}
    if row["method"] == "PUT":
        allowed = {"host", "accept", "user-agent", "npm-auth-type", "npm-command", "npm-in-ci", "npm-scope", "content-type"}
    require(type(headers) is dict and set(headers) <= allowed
        and all(type(v) is str and v.isascii() and len(v) <= 8192 for v in headers.values())
        and headers.get("host") == "registry.npmjs.org" and headers.get("npm-in-ci") in (None, "false")
        and headers.get("npm-scope", "") == "", "npm example request header projection differs")
    if spec["operation"] == "manifest":
        require(headers.get("user-agent") == "pacote/21.0.4 node/v25.5.0"
            and not set(headers) & {"npm-command", "npm-auth-type", "npm-scope"}, "standalone pacote headers differ")
    else:
        require(re.fullmatch(r"npm/11\.8\.0 node/v25\.5\.0 linux x64(?: workspaces/false)?", headers.get("user-agent", ""))
            and headers.get("npm-command") == spec["operation"] and headers.get("npm-auth-type", "web") == "web",
            "stock npm CLI headers differ")
    if row["method"] == "GET":
        require(headers.get("accept") == (fixture.FULL if spec["operation"] == "view" else fixture.CORGI)
            and headers.get("pacote-version") == "21.0.4" and headers.get("pacote-req-type") == "packument"
            and headers.get("pacote-pkg-id") == "registry:" + spec["package"], "npm example metadata headers differ")
    else:
        require(row["method"] == "PUT" and spec["operation"] == "publish" and headers.get("accept") == "*/*"
            and headers.get("content-type") == fixture.FULL, "npm example publication headers differ")


def canonical_digests(row, scope, credential_id):
    spec = fixture.spec_for(row["case"])
    validate_header_projection(row, spec)
    require(len(scope) == 3 and all(type(v) is str for v in scope) and SHA256.fullmatch(scope[2])
        and type(credential_id) is str and UUID.fullmatch(credential_id), "npm example canonical scope differs")
    if spec["operation"] == "publish":
        return publish.canonical_digests(row, tuple(scope), credential_id)
    headers = dict(row["requestHeaders"])
    if row["method"] == "POST":
        require(spec["case"] in fixture.INSTALL_CASES and type(row["requestBodyBytes"]) is int
            and 0 < row["requestBodyBytes"] <= 65536 and SHA256.fullmatch(row["requestBodySha256"]),
            "npm install compressed body commitment differs")
        headers["content-length"] = str(row["requestBodyBytes"])
    else:
        require(row["method"] == "GET" and type(row["requestBodyBytes"]) is int and row["requestBodyBytes"] == 0
            and row["requestBodySha256"] == digest(b""), "npm example metadata body differs")
    canonical = {"v": 2, "principal": scope[0], "client_ip": "127.0.0.1", "route_id": scope[1],
        "credential_ref": credential_id, "credential_version": "1", "policy_hash": scope[2],
        "request": {"method": row["method"], "scheme": "https", "authority": "registry.npmjs.org", "path": row["rawTarget"],
            "query": [], "headers": headers, "body_sha256": row["requestBodySha256"],
            "discard_headers": ["accept-encoding", "npm-session"]},
        "operation": row["operation"]}
    return digest(encoded(canonical)), digest(encoded({k: v for k, v in canonical.items() if k not in {"v", "client_ip"}}))


def stored_record(spec):
    payload = fixture.tarball(spec)
    return {"case": spec["case"], "package": spec["package"], "version": spec["version"], "tag": "fixture",
        "attachmentName": spec["package"] + "-" + spec["version"] + ".tgz", "attachmentBytes": len(payload),
        "tarballSha256": digest(payload), "tarballIntegrity": "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode(),
        "tarballShasum": hashlib.sha1(payload).hexdigest()}


def scope_key(row):
    if row["case"] not in fixture.INSTALL_CASES:
        return row["method"]
    operation = row.get("operation")
    modes = {"npm.install.metadata.read": "metadata", "npm.install.tarball.read": "tarball", "npm.install.audit.read": "audit"}
    require(type(operation) is dict and type(operation.get("operation")) is str and operation["operation"] in modes,
        "npm install operation scope differs")
    return modes[operation["operation"]]


def validate_observations(value, completed, phase_scopes, credential_id):
    require(type(completed) is list and completed == list(PHASES[:len(completed)]), "npm example phase order differs")
    arrivals = [item for item in fixture.ARRIVALS if item[0] in completed]
    require(type(value) is dict and set(value) == {"schema", "syntheticOnly", "total", "attempts", "stored"}
        and value["schema"] == SCHEMA.replace("Check", "Observations") and value["syntheticOnly"] is True
        and type(value["total"]) is int and value["total"] == len(arrivals)
        and type(value["attempts"]) is list and len(value["attempts"]) == len(arrivals), "npm example provider arrival count differs")
    wire, stored, seen_install = [], [], set()
    for ordinal, (row, (phase, method)) in enumerate(zip(value["attempts"], arrivals), 1):
        spec = fixture.spec_for(phase)
        require(type(row) is dict and set(row) == ROW_KEYS and row["accepted"] is True
            and type(row["ordinal"]) is int and row["ordinal"] == ordinal and row["case"] == phase
            and row["allParsedHeadersValidated"] is True and type(row["status"]) is int,
            "npm example exact provider request differs")
        mode, package, version = None, spec["package"], spec["version"]
        if phase in fixture.INSTALL_CASES:
            candidates = [item for item in fixture.install_requests(phase)
                if item[:2] == (row["method"], row["rawTarget"])]
            key = (phase, row["method"], row["rawTarget"])
            require(len(candidates) == 1 and key not in seen_install, "npm install unexpected or repeated arrival")
            seen_install.add(key)
            method, _, mode, package, version = candidates[0]
        else:
            require(row["method"] == method and row["rawTarget"] == fixture.path(package), "npm example target differs")
        if mode == "audit":
            operation = {"operation": "npm.install.audit.read", "packages": sorted(fixture.PACKAGES),
                "packageVersions": {fixture.PACKAGES[1]: ["3.0.0"], fixture.PACKAGES[0]: ["1.0.2"]}}
            status = 400 if phase == "install_audit_negative" else 200
            response = b'{"error":"synthetic_audit_refused"}' if status == 400 else b'{}'
            require(row["status"] == status and row["responseContentType"] == fixture.FULL
                and type(row["requestBodyBytes"]) is int and 0 < row["requestBodyBytes"] <= 65536
                and type(row["requestBodySha256"]) is str and SHA256.fullmatch(row["requestBodySha256"]),
                "npm install audit status/body differs")
        elif mode == "tarball":
            spec_blob = fixture.spec_for("publish_dependency" if package == fixture.PACKAGES[0] else "publish_scoped")
            record = stored_record(spec_blob)
            require(record in stored, "npm install tarball was not independently published")
            response = fixture.tarball(spec_blob)
            operation = {"operation": "npm.install.tarball.read", "package": package, "version": version}
            require(row["status"] == 200 and row["responseContentType"] == "application/octet-stream"
                and type(row["requestBodyBytes"]) is int and row["requestBodyBytes"] == 0
                and row["requestBodySha256"] == digest(b""), "npm install tarball response differs")
        elif method == "GET":
            response = fixture.encoded(fixture.packument(package, stored))
            operation = {"operation": "npm.install.metadata.read" if mode else "npm.metadata.read", "package": package}
            require(type(row["requestBodyBytes"]) is int and row["requestBodyBytes"] == 0
                and row["requestBodySha256"] == digest(b"") and row["status"] == 200
                and row["responseContentType"] == (fixture.FULL if spec["operation"] == "view" else "application/vnd.npm.install-v1+json"),
                "npm example complete metadata response differs")
        else:
            record = stored_record(spec); stored.append(record)
            operation = {"operation": "npm.publish", "packageName": spec["package"], "packageVersion": spec["version"],
                "tag": "fixture", **{k: record[k] for k in ("tarballIntegrity", "tarballShasum", "attachmentName")},
                "attachmentBytes": str(record["attachmentBytes"])}
            response = fixture.encoded({"ok": True, "id": spec["package"], "rev": "fixture-" + spec["version"]})
            require(row["status"] == 201 and row["responseContentType"] == fixture.FULL
                and type(row["requestBodyBytes"]) is int and 0 < row["requestBodyBytes"] <= fixture.MAX_BODY
                and type(row["requestBodySha256"]) is str and SHA256.fullmatch(row["requestBodySha256"]), "npm example publication body differs")
        require(row["operation"] == operation and row["responseBodySha256"] == digest(response)
            and type(row["responseBodyBytes"]) is int and row["responseBodyBytes"] == len(response), "npm example operation/response commitment differs")
        scope = tuple(phase_scopes[phase][mode if mode else method])
        request, operation_digest = canonical_digests(row, scope, credential_id)
        wire.append({**row, "scope": scope, "requestDigest": request, "operationDigest": operation_digest})
    require(value["stored"] == stored, "npm example independently stored versions differ")
    return wire, stored


def joined_attempts(rows, wire, credential_id):
    features.audit_cutoff(rows)
    expected, pairs, starts, terminals = {}, {}, Counter(), Counter()
    for item in wire:
        key = (item["requestDigest"], item["operationDigest"])
        expected.setdefault(key, []).append(item)
    for row in rows:
        if row["event_type"] in {START, RELEASE, BLOCK}:
            kind, event = row["event_type"], row["event"]
            require(SHA256.fullmatch(row["id"]) and type(event.get("credential_version")) is int,
                "npm example gate audit identity/generation differs")
            require(kind != BLOCK, "npm example response was blocked")
            key = (event.get("request_digest"), event.get("operation_digest"))
            require(key in expected, "npm example unexpected release commitment")
            item = expected[key][0]
            require(tuple(event.get(name) for name in ("principal_id", "route_id", "policy_hash")) == item["scope"]
                and event.get("credential_ref") == credential_id and event["credential_version"] == 1
                and event.get("method") == item["method"] and event.get("body_sha256") == item["requestBodySha256"],
                "npm example release authority differs")
            attempt = event.get("attempt_id")
            require(type(attempt) is str and SHA256.fullmatch(attempt) and event.get("flow_id") == attempt,
                "npm example release attempt identity differs")
            pair = pairs.setdefault(attempt, {"key": key})
            slot = "start" if kind == START else "terminal"
            require(pair["key"] == key and slot not in pair, "npm example repeated or rebound release attempt")
            pair[slot] = row["id"]
            if kind == START:
                require(event.get("outcome") == "release_started", "npm example release start differs")
                starts[key] += 1
                require(starts[key] <= len(expected[key]), "npm example extra release start")
            else:
                signature = (event.get("upstream_status"), event.get("response_body_sha256"), event.get("response_body_bytes"))
                available = Counter((r["status"], r["responseBodySha256"], r["responseBodyBytes"]) for r in expected[key])
                require(type(signature[0]) is int and type(signature[2]) is int and signature in available,
                    "npm example release response commitment differs")
                validation = event.get("response_validation", {})
                if item["case"] in fixture.INSTALL_CASES:
                    mode = {"metadata": "npmInstallMetadataJsonV1", "tarball": "npmInstallTarballV1",
                        "audit": "npmInstallAuditJsonV1"}[scope_key(item)]
                    adapter = "npm.install.v1"
                else:
                    mode = "npmMetadataJsonV1" if item["method"] == "GET" else "npmPublishJsonV1"
                    adapter = "npm.metadata.v1" if item["method"] == "GET" else "npm.publish.v1"
                require(event.get("outcome") == "released" and validation.get("ok") is True
                    and validation.get("mode") == mode and validation.get("adapter") == adapter
                    and validation.get("body_bytes_preserved") is True and validation.get("allowed_fields_redacted") is False,
                    "npm example typed response validation differs")
                terminals[(key, signature)] += 1
                require(terminals[(key, signature)] <= available[signature], "npm example extra terminal release")
    require(len(pairs) <= len(wire), "npm example extra attempt identity")
    return pairs, len(pairs) == sum(terminals.values()) == len(wire) and all(
        {"start", "terminal"} <= pair.keys() for pair in pairs.values())


def expected_denials(spec, rule):
    phase, package = spec["case"], spec["package"]
    if phase == "metadata_only_publish":
        return [("PUT", "unknown_route_denied", None, None, package)]
    if phase == "outside_window_publish":
        return [("PUT", "request_time_daily_window_denied", rule["route_id"], "npm.publish.v1", package)]
    if phase.startswith("wrong_package_"):
        value = [("GET", "npm_metadata_package_denied", rule["route_id"] + ".metadata", "npm.metadata.v1", package)]
        if spec["operation"] == "publish":
            value.append(("PUT", "npm_publish_package_denied", rule["route_id"], "npm.publish.v1", package))
        return value
    return []


def connection_units(spec):
    phase = spec["case"]
    if phase in LOCAL_PHASES or phase == "wrong_outer_ca":
        return 0, 0
    count = len(fixture.install_requests(phase)) if phase in fixture.INSTALL_CASES else 2 if spec["operation"] == "publish" else 1
    return (0, count) if phase.startswith(("wrong_app_", "revoked_")) else (count, 0)


def local_lease_delta(before, after, event_kinds):
    """Account for concurrent issuance, after the full audit validator ran.

    This does not attribute a lease to a background task or to the local client.
    Existing rows remain immutable; no new request or connection row is allowed.
    """
    require(type(before) is dict and type(after) is dict and type(event_kinds) is dict
        and len(before) <= len(after) <= 500 and set(event_kinds) == set(after)
        and all(type(k) is str and type(v) is str and SHA256.fullmatch(v) for k, v in after.items())
        and all(after.get(k) == v for k, v in before.items()), "npm example local audit history changed")
    added = sorted(set(after) - set(before))
    require(len(added) <= 64 and all(UUID.fullmatch(k) and event_kinds[k] == LEASE for k in added),
        "npm example local refusal produced a request or connection event")
    return added


def project_bytes():
    return fixture.encoded({"name": "serverware-fixture-consumer", "version": "1.0.0", "private": True,
        "dependencies": {"serverware-fixture-publish": "1.0.2"}}) + b"\n"


def project_files(directory):
    """Bounded actual output/source inventory; no archive extraction or execution."""
    require(directory.is_absolute() and directory.resolve() == directory and not directory.is_symlink(),
        "npm installation directory identity differs")
    pending, files, count, total = [directory], {}, 0, 0
    while pending:
        parent = pending.pop()
        require(stat.S_ISDIR(parent.lstat().st_mode), "npm installation directory changed")
        for entry in sorted(parent.iterdir()):
            count += 1
            require(count <= 24, "npm installation output roster exceeds bound")
            info = entry.lstat()
            if stat.S_ISDIR(info.st_mode):
                pending.append(entry)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 4 * 1024**2,
                    "npm installation output file differs")
                total += info.st_size
                require(total <= 8 * 1024**2, "npm installation output bytes exceed bound")
                identity, checksum = file_pin(entry)
                raw = entry.read_bytes()
                require(file_identity(entry) == identity and hashlib.sha256(raw).hexdigest() == checksum,
                    "npm installation output changed during readback")
                files[entry.relative_to(directory).as_posix()] = raw
    return files


def validate_installation_receipt(value, spec):
    require(type(value) is dict and set(value) == {"directory", "lockSha256", "fileSha256", "sourcePreserved", "ciLockUnchanged"}
        and type(value["directory"]) is str and re.fullmatch(r"/tmp/serverware-npm-install-[a-zA-Z0-9_]{8}/" + spec["case"], value["directory"])
        and type(value["lockSha256"]) is str and HEX.fullmatch(value["lockSha256"])
        and value["sourcePreserved"] is True and value["ciLockUnchanged"] is (spec["operation"] == "ci"),
        "npm installation receipt differs")
    files = value["fileSha256"]
    expected = {"package.json", "package-lock.json", "node_modules/.package-lock.json"}
    for package in fixture.PACKAGES:
        expected |= {"node_modules/" + package + "/package.json", "node_modules/" + package + "/index.js"}
    require(type(files) is dict and set(files) == expected and all(type(item) is str and HEX.fullmatch(item) for item in files.values())
        and files["package-lock.json"] == value["lockSha256"]
        and files["package.json"] == hashlib.sha256(project_bytes()).hexdigest(), "npm installation file commitments differ")
    for package, case in zip(fixture.PACKAGES, ("publish_dependency", "publish_scoped")):
        manifest = fixture.encoded(fixture.package_manifest(fixture.spec_for(case))) + b"\n"
        require(files["node_modules/" + package + "/package.json"] == hashlib.sha256(manifest).hexdigest()
            and files["node_modules/" + package + "/index.js"] == hashlib.sha256(b"module.exports = 'inert synthetic package';\n").hexdigest(),
            "npm installation published byte commitment differs")


def inspect_installation(spec, output, source, before, clean):
    require(project_files(source) == before, "npm installation changed original project")
    files = project_files(output)
    for raw in files.values():
        clean(raw)
    require(files.get("package.json") == project_bytes(), "npm installation manifest copy differs")
    lock_raw = files.get("package-lock.json", b"")
    lock = fixture.publish.strict_json(lock_raw)
    expected_locations = {"", *("node_modules/" + package for package in fixture.PACKAGES)}
    require(type(lock) is dict and type(lock.get("lockfileVersion")) is int and lock["lockfileVersion"] == 3
        and lock.get("name") == "serverware-fixture-consumer" and lock.get("version") == "1.0.0"
        and type(lock.get("packages")) is dict and set(lock["packages"]) == expected_locations
        and lock["packages"][""].get("dependencies") == {fixture.PACKAGES[0]: "1.0.2"},
        "npm installation exact lock closure differs")
    for package, case in zip(fixture.PACKAGES, ("publish_dependency", "publish_scoped")):
        saved = stored_record(fixture.spec_for(case))
        entry = lock["packages"]["node_modules/" + package]
        require(entry.get("version") == saved["version"] and entry.get("integrity") == saved["tarballIntegrity"]
            and entry.get("resolved") == fixture.ORIGIN + fixture.tarball_path(package, saved["version"])
            and entry.get("dependencies", {}) == ({fixture.PACKAGES[1]: "3.0.0"} if package == fixture.PACKAGES[0] else {})
            and entry.get("link") is not True, "npm installation transitive dependency differs")
    if spec["operation"] == "ci":
        require(lock_raw == before.get("package-lock.json"), "npm ci changed reviewed source lock")
    receipt = {"directory": str(output), "lockSha256": hashlib.sha256(lock_raw).hexdigest(),
        "fileSha256": {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(files.items())},
        "sourcePreserved": True, "ciLockUnchanged": spec["operation"] == "ci"}
    validate_installation_receipt(receipt, spec)
    return receipt


def run_client(spec, environment, seconds, *, clean=None):
    require(spec in fixture.SPECS and 0 < seconds <= 25, "npm example process deadline differs")
    deadline = time.monotonic() + seconds
    source = Path(environment["SERVERWARE_NPM_PROJECT"]) if spec["case"] in fixture.INSTALL_CASES else None
    output = Path(environment["SERVERWARE_NPM_OUTPUT"]) if source is not None else None
    before = project_files(source) if source is not None else None
    if source is not None:
        require(not output.exists() and not output.is_symlink() and callable(clean), "npm install requires fresh output and leak guard")
    argv = COMMAND if spec["case"] == "view_unscoped" else (*COMMAND, spec["operation"])
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, close_fds=True, start_new_session=True)
    output = {"out": bytearray(), "err": bytearray()}
    try:
        with selectors.DefaultSelector() as selected:
            for stream, name in ((process.stdout, "out"), (process.stderr, "err")):
                selected.register(stream, selectors.EVENT_READ, name)
            while selected.get_map():
                require(time.monotonic() < deadline, "npm example process deadline exceeded")
                for key, _ in selected.select(min(0.1, max(0.001, deadline - time.monotonic()))):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selected.unregister(key.fileobj)
                    else:
                        output[key.data].extend(chunk)
                        require(len(output[key.data]) <= 4096, "npm example process output exceeds bound")
        code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        installation = (inspect_installation(spec, Path(environment["SERVERWARE_NPM_OUTPUT"]), source, before, clean)
            if source is not None else None)
        return validate_client_result(spec, code, bytes(output["out"]), bytes(output["err"]), installation=installation)
    finally:
        # The actual example deliberately creates its own detached worker.
        # This is not a descendant-containment claim: any uncertain result
        # propagates to checker exit, and the runner kills this container first.
        if process.poll() is None:
            process.kill(); process.wait(timeout=2)
        process.stdout.close(); process.stderr.close()


def file_identity(path):
    require(path.is_absolute() and path.resolve() == path and not path.is_symlink(), "npm example pin path differs")
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 160 * 1024**2, "npm example pin file differs")
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def file_pin(path):
    before = file_identity(path)
    with path.open("rb") as stream:
        checksum = hashlib.file_digest(stream, "sha256").hexdigest()
    require(file_identity(path) == before, "npm example input changed while pinned")
    return before, checksum


class NpmExampleCheck(metadata.NpmMetadataCheck):
    def __init__(self, args):
        self.phase = "startup"
        super().__init__(args)
        from scripts.prepare_operator_npm_example_fixture import validate_dependencies
        account = pwd.getpwuid(os.geteuid())
        require(os.geteuid() == os.getegid() == account.pw_uid == account.pw_gid == 10001
            and account.pw_name == "serverware" and account.pw_dir == "/home/serverware"
            and Path(account.pw_dir).is_dir(), "npm example existing service account differs")
        require(args.ca_file == Path(INNER) and args.proxy_ca_file == Path(OUTER), "npm example trust paths differ")
        require(tuple(s["case"] for s in fixture.SPECS) == PHASES and len(fixture.ARRIVALS) == 25,
            "npm example fixed fixture protocol differs")
        self.dependency_root = Path("/app/examples/npm-registry/node_modules")
        self.dependencies = validate_dependencies(self.dependency_root, args.expected_node_modules_sha256)
        paths = [Path("/node"), *(Path("/app") / name for name in SOURCE_FILES), Path(INNER), Path(OUTER),
            Path("/client-trust/requests-ca.pem"), *[Path("/client-packages") / (s["case"] + ".tgz")
                for s in fixture.SPECS if s["operation"] == "publish"]]
        self.pins = {path: file_pin(path) for path in paths}
        require(self.pins[Path("/node")][1] == metadata.NODE_SHA256, "npm example Node pin differs")
        inner, outer = Path(INNER).read_bytes(), Path(OUTER).read_bytes()
        require(inner != outer and all(b"BEGIN CERTIFICATE" in raw and b"PRIVATE KEY" not in raw for raw in (inner, outer))
            and Path("/client-trust/requests-ca.pem").read_bytes() == outer + inner, "npm example distinct additive CA roots differ")
        for spec in fixture.SPECS:
            if spec["operation"] == "publish":
                require(self.pins[Path("/client-packages") / (spec["case"] + ".tgz")][1]
                    == hashlib.sha256(fixture.tarball(spec)).hexdigest(), "npm example reviewed synthetic tarball differs")
        self.completed, self.clients, self.phase_evidence = [], [], []
        self.phase_scopes, self.bindings, self.rules, self.apps = {}, {}, {}, {}
        self.baseline, self.cutoff, self.previous_provider = {}, {}, None
        self.revocation = None
        self.install_root = Path(tempfile.mkdtemp(prefix="serverware-npm-install-"))
        self.install_source = self.install_root / "source"
        self.install_source.mkdir(mode=0o700)
        fixture.save_new(self.install_source / "package.json", project_bytes())

    def current_files(self, *, full=False):
        for path, pin in self.pins.items():
            require((file_pin(path) == pin) if full or path != Path("/node") else (file_identity(path) == pin[0]),
                "npm example source, executable, trust or tarball changed")
        if full:
            from scripts.prepare_operator_npm_example_fixture import validate_dependencies
            require(validate_dependencies(self.dependency_root, self.args.expected_node_modules_sha256) == self.dependencies,
                "npm example dependency tree changed")

    def observe(self):
        status, value = self.json_request(self.registry, "/_fixture/observations", context=self.upstream_ca)
        require(status == 200, "npm example provider observations unavailable")
        wire, stored = validate_observations(value, self.completed, self.phase_scopes, self.credential_id)
        if self.previous_provider is not None:
            previous = self.previous_provider
            require(value["attempts"][:previous["total"]] == previous["attempts"]
                and value["stored"][:len(previous["stored"])] == previous["stored"], "npm example provider history changed")
        self.previous_provider, self.wire, self.stored = value, wire, stored
        return value

    def validate_audits(self, events):
        cutoff = features.audit_cutoff(events)
        require(all(cutoff.get(k) == v for k, v in self.cutoff.items()), "npm example audit history changed")
        self.cutoff = cutoff
        rows = [row for row in events if row["id"] not in self.baseline]
        allowed = {START, RELEASE, LEASE, CONNECT, KEEP_ALIVE, CONNECT_DENIED, DENIED}
        if self.revocation is not None:
            allowed |= {RELOAD, "operator_catalog.application.revoked"}
        require(all(row["event_type"] in allowed for row in rows), "npm example unaccounted audit event")
        pairs, complete = joined_attempts(rows, self.wire, self.credential_id)
        needed_denials, needed_connections, needed_kept = [], Counter(), Counter()
        needed_connect_denied = 0
        for phase in self.completed:
            spec = fixture.spec_for(phase)
            binding = self.bindings[phase]
            units, denied = connection_units(spec)
            needed_connect_denied += denied
            if units:
                key = (binding["principal"], binding["policy"])
                needed_connections[key] += units
                needed_kept[key] += max(0, units - 1)
            needed_denials.extend(expected_denials(spec, self.rules.get(spec["application"])))
        scopes = {tuple(scope) for phase in self.completed for scope in self.phase_scopes[phase].values()
            if not phase.startswith("revoked_") and phase not in LOCAL_PHASES | {"wrong_outer_ca", "wrong_inner_ca"}}
        dispatched = {item["scope"] for item in self.wire}
        counts, denials, connects, kept, established_authorities, kept_authorities = (Counter() for _ in range(6))
        dispatch_seen = False
        for row in rows:
            kind, event = row["event_type"], row["event"]
            require((UUID if kind == LEASE or kind.startswith("operator_catalog.") else SHA256).fullmatch(row["id"]),
                "npm example audit row namespace differs")
            counts[kind] += 1
            if kind == DENIED:
                require(type(event.get("status_code")) is int, "npm example denial status differs")
                signature = publish.validate_denial(event, list(set(needed_denials)))
                denials[signature] += 1
                require(denials[signature] <= Counter(needed_denials)[signature], "npm example repeated request denial")
                # Early policy guards deliberately do not invent principal or
                # policy fields. Their already-counted CONNECT carries scope.
                require(event.get("principal_id") is None and event.get("policy_hash") is None,
                    "npm example early denial fabricated authority")
            elif kind == LEASE:
                scope = tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash"))
                require(scope in scopes and event.get("credential_id") == self.credential_id
                    and type(event.get("status_code")) is int and event["status_code"] == 200 and event.get("outcome") == "issued"
                    and event.get("data_plane_binary_digest") == self.args.expected_binary_sha256
                    and event.get("purpose") in {"generationMetadata", "dispatchSecret"}, "npm example lease authority differs")
                if event["purpose"] == "dispatchSecret":
                    require(scope in dispatched and type(event.get("expected_credential_version")) is int
                        and event["expected_credential_version"] == 1, "npm example unexpected dispatch lease")
                    dispatch_seen = True
                else:
                    require(event.get("expected_credential_version") is None, "npm example metadata lease version differs")
            elif kind in {CONNECT, KEEP_ALIVE}:
                key = (event.get("principal_id"), event.get("policy_hash"))
                require(key in needed_connections and event.get("target") == "registry.npmjs.org:443"
                    and event.get("method") == "CONNECT" and event.get("client_ip") == "127.0.0.1"
                    and event.get("outcome") == ("established" if kind == CONNECT else "keep_alive")
                    and type(event.get("status_code")) is int and event["status_code"] == 200,
                    "npm example CONNECT scope differs")
                authority = dict(event); authority.pop("outcome")
                if kind == KEEP_ALIVE:
                    limit = 5 if key[0] == self.apps["install"][0]["principal_id"] else 2
                    require(type(event.get("intercepted_request_count")) is int and 2 <= event["intercepted_request_count"] <= limit,
                        "npm example reused tunnel request count differs")
                    authority.pop("intercepted_request_count"); kept[key] += event["intercepted_request_count"] - 1
                    require(kept[key] <= needed_kept[key], "npm example extra reused tunnel")
                    kept_authorities[encoded(authority)] += 1
                else:
                    require("intercepted_request_count" not in event, "npm example established tunnel has a request count")
                    connects[key] += 1; established_authorities[encoded(authority)] += 1
                require(connects[key] + kept[key] <= needed_connections[key], "npm example repeated CONNECT")
            elif kind == CONNECT_DENIED:
                require(event.get("principal_id") is None and event.get("policy_hash") is None
                    and event.get("target") == "registry.npmjs.org:443" and event.get("method") == "CONNECT"
                    and event.get("client_ip") == "127.0.0.1" and event.get("outcome") == "denied"
                    and type(event.get("status_code")) is int and event["status_code"] == 403
                    and event.get("payload", {}).get("error") == "client_principal_denied"
                    and counts[kind] <= needed_connect_denied, "npm example application denial differs")
            elif kind == RELOAD:
                require(self.revocation is not None and event.get("previous_policy_hash") == self.accepted_policy
                    and event.get("policy_hash") == self.revocation[2]
                    and event.get("policy_sequence") == self.snapshot["policy"]["sequence"]
                    and type(event.get("routes")) is int and event["routes"] == 8 and counts[kind] <= 1,
                    "npm example revoked policy reload differs")
            elif kind == "operator_catalog.application.revoked":
                require((kind, event.get("resource_id"), event.get("policy_hash")) == self.revocation
                    and counts[kind] <= 1, "npm example app revocation audit differs")
        require(all(n <= established_authorities[key] for key, n in kept_authorities.items()),
            "npm example keep-alive lacks established authority")
        require(counts[LEASE] <= 128, "npm example lease event bound exceeded")
        complete = (complete and (dispatch_seen or not self.wire) and denials == Counter(needed_denials)
            and all(connects[key] + kept[key] == n for key, n in needed_connections.items())
            and counts[CONNECT_DENIED] == needed_connect_denied)
        if self.revocation is not None:
            complete = complete and counts[RELOAD] == counts["operator_catalog.application.revoked"] == 1
        self.audit_kinds = {row["id"]: row["event_type"] for row in events}
        return complete, {"namedAuditInventory": dict(sorted(counts.items())), "auditAttemptIds": sorted(pairs),
            "reusedTunnelRequestUnits": sum(kept.values())}

    def checkpoint(self):
        drained = None
        while True:
            self.observe()
            events = self.audit()
            if drained is not None:
                require(all(row["id"] in drained or row["event_type"] == LEASE for row in events),
                    "npm example new non-lease event after drained checkpoint")
            complete, evidence = self.validate_audits(events)
            if complete and self.audit_drained():
                if drained is not None:
                    return evidence
                drained = dict(self.cutoff)
            time.sleep(min(0.1, self.timeout()))

    def run(self):
        self.health(); self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        require(initial["revision"] == 1 and all(not initial[k] for k in COLLECTIONS), "npm example requires fresh empty catalog")
        capabilities = initial.get("capabilities", {})
        require(capabilities.get("npm", {}).get("destination_allowed") is True
            and capabilities.get("npm_publish", {}).get("source_pair_required") is True
            and capabilities["npm_publish"].get("destination_allowed") is True
            and capabilities["npm_publish"].get("registry_origin") == fixture.ORIGIN
            and capabilities.get("npm_install", {}).get("schema") == "serverware.operatorNpmInstall/v1"
            and capabilities["npm_install"].get("source_pair_required") is True
            and capabilities["npm_install"].get("destination_allowed") is True
            and capabilities["npm_install"].get("modes") == ["metadata", "tarball", "audit"]
            and capabilities["npm_install"].get("dependencies_require_explicit_grant") is True
            and capabilities.get("application_proxy_authentication", {}).get("modes") == ["bearer", "basic_and_bearer_v1"],
            "npm example paired Basic metadata/publish capability missing")
        self.policy_hash = initial["policy"]["policy_hash"]
        credential, _, _ = self.mutate("/credentials/npm-token", {"name": self.run_id + "-npm", "secret": self.credential},
            collection="credentials", result_key="credential", event="operator_catalog.credential.npm_token_created", creates=True)
        self.credential_id = credential["id"]
        require(type(credential.get("credential_generation")) is int and credential["credential_generation"] == 1,
            "npm example credential generation differs")
        self.window = publish.closed_window(datetime.now(timezone.utc))
        for name in APPLICATIONS:
            app, token, _ = self.mutate("/applications", {"name": self.run_id + "-" + name, "token_lifetime_seconds": 3600,
                "proxy_authentication": "basic_and_bearer_v1"}, collection="applications", result_key="application",
                event="operator_catalog.application.created", creates=True, token=True)
            require(app.get("proxy_authentication") == "basic_and_bearer_v1", "npm example saved Basic mode differs")
            self.apps[name] = (app, token)
            if name == "unassigned":
                continue
            common = {"name": self.run_id + "-" + name, "application_id": app["id"], "credential_id": self.credential_id}
            package = fixture.PACKAGES[1 if name == "scoped" else 0]
            if name == "metadata":
                route, payload, event = "/access-rules/npm-metadata", {**common, "operation_bundle": "npm_metadata_read_v1",
                    "packages": [package]}, "npm_metadata_created"
            elif name == "install":
                self.wait_catalog_loaded("npm-example-install-admission")
                route, payload, event = "/access-rules/npm-install", {**common, "operation_bundle": "npm_install_v1",
                    "packages": sorted(fixture.PACKAGES)}, "npm_install_created"
            else:
                route, payload, event = "/access-rules/npm-publish", {**common, "operation_bundle": "npm_publish_v1", "package": package,
                    "tag": "fixture", "publishing_window": self.window if name == "outside" else None}, "npm_publish_created"
            rule, _, _ = self.mutate(route, payload, collection="access_rules", result_key="access_rule",
                event="operator_catalog.access_rule." + event, creates=True, authority_changed=True)
            require(all(rule.get(k) == v for k, v in payload.items()), "npm example saved permission differs")
            self.rules[name] = rule
        self.wait_catalog_loaded("npm-example-ready"); pins = self.warm_cas_snapshot()
        require([len(pins[k]) for k in COLLECTIONS] == [1, 6, 5], "npm example resource inventory differs")
        while not self.audit_drained():
            time.sleep(min(0.1, self.timeout()))
        self.baseline = self.cutoff = features.audit_cutoff(self.audit())
        self.accepted_policy = self.policy_hash
        self.observe()
        for spec in fixture.SPECS:
            self.phase = phase = spec["case"]
            app, token = self.apps[spec["application"]]
            rule = self.rules.get(spec["application"])
            if phase == "revoked_view":
                self.mutate("/applications/revoke", {"id": app["id"]}, collection="applications", result_key="application",
                    event="operator_catalog.application.revoked", authority_changed=True)
                self.revocation = self.mutations[-1]
                self.wait_catalog_loaded("npm-example-revoked"); pins = self.warm_cas_snapshot()
                require(self.resource(pins, "applications", app["id"])["status"] == "revoked"
                    and self.resource(pins, "access_rules", rule["id"])["status"] == "revoked", "npm example scoped app/grant revocation differs")
                self.checkpoint()
            self.unchanged(pins)
            self.bindings[phase] = {"principal": app["principal_id"], "policy": self.policy_hash}
            if spec["application"] == "install":
                scopes = {mode: (app["principal_id"], rule["route_id"] + suffix, self.policy_hash)
                    for mode, suffix in (("metadata", ""), ("tarball", ".tarball"), ("audit", ".audit"))}
            else:
                scopes = {} if rule is None else {"GET": (app["principal_id"], rule["route_id"]
                    + ("" if spec["application"] == "metadata" else ".metadata"), self.policy_hash)}
            if rule is not None and spec["application"] not in {"metadata", "install"}:
                scopes["PUT"] = (app["principal_id"], rule["route_id"], self.policy_hash)
            self.phase_scopes[phase] = scopes
            before_provider, before_cutoff = self.previous_provider, dict(self.cutoff)
            self.current_files()
            project = (self.install_root / "install_published" if spec["operation"] == "ci" else self.install_source)
            environment = client_environment(spec, app["id"], token,
                **({"project": project, "output": self.install_root / phase} if phase in fixture.INSTALL_CASES else {}))
            self.clients.append(run_client(spec, environment, min(25, self.deadline - time.monotonic()), clean=self.clean))
            self.current_files(); self.completed.append(phase)
            evidence = self.checkpoint()
            if not any(case == phase for case, _ in fixture.ARRIVALS):
                require(self.previous_provider == before_provider, "npm example denied/local phase changed provider state")
            new_ids = sorted(set(self.cutoff) - set(before_cutoff))
            local_leases = local_lease_delta(before_cutoff, self.cutoff, self.audit_kinds) if phase in LOCAL_PHASES else []
            units, denied = connection_units(spec)
            self.phase_evidence.append({"phase": phase, "applicationId": app["id"], "policyHash": self.policy_hash,
                "providerAttemptsBefore": before_provider["total"], "providerAttemptsAfter": self.previous_provider["total"],
                "newAuditEventIds": new_ids, "requestDenials": len(expected_denials(spec, rule)),
                "connectDenials": denied, "connectRequestUnits": units, "localOnly": phase in LOCAL_PHASES,
                "localConcurrentLeaseEventIds": local_leases})
            self.unchanged(pins)
        self.phase = "final"; evidence = self.checkpoint(); events = self.audit()
        complete, evidence = self.validate_audits(events)
        require(complete, "npm example final retained audit snapshot incomplete")
        found, durable = set(), set()
        for row in events:
            event = row["event"]
            key = (row["event_type"], event.get("resource_id"), event.get("policy_hash"))
            if key in self.mutations:
                found.add(key); durable.add(row["id"])
            if row["event_type"] in {START, RELEASE}:
                durable.add(row["id"])
        require(found == set(self.mutations) and len(found) == 13 and len(durable) == 63, "npm example durable mutation/request inventory differs")
        chain = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(chain.get("ok") is True and chain.get("complete") is True and chain.get("backend") == "sqlite",
            "npm example complete persisted audit chain unavailable")
        self.current_files(full=True)
        result = {"schema": SCHEMA, "ok": True, "syntheticOnly": True, "actualExampleEntrypoint": True,
            "auditChainVerified": True, "stockClientTransports": True, "allParsedUpstreamHeadersValidated": True,
            "distinctOuterInnerCAs": True, "trustMode": "additiveSharedNodeRoots", "productionReady": False, "realNpmVerified": False,
            "npmInstallVerified": True, "coldCiVerified": True, "transitiveDependencyVerified": True,
            "defaultAuditSuccessVerified": True, "swallowedAuditFailureDetected": True,
            "publicDnsVerified": False, "hiddenWireHeaderProof": False,
            "defaultRetryBehaviorVerified": False, "configuredRetries": 0, "commandRetries": 0,
            "clientCommands": 25, "successfulClientCommands": 9, "expectedFailedClientCommands": 16,
            "providerAttempts": 25, "metadataReleases": 13, "tarballReleases": 6, "auditReleases": 3,
            "unauthorizedPuts": 0,
            "npmVersion": "11.8.0", "pacoteVersion": "21.0.4", "registryFetchVersion": "19.1.1",
            "dataPlaneBinaryDigest": self.args.expected_binary_sha256, "nodeSha256": metadata.NODE_SHA256,
            "nodeModulesSha256": self.args.expected_node_modules_sha256,
            "sourceSha256": {name: self.pins[Path("/app") / name][1] for name in SOURCE_FILES},
            "credentialId": self.credential_id, "applicationIds": {name: row[0]["id"] for name, row in self.apps.items()},
            "ruleIds": {name: row["id"] for name, row in self.rules.items()}, "policyHash": self.accepted_policy,
            "revokedPolicyHash": self.policy_hash, "publishingWindowUtc": self.window, "clients": self.clients,
            "requests": self.wire, "storedPublications": self.stored, "phaseEvidence": self.phase_evidence,
            "catalogMutations": self.mutations, "durableAuditEventIds": sorted(durable), **evidence}
        validate_success_result(result); self.clean(encoded(result))
        return result


def validate_success_result(value):
    """Closed actual-entrypoint evidence; runner additionally requires exit zero."""
    true_flags = {"ok", "syntheticOnly", "actualExampleEntrypoint", "auditChainVerified", "stockClientTransports",
        "allParsedUpstreamHeadersValidated", "distinctOuterInnerCAs", "npmInstallVerified", "coldCiVerified",
        "transitiveDependencyVerified", "defaultAuditSuccessVerified", "swallowedAuditFailureDetected"}
    false_flags = {"productionReady", "realNpmVerified", "publicDnsVerified",
        "hiddenWireHeaderProof", "defaultRetryBehaviorVerified"}
    integers = {"configuredRetries": 0, "commandRetries": 0, "clientCommands": 25, "successfulClientCommands": 9,
        "expectedFailedClientCommands": 16, "providerAttempts": 25, "metadataReleases": 13,
        "tarballReleases": 6, "auditReleases": 3, "unauthorizedPuts": 0}
    fields = true_flags | false_flags | set(integers) | {"schema", "trustMode", "npmVersion", "pacoteVersion", "registryFetchVersion",
        "dataPlaneBinaryDigest", "nodeSha256", "nodeModulesSha256", "sourceSha256", "credentialId", "applicationIds",
        "ruleIds", "policyHash", "revokedPolicyHash", "publishingWindowUtc", "clients", "requests", "storedPublications",
        "phaseEvidence", "catalogMutations", "durableAuditEventIds", "namedAuditInventory", "auditAttemptIds", "reusedTunnelRequestUnits"}
    require(type(value) is dict and set(value) == fields and value["schema"] == SCHEMA
        and all(value[k] is True for k in true_flags) and all(value[k] is False for k in false_flags)
        and all(type(value[k]) is int and value[k] == v for k, v in integers.items()), "npm example final result shape differs")
    require(value["trustMode"] == "additiveSharedNodeRoots" and value["npmVersion"] == "11.8.0"
        and value["pacoteVersion"] == "21.0.4" and value["registryFetchVersion"] == "19.1.1"
        and value["nodeSha256"] == metadata.NODE_SHA256 and type(value["nodeModulesSha256"]) is str
        and HEX.fullmatch(value["nodeModulesSha256"]) and type(value["sourceSha256"]) is dict
        and set(value["sourceSha256"]) == set(SOURCE_FILES)
        and all(type(v) is str and HEX.fullmatch(v) for v in value["sourceSha256"].values())
        and all(type(value[k]) is str and SHA256.fullmatch(value[k]) for k in ("dataPlaneBinaryDigest", "policyHash", "revokedPolicyHash"))
        and value["policyHash"] != value["revokedPolicyHash"], "npm example artifact/policy pins differ")
    apps, rules = value["applicationIds"], value["ruleIds"]
    require(type(apps) is dict and set(apps) == set(APPLICATIONS) and type(rules) is dict
        and set(rules) == set(APPLICATIONS) - {"unassigned"}, "npm example saved resource inventory differs")
    ids = [value["credentialId"], *apps.values(), *rules.values()]
    require(all(type(v) is str and UUID.fullmatch(v) for v in ids) and len(set(ids)) == 12, "npm example resource identities differ")
    require(value["publishingWindowUtc"] in ({"start": "18:00", "end": "19:00"}, {"start": "06:00", "end": "07:00"}),
        "npm example original closed window differs")
    require(type(value["clients"]) is list and len(value["clients"]) == 25, "npm example actual command count differs")
    installations = {}
    for row, spec in zip(value["clients"], fixture.SPECS):
        require(type(row) is dict, "npm example client receipt differs")
        installation = row.get("installation")
        if spec["case"] in fixture.INSTALL_CASES:
            validate_installation_receipt(installation, spec)
            installations[spec["case"]] = installation
        else:
            require(installation is None and "installation" not in row, "unexpected installation receipt")
        expected = {"phase": spec["case"], "operation": spec["operation"], "exitCode": 0 if spec["success"] else 1,
            "summary": expected_summary(spec, installation), **({"installation": installation} if installation is not None else {})}
        require(type(row) is dict and encoded(row) == encoded(expected), "npm example actual client receipt differs")
    require(len({str(Path(row["directory"]).parent) for row in installations.values()}) == 1
        and installations["ci_published"]["lockSha256"] == installations["install_published"]["lockSha256"],
        "npm ci original lock or fresh output relationship differs")
    requests = value["requests"]
    require(type(requests) is list and len(requests) == 25 and all(type(row) is dict
        and set(row) == ROW_KEYS | {"scope", "requestDigest", "operationDigest"} for row in requests), "npm example request inventory differs")
    scopes = {}
    for row in requests:
        scope = row["scope"]
        require(type(scope) in (list, tuple) and len(scope) == 3 and all(type(v) is str and 0 < len(v) <= 256 for v in scope)
            and scope[2] == value["policyHash"], "npm example request policy scope differs")
        key = scope_key(row)
        previous = scopes.setdefault(row["case"], {}).setdefault(key, scope)
        require(previous == scope, "npm example phase route rebound")
    observed = {"schema": fixture.SCHEMA, "syntheticOnly": True, "total": 25,
        "attempts": [{k: v for k, v in row.items() if k in ROW_KEYS} for row in requests], "stored": value["storedPublications"]}
    wire, stored = validate_observations(observed, list(PHASES), scopes, value["credentialId"])
    require(encoded(wire) == encoded(requests) and len(stored) == 3,
        "npm example request/operation/storage joins differ")
    phases = value["phaseEvidence"]
    require(type(phases) is list and len(phases) == 25, "npm example per-phase checkpoints unavailable")
    count, seen = 0, set()
    for row, spec in zip(phases, fixture.SPECS):
        phase = spec["case"]
        next_count = count + sum(case == phase for case, _ in fixture.ARRIVALS)
        units, denied = connection_units(spec)
        expected_requests = 1 if phase in {"metadata_only_publish", "outside_window_publish", "wrong_package_view", "wrong_package_manifest"} else 2 if phase == "wrong_package_publish" else 0
        require(type(row) is dict and set(row) == {"phase", "applicationId", "policyHash", "providerAttemptsBefore",
            "providerAttemptsAfter", "newAuditEventIds", "requestDenials", "connectDenials", "connectRequestUnits", "localOnly",
            "localConcurrentLeaseEventIds"}
            and row["phase"] == phase and row["applicationId"] == apps[spec["application"]]
            and row["policyHash"] == value["revokedPolicyHash" if phase.startswith("revoked_") else "policyHash"]
            and row["localOnly"] is (phase in LOCAL_PHASES)
            and all(type(row[k]) is int and row[k] == v for k, v in {"providerAttemptsBefore": count,
                "providerAttemptsAfter": next_count, "requestDenials": expected_requests, "connectDenials": denied,
                "connectRequestUnits": units}.items()), "npm example checkpoint/control count differs")
        audit_ids = row["newAuditEventIds"]
        local_leases = row["localConcurrentLeaseEventIds"]
        require(type(local_leases) is list and all(type(v) is str and UUID.fullmatch(v) for v in local_leases)
            and local_leases == sorted(set(local_leases))
            and (local_leases == audit_ids if phase in LOCAL_PHASES else local_leases == []),
            "npm example local concurrent lease accounting differs")
        require(type(audit_ids) is list and len(audit_ids) <= 64 and all(type(v) is str and (UUID.fullmatch(v) or SHA256.fullmatch(v)) for v in audit_ids)
            and len(set(audit_ids)) == len(audit_ids) and not seen.intersection(audit_ids)
            and (bool(audit_ids) if units or denied else True),
            "npm example checkpoint audit identities differ")
        seen.update(audit_ids); count = next_count
    mutations = value["catalogMutations"]
    require(type(mutations) is list and len(mutations) == 13 and all(type(row) in (list, tuple) and len(row) == 3
        and type(row[0]) is str and type(row[1]) is str and UUID.fullmatch(row[1])
        and type(row[2]) is str and SHA256.fullmatch(row[2]) for row in mutations), "npm example mutation evidence differs")
    require(Counter(row[0] for row in mutations) == Counter({"operator_catalog.credential.npm_token_created": 1,
        "operator_catalog.application.created": 6, "operator_catalog.access_rule.npm_metadata_created": 1,
        "operator_catalog.access_rule.npm_publish_created": 3, "operator_catalog.access_rule.npm_install_created": 1,
        "operator_catalog.application.revoked": 1})
        and mutations[-1] == type(mutations[-1])(("operator_catalog.application.revoked", apps["scoped"], value["revokedPolicyHash"])),
        "npm example publication/revocation mutation inventory differs")
    for key, length, hash_count in (("durableAuditEventIds", 63, 50), ("auditAttemptIds", 25, 25)):
        rows = value[key]
        require(type(rows) is list and len(rows) == length and all(type(v) is str and (UUID.fullmatch(v) or SHA256.fullmatch(v)) for v in rows)
            and len(set(rows)) == length and sum(bool(SHA256.fullmatch(v)) for v in rows) == hash_count,
            "npm example durable audit identity inventory differs")
    counts = value["namedAuditInventory"]
    expected = {START: 25, RELEASE: 25, DENIED: 6, CONNECT_DENIED: 8, RELOAD: 1, "operator_catalog.application.revoked": 1}
    reused = value["reusedTunnelRequestUnits"]
    require(type(counts) is dict and set(counts) in (set(expected) | {CONNECT, LEASE}, set(expected) | {CONNECT, LEASE, KEEP_ALIVE})
        and all(type(v) is int for v in counts.values()) and all(counts[k] == v for k, v in expected.items())
        and 1 <= counts[LEASE] <= 128 and type(reused) is int and 0 <= counts.get(KEEP_ALIVE, 0) <= reused <= 16
        and reused <= 4 * counts.get(KEEP_ALIVE, 0)
        and sum(len(row["localConcurrentLeaseEventIds"]) for row in phases) <= counts[LEASE]
        and counts[CONNECT] + reused == 32, "npm example final named audit inventory differs")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256", "expected-node-modules-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "proxy-ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file", "run-claim-file"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--upstream-address"); parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args(); check = None
    def expired(*_):
        raise CheckFailure("npm example checker deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    try:
        require(type(args.timeout_seconds) is int and 30 <= args.timeout_seconds <= 180
            and SHA256.fullmatch(args.expected_binary_sha256) and HEX.fullmatch(args.expected_node_modules_sha256),
            "npm example checker pins/deadline differ")
        signal.alarm(args.timeout_seconds); claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = NpmExampleCheck(args); result = check.run()
    except Exception as error:
        result = {"schema": SCHEMA, "ok": False, "syntheticOnly": True, "productionReady": False, "realNpmVerified": False,
            "phase": check.phase if check is not None and check.phase in (*PHASES, "startup", "final") else "startup",
            "failureSite": failure_site(error, Path(__file__).resolve().parents[1]),
            "error": "acceptance_check_failed" if isinstance(error, CheckFailure) else "acceptance_internal_failure"}
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True)); return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
