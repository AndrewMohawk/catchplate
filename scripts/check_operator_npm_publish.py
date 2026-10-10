#!/usr/bin/env python3
"""One-shot real catalog -> Rust -> stock npm publish -> synthetic storage proof.

Only the fixed network-none fixture is admitted. No install, provider contact,
command replay, clock override, transport stub or real publication is performed.
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
import selectors
import signal
import subprocess
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import check_operator_npm_metadata as metadata
from scripts import operator_npm_publish_fixture as fixture
from scripts.check_operator_catalog import COLLECTIONS, PREFIX, claim_fixture, features
from scripts.check_operator_demo import SHA256, CheckFailure, require, token_file
from scripts.check_operator_ordinary_client import BLOCK, CONNECT, DENIED, LEASE, RELEASE, RELOAD, START, digest

CONNECT_DENIED = metadata.CONNECT_DENIED
KEEP_ALIVE = "data_plane.connect.keep_alive"
PHASES = tuple(spec["case"] for spec in fixture.SPECS)
CLIENT_STAGES = {"input", "identity", "trust", "package", "workspace", "npm_spawn", "npm_process", "npm_json", "npm_denial", "npm_receipt"}
CLIENT_ERRORS = metadata.CLIENT_ERRORS | {"ENEEDAUTH", "E400", "E401", "E409", "E422", "E429", "E500", "E503", "E504",
    "EPUBLISHCONFLICT", "EPRIVATE", "EUNSCOPED", "EBADSEMVER", "FETCH_ERROR", "EPIPE"}
CLIENT_STDOUT_SHAPES = {"not_observed", "empty", "oversized", "invalid_json", "json_null", "json_scalar", "json_array",
    "json_object", "npm_error", "npm_error_invalid", "npm_receipt"}
CLIENT_STDOUT_CODE_KINDS = {"not_observed", "absent", "null", "recognized", "unsupported_string", "other_type"}
CLIENT_STDOUT_CONTEXTS = {"none", "unrecognized", "http_error", "publish_conflict", "package_private", "unscoped_access",
    "invalid_version", "auth_required", "transport_error", "tls_error", "duplicate_version", "implicit_latest",
    "fetch_broken_pipe", "fetch_connection_reset", "fetch_socket_hang_up", "fetch_other", "fetch_network_timeout", "fetch_response_timeout"}


def client_failure_observation(value, phase):
    keys = {"schema", "phase", "npmVersion", "pacoteVersion", "registryFetchVersion", "strictSSL",
        "extraCaPreservesDefaultRoots", "configuredRetries", "isolatedCache", "requestRewrite", "force",
        "dryRun", "provenance", "ok", "error", "stage", "errorCode", "processExitCode", "stdoutBytes", "stderrBytes",
        "stdoutShape", "stdoutCodeKind", "stdoutContext"}
    if not isinstance(phase, str) or phase not in PHASES or not isinstance(value, dict) or set(value) != keys:
        return None
    if (value.get("schema") != "serverware.privateNpmPublishClient/v1" or value.get("ok") is not False
            or not isinstance(value.get("phase"), str) or value["phase"] not in {phase, "unknown"}
            or value.get("error") != "stock npm publish operation failed"
            or not isinstance(value.get("stage"), str) or value["stage"] not in CLIENT_STAGES
            or not isinstance(value.get("errorCode"), str) or value["errorCode"] not in CLIENT_ERRORS
            or not isinstance(value.get("stdoutShape"), str) or value["stdoutShape"] not in CLIENT_STDOUT_SHAPES
            or not isinstance(value.get("stdoutCodeKind"), str) or value["stdoutCodeKind"] not in CLIENT_STDOUT_CODE_KINDS
            or not isinstance(value.get("stdoutContext"), str) or value["stdoutContext"] not in CLIENT_STDOUT_CONTEXTS
            or value.get("npmVersion") != "11.8.0" or value.get("pacoteVersion") != "21.0.4"
            or value.get("registryFetchVersion") != "19.1.1"
            or any(value.get(key) is not True for key in ("strictSSL", "extraCaPreservesDefaultRoots", "isolatedCache"))
            or any(value.get(key) is not False for key in ("requestRewrite", "force", "dryRun", "provenance"))
            or type(value.get("configuredRetries")) is not int or value["configuredRetries"] != 0
            or any(type(value.get(key)) is not int or not 0 <= value[key] <= 262144 for key in ("stdoutBytes", "stderrBytes"))
            or value.get("processExitCode") is not None and
                (type(value["processExitCode"]) is not int or not 0 <= value["processExitCode"] <= 255)):
        return None
    if value["stdoutShape"] != "npm_error":
        if value["stdoutCodeKind"] != "not_observed" or value["stdoutContext"] != "none":
            return None
    elif value["stdoutCodeKind"] == "not_observed" or value["stdoutContext"] == "none":
        return None
    return {key: value[key] for key in ("phase", "stage", "errorCode", "processExitCode", "stdoutBytes", "stderrBytes",
        "stdoutShape", "stdoutCodeKind", "stdoutContext")}


class ClientFailure(CheckFailure):
    def __init__(self, phase, value):
        self.observation = client_failure_observation(value, phase)
        super().__init__("stock npm publish failed in " + phase + "; raw output suppressed")


def run_client(spec, application, token, run_id, seconds):
    require(spec["case"] in PHASES and 0 < seconds <= 25, "publish client phase or deadline invalid")
    payload = json.dumps({"phase": spec["case"], "applicationId": application, "token": token,
        "runId": run_id, "package": spec["package"], "version": spec["version"],
        "tarballSha256": digest(fixture.tarball(spec))}).encode()
    deadline = time.monotonic() + seconds
    process = subprocess.Popen(["/node", "/app/scripts/operator_npm_publish_job.mjs"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"LANG": "C.UTF-8", "NODE_EXTRA_CA_CERTS": "/client-trust/requests-ca.pem"}, close_fds=True)
    output = {"out": bytearray(), "err": bytearray()}
    try:
        process.stdin.write(payload); process.stdin.close()
        with selectors.DefaultSelector() as selector:
            for stream, name in ((process.stdout, "out"), (process.stderr, "err")):
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                require(time.monotonic() < deadline, "publish client deadline exceeded")
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fd, 16384)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output[key.data].extend(chunk)
                        require(len(output[key.data]) <= (16384 if key.data == "out" else 8192), "publish client output bound exceeded")
        code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if code != 0 or output["err"]:
            value = None
            try:
                value = json.loads(output["out"])
            except (ValueError, TypeError, RecursionError):
                pass
            raise ClientFailure(spec["case"], value)
        return bytes(output["out"])
    finally:
        if process.poll() is None:
            process.kill(); process.wait(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def closed_window(now):
    """Hours far outside this original 180-second run; no clock manipulation."""
    require(now.tzinfo == timezone.utc, "publish fixture clock must be UTC")
    return {"start": "18:00", "end": "19:00"} if now.hour < 12 else {"start": "06:00", "end": "07:00"}


def canonical_digests(row, scope, credential):
    observed_headers = row["requestHeaders"]
    body_bytes = row["requestBodyBytes"]
    common = {"host", "accept", "user-agent", "npm-auth-type", "npm-command", "npm-in-ci", "npm-scope"}
    allowed = common | ({"pacote-version", "pacote-req-type", "pacote-pkg-id"}
        if row["method"] == "GET" else {"content-type"})
    require(row["method"] in {"GET", "PUT"} and isinstance(observed_headers, dict) and set(observed_headers) <= allowed
        and observed_headers.get("host") == "registry.npmjs.org" and observed_headers.get("npm-command") == "publish"
        and all(isinstance(value, str) and value.isascii() and len(value) <= 8192 for value in observed_headers.values()),
        "unexpected canonical publish request header")
    require(type(body_bytes) is int and (body_bytes == 0 if row["method"] == "GET"
        else 1 <= body_bytes <= fixture.MAX_BODY), "canonical publish observed body length differs")
    headers = dict(observed_headers)
    if row["method"] == "PUT":
        # Rust commits the derived framing for a nonempty buffered request.
        # Reconstruct it only from independently observed bytes, never from a
        # receiver-provided framing header or the caller's claimed value.
        headers["content-length"] = str(body_bytes)
    canonical = {"v": 2, "principal": scope[0], "client_ip": "127.0.0.1", "route_id": scope[1],
        "credential_ref": credential, "credential_version": "1", "policy_hash": scope[2],
        "request": {"method": row["method"], "scheme": "https", "authority": "registry.npmjs.org",
            "path": row["rawTarget"], "query": [], "headers": headers,
            "body_sha256": row["requestBodySha256"], "discard_headers": ["accept-encoding", "npm-session"]},
        "operation": row["operation"]}
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return digest(encode(canonical)), digest(encode({key: value for key, value in canonical.items() if key not in {"v", "client_ip"}}))


def joined_attempts(rows, wire, credential):
    expected = {(item["requestDigest"], item["operationDigest"]): item for item in wire}
    require(len(expected) == len(wire), "publish requests unexpectedly share canonical commitments")
    pairs, terminals = {}, set()
    for row in rows:
        kind, event = row["event_type"], row["event"]
        if kind not in {START, RELEASE, BLOCK}:
            continue
        require(kind != BLOCK, "publish fixture response was blocked")
        key = (event.get("request_digest"), event.get("operation_digest"))
        require(key in expected, "unaccounted publish credential release")
        item = expected[key]
        require(tuple(event.get(name) for name in ("principal_id", "route_id", "policy_hash")) == item["scope"]
            and event.get("credential_ref") == credential and type(event.get("credential_version")) is int
            and event["credential_version"] == 1 and event.get("method") == item["method"]
            and event.get("body_sha256") == item["requestBodySha256"], "publish audit authority or body differs")
        attempt = event.get("attempt_id")
        require(isinstance(attempt, str) and SHA256.fullmatch(attempt) and event.get("flow_id") == attempt,
            "publish attempt identity differs")
        pair = pairs.setdefault(attempt, {"key": key})
        slot = "start" if kind == START else "terminal"
        require(pair["key"] == key and slot not in pair, "publish attempt reused or rebound")
        pair[slot] = row["id"]
        if kind == START:
            require(event.get("outcome") == "release_started", "publish start outcome differs")
        else:
            validation = event.get("response_validation", {})
            mode = "npmMetadataJsonV1" if item["method"] == "GET" else "npmPublishJsonV1"
            adapter = "npm.metadata.v1" if item["method"] == "GET" else "npm.publish.v1"
            require(key not in terminals and event.get("outcome") == "released"
                and event.get("upstream_status") == item["status"]
                and event.get("response_body_sha256") == item["responseBodySha256"]
                and event.get("response_body_bytes") == item["responseBodyBytes"]
                and validation.get("ok") is True and validation.get("mode") == mode
                and validation.get("adapter") == adapter and validation.get("body_bytes_preserved") is True
                and validation.get("allowed_fields_redacted") is False, "publish response release differs")
            terminals.add(key)
    require(len(pairs) <= len(wire), "extra publish release attempt")
    return pairs, len(terminals) == len(wire) and len(pairs) == len(wire) and all(
        {"start", "terminal"} <= pair.keys() for pair in pairs.values())


def expected_denials(phase, app, rule):
    package = fixture.spec_for(phase)["package"]
    primary, companion = rule["route_id"], rule["route_id"] + ".metadata"
    if phase == "prerequisite":
        return [("PUT", "unknown_route_denied", None, None, package)]
    if phase == "wrong_package":
        return [("GET", "npm_metadata_package_denied", companion, "npm.metadata.v1", package),
            ("PUT", "npm_publish_package_denied", primary, "npm.publish.v1", package)]
    if phase == "outside_window":
        return [("PUT", "request_time_daily_window_denied", primary, "npm.publish.v1", package)]
    if phase == "wrong_placeholder":
        return [(method, "credential_existing_header_mismatch", route, adapter, package) for method, route, adapter in
            (("GET", companion, "npm.metadata.v1"), ("PUT", primary, "npm.publish.v1"))]
    return []


def validate_denial(event, expected):
    signature = (event.get("method"), event.get("error"), event.get("route_id"), event.get("adapter"))
    matching = [row for row in expected if row[:4] == signature]
    require(len(matching) == 1 and event.get("outcome") == "denied" and event.get("status_code") == 403,
        "publish denial guard differs")
    target = fixture.path(matching[0][4])
    require(event.get("url") == {"origin_sha256": digest(fixture.ORIGIN.encode()), "origin_bytes": len(fixture.ORIGIN),
        "path_sha256": digest(target.encode()), "path_bytes": len(target), "query_keys": []}, "publish denial target differs")
    return matching[0]


class NpmPublishCheck(metadata.NpmMetadataCheck):
    def __init__(self, args):
        super().__init__(args)
        self.completed, self.expected_denial_rows, self.phase_scopes = [], [], []
        self.cutoff, self.baseline, self.revocation = {}, {}, None

    def observe(self):
        status, value = self.json_request(self.registry, "/_fixture/observations", context=self.upstream_ca)
        require(status == 200 and isinstance(value, dict) and set(value) == {"schema", "syntheticOnly", "total", "attempts", "stored"}
            and value["schema"] == fixture.SCHEMA and value["syntheticOnly"] is True
            and type(value["total"]) is int and isinstance(value["attempts"], list) and isinstance(value["stored"], list)
            and value["total"] == len(value["attempts"]) <= fixture.MAX_ATTEMPTS, "publish registry observations unavailable")
        return value

    def accept_observation(self, observed):
        expected_arrivals = [item for item in fixture.ARRIVALS if item[0] in self.completed]
        require(observed["total"] == len(expected_arrivals), "extra/missing prerequisite, PUT, retry or unsupported registry request")
        stored, wire = [], []
        for ordinal, (row, (phase, method)) in enumerate(zip(observed["attempts"], expected_arrivals), 1):
            spec = fixture.spec_for(phase)
            require(row.get("ordinal") == ordinal and row.get("accepted") is True and row.get("case") == phase
                and row.get("method") == method and row.get("rawTarget") == fixture.path(spec["package"])
                and row.get("allParsedHeadersValidated") is True, "publish wire identity or parsed headers differ")
            if method == "GET":
                response = fixture.encoded(fixture.packument(spec["package"], stored))
                operation = {"operation": "npm.metadata.read", "package": spec["package"]}
                require(row["requestBodySha256"] == digest(b"") and row["requestBodyBytes"] == 0
                    and row["status"] == 200 and row["responseContentType"] == "application/vnd.npm.install-v1+json",
                    "publish prerequisite GET did not return expected whole metadata")
            else:
                payload = fixture.tarball(spec)
                record = {"case": phase, "package": spec["package"], "version": spec["version"], "tag": fixture.TAG,
                    "attachmentName": spec["package"] + "-" + spec["version"] + ".tgz", "attachmentBytes": len(payload),
                    "tarballSha256": digest(payload), "tarballIntegrity": "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode(),
                    "tarballShasum": hashlib.sha1(payload).hexdigest()}
                stored.append(record)
                operation = {"operation": "npm.publish", "packageName": spec["package"], "packageVersion": spec["version"],
                    "tag": fixture.TAG, **{key: record[key] for key in ("tarballIntegrity", "tarballShasum", "attachmentName")},
                    "attachmentBytes": str(record["attachmentBytes"])}
                response = fixture.encoded({"ok": True, "id": spec["package"], "rev": "fixture-" + spec["version"]})
                require(row["status"] == 201 and row["responseContentType"] == fixture.FULL
                    and type(row["requestBodyBytes"]) is int and 0 < row["requestBodyBytes"] <= fixture.MAX_BODY
                    and isinstance(row["requestBodySha256"], str) and SHA256.fullmatch(row["requestBodySha256"]), "publish PUT body/status differs")
            require(row["operation"] == operation and row["responseBodySha256"] == digest(response)
                and row["responseBodyBytes"] == len(response), "publish receiver response/operation differs")
            scope = next(item["routes"][method] for item in self.phase_scopes if item["phase"] == phase)
            request, operation_digest = canonical_digests(row, scope, self.credential_id)
            wire.append({**row, "scope": scope, "requestDigest": request, "operationDigest": operation_digest})
        require(observed["stored"] == stored, "independent immutable stored versions or tarball hashes differ")
        self.wire = wire
        return stored

    def validate_audits(self, events):
        cutoff = features.audit_cutoff(events)
        require(all(cutoff.get(key) == value for key, value in self.cutoff.items()), "publish audit history changed")
        self.cutoff = cutoff
        rows = [row for row in events if row["id"] not in self.baseline]
        allowed = {START, RELEASE, LEASE, CONNECT, KEEP_ALIVE, CONNECT_DENIED, DENIED}
        if self.revocation is not None:
            allowed |= {RELOAD, "operator_catalog.application.revoked"}
        require(all(row["event_type"] in allowed for row in rows), "unaccounted publish audit event")
        pairs, complete = joined_attempts(rows, self.wire, self.credential_id)
        counts, denials, connects, kept, revoked = Counter(), Counter(), Counter(), Counter(), 0
        established_authorities, kept_authorities = Counter(), Counter()
        completed_phases = [item for item in self.phase_scopes
            if item["phase"] in self.completed and item["phase"] != "revoked_app"]
        connection_invocations = Counter((item["principal"], item["policy"]) for item in completed_phases)
        dispatch_seen = False
        known_scopes = {scope for phase in self.phase_scopes if phase["phase"] != "revoked_app"
            for scope in phase["routes"].values()}
        dispatched_scopes = {item["scope"] for item in self.wire}
        for row in rows:
            kind, event = row["event_type"], row["event"]
            counts[kind] += 1
            if kind == DENIED:
                signature = validate_denial(event, self.expected_denial_rows); denials[signature] += 1
                require(denials[signature] <= Counter(self.expected_denial_rows)[signature], "repeated publish denial")
            elif kind == LEASE:
                scope = tuple(event.get(key) for key in ("principal_id", "route_id", "policy_hash"))
                require(scope in known_scopes and event.get("credential_id") == self.credential_id
                    and event.get("status_code") == 200 and event.get("outcome") == "issued"
                    and event.get("data_plane_binary_digest") == self.args.expected_binary_sha256
                    and event.get("purpose") in {"generationMetadata", "dispatchSecret"}, "publish lease authority differs")
                if event["purpose"] == "dispatchSecret":
                    require(scope in dispatched_scopes and type(event.get("expected_credential_version")) is int
                        and event["expected_credential_version"] == 1, "unauthorized publish dispatch lease")
                    dispatch_seen = True
                else:
                    require(event.get("expected_credential_version") is None, "publish generation lease pins a version")
            elif kind in {CONNECT, KEEP_ALIVE}:
                key = (event.get("principal_id"), event.get("policy_hash"))
                require(key in connection_invocations and event.get("target") == "registry.npmjs.org:443"
                    and event.get("method") == "CONNECT"
                    and event.get("outcome") == ("established" if kind == CONNECT else "keep_alive")
                    and type(event.get("status_code")) is int and event["status_code"] == 200
                    and event.get("client_ip") == "127.0.0.1", "publish CONNECT authority differs")
                authority = dict(event)
                authority.pop("outcome")
                if kind == KEEP_ALIVE:
                    # The gate emits this once on tunnel close, only for more
                    # than one intercepted request. Each fresh npm invocation
                    # performs exactly one metadata GET and one publish PUT.
                    require(type(event.get("intercepted_request_count")) is int
                        and event["intercepted_request_count"] == 2,
                        "publish reused CONNECT request count differs")
                    authority.pop("intercepted_request_count")
                    kept[key] += 1
                    require(kept[key] <= connection_invocations[key], "extra publish reused CONNECT or retry")
                    kept_authorities[json.dumps(authority, sort_keys=True, separators=(",", ":"))] += 1
                else:
                    require("intercepted_request_count" not in event, "publish established CONNECT count differs")
                    connects[key] += 1
                    established_authorities[json.dumps(authority, sort_keys=True, separators=(",", ":"))] += 1
                require(connects[key] + kept[key] <= 2 * connection_invocations[key], "extra publish CONNECT or retry")
            elif kind == CONNECT_DENIED:
                require("revoked_app" in self.completed and event.get("principal_id") is None
                    and event.get("target") == "registry.npmjs.org:443" and event.get("method") == "CONNECT"
                    and event.get("outcome") == "denied" and event.get("payload", {}).get("error") == "client_principal_denied",
                    "revoked npm application was not denied")
                revoked += 1; require(revoked <= 2, "extra revoked application attempt")
            elif kind == RELOAD:
                require(self.revocation is not None and event.get("previous_policy_hash") == self.before_revoke_policy
                    and event.get("policy_hash") == self.revocation[2]
                    and event.get("policy_sequence") == self.snapshot["policy"]["sequence"]
                    and event.get("routes") == 5 and counts[kind] <= 1, "publish revocation policy reload differs")
            elif kind == "operator_catalog.application.revoked":
                require((kind, event.get("resource_id"), event.get("policy_hash")) == self.revocation
                    and counts[kind] <= 1, "publish application revocation audit differs")
        # A reused-tunnel receipt must join an established receipt with the
        # exact same public CONNECT authority. There is no per-tunnel ID in
        # these audit events, so validate multiplicities, not invented pairs.
        require(all(number <= established_authorities[authority]
            for authority, number in kept_authorities.items()), "publish reused CONNECT has no matching established authority")
        complete = (complete and dispatch_seen and denials == Counter(self.expected_denial_rows)
            and all(connects[key] + kept[key] == 2 * number
                for key, number in connection_invocations.items())
            and revoked == (2 if "revoked_app" in self.completed else 0))
        if self.revocation is not None:
            complete = complete and counts[RELOAD] == counts["operator_catalog.application.revoked"] == 1
        require(counts[LEASE] <= 64, "publish lease event bound exceeded")
        return complete, {"namedAuditInventory": dict(sorted(counts.items())), "auditAttemptIds": sorted(pairs)}

    def checkpoint(self):
        drained = None
        while True:
            self.accept_observation(self.observe())
            events = self.audit()
            if drained is not None:
                require(all(row["id"] in drained or row["event_type"] == LEASE for row in events),
                    "new non-lease event appeared after complete drained publish checkpoint")
            complete, evidence = self.validate_audits(events)
            if complete and self.audit_drained():
                if drained is not None:
                    return evidence
                drained = dict(self.cutoff)
            time.sleep(min(0.1, self.timeout()))

    def client(self, spec, app, token):
        raw = run_client(spec, app["id"], token, self.run_id, min(25, self.deadline - time.monotonic()))
        self.clean(raw); result = json.loads(raw)
        require(result.get("schema") == "serverware.privateNpmPublishClient/v1" and result.get("ok") is True
            and result.get("phase") == spec["case"] and result.get("npmVersion") == "11.8.0"
            and result.get("pacoteVersion") == "21.0.4" and result.get("registryFetchVersion") == "19.1.1"
            and all(result.get(key) is True for key in ("strictSSL", "extraCaPreservesDefaultRoots", "isolatedCache"))
            and all(result.get(key) is False for key in ("requestRewrite", "force", "dryRun", "provenance"))
            and type(result.get("configuredRetries")) is int and result["configuredRetries"] == 0,
            "stock publish client receipt differs")
        if spec["success"]:
            require(result.get("package") == spec["package"] and result.get("version") == spec["version"]
                and result.get("tarballSha256") == digest(fixture.tarball(spec)), "npm publish tarball receipt differs")
        else:
            require(result.get("refused") is True, "negative stock npm publish was not refused")
        self.clients.append(result)
        return result

    def run(self):
        self.health(); self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        require(initial["revision"] == 1 and all(not initial[key] and initial["limits"][key]["retained"] == 0 for key in COLLECTIONS)
            and self.observe()["total"] == 0, "fresh unused npm publish catalog required")
        capability = initial.get("capabilities", {}).get("npm_publish", {})
        require(capability.get("schema") == "serverware.operatorNpmPublish/v1"
            and capability.get("destination_allowed") is True and capability.get("read_metadata_included") is True
            and capability.get("operation_bundles") == ["npm_publish_v1"] and capability.get("registry_origin") == fixture.ORIGIN,
            "paired npm publish capability unavailable")
        self.policy_hash = initial["policy"]["policy_hash"]
        credential, _, _ = self.mutate("/credentials/npm-token", {"name": self.run_id + "-npm", "secret": self.credential},
            collection="credentials", result_key="credential", event="operator_catalog.credential.npm_token_created", creates=True)
        self.credential_id = credential["id"]
        require(credential.get("credential_generation") == 1, "npm credential generation differs")
        window = closed_window(datetime.now(timezone.utc))
        apps, rules = {}, {}
        for name, package in (("prerequisite", fixture.PACKAGES[0]), ("unscoped", fixture.PACKAGES[0]),
                ("scoped", fixture.PACKAGES[1]), ("outside_window", fixture.PACKAGES[0])):
            app, token, _ = self.mutate("/applications", {"name": self.run_id + "-" + name, "token_lifetime_seconds": 3600,
                "proxy_authentication": "basic_and_bearer_v1"}, collection="applications", result_key="application",
                event="operator_catalog.application.created", creates=True, token=True)
            apps[name] = (app, token)
            common = {"name": self.run_id + "-" + name, "application_id": app["id"], "credential_id": self.credential_id}
            if name == "prerequisite":
                route, payload, event = "/access-rules/npm-metadata", {**common, "operation_bundle": "npm_metadata_read_v1", "packages": [package]}, "npm_metadata_created"
            else:
                route, payload, event = "/access-rules/npm-publish", {**common, "operation_bundle": "npm_publish_v1", "package": package,
                    "tag": fixture.TAG, "publishing_window": window if name == "outside_window" else None}, "npm_publish_created"
            rule, _, _ = self.mutate(route, payload, collection="access_rules", result_key="access_rule",
                event="operator_catalog.access_rule." + event, creates=True, authority_changed=True)
            rules[name] = rule
        self.wait_catalog_loaded("publish-fixture-ready")
        pins = self.warm_cas_snapshot()
        require([len(pins[key]) for key in COLLECTIONS] == [1, 4, 4], "publish fixture resource inventory differs")
        while not self.audit_drained():
            time.sleep(min(0.1, self.timeout()))
        self.baseline = self.cutoff = features.audit_cutoff(self.audit())
        for spec in fixture.SPECS:
            phase = spec["case"]
            selected = "unscoped" if phase in {"wrong_package", "wrong_placeholder"} else "scoped" if phase == "revoked_app" else phase
            app, token = apps[selected]; rule = rules[selected]
            if phase == "revoked_app":
                self.before_revoke_policy = self.policy_hash
                self.mutate("/applications/revoke", {"id": app["id"]}, collection="applications", result_key="application",
                    event="operator_catalog.application.revoked", authority_changed=True)
                self.revocation = self.mutations[-1]
                self.wait_catalog_loaded("publish-application-revoked")
                pins = self.warm_cas_snapshot()
                require(self.resource(pins, "applications", app["id"])["status"] == "revoked"
                    and self.resource(pins, "access_rules", rule["id"])["status"] == "revoked",
                    "publish application and paired permission did not revoke together")
            self.unchanged(pins)
            route_scopes = {"GET": (app["principal_id"], rule["route_id"] + ("" if phase == "prerequisite" else ".metadata"), self.policy_hash)}
            if phase != "prerequisite":
                route_scopes["PUT"] = (app["principal_id"], rule["route_id"], self.policy_hash)
            self.phase_scopes.append({"phase": phase, "principal": app["principal_id"], "policy": self.policy_hash, "routes": route_scopes})
            self.expected_denial_rows += expected_denials(phase, app, rule)
            self.client(spec, app, token); self.completed.append(phase)
            evidence = self.checkpoint(); self.unchanged(pins)
        stored = self.accept_observation(self.observe())
        require(len(stored) == 2 and len(self.wire) == 6, "final publication inventory differs")
        verified = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(verified.get("ok") is True and verified.get("complete") is True and verified.get("backend") == "sqlite",
            "npm publish durable audit chain incomplete")
        return {"ok": True, "schema": "serverware.privateNpmPublishCheck/v1", "syntheticOnly": True,
            "productionReady": False, "realNpmVerified": False, "npmInstallVerified": False,
            "npmVersion": "11.8.0", "pacoteVersion": "21.0.4", "registryFetchVersion": "19.1.1",
            "dataPlaneBinaryDigest": self.args.expected_binary_sha256, "stockClientTransports": True,
            "configuredRetries": 0, "commandRetries": 0, "defaultRetryBehaviorVerified": False,
            "clientCommands": 7, "providerAttempts": 6, "prerequisiteMetadataReleases": 4, "storedPublications": stored,
            "unauthorizedPuts": 0, "publishingWindowUtc": window, "auditChainVerified": True,
            "allParsedUpstreamHeadersValidated": True, "hiddenWireHeaderProof": False, "publicDnsVerified": False,
            "clients": self.clients, "requests": self.wire, "catalogMutations": self.mutations, **evidence}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "proxy-ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file", "run-claim-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--upstream-address"); parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args(); check = None
    def expired(*_):
        raise CheckFailure("private npm publish deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    try:
        require(30 <= args.timeout_seconds <= 180 and SHA256.fullmatch(args.expected_binary_sha256), "publish checker bounds invalid")
        signal.alarm(args.timeout_seconds); claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = NpmPublishCheck(args); result = check.run(); check.clean(json.dumps(result).encode())
    except Exception as error:
        result = {"ok": False, "syntheticOnly": True, "productionReady": False,
            "error": str(error) if isinstance(error, CheckFailure) else type(error).__name__,
            "completedClientPhases": [] if check is None else [row["phase"] for row in check.clients]}
        if isinstance(error, ClientFailure) and error.observation is not None:
            result["failedClient"] = error.observation
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True)); return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
