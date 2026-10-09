#!/usr/bin/env python3
"""One-shot private stock @octokit/rest acceptance. Never launches a stack.

Only the synthetic named repository is used. The real catalog, signed policy,
normal Rust gate, verified outer/inner TLS and unmodified SDK request builders
participate. No live provider, token discovery, mutation retry, or SDK retry
plugin. The fixture/recipe, not public DNS, establishes private containment.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
from urllib.parse import parse_qsl, urlsplit

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.check_operator_catalog import COLLECTIONS, PREFIX, claim_fixture, features
from scripts.check_operator_demo import SHA256, CheckFailure, Endpoint, require, token_file
from scripts.check_operator_key_replacement import authority_projection
from scripts.check_operator_ordinary_client import BLOCK, CONNECT, DENIED, LEASE, RELEASE, RELOAD, START, OrdinaryClientCheck, digest
from scripts import operator_github_fixture as fixture
from scripts import operator_github_fixture_network as isolated

PROXY = "https://proxy.operator-basic.example.test:8443"
CONNECT_DENIED, KEEP_ALIVE = "data_plane.connect.denied", "data_plane.connect.keep_alive"
NEGATIVES = ("wrong_app", "wrong_repo", "wrong_dummy", "numeric")
SDK_PHASES = frozenset((*NEGATIVES, "job", *fixture.BLOCK_CASES))
SDK_STAGES = frozenset(("initializing", "pagination", "read_issue", "read_comments", "read_comment",
    "create_issue", "create_comment", "not_found", "rate_limit", "final_checks", "negative"))
NODE_SHA256 = "3dc3f85ca5539ca81b7d106992ebcd82d09bce27326016873653a661ad6b2a7d"


def run_sdk(phase, application, token, run_id, seconds):
    require(phase in SDK_PHASES and 0 < seconds <= 70, "SDK phase or deadline invalid")
    payload = json.dumps({"phase": phase, "applicationId": application, "token": token, "runId": run_id}).encode()
    deadline = time.monotonic() + seconds
    process = subprocess.Popen(["/node", "/app/scripts/operator_github_job.mjs"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"LANG": "C.UTF-8"}, close_fds=True)
    output = {"out": bytearray(), "err": bytearray()}
    try:
        process.stdin.write(payload); process.stdin.close()
        with selectors.DefaultSelector() as selector:
            for stream, name in ((process.stdout, "out"), (process.stderr, "err")):
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                require(time.monotonic() < deadline, "SDK process deadline exceeded")
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fd, 16384)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output[key.data].extend(chunk)
                        require(len(output[key.data]) <= (262144 if key.data == "out" else 8192), "SDK output bound exceeded")
        code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if code != 0 or output["err"]:
            stage = None
            try:
                failure = json.loads(output["out"])
                if (isinstance(failure, dict) and failure.get("schema") == "serverware.privateGithubSdk/v1"
                        and failure.get("ok") is False and failure.get("phase") == phase
                        and failure.get("stage") in SDK_STAGES):
                    stage = failure["stage"]
            except (ValueError, TypeError):
                pass
            raise CheckFailure("stock SDK process failed: " + phase + "/" + (stage or "unknown")
                               + "; raw error suppressed")
        return bytes(output["out"])
    finally:
        if process.poll() is None:
            process.kill(); process.wait(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def canonical_digests(row, scope, credential_id, peer):
    """Independent v3 recipe, joined to the fixture's actual raw target/body."""
    parts = urlsplit(fixture.ORIGIN + row["target"])
    headers = dict(row["clientHeaders"])
    require(set(headers) <= {"accept", "user-agent", "content-type", "x-github-api-version"}
        and headers.get("accept") == "application/vnd.github.v3+json", "SDK semantic headers differ")
    headers.update({"host": "api.github.com", "accept-language": "*", "sec-fetch-mode": "cors"})
    body = base64.b64decode(row["requestBodyBase64"], validate=True)
    if row["method"] == "POST":
        headers["content-length"] = str(len(body))
    canonical = {"v": 3, "principal": scope[0], "client_ip": peer, "route_id": scope[1],
        "credential_ref": credential_id, "credential_version": "1", "policy_hash": scope[2],
        "request": {"method": row["method"], "scheme": "https", "authority": "api.github.com", "path": parts.path,
            "query": [list(pair) for pair in parse_qsl(parts.query, keep_blank_values=True, encoding="utf-8", errors="strict")],
            "query_wire": parts.query if "?" in row["target"] else None, "query_mode": "githubRestV1",
            "headers": headers, "body_sha256": digest(body), "discard_headers": ["accept-encoding"]},
        "operation": {"operation": "github.issues.write"}}
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return digest(encode(canonical)), digest(encode({key: value for key, value in canonical.items() if key not in {"v", "client_ip"}}))


class GithubCheck(OrdinaryClientCheck):
    def __init__(self, args):
        # This guard precedes inherited endpoint resolution and every HTTP/SDK
        # operation. The public-looking provider address is local to this netns.
        isolated.assert_isolated_network()
        require(args.control_base == "http://serverware:3000" and args.management_base == "http://127.0.0.1:9091"
            and args.proxy_url == PROXY and args.upstream_address is None,
            "fixed isolated GitHub endpoints required")
        # The inherited unused demo endpoint is only constructed, never called.
        super().__init__(argparse.Namespace(**{**vars(args), "upstream_address": isolated.LOOPBACK}))
        self.credential = fixture.TOKEN
        require(args.proxy_url == PROXY and Path("/node").is_file()
            and hashlib.sha256(Path("/node").read_bytes()).hexdigest() == NODE_SHA256,
            "private HTTPS proxy or pinned Node differs")
        require(self.control.address == self.management.address == self.proxy.address == isolated.LOOPBACK,
                "isolated control/proxy/actual relay peer differs")
        self.github = Endpoint(fixture.ORIGIN, address=isolated.LOOPBACK)
        self.github.address = isolated.FIXTURE_IP
        self.wire = []
        self.negative_cutoffs = []

    def catalog(self):
        value = self.control_json(PREFIX + "/catalog", authenticated=True)
        require(value.get("schema") == "serverware.operatorCatalog/v1" and value.get("mode") == "operator-development"
            and value.get("productionReady") is False and value.get("hardwareVerified") is False
            and value.get("allowed_upstreams") == [fixture.ORIGIN]
            and type(value.get("revision")) is int and all(isinstance(value.get(key), list) for key in COLLECTIONS),
            "fresh synthetic GitHub catalog contract differs")
        policy = value.get("policy", {})
        require(SHA256.fullmatch(policy.get("policy_hash", "")) and type(policy.get("sequence")) is int,
            "GitHub signed policy unavailable")
        self.snapshot = value
        return value

    def observe(self):
        status, value = self.json_request(self.github, "/_fixture/observations", context=self.upstream_ca)
        require(status == 200 and value.get("schema") == fixture.SCHEMA and value.get("syntheticOnly") is True
            and type(value.get("total")) is int and isinstance(value.get("attempts"), list)
            and value["total"] == len(value["attempts"]) <= fixture.MAX_ATTEMPTS, "bounded provider observations unavailable")
        return value

    def count(self):
        return self.observe()["total"]

    def unchanged(self, pins):
        require(authority_projection(self.warm_cas_snapshot()) == authority_projection(pins), "catalog authority changed during SDK job")

    def sdk(self, phase, app, token):
        raw = run_sdk(phase, app["id"], token, self.run_id, min(70, self.deadline - time.monotonic()))
        self.clean(raw)
        value = json.loads(raw)
        require(value.get("ok") is True and value.get("schema") == "serverware.privateGithubSdk/v1"
            and value.get("phase") == phase and value.get("package") == "@octokit/rest"
            and value.get("version") == "22.0.1" and value.get("undiciVersion") == "8.11.2"
            and value.get("retryPlugin") is False and value.get("requestRewrite") is False,
            "stock SDK did not complete its finite operation")
        for observation in value.get("observations", []):
            self.clean(base64.b64decode(observation["responseBodyBase64"], validate=True))
            self.clean(json.dumps(observation["headers"]).encode())
        return value

    def checkpoint(self, baseline, phase, denied_count):
        while True:
            events = self.audit(); cutoff = features.audit_cutoff(events)
            require(all(cutoff.get(key) == value for key, value in baseline.items()), "baseline audit changed")
            rows = [row for row in events if row["id"] not in baseline]
            require(self.count() == 0 and not any(row["event_type"] in {LEASE, START, RELEASE, BLOCK} for row in rows),
                "denied SDK request reached provider or credential release")
            counts = Counter(row["event_type"] for row in rows)
            require(counts[CONNECT_DENIED] <= 1 and counts[DENIED] <= denied_count, "extra denial attempt detected")
            if counts[CONNECT_DENIED] == 1 and counts[DENIED] == denied_count and self.audit_drained():
                self.negative_cutoffs.append(cutoff)
                self.negative_observations.append({"case": phase, "providerAttempts": 0, "leaseEvents": 0})
                return
            time.sleep(min(0.1, self.timeout()))

    def accept_wire(self, rows, cases, scope, credential_id):
        require(len(rows) == len(cases), "SDK attempted an unexpected number of requests")
        for row, case in zip(rows, cases):
            spec = fixture.SPECS[case]
            require((row["method"], row["target"]) == (spec["method"], spec["target"])
                and base64.b64decode(row["requestBodyBase64"], validate=True) == spec["request"]
                and row["requestBodySha256"] == digest(spec["request"]), "stock SDK changed fixed raw query or body")
            request_digest, operation_digest = canonical_digests(row, scope, credential_id, self.proxy.address)
            body = base64.b64decode(row["responseBodyBase64"], validate=True)
            self.clean(body)
            headers = row["headers"]
            self.clean(json.dumps(headers).encode())
            if case in fixture.BLOCK_CASES:
                require(row["status"] == 502 and json.loads(body).get("error") == "github_response_link_denied",
                    "hostile pagination link was not blocked before SDK follow")
            else:
                require(row["status"] == spec["status"] and body == spec["body"]
                    and headers.get("x-serverware-policy-hash") == self.policy_hash
                    and headers.get("x-serverware-response-body-sha256") == digest(body)
                    and headers.get("x-serverware-request-digest") == request_digest
                    and headers.get("x-serverware-operation-digest") == operation_digest,
                    "SDK response bytes/status/canonical-v3 commitments differ")
                require(headers.get("x-github-request-id") == "fixture:" + case
                    and headers.get("x-ratelimit-limit") == "5000" and headers.get("x-ratelimit-resource") == "core"
                    and headers.get("x-ratelimit-remaining") == ("0" if case == "rate_limit" else "4999")
                    and headers.get("x-ratelimit-reset") == "2000000000" and headers.get("x-ratelimit-used") == "1"
                    and "etag" not in headers and "content-encoding" not in headers,
                    "selected GitHub rate metadata or discard differs")
                expected_link = f'<{fixture.ORIGIN}{fixture.BASE}?{fixture.QUERY2}>; rel="next"' if case == "page1" else None
                require(headers.get("link") == expected_link and headers.get("retry-after") == ("2" if case == "rate_limit" else None),
                    "GitHub normalized pagination or retry metadata differs")
            self.wire.append({"case": case, "method": row["method"], "target": row["target"],
                "requestDigest": request_digest, "operationDigest": operation_digest,
                "bodySha256": digest(spec["request"]), "upstreamStatus": spec["status"],
                "responseBodySha256": digest(spec["body"]), "responseBodyBytes": len(spec["body"])})

    def verify_audits(self, baseline, scope, credential_id):
        expected = {(item["requestDigest"], item["operationDigest"]): item for item in self.wire}
        require(len(expected) == 11, "SDK requests reused canonical commitments")
        while True:
            events = self.audit(); cutoff = features.audit_cutoff(events)
            require(all(cutoff.get(key) == value for prior in [baseline, *self.negative_cutoffs]
                        for key, value in prior.items()), "retained SDK audit prefix changed")
            rows = [row for row in events if row["id"] not in baseline]
            counts = Counter(row["event_type"] for row in rows)
            exact = Counter(kind for kind, _, _ in self.mutations)
            exact.update({START: 11, RELEASE: 9, BLOCK: 2, DENIED: 3, CONNECT_DENIED: 1, RELOAD: 1})
            require(set(counts) <= set(exact) | {CONNECT, KEEP_ALIVE, LEASE}
                and all(counts[key] <= count for key, count in exact.items())
                and counts[CONNECT] <= 14 and counts[KEEP_ALIVE] <= 8 and counts[LEASE] <= 22,
                "extra SDK audit event or retry detected")
            pairs = {}; dispatch_lease = False; intercepted = counts[CONNECT]
            for row in rows:
                kind, event = row["event_type"], row["event"]
                if kind in {START, RELEASE, BLOCK}:
                    key = (event.get("request_digest"), event.get("operation_digest"))
                    require(key in expected, "audit attempt does not join actual SDK request")
                    item = expected[key]; attempt = event.get("attempt_id")
                    require(SHA256.fullmatch(attempt or "") and event.get("flow_id") == attempt
                        and tuple(event.get(name) for name in ("principal_id", "route_id", "policy_hash")) == scope
                        and event.get("credential_ref") == credential_id and type(event.get("credential_version")) is int
                        and event["credential_version"] == 1 and event.get("method") == item["method"]
                        and event.get("body_sha256") == item["bodySha256"], "SDK audit authority or actual generation differs")
                    pair = pairs.setdefault(key, {"attempt": attempt})
                    slot = "start" if kind == START else "terminal"
                    require(slot not in pair and pair["attempt"] == attempt, "SDK audit attempt reused")
                    pair[slot] = row["id"]
                    if kind == START:
                        require(event.get("outcome") == "release_started", "release start outcome differs")
                    else:
                        validation = event.get("response_validation", {})
                        require(event.get("upstream_status") == item["upstreamStatus"], "provider response status audit differs")
                        if item["case"] in fixture.BLOCK_CASES:
                            require(kind == BLOCK and event.get("outcome") == "blocked" and validation.get("error") == "github_response_link_denied", "Link block audit differs")
                        else:
                            require(kind == RELEASE and event.get("outcome") == "released"
                                and event.get("response_body_sha256") == item["responseBodySha256"]
                                and event.get("response_body_bytes") == item["responseBodyBytes"]
                                and validation.get("ok") is True and validation.get("mode") == "bufferedJsonOrEmpty204V2"
                                and validation.get("body_bytes_preserved") is True, "whole JSON release audit differs")
                elif kind in {CONNECT, KEEP_ALIVE}:
                    require(event.get("target") == "api.github.com:443" and event.get("principal_id") == scope[0]
                        and event.get("policy_hash") == scope[2] and event.get("method") == "CONNECT"
                        and event.get("outcome") == ("established" if kind == CONNECT else "keep_alive"), "SDK CONNECT scope differs")
                    if kind == KEEP_ALIVE:
                        number = event.get("intercepted_request_count")
                        require(type(number) is int and 2 <= number <= 9, "SDK pooled connection inventory differs")
                        intercepted += number - 1
                elif kind == CONNECT_DENIED:
                    require(event.get("target") == "api.github.com:443" and event.get("method") == "CONNECT"
                        and event.get("outcome") == "denied" and event.get("principal_id") is None,
                        "wrong application was not denied at CONNECT authentication")
                elif kind == DENIED:
                    require(event.get("method") == "GET" and event.get("outcome") == "denied",
                        "request denial inventory differs")
                elif kind == LEASE:
                    require(tuple(event.get(name) for name in ("principal_id", "route_id", "policy_hash")) == scope
                        and event.get("credential_id") == credential_id and event.get("status_code") == 200
                        and event.get("data_plane_binary_digest") == self.args.expected_binary_sha256
                        and event.get("outcome") == "issued" and event.get("purpose") in {"generationMetadata", "dispatchSecret"}, "SDK lease scope differs")
                    if event["purpose"] == "dispatchSecret":
                        require(event.get("expected_credential_version") == 1, "SDK lease generation differs")
                        dispatch_lease = True
                elif kind == RELOAD:
                    require(event.get("previous_policy_hash") == self.initial_policy_hash and event.get("policy_hash") == scope[2]
                        and event.get("policy_sequence") == self.snapshot["policy"]["sequence"] and event.get("routes") == 1,
                        "GitHub reload not joined to sole rule")
            require(intercepted <= 14 and len({pair["attempt"] for pair in pairs.values()}) == len(pairs), "SDK hidden request or reused attempt")
            mutations = {(row["event_type"], row["event"].get("resource_id"), row["event"].get("policy_hash")) for row in rows}
            if (all(counts[key] == count for key, count in exact.items()) and intercepted == 14 and dispatch_lease
                    and set(self.mutations) <= mutations and len(pairs) == 11
                    and all({"start", "terminal"} <= pair.keys() for pair in pairs.values()) and self.audit_drained()):
                break
            time.sleep(min(0.1, self.timeout()))
        require(features.audit_cutoff(self.audit()) == cutoff, "SDK audit changed after terminal drain")
        verified = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(verified.get("ok") is True and verified.get("complete") is True, "SDK durable audit chain incomplete")
        return {"namedAuditInventory": dict(sorted(counts.items())), "auditAttemptIds": sorted(pair["attempt"] for pair in pairs.values())}

    def run(self):
        self.health(); self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        require(initial["revision"] == 1 and all(not initial[key] and initial["limits"][key]["retained"] == 0 for key in COLLECTIONS)
            and self.count() == 0, "fresh isolated catalog and unused provider fixture required")
        capability = initial.get("capabilities", {}).get("github")
        require(isinstance(capability, dict) and capability.get("destination_allowed") is True
            and capability.get("connection_type") == "github_token_v1", "paired GitHub catalog unavailable")
        self.policy_hash = self.initial_policy_hash = initial["policy"]["policy_hash"]
        self.wait_catalog_loaded("initial")
        while not self.audit_drained(): time.sleep(min(0.1, self.timeout()))
        baseline = features.audit_cutoff(self.audit())
        credential, _, _ = self.mutate("/credentials/github-token", {"name": self.run_id + "-github", "secret": self.credential},
            collection="credentials", result_key="credential", event="operator_catalog.credential.github_token_created", creates=True)
        apps = []
        for suffix in ("assigned", "unassigned"):
            app, token, _ = self.mutate("/applications", {"name": self.run_id + "-" + suffix,
                "token_lifetime_seconds": 3600, "proxy_authentication": "basic_and_bearer_v1"},
                collection="applications", result_key="application", event="operator_catalog.application.created", creates=True, token=True)
            apps.append((app, token))
        app, token = apps[0]
        rule, _, _ = self.mutate("/access-rules/github", {"name": self.run_id + "-issues", "application_id": app["id"],
            "credential_id": credential["id"], "operation_bundle": "github_issues_write_v1",
            "repository": {"owner": fixture.OWNER, "name": fixture.REPO}}, collection="access_rules", result_key="access_rule",
            event="operator_catalog.access_rule.github_created", creates=True, authority_changed=True)
        self.wait_catalog_loaded("assigned")
        pins = self.warm_cas_snapshot(); scope = (app["principal_id"], rule["route_id"], self.policy_hash)
        require([len(pins[key]) for key in COLLECTIONS] == [1, 2, 1] and credential.get("credential_generation") == 1,
            "GitHub saved resource inventory differs")
        for index, phase in enumerate(NEGATIVES):
            self.unchanged(pins)
            result = self.sdk(phase, *(apps[1] if phase == "wrong_app" else apps[0]))
            require(result.get("refused") is True and (phase == "wrong_app" or result.get("status") == 403), "SDK authority denial differs")
            self.checkpoint(baseline, phase, index)
        self.accept_wire(self.sdk("job", app, token)["observations"], fixture.RELEASE_CASES, scope, credential["id"])
        for phase in fixture.BLOCK_CASES:
            self.accept_wire(self.sdk(phase, app, token)["observations"], (phase,), scope, credential["id"])
        observed = self.observe()
        require(observed["total"] == 11 and [row["case"] for row in observed["attempts"]] == list(fixture.SPECS)
            and all(row["accepted"] is True and row["allParsedHeadersValidated"] is True
                and row["rawTarget"] == fixture.SPECS[row["case"]]["target"] for row in observed["attempts"]),
            "provider wire oracle found a retry, follow, mutation, header leak or changed target")
        evidence = self.verify_audits(baseline, scope, credential["id"])
        self.unchanged(pins)
        return {"ok": True, "schema": "serverware.privateGithubCheck/v1", "syntheticOnly": True, "productionReady": False,
            "realGithubVerified": False, "package": "@octokit/rest", "version": "22.0.1", "undiciVersion": "8.11.2",
            "dataPlaneBinaryDigest": self.args.expected_binary_sha256, "providerAttempts": 11, "releases": 9, "responseBlocks": 2,
            "deniedBeforeLease": 4, "canonicalRequestVersion": 3, "rawQueryAndBodyVerified": True,
            "fullJsonAndErrorMetadataVerified": True, "numericClientAuthority": False, "numericPaginationNormalized": True,
            "noRetryPlugin": True, "allParsedUpstreamHeadersValidated": True, "hiddenWireHeaderProof": False,
            "publicDnsVerified": False, "negativeControls": self.negative_observations, "requests": self.wire, **evidence}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "proxy-ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file", "run-claim-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--upstream-address")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args(); check = None
    def expired(*_): raise CheckFailure("private GitHub checker deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    try:
        require(30 <= args.timeout_seconds <= 180 and SHA256.fullmatch(args.expected_binary_sha256), "checker bounds invalid")
        signal.alarm(args.timeout_seconds)
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = GithubCheck(args); result = check.run()
        check.clean(json.dumps(result).encode())
    except Exception as error:
        safe = {}
        if check is not None:
            try:
                safe = features.safe_evidence(check)
                safe["completedSdkRequests"] = check.wire
            except Exception:
                safe = {"safeEvidenceUnavailable": True}
        result = {"ok": False, "syntheticOnly": True, "productionReady": False,
                  "error": str(error) if isinstance(error, CheckFailure) else type(error).__name__, **safe}
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
