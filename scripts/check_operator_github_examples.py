#!/usr/bin/env python3
"""Execute the actual checked-in GitHub examples in the private HTTPS fixture.

Never launches a stack, installs dependencies, compiles Go, contacts GitHub, or
retries a command. The preparer/runner must pin the complete source, dependencies,
Go build receipt and all mounts. This checker pins the resulting Go executable;
its source hashes are observations, not a substitute for that build receipt.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
from urllib.parse import parse_qsl, urlsplit

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.check_operator_catalog import COLLECTIONS, claim_fixture, features
from scripts.check_operator_demo import SHA256, CheckFailure, require, token_file
from scripts.check_operator_github import GithubCheck, CONNECT_DENIED, KEEP_ALIVE
from scripts.check_operator_key_replacement import authority_projection
from scripts.check_operator_ordinary_client import BLOCK, CONNECT, DENIED, LEASE, RELEASE, RELOAD, START, digest
from scripts import operator_github_examples_fixture as fixture

SCHEMA = "serverware.privateGithubExamplesCheck/v1"
PHASES = ("wrong_app", "wrong_repo", "read")
COMMANDS = {
    "node": ("/node", "/app/examples/github-issues-node/client.mjs"),
    "python": ("/example-python/bin/python", "-I", "-B", "/app/examples/github-issues-python/issues.py"),
    "go": ("/example-go/github-issues",),
}
SOURCE_FILES = ("examples/github-issues-node/client.mjs", "examples/github-issues-node/package.json",
    "examples/github-issues-python/issues.py", "examples/github-issues-python/requirements.txt",
    "examples/github-issues-go/main.go", "examples/github-issues-go/go.mod")
ROW_KEYS = {"ordinal", "accepted", "client", "page", "method", "target", "semanticHeaders",
    "requestBodySha256", "responseBodySha256", "responseBodyBytes", "status",
    "providerCredentialMatched", "proxyAuthorizationPresent", "allParsedHeadersValidated"}


def expected_output(client):
    rows = [{"number": number, "title": "Fixture issue " + str(number)} for number in (11, 12)]
    if client == "node":
        return {"ok": True, "operation": "list", "issueCount": 2, "issues": rows}
    if client == "python":
        return [{**row, "state": "open"} for row in rows]
    require(client == "go", "unknown example client")
    return {"pages": 2, "issues": 2, "pull_requests": 0}


def client_environment(client, application, token, *, wrong_repo=False):
    require(client in fixture.CLIENTS, "unknown example client")
    env = {"LANG": "C.UTF-8", "SERVERWARE_PROXY_URL": "https://proxy.operator-basic.example.test:8443",
        "SERVERWARE_APP_ID": application, "SERVERWARE_PROXY_TOKEN": token,
        "SERVERWARE_GITHUB_OWNER": fixture.OWNER,
        "SERVERWARE_GITHUB_REPO": "other-repo" if wrong_repo else fixture.REPO,
        "SERVERWARE_CA_FILE": "/client-trust/requests-ca.pem" if client == "python" else "/client-trust/inner-ca.pem"}
    if client != "python":
        env["SERVERWARE_PROXY_CA_FILE"] = "/client-trust/outer-ca.pem"
    return env


def _child_exit_status(process):
    """Observe ONLY our child without reaping its process-group identity.

    Linux WNOWAIT retains the exited leader as our child until cleanup. In
    particular, do not replace this with Popen.poll()/wait(): either can release
    its PID while descendants still hold the group's stdout/stderr pipes.
    """
    require(type(process.pid) is int and process.pid > 1 and process.returncode is None,
        "example child ownership unavailable")
    try:
        result = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        raise CheckFailure("example child ownership unavailable") from None
    if result is None:
        return None
    require(result.si_pid == process.pid and result.si_code in {os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED},
        "example child exit observation invalid")
    return result.si_status if result.si_code == os.CLD_EXITED else -result.si_status


def _cleanup_example_group(process):
    """Stop the exact fresh session while its leader PID is still reserved."""
    _child_exit_status(process)  # ECHILD refuses signaling, never adopts a PID.
    try:
        require(os.getpgid(process.pid) == process.pid == os.getsid(process.pid)
            and process.pid != os.getpgrp(), "example process group ownership differs")
    except ProcessLookupError:
        raise CheckFailure("example process group ownership unavailable") from None
    try:
        # Also kill descendants after the leader has exited. WNOWAIT above and
        # no intervening reap keep this ID reserved until the bounded wait below.
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        # The owned leader can be a zombie with no remaining live group member.
        # No child has been reaped, so this cannot refer to a recycled group.
        pass
    process.wait(timeout=2)


def run_example(client, environment, seconds):
    """Bound the real entrypoint and its children; never return raw diagnostics."""
    require(client in COMMANDS and 0 < seconds <= 70, "example deadline invalid")
    deadline = time.monotonic() + seconds
    process = subprocess.Popen(COMMANDS[client], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
        close_fds=True, start_new_session=True)
    output = {"out": bytearray(), "err": bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for stream, key in ((process.stdout, "out"), (process.stderr, "err")):
                selector.register(stream, selectors.EVENT_READ, key)
            while selector.get_map():
                require(time.monotonic() < deadline, "example process deadline exceeded")
                for key, _ in selector.select(min(0.1, max(0.001, deadline - time.monotonic()))):
                    chunk = os.read(key.fd, 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output[key.data].extend(chunk)
                        require(len(output[key.data]) <= (65536 if key.data == "out" else 8192),
                            "example output bound exceeded")
        while True:
            code = _child_exit_status(process)
            if code is not None:
                return code, bytes(output["out"]), bytes(output["err"])
            require(time.monotonic() < deadline, "example process deadline exceeded")
            time.sleep(min(0.01, max(0.001, deadline - time.monotonic())))
    finally:
        try:
            _cleanup_example_group(process)
        finally:
            for stream in (process.stdout, process.stderr):
                stream.close()


def validate_row(row, ordinal, client, page):
    require(isinstance(row, dict) and set(row) == ROW_KEYS
        and type(row["ordinal"]) is int and row["ordinal"] == ordinal
        and row["accepted"] is True and row["client"] == client and row["page"] == page
        and type(row["page"]) is int and row["method"] == "GET"
        and row["target"] == fixture.target(client, page)
        and row["providerCredentialMatched"] is True and row["proxyAuthorizationPresent"] is False
        and row["allParsedHeadersValidated"] is True and type(row["status"]) is int and row["status"] == 200
        and row["requestBodySha256"] == digest(b"")
        and row["responseBodySha256"] == digest(fixture.body(page))
        and type(row["responseBodyBytes"]) is int and row["responseBodyBytes"] == len(fixture.body(page)),
        "example provider observation differs")
    headers = row["semanticHeaders"]
    require(isinstance(headers, dict) and all(type(k) is str and type(v) is str for k, v in headers.items()),
        "example header observation malformed")
    admitted = fixture.validated_headers(client, list(headers.items()) +
        [("host", "api.github.com"), ("authorization", "Bearer " + fixture.TOKEN)])
    require(admitted == headers, "example header observation not closed")


def canonical_digests(row, scope, credential_id, peer):
    """Independent canonical-v3 reconstruction from closed, observed wire fields."""
    parts = urlsplit(fixture.ORIGIN + row["target"])
    canonical = {"v": 3, "principal": scope[0], "client_ip": peer, "route_id": scope[1],
        "credential_ref": credential_id, "credential_version": "1", "policy_hash": scope[2],
        "request": {"method": "GET", "scheme": "https", "authority": "api.github.com", "path": parts.path,
            "query": [list(pair) for pair in parse_qsl(parts.query, keep_blank_values=True,
                encoding="utf-8", errors="strict")], "query_wire": parts.query, "query_mode": "githubRestV1",
            "headers": {"host": "api.github.com", **row["semanticHeaders"]},
            "body_sha256": digest(b""), "discard_headers": ["accept-encoding"]},
        "operation": {"operation": "github.issues.read"}}
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return digest(encode(canonical)), digest(encode({k: v for k, v in canonical.items() if k not in {"v", "client_ip"}}))


class ExamplesCheck(GithubCheck):
    def __init__(self, args):
        super().__init__(args)  # Preserves exact private-network, binary and HTTPS admission.
        require(re.fullmatch(r"[0-9a-f]{64}", args.expected_go_sha256) is not None,
            "compiled example pin missing")
        go = Path(COMMANDS["go"][0])
        require(go.is_file() and not go.is_symlink() and go.stat().st_size <= 64 * 1024**2
            and hashlib.sha256(go.read_bytes()).hexdigest() == args.expected_go_sha256,
            "compiled Go example differs")
        self.example_sources = {}
        for name in SOURCE_FILES:
            path = Path("/app") / name
            require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 256 * 1024,
                "checked-in example source missing")
            self.example_sources[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        # Existing offline PKI emits this exact public-only union. The Python
        # launcher adds certifi roots itself; no SDK or trust-store patching.
        inner = Path("/client-trust/inner-ca.pem").read_bytes()
        outer = Path("/client-trust/outer-ca.pem").read_bytes()
        union = Path("/client-trust/requests-ca.pem").read_bytes()
        require(0 < len(inner) <= 65536 and 0 < len(outer) <= 65536 and inner != outer
            and union == outer + inner and len(union) <= 65536, "public client CA union differs")
        self.completed = []
        self.current_client, self.current_phase = None, None

    def observe(self):
        status, value = self.json_request(self.github, "/_fixture/observations", context=self.upstream_ca)
        require(status == 200 and isinstance(value, dict)
            and set(value) == {"schema", "syntheticOnly", "total", "attempts"}
            and value["schema"] == fixture.SCHEMA and value["syntheticOnly"] is True
            and type(value["total"]) is int and isinstance(value["attempts"], list)
            and value["total"] == len(value["attempts"]) <= fixture.MAX_ATTEMPTS,
            "example observations unavailable")
        return value

    def example(self, client, phase, app, token):
        self.current_client, self.current_phase = client, phase
        code, stdout, stderr = run_example(client, client_environment(client, app["id"], token,
            wrong_repo=phase == "wrong_repo"), min(70, self.deadline - time.monotonic()))
        self.clean(stdout); self.clean(stderr)
        if phase == "read":
            require(code == 0 and not stderr, "checked-in example failed")
            actual = json.loads(stdout)
            require(json.dumps(actual, sort_keys=True) == json.dumps(expected_output(client), sort_keys=True),
                "checked-in example output differs")
        else:
            require(code == 1, "stock example did not fail closed")
        self.completed.append({"client": client, "phase": phase, "exitCode": code})

    def denied_checkpoint(self, baseline, phase):
        while True:
            events = self.audit(); cutoff = features.audit_cutoff(events)
            require(all(cutoff.get(key) == value for key, value in baseline.items()), "negative audit prefix changed")
            rows = [row for row in events if row["id"] not in baseline]
            require(self.count() == 0 and not any(row["event_type"] in {START, RELEASE, BLOCK}
                or row["event_type"] == LEASE and row["event"].get("purpose") == "dispatchSecret" for row in rows),
                "denied example reached provider or credential dispatch")
            counts = Counter(row["event_type"] for row in rows)
            expected = CONNECT_DENIED if phase == "wrong_app" else DENIED
            require(counts[expected] <= 1 and counts[DENIED if phase == "wrong_app" else CONNECT_DENIED] == 0,
                "negative example attempted extra requests")
            for row in rows:
                if row["event_type"] == expected:
                    event = row["event"]
                    require(event.get("outcome") == "denied" and event.get("method") ==
                        ("CONNECT" if phase == "wrong_app" else "GET"), "negative example audit kind differs")
                    if phase == "wrong_app":
                        require(event.get("target") == "api.github.com:443" and event.get("principal_id") is None,
                            "unassigned application was not refused at CONNECT")
            if counts[expected] == 1 and self.audit_drained():
                return cutoff
            time.sleep(min(0.1, self.timeout()))

    def verify_audits(self, baseline, scope, credential_id):
        expected = {(row["requestDigest"], row["operationDigest"]): row for row in self.wire}
        require(len(expected) == 6, "six distinct example requests required")
        while True:
            events = self.audit(); cutoff = features.audit_cutoff(events)
            require(all(cutoff.get(k) == v for k, v in baseline.items()), "example audit prefix changed")
            rows = [row for row in events if row["id"] not in baseline]
            counts = Counter(row["event_type"] for row in rows)
            exact = Counter(kind for kind, _, _ in self.mutations)
            exact.update({START: 6, RELEASE: 6, DENIED: 3, CONNECT_DENIED: 3, RELOAD: 1})
            require(set(counts) <= set(exact) | {CONNECT, KEEP_ALIVE, LEASE}
                and all(counts[k] <= v for k, v in exact.items()) and counts[CONNECT] <= 9
                and counts[KEEP_ALIVE] <= 3 and counts[LEASE] <= 64,
                "unexpected example audit inventory")
            pairs = {}; dispatches = 0
            for row in rows:
                kind, event = row["event_type"], row["event"]
                if kind in {START, RELEASE}:
                    key = event.get("request_digest"), event.get("operation_digest")
                    require(key in expected and tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash")) == scope
                        and event.get("credential_ref") == credential_id and type(event.get("credential_version")) is int
                        and event["credential_version"] == 1 and event.get("method") == "GET"
                        and event.get("body_sha256") == digest(b""), "example audit does not match request authority")
                    attempt = event.get("attempt_id")
                    require(isinstance(attempt, str) and SHA256.fullmatch(attempt)
                        and event.get("flow_id") == attempt, "example attempt identity missing")
                    pair = pairs.setdefault(key, {"attempt": attempt})
                    slot = "start" if kind == START else "release"
                    require(slot not in pair and pair["attempt"] == attempt, "example attempt duplicated")
                    pair[slot] = row["id"]
                    if kind == START:
                        require(event.get("outcome") == "release_started", "example release start differs")
                    else:
                        validation = event.get("response_validation", {})
                        require(event.get("outcome") == "released" and event.get("upstream_status") == 200
                            and event.get("response_body_sha256") == expected[key]["responseBodySha256"]
                            and event.get("response_body_bytes") == expected[key]["responseBodyBytes"]
                            and validation.get("ok") is True and validation.get("body_bytes_preserved") is True
                            and validation.get("mode") == "bufferedJsonOrEmpty204V2", "example response release differs")
                elif kind == LEASE:
                    require(event.get("outcome") == "issued" and event.get("status_code") == 200
                        and tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash")) == scope
                        and event.get("credential_id") == credential_id
                        and event.get("data_plane_binary_digest") == self.args.expected_binary_sha256
                        and event.get("purpose") in {"generationMetadata", "dispatchSecret"}, "example credential lease differs")
                    if event["purpose"] == "dispatchSecret":
                        require(event.get("expected_credential_version") == 1, "example dispatch generation differs")
                        dispatches += 1
                elif kind in {CONNECT, KEEP_ALIVE}:
                    require(event.get("target") == "api.github.com:443" and event.get("principal_id") == scope[0]
                        and event.get("policy_hash") == scope[2], "example CONNECT authority differs")
                elif kind == RELOAD:
                    require(event.get("previous_policy_hash") == self.initial_policy_hash
                        and event.get("policy_hash") == scope[2] and event.get("routes") == 1,
                        "example policy reload differs")
            mutations = {(r["event_type"], r["event"].get("resource_id"), r["event"].get("policy_hash")) for r in rows}
            require(len({p["attempt"] for p in pairs.values()}) == len(pairs), "example attempt reused")
            if (all(counts[k] == v for k, v in exact.items()) and len(pairs) == 6 and dispatches >= 1
                    and all({"start", "release"} <= p.keys() for p in pairs.values())
                    and set(self.mutations) <= mutations and self.audit_drained()):
                break
            time.sleep(min(0.1, self.timeout()))
        require(features.audit_cutoff(self.audit()) == cutoff, "example audit changed after drain")
        verified = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(verified.get("ok") is True and verified.get("complete") is True, "example audit chain incomplete")
        return {"namedAuditInventory": dict(sorted(counts.items())),
            "auditAttemptIds": sorted(p["attempt"] for p in pairs.values())}

    def run(self):
        self.health(); self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        require(initial["revision"] == self.args.expected_initial_revision
            and all(not initial[key] and initial["limits"][key]["retained"] == 0 for key in COLLECTIONS)
            and self.count() == 0, "fresh pinned example catalog required")
        require(initial.get("capabilities", {}).get("github", {}).get("destination_allowed") is True,
            "GitHub catalog capability unavailable")
        self.policy_hash = self.initial_policy_hash = initial["policy"]["policy_hash"]
        self.wait_catalog_loaded("initial")
        while not self.audit_drained():
            time.sleep(min(0.1, self.timeout()))
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
        rule, _, _ = self.mutate("/access-rules/github", {"name": self.run_id + "-read", "application_id": app["id"],
            "credential_id": credential["id"], "operation_bundle": "github_issues_read_v1",
            "repository": {"owner": fixture.OWNER, "name": fixture.REPO}}, collection="access_rules", result_key="access_rule",
            event="operator_catalog.access_rule.github_created", creates=True, authority_changed=True)
        self.wait_catalog_loaded("assigned")
        pins = self.warm_cas_snapshot(); scope = app["principal_id"], rule["route_id"], self.policy_hash
        while not self.audit_drained():
            time.sleep(min(0.1, self.timeout()))
        previous = features.audit_cutoff(self.audit())
        for client in fixture.CLIENTS:
            for phase in ("wrong_app", "wrong_repo"):
                self.unchanged(pins)
                self.example(client, phase, *(apps[1] if phase == "wrong_app" else apps[0]))
                previous = self.denied_checkpoint(previous, phase)
        for client in fixture.CLIENTS:
            self.unchanged(pins)
            self.example(client, "read", app, token)
            observed = self.observe()["attempts"]
            first = len(self.wire)
            require(len(observed) == first + 2, "example made extra or missing provider requests")
            for page, row in enumerate(observed[first:], 1):
                validate_row(row, first + page, client, page)
                request_digest, operation_digest = canonical_digests(row, scope, credential["id"], self.proxy.address)
                self.wire.append({"client": client, "page": page, "requestDigest": request_digest,
                    "operationDigest": operation_digest, "responseBodySha256": row["responseBodySha256"],
                    "responseBodyBytes": row["responseBodyBytes"]})
        evidence = self.verify_audits(baseline, scope, credential["id"])
        require(self.count() == 6 and authority_projection(self.warm_cas_snapshot()) == authority_projection(pins),
            "example job changed provider count or saved authority")
        return {"schema": SCHEMA, "ok": True, "syntheticOnly": True, "realGithubVerified": False,
            "productionReady": False, "publicDnsVerified": False,
            "actualExampleEntrypoints": True, "providerAttempts": 6, "releases": 6,
            "deniedBeforeDispatch": 6, "dataPlaneBinaryDigest": self.args.expected_binary_sha256,
            "goExampleSha256": self.args.expected_go_sha256, "exampleSourceSha256": self.example_sources,
            "pythonTrust": "client-only-union-not-independent-roots", "completed": self.completed,
            "requests": self.wire, **evidence}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256", "expected-go-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "proxy-ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file", "run-claim-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--upstream-address")
    parser.add_argument("--expected-initial-revision", type=int, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args(); check = None
    def expired(*_):
        raise CheckFailure("private examples checker deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    try:
        require(30 <= args.timeout_seconds <= 180 and SHA256.fullmatch(args.expected_binary_sha256)
            and 1 <= args.expected_initial_revision <= 3, "example checker bounds invalid")
        signal.alarm(args.timeout_seconds)
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = ExamplesCheck(args)
        result = check.run()
        check.clean(json.dumps(result).encode())
    except Exception:
        result = {"schema": SCHEMA, "ok": False, "syntheticOnly": True, "productionReady": False,
            "error": "checked-in GitHub example acceptance failed",
            "client": check.current_client if check is not None and check.current_client in fixture.CLIENTS else None,
            "phase": check.current_phase if check is not None and check.current_phase in PHASES else None,
            "completed": check.completed if check is not None else []}
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
