#!/usr/bin/env python3
"""One-shot actual Node/Python/Go X examples through the private normal gate.

The root-owned fixture pins source, dependencies, Go build and actual Rust
binary. This checker never builds, installs, launches a stack or contacts X.
SDK success, raw protocol probes and synthetic receiver observations remain
separate evidence. All twenty proxy connections are finite and never retried.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import selectors
import signal
import ssl
import subprocess
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.check_operator_catalog import COLLECTIONS, PREFIX, OperatorCatalogCheck, claim_fixture, features
from scripts.check_operator_demo import SHA256, CheckFailure, Endpoint, TunnelTLS, require, token_file
from scripts.check_operator_github import NODE_SHA256, CONNECT_DENIED, KEEP_ALIVE
from scripts.check_operator_github_examples import _child_exit_status, _cleanup_example_group
from scripts.check_operator_key_replacement import authority_projection
from scripts.check_operator_ordinary_client import (
    BLOCK, CONNECT, DENIED, LEASE, RELEASE, RELOAD, START, CapturedTLS, OrdinaryClientCheck, digest,
)
from scripts import operator_x_examples_fixture as fixture
from scripts import operator_x_fixture_network as isolated

SCHEMA = "serverware.privateXExamplesCheck/v1"
PROXY = "https://proxy.operator-basic.example.test:8443"
DESCRIPTOR = {"schema": "serverware.operatorXAppReadGate/v1",
    "adapter": "x.app_read.v1", "operation": "x.username.read"}
COMMANDS = {
    "node": ("/node", "/app/examples/x-username-node/client.mjs"),
    "python": ("/example-python/bin/python", "-I", "-B", "/app/examples/x-username-python/username.py"),
    "go": ("/example-go/x-username",),
}
SOURCE_FILES = ("examples/x-username-node/client.mjs", "examples/x-username-node/package.json",
    "examples/x-username-node/package-lock.json", "examples/x-username-python/username.py",
    "examples/x-username-python/requirements.txt", "examples/x-username-go/main.go",
    "examples/x-username-go/go.mod", "examples/x-username-go/go.sum")
SDK_PHASES = ("read", "wrong_app", "wrong_username", "revoked")
REQUEST_PROBES = ("wrong_dummy", "wrong_method", "query")
RESPONSE_PROBES = ("error429", "oversize", "error-oversize", "reflection", "invalid-json")
BLOCK_ERRORS = {"oversize": "response_body_too_large", "error-oversize": "response_body_too_large",
    "reflection": "response_credential_reflection", "invalid-json": "response_invalid_json"}
RESULT_COUNTS = {"providerAttempts": 8, "releases": 4, "responseBlocks": 4,
    "deniedBeforeDispatch": 6, "requestProbeDenials": 3, "revokedGrantDenials": 3, "proxyConnections": 20}


def expected_output(client):
    if client == "node":
        return {"ok": True, "operation": "lookup-username", "username": fixture.USER["username"],
            "id": fixture.USER["id"]}
    if client == "python":
        return dict(fixture.USER)
    require(client == "go", "unknown X example client")
    return {"users": 1}


def client_environment(client, application, token, *, wrong_username=False):
    require(client in fixture.CLIENTS, "unknown X example client")
    return {"LANG": "C.UTF-8", "SERVERWARE_PROXY_URL": PROXY,
        "SERVERWARE_APP_ID": application, "SERVERWARE_PROXY_TOKEN": token,
        "SERVERWARE_X_USERNAME": "other_user" if wrong_username else fixture.USERNAME,
        "SERVERWARE_CA_FILE": "/client-trust/inner-ca.pem",
        "SERVERWARE_PROXY_CA_FILE": "/client-trust/outer-ca.pem"}


def run_example(client, environment, seconds):
    """Accepted child/session cleanup primitive, but the actual X entrypoints."""
    require(client in COMMANDS and 0 < seconds <= 70, "X example deadline invalid")
    deadline = time.monotonic() + seconds
    process = subprocess.Popen(COMMANDS[client], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
        close_fds=True, start_new_session=True)
    output = {"out": bytearray(), "err": bytearray()}
    try:
        with selectors.DefaultSelector() as selected:
            for stream, key in ((process.stdout, "out"), (process.stderr, "err")):
                selected.register(stream, selectors.EVENT_READ, key)
            while selected.get_map():
                require(time.monotonic() < deadline, "X example process deadline exceeded")
                for key, _ in selected.select(min(0.1, max(0.001, deadline - time.monotonic()))):
                    chunk = os.read(key.fd, 8192)
                    if not chunk:
                        selected.unregister(key.fileobj)
                    else:
                        output[key.data].extend(chunk)
                        require(len(output[key.data]) <= (65536 if key.data == "out" else 8192),
                            "X example output bound exceeded")
        while True:
            code = _child_exit_status(process)
            if code is not None:
                return code, bytes(output["out"]), bytes(output["err"])
            require(time.monotonic() < deadline, "X example process deadline exceeded")
            time.sleep(min(0.01, max(0.001, deadline - time.monotonic())))
    finally:
        try:
            _cleanup_example_group(process)
        finally:
            process.stdout.close()
            process.stderr.close()


def validate_row(row, ordinal, client, case):
    require(type(row) is dict and set(row) == fixture.ROW_KEYS
        and type(row["ordinal"]) is int and row["ordinal"] == ordinal
        and row["accepted"] is True and row["client"] == client and row["case"] == case
        and row["method"] == "GET" and row["target"] == fixture.TARGET
        and row["providerCredentialMatched"] is True and row["proxyAuthorizationPresent"] is False
        and row["allParsedHeadersValidated"] is True and type(row["status"]) is int
        and row["status"] == fixture.status(case) and row["requestBodySha256"] == digest(b"")
        and row["responseBodySha256"] == digest(fixture.body(case))
        and type(row["responseBodyBytes"]) is int and row["responseBodyBytes"] == len(fixture.body(case)),
        "X provider observation differs")
    headers = row["semanticHeaders"]
    require(type(headers) is dict and all(type(k) is str and type(v) is str for k, v in headers.items()),
        "X header observation malformed")
    admitted = fixture.validated_headers(client, list(headers.items()) +
        [("host", "api.x.com"), ("authorization", "Bearer " + fixture.TOKEN)], case=case)
    require(admitted == headers, "X header fingerprint is not closed")


def canonical_digests(row, scope, credential_id, peer):
    """Independent V2, empty query; no ordered-query mode or query-wire field."""
    canonical = {"v": 2, "principal": scope[0], "client_ip": peer, "route_id": scope[1],
        "credential_ref": credential_id, "credential_version": "1", "policy_hash": scope[2],
        "request": {"method": "GET", "scheme": "https", "authority": "api.x.com", "path": fixture.TARGET,
            "query": [], "headers": {"host": "api.x.com", **row["semanticHeaders"]},
            "body_sha256": digest(b""), "discard_headers": ["accept-encoding"]},
        "operation": {"operation": "x.username.read", "username": fixture.USERNAME}}
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return digest(encode(canonical)), digest(encode({k: v for k, v in canonical.items() if k not in {"v", "client_ip"}}))


class XTunnel(TunnelTLS):
    """The existing bounded TLS-over-TLS implementation with fixed X SNI."""
    def __init__(self, raw, context, timeout):
        io.RawIOBase.__init__(self)
        self.raw, self.timeout = raw, timeout
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_hostname="api.x.com")
        self._perform(self.tls.do_handshake)


class ExamplesCheck(OperatorCatalogCheck):
    audit_drained = OrdinaryClientCheck.audit_drained

    def __init__(self, args):
        isolated.assert_isolated_network()
        require(args.control_base == "http://serverware:3000"
            and args.management_base == "http://127.0.0.1:9091" and args.proxy_url == PROXY
            and args.upstream_address is None, "fixed isolated X endpoints required")
        super().__init__(argparse.Namespace(**{**vars(args), "upstream_address": isolated.LOOPBACK}))
        self.credential = fixture.TOKEN
        require(self.control.address == self.management.address == self.proxy.address == isolated.LOOPBACK,
            "isolated X control/proxy/relay peer differs")
        self.upstream = Endpoint(fixture.ORIGIN, address=isolated.LOOPBACK)
        self.upstream.address = isolated.FIXTURE_IP
        require(Path("/node").is_file() and hashlib.sha256(Path("/node").read_bytes()).hexdigest() == NODE_SHA256,
            "pinned Node executable differs")
        require(type(args.expected_go_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", args.expected_go_sha256),
            "compiled X Go example pin missing")
        go = Path(COMMANDS["go"][0])
        require(go.is_file() and not go.is_symlink() and go.stat().st_size <= 64 * 1024**2
            and hashlib.sha256(go.read_bytes()).hexdigest() == args.expected_go_sha256, "compiled X Go example differs")
        self.example_sources = {}
        for name in SOURCE_FILES:
            path = Path("/app") / name
            require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 512 * 1024,
                "X example source unavailable")
            self.example_sources[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        inner, outer = (Path("/client-trust/" + name + "-ca.pem").read_bytes() for name in ("inner", "outer"))
        require(0 < len(inner) <= 65536 and 0 < len(outer) <= 65536 and inner != outer
            and b"PRIVATE KEY" not in inner + outer, "distinct public X client trust roots required")
        self.completed, self.wire, self.denials, self.cutoffs, self.reloads = [], [], [], [], []
        self.connections = 0
        self.current_client = self.current_phase = None
        self.scope = self.credential_id = None

    def health(self):
        value = super().health()
        require(value.get("operator_x_app_read") == DESCRIPTOR, "actual Rust X capability missing")
        return value

    def catalog(self):
        value = self.control_json(PREFIX + "/catalog", authenticated=True)
        require(value.get("schema") == "serverware.operatorCatalog/v1" and value.get("mode") == "operator-development"
            and value.get("productionReady") is False and value.get("hardwareVerified") is False
            and value.get("allowed_upstreams") == [fixture.ORIGIN]
            and type(value.get("revision")) is int and all(type(value.get(key)) is list for key in COLLECTIONS),
            "fresh synthetic X catalog contract differs")
        policy = value.get("policy", {})
        require(type(policy.get("policy_hash")) is str and SHA256.fullmatch(policy["policy_hash"])
            and type(policy.get("sequence")) is int, "X signed policy unavailable")
        self.snapshot = value
        return value

    def observe(self):
        status, value = self.json_request(self.upstream, "/_fixture/observations", context=self.upstream_ca)
        require(status == 200 and type(value) is dict
            and set(value) == {"schema", "syntheticOnly", "total", "attempts"}
            and value["schema"] == fixture.SCHEMA and value["syntheticOnly"] is True
            and type(value["total"]) is int and type(value["attempts"]) is list
            and value["total"] == len(value["attempts"]) <= fixture.MAX_ATTEMPTS,
            "X receiver observations unavailable")
        return value

    def count(self):
        return self.observe()["total"]

    def unchanged(self, pins):
        require(authority_projection(self.warm_cas_snapshot()) == authority_projection(pins),
            "X saved authority changed during client operation")

    def example(self, client, phase, app, token):
        self.current_client, self.current_phase = client, phase
        require(phase in SDK_PHASES, "X SDK phase differs")
        code, stdout, stderr = run_example(client, client_environment(client, app["id"], token,
            wrong_username=phase == "wrong_username"), min(70, self.deadline - time.monotonic()))
        self.clean(stdout)
        self.clean(stderr)
        if phase == "read":
            require(code == 0 and not stderr and json.loads(stdout) == expected_output(client),
                "actual X example did not return the exact username")
        else:
            require(code == 1 and not stdout, "actual X example did not fail closed")
        self.completed.append({"client": client, "phase": phase, "exitCode": code})
        if phase not in {"wrong_app", "revoked"}:
            self.connections += 1

    def raw_probe(self, case, app, token):
        require(case in REQUEST_PROBES + RESPONSE_PROBES, "X raw probe differs")
        self.current_client, self.current_phase = "probe", case
        self.connections += 1
        method = "POST" if case == "wrong_method" else "GET"
        target = fixture.TARGET + ("?unexpected=1" if case == "query" else "")
        agent = "serverware-x-probe/" + ("request-denied" if case in REQUEST_PROBES else case)
        dummy = "Bearer wrong-public-placeholder" if case == "wrong_dummy" else "Bearer serverware-x-placeholder-v1"
        raw = self.proxy.connect(self.timeout(), self.proxy_ca)
        try:
            login = base64.b64encode((app["id"] + ":" + token).encode()).decode("ascii")
            raw.sendall(("CONNECT api.x.com:443 HTTP/1.1\r\nHost: api.x.com:443\r\n"
                "Proxy-Authorization: Basic " + login + "\r\n\r\n").encode("ascii"))
            head = bytearray()
            while not head.endswith(b"\r\n\r\n"):
                raw.settimeout(self.timeout())
                part = raw.recv(1)
                require(bool(part) and len(head) < 16384, "X probe CONNECT response incomplete")
                head.extend(part)
            self.clean(bytes(head))
            require(head.split(b" ", 2)[1] == b"200", "X probe CONNECT refused")
            with XTunnel(raw, self.ca, self.timeout) as tls:
                tls.sendall((method + " " + target + " HTTP/1.1\r\nHost: api.x.com\r\n"
                    "Connection: close\r\nAccept: application/json\r\nUser-Agent: " + agent
                    + "\r\nAuthorization: " + dummy + "\r\n\r\n").encode("ascii"))
                capture = CapturedTLS(tls)
                response = http.client.HTTPResponse(capture)
                try:
                    response.begin()
                    body = response.read(65537)
                    require(len(body) <= 65536, "X probe released an oversized response")
                    headers = [(k.lower(), v) for k, v in response.getheaders()]
                    wire = capture.finish()
                    self.clean(wire)
                    physical, separator, raw_body = wire.partition(b"\r\n\r\n")
                    require(separator and len(physical) <= 16384 and raw_body == body
                        and len({k for k, _ in headers}) == len(headers), "X probe response framing differs")
                    values = dict(headers)
                    require(not {"transfer-encoding", "trailer"} & values.keys()
                        and values.get("content-length") == str(len(body)), "X probe response framing is ambiguous")
                    if case in REQUEST_PROBES:
                        document = json.loads(body)
                        require(response.status == 403 and document.get("allowed") is False
                            and document.get("action") == "deny", "X raw request was not denied")
                        if case == "wrong_dummy":
                            require(document.get("payload", {}).get("error") == "credential_existing_header_mismatch",
                                "X wrong dummy was not rejected by exact replacement")
                    elif case in BLOCK_ERRORS:
                        require(response.status == 502 and json.loads(body).get("error") == BLOCK_ERRORS[case],
                            "X hostile response was not blocked")
                    else:
                        require(response.status == fixture.status(case) and body == fixture.body(case)
                            and values.get("content-type") == "application/json"
                            and values.get("x-serverware-policy-hash") == self.scope[2]
                            and values.get("x-serverware-response-body-sha256") == digest(body),
                            "X provider error bytes or commitment changed")
                    return values
                finally:
                    response.close()
        finally:
            raw.close()

    def accept_arrival(self, client, case, headers=None):
        rows = self.observe()["attempts"]
        require(len(rows) == len(self.wire) + 1, "X operation caused extra or missing upstream requests")
        for old, observed in zip(self.wire, rows):
            require(old["observation"] == observed, "X earlier receiver observation changed")
        row = rows[-1]
        validate_row(row, len(rows), client, case)
        request_digest, operation_digest = canonical_digests(row, self.scope, self.credential_id, self.proxy.address)
        if headers is not None and case not in BLOCK_ERRORS:
            require(headers.get("x-serverware-request-digest") == request_digest
                and headers.get("x-serverware-operation-digest") == operation_digest,
                "X raw response canonical V2 commitments differ")
        self.wire.append({"client": client, "case": case, "requestDigest": request_digest,
            "operationDigest": operation_digest, "responseBodySha256": row["responseBodySha256"],
            "responseBodyBytes": row["responseBodyBytes"], "upstreamStatus": row["status"], "observation": row})

    def validate_lease(self, event):
        require(tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash")) == self.scope
            and event.get("credential_id") == self.credential_id and event.get("outcome") == "issued"
            and type(event.get("status_code")) is int and event["status_code"] == 200
            and event.get("data_plane_binary_digest") == self.args.expected_binary_sha256
            and event.get("purpose") in {"generationMetadata", "dispatchSecret"}, "X lease authority differs")
        require((event.get("expected_credential_version") is None) if event["purpose"] == "generationMetadata"
            else type(event.get("expected_credential_version")) is int and event["expected_credential_version"] == 1,
            "X lease generation differs")

    def deny_checkpoint(self, before, arrival_baseline, phase, *, client="probe"):
        # Explicit post-success baseline: never assume the receiver is empty.
        expected_kind = CONNECT_DENIED if phase in {"wrong_app", "revoked"} else DENIED
        while True:
            events = self.audit()
            cutoff = features.audit_cutoff(events)
            require(all(cutoff.get(k) == v for k, v in before.items()), "X denial audit prefix changed")
            rows = [row for row in events if row["id"] not in before]
            require(self.observe() == arrival_baseline, "denied X request reached upstream")
            counts = Counter(row["event_type"] for row in rows)
            require(set(counts) <= {expected_kind, CONNECT, LEASE}
                and counts[expected_kind] <= 1 and counts[CONNECT] <= (0 if expected_kind == CONNECT_DENIED else 1)
                and counts[LEASE] <= 64, "X denial caused extra dispatch or audit attempts")
            for row in rows:
                event = row["event"]
                if row["event_type"] == LEASE:
                    self.validate_lease(event)  # Earlier hot-scope renewal is not a new dispatch.
                elif row["event_type"] == expected_kind:
                    require(event.get("outcome") == "denied" and event.get("method") ==
                        ("CONNECT" if expected_kind == CONNECT_DENIED else "POST" if phase == "wrong_method" else "GET"),
                        "X denial method or outcome differs")
                    if expected_kind == CONNECT_DENIED:
                        require(event.get("target") == "api.x.com:443" and event.get("principal_id") is None,
                            "X unassigned or revoked grant was not denied at CONNECT")
                    if phase == "wrong_dummy":
                        require(event.get("error") == "credential_existing_header_mismatch", "X dummy denial audit differs")
            if counts[expected_kind] == 1 and counts[CONNECT] == (0 if expected_kind == CONNECT_DENIED else 1) and self.audit_drained():
                row = next(row for row in rows if row["event_type"] == expected_kind)
                self.denials.append({"id": row["id"], "kind": expected_kind, "client": client, "phase": phase})
                self.cutoffs.append(cutoff)
                return cutoff
            time.sleep(min(0.1, self.timeout()))

    def validate_audits(self, events, baseline):
        cutoff = features.audit_cutoff(events)
        require(all(cutoff.get(k) == v for prior in [baseline, *self.cutoffs] for k, v in prior.items()),
            "X retained audit history changed")
        rows = [row for row in events if row["id"] not in baseline]
        counts = Counter(row["event_type"] for row in rows)
        exact = Counter(kind for kind, _, _ in self.mutations)
        exact.update({START: len(self.wire), RELEASE: sum(item["case"] not in BLOCK_ERRORS for item in self.wire),
            BLOCK: sum(item["case"] in BLOCK_ERRORS for item in self.wire), CONNECT: self.connections,
            DENIED: sum(item["kind"] == DENIED for item in self.denials),
            CONNECT_DENIED: sum(item["kind"] == CONNECT_DENIED for item in self.denials), RELOAD: len(self.reloads)})
        require(set(counts) <= set(exact) | {LEASE} and counts[LEASE] <= 64
            and all(counts[k] <= v for k, v in exact.items()), "unexpected X audit inventory or client retry")
        expected = {(item["requestDigest"], item["operationDigest"]): item for item in self.wire}
        require(len(expected) == len(self.wire), "X clients reused canonical commitments")
        pairs, dispatched, seen_reloads = {}, False, set()
        for row in rows:
            kind, event = row["event_type"], row["event"]
            if kind in {START, RELEASE, BLOCK}:
                key = event.get("request_digest"), event.get("operation_digest")
                require(key in expected and tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash")) == self.scope
                    and event.get("credential_ref") == self.credential_id and type(event.get("credential_version")) is int
                    and event["credential_version"] == 1 and event.get("method") == "GET"
                    and event.get("body_sha256") == digest(b""), "X audit does not join observed request authority")
                attempt = event.get("attempt_id")
                require(type(attempt) is str and SHA256.fullmatch(attempt) and event.get("flow_id") == attempt,
                    "X audit attempt identity unavailable")
                pair = pairs.setdefault(key, {"attempt": attempt})
                slot = "start" if kind == START else "terminal"
                require(slot not in pair and pair["attempt"] == attempt, "X audit attempt duplicated")
                pair[slot] = row["id"]
                item = expected[key]
                if kind == START:
                    require(event.get("outcome") == "release_started", "X release start differs")
                else:
                    validation = event.get("response_validation", {})
                    require(type(event.get("upstream_status")) is int and event["upstream_status"] == item["upstreamStatus"],
                        "X upstream response status audit differs")
                    if item["case"] in BLOCK_ERRORS:
                        require(kind == BLOCK and event.get("outcome") == "blocked" and validation.get("ok") is False
                            and validation.get("error") == BLOCK_ERRORS[item["case"]], "X response block audit differs")
                    else:
                        require(kind == RELEASE and event.get("outcome") == "released"
                            and event.get("response_body_sha256") == item["responseBodySha256"]
                            and type(event.get("response_body_bytes")) is int and event["response_body_bytes"] == item["responseBodyBytes"]
                            and validation.get("ok") is True and validation.get("body_bytes_preserved") is True
                            and validation.get("mode") == "xAppReadJsonV1", "X exact response release differs")
            elif kind == LEASE:
                self.validate_lease(event)
                dispatched |= event["purpose"] == "dispatchSecret"
            elif kind == CONNECT:
                require(event.get("target") == "api.x.com:443" and event.get("method") == "CONNECT"
                    and event.get("principal_id") == self.scope[0] and event.get("policy_hash") == self.scope[2]
                    and event.get("outcome") == "established", "X CONNECT scope differs")
            elif kind in {DENIED, CONNECT_DENIED}:
                require(any(row["id"] == item["id"] and kind == item["kind"] for item in self.denials),
                    "X denial is not a separately observed negative control")
            elif kind == RELOAD:
                identity = (event.get("previous_policy_hash"), event.get("policy_hash"), event.get("policy_sequence"))
                require(identity in self.reloads and identity not in seen_reloads and event.get("routes") == 1,
                    "X reload is not the exact grant or revocation")
                seen_reloads.add(identity)
        require(len({pair["attempt"] for pair in pairs.values()}) == len(pairs), "X attempt identity reused")
        mutations = {(r["event_type"], r["event"].get("resource_id"), r["event"].get("policy_hash")) for r in rows}
        complete = (all(counts[k] == v for k, v in exact.items()) and len(pairs) == len(self.wire)
            and all({"start", "terminal"} <= pair.keys() for pair in pairs.values()) and dispatched
            and set(self.mutations) <= mutations)
        return complete, cutoff, {"namedAuditInventory": dict(sorted(counts.items())),
            "auditAttemptIds": sorted(pair["attempt"] for pair in pairs.values())}

    def wait_audits(self, baseline):
        retained = None
        while True:
            events = self.audit()
            complete, cutoff, evidence = self.validate_audits(events, baseline)
            if retained is not None:
                require(all(cutoff.get(k) == v for k, v in retained.items())
                    and all(row["event_type"] == LEASE for row in events if row["id"] not in retained),
                    "X audit changed after complete checkpoint")
                retained = cutoff
            if complete and self.audit_drained():
                if retained is not None:
                    self.cutoffs.append(cutoff)
                    return cutoff, evidence
                retained = cutoff
            time.sleep(min(0.1, self.timeout()))

    def run(self):
        self.health()
        self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        require(initial["revision"] == self.args.expected_initial_revision
            and all(not initial[key] and initial["limits"][key]["retained"] == 0 for key in COLLECTIONS)
            and self.count() == 0, "fresh pinned X catalog required")
        capability = initial.get("capabilities", {}).get("x")
        require(type(capability) is dict and capability.get("destination_allowed") is True
            and capability.get("connection_type") == "x_app_bearer_v1"
            and capability.get("operation_bundles") == ["x_username_read_v1"]
            and capability.get("source_pair_required") is True, "paired X catalog capability unavailable")
        self.policy_hash = initial_hash = initial["policy"]["policy_hash"]
        self.wait_catalog_loaded("initial")
        while not self.audit_drained():
            time.sleep(min(0.1, self.timeout()))
        baseline = features.audit_cutoff(self.audit())
        credential, _, _ = self.mutate("/credentials/x-app-bearer", {"name": self.run_id + "-x", "secret": self.credential},
            collection="credentials", result_key="credential", event="operator_catalog.credential.x_app_bearer_created", creates=True)
        apps = []
        for suffix in ("assigned", "unassigned"):
            app, token, _ = self.mutate("/applications", {"name": self.run_id + "-" + suffix,
                "token_lifetime_seconds": 3600, "proxy_authentication": "basic_and_bearer_v1"},
                collection="applications", result_key="application", event="operator_catalog.application.created", creates=True, token=True)
            apps.append((app, token))
        app, token = apps[0]
        rule, _, _ = self.mutate("/access-rules/x-username", {"name": self.run_id + "-read", "application_id": app["id"],
            "credential_id": credential["id"], "operation_bundle": "x_username_read_v1", "username": fixture.USERNAME},
            collection="access_rules", result_key="access_rule", event="operator_catalog.access_rule.x_username_created",
            creates=True, authority_changed=True)
        self.wait_catalog_loaded("assigned")
        pins = self.warm_cas_snapshot()
        self.scope, self.credential_id = (app["principal_id"], rule["route_id"], self.policy_hash), credential["id"]
        require([len(pins[key]) for key in COLLECTIONS] == [1, 2, 1] and credential.get("credential_generation") == 1,
            "X saved resource inventory differs")
        self.reloads.append((initial_hash, self.policy_hash, pins["policy"]["sequence"]))
        for client in fixture.CLIENTS:
            self.unchanged(pins)
            self.example(client, "read", app, token)
            self.accept_arrival(client, "success")
        previous, _ = self.wait_audits(baseline)
        success_baseline = self.observe()  # Explicit three-arrival no-dispatch baseline.
        for client in fixture.CLIENTS:
            for phase in ("wrong_app", "wrong_username"):
                self.unchanged(pins)
                self.example(client, phase, *(apps[1] if phase == "wrong_app" else apps[0]))
                previous = self.deny_checkpoint(previous, success_baseline, phase, client=client)
        for case in REQUEST_PROBES:
            self.unchanged(pins)
            self.raw_probe(case, app, token)
            previous = self.deny_checkpoint(previous, success_baseline, case)
        for case in RESPONSE_PROBES:
            self.unchanged(pins)
            headers = self.raw_probe(case, app, token)
            self.accept_arrival("probe", case, headers)
        self.wait_audits(baseline)
        self.unchanged(pins)
        last_hash = self.policy_hash
        self.mutate("/access-rules/revoke", {"id": rule["id"]}, collection="access_rules", result_key="access_rule",
            event="operator_catalog.access_rule.revoked", authority_changed=True)
        self.wait_catalog_loaded("revoked")
        revoked = self.warm_cas_snapshot()
        require(self.resource(revoked, "access_rules", rule["id"])["status"] == "revoked"
            and self.resource(revoked, "credentials", credential["id"])["status"] == "active"
            and self.resource(revoked, "applications", app["id"])["token_status"] == "valid",
            "X grant revocation changed the credential or application token")
        self.reloads.append((last_hash, self.policy_hash, revoked["policy"]["sequence"]))
        previous, _ = self.wait_audits(baseline)
        revoked_baseline = self.observe()
        for client in fixture.CLIENTS:
            self.unchanged(revoked)
            self.example(client, "revoked", app, token)
            previous = self.deny_checkpoint(previous, revoked_baseline, "revoked", client=client)
        _, evidence = self.wait_audits(baseline)
        chain = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(chain.get("ok") is True and chain.get("complete") is True and chain.get("backend") == "sqlite",
            "X durable audit chain incomplete")
        require(self.observe() == revoked_baseline and len(self.wire) == 8 and self.connections == 14,
            "X final provider or proxy inventory differs")
        self.unchanged(revoked)
        result = {"schema": SCHEMA, "ok": True, "syntheticOnly": True, "realXVerified": False,
            "productionReady": False, "publicDnsVerified": False, "actualExampleEntrypoints": True,
            "auditChainVerified": True, "separateOuterInnerTrust": True, **RESULT_COUNTS,
            "dataPlaneBinaryDigest": self.args.expected_binary_sha256, "goExampleSha256": self.args.expected_go_sha256,
            "exampleSourceSha256": self.example_sources, "completed": self.completed,
            "requests": [{k: v for k, v in row.items() if k != "observation"} for row in self.wire],
            "negativeControls": [{k: v for k, v in row.items() if k != "id"} for row in self.denials], **evidence}
        validate_success_result(result)
        return result


def validate_success_result(value):
    """Pure closed runner predicate; never substitutes for actual checker exit0."""
    fields = {"schema", "ok", "syntheticOnly", "realXVerified", "productionReady", "publicDnsVerified",
        "actualExampleEntrypoints", "auditChainVerified", "separateOuterInnerTrust", "dataPlaneBinaryDigest",
        "goExampleSha256", "exampleSourceSha256", "completed", "requests", "negativeControls",
        "namedAuditInventory", "auditAttemptIds", *RESULT_COUNTS}
    require(type(value) is dict and set(value) == fields and value.get("schema") == SCHEMA
        and all(value.get(k) is True for k in ("ok", "syntheticOnly", "actualExampleEntrypoints",
            "auditChainVerified", "separateOuterInnerTrust"))
        and all(value.get(k) is False for k in ("realXVerified", "productionReady", "publicDnsVerified"))
        and all(type(value.get(k)) is int and value[k] == v for k, v in RESULT_COUNTS.items()), "X result contract differs")
    require(Counter((row.get("client"), row.get("phase"), row.get("exitCode")) for row in value["completed"])
        == Counter((client, phase, 0 if phase == "read" else 1) for client in fixture.CLIENTS for phase in SDK_PHASES),
        "X actual SDK case inventory differs")
    require(Counter((row.get("client"), row.get("case")) for row in value["requests"])
        == Counter([(client, "success") for client in fixture.CLIENTS] + [("probe", case) for case in RESPONSE_PROBES])
        and len(value["auditAttemptIds"]) == len(set(value["auditAttemptIds"])) == 8
        and all(type(item) is str and SHA256.fullmatch(item) for item in value["auditAttemptIds"]),
        "X response or attempt inventory differs")
    require(Counter((row.get("client"), row.get("phase"), row.get("kind")) for row in value["negativeControls"])
        == Counter([(client, phase, CONNECT_DENIED if phase in {"wrong_app", "revoked"} else DENIED)
            for client in fixture.CLIENTS for phase in ("wrong_app", "wrong_username", "revoked")]
            + [("probe", case, DENIED) for case in REQUEST_PROBES]), "X negative control inventory differs")
    require(type(value["dataPlaneBinaryDigest"]) is str and SHA256.fullmatch(value["dataPlaneBinaryDigest"])
        and re.fullmatch(r"[0-9a-f]{64}", value["goExampleSha256"] or "")
        and set(value["exampleSourceSha256"]) == set(SOURCE_FILES)
        and all(re.fullmatch(r"[0-9a-f]{64}", item) for item in value["exampleSourceSha256"].values()),
        "X result executable or source pins missing")
    return True


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
    args = parser.parse_args()
    check = None
    def expired(*_):
        raise CheckFailure("private X checker deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    try:
        require(30 <= args.timeout_seconds <= 180 and SHA256.fullmatch(args.expected_binary_sha256)
            and 1 <= args.expected_initial_revision <= 3, "X checker bounds invalid")
        signal.alarm(args.timeout_seconds)
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = ExamplesCheck(args)
        result = check.run()
        check.clean(json.dumps(result).encode())
    except Exception:
        result = {"schema": SCHEMA, "ok": False, "syntheticOnly": True, "productionReady": False,
            "error": "checked-in X example acceptance failed",
            "client": check.current_client if check is not None and check.current_client in (*fixture.CLIENTS, "probe") else None,
            "phase": check.current_phase if check is not None and check.current_phase in SDK_PHASES + REQUEST_PROBES + RESPONSE_PROBES else None,
            "completed": check.completed if check is not None else []}
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
