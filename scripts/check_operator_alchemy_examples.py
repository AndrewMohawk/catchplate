#!/usr/bin/env python3
"""One-shot actual Alchemy SDK examples through the isolated normal Rust gate.

Never installs, builds, starts a stack, or contacts a real provider. SDK calls,
raw protocol controls, receiver bytes and durable audit are separate oracles.
The root-owned runner pins all source/dependencies/binaries and owns cleanup.
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
from scripts import operator_alchemy_examples_fixture as fixture
from scripts import operator_alchemy_fixture_network as isolated

SCHEMA = "serverware.privateAlchemyExamplesCheck/v1"
PROXY = "https://proxy.operator-basic.example.test:8443"
HOST, OTHER_HOST = "eth-mainnet.g.alchemy.com", "eth-sepolia.g.alchemy.com"
METHODS = ("eth_chainId", "eth_blockNumber")
DESCRIPTOR = {"schema": "serverware.operatorAlchemyRpcReadGate/v1",
    "adapter": "alchemy.rpc_read.v1", "operation": "alchemy.rpc.read"}
COMMANDS = {
    "node": ("/node", "/app/examples/alchemy-chain-status-node/client.mjs"),
    "python": ("/example-python/bin/python", "-I", "-B", "/app/examples/alchemy-chain-status-python/chain_status.py"),
    "go": ("/example-go/alchemy-chain-status",),
}
SOURCE_FILES = ("examples/alchemy-chain-status-node/client.mjs", "examples/alchemy-chain-status-node/request.mjs",
    "examples/alchemy-chain-status-node/package.json", "examples/alchemy-chain-status-node/package-lock.json",
    "examples/alchemy-chain-status-python/chain_status.py", "examples/alchemy-chain-status-python/requirements.txt",
    "examples/alchemy-chain-status-go/main.go", "examples/alchemy-chain-status-go/config_file.go",
    "examples/alchemy-chain-status-go/go.mod",
    "examples/alchemy-chain-status-go/go.sum")
SDK_PHASES = ("read", "wrong_app", "wrong_chain", "revoked")
REQUEST_PROBES = ("wrong_dummy", "rpc_write", "batch", "notification", "query")
RESPONSE_PROBES = ("rpc-error", "error429", "wrong-id", "oversize", "reflection", "invalid-json")
BLOCK_ERRORS = {"wrong-id": "alchemy_rpc_response_invalid", "oversize": "response_body_too_large",
    "reflection": "response_credential_reflection", "invalid-json": "response_invalid_json"}
RESULT_COUNTS = {"providerAttempts": 12, "releases": 8, "responseBlocks": 4,
    "requestProbeDenials": 5, "sdkConnectDenials": 9, "interceptedRequests": 17}
PHASES = ("startup", "setup", "read", "wrong_app", "wrong_chain", "request_probe",
    "response_probe", "revoke", "revoked", "final")
STAGES = ("unknown", "preflight", "health", "catalog", "mutation", "policy", "authority", "client",
    "client_result", "receiver", "receiver_join", "raw_connect", "raw_request", "raw_response",
    "audit", "audit_chain", "result")
REQUEST_FIELDS = {"client", "case", "rpcMethod", "requestId", "requestDigest", "operationDigest",
    "requestBodySha256", "responseBodySha256", "responseBodyBytes", "upstreamStatus"}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON member")
            result[key] = value
        return result
    def refused(_value):
        raise CheckFailure("unsupported JSON number")
    def integer(value):
        require(value == "0" or re.fullmatch(r"-?[1-9][0-9]*", value), "noncanonical JSON integer")
        return int(value)
    return json.loads(raw, object_pairs_hook=pairs, parse_int=integer, parse_float=refused, parse_constant=refused)


def expected_output(client):
    require(client in COMMANDS, "unknown Alchemy client")
    if client == "node":
        return {"ok": True, "operation": "chain-status", "chain": "eth-mainnet", "chainId": "0x1", "blockNumber": "0x10"}
    if client == "python":
        return {"chain": "eth-mainnet", "chain_id": 1, "block_number": 16}
    return {"chain_id": "0x1", "block_number": 16}


def client_environment(client, application, token, *, wrong_chain=False):
    require(client in COMMANDS, "unknown Alchemy client")
    return {"LANG": "C.UTF-8", "SERVERWARE_PROXY_URL": PROXY,
        "SERVERWARE_APP_ID": application, "SERVERWARE_PROXY_TOKEN": token,
        "SERVERWARE_ALCHEMY_CHAIN": "eth-sepolia" if wrong_chain else "eth-mainnet",
        "SERVERWARE_CA_FILE": "/client-trust/inner-ca.pem",
        "SERVERWARE_PROXY_CA_FILE": "/client-trust/outer-ca.pem"}


def run_example(client, environment, seconds):
    """Actual entrypoints; retain the accepted WNOWAIT/session cleanup boundary."""
    require(client in COMMANDS and 0 < seconds <= 70, "Alchemy example deadline invalid")
    deadline = time.monotonic() + seconds
    process = subprocess.Popen(COMMANDS[client], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=environment, close_fds=True, start_new_session=True)
    output = {"out": bytearray(), "err": bytearray()}
    try:
        with selectors.DefaultSelector() as selected:
            for stream, key in ((process.stdout, "out"), (process.stderr, "err")):
                selected.register(stream, selectors.EVENT_READ, key)
            while selected.get_map():
                require(time.monotonic() < deadline, "Alchemy example process deadline exceeded")
                for key, _ in selected.select(min(0.1, max(0.001, deadline - time.monotonic()))):
                    chunk = os.read(key.fd, 8192)
                    if not chunk:
                        selected.unregister(key.fileobj)
                    else:
                        output[key.data].extend(chunk)
                        require(len(output[key.data]) <= (65536 if key.data == "out" else 8192),
                            "Alchemy example output bound exceeded")
        while True:
            code = _child_exit_status(process)
            if code is not None:
                return code, bytes(output["out"]), bytes(output["err"])
            require(time.monotonic() < deadline, "Alchemy example process deadline exceeded")
            time.sleep(min(0.01, max(0.001, deadline - time.monotonic())))
    finally:
        try:
            _cleanup_example_group(process)
        finally:
            process.stdout.close()
            process.stderr.close()


def expected_id(client, case, method):
    require(method in METHODS, "Alchemy method differs")
    if client == "probe":
        require(case in RESPONSE_PROBES and method == "eth_chainId", "Alchemy response probe differs")
        return "probe:" + case
    require(client in COMMANDS and case == "success", "Alchemy SDK request differs")
    return {"node": 0, "python": 0, "go": 1}[client] + METHODS.index(method)


def validate_row(row, ordinal, client, case, method):
    require(type(row) is dict and set(row) == fixture.ROW_KEYS
        and type(row["ordinal"]) is int and row["ordinal"] == ordinal
        and row["accepted"] is True and row["client"] == client and row["case"] == case
        and row["method"] == "POST" and row["target"] == "/v2" and row["chain"] == "eth-mainnet"
        and row["rpcMethod"] == method and row["providerCredentialMatched"] is True
        and row["proxyAuthorizationPresent"] is False and row["allParsedHeadersValidated"] is True,
        "Alchemy receiver identity differs")
    identifier = expected_id(client, case, method)
    require(type(row["requestId"]) is type(identifier) and row["requestId"] == identifier,
        "Alchemy typed request ID differs")
    require(type(row["requestBodyBase64"]) is str and len(row["requestBodyBase64"]) <= 87384,
        "Alchemy original request body unavailable")
    raw = base64.b64decode(row["requestBodyBase64"], validate=True)
    require(base64.b64encode(raw).decode("ascii") == row["requestBodyBase64"] and 1 <= len(raw) <= 65536,
        "Alchemy request encoding differs")
    document = strict_json(raw)
    require(type(document) is dict and set(document) == {"jsonrpc", "id", "method", "params"}
        and document["jsonrpc"] == "2.0" and document["method"] == method
        and type(document["params"]) is list and document["params"] == []
        and type(document["id"]) is type(identifier) and document["id"] == identifier
        and type(row["requestBodyBytes"]) is int and row["requestBodyBytes"] == len(raw)
        and row["requestBodySha256"] == digest(raw), "Alchemy original RPC bytes differ")
    headers = row["semanticHeaders"]
    require(type(headers) is dict and all(type(k) is str and type(v) is str for k, v in headers.items())
        and headers.get("content-length") == str(len(raw)), "Alchemy request framing differs")
    admitted = fixture.validated_headers(client, list(headers.items()) +
        [("host", HOST), ("authorization", "Bearer " + fixture.TOKEN)], case=case)
    response = fixture.body(case, identifier, method)
    require(admitted == headers and type(row["status"]) is int and row["status"] == fixture.status(case)
        and row["responseBodySha256"] == digest(response) and type(row["responseBodyBytes"]) is int
        and row["responseBodyBytes"] == len(response), "Alchemy receiver response or headers differ")
    return raw


def canonical_digests(row, scope, credential_id, peer):
    """Independent V2: original bytes, actual framing, and typed RPC identity."""
    canonical = {"v": 2, "principal": scope[0], "client_ip": peer, "route_id": scope[1],
        "credential_ref": credential_id, "credential_version": "1", "policy_hash": scope[2],
        "request": {"method": "POST", "scheme": "https", "authority": HOST, "path": "/v2",
            "query": [], "headers": {"host": HOST, **row["semanticHeaders"]},
            "body_sha256": row["requestBodySha256"], "discard_headers": ["accept-encoding"]},
        "operation": {"operation": "alchemy.rpc.read", "chain": "eth-mainnet",
            "method": row["rpcMethod"], "requestId": row["requestId"]}}
    return digest(encoded(canonical)), digest(encoded({k: v for k, v in canonical.items() if k not in {"v", "client_ip"}}))


def probe_body(case):
    require(case in REQUEST_PROBES + RESPONSE_PROBES, "unknown Alchemy probe")
    value = {"jsonrpc": "2.0", "id": "probe:" + case, "method": "eth_chainId", "params": []}
    if case == "rpc_write":
        value.update(method="eth_sendRawTransaction", params=["0x00"])
    if case == "notification":
        value.pop("id")
    return encoded([value] if case == "batch" else value)


class AlchemyTunnel(TunnelTLS):
    def __init__(self, raw, context, timeout):
        io.RawIOBase.__init__(self)
        self.raw, self.timeout = raw, timeout
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_hostname=HOST)
        self._perform(self.tls.do_handshake)


class ExamplesCheck(OperatorCatalogCheck):
    audit_drained = OrdinaryClientCheck.audit_drained

    def __init__(self, args):
        self.location = {"phase": "startup", "stage": "preflight", "client": None, "case": None}
        self.completed = []
        isolated.assert_isolated_network()
        require(args.control_base == "http://serverware:3000" and args.management_base == "http://127.0.0.1:9091"
            and args.proxy_url == PROXY and args.upstream_address is None, "fixed isolated Alchemy endpoints required")
        super().__init__(argparse.Namespace(**{**vars(args), "upstream_address": isolated.LOOPBACK}))
        self.credential = fixture.TOKEN
        require(self.control.address == self.management.address == self.proxy.address == isolated.LOOPBACK,
            "isolated Alchemy control/proxy/relay peer differs")
        self.upstream = Endpoint(fixture.ORIGIN, address=isolated.LOOPBACK)
        self.upstream.address = isolated.FIXTURE_IP
        require(Path("/node").is_file() and hashlib.sha256(Path("/node").read_bytes()).hexdigest() == NODE_SHA256,
            "pinned Node executable differs")
        require(type(args.expected_go_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", args.expected_go_sha256),
            "compiled Alchemy Go pin missing")
        go = Path(COMMANDS["go"][0])
        require(go.is_file() and not go.is_symlink() and go.stat().st_size <= 64 * 1024**2
            and hashlib.sha256(go.read_bytes()).hexdigest() == args.expected_go_sha256, "compiled Alchemy Go example differs")
        self.example_sources = {}
        for name in SOURCE_FILES:
            path = Path("/app") / name
            require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 512 * 1024,
                "Alchemy example source unavailable")
            self.example_sources[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        inner, outer = (Path("/client-trust/" + name + "-ca.pem").read_bytes() for name in ("inner", "outer"))
        require(0 < len(inner) <= 65536 and 0 < len(outer) <= 65536 and inner != outer
            and b"PRIVATE KEY" not in inner + outer, "distinct public Alchemy trust roots required")
        self.wire, self.denials, self.cutoffs, self.reloads = [], [], [], []
        self.intercepted = 0
        self.scope = self.credential_id = None

    def mark(self, phase, stage, client=None, case=None):
        require(phase in PHASES and stage in STAGES and client in (None, *COMMANDS, "probe")
            and case in (None, *SDK_PHASES, *REQUEST_PROBES, *RESPONSE_PROBES), "invalid checker location")
        self.location = {"phase": phase, "stage": stage, "client": client, "case": case}

    def stage(self, stage):
        self.mark(self.location["phase"], stage, self.location["client"], self.location["case"])

    def health(self):
        self.stage("health")
        value = super().health()
        require(value.get("operator_alchemy_rpc_read") == DESCRIPTOR, "actual Rust Alchemy capability missing")
        return value

    def catalog(self):
        self.stage("catalog")
        value = self.control_json(PREFIX + "/catalog", authenticated=True)
        require(type(value) is dict and value.get("schema") == "serverware.operatorCatalog/v1"
            and value.get("mode") == "operator-development" and value.get("productionReady") is False
            and value.get("hardwareVerified") is False
            and value.get("allowed_upstreams") == ["https://" + HOST, "https://" + OTHER_HOST]
            and type(value.get("revision")) is int and all(type(value.get(key)) is list for key in COLLECTIONS),
            "fresh two-origin Alchemy catalog required")
        policy = value.get("policy", {})
        require(type(policy.get("policy_hash")) is str and SHA256.fullmatch(policy["policy_hash"])
            and type(policy.get("sequence")) is int, "Alchemy signed policy unavailable")
        self.snapshot = value
        return value

    def observe(self):
        self.stage("receiver")
        status, value = self.json_request(self.upstream, "/_fixture/observations", context=self.upstream_ca)
        require(status == 200 and type(value) is dict and set(value) == {"schema", "syntheticOnly", "total", "attempts"}
            and value["schema"] == fixture.SCHEMA and value["syntheticOnly"] is True
            and type(value["total"]) is int and type(value["attempts"]) is list
            and value["total"] == len(value["attempts"]) <= fixture.MAX_ATTEMPTS,
            "Alchemy receiver observations unavailable")
        return value

    def unchanged(self, pins):
        current = self.warm_cas_snapshot()
        self.stage("authority")
        require(authority_projection(current) == authority_projection(pins), "Alchemy saved authority changed")

    def submit_mutation(self, before, route, payload, **kwargs):
        self.stage("mutation")
        return super().submit_mutation(before, route, payload, **kwargs)

    def example(self, client, phase, app, token):
        self.mark(phase, "client", client, phase)
        code, stdout, stderr = run_example(client, client_environment(client, app["id"], token,
            wrong_chain=phase == "wrong_chain"), min(70, self.deadline - time.monotonic()))
        self.stage("client_result")
        self.clean(stdout)
        self.clean(stderr)
        if phase == "read":
            require(code == 0 and not stderr and encoded(strict_json(stdout)) == encoded(expected_output(client)),
                "actual Alchemy SDK result differs")
            self.intercepted += 2
        else:
            require(code == 1 and not stdout and 0 < len(stderr) <= 8192, "actual Alchemy SDK did not fail closed")
        self.completed.append({"client": client, "phase": phase, "exitCode": code})

    def raw_probe(self, case, app, token):
        self.mark("request_probe" if case in REQUEST_PROBES else "response_probe", "raw_connect", "probe", case)
        raw_body = probe_body(case)
        self.intercepted += 1
        target = "/v2" + ("?unexpected=1" if case == "query" else "")
        agent = "serverware-alchemy-probe/" + ("request-denied" if case in REQUEST_PROBES else case)
        dummy = "Bearer wrong-public-placeholder" if case == "wrong_dummy" else "Bearer serverware-alchemy-placeholder-v1"
        raw = self.proxy.connect(self.timeout(), self.proxy_ca)
        try:
            login = base64.b64encode((app["id"] + ":" + token).encode()).decode("ascii")
            raw.sendall(("CONNECT " + HOST + ":443 HTTP/1.1\r\nHost: " + HOST + ":443\r\n"
                "Proxy-Authorization: Basic " + login + "\r\n\r\n").encode("ascii"))
            head = bytearray()
            while not head.endswith(b"\r\n\r\n"):
                raw.settimeout(self.timeout())
                part = raw.recv(1)
                require(bool(part) and len(head) < 16384, "Alchemy CONNECT response incomplete")
                head.extend(part)
            self.clean(bytes(head))
            require(head.split(b" ", 2)[1] == b"200", "Alchemy probe CONNECT refused")
            with AlchemyTunnel(raw, self.ca, self.timeout) as tls:
                self.stage("raw_request")
                tls.sendall(("POST " + target + " HTTP/1.1\r\nHost: " + HOST + "\r\n"
                    "Connection: close\r\nAccept: application/json\r\nContent-Type: application/json\r\n"
                    "Content-Length: " + str(len(raw_body)) + "\r\nUser-Agent: " + agent + "\r\nAuthorization: "
                    + dummy + "\r\n\r\n").encode("ascii") + raw_body)
                self.stage("raw_response")
                capture = CapturedTLS(tls)
                response = http.client.HTTPResponse(capture)
                try:
                    response.begin()
                    body = response.read(65537)
                    require(len(body) <= 65536, "Alchemy probe released an oversized response")
                    headers = [(k.lower(), v) for k, v in response.getheaders()]
                    wire = capture.finish()
                    self.clean(wire)
                    physical, separator, raw_received = wire.partition(b"\r\n\r\n")
                    require(separator and len(physical) <= 16384 and raw_received == body
                        and len({k for k, _ in headers}) == len(headers), "Alchemy response framing differs")
                    values = dict(headers)
                    require(not {"transfer-encoding", "trailer"} & values.keys()
                        and values.get("content-length") == str(len(body)), "Alchemy response framing is ambiguous")
                    if case in REQUEST_PROBES:
                        document = strict_json(body)
                        require(response.status == 403 and document.get("allowed") is False
                            and document.get("action") == "deny", "Alchemy raw request was not denied")
                        if case == "wrong_dummy":
                            require(document.get("payload", {}).get("error") == "credential_existing_header_mismatch",
                                "Alchemy exact replacement was not enforced")
                    elif case in BLOCK_ERRORS:
                        require(response.status == 502 and strict_json(body).get("error") == BLOCK_ERRORS[case],
                            "Alchemy hostile response was not blocked")
                    else:
                        require(response.status == fixture.status(case)
                            and body == fixture.body(case, "probe:" + case)
                            and values.get("content-type") == "application/json"
                            and values.get("x-serverware-policy-hash") == self.scope[2]
                            and values.get("x-serverware-response-body-sha256") == digest(body),
                            "Alchemy RPC/HTTP error bytes or commitment changed")
                    return values
                finally:
                    response.close()
        finally:
            raw.close()

    def accept_arrivals(self, client, case, methods, headers=None):
        rows = self.observe()["attempts"]
        self.stage("receiver_join")
        require(len(rows) == len(self.wire) + len(methods), "Alchemy extra or missing provider requests")
        require(all(old["observation"] == row for old, row in zip(self.wire, rows)), "Alchemy receiver prefix changed")
        for row, method in zip(rows[len(self.wire):], methods):
            validate_row(row, len(self.wire) + 1, client, case, method)
            request_digest, operation_digest = canonical_digests(row, self.scope, self.credential_id, self.proxy.address)
            if headers is not None and case not in BLOCK_ERRORS:
                require(headers.get("x-serverware-request-digest") == request_digest
                    and headers.get("x-serverware-operation-digest") == operation_digest,
                    "Alchemy original-byte canonical V2 commitments differ")
            self.wire.append({"client": client, "case": case, "rpcMethod": method, "requestId": row["requestId"],
                "requestDigest": request_digest, "operationDigest": operation_digest,
                "requestBodySha256": row["requestBodySha256"], "responseBodySha256": row["responseBodySha256"],
                "responseBodyBytes": row["responseBodyBytes"], "upstreamStatus": row["status"], "observation": row})

    def validate_lease(self, event):
        require(tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash")) == self.scope
            and event.get("credential_id") == self.credential_id and event.get("outcome") == "issued"
            and type(event.get("status_code")) is int and event["status_code"] == 200
            and event.get("data_plane_binary_digest") == self.args.expected_binary_sha256
            and event.get("purpose") in {"generationMetadata", "dispatchSecret"}, "Alchemy lease authority differs")
        require((event.get("expected_credential_version") is None) if event["purpose"] == "generationMetadata"
            else type(event.get("expected_credential_version")) is int and event["expected_credential_version"] == 1,
            "Alchemy lease generation differs")

    def deny_checkpoint(self, before, arrivals, phase, *, client="probe"):
        connect_denial = phase in {"wrong_app", "wrong_chain", "revoked"}
        kind = CONNECT_DENIED if connect_denial else DENIED
        while True:
            self.stage("audit")
            events = self.audit()
            cutoff = features.audit_cutoff(events)
            require(all(cutoff.get(k) == v for k, v in before.items()), "Alchemy denial audit prefix changed")
            rows = [row for row in events if row["id"] not in before]
            require(self.observe() == arrivals, "denied Alchemy request reached a provider")
            self.stage("audit")
            counts = Counter(row["event_type"] for row in rows)
            require(set(counts) <= {kind, CONNECT, LEASE} and counts[kind] <= 1
                and counts[CONNECT] <= (0 if connect_denial else 1) and counts[LEASE] <= 64,
                "Alchemy denial caused extra dispatch or retry")
            for row in rows:
                event = row["event"]
                if row["event_type"] == LEASE:
                    self.validate_lease(event)  # Only the earlier successful hot scope may renew.
                elif row["event_type"] == kind:
                    require(event.get("outcome") == "denied"
                        and event.get("method") == ("CONNECT" if connect_denial else "POST"), "Alchemy denial differs")
                    if connect_denial:
                        host = OTHER_HOST if phase == "wrong_chain" else HOST
                        require(event.get("target") == host + ":443" and event.get("principal_id") is None,
                            "Alchemy wrong application/chain or revoked grant was not denied at CONNECT")
                    if phase == "wrong_dummy":
                        require(event.get("error") == "credential_existing_header_mismatch", "Alchemy dummy denial differs")
            if counts[kind] == 1 and counts[CONNECT] == (0 if connect_denial else 1) and self.audit_drained():
                row = next(row for row in rows if row["event_type"] == kind)
                self.denials.append({"id": row["id"], "kind": kind, "client": client, "phase": phase})
                self.cutoffs.append(cutoff)
                return cutoff
            time.sleep(min(0.1, self.timeout()))

    def validate_audits(self, events, baseline):
        cutoff = features.audit_cutoff(events)
        require(all(cutoff.get(k) == v for prior in [baseline, *self.cutoffs] for k, v in prior.items()),
            "Alchemy retained audit history changed")
        rows = [row for row in events if row["id"] not in baseline]
        counts = Counter(row["event_type"] for row in rows)
        exact = Counter(kind for kind, _, _ in self.mutations)
        exact.update({START: len(self.wire), RELEASE: sum(item["case"] not in BLOCK_ERRORS for item in self.wire),
            BLOCK: sum(item["case"] in BLOCK_ERRORS for item in self.wire),
            DENIED: sum(item["kind"] == DENIED for item in self.denials),
            CONNECT_DENIED: sum(item["kind"] == CONNECT_DENIED for item in self.denials), RELOAD: len(self.reloads)})
        pooled_max = int(any(item["client"] == "python" and item["phase"] == "read" for item in self.completed))
        require(set(counts) <= set(exact) | {CONNECT, KEEP_ALIVE, LEASE} and counts[LEASE] <= 64
            and counts[CONNECT] <= self.intercepted and counts[KEEP_ALIVE] <= pooled_max
            and all(counts[k] <= v for k, v in exact.items()), "unexpected Alchemy audit inventory or retry")
        expected = {(item["requestDigest"], item["operationDigest"]): item for item in self.wire}
        require(len(expected) == len(self.wire), "Alchemy canonical commitments reused")
        pairs, dispatched, seen_reloads = {}, False, set()
        established, kept = Counter(), Counter()
        for row in rows:
            kind, event = row["event_type"], row["event"]
            if kind in {START, RELEASE, BLOCK}:
                key = event.get("request_digest"), event.get("operation_digest")
                require(key in expected, "Alchemy audit has no observed request")
                item = expected[key]
                require(tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash")) == self.scope
                    and event.get("credential_ref") == self.credential_id and type(event.get("credential_version")) is int
                    and event["credential_version"] == 1 and event.get("method") == "POST"
                    and event.get("body_sha256") == item["requestBodySha256"], "Alchemy request authority or raw body differs")
                attempt = event.get("attempt_id")
                require(type(attempt) is str and SHA256.fullmatch(attempt) and event.get("flow_id") == attempt,
                    "Alchemy audit attempt identity unavailable")
                pair = pairs.setdefault(key, {"attempt": attempt})
                slot = "start" if kind == START else "terminal"
                require(slot not in pair and pair["attempt"] == attempt, "Alchemy audit attempt duplicated")
                pair[slot] = row["id"]
                if kind == START:
                    require(event.get("outcome") == "release_started", "Alchemy release start differs")
                else:
                    validation = event.get("response_validation", {})
                    require(type(event.get("upstream_status")) is int and event["upstream_status"] == item["upstreamStatus"],
                        "Alchemy response status audit differs")
                    if item["case"] in BLOCK_ERRORS:
                        # BLOCK commits request/operation/attempt + status/error;
                        # it does not promise a full blocked-response body hash.
                        require(kind == BLOCK and event.get("outcome") == "blocked" and validation.get("ok") is False
                            and validation.get("error") == BLOCK_ERRORS[item["case"]], "Alchemy response block audit differs")
                    else:
                        require(kind == RELEASE and event.get("outcome") == "released"
                            and event.get("response_body_sha256") == item["responseBodySha256"]
                            and type(event.get("response_body_bytes")) is int and event["response_body_bytes"] == item["responseBodyBytes"]
                            and validation.get("ok") is True and validation.get("body_bytes_preserved") is True
                            and validation.get("mode") == "alchemyRpcReadJsonV1", "Alchemy exact response release differs")
            elif kind == LEASE:
                self.validate_lease(event)
                dispatched |= event["purpose"] == "dispatchSecret"
            elif kind in {CONNECT, KEEP_ALIVE}:
                require(event.get("target") == HOST + ":443" and event.get("method") == "CONNECT"
                    and event.get("principal_id") == self.scope[0] and event.get("policy_hash") == self.scope[2]
                    and event.get("outcome") == ("established" if kind == CONNECT else "keep_alive")
                    and type(event.get("status_code")) is int and event["status_code"] == 200
                    and event.get("client_ip") == self.proxy.address, "Alchemy CONNECT scope differs")
                authority = dict(event)
                authority.pop("outcome")
                if kind == KEEP_ALIVE:
                    require(type(event.get("intercepted_request_count")) is int
                        and event["intercepted_request_count"] == 2, "Alchemy pooled request count differs")
                    authority.pop("intercepted_request_count")
                    kept[encoded(authority)] += 1
                else:
                    require("intercepted_request_count" not in event, "Alchemy initial CONNECT count differs")
                    established[encoded(authority)] += 1
            elif kind in {DENIED, CONNECT_DENIED}:
                require(any(row["id"] == item["id"] and kind == item["kind"] for item in self.denials),
                    "Alchemy denial lacks a separately observed control")
            elif kind == RELOAD:
                identity = (event.get("previous_policy_hash"), event.get("policy_hash"), event.get("policy_sequence"))
                require(identity in self.reloads and identity not in seen_reloads and event.get("routes") == 1,
                    "Alchemy reload differs from exact grant or revocation")
                seen_reloads.add(identity)
        require(counts[CONNECT] + counts[KEEP_ALIVE] <= self.intercepted
            and len({pair["attempt"] for pair in pairs.values()}) == len(pairs), "Alchemy tunnel or attempt reused")
        mutations = {(r["event_type"], r["event"].get("resource_id"), r["event"].get("policy_hash")) for r in rows}
        complete = (all(counts[k] == v for k, v in exact.items()) and len(pairs) == len(self.wire)
            and all({"start", "terminal"} <= pair.keys() for pair in pairs.values()) and dispatched
            and set(self.mutations) <= mutations and counts[CONNECT] + counts[KEEP_ALIVE] == self.intercepted
            and all(count <= established[authority] for authority, count in kept.items()))
        return complete, cutoff, {"namedAuditInventory": dict(sorted(counts.items())),
            "auditAttemptIds": sorted(pair["attempt"] for pair in pairs.values()),
            "proxyConnections": counts[CONNECT] + counts[CONNECT_DENIED], "pooledConnections": counts[KEEP_ALIVE]}

    def wait_audits(self, baseline):
        retained = None
        while True:
            self.stage("audit")
            events = self.audit()
            complete, cutoff, evidence = self.validate_audits(events, baseline)
            if retained is not None:
                require(all(cutoff.get(k) == v for k, v in retained.items())
                    and all(row["event_type"] == LEASE for row in events if row["id"] not in retained),
                    "Alchemy audit changed after complete checkpoint")
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
            and self.observe()["total"] == 0, "fresh pinned Alchemy catalog required")
        capability = initial.get("capabilities", {}).get("alchemy")
        require(type(capability) is dict and capability.get("connection_type") == "alchemy_key_v1"
            and capability.get("operation_bundles") == ["alchemy_chain_status_read_v1"]
            and capability.get("rpc_methods") == list(METHODS) and capability.get("source_pair_required") is True
            and capability.get("chains") == [{"chain": chain, "api_origin": "https://" + host, "destination_allowed": True}
                for chain, host in (("eth-mainnet", HOST), ("eth-sepolia", OTHER_HOST))], "paired Alchemy capability unavailable")
        self.policy_hash = initial_hash = initial["policy"]["policy_hash"]
        self.mark("setup", "policy")
        self.wait_catalog_loaded("initial")
        while not self.audit_drained():
            time.sleep(min(0.1, self.timeout()))
        baseline = features.audit_cutoff(self.audit())
        self.stage("mutation")
        credential, _, _ = self.mutate("/credentials/alchemy-key", {"name": self.run_id + "-alchemy", "secret": self.credential},
            collection="credentials", result_key="credential", event="operator_catalog.credential.alchemy_key_created", creates=True)
        apps = []
        for suffix in ("assigned", "unassigned"):
            self.stage("mutation")
            app, token, _ = self.mutate("/applications", {"name": self.run_id + "-" + suffix,
                "token_lifetime_seconds": 3600, "proxy_authentication": "basic_and_bearer_v1"},
                collection="applications", result_key="application", event="operator_catalog.application.created", creates=True, token=True)
            apps.append((app, token))
        app, token = apps[0]
        self.stage("mutation")
        rule, _, _ = self.mutate("/access-rules/alchemy-chain-status", {"name": self.run_id + "-read", "application_id": app["id"],
            "credential_id": credential["id"], "operation_bundle": "alchemy_chain_status_read_v1", "chain": "eth-mainnet"},
            collection="access_rules", result_key="access_rule", event="operator_catalog.access_rule.alchemy_chain_status_created",
            creates=True, authority_changed=True)
        self.wait_catalog_loaded("assigned")
        pins = self.warm_cas_snapshot()
        self.scope, self.credential_id = (app["principal_id"], rule["route_id"], self.policy_hash), credential["id"]
        require([len(pins[key]) for key in COLLECTIONS] == [1, 2, 1] and credential.get("credential_generation") == 1,
            "Alchemy saved resource inventory differs")
        self.reloads.append((initial_hash, self.policy_hash, pins["policy"]["sequence"]))
        for client in fixture.CLIENTS:
            self.mark("read", "authority", client, "read")
            self.unchanged(pins)
            self.example(client, "read", app, token)
            self.accept_arrivals(client, "success", METHODS)
        previous, _ = self.wait_audits(baseline)
        success_baseline = self.observe()
        for client in fixture.CLIENTS:
            for phase in ("wrong_app", "wrong_chain"):
                self.mark(phase, "authority", client, phase)
                self.unchanged(pins)
                self.example(client, phase, *(apps[1] if phase == "wrong_app" else apps[0]))
                previous = self.deny_checkpoint(previous, success_baseline, phase, client=client)
        for case in REQUEST_PROBES:
            self.mark("request_probe", "authority", "probe", case)
            self.unchanged(pins)
            self.raw_probe(case, app, token)
            previous = self.deny_checkpoint(previous, success_baseline, case)
        for case in RESPONSE_PROBES:
            self.mark("response_probe", "authority", "probe", case)
            self.unchanged(pins)
            headers = self.raw_probe(case, app, token)
            self.accept_arrivals("probe", case, ("eth_chainId",), headers)
        self.wait_audits(baseline)
        self.mark("revoke", "authority")
        self.unchanged(pins)
        last_hash = self.policy_hash
        self.stage("mutation")
        self.mutate("/access-rules/revoke", {"id": rule["id"]}, collection="access_rules", result_key="access_rule",
            event="operator_catalog.access_rule.revoked", authority_changed=True)
        self.wait_catalog_loaded("revoked")
        revoked = self.warm_cas_snapshot()
        require(self.resource(revoked, "access_rules", rule["id"])["status"] == "revoked"
            and self.resource(revoked, "credentials", credential["id"])["status"] == "active"
            and self.resource(revoked, "applications", app["id"])["token_status"] == "valid",
            "Alchemy grant revocation changed the credential or application token")
        self.reloads.append((last_hash, self.policy_hash, revoked["policy"]["sequence"]))
        previous, _ = self.wait_audits(baseline)
        revoked_baseline = self.observe()
        for client in fixture.CLIENTS:
            self.mark("revoked", "authority", client, "revoked")
            self.unchanged(revoked)
            self.example(client, "revoked", app, token)
            previous = self.deny_checkpoint(previous, revoked_baseline, "revoked", client=client)
        self.mark("final", "audit")
        _, evidence = self.wait_audits(baseline)
        self.stage("audit_chain")
        chain = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(chain.get("ok") is True and chain.get("complete") is True and chain.get("backend") == "sqlite",
            "Alchemy durable audit chain incomplete")
        require(self.observe() == revoked_baseline and len(self.wire) == 12 and self.intercepted == 17,
            "Alchemy final provider or request inventory differs")
        self.unchanged(revoked)
        self.stage("result")
        result = {"schema": SCHEMA, "ok": True, "syntheticOnly": True, "realAlchemyVerified": False,
            "productionReady": False, "publicDnsVerified": False, "actualExampleEntrypoints": True,
            "auditChainVerified": True, "separateOuterInnerTrust": True, **RESULT_COUNTS,
            "dataPlaneBinaryDigest": self.args.expected_binary_sha256, "goExampleSha256": self.args.expected_go_sha256,
            "exampleSourceSha256": self.example_sources, "completed": self.completed,
            "requests": [{k: v for k, v in row.items() if k != "observation"} for row in self.wire],
            "negativeControls": [{k: v for k, v in row.items() if k != "id"} for row in self.denials], **evidence}
        validate_success_result(result)
        return result


def validate_success_result(value):
    """Closed pure runner predicate, not a substitute for actual checker exit0."""
    fields = {"schema", "ok", "syntheticOnly", "realAlchemyVerified", "productionReady", "publicDnsVerified",
        "actualExampleEntrypoints", "auditChainVerified", "separateOuterInnerTrust", "dataPlaneBinaryDigest",
        "goExampleSha256", "exampleSourceSha256", "completed", "requests", "negativeControls",
        "namedAuditInventory", "auditAttemptIds", "proxyConnections", "pooledConnections", *RESULT_COUNTS}
    require(type(value) is dict and set(value) == fields and value["schema"] == SCHEMA
        and all(value[k] is True for k in ("ok", "syntheticOnly", "actualExampleEntrypoints", "auditChainVerified", "separateOuterInnerTrust"))
        and all(value[k] is False for k in ("realAlchemyVerified", "productionReady", "publicDnsVerified"))
        and all(type(value[k]) is int and value[k] == count for k, count in RESULT_COUNTS.items()), "Alchemy result contract differs")
    completed = value["completed"]
    require(type(completed) is list and len(completed) == 12
        and all(type(row) is dict and set(row) == {"client", "phase", "exitCode"} and type(row["exitCode"]) is int for row in completed)
        and Counter((r["client"], r["phase"], r["exitCode"]) for r in completed)
            == Counter((client, phase, 0 if phase == "read" else 1) for client in COMMANDS for phase in SDK_PHASES),
        "Alchemy actual SDK case inventory differs")
    requests = value["requests"]
    require(type(requests) is list and len(requests) == 12
        and all(type(row) is dict and set(row) == REQUEST_FIELDS for row in requests)
        and Counter((r["client"], r["case"], r["rpcMethod"]) for r in requests)
            == Counter([(client, "success", method) for client in COMMANDS for method in METHODS]
                + [("probe", case, "eth_chainId") for case in RESPONSE_PROBES]), "Alchemy response inventory differs")
    for row in requests:
        identifier = expected_id(row["client"], row["case"], row["rpcMethod"])
        require(type(row["requestId"]) is type(identifier) and row["requestId"] == identifier
            and all(type(row[k]) is str and SHA256.fullmatch(row[k]) for k in
                ("requestDigest", "operationDigest", "requestBodySha256", "responseBodySha256"))
            and type(row["upstreamStatus"]) is int and row["upstreamStatus"] == fixture.status(row["case"])
            and type(row["responseBodyBytes"]) is int
            and row["responseBodyBytes"] == len(fixture.body(row["case"], identifier, row["rpcMethod"]))
            and row["responseBodySha256"] == digest(fixture.body(row["case"], identifier, row["rpcMethod"])),
            "Alchemy result request/response commitments differ")
    require(len({r["requestDigest"] for r in requests}) == len({r["operationDigest"] for r in requests}) == 12,
        "Alchemy result canonical commitment reused")
    negative = value["negativeControls"]
    require(type(negative) is list and len(negative) == 14
        and all(type(row) is dict and set(row) == {"client", "phase", "kind"} for row in negative)
        and Counter((r["client"], r["phase"], r["kind"]) for r in negative)
            == Counter([(client, phase, CONNECT_DENIED) for client in COMMANDS for phase in SDK_PHASES[1:]]
                + [("probe", case, DENIED) for case in REQUEST_PROBES]), "Alchemy negative control inventory differs")
    expected_audit = {"operator_catalog.credential.alchemy_key_created": 1, "operator_catalog.application.created": 2,
        "operator_catalog.access_rule.alchemy_chain_status_created": 1, "operator_catalog.access_rule.revoked": 1,
        START: 12, RELEASE: 8, BLOCK: 4, DENIED: 5, CONNECT_DENIED: 9, RELOAD: 2}
    inventory = value["namedAuditInventory"]
    require(type(inventory) is dict and set(inventory) <= set(expected_audit) | {CONNECT, KEEP_ALIVE, LEASE}
        and all(type(item) is int and 1 <= item <= 64 for item in inventory.values())
        and all(inventory.get(kind) == count for kind, count in expected_audit.items())
        and 1 <= inventory.get(LEASE, 0) <= 64 and inventory.get(CONNECT) in {16, 17}
        and inventory.get(KEEP_ALIVE, 0) in {0, 1} and inventory[CONNECT] + inventory.get(KEEP_ALIVE, 0) == 17
        and type(value["proxyConnections"]) is int and value["proxyConnections"] == inventory[CONNECT] + 9
        and type(value["pooledConnections"]) is int and value["pooledConnections"] == inventory.get(KEEP_ALIVE, 0),
        "Alchemy exact audit/tunnel inventory differs")
    attempts = value["auditAttemptIds"]
    require(type(attempts) is list and len(attempts) == len(set(attempts)) == 12
        and all(type(item) is str and SHA256.fullmatch(item) for item in attempts)
        and type(value["dataPlaneBinaryDigest"]) is str and SHA256.fullmatch(value["dataPlaneBinaryDigest"])
        and type(value["goExampleSha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["goExampleSha256"])
        and type(value["exampleSourceSha256"]) is dict and set(value["exampleSourceSha256"]) == set(SOURCE_FILES)
        and all(type(item) is str and re.fullmatch(r"[0-9a-f]{64}", item) for item in value["exampleSourceSha256"].values()),
        "Alchemy result attempt, executable or source pins missing")
    return True


def failure_result(check, error):
    location = {"phase": "startup", "stage": "preflight", "client": None, "case": None}
    completed = []
    if check is not None:
        candidate = check.location
        if (type(candidate) is dict and set(candidate) == set(location) and candidate.get("phase") in PHASES
                and candidate.get("stage") in STAGES and candidate.get("client") in (None, *COMMANDS, "probe")
                and candidate.get("case") in (None, *SDK_PHASES, *REQUEST_PROBES, *RESPONSE_PROBES)):
            location = dict(candidate)
        completed = [{"client": row["client"], "phase": row["phase"], "exitCode": row["exitCode"]}
            for row in check.completed[:12] if type(row) is dict and row.get("client") in COMMANDS
            and row.get("phase") in SDK_PHASES and type(row.get("exitCode")) is int and row["exitCode"] in {0, 1}]
    category = "timeout" if isinstance(error, TimeoutError) else "check" if isinstance(error, CheckFailure) else "internal"
    return {"schema": SCHEMA, "ok": False, "syntheticOnly": True, "productionReady": False,
        "error": "checked-in Alchemy example acceptance failed", "failureCategory": category,
        "failureLocation": location, "completed": completed}


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
        raise CheckFailure("private Alchemy checker deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    try:
        require(30 <= args.timeout_seconds <= 180 and SHA256.fullmatch(args.expected_binary_sha256)
            and 1 <= args.expected_initial_revision <= 3, "Alchemy checker bounds invalid")
        signal.alarm(args.timeout_seconds)
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = ExamplesCheck(args)
        result = check.run()
        check.clean(encoded(result))
    except Exception as error:
        result = failure_result(check, error)
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
