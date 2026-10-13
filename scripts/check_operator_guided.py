#!/usr/bin/env python3
"""Fresh isolated actual UI → catalog → normal Rust → synthetic echo → UI revoke.

The browser's admitted HTTP bytes go to the real backend. No direct catalog
mutations, seeded resources, fake health, shell evaluation, or provider calls.
Private downloads/tokens travel only through bounded private stdio and memory.
The caller owns source/image isolation and the browser/container lifetime.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time
from urllib.parse import urlencode

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import operator_guided_browser as wire
from scripts.check_operator_catalog import OperatorCatalogCheck, TOKEN, claim_fixture, features
from scripts.check_operator_demo import AUTHORITY, CheckFailure, SHA256, require, token_file
from scripts.check_operator_live_smoke import response_evidence
from scripts.check_operator_ordinary_client import OrdinaryClientCheck, START, RELEASE, BLOCK, CONNECT, LEASE, RELOAD
from scripts.run_ordinary_regression import child_exit_status, stop_group
from scripts.run_operator_x_examples_fixture import failure_site

SCHEMA = "serverware.privateGuidedCheck/v1"
CONNECT_DENIED = "data_plane.connect.denied"
CURL_SHA256 = "0ca2b923679ab186f6512c7512e131a1c5c1b43d4cb5d55933998405b39e85bf"
CURL_TRAILER = b"\nserverware-guided-connect:"


def sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def emit(value):
    print(json.dumps(value, separators=(",", ":"), allow_nan=False), flush=True)


def failure_result(error, stage):
    return {"schema": SCHEMA, "ok": False, "error": "guided_check_failed", "stage": stage,
        "exceptionType": type(error).__name__,
        "failureSite": failure_site(error, Path(__file__).resolve().parents[1])}


def read_frame(fd, selector, buffer, deadline):
    while b"\n" not in buffer:
        remaining = deadline - time.monotonic()
        require(remaining > 0 and selector.select(remaining), "guided browser deadline expired")
        try:
            chunk = os.read(fd, wire.MAX_FRAME + 1 - len(buffer))
        except BlockingIOError:
            continue
        require(chunk, "guided browser stream ended early")
        buffer += chunk
        require(len(buffer) <= wire.MAX_FRAME, "guided browser frame exceeded bound")
    line, buffer = buffer.split(b"\n", 1)
    require(line and time.monotonic() < deadline, "guided browser deadline expired")
    return wire.document(line), buffer


def run_curl(arguments, private_input, seconds):
    """Owned fresh process group; leader remains unreaped until exact cleanup."""
    require(type(private_input) is bytes and len(private_input) <= 4096 and 0 < seconds <= 12,
            "guided curl input bound refused")
    deadline = time.monotonic() + seconds
    process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env={"LANG": "C", "LC_ALL": "C"}, close_fds=True, start_new_session=True)
    output = {"out": bytearray(), "err": bytearray()}
    try:
        process.stdin.write(private_input)
        process.stdin.close()
        with selectors.DefaultSelector() as selector:
            for stream, key in ((process.stdout, "out"), (process.stderr, "err")):
                selector.register(stream, selectors.EVENT_READ, key)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "guided curl deadline expired")
                for key, _ in selector.select(min(0.1, remaining)):
                    chunk = os.read(key.fd, 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output[key.data].extend(chunk)
                        require(len(output[key.data]) <= (98304 if key.data == "out" else 8192),
                                "guided curl output exceeded bound")
        while True:
            code = child_exit_status(process)
            if code is not None:
                return code, bytes(output["out"]), bytes(output["err"])
            require(time.monotonic() < deadline, "guided curl deadline expired")
            time.sleep(min(0.01, max(0.001, deadline - time.monotonic())))
    finally:
        try:
            stop_group(process)
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()


def exchange(check, frame, raw):
    connection = http.client.HTTPConnection(check.control.host, check.control.port, timeout=check.timeout())
    connection.connect = lambda: setattr(connection, "sock", check.control.connect(check.timeout(), check.control_ca))
    try:
        headers = {**frame["headers"], "Host": check.control.host, "Connection": "close",
            "Accept-Encoding": "identity", "X-Serverware-Admin-Token": check.admin_token}
        connection.request(frame["method"], frame["path"], body=raw if frame["method"] == "POST" else None,
                           headers=headers)
        response = connection.getresponse()
        body, pairs = response.read(wire.MAX_RESPONSE + 1), response.getheaders()
        require(0 < len(body) <= wire.MAX_RESPONSE and len(pairs) <= 64 and len(str(pairs)) <= 16384,
                "guided backend response exceeded bound")
        check.clean(str(pairs).encode())
        check.clean(body, allow_client_token=frame["path"] == wire.PREFIX + "/applications")
        mapped = {key.lower(): value for key, value in pairs}
        require(len(mapped) == len(pairs) and not set(mapped) & {
            "set-cookie", "location", "content-encoding", "transfer-encoding"}
            and "no-store" in mapped.get("cache-control", ""), "guided backend response headers refused")
        require(mapped.get("content-type", "").split(";", 1)[0] == (
            "text/html" if frame["path"] == "/" else "application/json"), "guided backend response media refused")
        return response.status, pairs, body
    finally:
        connection.close()


def audit_pairs(rows, scope, credential, observation):
    """One actual wire result joins one start/terminal by unique attempt ID."""
    pairs, identifiers = {}, set()
    for row in rows:
        kind, event = row["event_type"], row["event"]
        if kind not in {START, RELEASE, BLOCK}:
            continue
        require(kind != BLOCK and row["id"] not in identifiers, "guided response blocked or audit repeated")
        identifiers.add(row["id"])
        require(tuple(event.get(key) for key in ("principal_id", "route_id", "policy_hash")) == tuple(scope)
            and event.get("credential_ref") == credential and type(event.get("credential_version")) is int
            and event["credential_version"] == 1 and event.get("method") == "POST"
            and event.get("body_sha256") == sha(wire.BODY)
            and event.get("request_digest") == observation["requestDigest"]
            and event.get("operation_digest") == observation["operationDigest"], "guided audit request differs")
        attempt = event.get("attempt_id")
        require(type(attempt) is str and SHA256.fullmatch(attempt) and event.get("flow_id") == attempt,
                "guided audit attempt identity refused")
        pair = pairs.setdefault(attempt, {})
        require(kind not in pair, "guided audit attempt replayed")
        pair[kind] = row["id"]
        if kind == START:
            require(event.get("outcome") == "release_started", "guided audit start refused")
        else:
            validation = event.get("response_validation", {})
            require(event.get("outcome") == "released" and event.get("upstream_status") == 200
                and event.get("response_body_sha256") == observation["responseBodySha256"]
                and event.get("response_body_bytes") == observation["responseBodyBytes"]
                and validation.get("ok") is True and validation.get("mode") == "bufferedJsonOrEmpty204V2"
                and validation.get("body_bytes_preserved") is True, "guided audit terminal differs")
    require(len(pairs) <= 1, "guided extra provider attempt refused")
    return {key: value for key, value in pairs.items() if set(value) == {START, RELEASE}}


def validate_reload(event, initial_policy, granted_hash, revoked_hash):
    # The real empty policy retains operator.empty, so both publications have
    # one route. Authority identity, not route count, selects the transition.
    expected = {granted_hash: (initial_policy["policy_hash"], initial_policy["sequence"] + 1),
                revoked_hash: (granted_hash, initial_policy["sequence"] + 2)}
    actual = expected.get(event.get("policy_hash"))
    require(actual is not None and type(event.get("routes")) is int and event["routes"] == 1
        and event.get("previous_policy_hash") == actual[0]
        and type(event.get("policy_sequence")) is int and event["policy_sequence"] == actual[1],
        "guided policy reload identity differs")


class GuidedCheck(OperatorCatalogCheck):
    audit_drained = OrdinaryClientCheck.audit_drained

    def __init__(self, args):
        super().__init__(args)
        self.protocol = wire.Protocol(self.run_id, self.credential)
        self.phase = "preflight"
        self.resource_rows = {}
        self.responses = []
        self.mutation_audits = {}
        self.config = None
        self.basic_secret = None
        require(args.operator_origin == wire.ORIGIN and args.proxy_url == wire.PROXY
            and args.control_base == "http://127.0.0.1:3000"
            and args.management_base == "http://127.0.0.1:9091"
            and self.proxy.address == "127.0.0.1" and self.upstream.address == "127.0.0.2"
            and str(args.ca_file) == wire.CA_PATH, "guided isolated endpoint selection refused")
        path = args.curl_binary
        info = path.lstat()
        require(path.is_absolute() and path.resolve() == path and stat.S_ISREG(info.st_mode)
            and info.st_size <= 67108864 and args.expected_curl_sha256 == CURL_SHA256
            and hashlib.sha256(path.read_bytes()).hexdigest() == CURL_SHA256, "guided cached curl differs")
        self.body_file = args.run_claim_file.parent / ".guided-request.json"
        fd = os.open(self.body_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(wire.BODY)

    def clean(self, content, *, allow_client_token=False):
        super().clean(content, allow_client_token=allow_client_token)
        value = getattr(self, "basic_secret", None)
        require(value is None or value.encode() not in content, "guided proxy secret escaped")

    def count(self):
        status, value = self.json_request(self.upstream, "/_test/request-count?" +
            urlencode({"method": "POST", "path": "/echo"}), context=self.upstream_ca)
        require(status == 200 and type(value.get("count")) is int
            and value["count"] == self.upstream_count("POST"), "guided provider count differs")
        for method in ("GET", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
            other_status, other = self.json_request(self.upstream, "/_test/request-count?" +
                urlencode({"method": method, "path": "/echo"}), context=self.upstream_ca)
            require(other_status == 200 and type(other.get("count")) is int and other["count"] == 0
                and self.upstream_count(method) == 0, "guided unexpected upstream method")
        return value["count"]

    def retain_mutation(self, before, frame, status, body):
        index = {route: number for number, route in enumerate(wire.ROUTES)}[
            frame["path"].removeprefix(wire.PREFIX).removesuffix("/revoke")]
        revoke = frame["path"].endswith("/revoke")
        require(status == (200 if revoke else 201), "guided UI mutation failed")
        result = wire.document(body)
        token = result.pop("client_token", None)
        require((type(token) is str and TOKEN.fullmatch(token)) if index == 1 and not revoke else token is None,
                "guided one-time app token contract refused")
        if token is not None:
            self.client_token = token
            self.issued_tokens.append(token)
        self.clean(wire.encoded(result))
        resource = result.get(wire.KINDS[index], {})
        require(type(resource.get("id")) is str and wire.UUID.fullmatch(resource["id"])
            and type(resource.get("version")) is int and resource["version"] == (2 if revoke else 1)
            and resource.get("status") == ("revoked" if revoke else "active")
            and type(result.get("revision")) is int and result["revision"] == before["revision"] + 1,
            "guided persisted mutation identity differs")
        name = ("credential", "application", "rule")[index]
        require(resource["name"] == self.protocol.names[name]
            and (not revoke or resource["id"] == self.protocol.identifiers[name]), "guided resource ownership differs")
        self.protocol.identifiers[name] = resource["id"]
        policy = result["policy"]
        changed = index == 2
        require(type(policy.get("sequence")) is int and policy["sequence"] == before["policy"]["sequence"] + int(changed)
            and type(policy.get("policy_hash")) is str and SHA256.fullmatch(policy["policy_hash"])
            and (policy["policy_hash"] != before["policy"]["policy_hash"] if changed
                 else policy["policy_hash"] == before["policy"]["policy_hash"]), "guided policy publication differs")
        event = "operator_catalog." + wire.KINDS[index] + (".revoked" if revoke else ".created")
        expected_audit = {"resource_type": wire.KINDS[index], "resource_id": resource["id"],
            "revision": result["revision"], "policy_hash": policy["policy_hash"], "policy_sequence": policy["sequence"]}
        if index == 1:
            expected_audit.update(token_generation=1, token_expires_at_epoch_ms=resource["token_expires_at_epoch_ms"])
        elif index == 2:
            expected_audit.update(application_id=resource["application_id"], credential_id=resource["credential_id"])
        self.mutation_audits[event] = expected_audit
        self.finalize_mutation(result, self.catalog(), collection=wire.COLLECTIONS[index],
                               result_key=wire.KINDS[index], event=event)
        self.responses.append({"route": frame["path"], "status": status, "revision": result["revision"],
                               "resourceId": resource["id"], "policyHash": policy["policy_hash"]})

    def dispatch(self, *, denied=False):
        config = self.config
        require(config is not None and self.count() == (1 if denied else 0), "guided proxy phase count differs")
        require({item[4][0] for item in socket.getaddrinfo(self.proxy.host, 443, type=socket.SOCK_STREAM)}
                == {self.proxy.address}, "guided proxy DNS mapping changed")
        token = config["proxy_password"]
        require(re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is not None, "guided app token shape refused")
        self.basic_secret = base64.b64encode((config["proxy_username"] + ":" + token).encode()).decode()
        target = config["upstream_url"] + "?" + urlencode({"expectedAuthorizationSha256": sha(("Bearer " + self.credential).encode())})
        arguments = [str(self.args.curl_binary), "-q", "--config", "-", "--silent", "--show-error",
            "--proxy-basic", "--proxy", config["proxy_url"], "--noproxy", "", "--proxy-cacert", str(self.args.proxy_ca_file),
            "--cacert", config["ca_file"], "--proto", "=https", "--proto-redir", "=https", "--http1.1",
            "--connect-timeout", "3", "--max-time", "8", "--retry", "0", "--max-filesize", "65536",
            "--raw", "--include", "--suppress-connect-headers", "--request", config["methods"][0],
            "--data-binary", "@" + str(self.body_file), "--header", "Authorization: " + config["request_headers"]["Authorization"],
            "--header", "Content-Type: application/json", "--header", "Accept: application/json",
            "--header", "Accept-Encoding: identity", "--header", "Connection: close",
            "--header", "User-Agent: serverware-test-run/" + self.run_id,
            "--write-out", "\nserverware-guided-connect:%{http_connect}\nserverware-guided-status:%{http_code}\n", target]
        private_input = ('proxy-user = "' + config["proxy_username"] + ":" + token + '"\n').encode()
        code, output, error = run_curl(arguments, private_input, min(12, self.deadline - time.monotonic()))
        self.clean(output); self.clean(error)
        content, separator, trailer = output.rpartition(CURL_TRAILER)
        match = re.fullmatch(rb"([0-9]{3})\nserverware-guided-status:([0-9]{3})\n", trailer)
        require(separator and match, "guided curl status unavailable")
        connect, status = (int(value) for value in match.groups())
        if denied:
            require(code == 56 and connect == 403 and status == 0 and not content and self.count() == 1,
                    "guided revoked rule did not deny without arrival")
            return {"outcome": "denied", "connectStatus": 403, "providerArrivals": 0}
        require(code == 0 and not error and connect == 200 and status == 200 and self.count() == 1,
                "guided stock proxy request failed")
        head, separator, body = content.partition(b"\r\n\r\n")
        require(separator and len(head) <= 16384 and head.startswith(b"HTTP/1.1 200 "), "guided response framing differs")
        headers = []
        for line in head.split(b"\r\n")[1:]:
            name, colon, value = line.partition(b":")
            require(colon and name and len(line) <= 4096, "guided response header refused")
            headers.append((name.decode("ascii"), value.decode("ascii").strip()))
        mapped = {name.lower(): value for name, value in headers}
        require(len(mapped) == len(headers) and not set(mapped) & {"transfer-encoding", "trailer"}
                and mapped.get("content-length") == str(len(body)), "guided response boundary differs")
        return response_evidence("positive", status, headers, body, self.policy_hash)

    def settled(self):
        while not self.audit_drained():
            time.sleep(min(0.1, self.timeout()))
        return self.audit()

    def verify_audit(self):
        rows = self.settled()
        cutoff = features.audit_cutoff(rows)
        require(all(cutoff.get(key) == value for key, value in self.baseline.items()), "guided initial audit changed")
        added = [row for row in rows if row["id"] not in self.baseline]
        counts = Counter(row["event_type"] for row in added)
        expected = Counter({event: 1 for event, _, _ in self.mutations})
        expected.update({START: 1, RELEASE: 1, CONNECT: 1, CONNECT_DENIED: 1, RELOAD: 2})
        require(set(counts) <= set(expected) | {LEASE} and all(counts[key] == count for key, count in expected.items()),
                "guided exact audit event inventory differs")
        actual = {(row["event_type"], row["event"].get("resource_id"), row["event"].get("policy_hash")) for row in added}
        require(set(self.mutations) <= actual, "guided UI mutation audit binding differs")
        pairs = audit_pairs(added, self.scope, self.protocol.identifiers["credential"], self.positive)
        require(len(pairs) == 1, "guided actual request lacks complete audit pair")
        leases = Counter()
        for row in added:
            kind, event = row["event_type"], row["event"]
            if kind in self.mutation_audits:
                require(wire.encoded(event) == wire.encoded(self.mutation_audits[kind]), "guided mutation audit fields differ")
            elif kind == LEASE:
                require(tuple(event.get(key) for key in ("principal_id", "route_id", "policy_hash")) == self.scope
                    and event.get("credential_id") == self.protocol.identifiers["credential"]
                    and event.get("purpose") in {"generationMetadata", "dispatchSecret"}
                    and event.get("data_plane_binary_digest") == self.args.expected_binary_sha256
                    and (event.get("expected_credential_version") is None if event["purpose"] == "generationMetadata"
                         else type(event.get("expected_credential_version")) is int and event["expected_credential_version"] == 1)
                    and event.get("outcome") == "issued" and event.get("status_code") == 200,
                    "guided lease escaped authorized scope")
                leases[event["purpose"]] += 1
            elif kind in {CONNECT, CONNECT_DENIED}:
                require(event.get("method") == "CONNECT" and event.get("target") == AUTHORITY
                    and event.get("policy_hash") == (self.scope[2] if kind == CONNECT else self.policy_hash)
                    and (kind != CONNECT or event.get("principal_id") == self.scope[0])
                    and event.get("outcome") == ("established" if kind == CONNECT else "denied"),
                    "guided CONNECT audit differs")
            elif kind == RELOAD:
                validate_reload(event, self.initial["policy"], self.scope[2], self.policy_hash)
        require(leases["dispatchSecret"] >= 1 and sum(leases.values()) <= 32, "guided lease bounds differ")
        chain = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(chain.get("ok") is True and chain.get("complete") is True and chain.get("backend") == "sqlite",
                "guided durable audit chain failed")
        require(features.audit_cutoff(self.settled()) == cutoff, "guided audit changed after final verification")
        return {"eventCounts": dict(sorted(counts.items())), "eventIds": sorted(row["id"] for row in added),
            "attemptIds": sorted(pairs), "chainVerified": True}

    def checkpoint(self, frame):
        phase = frame["phase"]
        current, _ = self.wait_catalog_loaded(phase)
        require(all(len(current[key]) == 1 for key in wire.COLLECTIONS), "guided resource inventory differs")
        if phase == "configured":
            credential, application, rule = (current[key][0] for key in wire.COLLECTIONS)
            require(all(row["status"] == "active" and row["version"] == 1 for row in (credential, application, rule))
                and credential["auth_type"] == "bearer" and credential["header_name"] == "Authorization"
                and application["principal_id"] == "agent:operator-demo:" + application["id"]
                and application["proxy_authentication"] == "basic_and_bearer_v1"
                and application["token_generation"] == 1 and application["token_status"] == "valid"
                and application["active_rule_count"] == 1 and application["access_status"] == "active"
                and rule["enforcement"] == "active"
                and all(wire.encoded(rule.get(key)) == wire.encoded(value) for key, value in wire.rule_values(
                    self.protocol.names["rule"], application["id"], credential["id"]).items()),
                "guided real saved permission differs")
            self.config = wire.private_configuration(wire.decode(frame["configuration"], 16384), application, rule, self.client_token)
            self.scope = (application["principal_id"], rule["route_id"], self.policy_hash)
            self.positive = self.dispatch()
            self.settled()
            self.protocol.phase = "revoke_rule"
        elif phase == "rule_revoked":
            require(current["access_rules"][0]["status"] == "revoked"
                and current["access_rules"][0]["enforcement"] == "revoked"
                and current["applications"][0]["status"] == current["credentials"][0]["status"] == "active",
                "guided rule revocation not loaded")
            baseline = features.audit_cutoff(self.settled())
            self.negative = self.dispatch(denied=True)
            new = [row for row in self.settled() if row["id"] not in baseline]
            require(Counter(row["event_type"] for row in new) == {CONNECT_DENIED: 1},
                    "guided revoked request produced more than its CONNECT denial")
            self.protocol.phase = "revoke_rest"
        else:
            wire.validate_browser(frame["browser"], get_count=self.protocol.gets)
            require(current["revision"] == self.initial["revision"] + 6
                and current["policy"]["sequence"] == self.initial["policy"]["sequence"] + 2
                and all(row["status"] == "revoked" and row["version"] == 2
                    for key in wire.COLLECTIONS for row in current[key])
                and current["applications"][0]["token_generation"] == 1
                and current["applications"][0]["token_status"] == "revoked" and self.count() == 1,
                "guided retained revocation state differs")
            self.phase = "audit"
            audit = self.verify_audit()
            result = {"schema": SCHEMA, "ok": True, "syntheticOnly": True, "realProviderVerified": False,
                "publicDnsVerified": False, "externalSsoVerified": False, "productionReady": False,
                "hardwareVerified": False, "runId": self.run_id, "dataPlaneBinaryDigest": self.args.expected_binary_sha256,
                "resourceIds": self.protocol.identifiers, "initialRevision": self.initial["revision"],
                "finalRevision": current["revision"], "initialPolicyHash": self.initial["policy"]["policy_hash"],
                "policyHash": self.policy_hash, "providerArrivals": 1, "proxyAttempts": 2,
                "mutations": self.responses, "positive": self.positive, "negative": self.negative,
                "audit": audit, "browser": frame["browser"]}
            validate_success_result(result)
            return result
        emit({"kind": "continue", "id": frame["id"], "phase": self.protocol.phase,
              "resourceIds": self.protocol.identifiers})
        return None

    def run(self):
        self.health()
        self.admin_token = token_file(self.args.admin_token_file)
        # The real separate-resource catalog deliberately refuses legacy status.
        # catalog() independently validates the ordinary profile and destinations.
        self.initial = self.catalog()
        require(self.initial["revision"] == 1 and all(not self.initial[key] for key in wire.COLLECTIONS)
            and self.initial["proxy_url"] == wire.PROXY and self.count() == 0, "guided fixture is not fresh")
        self.policy_hash = self.initial["policy"]["policy_hash"]
        self.wait_catalog_loaded("initial")
        self.baseline = features.audit_cutoff(self.settled())
        emit(self.protocol.ready(self.initial))
        fd, buffer = sys.stdin.fileno(), b""
        blocking = os.get_blocking(fd)
        os.set_blocking(fd, False)
        try:
            with selectors.DefaultSelector() as selected:
                selected.register(fd, selectors.EVENT_READ)
                while True:
                    frame, buffer = read_frame(fd, selected, buffer, self.deadline)
                    self.phase = self.protocol.phase
                    current = self.catalog() if frame.get("method") == "POST" else self.snapshot
                    raw = self.protocol.admit(frame, current)
                    if raw is None:
                        result = self.checkpoint(frame)
                        if result is not None:
                            return result
                        continue
                    status, headers, body = exchange(self, frame, raw)
                    if frame["method"] == "POST":
                        self.retain_mutation(current, frame, status, body)
                    else:
                        require(status == 200, "guided UI read failed")
                    emit({"kind": "response", "id": frame["id"], "status": status, "headers": headers,
                          "body": base64.b64encode(body).decode("ascii")})
        finally:
            os.set_blocking(fd, blocking)


def validate_success_result(value):
    fields = {"schema", "ok", "syntheticOnly", "realProviderVerified", "publicDnsVerified", "externalSsoVerified",
        "productionReady", "hardwareVerified", "runId", "dataPlaneBinaryDigest", "resourceIds", "initialRevision",
        "finalRevision", "initialPolicyHash", "policyHash", "providerArrivals", "proxyAttempts", "mutations",
        "positive", "negative", "audit", "browser"}
    require(type(value) is dict and set(value) == fields and value["schema"] == SCHEMA
        and value["ok"] is True and value["syntheticOnly"] is True
        and all(value[key] is False for key in ("realProviderVerified", "publicDnsVerified", "externalSsoVerified", "productionReady", "hardwareVerified"))
        and type(value["initialRevision"]) is int and value["initialRevision"] == 1
        and type(value["finalRevision"]) is int and value["finalRevision"] == 7
        and type(value["providerArrivals"]) is int and value["providerArrivals"] == 1
        and type(value["proxyAttempts"]) is int and value["proxyAttempts"] == 2
        and len(value["mutations"]) == 6 and value["positive"]["status"] == 200
        and value["negative"] == {"outcome": "denied", "connectStatus": 403, "providerArrivals": 0}
        and len(value["audit"]["attemptIds"]) == 1 and value["audit"]["chainVerified"] is True,
        "guided terminal receipt refused")
    require(set(value["resourceIds"]) == {"credential", "application", "rule"}
        and all(type(item) is str and wire.UUID.fullmatch(item) for item in value["resourceIds"].values())
        and len(set(value["resourceIds"].values())) == 3
        and all(type(value[key]) is str and SHA256.fullmatch(value[key]) for key in ("initialPolicyHash", "policyHash", "dataPlaneBinaryDigest")),
        "guided terminal identity refused")
    require(type(value["runId"]) is str and re.fullmatch(r"operator-check-[0-9a-f]{32}", value["runId"])
        and value["initialPolicyHash"] != value["policyHash"], "guided terminal run refused")
    positive = value["positive"]
    require(type(positive) is dict and set(positive) == {"case", "status", "responseMode", "responseBodySha256",
        "responseBodyBytes", "requestDigest", "operationDigest"} and positive["case"] == "positive"
        and type(positive["status"]) is int and positive["status"] == 200
        and positive["responseMode"] == "unfiltered_json_or_empty_v2"
        and type(positive["responseBodyBytes"]) is int and 0 < positive["responseBodyBytes"] <= 65536
        and all(type(positive[key]) is str and SHA256.fullmatch(positive[key]) for key in
            ("responseBodySha256", "requestDigest", "operationDigest")), "guided terminal response refused")
    require(wire.encoded(value["negative"]) == wire.encoded({"outcome": "denied", "connectStatus": 403, "providerArrivals": 0}),
            "guided terminal denial refused")
    order = ((0, False), (1, False), (2, False), (2, True), (1, True), (0, True))
    require(type(value["mutations"]) is list, "guided mutation receipts refused")
    for ordinal, (item, (index, revoke)) in enumerate(zip(value["mutations"], order), 2):
        require(type(item) is dict and set(item) == {"route", "status", "revision", "resourceId", "policyHash"}
            and item["route"] == wire.PREFIX + wire.ROUTES[index] + ("/revoke" if revoke else "")
            and type(item["status"]) is int and item["status"] == (200 if revoke else 201)
            and type(item["revision"]) is int and item["revision"] == ordinal
            and item["resourceId"] == value["resourceIds"][("credential", "application", "rule")[index]]
            and type(item["policyHash"]) is str and SHA256.fullmatch(item["policyHash"]),
            "guided mutation receipt identity refused")
    hashes = [item["policyHash"] for item in value["mutations"]]
    require(hashes[:2] == [value["initialPolicyHash"]] * 2
        and hashes[2] not in {value["initialPolicyHash"], value["policyHash"]}
        and hashes[3:] == [value["policyHash"]] * 3, "guided receipt publication sequence refused")
    audit = value["audit"]
    require(type(audit) is dict and set(audit) == {"eventCounts", "eventIds", "attemptIds", "chainVerified"}
        and type(audit["eventCounts"]) is dict and type(audit["eventIds"]) is list
        and 10 <= len(audit["eventIds"]) <= 100 and len(set(audit["eventIds"])) == len(audit["eventIds"])
        and all(type(item) is str and (wire.UUID.fullmatch(item) or SHA256.fullmatch(item)) for item in audit["eventIds"])
        and type(audit["attemptIds"]) is list and len(audit["attemptIds"]) == 1
        and type(audit["attemptIds"][0]) is str and SHA256.fullmatch(audit["attemptIds"][0]),
        "guided terminal audit identity refused")
    expected = {"operator_catalog." + wire.KINDS[index] + (".revoked" if revoke else ".created"): 1
                for index, revoke in order}
    expected.update({START: 1, RELEASE: 1, CONNECT: 1, CONNECT_DENIED: 1, RELOAD: 2})
    require(set(audit["eventCounts"]) == set(expected) | {LEASE}
        and all(type(audit["eventCounts"][key]) is int and audit["eventCounts"][key] == count for key, count in expected.items())
        and type(audit["eventCounts"][LEASE]) is int and 1 <= audit["eventCounts"][LEASE] <= 32
        and sum(audit["eventCounts"].values()) == len(audit["eventIds"]), "guided terminal audit inventory refused")
    wire.validate_browser(value["browser"])


def validate_joined_result(value):
    require(type(value) is dict and set(value) == {"schema", "ok", "browserClosed", "browser", "checker"}
        and value["schema"] == wire.JOINED_SCHEMA and value["ok"] is True and value["browserClosed"] is True,
        "guided browser joined receipt refused")
    validate_success_result(value["checker"])
    require(wire.encoded(value["browser"]) == wire.encoded(value["checker"]["browser"]), "guided browser receipts differ")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256", "expected-curl-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file", "run-claim-file", "curl-binary"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("proxy-ca-file", "control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--upstream-address")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()
    check = None
    def expired(*_):
        raise CheckFailure("guided original process deadline expired")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 180)
    try:
        require(args.timeout_seconds == 180 and SHA256.fullmatch(args.expected_binary_sha256), "guided original bounds refused")
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = GuidedCheck(args)
        result = check.run()
    except Exception as error:
        result = failure_result(error, check.phase if check is not None else "preflight")
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    emit({"kind": "result", "result": result})
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
