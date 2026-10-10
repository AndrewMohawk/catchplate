#!/usr/bin/env python3
"""One-shot PRIVATE normal-gate acceptance for stock HTTPS-proxy clients.

Requests uses its unchanged Session/adapters and proxy-URL username/password.
Curl uses --proxy-basic and its proxy-user option, supplied through stdin (not
argv). Neither client is taught to manufacture a Proxy-Authorization header.
Distinct throwaway outer/inner CAs are required. Stock Requests uses one scoped
two-root bundle, NOT separate per-layer trust stores; curl has separate stores.
Fresh API tokens cannot naturally expire within this run: that proof is OPEN.
No real provider, deployment, system trust changes, mutation retries or OAuth.
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
import secrets
import selectors
import signal
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import quote, urlsplit
import uuid

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import requests
import urllib3

from scripts.check_operator_catalog import COLLECTIONS, PREFIX, claim_fixture, features
from scripts.check_operator_demo import AUTHORITY, SHA256, CheckFailure, TunnelTLS, require, token_file
from scripts.check_operator_key_replacement import authority_projection, joined_attempts
from scripts.check_operator_ordinary_client import (
    BLOCK, CONNECT, LEASE, RELEASE, RELOAD, START, CapturedTLS, OrdinaryClientCheck,
    V2_RESPONSE_MODE, check_response, digest,
)
from scripts.operator_ordinary_client_fixture import (
    DUMMY_AUTHORIZATION, FIXTURE_PATH, QUERY_KEYS, REQUEST_BODY, V2_RESPONSE_METADATA, build_target,
)
from scripts.operator_proxy_basic_tls import PROXY_HOST, PROXY_PORT

PROXY = f"https://{PROXY_HOST}:{PROXY_PORT}"
CONNECT_DENIED = "data_plane.connect.denied"
BASIC = "basic_and_bearer_v1"
FIXTURE_CASE = "json_proxy_basic_v1"
ACCEPT = {"requests": "application/json", "curl": "application/json;q=0.9",
          "bearer_opt_in": "application/json;q=0.8", "bearer_default": "application/json;q=0.7"}
MAX_OUTPUT = 98304
MAX_ERROR = 8192
CURL_TRAILER = b"\nserverware-check-connect:"
PEM = re.compile(rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----")


def certificate_blocks(path):
    require(path.is_absolute() and path.resolve() == path and path.is_file()
            and path.stat().st_size <= 32768, "explicit bounded public CA file required")
    value = path.read_bytes()
    blocks = PEM.findall(value)
    require(blocks and not PEM.sub(b"", value).strip(), "CA file contains unexpected material")
    return [ssl.PEM_cert_to_DER_cert(block.decode("ascii")) for block in blocks]


def require_ca_pair(outer, inner, combined):
    edge, origin, roots = (certificate_blocks(path) for path in (outer, inner, combined))
    require(len(edge) == len(origin) == 1 and edge[0] != origin[0]
            and len(roots) == 2 and set(roots) == {edge[0], origin[0]},
            "Requests bundle must contain exactly the distinct outer and inner roots")
    return {"outerCaSha256": hashlib.sha256(edge[0]).hexdigest(),
            "innerCaSha256": hashlib.sha256(origin[0]).hexdigest(),
            "requestsTrustStores": "one-scoped-bundle-with-two-distinct-roots"}


def exception_tree(error):
    """Bounded inspection only; never stringify an exception containing a URL."""
    pending, seen = [error], set()
    while pending and len(seen) < 32:
        item = pending.pop()
        if not isinstance(item, BaseException) or id(item) in seen:
            continue
        seen.add(id(item))
        yield item
        pending.extend(value for value in item.args if isinstance(value, BaseException))
        pending.extend(getattr(item, name, None) for name in
                       ("__cause__", "__context__", "reason", "original_error"))


def require_requests_failure(error, expected):
    chain = list(exception_tree(error))
    if expected == "tls":
        require(any(isinstance(item, ssl.SSLCertVerificationError) for item in chain),
                "Requests did not fail at certificate verification")
    else:
        require(expected == "denied" and isinstance(error, requests.exceptions.ProxyError)
                and any(isinstance(item, OSError) and item.args and isinstance(item.args[0], str)
                        and re.fullmatch(r"Tunnel connection failed: 403(?: [^\r\n]{0,128})?", item.args[0])
                        for item in chain), "Requests did not observe a CONNECT 403")


def bounded_process(arguments, data, seconds):
    """No shell, credentials in argv, inherited proxy env, or unbounded output."""
    require(isinstance(data, bytes) and len(data) <= 4096 and 0 < seconds <= 10,
            "curl input or deadline exceeds bound")
    deadline = time.monotonic() + seconds
    process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env={"LANG": "C", "LC_ALL": "C"}, close_fds=True)
    output = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        process.stdin.write(data)
        process.stdin.close()
        with selectors.DefaultSelector() as selected:
            for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                selected.register(stream, selectors.EVENT_READ, name)
            while selected.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "curl process deadline exceeded")
                for key, _ in selected.select(min(remaining, 0.25)):
                    chunk = os.read(key.fd, 16384)
                    if not chunk:
                        selected.unregister(key.fileobj)
                        continue
                    result = output[key.data]
                    require(len(result) + len(chunk) <= (MAX_OUTPUT if key.data == "stdout" else MAX_ERROR),
                            "curl output exceeds private checker bound")
                    result.extend(chunk)
        code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        return code, bytes(output["stdout"]), bytes(output["stderr"])
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def parsed_response(status, headers, body, policy_hash):
    """Requests' parsed physical fields/raw body, not invented raw HTTP bytes."""
    require(len(headers) <= 64 and len(str(headers).encode("utf-8")) <= 16384,
            "Requests response headers exceed bounds")
    fields = [(name.lower(), value) for name, value in headers]
    require(all(isinstance(name, str) and isinstance(value, str) for name, value in fields)
            and len({name for name, _ in fields}) == len(fields), "Requests response headers ambiguous")
    values = dict(fields)
    require(status == 200 and body == REQUEST_BODY
            and values.get("content-type") == "application/json"
            and values.get("content-length") == str(len(REQUEST_BODY))
            and not set(values).intersection({"content-encoding", "transfer-encoding", "trailer"})
            and not any(name in values for name, _ in V2_RESPONSE_METADATA),
            "Requests exact JSON response or framing differs")
    require(values.get("x-serverware-policy-hash") == policy_hash
            and values.get("x-serverware-response-body-sha256") == digest(body),
            "Requests policy or response-body commitment differs")
    commitments = {"requestDigest": values.get("x-serverware-request-digest"),
                   "operationDigest": values.get("x-serverware-operation-digest")}
    require(all(isinstance(value, str) and SHA256.fullmatch(value) for value in commitments.values()),
            "Requests request commitments unavailable")
    return {"case": "json", "status": status, "responseMode": V2_RESPONSE_MODE,
            "responseBodySha256": digest(body), "responseBodyBytes": len(body),
            "headerEvidence": "client-parsed-fields", "rawWireFramingVerified": False, **commitments}


class ProxyBasicCheck(OrdinaryClientCheck):
    def __init__(self, args):
        self.sensitive_proxy_forms = []
        super().__init__(args)
        require(args.proxy_url == PROXY and self.proxy.scheme == "https",
                "the private certificate-verified HTTPS proxy hostname is required")
        self.ca_evidence = require_ca_pair(args.proxy_ca_file, args.ca_file, args.requests_ca_file)
        self.expected_connects = self.expected_denials = 0
        self.trust_controls = []
        self.negative_cutoffs = []
        self.wrong_basic_token = secrets.token_urlsafe(32)
        self.sensitive_proxy_forms.append(self.wrong_basic_token)
        path = args.curl_binary
        require(path.is_absolute() and path.resolve() == path and path.is_file()
                and path.stat().st_size <= 67108864, "explicit bounded cached curl executable required")
        self.curl_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.body_file = args.run_claim_file.parent / ".operator-proxy-basic-body.json"
        with self.body_file.open("xb") as target:
            os.chmod(self.body_file, 0o600)
            target.write(REQUEST_BODY)
        require(self.body_file.read_bytes() == REQUEST_BODY, "fixed curl input differs")

    def clean(self, content, *, allow_client_token=False):
        super().clean(content, allow_client_token=allow_client_token)
        require(all(value.encode("ascii") not in content for value in self.sensitive_proxy_forms),
                "proxy authentication material escaped into evidence")

    def credentials(self, username, token):
        require(str(uuid.UUID(username)) == username and re.fullmatch(r"[A-Za-z0-9_-]{43}", token),
                "ordinary proxy credentials must have the signed canonical shape")
        # Encoding here is exclusively a leak detector; neither client receives
        # this manufactured header. Their normal authentication handles encoding.
        self.sensitive_proxy_forms.extend([token, base64.b64encode((username + ":" + token).encode()).decode()])
        return username, token

    def fixed_proxy_resolution(self):
        addresses = {item[4][0] for item in socket.getaddrinfo(PROXY_HOST, PROXY_PORT, type=socket.SOCK_STREAM)}
        require(addresses == {self.proxy.address}, "private proxy name mapping changed")

    def target(self):
        return "https://" + AUTHORITY + build_target(FIXTURE_CASE,
            hashlib.sha256(("Bearer " + self.credential).encode("ascii")).hexdigest())

    def request_headers(self, accept):
        return {"Authorization": DUMMY_AUTHORIZATION, "Content-Type": "application/json",
                "User-Agent": "serverware-test-run/" + self.run_id, "Accept": accept,
                "Accept-Encoding": "identity", "Connection": "close"}

    def requests_call(self, username, token, *, expected="success", ca=None):
        self.fixed_proxy_resolution()
        username, token = self.credentials(username, token)
        proxy = f"https://{quote(username, safe='')}:{quote(token, safe='')}@{PROXY_HOST}:{PROXY_PORT}"
        self.sensitive_proxy_forms.append(proxy)
        # Ordinary configuration only: no subclass, mounted custom adapter,
        # monkeypatch, custom CONNECT, or manually supplied proxy header.
        with requests.Session() as session:
            session.trust_env = False
            session.proxies = {"https": proxy}
            session.verify = str(ca or self.args.requests_ca_file)
            require(all(adapter.max_retries.total == 0 for adapter in session.adapters.values()),
                    "stock Requests retry defaults differ")
            try:
                with session.post(self.target(), data=REQUEST_BODY, headers=self.request_headers(ACCEPT["requests"]),
                        timeout=(min(3.0, self.timeout()), min(5.0, self.timeout())),
                        allow_redirects=False, stream=True) as response:
                    require(expected == "success", "Requests negative case unexpectedly reached an origin response")
                    prepared = response.request
                    require(prepared.url == self.target() and prepared.method == "POST"
                            and prepared.body == REQUEST_BODY
                            and not any(name.lower() == "proxy-authorization" for name in prepared.headers),
                            "stock Requests changed the target/body or installed origin proxy credentials")
                    body = response.raw.read(65537, decode_content=False)
                    fields = list(response.raw.headers.iteritems())
                    self.clean(body)
                    self.clean(str(fields).encode("utf-8"))
                    return parsed_response(response.status_code, fields, body, self.policy_hash)
            except requests.exceptions.RequestException as error:
                require(expected != "success", "stock Requests proxy operation failed")
                require_requests_failure(error, expected)
                return {"client": "requests", "outcome": expected}

    def curl_call(self, username, token, *, expected="success", outer=None, inner=None):
        self.fixed_proxy_resolution()
        username, token = self.credentials(username, token)
        # curl's stock proxy-user option remains in its private stdin config.
        # No credential-bearing URL/argument, curlrc, shell or proxy environment.
        config = ('proxy-user = "' + username + ":" + token + '"\n').encode("ascii")
        arguments = [str(self.args.curl_binary), "-q", "--config", "-", "--silent", "--show-error",
            "--proxy-basic", "--proxy", PROXY, "--noproxy", "", "--proxy-cacert", str(outer or self.args.proxy_ca_file),
            "--cacert", str(inner or self.args.ca_file), "--proto", "=https", "--proto-redir", "=https",
            "--http1.1", "--connect-timeout", "3", "--max-time", "8", "--retry", "0",
            "--max-filesize", "65536", "--raw", "--include", "--suppress-connect-headers",
            "--request", "POST", "--data-binary", "@" + str(self.body_file),
            "--write-out", "\nserverware-check-connect:%{http_connect}\nserverware-check-status:%{http_code}\n"]
        for name, value in self.request_headers(ACCEPT["curl"]).items():
            arguments.extend(["--header", name + ": " + value])
        arguments.append(self.target())
        code, output, error = bounded_process(arguments, config, min(10.0, self.timeout()))
        self.clean(output)
        self.clean(error)
        wire, marker, tail = output.rpartition(CURL_TRAILER)
        match = re.fullmatch(rb"([0-9]{3})\nserverware-check-status:([0-9]{3})\n", tail)
        require(marker and match, "curl connection/status receipt missing")
        connect, status = (int(value) for value in match.groups())
        if expected == "denied":
            require(code == 56 and connect == 403 and status == 0, "curl did not observe a CONNECT 403")
            return {"client": "curl", "outcome": expected}
        if expected == "tls":
            require(code == 60 and connect in {0, 200} and status == 0, "curl did not refuse certificate verification")
            return {"client": "curl", "outcome": expected, "connectStatus": connect}
        require(expected == "success" and code == 0 and connect == status == 200 and not error,
                "stock curl proxy operation failed")
        head, separator, body = wire.partition(b"\r\n\r\n")
        require(separator, "curl origin response framing missing")
        fields = []
        for line in head.split(b"\r\n")[1:]:
            name, colon, value = line.partition(b":")
            require(colon, "curl origin response header invalid")
            fields.append((name.decode("ascii"), value.decode("ascii").strip(" \t")))
        result = check_response("json", status, fields, body, wire, self.policy_hash, response_mode=V2_RESPONSE_MODE)
        result["headerEvidence"] = "curl-header-dump-and-raw-transfer-body"
        return result

    def bearer_call(self, token, client):
        """Existing raw Bearer control only; never used to prove stock Basic."""
        raw = self.tunnel(token)
        try:
            with TunnelTLS(raw, self.ca, self.timeout) as tls:
                target = urlsplit(self.target())
                fields = {"Host": AUTHORITY, **self.request_headers(ACCEPT[client]),
                          "Content-Length": str(len(REQUEST_BODY))}
                head = [f"POST {target.path}?{target.query} HTTP/1.1"]
                head.extend(name + ": " + value for name, value in fields.items())
                tls.sendall(("\r\n".join(head) + "\r\n\r\n").encode("ascii") + REQUEST_BODY)
                capture = CapturedTLS(tls)
                response = http.client.HTTPResponse(capture)
                try:
                    response.begin()
                    body = response.read(65537)
                    wire = capture.finish()
                    self.clean(wire)
                    return check_response("json", response.status, response.getheaders(), body, wire,
                                          self.policy_hash, response_mode=V2_RESPONSE_MODE)
                finally:
                    response.close()
        finally:
            raw.close()

    def cold_checkpoint(self, case, baseline):
        """All controls precede the first positive request on every fresh scope."""
        require(self.count() == 0, "negative client control dispatched upstream")
        while True:
            events = self.audit()
            cutoff = features.audit_cutoff(events)
            require(all(cutoff.get(key) == value for key, value in baseline.items()), "baseline audit changed")
            rows = [row for row in events if row["id"] not in baseline]
            require(not any(row["event_type"] in {LEASE, START, RELEASE, BLOCK} for row in rows),
                    "negative client control obtained credential material or release authority")
            counts = Counter(row["event_type"] for row in rows)
            require(counts[CONNECT] <= self.expected_connects and counts[CONNECT_DENIED] <= self.expected_denials,
                    "negative control caused an extra CONNECT")
            if counts[CONNECT] == self.expected_connects and counts[CONNECT_DENIED] == self.expected_denials and self.audit_drained():
                self.negative_cutoffs.append(cutoff)
                self.negative_observations.append({"case": case, "upstreamDispatches": 0,
                    "credentialLeaseEvents": 0, "credentialReleaseEvents": 0,
                    "auditCutoffRows": len(cutoff),
                    "auditCutoffSha256": digest(json.dumps(cutoff, sort_keys=True, separators=(",", ":")).encode("ascii"))})
                return
            time.sleep(min(0.1, self.timeout()))

    def current(self, pins):
        require(authority_projection(self.warm_cas_snapshot()) == authority_projection(pins),
                "saved catalog or loaded policy changed during client acceptance")

    def positive(self, client, app, rule, token):
        before = self.count()
        if client == "requests":
            result = self.requests_call(app["id"], token)
        elif client == "curl":
            result = self.curl_call(app["id"], token)
        else:
            result = self.bearer_call(token, client)
        self.expected_connects += 1
        require(self.count() == before + 1, "positive client did not dispatch exactly once")
        result.update(client=client, principalId=app["principal_id"], routeId=rule["route_id"],
                      applicationId=app["id"], generation=1, upstreamCountBefore=before, upstreamCountAfter=before + 1)
        self.feature_observations.append(result)

    def verify_client_audit(self, baseline, assigned, credential_id):
        expected = Counter(kind for kind, _, _ in self.mutations)
        expected.update({CONNECT: self.expected_connects, CONNECT_DENIED: self.expected_denials, START: 4, RELEASE: 4})
        scopes = {(app["principal_id"], rule["route_id"]) for app, rule, _ in assigned}
        loaded = [next(item for item in self.observations if item["stage"] == stage)
                  for stage in ("initial", "assigned_rule_0", "assigned_rule_1")]
        reload_chain = Counter((previous["policyHash"], current["policyHash"], current["sequence"], index)
                              for index, (previous, current) in enumerate(zip(loaded, loaded[1:]), 1))
        drained_cutoff = None
        while True:
            events = self.audit()
            cutoff = features.audit_cutoff(events)
            require(all(cutoff.get(key) == value for key, value in baseline.items()), "baseline audit changed")
            for observed_cutoff in self.negative_cutoffs:
                require(all(cutoff.get(key) == value for key, value in observed_cutoff.items()),
                        "negative phase history changed")
            if drained_cutoff is not None:
                # App-side issuance audit is outside the gate's delivery queue:
                # hot-scope renewal may append either lease purpose after drain.
                # Preserve every observed row and revalidate the ENTIRE fresh
                # view below; this is not permission to ignore arbitrary tails.
                require(all(cutoff.get(key) == value for key, value in drained_cutoff.items()),
                        "audit history changed after drained checkpoint")
                require(all(row["id"] in drained_cutoff or row["event_type"] == LEASE for row in events),
                        "non-lease audit appended after drained checkpoint")
            rows = [row for row in events if row["id"] not in baseline]
            counts = Counter(row["event_type"] for row in rows)
            require(not set(counts) - (set(expected) | {LEASE, RELOAD})
                    and all(counts[key] <= count for key, count in expected.items()), "unexpected client audit event")
            pairs = joined_attempts(rows, self.feature_observations, credential_id, self.policy_hash)
            reloads, leased = Counter(), set()
            for row in rows:
                kind, event = row["event_type"], row.get("event", {})
                if kind in {CONNECT, CONNECT_DENIED}:
                    require(event.get("method") == "CONNECT" and event.get("target") == AUTHORITY,
                            "CONNECT audit destination differs")
                    if kind == CONNECT:
                        require(event.get("principal_id") in {scope[0] for scope in scopes}
                                and event.get("policy_hash") == self.policy_hash
                                and event.get("outcome") == "established", "CONNECT audit identity differs")
                    else:
                        # Principal denial happens before a canonical policy-bound
                        # identity is returned; do not invent that audit binding.
                        require(event.get("principal_id") is None and event.get("outcome") == "denied"
                                and event.get("policy_hash") is None
                                and event.get("payload", {}).get("error") == "client_principal_denied",
                                "CONNECT refusal was not principal authentication")
                elif kind == LEASE:
                    scope = (event.get("principal_id"), event.get("route_id"))
                    require(scope in scopes and event.get("credential_id") == credential_id
                            and event.get("policy_hash") == self.policy_hash and event.get("status_code") == 200
                            and event.get("outcome") == "issued"
                            and event.get("data_plane_binary_digest") == self.args.expected_binary_sha256
                            and event.get("purpose") in {"generationMetadata", "dispatchSecret"}, "lease scope differs")
                    if event.get("purpose") == "dispatchSecret":
                        require(type(event.get("expected_credential_version")) is int
                                and event["expected_credential_version"] == 1, "dispatch lease generation differs")
                        leased.add(scope)
                    else:
                        require(event.get("expected_credential_version") is None,
                                "generation metadata lease unexpectedly pins a version")
                elif kind == RELOAD:
                    transition = tuple(event.get(key) for key in
                                       ("previous_policy_hash", "policy_hash", "policy_sequence", "routes"))
                    require(transition in reload_chain and type(event.get("policy_sequence")) is int
                            and type(event.get("routes")) is int, "reload does not join the two saved rules")
                    reloads[transition] += 1
                    require(reloads[transition] <= reload_chain[transition], "policy reloaded twice")
            mutations = {(row["event_type"], row.get("event", {}).get("resource_id"), row.get("event", {}).get("policy_hash")) for row in rows}
            if (all(counts[key] == count for key, count in expected.items()) and len(pairs) == 4
                    and reloads == reload_chain and leased == scopes and set(self.mutations) <= mutations
                    and self.audit_drained()):
                if drained_cutoff is not None:
                    break
                drained_cutoff = cutoff
                continue  # Fresh read gets the same complete oracle, not an equality-only check.
            if drained_cutoff is not None:
                drained_cutoff = cutoff
            self.audit_drained()
            time.sleep(min(0.1, self.timeout()))
        verified = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(verified.get("ok") is True and verified.get("complete") is True and verified.get("backend") == "sqlite",
                "complete durable audit verification failed")
        return {"namedAuditInventory": dict(sorted(counts.items())), "auditedRequestAttemptIds": sorted(pairs),
                "durableAuditEventIds": sorted(row["id"] for row in rows)}

    def run(self):
        self.health()
        self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        require(initial["revision"] == 1 and all(not initial[key] and initial["limits"][key]["retained"] == 0 for key in COLLECTIONS)
                and self.count() == 0, "fresh private catalog and upstream required")
        capability = initial.get("capabilities", {}).get("application_proxy_authentication")
        require(capability == {"schema": "serverware.operatorProxyAuthentication/v1",
                "modes": ["bearer", BASIC], "path": PREFIX + "/applications/proxy-authentication"}
                and V2_RESPONSE_MODE in initial.get("capabilities", {}).get("response_modes", []),
                "paired Basic and ordinary response capabilities unavailable")
        self.policy_hash = self.initial_policy_hash = initial["policy"]["policy_hash"]
        self.wait_catalog_loaded("initial")
        while not self.audit_drained():
            time.sleep(min(0.1, self.timeout()))
        baseline = features.audit_cutoff(self.audit())
        credential, _, _ = self.mutate("/credentials", {"name": self.run_id + "-key", "auth_type": "bearer", "secret": self.credential},
            collection="credentials", result_key="credential", event="operator_catalog.credential.created", creates=True)
        require(credential.get("credential_generation") == 1, "fresh static generation differs")
        apps = []
        for index, mode in enumerate((BASIC, "bearer", BASIC)):
            payload = {"name": self.run_id + "-app-" + str(index), "token_lifetime_seconds": 3600}
            if mode == BASIC:
                payload["proxy_authentication"] = mode
            app, token, _ = self.mutate("/applications", payload, collection="applications", result_key="application",
                event="operator_catalog.application.created", creates=True, token=True)
            require(app.get("proxy_authentication") == mode, "saved application authentication mode differs")
            self.credentials(app["id"], token)
            apps.append((app, token))
        assigned = []
        for index, (app, token) in enumerate(apps[:2]):
            rule, _, _ = self.mutate("/access-rules", {"name": self.run_id + "-rule-" + str(index),
                "application_id": app["id"], "credential_id": credential["id"], "upstream_url": "https://" + AUTHORITY + FIXTURE_PATH,
                "methods": ["POST"], "request_body_mode": "preserve_json_v1", "response_mode": V2_RESPONSE_MODE,
                "request_fields": [], "response_fields": [], "credential_input": "replace_exact", "placeholder": DUMMY_AUTHORIZATION,
                "query_keys": list(QUERY_KEYS), "allowed_headers": ["accept", "accept-encoding", "user-agent"]},
                collection="access_rules", result_key="access_rule", event="operator_catalog.access_rule.created", creates=True, authority_changed=True)
            self.wait_catalog_loaded("assigned_rule_" + str(index))
            assigned.append((app, rule, token))
        pins = self.warm_cas_snapshot()
        require([len(pins[key]) for key in COLLECTIONS] == [1, 3, 2]
                and self.resource(pins, "applications", apps[2][0]["id"])["access_status"] == "unassigned", "resource budget differs")
        opt, opt_token = apps[0]
        for client in ("requests", "curl"):
            call = self.requests_call if client == "requests" else self.curl_call
            for label, username, token in (
                ("wrong_username", apps[1][0]["id"], opt_token),
                ("wrong_token", opt["id"], self.wrong_basic_token),
                ("default_bearer", apps[1][0]["id"], apps[1][1]),
                ("unassigned", apps[2][0]["id"], apps[2][1]),
            ):
                self.current(pins)
                call(username, token, expected="denied")
                self.expected_denials += 1
                self.cold_checkpoint(client + "_" + label, baseline)
            for layer in ("outer", "inner"):
                if client == "requests":
                    call(opt["id"], opt_token, expected="tls",
                         ca=self.args.ca_file if layer == "outer" else self.args.proxy_ca_file)
                else:
                    observation = call(opt["id"], opt_token, expected="tls",
                        outer=self.args.ca_file if layer == "outer" else None,
                        inner=self.args.proxy_ca_file if layer == "inner" else None)
                    require(observation["connectStatus"] == (0 if layer == "outer" else 200), "curl failed at the wrong TLS layer")
                if layer == "inner":
                    self.expected_connects += 1
                self.cold_checkpoint(client + "_missing_" + layer + "_root", baseline)
                self.trust_controls.append({"client": client, "missingRoot": layer, "certificateVerificationRefused": True})
        for client, selected in (("requests", assigned[0]), ("curl", assigned[0]),
                                 ("bearer_opt_in", assigned[0]), ("bearer_default", assigned[1])):
            self.current(pins)
            self.positive(client, *selected)
        require(self.count() == 4 and self.expected_connects == 6 and self.expected_denials == 8,
                "fixed actual-client request inventory differs")
        evidence = self.verify_client_audit(baseline, assigned, credential["id"])
        self.current(pins)
        return {"ok": True, "schema": "serverware.operatorProxyBasicCheck/v1", "syntheticOnly": True,
            "productionReady": False, "realProviderVerified": False, "publicDnsVerified": False,
            "proxyTransport": "private-verified-https-edge", "proxyHostname": PROXY_HOST,
            "dataPlaneBinaryDigest": self.args.expected_binary_sha256, "curlExecutableSha256": self.curl_digest,
            "requestsVersion": requests.__version__, "urllib3Version": urllib3.__version__,
            "customRequestsAdapter": False, "manufacturedBasicHeaderUsed": False,
            "upstreamDispatches": 4, "authenticationDenials": 8, "tlsControls": self.trust_controls,
            "functionalRetries": 0, "freshApiNaturalExpiryVerified": False,
            "expiryBoundary": "OPEN: minimum API token lifetime is3600s; no TTL/clock/database override",
            "basicHeaderForwarded": False, "providerInjectionVerifiedByPhysicalHeaderDigest": True,
            "upstreamClosedHeaderOracleVerified": True,
            "secretIsolationBoundary": "json_proxy_basic_v1 closes every parsed upstream header name/value plus exact query/body; no arbitrary encoding or hidden-wire claim",
            **self.ca_evidence, **features.safe_evidence(self), **evidence}


def run_checks(args):
    check = None
    try:
        require(isinstance(args.expected_binary_sha256, str) and SHA256.fullmatch(args.expected_binary_sha256)
                and type(args.timeout_seconds) is int and 30 <= args.timeout_seconds <= 120,
                "accepted normal binary digest and30..120second deadline required")
        require(args.proxy_url == PROXY and args.response_mode == V2_RESPONSE_MODE, "exact private HTTPS proxy and V2 required")
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = ProxyBasicCheck(args)
        result = check.run()
        check.clean(json.dumps(result, sort_keys=True).encode("utf-8"))
        return result
    except Exception as error:
        safe = {}
        if check is not None:
            try:
                safe = features.safe_evidence(check)
            except Exception:
                safe = {"safeEvidenceUnavailable": True}
        return {"ok": False, "syntheticOnly": True, "productionReady": False, **safe,
                "error": str(error) if isinstance(error, CheckFailure) else type(error).__name__}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "proxy-ca-file", "requests-ca-file", "upstream-ca-file", "admin-token-file",
                 "fixture-marker-file", "run-claim-file", "curl-binary"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--upstream-address")
    parser.add_argument("--response-mode", choices=(V2_RESPONSE_MODE,), default=V2_RESPONSE_MODE)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    args = parser.parse_args()

    def expired(_signum, _frame):
        raise CheckFailure("private Basic client acceptance process deadline exceeded")

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(max(args.timeout_seconds, 1), 120))
    try:
        result = run_checks(args)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
