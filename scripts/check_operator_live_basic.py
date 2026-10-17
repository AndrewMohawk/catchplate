#!/usr/bin/env python3
"""Explicit one-shot LIVE synthetic stock-client Basic smoke; never launch it.

Adds one credential/application/rule and retains them and the private app token.
Only the existing /echo fixture is used: it proves selected injection checks,
not arbitrary-header containment, JSON byte preservation,204 or token expiry.
Requests has one scoped system-roots+inner-CA bundle, not separate trust stores.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import sys
import time
from urllib.parse import quote, urlencode
import uuid

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import requests
import urllib3

from scripts import check_operator_live_smoke as smoke
from scripts.check_operator_catalog import OperatorCatalogCheck, PREFIX
from scripts.check_operator_key_replacement import authority_projection
from scripts.check_operator_proxy_basic import bounded_process, require_requests_failure

PIN = "sha256:e7529b4484228ebdbf2be1ebb471a80a78a3e127673f0bc6dcb4921db92489e2"
BASIC = "basic_and_bearer_v1"
CONNECT_DENIED = "data_plane.connect.denied"
CURL = Path("/usr/bin/curl")
CURL_SHA256 = "0ca2b923679ab186f6512c7512e131a1c5c1b43d4cb5d55933998405b39e85bf"
SYSTEM_CA = Path("/etc/ssl/certs/ca-certificates.crt")
SYSTEM_CA_SHA256 = "ecd9dc38bc3efb7dbd6431f57e29d2f8d6a0f0d211e1464b3fef2cbfe266fcd2"
CLAIM = ".operator-live-basic.claim"
TOKEN_FILE = ".operator-live-basic-client.token"
ACCEPT = {"requests": "application/json", "curl": "application/json;q=0.9"}
require = smoke.require


def trust_bundle(args):
    """Use the pinned installed bundle, even when OpenSSL's default cafile is absent."""
    payloads = []
    for path, maximum in ((SYSTEM_CA, 1024 * 1024), (args.ca_file, 16384), (args.requests_ca_file, 2 * 1024 * 1024)):
        require(path.is_absolute() and path.resolve() == path and path.is_file()
                and 0 < path.stat().st_size <= maximum, "bounded explicit CA material required")
        value = path.read_bytes()
        require(b"PRIVATE KEY" not in value, "CA bundle includes private material")
        payloads.append(value)
    system, inner, combined = payloads
    require(hashlib.sha256(system).hexdigest() == SYSTEM_CA_SHA256
            and system.count(b"-----BEGIN CERTIFICATE-----") == system.count(b"-----END CERTIFICATE-----") == 121,
            "installed live system trust bundle differs")
    require(inner.count(b"-----BEGIN CERTIFICATE-----") == inner.count(b"-----END CERTIFICATE-----") == 1
            and combined == system + inner and inner not in system, "Requests scoped trust bundle differs")
    ssl.PEM_cert_to_DER_cert(inner.decode("ascii"))
    return {"systemRootsSha256": smoke.sha(system), "innerCaSha256": smoke.sha(inner),
            "outerTrustSource": "explicit-pinned-installed-system-ca-bundle",
            "outerTrustBundle": str(SYSTEM_CA),
            "requestsTrustStores": "one-scoped-explicit-system-bundle-plus-inner-ca"}


def release_pairs(rows, scope, credential_id, positives):
    expected = {(item["requestDigest"], item["operationDigest"]): item for item in positives}
    require(len(expected) == 2, "two distinct positive wire commitments required")
    counts, pairs, retained, issued = Counter(), {}, [], 0
    for row in rows:
        event, kind = row.get("event", {}), row.get("event_type")
        if event.get("principal_id") != scope[0] and event.get("route_id") != scope[1]:
            continue
        require(kind in {smoke.CONNECT, smoke.START, smoke.RELEASE, smoke.LEASE}, "unexpected event for new Basic scope")
        counts[kind] += 1
        retained.append(row["id"])
        require(event.get("principal_id") == scope[0] and event.get("policy_hash") == scope[2], "live Basic audit identity differs")
        if kind == smoke.CONNECT:
            require(event.get("method") == "CONNECT" and event.get("target") == smoke.AUTHORITY
                    and event.get("outcome") == "established", "live Basic CONNECT differs")
            continue
        require(event.get("route_id") == scope[1], "live Basic audit route differs")
        if kind == smoke.LEASE:
            require(event.get("credential_id") == credential_id and event.get("data_plane_binary_digest") == PIN
                    and event.get("purpose") in {"generationMetadata", "dispatchSecret"}
                    and event.get("outcome") == "issued" and event.get("status_code") == 200, "live Basic lease differs")
            if event["purpose"] == "dispatchSecret":
                require(type(event.get("expected_credential_version")) is int
                        and event["expected_credential_version"] == 1, "live Basic lease generation differs")
                issued += 1
            continue
        key = (event.get("request_digest"), event.get("operation_digest"))
        require(key in expected and event.get("method") == "POST" and event.get("body_sha256") == smoke.sha(smoke.BODY)
                and event.get("credential_ref") == credential_id and type(event.get("credential_version")) is int
                and event["credential_version"] == 1, "live Basic release request differs")
        attempt = event.get("attempt_id")
        require(isinstance(attempt, str) and smoke.SHA256.fullmatch(attempt) and event.get("flow_id") == attempt,
                "live Basic release attempt invalid")
        pair = pairs.setdefault(attempt, {"key": key})
        require(pair["key"] == key and kind not in pair, "live Basic release attempt repeated")
        pair[kind] = row["id"]
        if kind == smoke.START:
            require(event.get("outcome") == "release_started", "live Basic start outcome differs")
        else:
            positive, validation = expected[key], event.get("response_validation", {})
            require(event.get("outcome") == "released" and event.get("upstream_status") == 200
                    and event.get("response_body_sha256") == positive["responseBodySha256"]
                    and event.get("response_body_bytes") == positive["responseBodyBytes"]
                    and validation.get("ok") is True and validation.get("mode") == smoke.RESPONSE_VALIDATION_MODE
                    and validation.get("body_bytes_preserved") is True, "live Basic response audit differs")
    require(counts[smoke.CONNECT] <= 2 and counts[smoke.START] <= 2 and counts[smoke.RELEASE] <= 2
            and counts[smoke.LEASE] <= 4 and issued <= 2 and len(pairs) <= 2, "live Basic audit request budget exceeded")
    complete = (counts[smoke.CONNECT] == counts[smoke.START] == counts[smoke.RELEASE] == 2 and 1 <= issued <= 2
                and len(pairs) == 2 and {value["key"] for value in pairs.values()} == set(expected)
                and all(smoke.START in value and smoke.RELEASE in value for value in pairs.values()))
    return complete, counts, retained, sorted(pairs)


class LiveBasic(smoke.LiveSmoke):
    def __init__(self, args):
        self.proxy_secrets = []
        super().__init__(args)
        self.run_id = "catchplate-live-basic-" + uuid.uuid4().hex
        self.plans = [{"route": route, "collection": collection, "name": self.run_id + "-" + kind,
                       "state": "not_submitted"} for route, collection, kind in smoke.CREATIONS]
        require(requests.__version__ == "2.31.0" and urllib3.__version__ == "2.0.7", "reviewed stock client versions differ")
        require(CURL.resolve() == CURL and CURL.is_file() and CURL.stat().st_size <= 64 * 1024**2
                and hashlib.sha256(CURL.read_bytes()).hexdigest() == CURL_SHA256, "reviewed stock curl differs")
        self.trust_evidence = trust_bundle(args)
        self.negative_cutoffs = []

    def clean(self, content, *, allow_client_token=False):
        super().clean(content, allow_client_token=allow_client_token)
        require(all(value.encode("ascii") not in content for value in self.proxy_secrets), "proxy secret escaped into evidence")

    def submit_mutation(self, before, route, payload, **kwargs):
        plan = next((item for item in self.plans if item["route"] == route), None)
        require(plan is not None and plan["state"] == "not_submitted" and payload.get("name") == plan["name"],
                "live Basic mutation budget or name differs")
        plan["state"] = "submitted_response_uncertain"
        resource, token, result = OperatorCatalogCheck.submit_mutation(self, before, route, payload, **kwargs)
        require(str(uuid.UUID(resource["id"])) == resource["id"], "created resource identity invalid")
        plan.update(state="response_validated", id=resource["id"])
        self.additions[plan["collection"]].append(resource["id"])
        if token is not None:
            smoke.private_output(self.args.run_claim_file.parent / TOKEN_FILE, (token + "\n").encode("ascii"))
            self.token_retained = True
        return resource, token, result

    def target(self):
        return "https://" + smoke.AUTHORITY + "/echo?" + urlencode({
            "expectedAuthorizationSha256": smoke.sha(("Bearer " + self.credential).encode("ascii"))})

    def stock_call(self, client, username, token, *, denied=False):
        require(str(uuid.UUID(username)) == username and re.fullmatch(r"[A-Za-z0-9_-]{43}", token), "proxy credential shape differs")
        self.proxy_secrets.extend([token, base64.b64encode((username + ":" + token).encode()).decode()])  # Leak detector only.
        addresses = {item[4][0] for item in socket.getaddrinfo(self.proxy.host, 443, type=socket.SOCK_STREAM)}
        require(addresses == {self.proxy.address}, "live proxy LAN resolution changed")
        headers = {"Authorization": smoke.DUMMY, "Content-Type": "application/json", "Accept": ACCEPT[client],
                   "Accept-Encoding": "identity", "Connection": "close", "User-Agent": "catchplate-test-run/" + self.run_id}
        if client == "requests":
            proxy = "https://" + quote(username, safe="") + ":" + quote(token, safe="") + "@" + self.proxy.host
            self.proxy_secrets.append(proxy)
            with requests.Session() as session:
                session.trust_env = False
                session.proxies = {"https": proxy}
                session.verify = str(self.args.requests_ca_file)
                require(all(adapter.max_retries.total == 0 for adapter in session.adapters.values()), "Requests retry defaults differ")
                try:
                    with session.post(self.target(), data=smoke.BODY, headers=headers, stream=True, allow_redirects=False,
                                      timeout=(min(3.0, self.timeout()), self.timeout())) as response:
                        require(not denied, "Basic negative unexpectedly reached origin response")
                        require(response.request.url == self.target() and response.request.body == smoke.BODY
                                and not any(key.lower() == "proxy-authorization" for key in response.request.headers),
                                "Requests changed origin request or installed origin proxy credentials")
                        status, fields, body = response.status_code, list(response.raw.headers.iteritems()), response.raw.read(65537, decode_content=False)
                except requests.exceptions.RequestException as error:
                    require(denied, "stock Requests live proxy call failed")
                    require_requests_failure(error, "denied")
                    return {"client": client, "connectStatus": 403}
        else:
            require(client == "curl", "unknown stock client")
            arguments = [str(CURL), "-q", "--config", "-", "--silent", "--show-error", "--proxy-basic",
                "--proxy", smoke.PROXY, "--noproxy", "", "--proxy-cacert", str(SYSTEM_CA), "--cacert", str(self.args.ca_file),
                "--proto", "=https", "--proto-redir", "=https", "--http1.1", "--connect-timeout", "3",
                "--max-time", "8", "--retry", "0", "--max-filesize", "65536", "--raw", "--include", "--suppress-connect-headers",
                "--request", "POST", "--data-binary", "@" + str(self.body_file),
                "--write-out", "\ncatchplate-check-connect:%{http_connect}\ncatchplate-check-status:%{http_code}\n"]
            for name, value in headers.items():
                arguments.extend(["--header", name + ": " + value])
            arguments.append(self.target())
            code, output, error = bounded_process(arguments, ('proxy-user = "' + username + ":" + token + '"\n').encode(), self.timeout())
            self.clean(output)
            self.clean(error)
            wire, marker, tail = output.rpartition(b"\ncatchplate-check-connect:")
            match = re.fullmatch(rb"([0-9]{3})\ncatchplate-check-status:([0-9]{3})\n", tail)
            require(marker and match, "curl status receipt missing")
            connect, status = (int(value) for value in match.groups())
            if denied:
                require(code == 56 and connect == 403 and status == 0, "curl did not observe CONNECT403")
                return {"client": client, "connectStatus": 403}
            require(code == 0 and connect == status == 200 and not error, "stock curl live proxy call failed")
            head, separator, body = wire.partition(b"\r\n\r\n")
            require(separator and head.startswith(b"HTTP/1.1 200 "), "curl origin framing missing")
            fields = []
            for line in head.split(b"\r\n")[1:]:
                name, colon, value = line.partition(b":")
                require(colon, "curl response header malformed")
                fields.append((name.decode("ascii"), value.decode("ascii").strip(" \t")))
        require(len(body) <= 65536 and len(fields) <= 64 and len(str(fields).encode()) <= 16384, "live response bound exceeded")
        self.clean(body)
        self.clean(str(fields).encode())
        self.clean(json.dumps(json.loads(body)).encode())
        return {**smoke.response_evidence("positive", status, fields, body, self.policy_hash), "client": client}

    def new_events(self, baseline):
        events = self.audit()
        cutoff = smoke.features.audit_cutoff(events)
        require(all(cutoff.get(key) == value for key, value in baseline.items()), "live retained audit baseline changed or aged out")
        return [row for row in events if row["id"] not in baseline], cutoff

    @staticmethod
    def denials(rows, count):
        denied = [row for row in rows if row.get("event_type") == CONNECT_DENIED]
        require(len(denied) <= count, "unrelated or repeated CONNECT refusal appeared")
        for row in denied:
            event = row.get("event", {})
            require(event.get("principal_id") is None and event.get("policy_hash") is None
                    and event.get("method") == "CONNECT" and event.get("target") == smoke.AUTHORITY
                    and event.get("outcome") == "denied" and event.get("payload", {}).get("error") == "client_principal_denied",
                    "live CONNECT refusal was not principal authentication")
        return denied

    def cold_checkpoint(self, baseline, scope, expected):
        while True:
            rows, cutoff = self.new_events(baseline)
            denied = self.denials(rows, expected)
            require(not any(row.get("event", {}).get("principal_id") == scope[0]
                or row.get("event", {}).get("route_id") == scope[1] for row in rows), "auth refusal reached assigned credential scope")
            if len(denied) == expected and self.drained():
                self.negative_cutoffs.append(cutoff)
                return
            time.sleep(min(0.1, self.timeout()))

    def verify_basic_audit(self, baseline, scope, credential_id):
        while True:
            rows, cutoff = self.new_events(baseline)
            for earlier in self.negative_cutoffs:
                require(all(cutoff.get(key) == value for key, value in earlier.items()), "negative audit history changed")
            denied = self.denials(rows, 2)
            complete, counts, ids, attempts = release_pairs(rows, scope, credential_id, self.feature_observations)
            mutations = [row for row in rows if (row.get("event_type"), row.get("event", {}).get("resource_id"),
                         row.get("event", {}).get("policy_hash")) in self.mutations]
            require(len(mutations) <= 3 and len({(row["event_type"], row["event"]["resource_id"]) for row in mutations}) == len(mutations),
                    "new-resource audit duplicated")
            if complete and len(denied) == 2 and len(mutations) == 3 and self.drained():
                break
            time.sleep(min(0.1, self.timeout()))
        self.new_events(cutoff)
        chain = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(chain.get("ok") is True and chain.get("complete") is True and chain.get("backend") == "sqlite", "retained audit chain verification failed")
        return {"scopedNamedAuditInventory": {**dict(counts), CONNECT_DENIED: 2}, "auditedRequestAttemptIds": attempts,
                "durableAuditEventIds": sorted(ids + [row["id"] for row in denied + mutations])}

    def run(self):
        self.health()
        self.admin_token = smoke.token_file(self.args.admin_token_file)
        initial = self.catalog()
        smoke.preflight_catalog(initial)
        require(initial.get("capabilities", {}).get("application_proxy_authentication") == {
            "schema": "catchplate.operatorProxyAuthentication/v1", "modes": ["bearer", BASIC],
            "path": PREFIX + "/applications/proxy-authentication"}, "paired Basic capability unavailable")
        self.policy_hash = initial["policy"]["policy_hash"]
        initial, _ = self.wait_catalog_loaded("live_basic_baseline")
        self.baseline_counts = {key: len(initial[key]) for key in smoke.COLLECTIONS}
        require(not any(row.get("name") in {plan["name"] for plan in self.plans}
            for key in smoke.COLLECTIONS for row in initial[key]), "planned synthetic name already exists")
        while not self.drained():
            time.sleep(min(0.1, self.timeout()))
        baseline = smoke.features.audit_cutoff(self.audit())
        total, run = self.counts()
        require(run == 0, "live Basic run already reached fixture")
        credential, _, _ = self.mutate("/credentials", {"name": self.plans[0]["name"], "auth_type": "bearer", "secret": self.credential},
            collection="credentials", result_key="credential", event="operator_catalog.credential.created", creates=True)
        require(credential.get("credential_generation") == 1, "new credential generation differs")
        app, token, _ = self.mutate("/applications", {"name": self.plans[1]["name"], "token_lifetime_seconds": 3600, "proxy_authentication": BASIC},
            collection="applications", result_key="application", event="operator_catalog.application.created", creates=True, token=True)
        require(app.get("proxy_authentication") == BASIC, "new app did not persist explicit Basic opt-in")
        values = smoke.access_rule_values(self.plans[2]["name"], app["id"], credential["id"])
        values["allowed_headers"] = ["accept", "accept-encoding", "user-agent"]
        rule, _, _ = self.mutate("/access-rules", values, collection="access_rules", result_key="access_rule",
            event="operator_catalog.access_rule.created", creates=True, authority_changed=True)
        smoke.require_rule_contract(rule, values)
        saved, _ = self.wait_catalog_loaded("live_basic_rule_loaded")
        require(saved["revision"] == initial["revision"] + 3 and saved["policy"]["sequence"] == initial["policy"]["sequence"] + 1,
                "catalog changed outside three creations")
        smoke.require_rule_contract(self.resource(saved, "access_rules", rule["id"]), values)
        smoke.preserved_rows(initial, saved, self.additions)
        self.client_token = token
        scope = (app["principal_id"], rule["route_id"], self.policy_hash)
        wrong_username = str(uuid.uuid4())
        require(wrong_username not in {row["id"] for row in saved["applications"]}, "negative username unexpectedly exists")
        wrong_token = secrets.token_urlsafe(32)
        require(wrong_token != token, "negative token unexpectedly matches")
        cases = (("requests", wrong_username, token, True), ("curl", app["id"], wrong_token, True),
                 ("requests", app["id"], token, False), ("curl", app["id"], token, False))
        for index, (client, username, material, denied) in enumerate(cases):
            require(authority_projection(self.warm_cas_snapshot()) == authority_projection(saved), "live catalog authority drifted")
            expected = max(0, index - 2)
            require(self.counts() == (total + expected, expected), "unrelated upstream traffic or extra client request")
            try:
                result = self.stock_call(client, username, material, denied=denied)
            finally:
                after = self.counts()
            expected += int(not denied)
            require(after == (total + expected, expected), "live Basic dispatch count differs")
            if denied:
                self.cold_checkpoint(baseline, scope, index + 1)
                self.negative_observations.append({**result, "upstreamDelta": 0, "scopedLeaseEvents": 0})
            else:
                self.feature_observations.append(result)
        require(self.counts() == (total + 2, 2), "live Basic total request budget differs")
        evidence = self.verify_basic_audit(baseline, scope, credential["id"])
        final = self.warm_cas_snapshot()
        require(authority_projection(final) == authority_projection(saved), "live catalog authority changed")
        smoke.preserved_rows(initial, final, self.additions)
        self.results.extend(["existing_catalog_preserved_three_synthetic_resources_added", "two_CONNECT_auth_refusals_without_upstream_or_lease",
            "stock_requests_and_curl_https_proxy_Basic_two_injections_audit_joined"])
        return {**self.receipt(True), **evidence, "upstreamDispatches": 2, "responsesReleased": 2, "responsesBlocked": 0}

    def receipt(self, ok):
        result = super().receipt(ok)
        result.update(schema="catchplate.operatorLiveBasic/v1", dataPlaneBinaryDigest=PIN,
            requestsVersion=requests.__version__, urllib3Version=urllib3.__version__, curlExecutableSha256=CURL_SHA256,
            authenticationDenials=self.negative_observations, functionalRetries=0, customRequestsAdapter=False,
            manufacturedBasicHeaderUsed=False, freshApiNaturalExpiryVerified=False, allHeaderCredentialIsolationVerified=False,
            evidenceBoundary="existing live /echo selected injection/header booleans only; no all-header or exact raw-body proof",
            **self.trust_evidence)
        self.clean(json.dumps(result, sort_keys=True).encode())
        return result


def run_checks(args):
    check = None
    try:
        require(args.execute is True and type(args.timeout_seconds) is int and 10 <= args.timeout_seconds <= 120,
                "explicit live Basic execution and bounded deadline required")
        require(args.run_claim_file.is_absolute() and args.run_claim_file.name == CLAIM, "exact live Basic claim required")
        args.control_base, args.management_base = "http://172.16.249.19:3000", "http://172.16.249.20:9091"
        args.proxy_url, args.operator_origin, args.upstream_address = smoke.PROXY, "https://catchplate-demo.example.com", "172.16.249.18"
        args.expected_binary_sha256 = PIN
        args.proxy_ca_file = args.control_ca_file = args.management_ca_file = None
        check = LiveBasic(args)
        smoke.private_output(args.run_claim_file, json.dumps({"runId": check.run_id, "plannedResources": check.plans,
            "retryAllowed": False, "dataPlaneBinaryDigest": PIN}, sort_keys=True).encode() + b"\n")
        token_path = args.run_claim_file.parent / TOKEN_FILE
        require(not token_path.exists() and not token_path.is_symlink(), "private client-token output already exists")
        check.body_file = args.run_claim_file.parent / ".operator-live-basic-body.json"
        smoke.private_output(check.body_file, smoke.BODY)
        return check.run()
    except Exception as error:
        result = check.receipt(False) if check is not None else {"ok": False, "schema": "catchplate.operatorLiveBasic/v1"}
        result["error"] = str(error) if isinstance(error, smoke.CheckFailure) else type(error).__name__
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    for name in ("admin-token-file", "ca-file", "requests-ca-file", "upstream-ca-file", "run-claim-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    args = parser.parse_args()
    def expired(_signum, _frame):
        raise smoke.CheckFailure("live Basic smoke process deadline exceeded")
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
