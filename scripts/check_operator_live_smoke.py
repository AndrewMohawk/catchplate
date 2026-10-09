#!/usr/bin/env python3
"""Explicit one-shot live demo smoke: three new synthetic resources, no cleanup.

Requires the paired normal V2 binary and explicit V2 response capability.
The old /echo fixture proves injection, not independent request/response byte
preservation or 204. A successful V2 audit claim does not close that gap.
Never retries POSTs or proxy requests. Uses the legitimate local administrator
API and the actual HTTPS proxy hostname with normal system certificate trust.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import ssl
import stat
import time
from urllib.parse import urlencode
import uuid

try:
    from scripts.check_operator_catalog import COLLECTIONS, OperatorCatalogCheck, features
    from scripts.check_operator_demo import AUTHORITY, SHA256, CheckFailure, TunnelTLS, require, token_file
    from scripts.check_operator_ordinary_client import (
        BLOCK, CONNECT, DENIED, DRAIN_COUNTERS, ERRORS, LEASE, RELEASE, START, ZERO_COUNTERS,
        RESPONSE_MODES, V2_RESPONSE_MODE,
    )
except ModuleNotFoundError:
    from check_operator_catalog import COLLECTIONS, OperatorCatalogCheck, features
    from check_operator_demo import AUTHORITY, SHA256, CheckFailure, TunnelTLS, require, token_file
    from check_operator_ordinary_client import (
        BLOCK, CONNECT, DENIED, DRAIN_COUNTERS, ERRORS, LEASE, RELEASE, START, ZERO_COUNTERS,
        RESPONSE_MODES, V2_RESPONSE_MODE,
    )


# operator_demo.origin canonicalizes default HTTPS port 443 out of catalog URLs.
# Endpoint still requires/connects port 443 and verifies this exact TLS hostname.
PROXY = "https://serverware-proxy.example.com"
PIN = "sha256:eba8cc0df0fcde6645e4b2b2c7d8d14e04bdad90e4587ee73fe2dc522108432d"
RESPONSE_MODE = V2_RESPONSE_MODE
RESPONSE_VALIDATION_MODE = RESPONSE_MODES[RESPONSE_MODE]
DUMMY = "Bearer SERVERWARE_LIVE_SMOKE_DUMMY"
BODY = b'{"live_smoke":true,"nested":{"kept":"synthetic"}}'
CASES = (("missing", None), ("wrong", DUMMY + "_WRONG"), ("positive", DUMMY))
CREATIONS = (("/credentials", "credentials", "credential"),
             ("/applications", "applications", "application"),
             ("/access-rules", "access_rules", "access_rule"))


def sha(body):
    return "sha256:" + hashlib.sha256(body).hexdigest()


def private_output(path, payload):
    require(path.parent.resolve() == path.parent and not path.is_symlink(), "private output path refused")
    info = path.parent.stat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_uid == os.geteuid(), "output directory must be owned and private")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def preflight_catalog(snapshot):
    capabilities = snapshot.get("capabilities", {})
    for key, value in (("credential_types", "bearer"), ("request_body_modes", "preserve_json_v1"),
                       ("response_modes", RESPONSE_MODE), ("credential_input_modes", "replace_exact")):
        choices = capabilities.get(key)
        require(isinstance(choices, list) and value in choices, "live catalog capability is unavailable")
    require(snapshot.get("proxy_url", "").rstrip("/") == PROXY, "catalog advertises another proxy")
    for collection in COLLECTIONS:
        limits = snapshot.get("limits", {}).get(collection, {})
        require(all(type(limits.get(key)) is int for key in ("active", "active_max", "retained", "retained_max"))
                and 0 <= limits["active"] < limits["active_max"]
                and 0 <= limits["retained"] < limits["retained_max"], "catalog cannot retain one more synthetic resource")
        rows = snapshot[collection]
        require(len({row["id"] for row in rows}) == len(rows), "existing catalog resource identity is duplicated")


def access_rule_values(name, application_id, credential_id):
    """The sole new rule is explicitly V2; there is no legacy-mode fallback."""
    return {"name": name, "application_id": application_id, "credential_id": credential_id,
        "upstream_url": "https://" + AUTHORITY + "/echo", "methods": ["POST"], "request_fields": [], "response_fields": [],
        "request_body_mode": "preserve_json_v1", "response_mode": RESPONSE_MODE,
        "credential_input": "replace_exact", "placeholder": DUMMY,
        "query_keys": ["expectedAuthorizationSha256"], "allowed_headers": ["accept", "user-agent"]}


def require_rule_contract(rule, expected):
    require(isinstance(rule, dict) and expected.get("response_mode") == RESPONSE_MODE
            and all(rule.get(key) == value for key, value in expected.items()),
            "live smoke V2 rule did not persist exactly")


def preserved_rows(before, after, additions):
    """No existing public field is exempt: new resources have separate bindings."""
    for collection in COLLECTIONS:
        original = {row["id"]: row for row in before[collection]}
        current = {row["id"]: row for row in after[collection]}
        require(len(current) == len(after[collection]) and set(current) == set(original) | set(additions[collection]),
                "live catalog resource set changed unexpectedly")
        require(all(current[key] == value for key, value in original.items()), "an existing catalog resource changed")


def response_evidence(case, status, headers, body, policy_hash):
    document = json.loads(body)
    if case in ERRORS:
        require(status == 403 and isinstance(document, dict) and document.get("allowed") is False
                and document.get("action") == "deny" and document.get("payload", {}).get("error") == ERRORS[case],
                "live dummy header was not denied by its exact guard")
        return {"case": case, "status": status, "responseMode": RESPONSE_MODE, "error": ERRORS[case]}
    require(case == "positive" and status == 200 and isinstance(document, dict)
            and document.get("method") == "POST" and document.get("path") == "/echo"
            and document.get("authorization_present") is True and document.get("authorization_scheme") == "Bearer"
            and document.get("authorization_matches_expected") is True and document.get("proxy_authorization_seen") is False
            and document.get("query", {}).get("_data_plane_token_seen") is False
            and document.get("query", {}).get("_cookie_seen") is False, "live credential injection evidence differs")
    values = {}
    for name, value in headers:
        key = name.lower()
        require(key not in values, "live response has duplicate headers")
        values[key] = value
    require(values.get("x-serverware-policy-hash") == policy_hash
            and values.get("x-serverware-response-body-sha256") == sha(body), "live response policy/body commitment differs")
    commitments = {"requestDigest": values.get("x-serverware-request-digest"),
                   "operationDigest": values.get("x-serverware-operation-digest")}
    require(all(isinstance(value, str) and SHA256.fullmatch(value) for value in commitments.values()),
            "live response request commitment missing")
    return {"case": case, "status": status, "responseMode": RESPONSE_MODE, "responseBodySha256": sha(body),
            "responseBodyBytes": len(body), **commitments}


def scoped_audit(events, scope, positive):
    require(positive.get("responseMode") == RESPONSE_MODE, "live response selection differs from V2")
    counts, pairs, reasons, retained = Counter(), {}, Counter(), []
    for row in events:
        event, kind = row.get("event", {}), row.get("event_type")
        if event.get("principal_id") != scope[0] and event.get("route_id") != scope[1]:
            continue
        require(kind in {CONNECT, DENIED, START, RELEASE, LEASE}, "unexpected audit event for live smoke scope")
        counts[kind] += 1
        retained.append(row["id"])
        if kind == CONNECT:
            require(event.get("policy_hash") == scope[2] and event.get("method") == "CONNECT"
                    and event.get("target") == AUTHORITY and event.get("outcome") == "established", "live CONNECT audit differs")
        elif kind == DENIED:
            require(event.get("route_id") == scope[1] and event.get("method") == "POST"
                    and event.get("outcome") == "denied" and event.get("error") in ERRORS.values(), "live denial audit differs")
            reasons[event["error"]] += 1
        elif kind == LEASE:
            require(event.get("policy_hash") == scope[2] and event.get("purpose") in {"dispatchSecret", "generationMetadata"}
                    and event.get("outcome") == "issued" and event.get("status_code") == 200, "live lease audit differs")
        else:
            require(tuple(event.get(key) for key in ("principal_id", "route_id", "policy_hash")) == tuple(scope)
                    and event.get("method") == "POST" and event.get("body_sha256") == sha(BODY)
                    and event.get("request_digest") == positive["requestDigest"]
                    and event.get("operation_digest") == positive["operationDigest"], "live release audit request commitment differs")
            attempt = event.get("attempt_id")
            require(isinstance(attempt, str) and SHA256.fullmatch(attempt) and event.get("flow_id") == attempt,
                    "live release audit attempt identity differs")
            pair = pairs.setdefault(attempt, {})
            require(kind not in pair, "live release audit event repeated")
            pair[kind] = row["id"]
            if kind == START:
                require(event.get("outcome") == "release_started", "live release start outcome differs")
            else:
                validation = event.get("response_validation", {})
                require(event.get("outcome") == "released" and event.get("upstream_status") == 200
                        and event.get("response_body_sha256") == positive["responseBodySha256"]
                        and event.get("response_body_bytes") == positive["responseBodyBytes"]
                        and validation.get("ok") is True and validation.get("mode") == RESPONSE_VALIDATION_MODE
                        and validation.get("body_bytes_preserved") is True, "live V2 response audit differs")
    require(counts[CONNECT] <= 3 and counts[DENIED] <= 2 and counts[START] <= 1 and counts[RELEASE] <= 1
            and counts[LEASE] <= 2 and len(pairs) <= 1 and all(value <= 1 for value in reasons.values()),
            "live smoke audit exceeds request budget")
    complete = (counts[CONNECT] == 3 and counts[DENIED] == 2 and counts[START] == counts[RELEASE] == 1
                and set(reasons) == set(ERRORS.values()) and len(pairs) == 1
                and set(next(iter(pairs.values()))) == {START, RELEASE})
    return complete, counts, sorted(retained), sorted(pairs)


class LiveSmoke(OperatorCatalogCheck):
    @staticmethod
    def _optional_ca(path, endpoint):
        if endpoint.host == "serverware-proxy.example.com":
            require(path is None and endpoint.scheme == "https" and endpoint.port == 443, "live proxy TLS selection differs")
            return ssl.create_default_context()  # System trust, never the interception CA.
        return OperatorCatalogCheck._optional_ca(path, endpoint)

    def __init__(self, args):
        super().__init__(args)
        self.run_id = "serverware-live-smoke-" + uuid.uuid4().hex
        self.plans = [{"route": route, "collection": collection, "name": self.run_id + "-" + kind,
                       "state": "not_submitted"} for route, collection, kind in CREATIONS]
        self.additions = {key: [] for key in COLLECTIONS}
        self.negative_observations, self.feature_observations = [], []
        self.token_retained = False

    def submit_mutation(self, before, route, payload, **kwargs):
        plan = next((item for item in self.plans if item["route"] == route), None)
        require(plan is not None and plan["state"] == "not_submitted" and payload.get("name") == plan["name"],
                "live smoke mutation budget or resource name differs")
        plan["state"] = "submitted_response_uncertain"
        resource, token, result = super().submit_mutation(before, route, payload, **kwargs)
        require(str(uuid.UUID(resource["id"])) == resource["id"], "created resource identifier is invalid")
        plan.update(state="response_validated", id=resource["id"])
        self.additions[plan["collection"]].append(resource["id"])
        if token is not None:
            private_output(self.args.run_claim_file.parent / ".operator-live-smoke-client.token", (token + "\n").encode("ascii"))
            self.token_retained = True
        return resource, token, result

    def counts(self):
        status, value = self.json_request(self.upstream,
            "/_test/request-count?" + urlencode({"method": "POST", "path": "/echo"}), context=self.upstream_ca)
        run_count = self.upstream_count("POST", "/echo")
        require(status == 200 and isinstance(value, dict) and type(value.get("count")) is int
                and value["count"] >= run_count >= 0, "live fixture request counters unavailable")
        return value["count"], run_count

    def dispatch(self, placeholder):
        target = "/echo?" + urlencode({"expectedAuthorizationSha256": sha(("Bearer " + self.credential).encode("ascii"))})
        raw = self.tunnel(self.client_token)
        try:
            with TunnelTLS(raw, self.ca, self.timeout) as tls:
                headers = [f"POST {target} HTTP/1.1", f"Host: {AUTHORITY}", "Connection: close",
                    f"User-Agent: serverware-test-run/{self.run_id}", "Accept: application/json",
                    "Content-Type: application/json", f"Content-Length: {len(BODY)}"]
                if placeholder is not None:
                    require(placeholder in {DUMMY, DUMMY + "_WRONG"}, "unexpected synthetic dummy header")
                    headers.append("Authorization: " + placeholder)
                tls.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + BODY)
                response = http.client.HTTPResponse(tls)
                try:
                    response.begin()
                    body = response.read(65537)
                    require(len(body) <= 65536, "live response body bound exceeded")
                    self.clean(str(response.getheaders()).encode("utf-8"))
                    self.clean(body)
                    self.clean(json.dumps(json.loads(body)).encode("utf-8"))
                    return response.status, response.getheaders(), body
                finally:
                    response.close()
        finally:
            raw.close()

    def drained(self):
        counters = self.health().get("audit", {})
        require(all(type(counters.get(key)) is int and counters[key] >= 0 for key in ZERO_COUNTERS + DRAIN_COUNTERS)
                and all(counters[key] == 0 for key in ZERO_COUNTERS), "live audit delivery counters failed")
        return all(counters[key] == 0 for key in DRAIN_COUNTERS)

    def verify_audit(self, baseline, scope, lease_scope):
        positive = self.feature_observations[-1]
        while True:
            events = self.audit()
            cutoff = features.audit_cutoff(events)
            require(all(cutoff.get(key) == value for key, value in baseline.items()), "retained audit baseline changed or aged out")
            new = [row for row in events if row["id"] not in baseline]
            complete, counts, ids, attempts = scoped_audit(new, scope, positive)
            mutation_rows = [row for row in new if (row.get("event_type"), row.get("event", {}).get("resource_id"),
                row.get("event", {}).get("policy_hash")) in self.mutations]
            mutations = {(row["event_type"], row["event"]["resource_id"], row["event"]["policy_hash"]): row["id"]
                         for row in mutation_rows}
            require(len(mutations) == len(mutation_rows), "live smoke mutation audit duplicated")
            for row in new:
                if row.get("event_type") == LEASE and row.get("event", {}).get("principal_id") == scope[0]:
                    require(all(row["event"].get(key) == value for key, value in lease_scope.items() if key != "purpose"),
                            "live smoke lease credential or binary binding differs")
            leases = [row for row in new if features.issued_lease(row, lease_scope)]
            require(len(leases) <= 1, "live smoke issued more than one dispatch lease")
            if complete and set(self.mutations) <= mutations.keys() and len(leases) == 1 and self.drained():
                ids.extend(mutations[key] for key in self.mutations)
                break
            self.drained()
            time.sleep(min(0.25, self.timeout()))
        final = self.audit()
        final_cutoff = features.audit_cutoff(final)
        require(all(final_cutoff.get(key) == value for key, value in cutoff.items()), "audit evidence did not survive reread")
        features.reconcile_negative_phases(self, final)
        chain = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(chain.get("ok") is True and chain.get("complete") is True and chain.get("backend") == "sqlite",
                "complete retained audit chain verification failed")
        return {"scopedNamedAuditInventory": dict(counts), "durableAuditEventIds": sorted(ids),
                "auditedRequestAttemptIds": attempts, "otherNewAuditEvents": len(new) - sum(counts.values())}

    def run(self):
        self.health()
        self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        preflight_catalog(initial)
        self.policy_hash = initial["policy"]["policy_hash"]
        initial, _ = self.wait_catalog_loaded("live_baseline_loaded")
        preflight_catalog(initial)
        self.original = initial
        self.baseline_counts = {key: len(initial[key]) for key in COLLECTIONS}
        require(not any(row.get("name") in {plan["name"] for plan in self.plans}
                        for collection in COLLECTIONS for row in initial[collection]), "synthetic resource name already exists")
        while not self.drained():
            time.sleep(min(0.25, self.timeout()))
        audit_before = features.audit_cutoff(self.audit())
        global_before, run_before = self.counts()
        require(run_before == 0, "live smoke run already contacted fixture")
        credential, _, _ = self.mutate("/credentials", {"name": self.plans[0]["name"], "auth_type": "bearer", "secret": self.credential},
            collection="credentials", result_key="credential", event="operator_catalog.credential.created", creates=True)
        application, token, _ = self.mutate("/applications", {"name": self.plans[1]["name"], "token_lifetime_seconds": 3600},
            collection="applications", result_key="application", event="operator_catalog.application.created", creates=True, token=True)
        rule_values = access_rule_values(self.plans[2]["name"], application["id"], credential["id"])
        rule, _, _ = self.mutate("/access-rules", rule_values, collection="access_rules", result_key="access_rule",
            event="operator_catalog.access_rule.created", creates=True, authority_changed=True)
        require_rule_contract(rule, rule_values)
        snapshot, _ = self.wait_catalog_loaded("live_smoke_rule_loaded")
        require(snapshot["revision"] == initial["revision"] + 3 and snapshot["policy"]["sequence"] == initial["policy"]["sequence"] + 1,
                "catalog changed outside the three smoke mutations")
        saved = self.resource(snapshot, "access_rules", rule["id"])
        require_rule_contract(saved, rule_values)
        preserved_rows(initial, snapshot, self.additions)
        self.client_token = token
        scope = (application["principal_id"], rule["route_id"], self.policy_hash)
        lease_scope = dict(zip(("principal_id", "route_id", "policy_hash"), scope), purpose="dispatchSecret",
                           credential_id=credential["id"], data_plane_binary_digest=PIN)
        for case, dummy in CASES:
            current = self.warm_cas_snapshot()
            require(current == snapshot, "live catalog drifted before smoke request")
            before = self.counts()
            expected_before = (global_before, 0)
            require(before == expected_before, "unexpected upstream traffic before live smoke request")
            observation = {"case": case, "upstreamCountBefore": before[0], "runCountBefore": before[1]}
            self.feature_observations.append(observation)
            try:
                response = self.dispatch(dummy)
            finally:
                after = self.counts()
                observation.update(upstreamCountAfter=after[0], runCountAfter=after[1])
            expected_delta = int(case == "positive")
            require(after == (before[0] + expected_delta, before[1] + expected_delta), "live smoke dispatch count differs")
            observation.update(response_evidence(case, *response, self.policy_hash))
            if case in ERRORS:
                features.record_negative_phase(self, ERRORS[case], lease_scope)
        require(self.counts() == (global_before + 1, 1), "live smoke total dispatch budget differs")
        evidence = self.verify_audit(audit_before, scope, lease_scope)
        final = self.warm_cas_snapshot()
        require(final == snapshot, "live catalog changed during smoke")
        preserved_rows(initial, final, self.additions)
        self.results.extend(["existing_catalog_preserved_three_synthetic_resources_added",
            "public_https_proxy_and_interception_tls_verified", "two_placeholder_denials_without_dispatch",
            "one_post_credential_injection_and_v2_durable_audit_join"])
        return {**self.receipt(True), **evidence, "upstreamDispatches": 1, "responsesReleased": 1, "responsesBlocked": 0}

    def receipt(self, ok):
        result = {"ok": ok, "schema": "serverware.operatorLiveSmoke/v1", "runId": self.run_id,
            "checks": self.results, "resourceCreations": self.plans, "existingResourceCounts": getattr(self, "baseline_counts", {}),
            "requestObservations": self.feature_observations, "clientTokenRetainedPrivately": self.token_retained,
            "resourcesAutomaticallyCleaned": False, "rawBodyPreservationVerified": False, "empty204Verified": False,
            "browserTransactionVerified": False, "externalDnsVerified": False, "productionReady": False,
            "dataPlaneBinaryDigest": PIN, "responseMode": RESPONSE_MODE,
            "auditResponseMode": RESPONSE_VALIDATION_MODE, "proxyUrl": PROXY}
        self.clean(json.dumps(result, sort_keys=True).encode("utf-8"))
        return result


def run_checks(args):
    check = None
    try:
        require(args.execute is True and type(args.timeout_seconds) is int and 10 <= args.timeout_seconds <= 120,
                "explicit live execution and bounded timeout required")
        require(args.run_claim_file.name == ".operator-live-smoke.claim", "live smoke claim filename differs")
        args.control_base, args.management_base = "http://172.16.249.19:3000", "http://172.16.249.20:9091"
        args.proxy_url, args.operator_origin, args.upstream_address = PROXY, "https://serverware-demo.example.com", "172.16.249.18"
        args.expected_binary_sha256 = PIN
        args.proxy_ca_file = args.control_ca_file = args.management_ca_file = None
        check = LiveSmoke(args)
        private_output(args.run_claim_file, json.dumps({"runId": check.run_id, "plannedResources": check.plans,
            "retryAllowed": False}, sort_keys=True).encode("utf-8") + b"\n")
        token_output = args.run_claim_file.parent / ".operator-live-smoke-client.token"
        require(not token_output.exists() and not token_output.is_symlink(), "private client-token output already exists")
        return check.run()
    except Exception as error:
        result = check.receipt(False) if check is not None else {"ok": False, "schema": "serverware.operatorLiveSmoke/v1"}
        result["error"] = str(error) if isinstance(error, CheckFailure) else type(error).__name__
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="Consume this one-shot live smoke authorization")
    for name in ("admin-token-file", "ca-file", "upstream-ca-file", "run-claim-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    args = parser.parse_args()
    def expired(_signum, _frame):
        raise CheckFailure("live smoke exceeded its process deadline")
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
