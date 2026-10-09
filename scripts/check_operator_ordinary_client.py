#!/usr/bin/env python3
"""One-shot private CONNECT/TLS acceptance for ordinary buffered JSON clients.

Never launches a stack or contacts a provider. Uses only the fixed synthetic
upstream, a fresh catalog and the existing durable one-shot fixture claim.
V1 remains the default; V2 metadata-discard acceptance requires explicit opt-in.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import http.client
import io
import json
from pathlib import Path
import signal
import ssl
import time
from urllib.parse import urlencode

try:
    from scripts.check_operator_catalog import (
        COLLECTIONS, OperatorCatalogCheck, claim_fixture, features,
    )
    from scripts.check_operator_demo import AUTHORITY, SHA256, CheckFailure, TunnelTLS, require, token_file
    from scripts.operator_ordinary_client_fixture import (
        DUMMY_AUTHORIZATION, EMPTY_RESPONSE_CONTENT_TYPE, FIXTURE_PATH,
        JSON_RESPONSE_BODY, QUERY_KEYS, REQUEST_BODY, REQUEST_BODY_SHA256, V2_RESPONSE_METADATA, build_target,
    )
except ModuleNotFoundError:
    from check_operator_catalog import COLLECTIONS, OperatorCatalogCheck, claim_fixture, features
    from check_operator_demo import AUTHORITY, SHA256, CheckFailure, TunnelTLS, require, token_file
    from operator_ordinary_client_fixture import (
        DUMMY_AUTHORIZATION, EMPTY_RESPONSE_CONTENT_TYPE, FIXTURE_PATH,
        JSON_RESPONSE_BODY, QUERY_KEYS, REQUEST_BODY, REQUEST_BODY_SHA256, V2_RESPONSE_METADATA, build_target,
    )


CASES = (("missing", None, 403), ("wrong", "Bearer SERVERWARE_WRONG", 403),
         ("json", DUMMY_AUTHORIZATION, 200), ("empty", DUMMY_AUTHORIZATION, 204))
ERRORS = {"missing": "credential_existing_header_missing", "wrong": "credential_existing_header_mismatch"}
MAX_WIRE = 16384 + 65536
START = "data_plane.credential.release_started"
RELEASE = "data_plane.response.released"
BLOCK = "data_plane.response.blocked"
CONNECT = "data_plane.connect.established"
DENIED = "data_plane.request.denied"
LEASE = "data_plane.credential_lease.issued"
RELOAD = "data_plane.policy.reloaded"
ZERO_COUNTERS = ("dropped", "required_failed", "send_failed")
DRAIN_COUNTERS = ("queue_depth", "reserved", "in_flight_optional", "pending_retry_batches", "pending_retry_events")
DEFAULT_RESPONSE_MODE = "unfiltered_json_or_empty_v1"
V2_RESPONSE_MODE = "unfiltered_json_or_empty_v2"
RESPONSE_MODES = {DEFAULT_RESPONSE_MODE: "bufferedJsonOrEmpty204V1",
                  V2_RESPONSE_MODE: "bufferedJsonOrEmpty204V2"}


def digest(body):
    return "sha256:" + hashlib.sha256(body).hexdigest()


def selected_response_mode(value=DEFAULT_RESPONSE_MODE):
    require(isinstance(value, str) and value in RESPONSE_MODES, "ordinary response mode selection invalid")
    return value


def request_path(case, authorization_sha256, body_sha256=REQUEST_BODY_SHA256, *,
                 response_mode=DEFAULT_RESPONSE_MODE):
    selected_response_mode(response_mode)
    require(case in {item[0] for item in CASES} and body_sha256 == REQUEST_BODY_SHA256,
            "ordinary fixture case or body commitment differs")
    fixture_case = "empty" if case == "empty" else "json"
    if response_mode == V2_RESPONSE_MODE:
        fixture_case += "_v2"
    return build_target(fixture_case, authorization_sha256)


def check_response(case, status, headers, body, wire, policy_hash, *, response_mode=DEFAULT_RESPONSE_MODE):
    """Compare parsed HTTP with independently captured bounded TLS plaintext."""
    selected_response_mode(response_mode)
    require(case in {item[0] for item in CASES} and isinstance(wire, bytes) and len(wire) <= MAX_WIRE,
            "ordinary response case or wire bound differs")
    head, separator, raw_body = wire.partition(b"\r\n\r\n")
    require(separator and len(head) <= 16384 and head.startswith(f"HTTP/1.1 {status} ".encode("ascii")),
            "ordinary response physical status or header bound differs")
    physical = []
    for line in head.split(b"\r\n")[1:]:
        name, colon, value = line.partition(b":")
        require(colon and name and not name[:1].isspace() and len(line) <= 4096,
                "ordinary response physical header invalid")
        physical.append((name.decode("ascii").lower(), value.decode("ascii").strip(" \t")))
    require(physical == [(name.lower(), value) for name, value in headers]
            and len({name for name, _ in physical}) == len(physical),
            "ordinary response duplicate or parser-divergent physical headers")
    values = dict(physical)
    require(not any(name in values for name in ("transfer-encoding", "trailer"))
            and raw_body == body, "ordinary response hidden bytes or unsupported framing")
    commitments = {}
    if case in ERRORS:
        document = json.loads(body)
        require(status == 403 and isinstance(document, dict) and document.get("allowed") is False
                and document.get("action") == "deny" and document.get("payload", {}).get("error") == ERRORS[case],
                "placeholder request was not denied by its exact policy guard")
    else:
        if response_mode == V2_RESPONSE_MODE:
            require(not any(name in values for name, _ in V2_RESPONSE_METADATA),
                    "ordinary V2 response forwarded unselected fixture metadata")
        require(values.get("x-serverware-policy-hash") == policy_hash,
                "ordinary response policy hash differs")
        commitments = {"requestDigest": values.get("x-serverware-request-digest"),
                       "operationDigest": values.get("x-serverware-operation-digest")}
        require(all(isinstance(value, str) and SHA256.fullmatch(value) for value in commitments.values()),
                "ordinary response request commitments missing")
        expected = JSON_RESPONSE_BODY if case == "json" else b""
        require(status == (200 if case == "json" else 204) and body == expected
                and values.get("x-serverware-response-body-sha256") == digest(expected),
                "ordinary response status, exact bytes or body commitment differs")
        if case == "empty":
            require("content-length" not in values and values.get("content-type") == EMPTY_RESPONSE_CONTENT_TYPE,
                    "empty204 invented framing or changed optional JSON metadata")
        else:
            require(values.get("content-type") == "application/json"
                    and values.get("content-length") == str(len(expected)),
                    "ordinary JSON response framing differs")
    return {"case": case, "status": status, "responseMode": response_mode, "responseBodyBytes": len(body),
            "responseBodySha256": digest(body), "capturedWireBytes": len(wire), **commitments}


class _CaptureReader(io.RawIOBase):
    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def readable(self):
        return True

    def readinto(self, buffer):
        return self.owner.readinto(buffer)


class CapturedTLS:
    """HTTPResponse may suppress 204 bodies; retain and drain actual plaintext.

    Closing its file view never closes the TLS owner before the independent
    EOF check. Already-prefetched bytes are captured exactly once.
    """
    def __init__(self, tls):
        self.tls, self.wire = tls, bytearray()

    def makefile(self, mode):
        require(mode == "rb", "unexpected ordinary response stream mode")
        return io.BufferedReader(_CaptureReader(self))

    def readinto(self, buffer):
        count = self.tls.readinto(buffer)
        require(len(self.wire) + count <= MAX_WIRE, "ordinary response exceeds captured wire bound")
        self.wire.extend(memoryview(buffer)[:count])
        return count

    def finish(self):
        buffer = bytearray(4096)
        try:
            while self.readinto(buffer):
                pass
        except ssl.SSLEOFError:
            # The complete HTTP message was parsed first. Abrupt transport EOF
            # does not make unobserved trailing bytes acceptable.
            pass
        return bytes(self.wire)


def audit_attempts(events, scope, *, response_mode=DEFAULT_RESPONSE_MODE):
    """Exact POST starts/terminals, separate from cache-dependent lease receipts."""
    expected_mode = RESPONSE_MODES[selected_response_mode(response_mode)]
    pairs, counts, row_ids = {}, Counter(), set()
    for row in events:
        kind, event = row.get("event_type"), row.get("event", {})
        if kind not in {START, RELEASE, BLOCK}:
            continue
        require(isinstance(row.get("id"), str) and row["id"] not in row_ids,
                "ordinary audit row identity reused")
        row_ids.add(row["id"])
        counts[kind] += 1
        require(kind != BLOCK and counts[kind] <= 2, "unexpected response block or extra dispatch audit")
        require(tuple(event.get(key) for key in ("principal_id", "route_id", "policy_hash")) == tuple(scope)
                and event.get("method") == "POST" and event.get("body_sha256") == "sha256:" + REQUEST_BODY_SHA256,
                "ordinary audit request scope, method or raw body differs")
        attempt = event.get("attempt_id")
        require(isinstance(attempt, str) and SHA256.fullmatch(attempt) and event.get("flow_id") == attempt,
                "ordinary audit attempt identity differs")
        commitments = tuple(event.get(key) for key in ("request_digest", "operation_digest"))
        require(all(isinstance(value, str) and SHA256.fullmatch(value) for value in commitments),
                "ordinary audit request commitments missing")
        pair = pairs.setdefault(attempt, {"commitments": commitments})
        slot = "start" if kind == START else "terminal"
        require(slot not in pair and pair["commitments"] == commitments,
                "ordinary attempt reused or commitment changed")
        pair[slot] = row["id"]
        if kind == START:
            require(event.get("outcome") == "release_started", "ordinary release-start outcome differs")
        else:
            status = event.get("upstream_status")
            expected = JSON_RESPONSE_BODY if status == 200 else b""
            validation = event.get("response_validation", {})
            require(status in {200, 204} and event.get("outcome") == "released"
                    and event.get("response_body_sha256") == digest(expected)
                    and event.get("response_body_bytes") == len(expected)
                    and validation.get("ok") is True and validation.get("mode") == expected_mode
                    and validation.get("body_bytes_preserved") is True,
                    "ordinary audit terminal bytes, status or mode differs")
            pair["status"] = status
    complete = {key: value for key, value in pairs.items() if {"start", "terminal"} <= value.keys()}
    require(len(pairs) <= 2 and len({pair["status"] for pair in complete.values()}) == len(complete),
            "ordinary response statuses or attempts repeated")
    require(len({pair["commitments"][0] for pair in complete.values()}) == len(complete),
            "ordinary distinct requests reused a canonical request commitment")
    return complete, counts


class OrdinaryClientCheck(OperatorCatalogCheck):
    def __init__(self, args):
        super().__init__(args)
        self.response_mode = selected_response_mode(getattr(args, "response_mode", DEFAULT_RESPONSE_MODE))
        self.negative_observations, self.feature_observations = [], []

    def count(self):
        status, document = self.json_request(self.upstream,
            "/_test/request-count?" + urlencode({"method": "POST", "path": FIXTURE_PATH}), context=self.upstream_ca)
        require(status == 200 and isinstance(document, dict) and type(document.get("count")) is int
                and document["count"] == self.upstream_count("POST", FIXTURE_PATH),
                "ordinary global and per-run dispatch counts differ")
        return document["count"]

    def dispatch(self, case, placeholder):
        target = request_path(case, hashlib.sha256(("Bearer " + self.credential).encode("ascii")).hexdigest(),
                              response_mode=self.response_mode)
        raw = self.tunnel(self.client_token)
        try:
            with TunnelTLS(raw, self.ca, self.timeout) as tls:
                headers = [f"POST {target} HTTP/1.1", f"Host: {AUTHORITY}", "Connection: close",
                    f"User-Agent: serverware-test-run/{self.run_id}", "Accept: application/json",
                    "Content-Type: application/json", f"Content-Length: {len(REQUEST_BODY)}"]
                if placeholder is not None:
                    require(placeholder in {DUMMY_AUTHORIZATION, "Bearer SERVERWARE_WRONG"}, "unexpected dummy header")
                    headers.append("Authorization: " + placeholder)
                tls.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + REQUEST_BODY)
                capture = CapturedTLS(tls)
                response = http.client.HTTPResponse(capture)
                try:
                    response.begin()
                    body = response.read(65537)
                    require(len(body) <= 65536, "ordinary response body bound exceeded")
                    wire = capture.finish()
                    self.clean(wire)
                    result = check_response(case, response.status, response.getheaders(), body, wire, self.policy_hash,
                                            response_mode=self.response_mode)
                    if case in ERRORS:
                        self.clean(json.dumps(json.loads(body)).encode("utf-8"))
                    return result
                finally:
                    response.close()
        finally:
            raw.close()

    def audit_drained(self):
        audit = self.health().get("audit", {})
        require(all(type(audit.get(key)) is int and audit[key] >= 0 for key in ZERO_COUNTERS + DRAIN_COUNTERS),
                "ordinary audit counters unavailable")
        self.last_audit_counters = {key: audit[key] for key in features.AUDIT_COUNTERS if type(audit.get(key)) is int}
        require(all(audit[key] == 0 for key in ZERO_COUNTERS), "ordinary audit delivery failed")
        return all(audit[key] == 0 for key in DRAIN_COUNTERS)

    def current(self, pins):
        snapshot = self.warm_cas_snapshot()
        require(snapshot["revision"] == pins["revision"] and snapshot["policy"]["sequence"] == pins["sequence"],
                "ordinary catalog changed during acceptance")
        for collection, original in pins["resources"].items():
            row = self.resource(snapshot, collection, original["id"])
            require(len(snapshot[collection]) == 1 and row["version"] == original["version"]
                    and row.get("status") == "active", "ordinary persisted resource changed")
        rule = self.resource(snapshot, "access_rules", pins["resources"]["access_rules"]["id"])
        require(rule.get("enforcement") == "active" and rule.get("response_mode") == self.response_mode,
                "ordinary rule is not active or its response mode changed")
        application = self.resource(snapshot, "applications", pins["resources"]["applications"]["id"])
        credential = self.resource(snapshot, "credentials", pins["resources"]["credentials"]["id"])
        require(application.get("principal_id") == pins["resources"]["applications"]["principal_id"]
                and application.get("token_generation") == 1 and application.get("token_status") == "valid"
                and application.get("access_status") == "active" and credential.get("active_rule_count") == 1
                and rule.get("route_id") == pins["resources"]["access_rules"]["route_id"]
                and rule.get("application_id") == application["id"] and rule.get("credential_id") == credential["id"],
                "ordinary current app, credential or rule binding differs")
        self.wait_health_loaded(self.policy_hash)

    def verify_ordinary_audit(self, baseline, scope, lease_scope):
        expected = Counter({CONNECT: 4, DENIED: 2, START: 2, RELEASE: 2,
            **{event: 1 for event, _, _ in self.mutations}})
        while True:
            events = self.audit()
            cutoff = features.audit_cutoff(events)
            require(all(cutoff.get(key) == value for key, value in baseline.items()), "startup audit history changed")
            new = [row for row in events if row["id"] not in baseline]
            counts = Counter(row.get("event_type") for row in new)
            require(not set(counts) - (set(expected) | {LEASE, RELOAD}), "unexpected named audit event in ordinary fixture")
            require(all(counts[key] <= amount for key, amount in expected.items()), "extra ordinary request or mutation audit")
            require(counts[RELOAD] <= 1, "ordinary fixture published more than one authority change")
            pairs, _ = audit_attempts(new, scope, response_mode=self.response_mode)
            observed = {item["status"]: (item["requestDigest"], item["operationDigest"])
                        for item in self.feature_observations if item["case"] in {"json", "empty"}}
            require(set(observed) == {200, 204}, "ordinary wire response commitments unavailable")
            require(all(pair["commitments"] == observed[pair["status"]] for pair in pairs.values()),
                    "ordinary durable audit commitments differ from actual wire responses")
            for row in new:
                event, kind = row.get("event", {}), row["event_type"]
                if kind == CONNECT:
                    require(event.get("principal_id") == scope[0] and event.get("policy_hash") == scope[2]
                            and event.get("method") == "CONNECT" and event.get("target") == AUTHORITY
                            and event.get("outcome") == "established", "ordinary CONNECT audit binding differs")
                elif kind == DENIED:
                    # Early placeholder denial retains route, not a fabricated principal or canonical digest.
                    require(event.get("route_id") == scope[1] and event.get("method") == "POST"
                            and event.get("outcome") == "denied" and event.get("error") in ERRORS.values(),
                            "ordinary placeholder denial audit differs")
                elif kind == LEASE:
                    require(event.get("purpose") in {"dispatchSecret", "generationMetadata"}
                            and all(event.get(key) == value for key, value in lease_scope.items() if key != "purpose")
                            and event.get("outcome") == "issued" and event.get("status_code") == 200,
                            "ordinary credential lease audit binding differs")
                elif kind == RELOAD:
                    require(event.get("policy_hash") == scope[2]
                            and event.get("previous_policy_hash") == self.initial_policy_hash
                            and event.get("policy_sequence") == self.active_sequence
                            and event.get("routes") == 1,
                            "ordinary policy reload audit binding differs")
            lease_counts = Counter(row["event"].get("purpose") for row in new if row["event_type"] == LEASE)
            require(all(value <= 2 for value in lease_counts.values()), "ordinary lease issuance exceeds two requests")
            mutations = {(row["event_type"], row.get("event", {}).get("resource_id"), row.get("event", {}).get("policy_hash")) for row in new}
            denials = Counter(row["event"].get("error") for row in new if row["event_type"] == DENIED)
            require(all(value <= 1 for value in denials.values()), "ordinary placeholder denial repeated")
            if (all(counts[key] == value for key, value in expected.items()) and len(pairs) == 2
                    and set(self.mutations) <= mutations and set(denials) == set(ERRORS.values())
                    and counts[RELOAD] >= 1 and 1 <= lease_counts["dispatchSecret"] <= 2 and self.audit_drained()):
                break
            self.audit_drained()
            time.sleep(min(0.25, self.timeout()))
        final = self.audit()
        require(features.audit_cutoff(final) == cutoff, "ordinary audit changed after drained checkpoint")
        features.reconcile_negative_phases(self, final)
        chain = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(chain.get("ok") is True and chain.get("complete") is True and chain.get("backend") == "sqlite",
                "ordinary complete persisted audit chain failed")
        return {"namedAuditInventory": dict(sorted(counts.items())), "leaseIssuanceByPurpose": dict(lease_counts),
                "durableAuditEventIds": sorted(row["id"] for row in new), "auditedRequestAttemptIds": sorted(pairs)}

    def run(self):
        self.response_mode = selected_response_mode(getattr(self.args, "response_mode", DEFAULT_RESPONSE_MODE))
        self.health()
        self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        if self.response_mode == V2_RESPONSE_MODE:
            capabilities = initial.get("capabilities")
            modes = capabilities.get("response_modes") if isinstance(capabilities, dict) else None
            require(isinstance(modes, list) and self.response_mode in modes,
                    "ordinary selected V2 response mode is not advertised")
        require(initial["revision"] == 1 and all(not initial[key] and initial["limits"][key]["retained"] == 0 for key in COLLECTIONS)
                and self.count() == 0, "ordinary acceptance requires a fresh unused catalog and upstream")
        self.policy_hash = self.initial_policy_hash = initial["policy"]["policy_hash"]
        self.wait_catalog_loaded("empty_catalog_loaded")
        while not self.audit_drained():
            time.sleep(min(0.25, self.timeout()))
        baseline = features.audit_cutoff(self.audit())
        credential, _, _ = self.mutate("/credentials", {"name": self.run_id + "-ordinary", "auth_type": "bearer", "secret": self.credential},
            collection="credentials", result_key="credential", event="operator_catalog.credential.created", creates=True)
        application, token, _ = self.mutate("/applications", {"name": self.run_id + "-ordinary", "token_lifetime_seconds": 3600},
            collection="applications", result_key="application", event="operator_catalog.application.created", creates=True, token=True)
        rule, _, _ = self.mutate("/access-rules", {"name": self.run_id + "-ordinary", "application_id": application["id"],
            "credential_id": credential["id"], "upstream_url": "https://" + AUTHORITY + FIXTURE_PATH, "methods": ["POST"],
            "request_body_mode": "preserve_json_v1", "response_mode": self.response_mode, "request_fields": [],
            "response_fields": [], "credential_input": "replace_exact", "placeholder": DUMMY_AUTHORIZATION,
            "query_keys": list(QUERY_KEYS), "allowed_headers": ["accept", "user-agent"]},
            collection="access_rules", result_key="access_rule", event="operator_catalog.access_rule.created", creates=True, authority_changed=True)
        expected_rule = {"request_body_mode": "preserve_json_v1", "response_mode": self.response_mode,
            "request_fields": [], "response_fields": [], "credential_input": "replace_exact", "placeholder": DUMMY_AUTHORIZATION}
        require(all(rule.get(key) == value for key, value in expected_rule.items()), "ordinary saved rule differs")
        snapshot, _ = self.wait_catalog_loaded("ordinary_rule_loaded")
        self.active_sequence = snapshot["policy"]["sequence"]
        require(all(self.resource(snapshot, "access_rules", rule["id"]).get(key) == value for key, value in expected_rule.items()),
                "ordinary content modes did not persist")
        pins = {"revision": snapshot["revision"], "sequence": snapshot["policy"]["sequence"],
            "resources": {"credentials": credential, "applications": application, "access_rules": rule}}
        self.client_token = token
        scope = (application["principal_id"], rule["route_id"], self.policy_hash)
        lease_scope = {"purpose": "dispatchSecret", "principal_id": scope[0], "route_id": scope[1], "policy_hash": scope[2],
            "credential_id": credential["id"], "data_plane_binary_digest": self.args.expected_binary_sha256}
        dispatched = 0
        for case, placeholder, _ in CASES:
            self.current(pins)
            require(self.count() == dispatched, "ordinary pre-request dispatch budget differs")
            observation = self.dispatch(case, placeholder)
            after = self.count()
            expected = dispatched + (case not in ERRORS)
            observation.update(upstreamCountBefore=dispatched, upstreamCountAfter=after)
            self.feature_observations.append(observation)
            require(after == expected, "ordinary dispatch count differs")
            if case in ERRORS:
                features.record_negative_phase(self, ERRORS[case], lease_scope)
            dispatched = after
        self.current(pins)
        require(dispatched == self.count() == 2, "ordinary total dispatch budget differs")
        evidence = self.verify_ordinary_audit(baseline, scope, lease_scope)
        self.results.extend(["missing_and_wrong_placeholder_403_without_dispatch_or_scoped_lease",
            "ordinary_post_preserves_exact_raw_json_and_injects_synthetic_credential",
            "empty204_preserves_optional_json_metadata_without_framing_or_body",
            "two_post_release_pairs_and_complete_drained_verified_audit_chain"])
        if self.response_mode == V2_RESPONSE_MODE:
            self.results.append("v2_fixed_unselected_metadata_absent_from_json_and_empty204_responses")
        result = {"ok": True, "schema": "serverware.operatorOrdinaryClientCheck/v1", "mode": "operator-development",
            "responseMode": self.response_mode, "auditResponseMode": RESPONSE_MODES[self.response_mode],
            "productionReady": False, "hardwareVerified": False, "publicDnsVerified": False,
            "proxyTransport": "private-http-connect-leg" if self.proxy.scheme == "http" else "verified-private-https-edge",
            "originTlsVerified": True, "runId": self.run_id, "checks": self.results,
            "credentialId": credential["id"], "applicationId": application["id"], "ruleId": rule["id"],
            "dataPlaneBinaryDigest": self.args.expected_binary_sha256, "upstreamDispatches": 2,
            "responsesReleased": 2, "responsesBlocked": 0, **features.safe_evidence(self), **evidence}
        self.clean(json.dumps(result, sort_keys=True).encode("utf-8"))
        return result


def run_checks(args):
    check = None
    try:
        require(isinstance(args.expected_binary_sha256, str) and SHA256.fullmatch(args.expected_binary_sha256),
                "expected binary digest must be exact lowercase SHA-256")
        require(type(args.timeout_seconds) is int and 10 <= args.timeout_seconds <= 180, "ordinary timeout must be between 10 and 180 seconds")
        selected_response_mode(getattr(args, "response_mode", DEFAULT_RESPONSE_MODE))
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = OrdinaryClientCheck(args)
        return check.run()
    except Exception as error:
        evidence = {}
        if check is not None:
            try:
                evidence = features.safe_evidence(check)
            except Exception:
                evidence = {"safeEvidenceUnavailable": True}
            evidence.update(responseMode=check.response_mode, auditResponseMode=RESPONSE_MODES[check.response_mode])
        return {"ok": False, "mode": "operator-development", "checks": list(check.results) if check else [], **evidence,
                "error": str(error) if isinstance(error, CheckFailure) else type(error).__name__}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file", "run-claim-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("proxy-ca-file", "control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--upstream-address")
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--response-mode", choices=tuple(RESPONSE_MODES), default=DEFAULT_RESPONSE_MODE)
    args = parser.parse_args()

    def expired(_signum, _frame):
        raise CheckFailure("ordinary acceptance exceeded its process deadline")

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(max(args.timeout_seconds, 1), 180))
    try:
        result = run_checks(args)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
