#!/usr/bin/env python3
"""One-shot private real-Rust static-key replacement across two warm tunnels.

Creates only synthetic resources in a fresh claimed private catalog. Never
launches a deployment or contacts a provider. Both assigned applications retain
their original token, rule and CONNECT/TLS socket across one replacement. The
explicit 5.25s wait accommodates the accepted five-second lease issuance cap;
it is not remote invalidation acknowledgement or recall of in-flight requests.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
import hashlib
import http.client
import json
from pathlib import Path
import secrets
import signal
import time

from scripts.check_operator_catalog import COLLECTIONS, claim_fixture, features
from scripts.check_operator_demo import AUTHORITY, SHA256, CheckFailure, TunnelTLS, require, token_file
from scripts.check_operator_ordinary_client import (
    BLOCK, CONNECT, LEASE, RELEASE, RELOAD, START, CapturedTLS, OrdinaryClientCheck,
    RESPONSE_MODES, V2_RESPONSE_MODE, check_response, digest, request_path,
)
from scripts.operator_ordinary_client_fixture import DUMMY_AUTHORIZATION, FIXTURE_PATH, QUERY_KEYS, REQUEST_BODY

PIN = "sha256:f430734734cb43fb60eb1e28a863b337c314bb3e5377b23b6671564c62a91d9b"
REPLACED = "operator_catalog.credential.key_replaced"
CONNECT_DENIED = "data_plane.connect.denied"
KEEP_ALIVE = "data_plane.connect.keep_alive"
LEASE_CAP_MS = 5000
WAIT_SECONDS = 5.25
# Preserve the real gate's ten-second head deadline, with one second margin.
TUNNEL_BUDGET_SECONDS = 9.0


def by_id(rows):
    result = {row["id"]: row for row in rows}
    require(len(result) == len(rows), "duplicate catalog resource identity")
    return result


def authority_projection(catalog):
    """Exclude only live observation; retain every other known or future field."""
    require(isinstance(catalog, dict), "catalog authority projection requires an object")
    return {key: value for key, value in catalog.items() if key != "observed_activity"}


def joined_attempts(rows, observations, credential_id, policy_hash):
    """Four POST/200 pairs keyed by app/route/commitments, not HTTP status."""
    expected = {(item["principalId"], item["routeId"], item["requestDigest"], item["operationDigest"]): item
                for item in observations}
    require(len(expected) == 4, "four distinct wire-scoped requests required")
    pairs, seen_rows = {}, set()
    for row in rows:
        kind, event = row.get("event_type"), row.get("event", {})
        if kind not in {START, RELEASE, BLOCK}:
            continue
        require(kind != BLOCK and row["id"] not in seen_rows, "blocked or repeated response audit")
        seen_rows.add(row["id"])
        key = tuple(event.get(name) for name in ("principal_id", "route_id", "request_digest", "operation_digest"))
        require(key in expected and event.get("policy_hash") == policy_hash
                and event.get("method") == "POST"
                and event.get("body_sha256") == digest(REQUEST_BODY)
                and event.get("credential_ref") == credential_id
                and type(event.get("credential_version")) is int
                and event["credential_version"] == expected[key]["generation"],
                "release audit request or actual key generation differs")
        attempt = event.get("attempt_id")
        require(isinstance(attempt, str) and SHA256.fullmatch(attempt)
                and event.get("flow_id") == attempt, "release audit attempt identity differs")
        pair = pairs.setdefault(attempt, {"key": key})
        slot = "start" if kind == START else "terminal"
        require(pair["key"] == key and slot not in pair, "release attempt reused")
        pair[slot] = row["id"]
        if kind == START:
            require(event.get("outcome") == "release_started", "release-start outcome differs")
        else:
            validation = event.get("response_validation", {})
            require(event.get("outcome") == "released" and event.get("upstream_status") == 200
                    and event.get("response_body_sha256") == expected[key]["responseBodySha256"]
                    and event.get("response_body_bytes") == len(REQUEST_BODY)
                    and validation.get("ok") is True
                    and validation.get("mode") == RESPONSE_MODES[V2_RESPONSE_MODE]
                    and validation.get("body_bytes_preserved") is True, "release terminal differs from wire response")
    require(len(pairs) <= 4, "extra request attempts")
    complete = {attempt: pair for attempt, pair in pairs.items() if {"start", "terminal"} <= pair.keys()}
    require(len({pair["key"] for pair in complete.values()}) == len(complete), "wire request joined twice")
    return complete


class KeyReplacementCheck(OrdinaryClientCheck):
    def __init__(self, args):
        self.key_material = []
        self.tunnel_deadline = None
        self.wait_evidence = None
        super().__init__(args)
        self.key_material = [self.credential, "synthetic-operator-" + secrets.token_urlsafe(32)]
        require(self.key_material[0] != self.key_material[1], "synthetic keys collided")

    def clean(self, content, *, allow_client_token=False):
        super().clean(content, allow_client_token=allow_client_token)
        require(all(value.encode("ascii") not in content for value in self.key_material),
                "old or replacement key escaped into a response or evidence")

    def timeout(self):
        remaining = super().timeout()
        if self.tunnel_deadline is not None:
            remaining = min(remaining, self.tunnel_deadline - time.monotonic())
            require(remaining > 0, "same-tunnel deadline exhausted; reconnect forbidden")
        return remaining

    def dispatch_same_tunnel(self, tls, application, rule, generation, *, close):
        target = request_path("json", hashlib.sha256(("Bearer " + self.key_material[generation - 1]).encode()).hexdigest(),
                              response_mode=V2_RESPONSE_MODE)
        require(not tls.closed and tls.raw.fileno() >= 0, "original tunnel is closed")
        started = time.monotonic()
        self.timeout()
        headers = [f"POST {target} HTTP/1.1", f"Host: {AUTHORITY}",
                   "Connection: " + ("close" if close else "keep-alive"),
                   f"User-Agent: catchplate-test-run/{self.run_id}", "Accept: application/json",
                   "Content-Type: application/json", f"Content-Length: {len(REQUEST_BODY)}",
                   "Authorization: " + DUMMY_AUTHORIZATION]
        tls.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + REQUEST_BODY)
        capture = CapturedTLS(tls)
        response = http.client.HTTPResponse(capture)
        try:
            response.begin()
            body = response.read(65537)
            require(len(body) <= 65536 and response.getheader("Connection", "").lower()
                    == ("close" if close else "keep-alive"), "response framing or persistence differs")
            # The first response has exact Content-Length; EOF belongs only to
            # the final response. A first-response finish() would close the test.
            wire = capture.finish() if close else bytes(capture.wire)
            self.clean(wire)
            result = check_response("json", response.status, response.getheaders(), body, wire,
                                    self.policy_hash, response_mode=V2_RESPONSE_MODE)
        finally:
            response.close()  # CapturedTLS file views do not own/close tls.
        result.update(applicationId=application["id"], principalId=application["principal_id"],
                      routeId=rule["route_id"], generation=generation,
                      connectionDirective="close" if close else "keep-alive",
                      requestStartedMonotonicNs=int(started * 1_000_000_000))
        self.feature_observations.append(result)
        return time.monotonic()

    def unchanged(self, before, after, credential):
        require(after["revision"] == before["revision"] + 1
                and after["policy"] == before["policy"], "replacement changed signed policy or wrong revision")
        for collection in ("applications", "access_rules"):
            require(by_id(after[collection]) == by_id(before[collection]), "replacement changed application or rule")
        row = self.resource(after, "credentials", credential["id"])
        require(len(after["credentials"]) == 1 and row["id"] == credential["id"]
                and row["status"] == "active" and row["auth_type"] == "bearer"
                and row["active_rule_count"] == 2 and row["version"] == credential["version"] + 1
                and type(row.get("credential_generation")) is int and row["credential_generation"] == 2,
                "replacement did not preserve identity and advance core/catalog versions")

    def verify_replacement_audit(self, baseline, assigned, unassigned, credential_id):
        expected = Counter(kind for kind, _, _ in self.mutations)
        expected.update({CONNECT: 2, CONNECT_DENIED: 1, KEEP_ALIVE: 2, START: 4, RELEASE: 4})
        scopes = {(app["principal_id"], rule["route_id"]) for app, rule, _ in assigned}
        loaded = []
        for stage in ("initial", "assigned_rule_0", "assigned_rule_1"):
            observed = [item for item in self.observations if item["stage"] == stage]
            require(len(observed) == 1, "exact initial and two loaded-rule observations required")
            loaded.append(observed[0])
        require(loaded[0]["policyHash"] == self.initial_policy_hash
                and loaded[-1]["policyHash"] == self.policy_hash
                and all(current["sequence"] == previous["sequence"] + 1
                        and current["policyHash"] != previous["policyHash"]
                        for previous, current in zip(loaded, loaded[1:])), "loaded policy chain differs")
        expected_reloads = Counter((previous["policyHash"], current["policyHash"], current["sequence"], index)
                                  for index, (previous, current) in enumerate(zip(loaded, loaded[1:]), 1))
        while True:
            events = self.audit()
            cutoff = features.audit_cutoff(events)
            require(all(cutoff.get(key) == value for key, value in baseline.items()), "baseline audit changed")
            rows = [row for row in events if row["id"] not in baseline]
            counts = Counter(row.get("event_type") for row in rows)
            require(not set(counts) - (set(expected) | {LEASE, RELOAD}), "unexpected audit event")
            require(all(counts[kind] <= amount for kind, amount in expected.items())
                    and counts[RELOAD] <= 2, "extra request, replacement or policy publication")
            pairs = joined_attempts(rows, self.feature_observations, credential_id, self.policy_hash)
            leases = Counter()
            reloads = Counter()
            established, kept = Counter(), Counter()
            replacements = []
            for row in rows:
                event, kind = row.get("event", {}), row["event_type"]
                principal = event.get("principal_id")
                if kind == CONNECT:
                    require(principal in {app["principal_id"] for app, _, _ in assigned}
                            and event.get("policy_hash") == self.policy_hash and event.get("target") == AUTHORITY
                            and event.get("outcome") == "established", "assigned CONNECT identity differs")
                    established[principal] += 1
                elif kind == KEEP_ALIVE:
                    require(event.get("intercepted_request_count") == 2
                            and principal in {app["principal_id"] for app, _, _ in assigned}
                            and event.get("policy_hash") == self.policy_hash, "same-tunnel request count differs")
                    kept[principal] += 1
                elif kind == CONNECT_DENIED:
                    # Unassigned apps are deliberately absent from signed
                    # principals. Do not invent an identity in their denial.
                    require(principal is None and event.get("outcome") == "denied"
                            and event.get("payload", {}).get("error") == "client_principal_denied",
                            "unassigned CONNECT denial identity differs")
                elif kind == LEASE:
                    scope = (principal, event.get("route_id"))
                    require(scope in scopes and event.get("credential_id") == credential_id
                            and event.get("policy_hash") == self.policy_hash
                            and event.get("data_plane_binary_digest") == PIN and event.get("outcome") == "issued"
                            and event.get("status_code") == 200
                            and event.get("purpose") in {"dispatchSecret", "generationMetadata"}, "lease escaped assigned scope")
                    if event.get("purpose") == "dispatchSecret":
                        issued, expiry = event.get("issued_at_epoch_ms"), event.get("expires_at_epoch_ms")
                        require(type(issued) is int and type(expiry) is int
                                and 0 < expiry - issued <= LEASE_CAP_MS, "accepted lease exceeds expiry-wait basis")
                        # Issuance DTO exposes expected_credential_version, not
                        # the actual returned generation. The actual version is
                        # proved by each joined release_started event above.
                        leases[scope] += 1
                elif kind == REPLACED:
                    require(event.get("resource_id") == credential_id
                            and event.get("previous_credential_generation") == 1
                            and event.get("credential_generation") == 2
                            and event.get("policy_hash") == self.policy_hash, "replacement audit generation differs")
                    replacements.append(row["id"])
                elif kind == RELOAD:
                    transition = tuple(event.get(key) for key in
                                       ("previous_policy_hash", "policy_hash", "policy_sequence", "routes"))
                    require(type(event.get("policy_sequence")) is int and type(event.get("routes")) is int
                            and transition in expected_reloads, "reload audit does not join the exact loaded policy chain")
                    reloads[transition] += 1
                    require(reloads[transition] <= expected_reloads[transition], "loaded policy transition repeated")
            needed = Counter({scope: 2 for scope in scopes})
            mutations = {(row["event_type"], row.get("event", {}).get("resource_id"), row.get("event", {}).get("policy_hash")) for row in rows}
            require(all(value <= 1 for value in established.values()) and all(value <= 1 for value in kept.values()),
                    "reconnect or extra persistent connection detected")
            require(not leases - needed, "extra dispatch-secret issuance")
            if (all(counts[kind] == amount for kind, amount in expected.items()) and len(pairs) == 4
                    and leases == needed and len(replacements) == 1 and set(self.mutations) <= mutations
                    and reloads == expected_reloads and self.audit_drained()):
                break
            self.audit_drained()
            time.sleep(min(0.25, self.timeout()))
        final = self.audit()
        require(features.audit_cutoff(final) == cutoff, "audit changed after drained checkpoint")
        features.reconcile_negative_phases(self, final)
        chain = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(chain.get("ok") is True and chain.get("complete") is True and chain.get("backend") == "sqlite",
                "complete durable audit chain verification failed")
        return {"namedAuditInventory": dict(sorted(counts.items())), "auditedRequestAttemptIds": sorted(pairs),
                "replacementAuditEventIds": replacements, "durableAuditEventIds": sorted(row["id"] for row in rows)}

    def run(self):
        self.health()
        self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        require(initial["revision"] == 1 and all(not initial[key] and initial["limits"][key]["retained"] == 0 for key in COLLECTIONS)
                and self.count() == 0, "fresh unused private catalog and upstream required")
        require(V2_RESPONSE_MODE in initial.get("capabilities", {}).get("response_modes", []), "ordinary V2 unavailable")
        self.policy_hash = self.initial_policy_hash = initial["policy"]["policy_hash"]
        self.wait_catalog_loaded("initial")
        while not self.audit_drained():
            time.sleep(min(0.25, self.timeout()))
        baseline = features.audit_cutoff(self.audit())
        credential, _, _ = self.mutate("/credentials", {"name": self.run_id + "-key", "auth_type": "bearer", "secret": self.key_material[0]},
            collection="credentials", result_key="credential", event="operator_catalog.credential.created", creates=True)
        require(type(credential.get("credential_generation")) is int and credential["credential_generation"] == 1,
                "fresh static credential must expose core generation one")
        apps = [self.mutate("/applications", {"name": self.run_id + "-app-" + str(index), "token_lifetime_seconds": 3600},
            collection="applications", result_key="application", event="operator_catalog.application.created", creates=True, token=True)[:2]
            for index in range(3)]
        assigned = []
        for index, (app, token) in enumerate(apps[:2]):
            rule, _, _ = self.mutate("/access-rules", {"name": self.run_id + "-rule-" + str(index),
                "application_id": app["id"], "credential_id": credential["id"], "upstream_url": "https://" + AUTHORITY + FIXTURE_PATH,
                "methods": ["POST"], "request_body_mode": "preserve_json_v1", "response_mode": V2_RESPONSE_MODE,
                "request_fields": [], "response_fields": [], "credential_input": "replace_exact", "placeholder": DUMMY_AUTHORIZATION,
                "query_keys": list(QUERY_KEYS), "allowed_headers": ["accept", "user-agent"]},
                collection="access_rules", result_key="access_rule", event="operator_catalog.access_rule.created", creates=True, authority_changed=True)
            self.wait_catalog_loaded("assigned_rule_" + str(index))
            assigned.append((app, rule, token))
        before = self.warm_cas_snapshot()
        require([len(before[key]) for key in COLLECTIONS] == [1, 3, 2], "private resource budget differs")
        credential = self.resource(before, "credentials", credential["id"])
        unassigned, unassigned_token = apps[2]
        require(self.resource(before, "applications", unassigned["id"])["access_status"] == "unassigned", "negative app is assigned")
        self.tunnel(unassigned_token, expected_status=403)
        require(self.count() == 0, "unassigned app dispatched upstream")
        features.record_negative_phase(self, "unassigned_app", {"principal_id": unassigned["principal_id"]})
        timings, sockets = [], []
        with ExitStack() as cleanup:
            for app, rule, token in assigned:
                raw = self.tunnel(token)
                cleanup.callback(raw.close)
                tls = cleanup.enter_context(TunnelTLS(raw, self.ca, self.timeout))
                finished = self.dispatch_same_tunnel(tls, app, rule, 1, close=False)
                if self.tunnel_deadline is None:
                    self.tunnel_deadline = finished + TUNNEL_BUDGET_SECONDS
                sockets.append((tls, raw.fileno(), finished))
            require(self.count() == 2, "both old-key warm dispatches required")
            cas = self.warm_cas_snapshot()
            require(authority_projection(cas) == authority_projection(before), "catalog authority changed before replacement")
            replacement, issued, result = self.submit_mutation(cas, "/credentials/replace-key",
                {"id": credential["id"], "expected_credential_generation": 1, "secret": self.key_material[1]}, result_key="credential")
            committed = time.monotonic()
            require(issued is None, "replacement issued an application token")
            details = result.get("key_replacement", {})
            require(details.get("previous_credential_generation") == 1 and details.get("credential_generation") == 2
                    and details.get("cache_invalidation") in {"local_completed", "local_unconfirmed"}
                    and details.get("in_flight_requests") == "not_recalled", "replacement cache/generation contract differs")
            require(self.tunnel_deadline - committed > WAIT_SECONDS + 0.25, "insufficient original-tunnel time for lease-expiry wait")
            time.sleep(WAIT_SECONDS)
            waited = time.monotonic() - committed
            require(waited >= WAIT_SECONDS, "post-commit wait was shortened")
            self.wait_evidence = {"basis": "accepted issuance TTL cap; private single checker with no other issuers",
                "sourceLeaseTtlUpperBoundMs": LEASE_CAP_MS, "minimumPostCommitWaitMs": 5250,
                "actualPostCommitWaitMonotonicNs": int(waited * 1_000_000_000),
                "remoteInvalidationAcknowledged": False, "inFlightRequestsRecalled": False,
                "localCacheInvalidation": details["cache_invalidation"]}
            for (app, rule, _), (tls, descriptor, old_finished) in zip(assigned, sockets):
                require(tls.raw.fileno() == descriptor, "original socket replaced")
                sent = time.monotonic()
                self.dispatch_same_tunnel(tls, app, rule, 2, close=True)
                timings.append({"applicationId": app["id"], "ruleId": rule["id"], "sameSocket": True,
                                "oldResponseToNewRequestMonotonicNs": int((sent - old_finished) * 1_000_000_000),
                                "unchangedGateHeadDeadlineMs": 10000, "checkerSafetyBudgetMs": 9000})
        self.tunnel_deadline = None
        after = self.warm_cas_snapshot()
        self.unchanged(before, after, credential)
        self.finalize_mutation(result, after, collection="credentials", result_key="credential", event=REPLACED)
        require(replacement == self.resource(after, "credentials", credential["id"]), "replacement DTO did not persist")
        require(self.count() == 4, "four and only four upstream dispatches required")
        evidence = self.verify_replacement_audit(baseline, assigned, unassigned, credential["id"])
        require(authority_projection(self.catalog()) == authority_projection(after), "catalog authority changed during final verification")
        return {"ok": True, "schema": "catchplate.operatorKeyReplacementCheck/v1", "syntheticOnly": True,
            "productionReady": False, "publicDnsVerified": False, "realProviderVerified": False,
            "dataPlaneBinaryDigest": PIN, "responseMode": V2_RESPONSE_MODE,
            "credentialId": credential["id"], "initialCredentialGeneration": 1, "replacementCredentialGeneration": 2,
            "assignedApplicationIds": [app["id"] for app, _, _ in assigned], "ruleIds": [rule["id"] for _, rule, _ in assigned],
            "unassignedApplicationId": unassigned["id"], "unassignedConnectDenied": True,
            "unchangedPolicyHash": self.policy_hash, "policySequence": after["policy"]["sequence"],
            "catalogRevision": after["revision"], "upstreamDispatches": 4, "assignedConnects": 2,
            "functionalRetries": 0, "reconnects": 0, "automaticKeyRenewals": 0,
            "leaseExpiryWait": self.wait_evidence, "tunnelTimings": timings, **features.safe_evidence(self), **evidence}


def run_checks(args):
    check = None
    try:
        require(args.expected_binary_sha256 == PIN, "exact accepted normal f430 binary required")
        require(type(args.timeout_seconds) is int and 10 <= args.timeout_seconds <= 120, "checker deadline must be 10..120 seconds")
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = KeyReplacementCheck(args)
        result = check.run()
        check.clean(json.dumps(result, sort_keys=True).encode("utf-8"))
        return result
    except Exception as error:
        safe = {}
        if check is not None:
            try:
                safe = features.safe_evidence(check)
                safe["leaseExpiryWait"] = check.wait_evidence
            except Exception:
                safe = {"safeEvidenceUnavailable": True}
        return {"ok": False, "syntheticOnly": True, "productionReady": False, **safe,
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
    parser.add_argument("--response-mode", choices=(V2_RESPONSE_MODE,), default=V2_RESPONSE_MODE)
    args = parser.parse_args()

    def expired(_signum, _frame):
        raise CheckFailure("key replacement acceptance process deadline exceeded")

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
