#!/usr/bin/env python3
"""One-shot PRIVATE app -> Rust -> CONNECT -> synthetic-provider acceptance.

Run only against the separately reviewed Basic fixture and accepted normal ELF.
The setup-only seed models an older one-hour manual token near natural expiry;
no product clock, token lifetime, grant limit or overlap constant is changed.
Enrollment, signed renewal, exact replay and cancellation use real HTTP. The
old socket is deliberately opened within ten seconds of its original expiry,
inside the unchanged private TLS relay's fifteen-second connection lifetime.
The seed starts a 150-second window; this checker has a 180-second wall bound,
leaving at least 30 seconds after that cutoff even with immediate startup.
This checker neither launches services nor retries provider/application writes.
"""
from __future__ import annotations

import argparse
from collections import Counter
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import sys
import time
from urllib.parse import urlsplit
import uuid

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.check_operator_catalog import claim_fixture, features
from scripts.check_operator_demo import AUTHORITY, SHA256, CheckFailure, TunnelTLS, require, token_file
from scripts.check_operator_ordinary_client import (
    BLOCK, CONNECT, LEASE, RELOAD, RELEASE, START, CapturedTLS, OrdinaryClientCheck, V2_RESPONSE_MODE, check_response, digest,
)
from scripts.check_operator_proxy_basic import BASIC, CONNECT_DENIED, PROXY, ProxyBasicCheck, require_ca_pair
from scripts.operator_ordinary_client_fixture import DUMMY_AUTHORIZATION, FIXTURE_PATH, QUERY_KEYS, REQUEST_BODY

PATH = "/v1/workload/renew"
DOMAIN = b"serverware.workload-token-renewal/v1\x00POST /v1/workload/renew\x00"
SEED = Path("/seed-output/client.json")
REAUTH = "data_plane.connect.reauthentication_denied"
KEEP_ALIVE = "data_plane.connect.keep_alive"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def seed_document():
    descriptor = os.open(SEED, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o400 and 0 < info.st_size <= 4096, "private seed file refused")
        raw = source.read(4097)
        require(len(raw) == info.st_size, "private seed file changed during read")
    value = json.loads(raw)
    require(set(value) == {"schema", "application_id", "client_token", "token_sha256", "original_expiry_epoch_ms",
        "created_at", "created_at_epoch_ms", "seeded_at_epoch_ms", "original_lifetime_seconds",
        "modeled_retained_age_seconds", "synthetic_retained_state", "token_generation", "proxy_authentication"}
        and value["schema"] == "serverware.privateWorkloadRenewalSeed/v1"
        and value["synthetic_retained_state"] is True and value["original_lifetime_seconds"] == 3600
        and value["modeled_retained_age_seconds"] == 3450 and value["token_generation"] == 1
        and value["proxy_authentication"] == BASIC
        and value["original_expiry_epoch_ms"] - value["created_at_epoch_ms"] == 3_600_000
        and value["original_expiry_epoch_ms"] - value["seeded_at_epoch_ms"] == 150_000
        and digest(value["client_token"].encode("ascii")) == value["token_sha256"], "retained seed contract differs")
    return value


class RenewalCheck(ProxyBasicCheck):
    def __init__(self, args):
        self.sensitive_proxy_forms = []
        # Reuse CA, endpoint, catalog, leak checking and stock Requests helpers;
        # the unrelated curl body-file/setup controls are intentionally absent.
        OrdinaryClientCheck.__init__(self, args)
        self.ca_evidence = require_ca_pair(args.proxy_ca_file, args.ca_file, args.requests_ca_file)
        self.seed = seed_document()
        self.old_token = self.seed["client_token"]
        self.issued_tokens.append(self.old_token)
        self.credentials(self.seed["application_id"], self.old_token)
        self.key = Ed25519PrivateKey.generate()
        self.sensitive_proxy_forms.append(self.key.private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex())
        self.application = self.rule = None
        self.renewal_receipt = None
        self.tunnels = []

    def persistent(self, token):
        raw = self.tunnel(token)
        try:
            tls = TunnelTLS(raw, self.ca, self.timeout)
        except BaseException:
            raw.close()
            raise
        self.tunnels.append(tls)
        return tls

    def same_socket(self, tls, phase, *, denied_reason=None):
        before = self.count()
        sent_at = time.time_ns() // 1_000_000
        descriptor = tls.raw.fileno()
        require(descriptor >= 0 and not tls.closed, "original CONNECT socket unavailable; reconnect forbidden")
        target = urlsplit(self.target())
        headers = {"Host": AUTHORITY, **self.request_headers("application/json;q=0.8"),
            "Connection": "keep-alive", "Content-Length": str(len(REQUEST_BODY))}
        wire = [f"POST {target.path}?{target.query} HTTP/1.1"]
        wire.extend(name + ": " + value for name, value in headers.items())
        tls.sendall(("\r\n".join(wire) + "\r\n\r\n").encode("ascii") + REQUEST_BODY)
        captured = CapturedTLS(tls)
        response = http.client.HTTPResponse(captured)
        try:
            response.begin()
            body = response.read(65537)
            self.clean(bytes(captured.wire))
            require(len(body) <= 65536 and tls.raw.fileno() == descriptor, "same-socket response bound differs")
            if denied_reason is not None:
                document = json.loads(body)
                require(response.status == 403 and document == {"error":"connect_identity_revalidation_failed",
                    "reason":denied_reason, "policy_hash":self.policy_hash}
                    and response.getheader("Connection", "").lower() == "close", "CONNECT revalidation refusal differs")
                require(self.count() == before, "rejected persistent request dispatched upstream")
                return {"phase":phase, "status":403, "reason":denied_reason, "sameSocket":True,
                    "sentAtEpochMs":sent_at, "finishedAtEpochMs":time.time_ns() // 1_000_000}
            require(response.getheader("Connection", "").lower() == "keep-alive", "persistent response closed connection")
            result = check_response("json", response.status, response.getheaders(), body, bytes(captured.wire),
                self.policy_hash, response_mode=V2_RESPONSE_MODE)
        finally:
            response.close()  # The capture's file view does not own tls.
        require(self.count() == before + 1, "persistent request did not dispatch exactly once")
        result.update(sentAtEpochMs=sent_at, finishedAtEpochMs=time.time_ns() // 1_000_000)
        self.record(result, phase)
        return result

    def record(self, result, phase):
        result.update(phase=phase, policyHash=self.policy_hash, principalId=self.application["principal_id"],
            applicationId=self.application["id"], routeId=self.rule["route_id"])
        self.feature_observations.append(result)

    def stock(self, token, phase, *, denied=False):
        before = self.count()
        result = self.requests_call(self.application["id"], token, expected="denied" if denied else "success")
        require(self.count() == before + (0 if denied else 1), "stock Requests dispatch count differs")
        if not denied:
            self.record(result, phase)

    def machine(self, raw):
        self.fixed_proxy_resolution()
        with requests.Session() as session:
            session.trust_env = False
            require(all(adapter.max_retries.total == 0 for adapter in session.adapters.values()), "machine retry defaults differ")
            with session.post(PROXY + PATH, data=raw, headers={"Content-Type":"application/json"},
                    verify=str(self.args.proxy_ca_file), timeout=(self.timeout(), self.timeout()),
                    allow_redirects=False, stream=True) as response:
                require(response.status_code == 200 and response.headers.get("Content-Type") == "application/json",
                    "signed Rust machine renewal failed; outcome may be unknown, no retry performed")
                body = response.raw.read(8193, decode_content=False)
                require(len(body) <= 8192, "renewal response exceeds bound")
                self.clean(body)
                value = json.loads(body)
                require(set(value) == {"operation", "application", "revision", "policy"}, "renewal response shape differs")
                return value

    def prepare_operation(self):
        enrollment = self.application["client_renewal"]
        issued = time.time_ns() // 1_000_000
        token = secrets.token_urlsafe(32)
        self.issued_tokens.append(token)
        self.credentials(self.application["id"], token)
        fields = {"schema":"serverware.workloadTokenRenewal/v1", "audience":enrollment["audience"],
            "application_id":self.application["id"], "enrollment_id":enrollment["enrollment_id"],
            "expected_token_generation":1, "operation_id":str(uuid.uuid4()), "issued_at_epoch_ms":issued,
            "expires_at_epoch_ms":issued + 60_000, "token_sha256":digest(token.encode("ascii")),
            "token_expires_at_epoch_ms":min(issued + 3_600_000, enrollment["expires_at_epoch_ms"])}
        require(enrollment["token_lifetime_seconds"] == 3600 and enrollment["overlap_seconds"] == 300,
            "enrolled product lifetime/overlap changed")
        signing = DOMAIN + canonical(fields)
        raw = canonical({**fields, "signature":self.key.sign(signing).hex()})
        path = self.args.run_claim_file.parent / "renewal-operation.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as journal:
            journal.write(canonical({"candidate_token":token, "request":json.loads(raw)}))
            journal.flush()
            os.fsync(journal.fileno())
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return token, fields, digest(signing), raw

    def verify_audit(self, baseline):
        expected = Counter((row["policyHash"], row["requestDigest"], row["operationDigest"])
            for row in self.feature_observations)
        while True:
            events = self.audit()
            cutoff = features.audit_cutoff(events)
            require(all(cutoff.get(key) == value for key, value in baseline.items()), "baseline audit was altered")
            rows = [row for row in events if row["id"] not in baseline]
            counts = Counter(row["event_type"] for row in rows)
            expected_counts = Counter(kind for kind, _, _ in self.mutations)
            expected_counts.update({START:5, RELEASE:5, CONNECT:4, CONNECT_DENIED:1, REAUTH:2, KEEP_ALIVE:2,
                "operator_catalog.application.token_renewed":1})
            require(not set(counts) - (set(expected_counts) | {LEASE, RELOAD})
                and all(counts[kind] <= number for kind, number in expected_counts.items()),
                "unexpected connected-renewal audit inventory")
            pairs, reauth, renewed, kept = {}, [], [], []
            for row in rows:
                event, kind = row.get("event", {}), row["event_type"]
                if kind in {START, RELEASE, BLOCK}:
                    require(kind != BLOCK and event.get("principal_id") == self.application["principal_id"]
                        and event.get("route_id") == self.rule["route_id"] and event.get("credential_ref") == self.credential_id
                        and event.get("credential_version") == 1 and event.get("body_sha256") == digest(REQUEST_BODY),
                        "release audit scope differs")
                    key = tuple(event.get(name) for name in ("policy_hash", "request_digest", "operation_digest"))
                    require(key in expected, "unobserved provider request in audit")
                    attempt = event.get("attempt_id")
                    require(isinstance(attempt, str) and SHA256.fullmatch(attempt) and event.get("flow_id") == attempt,
                        "release attempt identity differs")
                    pair = pairs.setdefault(attempt, {"key":key})
                    slot = "start" if kind == START else "terminal"
                    require(pair["key"] == key and slot not in pair, "audit attempt duplicated")
                    pair[slot] = row["id"]
                    if slot == "terminal":
                        require(event.get("outcome") == "released" and event.get("upstream_status") == 200
                            and event.get("response_body_sha256") == digest(REQUEST_BODY), "terminal audit differs")
                elif kind in {CONNECT, CONNECT_DENIED, KEEP_ALIVE}:
                    require(event.get("method") == "CONNECT" and event.get("target") == AUTHORITY,
                        "CONNECT audit destination differs")
                    if kind in {CONNECT, KEEP_ALIVE}:
                        require(event.get("principal_id") == self.application["principal_id"]
                            and event.get("policy_hash") in {item["policyHash"] for item in self.observations}
                            and event.get("outcome") == ("established" if kind == CONNECT else "keep_alive"),
                            "CONNECT audit identity differs")
                        if kind == KEEP_ALIVE:
                            kept.append(event.get("intercepted_request_count"))
                    else:
                        require(event.get("principal_id") is None and event.get("policy_hash") is None
                            and event.get("outcome") == "denied"
                            and event.get("payload", {}).get("error") == "client_principal_denied",
                            "fresh old-token refusal differs")
                elif kind == REAUTH:
                    require(event.get("principal_id") == self.application["principal_id"]
                        and event.get("target") == AUTHORITY and event.get("stage") == "inner_request_identity_revalidation",
                        "reauthentication audit scope differs")
                    reauth.append(event.get("reason"))
                elif kind == "operator_catalog.application.token_renewed":
                    require(event.get("resource_id") == self.application["id"]
                        and event.get("operation_id") == self.renewal_receipt["operation_id"]
                        and event.get("token_generation") == 2, "renewal audit receipt differs")
                    renewed.append(row["id"])
            complete = [pair for pair in pairs.values() if {"start", "terminal"} <= pair.keys()]
            require(len(pairs) <= 5 and len(reauth) <= 2 and len(renewed) <= 1, "extra renewal or request audit")
            if (len(complete) == 5 and Counter(pair["key"] for pair in complete) == expected
                    and Counter(reauth) == Counter(["connect_identity_selector_rejected", "connect_identity_policy_changed"])
                    and Counter(kept) == Counter([3, 2])
                    and len(renewed) == 1 and all(counts[kind] == number for kind, number in expected_counts.items())
                    and self.audit_drained()):
                mutations = {(row["event_type"], row.get("event", {}).get("resource_id"),
                    row.get("event", {}).get("policy_hash")) for row in rows}
                require(set(self.mutations) <= mutations, "catalog lifecycle audit missing")
                verified = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
                require(verified.get("ok") is True and verified.get("complete") is True, "durable audit chain failed")
                return {"releaseAttemptIds":sorted(pairs), "renewalAuditIds":renewed, "reauthenticationReasons":reauth,
                    "auditEventIds":sorted(row["id"] for row in rows)}
            time.sleep(min(0.1, self.timeout()))

    def run(self):
        started = time.monotonic_ns()
        started_at = time.time_ns() // 1_000_000
        self.health()
        self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        require(initial["revision"] == 2 and not initial["credentials"] and not initial["access_rules"]
            and len(initial["applications"]) == 1 and self.count() == 0, "isolated seeded catalog required")
        self.application = initial["applications"][0]
        require(self.application["id"] == self.seed["application_id"] and self.application["token_generation"] == 1
            and self.application["token_expires_at_epoch_ms"] == self.seed["original_expiry_epoch_ms"], "seed/catalog join differs")
        self.policy_hash = initial["policy"]["policy_hash"]
        self.wait_catalog_loaded("seed")
        baseline = features.audit_cutoff(self.audit())
        credential, _, _ = self.mutate("/credentials", {"name":self.run_id + "-key", "auth_type":"bearer", "secret":self.credential},
            collection="credentials", result_key="credential", event="operator_catalog.credential.created", creates=True)
        self.credential_id = credential["id"]
        self.rule, _, _ = self.mutate("/access-rules", {"name":self.run_id + "-rule", "application_id":self.application["id"],
            "credential_id":credential["id"], "upstream_url":"https://" + AUTHORITY + FIXTURE_PATH, "methods":["POST"],
            "request_body_mode":"preserve_json_v1", "response_mode":V2_RESPONSE_MODE, "request_fields":[], "response_fields":[],
            "credential_input":"replace_exact", "placeholder":DUMMY_AUTHORIZATION, "query_keys":list(QUERY_KEYS),
            "allowed_headers":["accept", "accept-encoding", "user-agent"]}, collection="access_rules", result_key="access_rule",
            event="operator_catalog.access_rule.created", creates=True, authority_changed=True)
        self.wait_catalog_loaded("rule")
        public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.application, _, _ = self.mutate("/applications/renewal/enroll", {"id":self.application["id"], "public_key":public,
            "enrollment_lifetime_seconds":86400, "token_lifetime_seconds":3600}, collection="applications", result_key="application",
            event="operator_catalog.application.renewal_enrolled", authority_changed=True)
        self.wait_catalog_loaded("enrolled")
        expiry = self.seed["original_expiry_epoch_ms"]
        require(expiry - time.time_ns() // 1_000_000 > 10_000, "insufficient seeded-token runway; do not retry runtime")
        while expiry - time.time_ns() // 1_000_000 > 10_000:
            time.sleep(min(0.2, self.timeout()))
        old = self.persistent(self.old_token)
        self.same_socket(old, "old_before_renewal")
        token, fields, request_sha, raw = self.prepare_operation()
        result = self.machine(raw)
        operation = result["operation"]
        require(operation["request_sha256"] == request_sha and operation["operation_id"] == fields["operation_id"]
            and operation["application_id"] == self.application["id"] and operation["enrollment_id"] == fields["enrollment_id"]
            and operation["previous_generation"] == 1 and operation["token_generation"] == 2
            and operation["token_sha256"] == fields["token_sha256"] and operation["expires_at_epoch_ms"] == fields["token_expires_at_epoch_ms"]
            and operation["previous_accept_until_epoch_ms"] == expiry, "renewal receipt does not bind requested verifier/original expiry")
        self.renewal_receipt = operation
        self.policy_hash = result["policy"]["policy_hash"]
        self.wait_catalog_loaded("renewed")
        self.same_socket(old, "old_after_renewal")
        require(time.time_ns() // 1_000_000 < expiry, "old success did not precede original cutoff")
        while time.time_ns() // 1_000_000 < expiry:
            time.sleep(min(0.025, self.timeout()))
        expired = self.same_socket(old, "old_at_original_expiry", denied_reason="connect_identity_selector_rejected")
        require(expired["sentAtEpochMs"] >= expiry, "expiry refusal preceded original deadline")
        old.close()
        self.stock(self.old_token, "old_fresh_connect_after_expiry", denied=True)
        self.stock(token, "new_stock_requests_after_old_expiry")
        replay = self.machine(raw)
        require(replay["operation"] == operation and replay["revision"] == result["revision"]
            and replay["policy"]["policy_hash"] == self.policy_hash and replay["policy"].get("activation") == "active",
            "exact signed replay changed issuance or lacked observed activation")
        current = self.persistent(token)
        self.same_socket(current, "current_before_cancel")
        self.application, _, _ = self.mutate("/applications/renewal/cancel", {"id":self.application["id"]},
            collection="applications", result_key="application", event="operator_catalog.application.renewal_cancelled", authority_changed=True)
        self.wait_catalog_loaded("cancelled")
        cancelled = self.same_socket(current, "current_after_cancel", denied_reason="connect_identity_policy_changed")
        current.close()
        self.stock(token, "fresh_manual_connection_after_cancel")
        require(self.count() == 5, "final provider dispatch inventory differs")
        audit = self.verify_audit(baseline)
        return {"ok":True, "schema":"serverware.operatorWorkloadRenewalConnected/v1", "syntheticOnly":True,
            "productionReady":False, "realProviderVerified":False, "publicOriginVerified":False,
            "dataPlaneBinaryDigest":self.args.expected_binary_sha256, "seededRetainedManualToken":True,
            "checkerStartedAtEpochMs":started_at, "checkerElapsedMonotonicMs":(time.monotonic_ns() - started) // 1_000_000,
            "checkerDeadlineSeconds":self.args.timeout_seconds, "seedRemainingLifetimeSeconds":150,
            "originalLifetimeSeconds":3600, "oldOriginalExpiryEpochMs":expiry, "productOverlapSeconds":300,
            "fiveMinuteWallWaitPerformed":False, "expiryBoundary":"earlier-original-expiry", "oldSocketAcrossRenewal":True,
            "originalExpiryDenial":expired, "cancellationDenial":cancelled, "stockRequestsNewVerifierAccepted":True,
            "customRequestsAdapter":False, "providerWriteRetries":0, "signedOperationExplicitReplays":1,
            "upstreamDispatches":5, "requestsVersion":requests.__version__, "operation":operation,
            "observations":self.feature_observations, **self.ca_evidence, **audit}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "proxy-ca-file", "requests-ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file", "run-claim-file"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--upstream-address")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()
    args.response_mode = V2_RESPONSE_MODE
    check = None
    def expired(_signal, _frame):
        raise CheckFailure("connected renewal fixture deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(max(args.timeout_seconds, 1), 180))
    try:
        require(args.proxy_url == PROXY and SHA256.fullmatch(args.expected_binary_sha256)
            and 30 <= args.timeout_seconds <= 180, "exact private proxy, normal binary and bounded deadline required")
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = RenewalCheck(args)
        result = check.run()
        check.clean(canonical(result))
    except Exception as error:
        result = {"ok":False, "syntheticOnly":True, "productionReady":False,
            "error":str(error) if isinstance(error, CheckFailure) else type(error).__name__, "automaticRetry":False}
    finally:
        if check is not None:
            for tunnel in check.tunnels:
                tunnel.close()
        signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
