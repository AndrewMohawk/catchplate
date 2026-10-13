#!/usr/bin/env python3
"""Separate, fresh ordinary-X claim-ACK fault fixtures.

No fake claims, direct quota calls, clock changes or retries. The hold mode
proves the observed revoke/loaded-policy/unexpired-ACK/SDK-failure sequence;
it does not identify the gate's exclusive internal failure cause. Actual
acceptance still requires the pinned real app, normal Rust and local provider.
"""
from __future__ import annotations

import argparse
from collections import Counter
import http.client
import json
from pathlib import Path
import queue
import signal
import sys
import threading
import time
import uuid

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import check_operator_x_post as base
from scripts import check_operator_x_quota as quota
from scripts.check_operator_demo import CheckFailure, SHA256, require, token_file
from scripts.check_operator_key_replacement import authority_projection

SCHEMA = "serverware.privateXQuotaFaultCheck/v1"
MODES = ("drop-ack", "revoke-before-release")
STATUS_SCHEMA = "serverware.privateXQuotaFaultStatus/v1"
STATUS_HASHES = {"arm_sha256", "lease_request_sha256", "lease_response_sha256",
    "claim_request_sha256", "claim_response_sha256", "claim_sha256"}
STATUS_FIELDS = {"schema", "status", "mode", "http_status"} | STATUS_HASHES
STAGES = {"idle", "armed", "lease_inflight", "bound", "claim_inflight", "held", "release_requested",
    "released", "dropped", "expired", "failed"}
EXHAUSTED = "X posting-attempt quota exhausted"
RELAY_CONTROLS = 48
FINAL_RELAY_CONTROLS = 2  # Actual release (hold mode) and final status.
encoded, digest, document, exact = base.encoded, base.digest, base.document, quota.exact


def validate_status(value, mode, *, arm_hash=None, terminal=False):
    require(mode in MODES and type(value) is dict and set(value) == STATUS_FIELDS
        and value["schema"] == STATUS_SCHEMA and value["status"] in STAGES,
        "quota fault relay status shape differs")
    expected_mode = "drop_ack" if mode == "drop-ack" else "hold_ack"
    require(value["mode"] == (None if value["status"] == "idle" else expected_mode)
        and all(v is None or type(v) is str and SHA256.fullmatch(v) for k, v in value.items() if k in STATUS_HASHES)
        and (value["http_status"] is None or type(value["http_status"]) is int and 100 <= value["http_status"] <= 599),
        "quota fault relay public fields differ")
    if arm_hash is not None:
        require(value["arm_sha256"] == arm_hash, "quota fault relay arm changed")
    if terminal or value["status"] in {"held", "release_requested", "released", "dropped"}:
        require(all(type(value[k]) is str and SHA256.fullmatch(value[k]) for k in STATUS_HASHES)
            and value["http_status"] == 200, "quota fault has no actual successful claim response")
    if terminal:
        require(value["status"] == ("dropped" if mode == "drop-ack" else "released"),
            "quota ACK expired, failed or was not faulted as selected")
    return value


def validate_provider(value, *, connected, cleaned, anchor):
    require(type(value) is dict and set(value) == base.OBSERVATION_KEYS
        and value["schema"] == "serverware.privateXQuotaFaultProvider/v1"
        and value["syntheticOnly"] is True and value["terminal"] == "running" and value["overflowed"] is False,
        "quota fault provider envelope differs")
    counts = {"authorize": int(connected), "code": int(connected), "refresh": 0,
        "identity": int(connected), "revoke": 2 if cleaned else 0, "posts": 0, "rejected": 0}
    counts["total"] = sum(counts.values())
    exact(value["counts"], counts, "quota fault made an extra provider contact")
    exact(value["tokenLifetimes"], {"initial": 120, "refreshed": 600}, "quota fault changed original TTL")
    exact(value["issuedGenerations"], [1] if connected else [], "quota fault refreshed or reconsented")
    require(value["initialAccessExpired"] is False and value["refreshAfterInitialExpiry"] is False
        and value["cleanupComplete"] is cleaned and value["posts"] == [], "quota fault provider effect differs")
    issued, expiry = value["initialAccessIssuedAtEpochMs"], value["initialAccessExpiresAtEpochMs"]
    require((type(anchor) is int and type(issued) is int and type(expiry) is int
        and 0 < anchor <= issued and expiry == issued + 120000) if connected else issued is expiry is None,
        "quota fault token lifetime differs")
    expected = [{"generation": 1, "tokenTypeHint": hint, "originalClientVerified": True}
        for hint in ("access_token", "refresh_token")] if cleaned else []
    require(type(value["revocations"]) is list, "quota cleanup roster differs")
    exact(sorted(value["revocations"], key=encoded), sorted(expected, key=encoded), "quota original-client cleanup differs")
    return value


def validate_sdk(client, code, stdout, stderr, status):
    require(client in ("node", "python") and status in (409, 429)
        and type(code) is int and code == 2 and stdout == b"" and type(stderr) is bytes and len(stderr) <= 8192,
        "quota fault SDK failed to preserve no-replay uncertainty")
    if client == "node":
        exact(document(stderr), {"ok": False, "operation": "create-post", "outcome": "unknown",
            "mayHaveBeenPosted": True, "automaticRetryAllowed": False, "httpStatus": status,
            "error": base.profiles.NODE_UNKNOWN}, "quota fault Node response differs")
    else:
        require(stderr == base.profiles.FAILURE_MESSAGES[client], "quota fault Python diagnostic differs")
    # Python's fixed diagnostic does not expose HTTP status. The429 must also be
    # independently present in the real signed-lease rejection audit.
    return {"client": client, "exitCode": 2, "confirmed": False,
        "sdkHttpStatus": status if client == "node" else None}


def selected_claim(events, status, scope, credential_id, subject):
    base.features.audit_cutoff(events)
    selected = [row for row in events if row["event_type"] in {quota.RESERVED, quota.CLAIMED}]
    require(Counter(row["event_type"] for row in selected) == {quota.RESERVED: 1, quota.CLAIMED: 1},
        "quota fault did not commit exactly one real claim")
    reserve = next(r["event"] for r in selected if r["event_type"] == quota.RESERVED)
    claim = next(r["event"] for r in selected if r["event_type"] == quota.CLAIMED)
    require(type(reserve) is dict and set(reserve) == quota.RECEIPT_FIELDS | {"binding"}
        and type(claim) is dict and set(claim) == quota.RECEIPT_FIELDS | {"binding", "claimed_at_epoch_ms"}
        and reserve["schema"] == "serverware.operatorXPostingQuotaReservation/v1"
        and claim["schema"] == "serverware.operatorXPostingQuotaClaim/v1", "quota fault durable claim shape differs")
    exact({k: v for k, v in claim.items() if k not in {"schema", "claimed_at_epoch_ms"}},
        {k: v for k, v in reserve.items() if k != "schema"}, "quota fault claim rebound")
    binding = claim["binding"]
    request, operation = quota.commitments("node", scope, credential_id, 1, subject)
    require(type(binding) is dict and set(binding) == quota.BINDING_FIELDS
        and digest(binding) == claim["binding_digest"] and type(binding["credential_version"]) is int,
        "quota fault original binding differs")
    expected = {"principal_id": scope[0], "route_id": scope[1], "policy_hash": scope[2],
        "credential_id": credential_id, "credential_version": 1, "request_digest": request,
        "operation_digest": operation}
    exact({k: binding[k] for k in expected}, expected, "quota fault claimed a different SDK request")
    require(all(type(binding[k]) is str and SHA256.fullmatch(binding[k]) for k in
        ("attempt_nonce", "recipient_digest", "request_binding_digest", "credential_metadata_digest"))
        and type(claim["reservation_id"]) is str and base.UUID.fullmatch(claim["reservation_id"])
        and type(claim["utc_day"]) is int and type(claim["claimed_at_epoch_ms"]) is int
        and type(claim["expires_at_epoch_ms"]) is int and claim["expires_at_epoch_ms"] == binding["expires_at_epoch_ms"]
        and 0 < claim["claimed_at_epoch_ms"] < claim["expires_at_epoch_ms"] <= claim["claimed_at_epoch_ms"] + 5000
        and claim["claimed_at_epoch_ms"] // quota.DAY_MS == claim["utc_day"]
        and claim["expires_at_epoch_ms"] <= (claim["utc_day"] + 1) * quota.DAY_MS,
        "quota fault original UTC or deadline differs")
    require(claim["bucket_key"] == digest({"provider": "x", "subject": subject,
        "operation": "tweets.write", "utc_day": claim["utc_day"]}), "quota fault changed account bucket")
    require(status["claim_sha256"] == digest({"attempt_nonce": binding["attempt_nonce"],
        "reservation_id": claim["reservation_id"], "request_binding_sha256": binding["request_binding_digest"]})
        and status["lease_request_sha256"] == binding["request_binding_digest"], "relay fault not bound to actual committed claim")
    return claim


def validate_hold(proof):
    fields = {"heldAtEpochMs", "loadedAtEpochMs", "releasedAtEpochMs", "sdkCompletedAtEpochMs",
        "expiresAtEpochMs", "elapsedAfterHeldNs", "remainingAtHeldMs", "oldPolicyHash", "loadedPolicyHash", "ruleId"}
    require(type(proof) is dict and set(proof) == fields and all(type(proof[k]) is int and proof[k] > 0
        for k in fields - {"oldPolicyHash", "loadedPolicyHash", "ruleId"}), "quota hold proof shape differs")
    require(proof["heldAtEpochMs"] <= proof["loadedAtEpochMs"] <= proof["releasedAtEpochMs"]
        <= proof["sdkCompletedAtEpochMs"] < proof["expiresAtEpochMs"]
        and proof["remainingAtHeldMs"] == proof["expiresAtEpochMs"] - proof["heldAtEpochMs"]
        and proof["elapsedAfterHeldNs"] < proof["remainingAtHeldMs"] * 1000000
        and proof["remainingAtHeldMs"] <= 5000, "expired ACK cannot prove revoke-before-send")
    require(all(type(proof[k]) is str and SHA256.fullmatch(proof[k]) for k in ("oldPolicyHash", "loadedPolicyHash"))
        and proof["oldPolicyHash"] != proof["loadedPolicyHash"]
        and type(proof["ruleId"]) is str and base.UUID.fullmatch(proof["ruleId"]), "quota actual revoke policy differs")
    return proof


class FaultCheck(base.XPostCheck):
    def __init__(self, args):
        require(args.fault_mode in MODES, "quota fault mode differs")
        super().__init__(args)
        self.mode, self.cleaned, self.status_reads = args.fault_mode, False, 0
        self.arm_hash = None
        self.hold_proof = None
        now = time.time_ns() // 1_000_000
        self.day = now // quota.DAY_MS
        require((self.day + 1) * quota.DAY_MS - now > 180000, "fault fixture cannot span actual UTC boundary")

    def observe(self, posts, *, connected=True, refreshed=False, disconnected=False, expired=False):
        require(posts == 0 and not refreshed and not expired, "quota fault cannot post, refresh or wait for expiry")
        status, _, raw = self.exchange(self.upstream, "/__test__/observations")
        require(status == 200, "quota fault provider unavailable")
        value = validate_provider(document(raw), connected=connected, cleaned=self.cleaned,
            anchor=getattr(self, "callback_anchor", None))
        previous = [p for p in self.provider_checkpoints if p["initialAccessExpiresAtEpochMs"] is not None]
        require(not previous or all(value[k] == previous[0][k] for k in
            ("initialAccessIssuedAtEpochMs", "initialAccessExpiresAtEpochMs")), "quota fault reset token lifetime")
        self.provider_checkpoints.append(value)
        require(len(self.provider_checkpoints) <= 12, "quota fault provider observation budget exceeded")
        return value

    def relay(self, path, payload=None):
        require(path in {"/__fault/arm", "/__fault/status", "/__fault/release"}
            and (payload is None) == (path == "/__fault/status"), "fixed local quota relay control required")
        self.status_reads += 1
        require(self.status_reads <= RELAY_CONTROLS, "quota relay observation budget exceeded")
        headers = {"Host": "127.0.0.1:3001", "Connection": "close"}
        body = None if payload is None else encoded(payload)
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection("127.0.0.1", 3001, timeout=min(3, self.timeout()))
        try:
            connection.request("GET" if body is None else "POST", path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(16385)
            require(response.status == 200 and len(raw) <= 16384, "quota relay control failed; never retry")
            self.clean(raw)
            return validate_status(document(raw), self.mode, arm_hash=self.arm_hash)
        finally:
            connection.close()

    def start_sdk(self, client):
        remaining = self.deadline - time.monotonic()
        require(remaining > 36 and time.time_ns() // 1_000_000 < self.callback_anchor + 60000,
            "quota fault does not fit original token/checker margin")
        results = queue.Queue(maxsize=1)
        def execute():
            try:
                value = base.run_example(client + ":first", base.client_environment(client + ":first",
                    self.application["id"], self.token), min(35, remaining))
                results.put((True, value, time.time_ns() // 1_000_000, time.monotonic_ns()))
            except BaseException as error:
                results.put((False, error, time.time_ns() // 1_000_000, time.monotonic_ns()))
        worker = threading.Thread(target=execute, name="bounded-quota-sdk", daemon=False)
        worker.start()
        return worker, results

    def finish_sdk(self, worker, results, client, expected_status):
        worker.join(timeout=min(36, max(0, self.deadline - time.monotonic())))
        require(not worker.is_alive() and results.qsize() == 1, "quota SDK child did not terminate within original bound")
        ok, value, wall, mono = results.get_nowait()
        if not ok:
            raise CheckFailure("quota SDK execution failed") from None
        code, stdout, stderr = value
        self.clean(stdout); self.clean(stderr)
        self.completed.append(validate_sdk(client, code, stdout, stderr, expected_status))
        return wall, mono

    def wait_for_fault(self, worker):
        selected = "dropped" if self.mode == "drop-ack" else "held"
        while True:
            require(self.status_reads < RELAY_CONTROLS - FINAL_RELAY_CONTROLS,
                "quota relay polling would consume final controls")
            observed = self.relay("/__fault/status")
            require(observed["status"] not in {"failed", "expired", "released"}, "quota fault expired or failed")
            if observed["status"] == selected:
                return observed
            require(worker.is_alive(), "quota SDK ended before actual claim fault")
            # Cold SDK startup has no selected lease yet. Preserve the finite
            # control budget for the real <=5s lease and <=3s claim connection;
            # these sleeps neither create nor renew either original deadline.
            delay = .25 if observed["status"] in {"lease_inflight", "bound", "claim_inflight"} else 1.5
            time.sleep(min(delay, self.timeout()))

    def fault_attempt(self):
        self.current_phase = self.mode
        before = self.observe(0)
        require(self.relay("/__fault/status")["status"] == "idle", "quota relay was previously armed")
        arm = {"schema": "serverware.privateXQuotaFaultArm/v1", "mode": "drop_ack" if self.mode == "drop-ack" else "hold_ack",
            "principal_id": self.scope[0], "route_id": self.scope[1], "body_sha256": digest(base.profiles.post_body("node"))}
        armed = self.relay("/__fault/arm", arm)
        self.arm_hash = digest(arm)
        require(armed["status"] == "armed" and armed["arm_sha256"] == self.arm_hash, "quota relay arm changed")
        worker, results = self.start_sdk("node")
        try:
            observed = self.wait_for_fault(worker)
            # The claim audit is the real committed store receipt, not a relay
            # assertion, seeded row, direct store read or synthetic signature.
            claim = selected_claim(self.audit(), observed, self.scope, self.credential_id, self.fixture.SUBJECT)
            if self.mode == "revoke-before-release":
                held_wall, held_mono = time.time_ns() // 1_000_000, time.monotonic_ns()
                expiry = claim["expires_at_epoch_ms"]
                require(held_wall < expiry, "quota original claim expired before actual revoke")
                revoked, _, _ = self.mutate("/access-rules/revoke", {"id": self.rule["id"]}, collection="access_rules",
                    result_key="access_rule", event="operator_catalog.access_rule.revoked", authority_changed=True)
                require(revoked["id"] == self.rule["id"] and revoked["status"] == "revoked", "quota actual rule revoke failed")
                catalog, health = self.wait_catalog_loaded("fault_revoke")
                loaded_wall = time.time_ns() // 1_000_000
                require(loaded_wall < expiry and health["policy_hash"] == catalog["policy"]["loaded_policy_hash"]
                    == self.policy_hash != self.scope[2], "quota revoked policy not loaded before original expiry")
                release = {"schema": "serverware.privateXQuotaFaultRelease/v1", "arm_sha256": self.arm_hash,
                    "claim_sha256": observed["claim_sha256"], "revoked_rule_id": self.rule["id"],
                    "policy_hash": self.policy_hash, "loaded_policy_hash": health["policy_hash"]}
                released_wall = time.time_ns() // 1_000_000
                require(self.relay("/__fault/release", release)["status"] in {"release_requested", "released"},
                    "quota original ACK not released after loaded revoke")
                finished_wall, finished_mono = self.finish_sdk(worker, results, "node", 409)
                self.hold_proof = validate_hold({"heldAtEpochMs": held_wall, "loadedAtEpochMs": loaded_wall,
                    "releasedAtEpochMs": released_wall, "sdkCompletedAtEpochMs": finished_wall,
                    "expiresAtEpochMs": expiry, "elapsedAfterHeldNs": finished_mono - held_mono,
                    "remainingAtHeldMs": expiry - held_wall, "oldPolicyHash": self.scope[2],
                    "loadedPolicyHash": self.policy_hash, "ruleId": self.rule["id"]})
            else:
                self.finish_sdk(worker, results, "node", 409)
        finally:
            # run_example owns its exact child group and a <=35s original
            # timeout. Join only that worker; no process discovery or PID reuse.
            worker.join(timeout=min(36, max(0, self.deadline - time.monotonic())))
            require(not worker.is_alive(), "quota SDK cleanup did not finish")
        self.relay_final = validate_status(self.relay("/__fault/status"), self.mode, arm_hash=self.arm_hash, terminal=True)
        exact(self.observe(0), before, "faulted claim contacted provider")
        self.claim = selected_claim(self.audit(), self.relay_final, self.scope, self.credential_id, self.fixture.SUBJECT)
        if self.mode == "drop-ack":
            # Different real SDK bytes do not match the consumed relay arm.
            # This reaches the actual app/store rather than the relay's replay fence.
            worker, results = self.start_sdk("python")
            self.finish_sdk(worker, results, "python", 429)
            exact(self.observe(0), before, "claim ACK loss refunded quota or caused provider replay")

    def disconnect_account(self):
        pinned = self.warm_cas_snapshot()
        review = self.lifecycle_json(base.PREFIX + "/accounts/" + self.credential_id + "/disconnect-review")
        affected = [self.rule["id"]] if self.mode == "drop-ack" else []
        require(review.get("affected_credential_ids") == [self.credential_id]
            and review.get("affected_rule_ids") == affected and review.get("expected_credential_generation") == 1
            and review.get("expected_revision") == pinned["revision"]
            and review.get("expected_policy_hash") == self.policy_hash, "fault disconnect scope differs")
        operation_id = str(uuid.uuid4())
        payload = {key: review[key] for key in ("credential_id", "expected_credential_generation",
            "expected_revision", "expected_policy_hash", "review_digest")}
        result = self.lifecycle_json(base.PREFIX + "/disconnect", payload={**payload, "operation_id": operation_id})
        require(set(result) == base.OPERATION_KEYS and result["operation_id"] == operation_id
            and result["kind"] == "disconnect" and result["status"] == "disconnected"
            and result["credential_id"] == self.credential_id and result["reason"] is None,
            "fault account cleanup uncertain; never retry")
        exact(self.lifecycle_json(base.PREFIX + "/operations/" + operation_id), result, "fault disconnect readback differs")
        current = self.catalog()
        require(current["revision"] == pinned["revision"] + 2 and len(current["credentials"]) == 1
            and len(current["applications"]) == 1 and len(current["access_rules"]) == 1
            and self.resource(current, "credentials", self.credential_id)["status"] == "revoked"
            and self.resource(current, "access_rules", self.rule["id"])["status"] == "revoked",
            "fault account and rule remain active")
        exact(current["applications"], [{**pinned["applications"][0], "active_rule_count": 0, "access_status": "unassigned"}],
            "fault cleanup changed application identity")
        require(current["policy"]["sequence"] == pinned["policy"]["sequence"] + int(bool(affected))
            and ((current["policy"]["policy_hash"] != self.policy_hash) if affected else current["policy"]["policy_hash"] == self.policy_hash),
            "fault cleanup publication differs")
        self.policy_hash = current["policy"]["policy_hash"]
        self.wait_catalog_loaded("fault_disconnected")
        self.cleaned = True
        return self.observe(0)

    def run(self):
        self.health()
        self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        require(initial["revision"] == self.args.expected_initial_revision and all(not initial[k]
            and initial["limits"][k]["retained"] == 0 for k in base.COLLECTIONS), "fresh quota fault catalog required")
        self.initial_policy_hash = self.policy_hash = initial["policy"]["policy_hash"]
        self.wait_catalog_loaded("fault_initial")
        baseline = base.features.audit_cutoff(self.settled_audit())
        self.configure_and_connect()
        self.application, self.token, _ = self.mutate("/applications", {"name": self.run_id + "-fault",
            "token_lifetime_seconds": 3600, "proxy_authentication": "basic_and_bearer_v1"}, collection="applications",
            result_key="application", event="operator_catalog.application.created", creates=True, token=True)
        capability = self.catalog()["capabilities"].get("x_post", {})
        require(capability.get("daily_quota_available") is True, "fault durable quota unavailable")
        exact(capability.get("daily_quota"), quota.QUOTA_DESCRIPTOR, "fault catalog quota capability differs")
        exact(self.health().get("operator_x_post_attempt_quota"), quota.QUOTA_DESCRIPTOR, "fault Rust quota capability differs")
        self.rule, _, _ = self.mutate("/access-rules/x-post", {"name": self.run_id + "-fault-rule",
            "application_id": self.application["id"], "credential_id": self.credential_id,
            "operation_bundle": "x_text_post_v1", "daily_post_attempt_limit": 1}, collection="access_rules",
            result_key="access_rule", event="operator_catalog.access_rule.x_post_created", creates=True, authority_changed=True)
        require(type(self.rule.get("daily_post_attempt_limit")) is int and self.rule["daily_post_attempt_limit"] == 1,
            "fault rule must admit exactly one durable attempt")
        self.wait_catalog_loaded("fault_granted")
        self.scope = (self.application["principal_id"], self.rule["route_id"], self.policy_hash)
        self.fault_attempt()
        provider = self.disconnect_account()
        events = self.settled_audit()
        evidence = verify_audit(events, baseline, self.mode, self.relay_final, self.scope, self.credential_id,
            self.fixture.SUBJECT, self.args.expected_binary_sha256)
        require(time.time_ns() // 1_000_000 // quota.DAY_MS == self.day == self.claim["utc_day"],
            "fault run crossed original account UTC day")
        chain = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(chain.get("ok") is True and chain.get("complete") is True and chain.get("backend") == "sqlite",
            "fault durable audit chain failed")
        self.current_files()
        result = {"schema": SCHEMA, "ok": True, "syntheticOnly": True, "realXVerified": False,
            "productionReady": False, "publicDnsVerified": False, "exclusiveInternalCauseProven": False,
            "actualManagedLifecycle": True, "actualExampleEntrypoints": True, "auditChainVerified": True,
            "faultMode": self.mode, "limit": 1, "dataPlaneBinaryDigest": self.args.expected_binary_sha256,
            "goExampleSha256": self.args.expected_go_sha256, "dependenciesSha256": self.args.expected_dependencies_sha256,
            "completed": self.completed, "provider": provider, "relay": self.relay_final, "hold": self.hold_proof,
            "preCallbackEpochMs": self.callback_anchor, "credentialId": self.credential_id,
            "applicationId": self.application["id"], "ruleId": self.rule["id"], **evidence}
        validate_success_result(result)
        require(all(value.encode() not in encoded(result) for value in self.transients), "fault transient escaped receipt")
        return result


def audit_inventory(mode):
    require(mode in MODES, "fault audit mode differs")
    expected = {base.START: 2 if mode == "drop-ack" else 1, base.CONNECT: 2 if mode == "drop-ack" else 1,
        quota.RESERVED: 1, quota.CLAIMED: 1, "operator_catalog.application.created": 1,
        "operator_catalog.access_rule.x_post_created": 1,
        **{base.LIFECYCLE + suffix: 1 for suffix in ("configuration_saved", "consent_started", "exchange_claimed",
            "account_connected", "disconnect_fenced", "disconnected")}}
    if mode == "drop-ack":
        expected.update({quota.DENIED: 1, base.LEASE_REJECT: 1})
    else:
        expected["operator_catalog.access_rule.revoked"] = 1
    return expected


def validate_inventory(counts, mode):
    expected = audit_inventory(mode)
    require(type(counts) in (dict, Counter) and all(type(k) is str and type(v) is int and 0 < v <= 100 for k, v in counts.items())
        and set(counts) <= set(expected) | {base.LEASE, base.RELOAD}
        and all(counts.get(k) == v for k, v in expected.items()) and 2 <= counts.get(base.LEASE, 0) <= 32
        and 2 <= counts.get(base.RELOAD, 0) <= 6, "fault actual durable inventory differs")


def verify_audit(events, baseline, mode, status, scope, credential_id, subject, binary):
    cutoff = base.features.audit_cutoff(events)
    require(all(cutoff.get(k) == v for k, v in baseline.items()), "fault initial audit prefix changed")
    ordered = quota.ordered_audit(events)
    position = {r["id"]: i for i, r in enumerate(ordered)}
    rows = [row for row in ordered if row["id"] not in baseline]
    claim = selected_claim(rows, status, scope, credential_id, subject)
    counts = Counter(row["event_type"] for row in rows)
    validate_inventory(counts, mode)
    starts = [r for r in rows if r["event_type"] == base.START]
    by_client = {}
    for row in starts:
        event = row["event"]
        clients = [c for c in ("node", "python") if (event.get("request_digest"), event.get("operation_digest"))
            == quota.commitments(c, scope, credential_id, 1, subject)]
        require(len(clients) == 1 and clients[0] not in by_client and event.get("outcome") == "release_started"
            and tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash")) == tuple(scope)
            and event.get("credential_ref") == credential_id and type(event.get("credential_version")) is int
            and event["credential_version"] == 1 and event.get("method") == "POST"
            and event.get("body_sha256") == digest(base.profiles.post_body(clients[0]))
            and type(event.get("attempt_id")) is str and SHA256.fullmatch(event["attempt_id"])
            and event.get("flow_id") == event["attempt_id"], "fault request start not exact SDK")
        by_client[clients[0]] = row
    require(set(by_client) == ({"node", "python"} if mode == "drop-ack" else {"node"})
        and by_client["node"]["event"]["attempt_id"] == claim["binding"]["attempt_nonce"], "fault claim did not consume first real attempt")
    reserved = next(r for r in rows if r["event_type"] == quota.RESERVED)
    claimed = next(r for r in rows if r["event_type"] == quota.CLAIMED)
    require(position[by_client["node"]["id"]] < position[reserved["id"]] < position[claimed["id"]],
        "fault claim lacks actual durable start ordering")
    leases = [r for r in rows if r["event_type"] == base.LEASE]
    for row in leases:
        base.validate_issued_lease(row["event"], scope, credential_id, binary)
    for row in (r for r in rows if r["event_type"] == base.CONNECT):
        event = row["event"]
        require(event.get("target") == "api.x.com:443" and event.get("method") == "CONNECT"
            and event.get("outcome") == "established" and event.get("principal_id") == scope[0]
            and event.get("policy_hash") == scope[2], "fault CONNECT escaped selected application")
    require(any(r["event"]["purpose"] == "dispatchSecret"
        and r["event"]["expected_credential_version"] == 1
        and r["event"]["expected_metadata_sha256"] == claim["binding"]["credential_metadata_digest"]
        and position[reserved["id"]] < position[r["id"]] < position[claimed["id"]] for r in leases),
        "fault claim lacks actual encrypted lease issuance")
    if mode == "drop-ack":
        denied = next(r for r in rows if r["event_type"] == quota.DENIED)
        rejected = next(r["event"] for r in rows if r["event_type"] == base.LEASE_REJECT)
        require(denied["event"].get("attempt_id") == by_client["python"]["event"]["attempt_id"]
            != claim["binding"]["attempt_nonce"] and denied["event"].get("stage") == "operator_x_quota"
            and denied["event"].get("error") == "operator_x_post_attempt_quota_unavailable"
            and denied["event"].get("outcome") == "denied" and rejected.get("status_code") == 429
            and type(rejected.get("status_code")) is int and rejected.get("reason") == EXHAUSTED
            and rejected.get("purpose") == "dispatchSecret" and rejected.get("data_plane_binary_digest") == binary
            and rejected.get("credential_id") == credential_id
            and tuple(rejected.get(k) for k in ("principal_id", "route_id", "policy_hash")) == tuple(scope)
            and position[claimed["id"]] < position[by_client["python"]["id"]] < position[denied["id"]],
            "lost ACK did not retain charge for distinct real exhausted request")
    else:
        revoked = next(r for r in rows if r["event_type"] == "operator_catalog.access_rule.revoked")
        require(revoked["event"].get("resource_id") == scope[1].removeprefix("operator.")
            and revoked["event"].get("policy_hash") != scope[2] and position[claimed["id"]] < position[revoked["id"]],
            "rule revoke did not follow actual committed claim")
    fence = next(r for r in rows if r["event_type"] == base.LIFECYCLE + "disconnect_fenced")
    require(all(position[r["id"]] < position[fence["id"]] for r in leases), "fault lease issued after disconnect")
    return {"attemptIds": sorted(r["event"]["attempt_id"] for r in starts), "claimAttemptId": claim["binding"]["attempt_nonce"],
        "reservationId": claim["reservation_id"], "claimBindingDigest": claim["binding_digest"],
        "claimExpiresAtEpochMs": claim["expires_at_epoch_ms"], "namedAuditInventory": dict(sorted(counts.items()))}


def validate_success_result(value):
    fields = {"schema", "ok", "syntheticOnly", "realXVerified", "productionReady", "publicDnsVerified",
        "exclusiveInternalCauseProven", "actualManagedLifecycle", "actualExampleEntrypoints", "auditChainVerified",
        "faultMode", "limit", "dataPlaneBinaryDigest", "goExampleSha256", "dependenciesSha256", "completed", "provider",
        "relay", "hold", "preCallbackEpochMs", "credentialId", "applicationId", "ruleId", "attemptIds", "claimAttemptId",
        "reservationId", "claimBindingDigest", "claimExpiresAtEpochMs", "namedAuditInventory"}
    require(type(value) is dict and set(value) == fields and value["schema"] == SCHEMA and value["faultMode"] in MODES
        and all(value[k] is True for k in ("ok", "syntheticOnly", "actualManagedLifecycle", "actualExampleEntrypoints", "auditChainVerified"))
        and all(value[k] is False for k in ("realXVerified", "productionReady", "publicDnsVerified", "exclusiveInternalCauseProven"))
        and type(value["limit"]) is int and value["limit"] == 1, "fault terminal boundary differs")
    mode = value["faultMode"]
    validate_status(value["relay"], mode, terminal=True)
    validate_provider(value["provider"], connected=True, cleaned=True, anchor=value["preCallbackEpochMs"])
    expected = [{"client": "node", "exitCode": 2, "confirmed": False, "sdkHttpStatus": 409}]
    if mode == "drop-ack":
        expected.append({"client": "python", "exitCode": 2, "confirmed": False, "sdkHttpStatus": None})
        require(value["hold"] is None, "dropped ACK claimed revoke observation")
    else:
        validate_hold(value["hold"])
        require(value["hold"]["expiresAtEpochMs"] == value["claimExpiresAtEpochMs"]
            and value["hold"]["ruleId"] == value["ruleId"], "hold proof switched original claim or rule")
    exact(value["completed"], expected, "fault SDK invocation inventory differs")
    require(all(type(value[k]) is str and base.UUID.fullmatch(value[k]) for k in
        ("credentialId", "applicationId", "ruleId", "reservationId"))
        and all(type(value[k]) is str and SHA256.fullmatch(value[k]) for k in
            ("dataPlaneBinaryDigest", "claimAttemptId", "claimBindingDigest"))
        and all(type(value[k]) is str and base.HEX.fullmatch(value[k]) for k in ("goExampleSha256", "dependenciesSha256"))
        and type(value["claimExpiresAtEpochMs"]) is int and value["claimExpiresAtEpochMs"] > 0,
        "fault identity/provenance missing")
    attempts = value["attemptIds"]
    require(type(attempts) is list and len(attempts) == len(set(attempts)) == len(expected)
        and all(type(v) is str and SHA256.fullmatch(v) for v in attempts)
        and value["claimAttemptId"] in attempts, "fault attempt replay or missing claim")
    validate_inventory(value["namedAuditInventory"], mode)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256",
            "expected-go-sha256", "expected-dependencies-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "proxy-ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file",
            "run-claim-file", "dependencies-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--upstream-address")
    parser.add_argument("--expected-initial-revision", type=int, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--fault-mode", choices=MODES, required=True)
    args = parser.parse_args(); check = None
    def expired(*_):
        raise CheckFailure("quota fault original checker deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    try:
        require(args.timeout_seconds == 180 and SHA256.fullmatch(args.expected_binary_sha256)
            and 1 <= args.expected_initial_revision <= 3, "quota fault original bounds differ")
        signal.alarm(180)
        base.claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = FaultCheck(args)
        result = check.run()
        check.clean(encoded(result))
    except Exception as error:
        from scripts.run_operator_x_examples_fixture import failure_site
        result = {"schema": SCHEMA, "ok": False, "syntheticOnly": True, "productionReady": False,
            "faultMode": args.fault_mode, "error": "managed X quota fault acceptance failed; no retry authorized",
            "failureSite": failure_site(error, Path("/app")), "completed": check.completed if check is not None else []}
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
