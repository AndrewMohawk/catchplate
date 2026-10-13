"""Pure fault-checker controls, not real claim commits or provider acceptance.

These literal audit/status documents prove refusal oracles only. The separate
fresh fixture must supply actual signed app replies, encrypted leases, durable
SQLite claims and unchanged SDKs before either fault story can pass.
"""
from copy import deepcopy
import hashlib
import json
import unittest

from scripts import check_operator_x_quota_fault as check

APP = "11111111-1111-4111-8111-111111111111"
CREDENTIAL = "22222222-2222-4222-8222-222222222222"
RULE = "33333333-3333-4333-8333-333333333333"
RESERVATION = "44444444-4444-4444-8444-444444444444"
SUBJECT = "18446744073709551001"
SCOPE = ("agent:operator-demo:" + APP, "operator." + RULE, "sha256:" + "a" * 64)
NOW = 2_000_000_000_000


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha(value):
    return "sha256:" + hashlib.sha256(value if type(value) is bytes else wire(value)).hexdigest()


def status(mode="drop-ack", state=None):
    return {"schema": "serverware.privateXQuotaFaultStatus/v1",
        "status": state or ("dropped" if mode == "drop-ack" else "released"),
        "mode": "drop_ack" if mode == "drop-ack" else "hold_ack", "http_status": 200,
        **{key: sha(key.encode()) for key in ("arm_sha256", "lease_request_sha256", "lease_response_sha256",
            "claim_request_sha256", "claim_response_sha256", "claim_sha256")}}


def provider():
    return {"schema": "serverware.privateXQuotaFaultProvider/v1", "syntheticOnly": True,
        "terminal": "running", "counts": {"total": 5, "authorize": 1, "code": 1, "refresh": 0,
            "identity": 1, "revoke": 2, "posts": 0, "rejected": 0},
        "initialAccessIssuedAtEpochMs": NOW + 1000, "initialAccessExpiresAtEpochMs": NOW + 121000,
        "initialAccessExpired": False, "refreshAfterInitialExpiry": False,
        "tokenLifetimes": {"initial": 120, "refreshed": 600}, "issuedGenerations": [1], "posts": [],
        "revocations": [{"generation": 1, "tokenTypeHint": hint, "originalClientVerified": True}
            for hint in ("access_token", "refresh_token")], "cleanupComplete": True, "overflowed": False}


def hold():
    return {"heldAtEpochMs": NOW, "loadedAtEpochMs": NOW + 100, "releasedAtEpochMs": NOW + 200,
        "sdkCompletedAtEpochMs": NOW + 300, "expiresAtEpochMs": NOW + 4000,
        "elapsedAfterHeldNs": 300000000, "remainingAtHeldMs": 4000,
        "oldPolicyHash": SCOPE[2], "loadedPolicyHash": sha(b"new"), "ruleId": RULE}


def claim_rows():
    request, operation = check.quota.commitments("node", SCOPE, CREDENTIAL, 1, SUBJECT)
    binding = {"principal_id": SCOPE[0], "route_id": SCOPE[1], "credential_id": CREDENTIAL,
        "credential_version": 1, "credential_metadata_digest": sha(b"metadata"), "policy_hash": SCOPE[2],
        "request_digest": request, "operation_digest": operation, "attempt_nonce": sha(b"attempt"),
        "recipient_digest": sha(b"recipient"), "request_binding_digest": sha(b"wire"), "expires_at_epoch_ms": NOW + 4000}
    receipt = {"schema": "serverware.operatorXPostingQuotaReservation/v1", "reservation_id": RESERVATION,
        "bucket_key": sha({"provider": "x", "subject": SUBJECT, "operation": "tweets.write", "utc_day": NOW // 86400000}),
        "utc_day": NOW // 86400000, "expires_at_epoch_ms": NOW + 4000, "binding_digest": sha(binding), "binding": binding}
    claim = {**deepcopy(receipt), "schema": "serverware.operatorXPostingQuotaClaim/v1", "claimed_at_epoch_ms": NOW}
    rows = [{"id": APP, "event_type": check.quota.RESERVED, "event": receipt, "event_hash": sha(b"r"), "prev_event_hash": None},
        {"id": RULE, "event_type": check.quota.CLAIMED, "event": claim, "event_hash": sha(b"c"), "prev_event_hash": sha(b"r")}]
    relay = status()
    relay["lease_request_sha256"] = binding["request_binding_digest"]
    relay["claim_sha256"] = sha({"attempt_nonce": binding["attempt_nonce"], "reservation_id": RESERVATION,
        "request_binding_sha256": binding["request_binding_digest"]})
    return rows, relay


def result(mode):
    return {"schema": "serverware.privateXQuotaFaultCheck/v1", "ok": True, "syntheticOnly": True,
        "realXVerified": False, "productionReady": False, "publicDnsVerified": False, "exclusiveInternalCauseProven": False,
        "actualManagedLifecycle": True, "actualExampleEntrypoints": True, "auditChainVerified": True,
        "faultMode": mode, "limit": 1, "dataPlaneBinaryDigest": sha(b"binary"), "goExampleSha256": "a" * 64,
        "dependenciesSha256": "b" * 64, "completed": [
            {"client": "node", "exitCode": 2, "confirmed": False, "sdkHttpStatus": 409},
            *([{"client": "python", "exitCode": 2, "confirmed": False, "sdkHttpStatus": None}] if mode == "drop-ack" else [])],
        "provider": provider(), "relay": status(mode), "hold": None if mode == "drop-ack" else hold(),
        "preCallbackEpochMs": NOW, "credentialId": CREDENTIAL, "applicationId": APP, "ruleId": RULE,
        "attemptIds": [sha(b"attempt"), *([sha(b"second")] if mode == "drop-ack" else [])],
        "claimAttemptId": sha(b"attempt"), "reservationId": RESERVATION, "claimBindingDigest": sha(b"binding"),
        "claimExpiresAtEpochMs": NOW + 4000,
        "namedAuditInventory": {**check.audit_inventory(mode), check.base.LEASE: 2, check.base.RELOAD: 3}}


class FaultCheckerTests(unittest.TestCase):
    def test_relay_status_is_closed_and_requires_actual_response_hashes(self):
        for mode in check.MODES:
            check.validate_status(status(mode), mode, terminal=True)
            for change in (lambda v: v.update(status="expired"), lambda v: v.update(http_status=True),
                    lambda v: v.update(claim_response_sha256=None), lambda v: v.update(secret="canary"),
                    lambda v: v.update(mode="other")):
                value = status(mode); change(value)
                with self.assertRaises(check.CheckFailure):
                    check.validate_status(value, mode, terminal=True)
            with self.assertRaises(check.CheckFailure):
                check.validate_status(status(mode), mode, arm_hash=sha(b"different"))

    def test_no_provider_post_refresh_reconsent_or_cleanup_omission(self):
        check.validate_provider(provider(), connected=True, cleaned=True, anchor=NOW)
        for change in (lambda v: v["counts"].update(posts=1, total=6),
                lambda v: v["counts"].update(refresh=1, total=6), lambda v: v.update(posts=[{}]),
                lambda v: v.update(initialAccessExpired=True), lambda v: v["revocations"].pop(),
                lambda v: v["revocations"][0].update(originalClientVerified=False),
                lambda v: v.update(issuedGenerations=[1, 2]), lambda v: v["tokenLifetimes"].update(initial=180)):
            value = provider(); change(value)
            with self.assertRaises(check.CheckFailure):
                check.validate_provider(value, connected=True, cleaned=True, anchor=NOW)

    def test_original_deadline_requires_both_wall_and_monotonic_before_expiry(self):
        check.validate_hold(hold())
        for change in (lambda v: v.update(sdkCompletedAtEpochMs=NOW + 4000),
                lambda v: v.update(elapsedAfterHeldNs=4000000000), lambda v: v.update(remainingAtHeldMs=5000),
                lambda v: v.update(loadedAtEpochMs=NOW + 201), lambda v: v.update(releasedAtEpochMs=NOW - 1),
                lambda v: v.update(loadedPolicyHash=SCOPE[2]), lambda v: v.update(elapsedAfterHeldNs=True)):
            value = hold(); change(value)
            with self.assertRaises(check.CheckFailure):
                check.validate_hold(value)

    def test_actual_claim_receipt_correlates_exact_relay_attempt_and_wire_hash(self):
        rows, relay = claim_rows()
        claim = check.selected_claim(rows, relay, SCOPE, CREDENTIAL, SUBJECT)
        self.assertEqual(claim["reservation_id"], RESERVATION)
        for field in ("claim_sha256", "lease_request_sha256"):
            changed = {**relay, field: sha(b"other")}
            with self.assertRaises(check.CheckFailure):
                check.selected_claim(rows, changed, SCOPE, CREDENTIAL, SUBJECT)
        for changed in (rows[:1], rows + [rows[1]]):
            with self.assertRaises(check.CheckFailure):
                check.selected_claim(changed, relay, SCOPE, CREDENTIAL, SUBJECT)

    def test_coherent_receipt_hash_cannot_substitute_sdk_scope_generation_or_body(self):
        for field, value in (("principal_id", "other"), ("route_id", "other"), ("credential_id", APP),
                ("credential_version", True), ("request_digest", sha(b"body")), ("operation_digest", sha(b"op")),
                ("policy_hash", sha(b"policy"))):
            rows, relay = claim_rows()
            for row in rows:
                row["event"]["binding"][field] = value
                row["event"]["binding_digest"] = sha(row["event"]["binding"])
            with self.subTest(field=field), self.assertRaises(check.CheckFailure):
                check.selected_claim(rows, relay, SCOPE, CREDENTIAL, SUBJECT)

    def test_sdk_no_replay_and_no_secret_diagnostics(self):
        node = {"ok": False, "operation": "create-post", "outcome": "unknown", "mayHaveBeenPosted": True,
            "automaticRetryAllowed": False, "httpStatus": 409, "error": check.base.profiles.NODE_UNKNOWN}
        check.validate_sdk("node", 2, b"", wire(node), 409)
        check.validate_sdk("python", 2, b"", check.base.profiles.FAILURE_MESSAGES["python"], 429)
        for change in (lambda v: v.update(httpStatus=503), lambda v: v.update(automaticRetryAllowed=True),
                lambda v: v.update(error="secret-canary"), lambda v: v.update(extra="canary")):
            value = deepcopy(node); change(value)
            with self.assertRaises(check.CheckFailure):
                check.validate_sdk("node", 2, b"", wire(value), 409)
        self.assertNotEqual(check.base.profiles.post_body("node"), check.base.profiles.post_body("python"))

    def test_inventory_forbids_fake_release_refund_replay_and_unknown_events(self):
        for mode in check.MODES:
            counts = {**check.audit_inventory(mode), check.base.LEASE: 2, check.base.RELOAD: 3}
            check.validate_inventory(counts, mode)
            for kind, count in ((check.quota.CLAIMED, 0), (check.quota.CLAIMED, 2),
                    (check.base.RELEASE, 1), (check.base.BLOCK, 1), ("secret-canary", 1), (check.base.START, True)):
                with self.assertRaises(check.CheckFailure):
                    check.validate_inventory({**counts, kind: count}, mode)

    def test_terminal_cannot_claim_exclusive_cause_or_relabel_expired_hold(self):
        for mode in check.MODES:
            check.validate_success_result(result(mode))
            for change in (lambda v: v.update(exclusiveInternalCauseProven=True), lambda v: v.update(realXVerified=True),
                    lambda v: v.update(limit=True), lambda v: v.update(secret="canary"),
                    lambda v: v["relay"].update(status="expired"), lambda v: v["attemptIds"].append(v["claimAttemptId"]),
                    lambda v: v["completed"][0].update(exitCode=0)):
                value = result(mode); change(value)
                with self.assertRaises(check.CheckFailure):
                    check.validate_success_result(value)
        value = result("revoke-before-release")
        value["hold"]["sdkCompletedAtEpochMs"] = value["claimExpiresAtEpochMs"]
        with self.assertRaises(check.CheckFailure):
            check.validate_success_result(value)


if __name__ == "__main__":
    unittest.main()
