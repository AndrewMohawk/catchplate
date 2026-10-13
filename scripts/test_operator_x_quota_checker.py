#!/usr/bin/env python3
"""Inert quota-checker oracles; not SQLite, SDK, gate or provider acceptance.

Literal synthetic observations exercise exact correlation and refusals. No
success-producing transport/store mocks, clock changes or external processes.
The separate seven-SDK checker must actually run before claiming acceptance.
"""
from collections import Counter
from copy import deepcopy
import hashlib
import json
import unittest

from scripts import check_operator_x_quota as check

APP_A = "11111111-1111-4111-8111-111111111111"
APP_B = "22222222-2222-4222-8222-222222222222"
CREDENTIAL = "33333333-3333-4333-8333-333333333333"
ALIAS = "44444444-4444-4444-8444-444444444444"
RULE = "55555555-5555-4555-8555-555555555555"
SUBJECT = "18446744073709551001"
ANCHOR = 2_000_000_000_000
DAY = ANCHOR // 86_400_000
SCOPE = ("agent:operator-demo:" + APP_A, "operator." + RULE, "sha256:" + "a" * 64)
TEXT = "Serverware local check: caf\u00e9 & <verified>\n"
BODIES = {
    "node": b'{"text":"Serverware local check: caf\xc3\xa9 & <verified>\\n"}',
    "python": b'{"text": "Serverware local check: caf\\u00e9 & <verified>\\n"}',
    "go": b'{"text":"Serverware local check: caf\xc3\xa9 \\u0026 \\u003cverified\\u003e\\n"}',
}


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha(value):
    return "sha256:" + hashlib.sha256(value if type(value) is bytes else wire(value)).hexdigest()


def headers(client):
    result = {"host": "api.x.com", "content-length": str(len(BODIES[client])), "content-type": "application/json",
        "accept": "*/*" if client == "python" else "application/json",
        "user-agent": {"node": "xdk-typescript/0.6.6", "python": "xdk-python/0.10.6", "go": "Go-http-client/1.1"}[client]}
    if client == "node":
        result.update({"accept-language": "*", "sec-fetch-mode": "cors"})
    return result


def provider():
    posts = []
    for ordinal, client in enumerate(("node", "python", "go", "node"), 1):
        response = wire({"data": {"id": str(9000000000000000000 + ordinal), "text": TEXT}})
        posts.append({"ordinal": ordinal, "client": client, "case": "success", "generation": 1 if ordinal <= 3 else 2,
            "alias": 1, "requestBodySha256": sha(BODIES[client]), "requestBodyBytes": len(BODIES[client]),
            "requestHeaders": headers(client), "timestampEpochMs": ANCHOR + (1000 if ordinal <= 3 else 122000) + ordinal,
            "responseBodySha256": sha(response), "responseBytes": len(response), "status": 201,
            "postId": str(9000000000000000000 + ordinal), "providerCredentialMatched": True,
            "proxyAuthorizationPresent": False})
    return {"schema": "serverware.privateXQuotaProvider/v1", "syntheticOnly": True, "terminal": "running",
        "counts": {"total": 18, "authorize": 2, "code": 2, "refresh": 1, "identity": 3, "revoke": 6, "posts": 4, "rejected": 0},
        "initialAccessIssuedAtEpochMs": ANCHOR + 1000, "initialAccessExpiresAtEpochMs": ANCHOR + 121000,
        "initialAccessExpired": True, "refreshAfterInitialExpiry": True,
        "tokenLifetimes": {"initial": 120, "refreshed": 600}, "issuedTokenFamilies": [
            {"alias": 1, "generation": 1}, {"alias": 1, "generation": 2}, {"alias": 2, "generation": 1}],
        "posts": posts, "revocations": [{"alias": alias, "generation": generation, "tokenTypeHint": hint,
            "originalClientVerified": True} for alias, generation in ((1, 1), (1, 2), (2, 1))
            for hint in ("access_token", "refresh_token")], "cleanupComplete": True, "overflowed": False}


def admit_provider(value):
    return check.validate_provider(value, posts=4, consents=2, refreshed=True, cleaned=2, anchor=ANCHOR, expired=True)


def quota_rows():
    starts, rows = {}, []
    bucket = sha({"provider": "x", "subject": SUBJECT, "operation": "tweets.write", "utc_day": DAY})
    previous = None
    for index in range(4):
        attempt = sha(str(index).encode())
        start = {"principal_id": SCOPE[0] if index % 2 == 0 else "agent:operator-demo:" + APP_B,
            "route_id": SCOPE[1], "credential_ref": CREDENTIAL, "credential_version": 1 if index < 3 else 2,
            "policy_hash": SCOPE[2], "request_digest": sha(b"request" + bytes([index])),
            "operation_digest": sha(b"operation" + bytes([index])), "attempt_id": attempt}
        starts[attempt] = start
        binding = {"principal_id": start["principal_id"], "route_id": start["route_id"], "credential_id": CREDENTIAL,
            "credential_version": start["credential_version"], "credential_metadata_digest": sha(b"metadata"),
            "policy_hash": SCOPE[2], "request_digest": start["request_digest"], "operation_digest": start["operation_digest"],
            "attempt_nonce": attempt, "recipient_digest": sha(b"recipient"), "request_binding_digest": sha(b"wire"),
            "expires_at_epoch_ms": ANCHOR + 5000 + index}
        for claimed in (False, True):
            event = {"schema": "serverware.operatorXPostingQuota" + ("Claim/v1" if claimed else "Reservation/v1"),
                "reservation_id": f"66666666-6666-4666-8666-{index:012d}", "bucket_key": bucket,
                "utc_day": DAY, "expires_at_epoch_ms": binding["expires_at_epoch_ms"], "binding_digest": sha(binding),
                "binding": deepcopy(binding), **({"claimed_at_epoch_ms": ANCHOR + 1000 + index} if claimed else {})}
            identifier = f"77777777-7777-4777-8777-{len(rows):012d}"
            event_hash = sha(identifier.encode())
            rows.append({"id": identifier, "event_type": check.CLAIMED if claimed else check.RESERVED,
                "event": event, "event_hash": event_hash, "prev_event_hash": previous})
            previous = event_hash
    return rows, starts


def terminal():
    value = {"schema": "serverware.privateXQuotaCheck/v1", "ok": True, "syntheticOnly": True,
        "realXVerified": False, "productionReady": False, "publicDnsVerified": False,
        "actualExampleEntrypoints": True, "actualManagedLifecycle": True, "auditChainVerified": True,
        "limit": 4, "dataPlaneBinaryDigest": sha(b"binary"), "goExampleSha256": "a" * 64,
        "dependenciesSha256": "b" * 64, "completed": [{"phase": phase, "exitCode": 0 if i < 4 else 2,
            "confirmed": i < 4} for i, phase in enumerate(check.PHASES)], "provider": provider(),
        "restart": {"schema": "serverware.privateXQuotaRestartAck/v1", "request_sha256": sha(b"request"), "status": "retained_restarted"},
        "preCallbackEpochMs": ANCHOR, "credentialIds": [CREDENTIAL, ALIAS], "applicationIds": [APP_A, APP_B], "utcDay": DAY,
        "attemptIds": [sha(bytes([i])) for i in range(7)], "chargedAttemptIds": [sha(bytes([i])) for i in range(4)],
        "deniedAttemptIds": [sha(bytes([i])) for i in range(4, 7)],
        "reservationIds": [f"66666666-6666-4666-8666-{i:012d}" for i in range(4)],
        "bucketKey": sha({"provider": "x", "subject": SUBJECT, "operation": "tweets.write", "utc_day": DAY}),
        "namedAuditInventory": {**check.AUDIT_EXACT, check.base.LEASE: 8, check.base.LEASE_REJECT: 3, check.base.RELOAD: 6}}
    return value


class QuotaCheckerTests(unittest.TestCase):
    def test_independent_limited_v2_commitments_bind_account_and_application(self):
        for client, body in BODIES.items():
            with self.subTest(client=client):
                canonical = {"v": 2, "principal": SCOPE[0], "client_ip": "127.0.0.1", "route_id": SCOPE[1],
                    "credential_ref": CREDENTIAL, "credential_version": "1", "policy_hash": SCOPE[2],
                    "request": {"method": "POST", "scheme": "https", "authority": "api.x.com", "path": "/2/tweets",
                        "query": [], "headers": headers(client), "body_sha256": sha(body), "discard_headers": ["accept-encoding"]},
                    "operation": {"operation": "tweets.write", "providerAccount": sha(b"x\0" + SUBJECT.encode())}}
                self.assertEqual(check.commitments(client, SCOPE, CREDENTIAL, 1, SUBJECT),
                    (sha(canonical), sha({k: v for k, v in canonical.items() if k not in {"v", "client_ip"}})))
                self.assertNotEqual(check.commitments(client, SCOPE, CREDENTIAL, 1, SUBJECT),
                    check.commitments(client, ("agent:operator-demo:" + APP_B, *SCOPE[1:]), CREDENTIAL, 1, SUBJECT))

    def test_provider_exact_four_posts_two_consents_and_six_cleanups(self):
        admit_provider(provider())
        for change in (lambda v: v["counts"].update(posts=5, total=19),
                lambda v: v["counts"].update(refresh=2, total=19), lambda v: v.update(extra="canary"),
                lambda v: v["posts"][0].update(proxyAuthorizationPresent=True),
                lambda v: v["posts"][0]["requestHeaders"].update(authorization="canary"),
                lambda v: v["posts"][0].update(requestBodySha256=sha(b"different")),
                lambda v: v["posts"][0].update(responseBodySha256=sha(b"different"))):
            value = provider(); change(value)
            with self.assertRaises(check.CheckFailure):
                admit_provider(value)

    def test_provider_preserves_original_expiry_refresh_and_alias_identity(self):
        for change in (lambda v: v.update(initialAccessExpiresAtEpochMs=ANCHOR + 180000),
                lambda v: v["tokenLifetimes"].update(initial=180),
                lambda v: v["posts"][2].update(timestampEpochMs=ANCHOR + 60000),
                lambda v: v["posts"][3].update(timestampEpochMs=ANCHOR + 121999),
                lambda v: v["issuedTokenFamilies"][2].update(alias=1),
                lambda v: v["posts"][0].update(alias=True),
                lambda v: v["revocations"][4].update(alias=1), lambda v: v["revocations"].pop()):
            value = provider(); change(value)
            with self.assertRaises(check.CheckFailure):
                admit_provider(value)

    def test_unchanged_sdk_failures_and_exact_node_429(self):
        node = {"ok": False, "operation": "create-post", "outcome": "unknown", "mayHaveBeenPosted": True,
            "automaticRetryAllowed": False, "httpStatus": 429, "error": check.base.profiles.NODE_UNKNOWN}
        check.validate_sdk("node:alias_exhausted", 2, b"", wire(node))
        for status in (200, 403, 409, None, True):
            with self.assertRaises(check.CheckFailure):
                check.validate_sdk("node:alias_exhausted", 2, b"", wire({**node, "httpStatus": status}))
        for client in ("python", "go"):
            phase = "python:a_exhausted" if client == "python" else "go:b_exhausted"
            check.validate_sdk(phase, 2, b"", check.base.profiles.FAILURE_MESSAGES[client])
            with self.assertRaises(check.CheckFailure):
                check.validate_sdk(phase, 2, b"", b"secret-canary")

    def test_exact_durable_four_reserve_claim_pairs_join_actual_attempts(self):
        rows, starts = quota_rows()
        attempts, reservations, bucket = check.validate_quota_events(rows, starts, subject=SUBJECT, day=DAY)
        self.assertEqual(set(attempts), set(starts))
        self.assertEqual(len(reservations), 4)
        self.assertEqual(bucket, sha({"provider": "x", "subject": SUBJECT, "operation": "tweets.write", "utc_day": DAY}))
        for changed in (rows[:-1], rows + [rows[-1]], [r for r in rows if r["event_type"] == check.CLAIMED]):
            with self.assertRaises(check.CheckFailure):
                check.validate_quota_events(changed, starts, subject=SUBJECT, day=DAY)

    def test_coherent_digest_tampering_cannot_rebind_scope_or_attempt(self):
        for field, value in (("principal_id", "different"), ("route_id", "other"), ("credential_id", ALIAS),
                ("credential_version", True), ("policy_hash", sha(b"other")), ("request_digest", sha(b"other")),
                ("operation_digest", sha(b"other")), ("attempt_nonce", sha(b"unknown"))):
            rows, starts = quota_rows()
            for row in rows[:2]:
                row["event"]["binding"][field] = value
                row["event"]["binding_digest"] = sha(row["event"]["binding"])
            with self.subTest(field=field), self.assertRaises(check.CheckFailure):
                check.validate_quota_events(rows, starts, subject=SUBJECT, day=DAY)

    def test_claim_day_original_deadline_and_pair_identity_cannot_change(self):
        for change in (lambda v: v.update(utc_day=DAY + 1), lambda v: v.update(claimed_at_epoch_ms=ANCHOR + 5000),
                lambda v: v.update(bucket_key=sha(b"other-account")), lambda v: v.update(extra="secret-canary"),
                lambda v: v.update(reservation_id="99999999-9999-4999-8999-999999999999")):
            rows, starts = quota_rows(); change(rows[1]["event"])
            with self.assertRaises(check.CheckFailure):
                check.validate_quota_events(rows, starts, subject=SUBJECT, day=DAY)

    def test_audit_predecessor_order_not_delivery_order(self):
        rows, _ = quota_rows()
        self.assertEqual(check.ordered_audit(list(reversed(rows))), rows)
        for changed in (rows[1:], rows + [rows[0]]):
            with self.assertRaises(check.CheckFailure):
                check.ordered_audit(changed)
        changed = deepcopy(rows); changed[-1]["prev_event_hash"] = changed[0]["event_hash"]
        with self.assertRaises(check.CheckFailure):
            check.ordered_audit(changed)

    def test_terminal_closed_roster_has_no_live_claim_or_reset(self):
        check.validate_success_result(terminal())
        for change in (lambda v: v.update(realXVerified=True), lambda v: v.update(publicDnsVerified=True),
                lambda v: v.update(limit=True), lambda v: v.update(secret="canary"),
                lambda v: v["completed"].pop(), lambda v: v["completed"][4].update(exitCode=0),
                lambda v: v["restart"].update(status="new_containers"),
                lambda v: v["namedAuditInventory"].update({check.CLAIMED: 3}),
                lambda v: v["deniedAttemptIds"].__setitem__(0, v["chargedAttemptIds"][0])):
            value = terminal(); change(value)
            with self.assertRaises(check.CheckFailure):
                check.validate_success_result(value)


if __name__ == "__main__":
    unittest.main()
