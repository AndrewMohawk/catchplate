"""Offline checker oracles: synthetic clocks, in-memory provider, no SDK process.

Expected canonical requests and durable rows are independently constructed;
these controls are not real expiry, signed-audit, TLS or proxy acceptance.
"""
from copy import deepcopy
import os
import unittest
from unittest.mock import patch
from urllib.parse import parse_qsl

from scripts import check_operator_gmail_sdk as checker
from scripts import test_operator_gmail_sdk_fixture as receiver


def sha(number):
    return "sha256:" + format(number, "064x")


def uid(number):
    return "00000000-0000-4000-8000-" + format(number, "012d")


SCOPE = ("synthetic-principal", "synthetic-route", sha(900))
CREDENTIAL = uid(1)
REVOCATION = {"rule_id": uid(4), "application_id": uid(2), "revision": 6,
    "policy_sequence": 3, "policy_hash": sha(902)}
GRANT = {"rule_id": uid(4), "application_id": uid(2), "revision": 5,
    "policy_sequence": 2, "previous_policy_hash": sha(899)}
PHASES = ("first", "refreshed", "wrong_outer_ca", "wrong_inner_ca", "wrong_app", "revoked")
START, RELEASE = "data_plane.credential.release_started", "data_plane.response.released"
CONNECT, DENIED = "data_plane.connect.established", "data_plane.connect.denied"
LEASE = "data_plane.credential_lease.issued"
REJECTED = "data_plane.credential_lease.rejected"
SUCCESS = b'{"pages":2,"messages_read":2,"more_pages":false}\n'
DENIAL = b"Gmail list failed; inspect Serverware audit records and the saved permission (no automatic retry)\n"


def provider_documents():
    # A different component supplies actual observation records. Only its
    # response transport and synthetic clock are replaced, as in its own tests.
    with receiver.captured() as provider, receiver.clock(0):
        documents = {"fresh": provider.observations()}
        tokens = receiver.authorize(provider)
        status, _ = receiver.send(provider, receiver.request("/v1/userinfo",
            host="openidconnect.googleapis.com", token=tokens["access_token"]))
        assert status == 200
        documents["connected"] = provider.observations()
        with receiver.clock(1):
            for target in receiver.TARGETS:
                assert receiver.send(provider, receiver.request(target, token=tokens["access_token"]))[0] == 200
            documents["first"] = provider.observations()
        with receiver.clock(91):
            documents["expired"] = provider.observations()
            status, renewed = receiver.refresh(provider, tokens)
            assert status == 200
            for target in receiver.TARGETS:
                assert receiver.send(provider, receiver.request(target, token=renewed["access_token"]))[0] == 200
            documents["refreshed"] = provider.observations()
    return documents


def canonical(index, generation):
    path, query = receiver.TARGETS[index].split("?", 1)
    operation = {"operation": "gmail.messages.list", "gmailUser": "me"}
    if index in (1, 3):
        operation = {"operation": "gmail.message.get", "gmailUser": "me", "messageId": ("msg_1" if index == 1 else "msg-2")}
    return {"v": 3, "principal": SCOPE[0], "client_ip": "127.0.0.1", "route_id": SCOPE[1],
        "credential_ref": CREDENTIAL, "credential_version": str(generation), "policy_hash": SCOPE[2],
        "request": {"method": "GET", "scheme": "https", "authority": "gmail.googleapis.com", "path": path,
            "query": [list(pair) for pair in parse_qsl(query, keep_blank_values=True)],
            "query_mode": "orderedFormV1", "query_wire": query,
            "headers": {"host": "gmail.googleapis.com", "user-agent": "google-api-go-client/0.5",
                "x-goog-api-client": "gl-go/1.26.9 gdcl/0.264.0"},
            "body_sha256": receiver.digest(b""), "discard_headers": ["accept-encoding"]}, "operation": operation}


def commitments(document):
    result = []
    for index, row in enumerate(document["gmailSdk"]["attempts"]):
        generation = 1 + index // 4
        value = canonical(index % 4, generation)
        operation = {key: item for key, item in value.items() if key not in {"v", "client_ip"}}
        result.append({"case": receiver.CASES[index % 4], "generation": generation,
            "requestDigest": receiver.digest(receiver.encoded(value)),
            "operationDigest": receiver.digest(receiver.encoded(operation)),
            "responseBodySha256": row["responseBodySha256"], "responseBodyBytes": row["responseBodyBytes"]})
    return result


def audit_rows(wire):
    events = []
    def append(kind, event):
        events.append({"id": sha(100 + len(events)) if kind in {START, RELEASE} else uid(100 + len(events)),
            "event_hash": sha(100 + len(events)),
            "prev_event_hash": events[-1]["event_hash"] if events else None,
            "created_at": "2026-10-11T22:06:%02d.000000+00:00" % len(events),
            "event_type": kind, "event": event})
    append("credential.oauth_connected", {"credential_id": CREDENTIAL, "credential_version": 1})
    append("credential.oauth_refreshed", {"credential_id": CREDENTIAL, "provider": "google",
        "previous_credential_version": 1, "credential_version": 2, "refresh_token_rotated": True,
        "scopes": list(receiver.SCOPES)})
    for index, row in enumerate(wire):
        common = {"principal_id": SCOPE[0], "route_id": SCOPE[1], "policy_hash": SCOPE[2],
            "method": "GET", "attempt_id": sha(index + 1), "flow_id": sha(index + 1),
            "credential_ref": CREDENTIAL, "credential_version": row["generation"],
            "request_digest": row["requestDigest"], "operation_digest": row["operationDigest"]}
        append(START, {**common, "outcome": "release_started"})
        append(RELEASE, {**common, "outcome": "released", "upstream_status": 200,
            "response_body_sha256": row["responseBodySha256"], "response_body_bytes": row["responseBodyBytes"]})
    # Unlike gate-submitted start/terminal rows, this data_plane event is
    # recorded by the control plane and has a UUID. It is not a release pair.
    append(LEASE, {"principal_id": SCOPE[0], "route_id": SCOPE[1], "policy_hash": SCOPE[2],
        "credential_id": CREDENTIAL, "purpose": "dispatchSecret", "expected_credential_version": 1,
        "data_plane_binary_digest": sha(901), "status_code": 200, "outcome": "issued"})
    return events


def reconciliation_row():
    # Actual control-plane audit shape: this is a no-envelope response to a
    # stale generation request, not another release or a provider arrival.
    return {"id": uid(500), "event_hash": sha(500), "event_type": REJECTED, "event": {
        "outcome": "rejected", "status_code": 409, "reason": "generationAdvancedBeforeEnvelope",
        "recipient_key_id": "synthetic-recipient", "recipient_nonce_sha256": sha(903),
        "policy_hash": SCOPE[2], "data_plane_binary_digest": sha(901), "purpose": "dispatchSecret",
        "expected_credential_version": 1, "expected_metadata_sha256": sha(904),
        "release_attempt_id": None, "release_binding_digest": None, "release_kind": None,
        "release_reservation_id": None, "release_request_digest": None, "release_operation_digest": None,
        "release_quota_claim_count": 0, "principal_id": SCOPE[0], "route_id": SCOPE[1],
        "credential_id": CREDENTIAL, "requested_max_ttl_seconds": 5, "recipient_attestation_present": False,
        "credential_count": 0, "credential_ids": [], "issued_at_epoch_ms": None, "expires_at_epoch_ms": None}}


def publication_rows(wire, *, rollover=True):
    rows = audit_rows(wire)
    if rollover:
        rows.append({**reconciliation_row(), "prev_event_hash": rows[-1]["event_hash"],
            "created_at": "2026-10-11T22:06:30.000000+00:00"})
    rejection = {**reconciliation_row()["event"], "status_code": 503,
        "reason": "active signed policy bundle is unavailable", "purpose": "generationMetadata",
        "expected_credential_version": None, "expected_metadata_sha256": None, "recipient_key_id": sha(905)}
    for index, (kind, event, timestamp) in enumerate((
            ("operator_catalog.access_rule.revoked", {"resource_type": "access_rule", "resource_id": uid(4),
                "application_id": uid(2), "credential_id": CREDENTIAL, "revision": 6,
                "policy_sequence": 3, "policy_hash": sha(902)}, "2026-10-11T22:06:58.523932+00:00"),
            (REJECTED, rejection, "2026-10-11T22:06:58.655651+00:00"),
            (checker.RELOAD, {"previous_policy_hash": SCOPE[2], "policy_hash": sha(902), "policy_sequence": 3},
                "2026-10-11T22:06:59.714774+00:00"))):
        rows.append({"id": sha(600 + index) if kind == checker.RELOAD else uid(600 + index),
            "event_hash": sha(600 + index), "prev_event_hash": rows[-1]["event_hash"],
            "event_type": kind, "event": event, "created_at": timestamp})
    return rows


def grant_failure_rows(wire):
    rows = audit_rows(wire)
    rows[0]["created_at"] = "2026-10-11T22:05:40+00:00"
    grant = {"id": uid(700), "event_hash": sha(700), "created_at": "2026-10-11T22:05:50+00:00",
        "event_type": "operator_catalog.access_rule.created", "event": {"resource_type": "access_rule",
            "resource_id": uid(4), "application_id": uid(2), "credential_id": CREDENTIAL,
            "revision": 5, "policy_sequence": 2, "policy_hash": SCOPE[2]}}
    failure = {"id": sha(701), "event_hash": sha(701), "created_at": "2026-10-11T22:05:51+00:00",
        "event_type": checker.RELOAD_FAILED, "event": {"component": "serverware-decision-gate-rs",
            "active_policy_hash": GRANT["previous_policy_hash"], "error": "policy_reload_failed",
            "error_sha256": "sha256:35819006a1b3c481018dbc9e8bd0d1753fe7cf725ae7c248a5f47d1f36186b93"}}
    reload = {"id": sha(702), "event_hash": sha(702), "created_at": "2026-10-11T22:05:52+00:00",
        "event_type": checker.RELOAD, "event": {"previous_policy_hash": GRANT["previous_policy_hash"],
            "policy_hash": SCOPE[2], "policy_sequence": 2}}
    rows = [rows[0], grant, failure, reload, *rows[1:]]
    for index, row in enumerate(rows):
        row["prev_event_hash"] = rows[index - 1]["event_hash"] if index else None
    return rows


def counts(consent, refresh, reads):
    return {key: value for key, value in {
        "authorization_requests": consent, "authorization_codes_issued": consent, "authorization_code_exchanges": consent,
        "token_requests": consent + refresh, "token_responses": consent + refresh, "refresh_exchanges": refresh,
        "identity_requests": consent, "resource_requests": reads, "resource_attempts": reads,
        "resource_gmail.messages.list": reads // 2, "resource_gmail.message.get": reads // 2}.items() if value}


def success_result(wire):
    expiry = receiver.EPOCH_MS + 90_000
    stages = (("fresh", 0, 0, 0), ("connected", 1, 0, 0), ("first", 1, 0, 4),
              ("expired", 1, 0, 4), ("refreshed", 1, 1, 8))
    return {"schema": "serverware.privateGmailSdkCheck/v1", "ok": True, "syntheticOnly": True,
        "actualExampleEntrypoint": True, "auditChainVerified": True, "separateOuterInnerTrust": True,
        "catalogUnchangedAcrossRefresh": True, "realGoogleVerified": False, "browserUiVerified": False,
        "productionReady": False, "hardwareVerified": False, "publicDnsVerified": False,
        "providerAttempts": 8, "automaticRefreshes": 1, "initialCredentialVersion": 1,
        "refreshedCredentialVersion": 2, "canonicalRequestVersion": 3, "reconciliationRejections": 0,
        "revocationPublicationRejections": 0,
        "grantPublicationReloadFailures": 0,
        "dataPlaneBinaryDigest": sha(901), "goExampleSha256": "a" * 64,
        "exampleSourceSha256": {"examples/google-gmail-go/main.go": "b" * 64,
            "examples/google-gmail-go/go.mod": "c" * 64, "examples/google-gmail-go/go.sum": "d" * 64},
        "credentialId": CREDENTIAL, "applicationIds": [uid(2), uid(3)], "ruleId": uid(4),
        "policyHash": SCOPE[2], "revokedPolicyHash": sha(902), "policyRevisions": {"accepted": 5, "revoked": 6},
        "originalAccessExpiresAtEpochMs": expiry, "refreshCompletedAtExpiry": False,
        "completed": [{"phase": phase, "exitCode": 0 if index < 2 else 1,
            "summary": {"pages": 2, "messages_read": 2, "more_pages": False} if index < 2 else None}
            for index, phase in enumerate(PHASES)],
        "providerObservations": [{"stage": stage, "counts": counts(consent, refresh, reads),
            "initialAccessExpiresAtEpochMs": expiry if consent else None,
            "initialAccessExpired": stage in {"expired", "refreshed"},
            "resourceGenerations": [1 + index // 4 for index in range(reads)],
            "cases": [receiver.CASES[index % 4] for index in range(reads)],
            "refreshCompletedAtExpiry": False if stage == "expired" else None}
            for stage, consent, refresh, reads in stages],
        "requests": deepcopy(wire), "negativeControls": [{"phase": phase, "providerAttemptsBefore": 8,
            "providerAttemptsAfter": 8, "auditEventType": kind, "auditEventId": sha(200 + index) if kind else None}
            for index, (phase, kind) in enumerate(zip(PHASES[2:], (None, CONNECT, DENIED, DENIED)))],
        # Four catalog mutations plus the same sixteen start/terminal rows.
        "durableAuditEventIds": [uid(300 + index) for index in range(4)] + [sha(102 + index) for index in range(16)],
        "auditAttemptIds": [sha(index + 1) for index in range(8)],
        "generationAuditEventIds": [uid(100), uid(101)] + [sha(100 + index) for index in (2, 4, 6, 8, 10, 12, 14, 16)],
        "namedAuditInventory": {START: 8, RELEASE: 8, CONNECT: 9, DENIED: 2, LEASE: 8,
            "data_plane.policy.reloaded": 2, "credential.oauth_connected": 1, "credential.oauth_refreshed": 1}}


class GmailSdkCheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.documents = provider_documents()
        cls.wire = commitments(cls.documents["refreshed"])

    def test_original_sdk_canonical_v3_excludes_provider_added_accept(self):
        rows = self.documents["refreshed"]["gmailSdk"]["attempts"]
        for index, row in enumerate(rows):
            original = deepcopy(row)
            expected = self.wire[index]
            self.assertEqual(checker.request_commitments(row, scope=SCOPE, credential_id=CREDENTIAL,
                generation=1 + index // 4), (expected["requestDigest"], expected["operationDigest"]))
            self.assertEqual(row, original)
            wrong = canonical(index % 4, 1 + index // 4)
            wrong["request"]["headers"]["accept"] = "*/*"
            self.assertNotEqual(receiver.digest(receiver.encoded(wrong)), expected["requestDigest"])
        for field, value in (("rawQuery", receiver.NEXT.replace("+%2F", "%20%2F")),
                ("ordinal", True), ("tokenGeneration", True), ("authorized", 1), ("requestBodyBytes", False),
                ("requestHeaders", {**receiver.PUBLIC_HEADERS, "authorization": "secret-canary"}),
                ("responseBodySha256", sha(999))):
            row = deepcopy(rows[0]); row[field] = value
            with self.subTest(field=field), self.assertRaises(checker.CheckFailure):
                checker.request_commitments(row, scope=SCOPE, credential_id=CREDENTIAL, generation=1)

    def test_supported_go_fingerprint_rejects_old_mixed_and_extra_headers(self):
        original = self.documents["refreshed"]["gmailSdk"]["attempts"][0]
        for name, value in (("x-goog-api-client", "gl-go/1.23.12 gdcl/0.230.0"),
                ("x-goog-api-client", "gl-go/1.23.12 gdcl/0.264.0"),
                ("x-goog-api-client", "gl-go/1.26.9 gdcl/0.230.0"),
                ("x-goog-api-client", "gl-go/1.26.9 gdcl/0.264.0 extra/1"),
                ("x-extra-sdk", "extra/1")):
            row = deepcopy(original)
            row["requestHeaders"][name] = value
            # Recompute the altered record's public commitment: rejection must
            # bind the exact supported wire, not merely detect a stale hash.
            public = {"schema": "serverware.privateGmailSdkRequest/v1", "method": "GET",
                "authority": "gmail.googleapis.com", "path": row["path"], "rawQuery": row["rawQuery"],
                "headers": row["requestHeaders"], "bodySha256": receiver.digest(b""), "bodyBytes": 0}
            row["requestCommitment"] = receiver.digest(receiver.encoded(public))
            with self.subTest(name=name, value=value), self.assertRaises(checker.CheckFailure):
                checker.request_commitments(row, scope=SCOPE, credential_id=CREDENTIAL, generation=1)
            wrong = canonical(0, 1)
            wrong["request"]["headers"][name] = value
            self.assertNotEqual(receiver.digest(receiver.encoded(wrong)), self.wire[0]["requestDigest"])

    def test_provider_checkpoints_require_original_expiry_typed_generations_and_counts(self):
        for stage, document in self.documents.items():
            result = checker.observations(document, stage)
            self.assertEqual(result["stage"], stage)
            self.assertEqual(result["resourceGenerations"], [1]*4 + [2]*4 if stage == "refreshed"
                else [1]*4 if stage in {"first", "expired"} else [])
        changes = (("count", lambda d: d["counts"]["google"].update(resource_attempts=9)),
            ("retry", lambda d: d["counts"]["google"].update(refresh_exchanges=2)),
            ("bool", lambda d: d["counts"]["google"].update(refresh_exchanges=True)),
            ("expired", lambda d: d.update(initialAccessExpired=False)),
            ("clock", lambda d: d["gmailSdk"]["attempts"][4].update(timestampEpochMs=receiver.EPOCH_MS + 90_999)),
            ("generation", lambda d: d["gmailSdk"]["attempts"][4].update(tokenGeneration=1)),
            ("order", lambda d: d["gmailSdk"]["attempts"].reverse()),
            ("extra", lambda d: d.update(secret="secret-canary")))
        for name, change in changes:
            value = deepcopy(self.documents["refreshed"]); change(value)
            with self.subTest(case=name), self.assertRaises(checker.CheckFailure):
                checker.observations(value, "refreshed")
        first = deepcopy(self.documents["first"])
        first["gmailSdk"]["attempts"][0]["timestampEpochMs"] = receiver.EPOCH_MS + 30_000
        with self.assertRaises(checker.CheckFailure):
            checker.observations(first, "first")

    def test_durable_pair_evidence_binds_generations_scope_body_and_unique_attempts(self):
        rows = audit_rows(self.wire)
        actual = checker.generation_evidence(rows, SCOPE, CREDENTIAL, self.wire, expected_binary_sha256=sha(901))
        self.assertEqual((actual["initialCredentialVersion"], actual["refreshedCredentialVersion"],
            actual["canonicalRequestVersion"]), (1, 2, 3))
        self.assertEqual(set(actual["generationAuditEventIds"]),
            {rows[index]["id"] for index in (0, 1, 2, 4, 6, 8, 10, 12, 14, 16)})
        self.assertEqual(rows[-1]["event_type"], LEASE)
        self.assertEqual(rows[-1]["id"], uid(118))
        self.assertNotIn(rows[-1]["id"], actual["generationAuditEventIds"])
        self.assertEqual(actual["reconciliationRejections"], 0)
        changes = (lambda r: r.remove(next(row for row in r if row["event_type"] == RELEASE)),
            lambda r: r[1]["event"].update(credential_version=1),
            lambda r: r[0]["event"].update(credential_version=True),
            lambda r: r[1]["event"].update(previous_credential_version=True),
            lambda r: r[1]["event"].update(refresh_token_rotated=False),
            lambda r: r[1]["event"].update(scopes=["openid"]),
            lambda r: r[2]["event"].update(credential_ref=uid(999)),
            lambda r: r[3]["event"].update(policy_hash=sha(999)),
            lambda r: r[3]["event"].update(response_body_sha256=sha(999)),
            lambda r: r[3]["event"].update(response_body_bytes=0),
            lambda r: r[3]["event"].update(outcome="blocked"),
            lambda r: r[3]["event"].update(attempt_id=sha(999)),
            lambda r: r[3].update(id=r[2]["id"]), lambda r: r[2].update(id=uid(999)),
            lambda r: r[0].update(id=sha(999)), lambda r: r[-1].update(id=sha(999)),
            lambda r: r[2].update(event_hash="secret-canary"))
        for index, change in enumerate(changes):
            value = deepcopy(rows); change(value)
            with self.subTest(case=index), self.assertRaises(checker.CheckFailure):
                checker.generation_evidence(value, SCOPE, CREDENTIAL, self.wire, expected_binary_sha256=sha(901))
        for field, replacement in (("generation", True), ("requestDigest", self.wire[0]["requestDigest"]),
                ("responseBodySha256", sha(999))):
            value = deepcopy(self.wire); value[1][field] = replacement
            with self.assertRaises(checker.CheckFailure):
                checker.generation_evidence(rows, SCOPE, CREDENTIAL, value, expected_binary_sha256=sha(901))

    def test_one_no_envelope_reconciliation_requires_exact_refresh_and_authority(self):
        original = audit_rows(self.wire)
        rows = original + [reconciliation_row()]
        expected = checker.generation_evidence(original, SCOPE, CREDENTIAL, self.wire, expected_binary_sha256=sha(901))
        expected["reconciliationRejections"] = 1
        self.assertEqual(checker.generation_evidence(rows, SCOPE, CREDENTIAL, self.wire,
            expected_binary_sha256=sha(901)), expected)
        self.assertNotIn(rows[-1]["id"], expected["generationAuditEventIds"])
        # The audit API can present newest-first; never infer causality from
        # list order instead of joining the single retained 1 -> 2 refresh.
        self.assertEqual(checker.generation_evidence(list(reversed(rows)), SCOPE, CREDENTIAL, self.wire,
            expected_binary_sha256=sha(901)), expected)
        changes = [(field, value) for field, value in (
            ("reason", "secret-canary"), ("outcome", "issued"), ("status_code", 503), ("status_code", True),
            ("purpose", "generation"), ("expected_credential_version", 2), ("expected_credential_version", True),
            ("principal_id", "wrong-principal"), ("route_id", "wrong-route"), ("policy_hash", sha(999)),
            ("credential_id", uid(999)), ("data_plane_binary_digest", sha(999)),
            ("expected_metadata_sha256", "secret-canary"), ("recipient_nonce_sha256", "secret-canary"),
            ("recipient_attestation_present", True), ("recipient_attestation_present", 0),
            ("credential_count", 1), ("credential_count", False), ("credential_ids", [CREDENTIAL]),
            ("credential_ids", ()), ("release_quota_claim_count", 1), ("release_quota_claim_count", False))]
        null_fields = ("release_attempt_id", "release_binding_digest", "release_kind", "release_reservation_id",
            "release_request_digest", "release_operation_digest", "issued_at_epoch_ms", "expires_at_epoch_ms")
        changes.extend((field, "secret-canary") for field in null_fields)
        for field, replacement in changes:
            value = deepcopy(rows); value[-1]["event"][field] = replacement
            with self.subTest(field=field, value=replacement), self.assertRaises(checker.CheckFailure) as caught:
                checker.generation_evidence(value, SCOPE, CREDENTIAL, self.wire, expected_binary_sha256=sha(901))
            self.assertNotIn("secret-canary", str(caught.exception))
        for field in null_fields:
            value = deepcopy(rows); del value[-1]["event"][field]
            with self.subTest(missing=field), self.assertRaises(checker.CheckFailure):
                checker.generation_evidence(value, SCOPE, CREDENTIAL, self.wire, expected_binary_sha256=sha(901))
        second = reconciliation_row(); second.update(id=uid(501), event_hash=sha(501))
        wrong_id = deepcopy(rows); wrong_id[-1]["id"] = sha(500)
        without_refresh = [row for row in rows if row["event_type"] != "credential.oauth_refreshed"]
        for value in (rows + [second], wrong_id, without_refresh):
            with self.assertRaises(checker.CheckFailure):
                checker.generation_evidence(value, SCOPE, CREDENTIAL, self.wire, expected_binary_sha256=sha(901))
        with self.assertRaises(checker.CheckFailure):
            checker.generation_evidence(rows, SCOPE, CREDENTIAL, self.wire, expected_binary_sha256=sha(999))

    def test_publication_refusal_is_separate_and_only_between_exact_revoke_and_reload(self):
        rows = publication_rows(self.wire)
        def check(value, context=REVOCATION):
            return checker.generation_evidence(value, SCOPE, CREDENTIAL, self.wire,
                expected_binary_sha256=sha(901), revocation=context)
        expected = check(rows)
        self.assertEqual((expected["reconciliationRejections"], expected["revocationPublicationRejections"]), (1, 1))
        self.assertEqual(check(list(reversed(rows))), expected)
        self.assertEqual(check(publication_rows(self.wire, rollover=False))["reconciliationRejections"], 0)
        with self.assertRaises(checker.CheckFailure): check(rows, None)
        context_changes = ({"rule_id": uid(999)}, {"application_id": uid(999)}, {"revision": 7},
            {"revision": True}, {"policy_sequence": 4}, {"policy_sequence": True},
            {"policy_hash": SCOPE[2]}, {"policy_hash": sha(999)}, {"extra": "secret-canary"})
        for change in context_changes:
            with self.subTest(context=change), self.assertRaises(checker.CheckFailure):
                check(rows, {**REVOCATION, **change})
        changes = (
            lambda r: r[-3]["event"].update(resource_id=uid(999)),
            lambda r: r[-3]["event"].update(resource_type="credential"),
            lambda r: r[-3]["event"].update(application_id=uid(999)),
            lambda r: r[-3]["event"].update(credential_id=uid(999)),
            lambda r: r[-3]["event"].update(revision=True),
            lambda r: r[-3]["event"].update(policy_sequence=4),
            lambda r: r[-1]["event"].update(previous_policy_hash=sha(999)),
            lambda r: r[-1]["event"].update(policy_hash=sha(999)),
            lambda r: r[-1]["event"].update(policy_sequence=True),
            lambda r: r[-1]["event"].update(policy_sequence=4),
            lambda r: r[-2].update(created_at=r[-3]["created_at"]),
            lambda r: r[-2].update(created_at=r[-1]["created_at"]),
            lambda r: r[-2].update(created_at="2026-10-11T22:06:57+00:00"),
            lambda r: r[-2].update(created_at="2026-10-11T22:07:01+00:00"),
            lambda r: r[-2].update(created_at="2026-10-11T22:06:58.600000"),
            lambda r: r[-2].update(created_at="2026-99-11T22:06:58+00:00"),
            lambda r: r[-2].pop("created_at"),
            lambda r: r[-2].update(prev_event_hash=r[-3]["prev_event_hash"]),
            lambda r: r[-1].update(prev_event_hash=r[-3]["event_hash"]),
            lambda r: r[-3].update(prev_event_hash=sha(999)),
            lambda r: r[-3].update(prev_event_hash=r[-1]["event_hash"]),
            lambda r: r[2].update(created_at=r[-1]["created_at"]),
            lambda r: r.pop(-3), lambda r: r.pop(-1))
        for index, change in enumerate(changes):
            value = deepcopy(rows); change(value)
            with self.subTest(case=index), self.assertRaises(checker.CheckFailure): check(value)
        for index in (-3, -2, -1):
            value = deepcopy(rows); duplicate = deepcopy(value[index])
            duplicate.update(id=sha(998) if index == -1 else uid(998), event_hash=sha(998))
            value.append(duplicate)
            with self.subTest(duplicate=index), self.assertRaises(checker.CheckFailure): check(value)
        # This new category does not lift the independent original rollover cap.
        value = deepcopy(rows); extra = reconciliation_row(); extra.update(id=uid(997), event_hash=sha(997))
        with self.assertRaises(checker.CheckFailure): check(value + [extra])

    def test_publication_refusal_accepts_only_two_exact_early_status_reason_pairs(self):
        rows = publication_rows(self.wire)
        def check(value):
            return checker.generation_evidence(value, SCOPE, CREDENTIAL, self.wire,
                expected_binary_sha256=sha(901), revocation=REVOCATION)
        expected = check(rows)
        inactive = deepcopy(rows)
        inactive[-2]["event"].update(status_code=409, reason="data-plane policy hash is not active")
        self.assertEqual(check(inactive), expected)
        self.assertEqual(check(list(reversed(inactive))), expected)
        for status, reason in ((409, "active signed policy bundle is unavailable"),
                (503, "data-plane policy hash is not active"), (409, "generationAdvancedBeforeEnvelope"),
                (409, "principal is not assigned to the requested active route"),
                (409, "credential does not match the requested active route"),
                (409, "credential is not declared by the active policy"),
                (503, "active signed policy bundle became unavailable"), (409, "secret-canary")):
            value = deepcopy(rows); value[-2]["event"].update(status_code=status, reason=reason)
            with self.subTest(status=status, reason=reason), self.assertRaises(checker.CheckFailure) as caught: check(value)
            self.assertNotIn("secret-canary", str(caught.exception))
        outside = deepcopy(inactive); outside[-2].update(created_at=outside[-1]["created_at"])
        with self.assertRaises(checker.CheckFailure): check(outside)
        with self.assertRaises(checker.CheckFailure):
            checker.generation_evidence(inactive, SCOPE, CREDENTIAL, self.wire, expected_binary_sha256=sha(901))

    def test_publication_refusal_requires_closed_empty_old_policy_metadata(self):
        rows = publication_rows(self.wire)
        def check(value):
            return checker.generation_evidence(value, SCOPE, CREDENTIAL, self.wire,
                expected_binary_sha256=sha(901), revocation=REVOCATION)
        changes = (("reason", "generationAdvancedBeforeEnvelope"), ("purpose", "dispatchSecret"),
            ("outcome", "issued"), ("status_code", 409), ("status_code", True),
            ("principal_id", "wrong-principal"), ("route_id", "wrong-route"), ("policy_hash", sha(902)),
            ("credential_id", uid(999)), ("data_plane_binary_digest", sha(999)),
            ("expected_credential_version", 2), ("expected_metadata_sha256", sha(904)),
            ("recipient_key_id", "secret-canary"), ("recipient_nonce_sha256", "secret-canary"),
            ("requested_max_ttl_seconds", 6), ("requested_max_ttl_seconds", True),
            ("recipient_attestation_present", True), ("recipient_attestation_present", 0),
            ("credential_count", 1), ("credential_count", False), ("credential_ids", [CREDENTIAL]),
            ("credential_ids", ()), ("release_quota_claim_count", 1), ("release_quota_claim_count", False),
            ("secretCiphertext", "secret-canary"), ("extra", "secret-canary"))
        null_fields = ("expected_credential_version", "expected_metadata_sha256", "release_attempt_id",
            "release_binding_digest", "release_kind", "release_reservation_id", "release_request_digest",
            "release_operation_digest", "issued_at_epoch_ms", "expires_at_epoch_ms")
        for field, replacement in (*changes, *((field, "secret-canary") for field in null_fields)):
            value = deepcopy(rows); value[-2]["event"][field] = replacement
            with self.subTest(field=field), self.assertRaises(checker.CheckFailure) as caught: check(value)
            self.assertNotIn("secret-canary", str(caught.exception))
        for field in rows[-2]["event"]:
            value = deepcopy(rows); del value[-2]["event"][field]
            with self.subTest(missing=field), self.assertRaises(checker.CheckFailure): check(value)

    def test_grant_reload_failure_requires_exact_digest_shape_and_single_saved_transition(self):
        rows = grant_failure_rows(self.wire)
        def check(value, context=GRANT):
            return checker.grant_publication_reload_failures(value, SCOPE, CREDENTIAL, grant=context)
        self.assertEqual(check(rows), 1)
        self.assertEqual(check(list(reversed(rows))), 1)
        self.assertEqual(check(audit_rows(self.wire)), 0)
        for context in (None, {**GRANT, "rule_id": uid(999)}, {**GRANT, "application_id": uid(999)},
                {**GRANT, "revision": True}, {**GRANT, "revision": 6}, {**GRANT, "policy_sequence": 3},
                {**GRANT, "previous_policy_hash": SCOPE[2]}, {**GRANT, "extra": True}):
            with self.subTest(context=context), self.assertRaises(checker.CheckFailure): check(rows, context)
        changes = (
            lambda r: r[2]["event"].update(error_sha256=sha(999)),
            lambda r: r[2]["event"].update(error_sha256=checker.digest(b"control-plane attestation nonce mismatch")),
            lambda r: r[2]["event"].update(component="other-component"),
            lambda r: r[2]["event"].update(active_policy_hash=SCOPE[2]),
            lambda r: r[2]["event"].update(error="operator_demo_policy_refused"),
            lambda r: r[2]["event"].update(candidate_policy_hash=SCOPE[2]),
            lambda r: r[2]["event"].update(extra="secret-canary"),
            lambda r: r[2]["event"].pop("active_policy_hash"),
            lambda r: r[2].update(id=uid(701)),
            lambda r: r[1]["event"].update(resource_id=uid(999)),
            lambda r: r[1]["event"].update(application_id=uid(999)),
            lambda r: r[1]["event"].update(credential_id=uid(999)),
            lambda r: r[1]["event"].update(resource_type="credential"),
            lambda r: r[1]["event"].update(revision=True),
            lambda r: r[1]["event"].update(policy_sequence=3),
            lambda r: r[1]["event"].update(policy_hash=sha(999)),
            lambda r: r[3]["event"].update(previous_policy_hash=sha(999)),
            lambda r: r[3]["event"].update(policy_hash=sha(999)),
            lambda r: r[3]["event"].update(policy_sequence=True),
            lambda r: r[3]["event"].update(policy_sequence=3),
            lambda r: r[2].update(created_at=r[1]["created_at"]),
            lambda r: r[2].update(created_at=r[3]["created_at"]),
            lambda r: r[2].update(created_at="2026-10-11T22:06:58+00:00"),
            lambda r: r[2].update(prev_event_hash=r[1]["prev_event_hash"]),
            lambda r: r[3].update(prev_event_hash=r[1]["event_hash"]),
            lambda r: r[5].update(created_at=r[3]["created_at"]),
            lambda r: r[5].update(prev_event_hash=r[1]["event_hash"]),
            lambda r: r.pop(1), lambda r: r.pop(3), lambda r: r.pop(5))
        for index, change in enumerate(changes):
            value = deepcopy(rows); change(value)
            with self.subTest(case=index), self.assertRaises(checker.CheckFailure) as caught: check(value)
            self.assertNotIn("secret-canary", str(caught.exception))
        for index in (1, 2, 3):
            value = deepcopy(rows); duplicate = deepcopy(value[index])
            duplicate.update(id=uid(998) if index == 1 else sha(998), event_hash=sha(998))
            with self.subTest(duplicate=index), self.assertRaises(checker.CheckFailure): check(value + [duplicate])

    def test_actual_denial_join_rejects_provider_arrival_before_further_audit_io(self):
        document = self.documents["refreshed"]
        self.assertTrue(checker.validate_no_arrivals(document, deepcopy(document)))
        for mutation in (lambda d: d["counts"]["google"].update(resource_attempts=9),
                lambda d: d["counts"]["google"].update(refresh_exchanges=2),
                lambda d: d["events"][0].update(timestamp_epoch_ms=receiver.EPOCH_MS + 1)):
            changed = deepcopy(document); mutation(changed)
            value = checker.GmailSdkCheck.__new__(checker.GmailSdkCheck)
            calls = []
            value.settled_audit = lambda: []
            value.client = lambda *args: calls.append("client")
            value.observe = lambda *args, **kwargs: changed
            value.audit = lambda: self.fail("bad provider evidence must stop before polling audit")
            with self.assertRaises(checker.CheckFailure):
                value.deny("wrong_app", {"id": uid(3)}, "synthetic-token", document)
            self.assertEqual(calls, ["client"])
        # A publication refusal is permitted only in the explicit revoke/reload
        # gap, never inside any of the unchanged SDK denial observations.
        for phase, status, reason in ((phase, status, reason) for phase in PHASES[2:] for status, reason in (
                (503, "active signed policy bundle is unavailable"), (409, "data-plane policy hash is not active"))):
            value = checker.GmailSdkCheck.__new__(checker.GmailSdkCheck)
            value.settled_audit = lambda: []
            value.client = lambda *args: None
            value.observe = lambda *args, **kwargs: deepcopy(document)
            rejection = publication_rows(self.wire)[-2]
            rejection["event"].update(status_code=status, reason=reason)
            value.audit = lambda: [rejection]
            value.audit_drained = lambda: self.fail("rejected lease must stop before further audit polling")
            with self.subTest(phase=phase, status=status), self.assertRaises(checker.CheckFailure):
                value.deny(phase, {"id": uid(3)}, "synthetic-token", document)
            value.audit = lambda: [grant_failure_rows(self.wire)[2]]
            with self.subTest(phase=phase, reload_failure=True), self.assertRaises(checker.CheckFailure):
                value.deny(phase, {"id": uid(3)}, "synthetic-token", document)

    def test_process_results_are_exact_and_errors_never_accept_arbitrary_output(self):
        for phase in PHASES:
            positive = phase in {"first", "refreshed"}
            self.assertEqual(checker.validate_client_result(phase, 0 if positive else 1,
                SUCCESS if positive else b"", b"" if positive else DENIAL),
                {"phase": phase, "exitCode": 0 if positive else 1,
                 "summary": {"pages": 2, "messages_read": 2, "more_pages": False} if positive else None})
        for phase, code, out, err in (("first", True, SUCCESS, b""), ("first", 0, SUCCESS.rstrip(), b""),
                ("first", 0, SUCCESS.replace(b'false', b'true'), b""), ("first", 0, SUCCESS, b"secret-canary"),
                ("wrong_app", 0, b"", DENIAL), ("wrong_app", 2, b"", DENIAL),
                ("wrong_app", 1, b"secret-canary", DENIAL), ("revoked", 1, b"", b"secret-canary")):
            with self.assertRaises(checker.CheckFailure) as caught:
                checker.validate_client_result(phase, code, out, err)
            self.assertNotIn("secret-canary", str(caught.exception))

    def test_clean_environment_keeps_basic_proxy_and_distinct_negative_trust_inputs(self):
        with patch.dict(os.environ, {"HTTPS_PROXY": "secret-canary", "GOOGLE_APPLICATION_CREDENTIALS": "secret-canary",
                "SSL_CERT_FILE": "secret-canary", "GODEBUG": "secret-canary"}):
            normal = checker.client_environment(uid(2), "a" * 43, "first")
        self.assertEqual(normal, {"LANG": "C.UTF-8", "SERVERWARE_PROXY_URL": "https://proxy.operator-basic.example.test:8443",
            "SERVERWARE_APP_ID": uid(2), "SERVERWARE_PROXY_TOKEN": "a" * 43,
            "SERVERWARE_CA_FILE": "/client-trust/inner-ca.pem", "SERVERWARE_PROXY_CA_FILE": "/client-trust/outer-ca.pem"})
        self.assertNotIn("secret-canary", str(normal))
        outer = checker.client_environment(uid(2), "a" * 43, "wrong_outer_ca")
        inner = checker.client_environment(uid(2), "a" * 43, "wrong_inner_ca")
        self.assertEqual((outer["SERVERWARE_CA_FILE"], outer["SERVERWARE_PROXY_CA_FILE"]),
            ("/client-trust/outer-ca.pem", "/client-trust/inner-ca.pem"))
        self.assertEqual((inner["SERVERWARE_CA_FILE"], inner["SERVERWARE_PROXY_CA_FILE"]),
            ("/client-trust/outer-ca.pem", "/client-trust/combined-ca.pem"))

    def test_closed_success_receipt_rejects_changed_claims_counts_pins_and_evidence(self):
        good = success_result(self.wire)
        self.assertTrue(checker.validate_success_result(good))
        reconciled = deepcopy(good)
        reconciled["reconciliationRejections"] = 1
        reconciled["namedAuditInventory"][REJECTED] = 1
        self.assertTrue(checker.validate_success_result(reconciled))
        publication = deepcopy(reconciled)
        publication["revocationPublicationRejections"] = 1
        publication["namedAuditInventory"][REJECTED] = 2
        self.assertTrue(checker.validate_success_result(publication))
        grant = deepcopy(publication)
        grant["grantPublicationReloadFailures"] = 1
        grant["namedAuditInventory"][checker.RELOAD_FAILED] = 1
        self.assertTrue(checker.validate_success_result(grant))
        for replacement in (True, -1, 2, 0):
            value = deepcopy(grant); value["grantPublicationReloadFailures"] = replacement
            with self.subTest(grant_count=replacement), self.assertRaises(checker.CheckFailure):
                checker.validate_success_result(value)
        for mutation in (lambda v: v["namedAuditInventory"].update({checker.RELOAD_FAILED: 2}),
                lambda v: v["namedAuditInventory"].pop(checker.RELOAD_FAILED),
                lambda v: v["namedAuditInventory"].update({checker.RELOAD: 3})):
            value = deepcopy(grant); mutation(value)
            with self.assertRaises(checker.CheckFailure): checker.validate_success_result(value)
        for field, replacement in (("revocationPublicationRejections", True), ("revocationPublicationRejections", 2),
                ("revocationPublicationRejections", -1), ("revocationPublicationRejections", 0),
                ("reconciliationRejections", 0)):
            value = deepcopy(publication); value[field] = replacement
            with self.subTest(field=field, replacement=replacement), self.assertRaises(checker.CheckFailure):
                checker.validate_success_result(value)
        value = deepcopy(publication); value["namedAuditInventory"][REJECTED] = 3
        with self.assertRaises(checker.CheckFailure): checker.validate_success_result(value)
        for mutation in (lambda v: v.update(reconciliationRejections=0),
                lambda v: v["namedAuditInventory"].pop(REJECTED),
                lambda v: v["namedAuditInventory"].update({REJECTED: 2}),
                lambda v: v["namedAuditInventory"].update({REJECTED: True}),
                lambda v: v["negativeControls"][2].update(auditEventType=REJECTED)):
            value = deepcopy(reconciled); mutation(value)
            with self.assertRaises(checker.CheckFailure):
                checker.validate_success_result(value)
        changes = (lambda v: v.update(secret="secret-canary"), lambda v: v.pop("auditChainVerified"),
            lambda v: v.update(ok=1), lambda v: v.update(productionReady=True), lambda v: v.update(realGoogleVerified=True),
            lambda v: v.pop("reconciliationRejections"), lambda v: v.update(reconciliationRejections=True),
            lambda v: v.pop("revocationPublicationRejections"), lambda v: v.update(revocationPublicationRejections=1),
            lambda v: v.pop("grantPublicationReloadFailures"), lambda v: v.update(grantPublicationReloadFailures=1),
            lambda v: v.update(reconciliationRejections=-1), lambda v: v.update(reconciliationRejections=2),
            lambda v: v.update(reconciliationRejections=1), lambda v: v["namedAuditInventory"].update({REJECTED: 1}),
            lambda v: v.update(automaticRefreshes=True), lambda v: v.update(providerAttempts=9),
            lambda v: v.update(revokedPolicyHash=v["policyHash"]), lambda v: v.update(goExampleSha256=sha(9)),
            lambda v: v["exampleSourceSha256"].pop("examples/google-gmail-go/go.sum"),
            lambda v: v["policyRevisions"].update(revoked=7), lambda v: v.update(refreshCompletedAtExpiry=0),
            lambda v: v["providerObservations"][3].update(initialAccessExpired=False),
            lambda v: v["providerObservations"][4]["resourceGenerations"].__setitem__(4, 1),
            lambda v: v["completed"][0]["summary"].update(pages=True),
            lambda v: v["negativeControls"][0].update(providerAttemptsAfter=9),
            lambda v: v["negativeControls"][1].update(auditEventType=DENIED),
            lambda v: v["negativeControls"][1].update(auditEventId=uid(999)),
            lambda v: v["generationAuditEventIds"].pop(), lambda v: v["durableAuditEventIds"].pop(),
            lambda v: v["durableAuditEventIds"].__setitem__(4, uid(999)),
            lambda v: v["generationAuditEventIds"].__setitem__(2, uid(999)),
            lambda v: v["auditAttemptIds"].__setitem__(1, v["auditAttemptIds"][0]),
            lambda v: v["namedAuditInventory"].update({RELEASE: 7}),
            lambda v: v["namedAuditInventory"].update({LEASE: 0}))
        for index, change in enumerate(changes):
            value = deepcopy(good); change(value)
            with self.subTest(case=index), self.assertRaises(checker.CheckFailure) as caught:
                checker.validate_success_result(value)
            self.assertNotIn("secret-canary", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
