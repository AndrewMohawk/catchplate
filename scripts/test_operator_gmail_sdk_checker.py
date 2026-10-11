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
PHASES = ("first", "refreshed", "wrong_outer_ca", "wrong_inner_ca", "wrong_app", "revoked")
START, RELEASE = "data_plane.credential.release_started", "data_plane.response.released"
CONNECT, DENIED = "data_plane.connect.established", "data_plane.connect.denied"
LEASE = "data_plane.credential_lease.issued"
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
                "x-goog-api-client": "gl-go/1.23.12 gdcl/0.230.0"},
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
        "refreshedCredentialVersion": 2, "canonicalRequestVersion": 3,
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
        actual = checker.generation_evidence(rows, SCOPE, CREDENTIAL, self.wire)
        self.assertEqual((actual["initialCredentialVersion"], actual["refreshedCredentialVersion"],
            actual["canonicalRequestVersion"]), (1, 2, 3))
        self.assertEqual(set(actual["generationAuditEventIds"]),
            {rows[index]["id"] for index in (0, 1, 2, 4, 6, 8, 10, 12, 14, 16)})
        self.assertEqual(rows[-1]["event_type"], LEASE)
        self.assertEqual(rows[-1]["id"], uid(118))
        self.assertNotIn(rows[-1]["id"], actual["generationAuditEventIds"])
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
                checker.generation_evidence(value, SCOPE, CREDENTIAL, self.wire)
        for field, replacement in (("generation", True), ("requestDigest", self.wire[0]["requestDigest"]),
                ("responseBodySha256", sha(999))):
            value = deepcopy(self.wire); value[1][field] = replacement
            with self.assertRaises(checker.CheckFailure):
                checker.generation_evidence(rows, SCOPE, CREDENTIAL, value)

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
        changes = (lambda v: v.update(secret="secret-canary"), lambda v: v.pop("auditChainVerified"),
            lambda v: v.update(ok=1), lambda v: v.update(productionReady=True), lambda v: v.update(realGoogleVerified=True),
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
