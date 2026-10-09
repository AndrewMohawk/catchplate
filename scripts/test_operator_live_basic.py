#!/usr/bin/env python3
"""Memory-only tests of the live Basic audit oracle, not HTTP acceptance.

No client, fixture, catalog, clock, filesystem or network action is exercised.
The synthetic rows deliberately represent evidence inputs, not real receipts.
"""
from copy import deepcopy
import unittest

from scripts import check_operator_live_basic as checker


smoke = checker.smoke
POLICY = "sha256:" + "a" * 64
SCOPE = ("agent:synthetic-basic", "route-synthetic-basic", POLICY)
CREDENTIAL = "12345678-1234-4234-8234-123456789abc"


def fixture():
    positives, rows = [], []
    for index in range(2):
        positive = {"requestDigest": "sha256:" + str(index + 1) * 64,
                    "operationDigest": "sha256:" + str(index + 3) * 64,
                    "responseBodySha256": "sha256:" + str(index + 7) * 64,
                    "responseBodyBytes": 137 + index}
        positives.append(positive)
        attempt = "sha256:" + str(index + 5) * 64
        request = dict(zip(("principal_id", "route_id", "policy_hash"), SCOPE),
            method="POST", body_sha256=smoke.sha(smoke.BODY), credential_ref=CREDENTIAL,
            credential_version=1, request_digest=positive["requestDigest"],
            operation_digest=positive["operationDigest"], attempt_id=attempt, flow_id=attempt)
        rows.extend([
            {"id": "connect-" + str(index), "event_type": smoke.CONNECT, "event": {
                "principal_id": SCOPE[0], "policy_hash": POLICY, "method": "CONNECT",
                "target": smoke.AUTHORITY, "outcome": "established"}},
            {"id": "start-" + str(index), "event_type": smoke.START,
             "event": {**request, "outcome": "release_started"}},
            {"id": "release-" + str(index), "event_type": smoke.RELEASE, "event": {
                **request, "outcome": "released", "upstream_status": 200,
                "response_body_sha256": positive["responseBodySha256"],
                "response_body_bytes": positive["responseBodyBytes"], "response_validation": {
                    "ok": True, "mode": smoke.RESPONSE_VALIDATION_MODE, "body_bytes_preserved": True}}},
        ])
    rows.append({"id": "lease-0", "event_type": smoke.LEASE, "event": {
        **dict(zip(("principal_id", "route_id", "policy_hash"), SCOPE)),
        "credential_id": CREDENTIAL, "data_plane_binary_digest": checker.PIN,
        "purpose": "dispatchSecret", "expected_credential_version": 1,
        "outcome": "issued", "status_code": 200}})
    return rows, positives


def event(rows, kind, index=0):
    return [row["event"] for row in rows if row["event_type"] == kind][index]


class LiveBasicReleasePairsTests(unittest.TestCase):
    def evaluate(self, rows, positives):
        return checker.release_pairs(rows, SCOPE, CREDENTIAL, positives)

    def rejected(self, rows, positives):
        with self.assertRaises(smoke.CheckFailure):
            self.evaluate(rows, positives)

    def test_two_distinct_complete_pairs_join_wire_and_generation(self):
        rows, positives = fixture()
        complete, counts, retained, attempts = self.evaluate(rows, positives)
        self.assertTrue(complete)
        self.assertEqual(dict(counts), {smoke.CONNECT: 2, smoke.START: 2, smoke.RELEASE: 2, smoke.LEASE: 1})
        self.assertEqual(retained, [row["id"] for row in rows])
        self.assertEqual(attempts, ["sha256:" + digit * 64 for digit in ("5", "6")])
        # Either one cached issuance or two independently issued leases may
        # support these same two requests; lease events are not dispatches.
        additional = deepcopy(rows[-1])
        additional["id"] = "lease-1"
        self.assertTrue(self.evaluate(rows + [additional], positives)[0])
        self.assertTrue(self.evaluate(list(reversed(rows)), positives)[0])

    def test_empty_and_incomplete_evidence_never_complete(self):
        rows, positives = fixture()
        complete, counts, retained, attempts = self.evaluate([], positives)
        self.assertFalse(complete)
        self.assertFalse(any(counts.values()))
        self.assertEqual((retained, attempts), ([], []))
        for missing in ("connect-0", "start-0", "release-0", "lease-0"):
            with self.subTest(missing=missing):
                self.assertFalse(self.evaluate([row for row in rows if row["id"] != missing], positives)[0])
        for kind in (smoke.START, smoke.RELEASE):
            with self.subTest(only=kind):
                self.assertFalse(self.evaluate([row for row in rows if row["event_type"] == kind], positives)[0])

    def test_duplicate_or_crossed_wire_commitments_refused(self):
        rows, positives = fixture()
        self.rejected(rows, [positives[0], deepcopy(positives[0])])
        for field, other in (("request_digest", "sha256:" + "b" * 64),
                             ("operation_digest", "sha256:" + "c" * 64)):
            changed = deepcopy(rows)
            event(changed, smoke.RELEASE)[field] = other
            with self.subTest(field=field):
                self.rejected(changed, positives)
        changed = deepcopy(rows)
        event(changed, smoke.RELEASE, 1).update(request_digest=positives[0]["requestDigest"],
                                             operation_digest=positives[0]["operationDigest"])
        self.rejected(changed, positives)

    def test_credential_generation_and_binary_bindings_refused_when_wrong(self):
        rows, positives = fixture()
        changes = [(kind, "credential_ref", "other-credential") for kind in (smoke.START, smoke.RELEASE)]
        changes += [(kind, "credential_version", version)
                    for kind in (smoke.START, smoke.RELEASE) for version in (None, True, 1.0, 2)]
        changes += [(smoke.LEASE, "credential_id", "other-credential"),
                    (smoke.LEASE, "data_plane_binary_digest", "sha256:" + "f" * 64)]
        changes += [(smoke.LEASE, "expected_credential_version", version) for version in (None, True, 1.0, 2)]
        for kind, field, value in changes:
            changed = deepcopy(rows)
            event(changed, kind)[field] = value
            with self.subTest(kind=kind, field=field, value=value):
                self.rejected(changed, positives)

    def test_request_and_response_body_evidence_refused_when_wrong(self):
        rows, positives = fixture()
        for kind in (smoke.START, smoke.RELEASE):
            changed = deepcopy(rows)
            event(changed, kind)["body_sha256"] = "sha256:" + "f" * 64
            with self.subTest(request_body=kind):
                self.rejected(changed, positives)
        for field, value in (("response_body_sha256", "sha256:" + "f" * 64),
                             ("response_body_bytes", 999), ("upstream_status", 204), ("outcome", "blocked")):
            changed = deepcopy(rows)
            event(changed, smoke.RELEASE)[field] = value
            with self.subTest(response_field=field):
                self.rejected(changed, positives)
        for field, value in (("ok", False), ("mode", "bufferedJsonOrEmpty204V1"), ("body_bytes_preserved", False)):
            changed = deepcopy(rows)
            event(changed, smoke.RELEASE)["response_validation"][field] = value
            with self.subTest(validation=field):
                self.rejected(changed, positives)

    def test_attempt_reuse_repeated_slot_and_flow_mismatch_refused(self):
        rows, positives = fixture()
        reused = deepcopy(rows)
        first = event(reused, smoke.START)["attempt_id"]
        for kind in (smoke.START, smoke.RELEASE):
            event(reused, kind, 1).update(attempt_id=first, flow_id=first)
        self.rejected(reused, positives)
        for kind in (smoke.START, smoke.RELEASE):
            duplicate = deepcopy(next(row for row in rows if row["event_type"] == kind))
            duplicate["id"] = "repeated-slot"
            with self.subTest(duplicate=kind):
                self.rejected(rows + [duplicate], positives)
        for field, value in (("attempt_id", "not-a-digest"), ("flow_id", "sha256:" + "f" * 64)):
            changed = deepcopy(rows)
            event(changed, smoke.START)[field] = value
            with self.subTest(field=field):
                self.rejected(changed, positives)

    def test_extra_connect_scoped_event_and_lease_budgets_refused(self):
        rows, positives = fixture()
        extra = deepcopy(rows[0])
        extra["id"] = "extra-connect"
        self.rejected(rows + [extra], positives)
        for kind in (smoke.BLOCK, smoke.DENIED, "data_plane.unexpected"):
            changed = deepcopy(rows)
            changed[1]["event_type"] = kind
            with self.subTest(kind=kind):
                self.rejected(changed, positives)
        leases = []
        for index in range(4):
            extra = deepcopy(rows[-1])
            extra["id"] = "extra-lease-" + str(index)
            leases.append(extra)
        self.rejected(rows + leases[:2], positives)  # Third dispatch issuance.
        for row in leases:
            row["event"]["purpose"] = "generationMetadata"
        self.assertTrue(self.evaluate(rows + leases[:3], positives)[0])
        self.rejected(rows + leases, positives)  # Fifth total lease event.

    def test_partial_scope_matches_cannot_bypass_exact_identity(self):
        rows, positives = fixture()
        for kind, field, value in ((smoke.START, "principal_id", "other-principal"),
                                  (smoke.RELEASE, "route_id", "other-route"),
                                  (smoke.LEASE, "policy_hash", "sha256:" + "f" * 64),
                                  (smoke.CONNECT, "target", "other.example:443")):
            changed = deepcopy(rows)
            event(changed, kind)[field] = value
            with self.subTest(kind=kind, field=field):
                self.rejected(changed, positives)


if __name__ == "__main__":
    unittest.main()
