"""Synthetic checker controls, not SDK, Docker, or provider acceptance."""
from copy import deepcopy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import check_operator_github_app_examples as checker
from scripts.check_operator_ordinary_client import START, RELEASE, LEASE
from scripts.check_operator_github import CONNECT_DENIED

SCOPE = ("principal", "route", "sha256:" + "c" * 64)
WIRE = {"requestDigest": "sha256:" + "d" * 64, "operationDigest": "sha256:" + "e" * 64,
    "responseBodySha256": "sha256:" + "f" * 64, "responseBodyBytes": 10}


def pair(number):
    attempt = "sha256:" + format(number, "064x")
    common = dict(zip(("principal_id", "route_id", "policy_hash"), SCOPE))
    common.update(attempt_id=attempt, flow_id=attempt, credential_ref="credential", credential_version=1,
        method="GET", body_sha256=checker.digest(b""), request_digest=WIRE["requestDigest"], operation_digest=WIRE["operationDigest"])
    return [{"id": "start-" + str(number), "event_type": START, "event": {**common, "outcome": "release_started"}},
        {"id": "release-" + str(number), "event_type": RELEASE, "event": {**common, "outcome": "released",
            "upstream_status": 200, "response_body_sha256": WIRE["responseBodySha256"], "response_body_bytes": 10,
            "response_validation": {"ok": True, "body_bytes_preserved": True, "mode": "bufferedJsonOrEmpty204V2"}}}]


def success():
    completed = [{"client": c, "phase": "read_initial", "exitCode": 0} for c in checker.fixture.examples.CLIENTS]
    completed += [{"client": c, "phase": p, "exitCode": 1} for c in checker.fixture.examples.CLIENTS for p in ("wrong_app", "wrong_repo")]
    completed += [{"client": c, "phase": "read_renewed", "exitCode": 0} for c in checker.fixture.examples.CLIENTS]
    completed += [{"client": c, "phase": "revoked", "exitCode": 1} for c in checker.fixture.examples.CLIENTS]
    return {"schema": checker.SCHEMA, "ok": True, "syntheticOnly": True, "actualExampleEntrypoints": True,
        "realGithubVerified": False, "productionReady": False, "storedGenerationUnchanged": True,
        "providerAttempts": 12, "provisioningAttempts": 6, "releases": 12, "deniedBeforeDispatch": 9,
        "auditAttemptIds": ["sha256:" + format(n, "064x") for n in range(12)], "dispatchLeaseIds": ["one", "two"],
        "completed": completed, "dataPlaneBinaryDigest": "sha256:" + "1" * 64, "goExampleSha256": "2" * 64,
        "exampleSourceSha256": {k: "3" * 64 for k in checker.stock.SOURCE_FILES},
        "pythonTrust": "client-only-union-not-independent-roots", "namedAuditInventory": {START: 12, RELEASE: 12},
        "mints": [{"issuedAt": 1000, "expiresAt": 1120}, {"issuedAt": 1122, "expiresAt": 4722}]}


class CheckerTests(unittest.TestCase):
    def setUp(self):
        for name in ("socket.socket", "socket.create_connection", "socket.getaddrinfo", "subprocess.Popen"):
            self.enterContext(patch(name, side_effect=AssertionError("inert test attempted runtime I/O")))

    def test_repeated_canonical_commitments_need_distinct_complete_attempts(self):
        rows = pair(1) + pair(2)
        result = checker.match_pairs(rows, [WIRE, WIRE], SCOPE, "credential")
        self.assertEqual(len(result), 2)
        self.assertNotEqual(result[0]["attemptId"], result[1]["attemptId"])
        self.assertIsNone(checker.match_pairs(rows[:-1], [WIRE, WIRE], SCOPE, "credential"))
        for bad in (pair(1) + pair(1), rows + pair(3), rows + [rows[0]]):
            with self.assertRaises(checker.CheckFailure): checker.match_pairs(bad, [WIRE, WIRE], SCOPE, "credential")

    def test_same_status_cannot_substitute_scope_generation_body_or_response_guard(self):
        for field, value in (("principal_id", "other"), ("policy_hash", "sha256:" + "0" * 64),
                ("credential_version", True), ("credential_ref", "other"), ("body_sha256", "different"),
                ("request_digest", "different"), ("operation_digest", "different"), ("upstream_status", 404),
                ("response_body_sha256", "different"), ("response_body_bytes", 11), ("flow_id", "different"),
                ("response_validation", {"ok": True, "body_bytes_preserved": False, "mode": "bufferedJsonOrEmpty204V2"})):
            rows = pair(1); rows[1]["event"][field] = value
            with self.subTest(field=field), self.assertRaises(checker.CheckFailure):
                checker.match_pairs(rows, [WIRE], SCOPE, "credential")
        rows = pair(1)[:1]; rows[0]["event"]["request_digest"] = "unrecognized"
        with self.assertRaises(checker.CheckFailure): checker.match_pairs(rows, [WIRE], SCOPE, "credential")

    def test_expiry_wait_is_original_wall_bound_read_only_and_deadline_limited(self):
        check = object.__new__(checker.AppExamplesCheck)
        first = {"mints": [{"expiresAt": 102}], "attempts": [None] * 6}
        check.observe, check.timeout = Mock(return_value=first), Mock(return_value=0.5)
        with patch.object(checker.time, "time", side_effect=[101, 103, 104]), patch.object(checker.time, "sleep") as sleep:
            check.wait_original_expiry()
        self.assertEqual(check.current_phase, "expiry_wait")
        self.assertEqual(sleep.call_args_list, [unittest.mock.call(0.5), unittest.mock.call(0.5)])
        self.assertEqual(check.observe.call_count, 3)
        error = checker.CheckFailure("synthetic fixed deadline")
        check.timeout.side_effect = error
        with patch.object(checker.time, "time", return_value=101), self.assertRaises(checker.CheckFailure) as caught:
            check.wait_original_expiry()
        self.assertIs(caught.exception, error)
        check.timeout.side_effect = None
        check.observe.side_effect = [first, {**first, "mints": [{"expiresAt": 500}]}]
        with patch.object(checker.time, "time", return_value=101), self.assertRaises(checker.CheckFailure): check.wait_original_expiry()

    def test_negative_requires_no_provider_change_no_dispatch_and_one_denial(self):
        for bad in ("none", "provider", "lease", "release", "duplicate"):
            check = object.__new__(checker.AppExamplesCheck)
            denial = {"id": "denial", "event_type": CONNECT_DENIED, "event": {"outcome": "denied", "method": "CONNECT",
                "target": "api.github.com:443", "principal_id": None}}
            rows = [denial]
            if bad == "lease": rows += [{"id": "lease", "event_type": LEASE, "event": {"purpose": "dispatchSecret"}}]
            if bad == "release": rows += pair(1)
            if bad == "duplicate": rows += [{**denial, "id": "denial2"}]
            check.audit = Mock(side_effect=[[], rows])
            check.observe = Mock(side_effect=[{"total": 3}, {"total": 4 if bad == "provider" else 3}])
            check.example, check.audit_drained = Mock(), Mock(return_value=True)
            with patch.object(checker.features, "audit_cutoff", side_effect=lambda rows: {r["id"]: r for r in rows}):
                if bad == "none": check.negative("node", "wrong_app", {"id": "unassigned"}, "synthetic")
                else:
                    with self.assertRaises(checker.CheckFailure): check.negative("node", "wrong_app", {"id": "unassigned"}, "synthetic")
            self.assertEqual(check.example.call_count, 1)

    def test_real_example_invocation_failure_is_not_retried_or_added_to_completed(self):
        check = object.__new__(checker.AppExamplesCheck)
        check.deadline, check.completed, check.clean = 100, [], Mock()
        with patch.object(checker.time, "monotonic", return_value=80), \
                patch.object(checker.stock, "run_example", return_value=(1, b"", b"")) as run, self.assertRaises(checker.CheckFailure):
            check.example("node", "read_initial", {"id": "app"}, "synthetic")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(check.completed, [])
        self.assertEqual(check.current_phase, "read_initial")

    def test_clean_refuses_public_observation_of_private_material(self):
        check = object.__new__(checker.AppExamplesCheck)
        check.app_pem = "-----BEGIN PRIVATE KEY-----\nsynthetic-private-key-line\n-----END PRIVATE KEY-----"
        with patch.object(checker.stock.ExamplesCheck, "clean", return_value=None):
            check.clean(b'{"safe":true}')
            for raw in (*checker.fixture.TOKENS, check.app_pem, "synthetic-private-key-line"):
                with self.assertRaises(checker.CheckFailure): check.clean(raw.encode())

    def test_terminal_success_requires_both_cycles_and_original_expiry(self):
        value = success(); checker.validate_success_result(value)
        for kind in ("extra", "count", "phase", "retry", "early", "attempt", "claim"):
            changed = deepcopy(value)
            if kind == "extra": changed["extra"] = True
            elif kind == "count": changed["providerAttempts"] = 13
            elif kind == "phase": changed["completed"].pop()
            elif kind == "retry": changed["completed"].append(changed["completed"][0])
            elif kind == "early": changed["mints"][1]["issuedAt"] = changed["mints"][0]["expiresAt"]
            elif kind == "attempt": changed["auditAttemptIds"][1] = changed["auditAttemptIds"][0]
            else: changed["realGithubVerified"] = True
            with self.subTest(kind=kind), self.assertRaises(checker.CheckFailure): checker.validate_success_result(changed)


if __name__ == "__main__":
    unittest.main()
