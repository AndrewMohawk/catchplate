#!/usr/bin/env python3
"""Pure checker-oracle tests with synthetic records and mocked I/O only.

No sockets, TLS peers, catalog service, provider, process or fixture is used.
The in-memory HTTP parser controls do not establish real proxy acceptance.
"""
from collections import Counter
from copy import deepcopy
import http.client
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

try:
    from scripts import check_operator_ordinary_client as checker
except ModuleNotFoundError:
    import check_operator_ordinary_client as checker


def sha(number):
    return "sha256:" + format(number, "064x")


POLICY, INITIAL = sha(10), sha(9)
SCOPE = ("synthetic-principal", "synthetic-route", POLICY)
LEASE_SCOPE = dict(zip(("principal_id", "route_id", "policy_hash"), SCOPE),
                   purpose="dispatchSecret", credential_id="synthetic-credential",
                   data_plane_binary_digest=sha(11))


def response(case):
    status = 200 if case == "json" else 204
    body = checker.JSON_RESPONSE_BODY if case == "json" else b""
    headers = [("Content-Type", "application/json" if case == "json" else checker.EMPTY_RESPONSE_CONTENT_TYPE),
               ("X-Serverware-Policy-Hash", POLICY),
               ("X-Serverware-Response-Body-SHA256", checker.digest(body)),
               ("X-Serverware-Request-Digest", sha(status)),
               ("X-Serverware-Operation-Digest", sha(status + 1000))]
    if case == "json":
        headers.append(("Content-Length", str(len(body))))
    return status, headers, body


def wire(status, headers, body):
    return (f"HTTP/1.1 {status} Synthetic\r\n" + "".join(
        f"{name}: {value}\r\n" for name, value in headers) + "\r\n").encode("ascii") + body


def check(case, status, headers, body, captured=None):
    return checker.check_response(case, status, headers, body,
                                  wire(status, headers, body) if captured is None else captured, POLICY)


def lifecycle_rows():
    rows = []
    for index, case in enumerate(("json", "empty")):
        status, _, body = response(case)
        event = dict(zip(("principal_id", "route_id", "policy_hash"), SCOPE), method="POST",
                     body_sha256="sha256:" + checker.REQUEST_BODY_SHA256,
                     attempt_id=sha(index + 1), flow_id=sha(index + 1),
                     request_digest=sha(status), operation_digest=sha(status + 1000))
        rows.extend([
            {"id": f"start-{index}", "event_type": checker.START,
             "event": {**event, "outcome": "release_started"}},
            {"id": f"terminal-{index}", "event_type": checker.RELEASE,
             "event": {**event, "outcome": "released", "upstream_status": status,
                       "response_body_sha256": checker.digest(body), "response_body_bytes": len(body),
                       "response_validation": {"ok": True, "mode": "bufferedJsonOrEmpty204V1",
                                               "body_bytes_preserved": True}}},
        ])
    return rows


def audit_fixture():
    """Only I/O is replaced; the actual complete audit verifier executes."""
    value = checker.OrdinaryClientCheck.__new__(checker.OrdinaryClientCheck)
    value.initial_policy_hash, value.active_sequence = INITIAL, 2
    value.feature_observations = [check(case, *response(case)) for case in ("json", "empty")]
    value.negative_observations = []
    value.mutations = [("operator_catalog." + kind + ".created", kind, POLICY)
                       for kind in ("credential", "application", "access_rule")]
    rows = lifecycle_rows()
    for number in range(4):
        rows.append({"id": "connect-" + str(number), "event_type": checker.CONNECT,
                     "event": {"principal_id": SCOPE[0], "policy_hash": POLICY, "method": "CONNECT",
                               "target": checker.AUTHORITY, "outcome": "established"}})
    for case, reason in checker.ERRORS.items():
        rows.append({"id": case, "event_type": checker.DENIED, "event": {
            "route_id": SCOPE[1], "method": "POST", "outcome": "denied", "error": reason}})
    for kind, identifier, policy in value.mutations:
        rows.append({"id": identifier, "event_type": kind,
                     "event": {"resource_id": identifier, "policy_hash": policy}})
    rows.append({"id": "lease", "event_type": checker.LEASE,
                 "event": {**LEASE_SCOPE, "outcome": "issued", "status_code": 200}})
    rows.append({"id": "reload", "event_type": checker.RELOAD, "event": {
        "policy_hash": POLICY, "previous_policy_hash": INITIAL, "policy_sequence": 2, "routes": 1}})
    for number, row in enumerate(rows):
        row["event_hash"] = sha(number + 100)
    value.audit = lambda: deepcopy(rows)
    value.health = lambda: {"audit": {key: 0 for key in checker.ZERO_COUNTERS + checker.DRAIN_COUNTERS}}
    value.control_json = lambda *args, **kwargs: {"ok": True, "complete": True, "backend": "sqlite"}
    value.timeout = lambda: (_ for _ in ()).throw(checker.CheckFailure("synthetic no-poll deadline"))
    return value, rows


class BeforeFinalAudit(Exception):
    pass


def ordering_fixture(drift_case=None):
    """Mock setup/network only; run() owns actual case order and count guards."""
    value = checker.OrdinaryClientCheck.__new__(checker.OrdinaryClientCheck)
    value.args = SimpleNamespace(admin_token_file=None, expected_binary_sha256=sha(11))
    value.run_id, value.credential = "synthetic-run", "synthetic-provider"
    value.results, value.feature_observations, value.mutations = [], [], []
    value.health, value.audit_drained, value.audit = lambda: {}, lambda: True, lambda: []
    rows = {name: [] for name in checker.COLLECTIONS}
    initial = {**deepcopy(rows), "revision": 1, "policy": {"policy_hash": INITIAL, "sequence": 1},
               "limits": {name: {"retained": 0} for name in rows}}
    value.catalog = lambda: deepcopy(initial)
    trace, counts, dispatched = [], [], [0]

    def mutate(route, payload, **kwargs):
        row = {**payload, "id": kwargs["result_key"], "version": 1, "status": "active"}
        row.update(principal_id=SCOPE[0], route_id=SCOPE[1])
        rows[kwargs["collection"]].append(row)
        value.policy_hash = POLICY
        return row, "synthetic-client-token" if kwargs.get("token") else None, {}

    def loaded(label):
        if label == "empty_catalog_loaded":
            return deepcopy(initial), {}
        return {**deepcopy(rows), "revision": 4, "policy": {"sequence": 2, "policy_hash": POLICY}}, {}

    def count():
        counts.append(dispatched[0])
        return dispatched[0]

    def dispatch(case, placeholder):
        trace.append((case, placeholder))
        dispatched[0] += int(case not in checker.ERRORS) + int(case == drift_case)
        return {"case": case, "status": dict((item[0], item[2]) for item in checker.CASES)[case]}

    def final_audit(*args):
        raise BeforeFinalAudit()

    value.mutate, value.wait_catalog_loaded, value.count = mutate, loaded, count
    value.current = lambda pins: trace.append("current")
    value.dispatch, value.verify_ordinary_audit = dispatch, final_audit
    return value, trace, counts


class OrdinaryCheckerTests(unittest.TestCase):
    def test_json_exact_bytes_and_wire_commitments(self):
        status, headers, body = response("json")
        observed = check("json", status, headers, body)
        self.assertEqual((observed["requestDigest"], observed["operationDigest"]), (sha(200), sha(1200)))
        changed = json.dumps(json.loads(body), separators=(",", ":")).encode("ascii")
        self.assertNotEqual(changed, body)
        self.assertEqual(json.loads(changed), json.loads(body))
        for change in (changed, body + b" ", b""):
            with self.subTest(body_length=len(change)), self.assertRaises(checker.CheckFailure):
                check("json", status, headers, change)
        for key, replacement in (("X-Serverware-Policy-Hash", sha(99)),
                                 ("X-Serverware-Response-Body-SHA256", sha(99)),
                                 ("X-Serverware-Request-Digest", "missing")):
            with self.subTest(header=key), self.assertRaises(checker.CheckFailure):
                check("json", status, [(name, replacement if name == key else val) for name, val in headers], body)

    def test_empty204_physical_framing_and_prefetched_or_later_bytes(self):
        status, headers, body = response("empty")
        self.assertEqual(check("empty", status, headers, body)["responseBodyBytes"], 0)
        for extra in (("Content-Length", "0"), ("Content-Length", "1"), ("Transfer-Encoding", "chunked"),
                      ("Trailer", "Digest"), ("Content-Type", checker.EMPTY_RESPONSE_CONTENT_TYPE)):
            with self.subTest(extra=extra), self.assertRaises(checker.CheckFailure):
                check("empty", status, headers + [extra], body)
        for chunks in ([wire(status, headers, b"hidden")], [wire(status, headers, b""), b"hidden"]):
            class MemoryTLS:
                def __init__(self):
                    self.parts = [io.BytesIO(part) for part in chunks]

                def readinto(self, buffer):
                    while self.parts:
                        size = self.parts[0].readinto(buffer)
                        if size:
                            return size
                        self.parts.pop(0)
                    return 0

            capture = checker.CapturedTLS(MemoryTLS())
            parsed = http.client.HTTPResponse(capture)
            try:
                parsed.begin()
                self.assertEqual(parsed.read(), b"", "stdlib suppresses the illegal 204 body")
                captured = capture.finish()
                self.assertTrue(captured.endswith(b"hidden"))
                with self.subTest(chunks=len(chunks)), self.assertRaises(checker.CheckFailure):
                    check("empty", parsed.status, parsed.getheaders(), b"", captured)
            finally:
                parsed.close()

    def test_denial_requires_exact_placeholder_guard(self):
        for case, error in checker.ERRORS.items():
            document = {"allowed": False, "action": "deny", "payload": {"error": error}}
            body = json.dumps(document).encode("ascii")
            headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
            self.assertEqual(check(case, 403, headers, body)["status"], 403)
            for status, reason in ((200, error), (403, "unrelated_denial")):
                bad = json.dumps({**document, "payload": {"error": reason}}).encode("ascii")
                with self.subTest(case=case, status=status, reason=reason), self.assertRaises(checker.CheckFailure):
                    check(case, status, headers, bad)

    def test_actual_run_four_request_order_and_denial_counter_guard(self):
        for drift in (None, "missing", "wrong"):
            value, trace, counts = ordering_fixture(drift)
            with patch.object(checker, "token_file", return_value="synthetic-admin"), patch.object(
                    checker.features, "record_negative_phase", side_effect=lambda _, code, scope: trace.append(code)):
                with self.subTest(drift=drift), self.assertRaises(BeforeFinalAudit if drift is None else checker.CheckFailure):
                    value.run()
            calls = [entry for entry in trace if isinstance(entry, tuple)]
            if drift is None:
                self.assertEqual(calls, [(case, dummy) for case, dummy, _ in checker.CASES])
                self.assertEqual([case for case, _ in calls], ["missing", "wrong", "json", "empty"])
                self.assertEqual(counts, [0, 0, 0, 0, 0, 0, 1, 1, 2, 2])
                self.assertLess(trace.index(checker.ERRORS["missing"]), trace.index(calls[1]))
                self.assertLess(trace.index(checker.ERRORS["wrong"]), trace.index(calls[2]))
            else:
                self.assertEqual([case for case, _ in calls], ["missing"] if drift == "missing" else ["missing", "wrong"])

    def test_audit_pairs_are_distinct_scoped_post_200_and_204(self):
        rows = lifecycle_rows()
        complete, counts = checker.audit_attempts(rows, SCOPE)
        self.assertEqual(len(complete), 2)
        self.assertEqual({pair["status"] for pair in complete.values()}, {200, 204})
        self.assertEqual(counts, Counter({checker.START: 2, checker.RELEASE: 2}))
        for key, value in (("principal_id", "other"), ("method", "GET"), ("body_sha256", sha(99)),
                           ("flow_id", sha(99)), ("operation_digest", sha(99)), ("upstream_status", 201)):
            bad = deepcopy(rows)
            bad[1]["event"][key] = value
            with self.subTest(key=key), self.assertRaises(checker.CheckFailure):
                checker.audit_attempts(bad, SCOPE)
        for kind in ("duplicate-row", "extra-attempt", "reused-request", "blocked"):
            bad = deepcopy(rows)
            if kind == "duplicate-row":
                bad[2]["id"] = bad[0]["id"]
            elif kind == "extra-attempt":
                bad.append({**deepcopy(bad[0]), "id": "extra"})
            elif kind == "reused-request":
                for row in bad[2:]:
                    row["event"]["request_digest"] = sha(200)
            else:
                bad[1]["event_type"] = checker.BLOCK
            with self.subTest(kind=kind), self.assertRaises(checker.CheckFailure):
                checker.audit_attempts(bad, SCOPE)

    def test_complete_audit_rejects_wrong_wire_join_duplicate_and_reload(self):
        value, rows = audit_fixture()
        self.assertEqual(len(value.verify_ordinary_audit({}, SCOPE, LEASE_SCOPE)["auditedRequestAttemptIds"]), 2)
        for kind in ("wire-join", "duplicate-row", "extra-reload", "wrong-reload"):
            value, rows = audit_fixture()
            if kind == "wire-join":
                value.feature_observations[0]["requestDigest"] = sha(99)
            elif kind == "duplicate-row":
                rows[-1]["id"] = rows[0]["id"]
            elif kind == "extra-reload":
                rows.append({**deepcopy(rows[-1]), "id": "extra-reload"})
            else:
                rows[-1]["event"]["previous_policy_hash"] = sha(99)
            with self.subTest(kind=kind), self.assertRaises(checker.CheckFailure):
                value.verify_ordinary_audit({}, SCOPE, LEASE_SCOPE)


if __name__ == "__main__":
    unittest.main()
