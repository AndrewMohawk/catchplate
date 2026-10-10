#!/usr/bin/env python3
"""Pure Basic audit-oracle regressions; real validation with mocked I/O only.

No app, database, socket, provider, subprocess or retained fixture is used.
These synthetic snapshots do not establish runtime acceptance of the failed run.
"""
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

try:
    from scripts import check_operator_proxy_basic as checker
    from scripts import check_operator_ordinary_client as ordinary
except ModuleNotFoundError:
    import check_operator_proxy_basic as checker
    import check_operator_ordinary_client as ordinary


def sha(number):
    return "sha256:" + format(number, "064x")


POLICY, BINARY, CREDENTIAL = sha(3), sha(4), "synthetic-credential"
SCOPES = (("principal-0", "route-0"), ("principal-1", "route-1"))


def row(identifier, kind, event):
    return {"id": identifier, "event_hash": checker.digest(identifier.encode()), "event_type": kind, "event": event}


def lease(identifier, *, purpose="dispatchSecret", scope=SCOPES[0]):
    return row(identifier, checker.LEASE, {"principal_id": scope[0], "route_id": scope[1],
        "credential_id": CREDENTIAL, "policy_hash": POLICY, "status_code": 200, "outcome": "issued",
        "data_plane_binary_digest": BINARY, "purpose": purpose,
        "expected_credential_version": 1 if purpose == "dispatchSecret" else None})


def health(*, queued=0, failed=0):
    values = {key: 0 for key in ordinary.ZERO_COUNTERS + ordinary.DRAIN_COUNTERS}
    values.update(queue_depth=queued, send_failed=failed)
    return {"audit": values}


def fixture():
    check = checker.ProxyBasicCheck.__new__(checker.ProxyBasicCheck)
    check.args = SimpleNamespace(expected_binary_sha256=BINARY)
    check.policy_hash, check.expected_connects, check.expected_denials = POLICY, 6, 8
    check.mutations = [("operator_catalog." + kind + ".created", str(index), POLICY)
        for index, kind in enumerate(("credential", "application", "application", "application",
            "access_rule", "access_rule"))]
    check.observations = [{"stage": stage, "policyHash": sha(index + 1), "sequence": index + 1}
        for index, stage in enumerate(("initial", "assigned_rule_0", "assigned_rule_1"))]
    baseline_row = row("baseline", "synthetic.baseline", {})
    baseline = checker.features.audit_cutoff([baseline_row])
    rows = [baseline_row]
    rows += [row("mutation-" + identifier, kind, {"resource_id": identifier, "policy_hash": policy})
        for kind, identifier, policy in check.mutations]
    rows += [row("reload-" + str(index), checker.RELOAD, {"previous_policy_hash": sha(index),
        "policy_hash": sha(index + 1), "policy_sequence": index + 1, "routes": index}) for index in (1, 2)]
    rows += [row("connect-" + str(index), checker.CONNECT, {"method": "CONNECT", "target": checker.AUTHORITY,
        "principal_id": SCOPES[index % 2][0], "policy_hash": POLICY, "outcome": "established"}) for index in range(6)]
    rows += [row("denied-" + str(index), checker.CONNECT_DENIED, {"method": "CONNECT", "target": checker.AUTHORITY,
        "principal_id": None, "policy_hash": None, "outcome": "denied",
        "payload": {"error": "client_principal_denied"}}) for index in range(8)]
    for index, scope in enumerate(SCOPES):
        rows += [lease("lease-secret-" + str(index), scope=scope),
            lease("lease-metadata-" + str(index), purpose="generationMetadata", scope=scope)]
    check.feature_observations = []
    for index in range(4):
        principal, route = SCOPES[int(index == 3)]
        observation = {"principalId": principal, "routeId": route, "requestDigest": sha(100 + index),
            "operationDigest": sha(200 + index), "generation": 1, "responseBodySha256": checker.digest(checker.REQUEST_BODY)}
        check.feature_observations.append(observation)
        event = {"principal_id": principal, "route_id": route, "request_digest": observation["requestDigest"],
            "operation_digest": observation["operationDigest"], "policy_hash": POLICY, "method": "POST",
            "body_sha256": checker.digest(checker.REQUEST_BODY), "credential_ref": CREDENTIAL, "credential_version": 1,
            "attempt_id": sha(300 + index), "flow_id": sha(300 + index)}
        rows += [row("start-" + str(index), checker.START, {**event, "outcome": "release_started"}),
            row("release-" + str(index), checker.RELEASE, {**event, "outcome": "released", "upstream_status": 200,
                "response_body_sha256": observation["responseBodySha256"], "response_body_bytes": len(checker.REQUEST_BODY),
                "response_validation": {"ok": True, "mode": ordinary.RESPONSE_MODES[checker.V2_RESPONSE_MODE],
                    "body_bytes_preserved": True}})]
    check.negative_cutoffs = [checker.features.audit_cutoff([baseline_row, next(item for item in rows if item["id"] == "denied-0")])]
    check.health = Mock(return_value=health())
    check.control_json = Mock(return_value={"ok": True, "complete": True, "backend": "sqlite"})
    check.timeout = Mock(side_effect=checker.CheckFailure("synthetic no-poll deadline"))
    assigned = [({"principal_id": principal}, {"route_id": route}, "unused-synthetic-token") for principal, route in SCOPES]
    return check, rows, baseline, assigned


def verify(check, snapshots, baseline, assigned):
    check.audit = Mock(side_effect=deepcopy(snapshots))
    return check.verify_client_audit(baseline, assigned, CREDENTIAL)


class ProxyBasicAuditTests(unittest.TestCase):
    def test_unchanged_fresh_snapshot_runs_real_full_oracle_and_chain_check(self):
        check, rows, baseline, assigned = fixture()
        result = verify(check, [rows, rows], baseline, assigned)
        self.assertEqual(check.audit.call_count, 2)
        self.assertEqual(len(result["auditedRequestAttemptIds"]), 4)
        self.assertEqual(result["namedAuditInventory"][checker.LEASE], 4)
        check.control_json.assert_called_once_with("/api/audit/verify?limit=1000", authenticated=True)

    def test_late_leases_of_both_purposes_and_scopes_are_fully_counted(self):
        check, rows, baseline, assigned = fixture()
        additions = [lease("late-" + str(index) + purpose, scope=scope, purpose=purpose)
            for index, scope in enumerate(SCOPES) for purpose in ("generationMetadata", "dispatchSecret")]
        result = verify(check, [rows, rows + additions], baseline, assigned)
        self.assertEqual(result["namedAuditInventory"][checker.LEASE], 8)
        self.assertEqual(set(result["durableAuditEventIds"]), {item["id"] for item in rows[1:] + additions})

    def test_late_lease_binding_status_purpose_and_exact_version_fail_closed(self):
        cases = {"principal_id": "other", "route_id": "other", "credential_id": "other", "policy_hash": sha(99),
            "data_plane_binary_digest": sha(99), "status_code": 201, "outcome": "rejected", "purpose": "unknown",
            "expected_credential_version": 2}
        for field, value in cases.items():
            with self.subTest(field=field):
                check, rows, baseline, assigned = fixture()
                addition = lease("late-bad")
                addition["event"][field] = value
                with self.assertRaises(checker.CheckFailure):
                    verify(check, [rows, rows + [addition]], baseline, assigned)
                check.control_json.assert_not_called()
        for purpose, version in (("dispatchSecret", True), ("dispatchSecret", None), ("generationMetadata", 1)):
            with self.subTest(purpose=purpose, version=version):
                check, rows, baseline, assigned = fixture()
                addition = lease("late-bad-version", purpose=purpose)
                addition["event"]["expected_credential_version"] = version
                with self.assertRaises(checker.CheckFailure):
                    verify(check, [rows, rows + [addition]], baseline, assigned)

    def test_old_baseline_negative_and_lease_rows_cannot_disappear_or_change_hash(self):
        for identifier in ("baseline", "denied-0", "lease-secret-0", "lease-metadata-1"):
            for remove in (False, True):
                with self.subTest(identifier=identifier, remove=remove):
                    check, rows, baseline, assigned = fixture()
                    final = deepcopy(rows)
                    if remove:
                        final = [item for item in final if item["id"] != identifier]
                    else:
                        next(item for item in final if item["id"] == identifier)["event_hash"] = sha(999)
                    with self.assertRaises(checker.CheckFailure):
                        verify(check, [rows, final], baseline, assigned)

    def test_every_nonlease_append_is_refused_even_when_previously_known(self):
        for kind in (checker.CONNECT, checker.CONNECT_DENIED, checker.START, checker.RELEASE, checker.RELOAD,
                checker.BLOCK, "operator_catalog.application.created", "unknown.event"):
            with self.subTest(kind=kind):
                check, rows, baseline, assigned = fixture()
                with self.assertRaisesRegex(checker.CheckFailure, "non-lease audit appended"):
                    verify(check, [rows, rows + [row("unexpected", kind, {})]], baseline, assigned)

    def test_duplicate_ids_and_saturated_final_view_are_refused(self):
        check, rows, baseline, assigned = fixture()
        with self.assertRaises(checker.CheckFailure):
            verify(check, [rows, rows + [deepcopy(rows[-1])]], baseline, assigned)
        check, rows, baseline, assigned = fixture()
        final = rows + [lease("bounded-" + str(index)) for index in range(500 - len(rows))]
        with self.assertRaisesRegex(checker.CheckFailure, "saturated"):
            verify(check, [rows, final], baseline, assigned)

    def test_negative_history_and_extra_count_are_checked_before_first_checkpoint(self):
        for identifier in ("denied-0", "connect-0"):
            with self.subTest(identifier=identifier):
                check, rows, baseline, assigned = fixture()
                if identifier == "denied-0":
                    next(item for item in rows if item["id"] == identifier)["event_hash"] = sha(999)
                else:
                    extra = deepcopy(next(item for item in rows if item["id"] == identifier))
                    extra.update(id="extra-connect", event_hash=sha(999))
                    rows.append(extra)
                with self.assertRaises(checker.CheckFailure):
                    verify(check, [rows], baseline, assigned)

    def test_incomplete_dispatch_pairs_do_not_get_a_checkpoint_or_new_deadline(self):
        check, rows, baseline, assigned = fixture()
        rows = [item for item in rows if item["id"] != "release-3"]
        with self.assertRaisesRegex(checker.CheckFailure, "synthetic no-poll deadline"):
            verify(check, [rows], baseline, assigned)
        check.control_json.assert_not_called()

    def test_queue_redrain_keeps_all_intermediate_lease_history(self):
        for corruption in (None, "removed", "changed"):
            with self.subTest(corruption=corruption):
                check, rows, baseline, assigned = fixture()
                second = rows + [lease("intermediate")]
                final = deepcopy(second) + [lease("last", purpose="generationMetadata")]
                if corruption == "removed":
                    final = [item for item in final if item["id"] != "intermediate"]
                elif corruption == "changed":
                    next(item for item in final if item["id"] == "intermediate")["event_hash"] = sha(999)
                check.health = Mock(side_effect=[health(), health(queued=1), health(queued=1), health()])
                check.timeout = lambda: 0  # Only the unchanged zero-second polling sleep is reached.
                if corruption:
                    with self.assertRaisesRegex(checker.CheckFailure, "audit history changed"):
                        verify(check, [rows, second, final], baseline, assigned)
                else:
                    result = verify(check, [rows, second, final], baseline, assigned)
                    self.assertEqual(check.audit.call_count, 3)
                    self.assertEqual(result["namedAuditInventory"][checker.LEASE], 6)

    def test_delivery_failure_or_failed_chain_cannot_be_accepted(self):
        check, rows, baseline, assigned = fixture()
        check.health = Mock(side_effect=[health(), health(failed=1)])
        with self.assertRaisesRegex(checker.CheckFailure, "audit delivery failed"):
            verify(check, [rows, rows], baseline, assigned)
        check, rows, baseline, assigned = fixture()
        check.control_json.return_value = {"ok": False, "complete": True, "backend": "sqlite"}
        with self.assertRaisesRegex(checker.CheckFailure, "durable audit verification failed"):
            verify(check, [rows, rows], baseline, assigned)


if __name__ == "__main__":
    unittest.main(verbosity=2)
