#!/usr/bin/env python3
"""Pure mocked catalog lifecycle ordering; no sockets, processes or clock sleeps."""
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

try:
    from scripts import check_operator_catalog as checker
except ModuleNotFoundError:
    import check_operator_catalog as checker


class LifecycleComplete(Exception):
    pass


class Harness(checker.OperatorCatalogCheck):
    """Exercise the real run/submission/finalization/denial methods with fake I/O."""
    def __init__(self):
        self.epoch_ms, self.monotonic_ns = 1_790_000_000_000, 5_000_000_000
        self.results, self.observations, self.successes, self.mutations = [], [], [], []
        self.warm_observations, self.warm_lease_checks, self.warm_denial_checks = [], [], []
        self.issued_tokens, self.trace, self.posts = [], [], []
        self.credential, self.admin_token = "synthetic-provider-secret", "synthetic-admin-secret"
        self.wrong_token, self.client_token = "synthetic-wrong-secret", None
        self.run_id, self.dispatches, self.policy_hash, self.snapshot = "synthetic-run", 0, None, None
        self.control, self.control_ca = object(), None
        self.args = SimpleNamespace(admin_token_file=None, expected_binary_sha256="sha256:" + "b" * 64)
        self.revision, self.sequence = 1, 1
        self.rows = {name: [] for name in checker.COLLECTIONS}
        self.catalog_hook, self.post_hook, self.health_hook = None, None, None
        self.catalog_latency_ms, self.header_latency_ms = 600, 30

    def advance(self, milliseconds):
        self.epoch_ms += milliseconds
        self.monotonic_ns += milliseconds * 1_000_000

    def policy(self):
        digest = "sha256:" + format(self.sequence, "064x")
        return {"policy_hash": digest, "loaded_policy_hash": digest, "sequence": self.sequence, "activation": "active"}

    def snapshot_value(self):
        rows = deepcopy(self.rows)
        for credential in rows["credentials"]:
            credential["active_rule_count"] = sum(rule["status"] == "active" for rule in rows["access_rules"])
        for app in rows["applications"]:
            if app["status"] == "active":
                app["access_status"] = "active" if any(rule["application_id"] == app["id"]
                    and rule["status"] == "active" for rule in rows["access_rules"]) else "unassigned"
        return {"schema": "serverware.operatorCatalog/v1", "mode": "operator-development",
            "productionReady": False, "hardwareVerified": False,
            "allowed_upstreams": ["https://" + checker.AUTHORITY], "revision": self.revision,
            "policy": self.policy(), "limits": {name: {"retained": len(values)} for name, values in rows.items()}, **rows}

    def control_json(self, path, **kwargs):
        assert path == checker.PREFIX + "/catalog"
        self.trace.append("catalog")
        self.advance(self.catalog_latency_ms)
        snapshot = self.snapshot_value()
        if self.catalog_hook:
            self.catalog_hook(snapshot)
        return snapshot

    def json_request(self, endpoint, path, **kwargs):
        route, payload = path.removeprefix(checker.PREFIX), kwargs["payload"]
        assert kwargs["method"] == "POST"
        self.trace.append("post:" + route)
        self.posts.append((route, deepcopy(payload)))
        self.advance(80)
        assert payload["expected_revision"] == self.revision
        assert payload["expected_policy_hash"] == self.policy()["policy_hash"]
        issued, affected = None, None
        if route == "/credentials":
            collection, result_key = "credentials", "credential"
            row = {"id": "credential1", "version": 1, "status": "active", "active_rule_count": 0}
            self.rows[collection].append(row)
        elif route == "/applications":
            collection, result_key = "applications", "application"
            number = len(self.rows[collection]) + 1
            row = {"id": "app" + str(number), "principal_id": "principal" + str(number),
                "name": payload["name"], "version": 1, "status": "active", "token_generation": 1,
                "token_status": "valid", "access_status": "unassigned",
                "token_expires_at_epoch_ms": self.epoch_ms + 3_600_000}
            self.rows[collection].append(row)
            issued = chr(64 + number) * 64
        elif route == "/access-rules":
            collection, result_key = "access_rules", "access_rule"
            number = len(self.rows[collection]) + 1
            row = {"id": "rule" + str(number), "route_id": "operator.rule" + str(number),
                "application_id": payload["application_id"], "credential_id": payload["credential_id"],
                "status": "active", "enforcement": "active", "version": 1}
            self.rows[collection].append(row)
            self.sequence += 1
        else:
            assert route in {"/applications/revoke", "/applications/rotate-token"}
            collection, result_key = "applications", "application"
            row = next(app for app in self.rows[collection] if app["id"] == payload["id"])
            row["version"] += 1
            self.sequence += 1
            if route.endswith("/revoke"):
                row.update(status="revoked", token_status="revoked", access_status="revoked")
                affected = []
                for rule in self.rows["access_rules"]:
                    if rule["application_id"] == row["id"]:
                        rule.update(status="revoked", enforcement="revoked")
                        affected.append(rule["id"])
            else:
                row.update(token_generation=2, access_status="active")
                issued = "C" * 64
        self.revision += 1
        result = {result_key: deepcopy(row), "revision": self.revision, "policy": self.policy()}
        if issued is not None:
            result["client_token"] = issued
        if affected is not None:
            result["affected_rule_ids"] = affected
        status = 201 if route in {"/credentials", "/applications", "/access-rules"} else 200
        if self.post_hook:
            status = self.post_hook(route, result, status)
        return status, result

    def health(self):
        self.trace.append("health")
        self.advance(10)
        result = {"policy_hash": self.policy()["policy_hash"],
            "policy_shadow": {"operator_policy_sha256": self.policy()["policy_hash"]}}
        if self.health_hook:
            self.health_hook(result)
        return result

    def timeout(self):
        return 4.0

    def count(self):
        self.trace.append("count")
        self.advance(10)
        return self.dispatches

    def tunnel(self, token, *, expected_status=200):
        assert expected_status == 403
        self.trace.append("headers403")
        self.advance(self.header_latency_ms)

    def injected(self, token, application, rule):
        self.trace.append("dispatch")
        self.dispatches += 1
        self.successes.append((application["principal_id"], rule["route_id"], self.policy_hash))

    def observe_live_lease(self, stage, application, rule, credential, *, minimum_scopes):
        # Actual health/scoped receipt capture has separate unchanged controls.
        self.trace.append("warm:" + stage)
        return {"stage": stage, "principalId": application["principal_id"], "routeId": rule["route_id"],
            "scopedLeaseAuditEventId": "synthetic-lease", "capturedAtEpochMs": self.epoch_ms,
            "_captured_monotonic_ns": self.monotonic_ns, "denialDeadlineEpochMs": self.epoch_ms + 1794,
            "healthEarliestUnexpiredLeaseEpochMs": self.epoch_ms + 1794,
            "scopedLeaseExpiryEpochMs": self.epoch_ms + 1794}

    def finalize_mutation(self, result, after, **kwargs):
        super().finalize_mutation(result, after, **kwargs)
        self.trace.append("finalize:" + kwargs["event"])


class PhaseSplitTests(unittest.TestCase):
    def run_lifecycle(self, value):
        def checkpoint(check, stage):
            self.assertIs(check, value)
            self.assertEqual(stage, "lifecycle")
            raise LifecycleComplete()

        with patch.object(checker, "token_file", return_value=value.admin_token), \
                patch.object(checker.time, "time_ns", side_effect=lambda: value.epoch_ms * 1_000_000), \
                patch.object(checker.time, "monotonic_ns", side_effect=lambda: value.monotonic_ns), \
                patch.object(checker.time, "time", side_effect=lambda: value.epoch_ms / 1000), \
                patch.object(checker.time, "sleep", side_effect=checker.CheckFailure("synthetic bounded poll stop")), \
                patch.object(checker.features, "checkpoint", side_effect=checkpoint):
            value.run()

    def test_real_lifecycle_moves_catalog_reads_outside_both_warm_windows(self):
        value = Harness()
        with self.assertRaises(LifecycleComplete):
            self.run_lifecycle(value)
        for stage, route, event in (("before_app1_revoke", "/applications/revoke", "revoked"),
                ("before_app2_rotate", "/applications/rotate-token", "token_rotated")):
            start = value.trace.index("warm:" + stage)
            post = value.trace.index("post:" + route, start)
            denial = value.trace.index("headers403", post)
            finalize = value.trace.index("finalize:operator_catalog.application." + event, denial)
            self.assertEqual(value.trace[start - 1], "catalog")
            self.assertEqual(value.trace[start + 1:denial], ["post:" + route, "health", "count"])
            self.assertEqual(value.trace[denial + 1:finalize], ["count", "catalog", "health"])
            self.assertEqual(sum(path == route for path, _ in value.posts), 1)
        self.assertEqual(value.dispatches, 6)
        self.assertEqual(value.trace.count("dispatch"), 6)
        self.assertEqual(len(value.warm_observations), 2)
        self.assertEqual(len(value.mutations), 7)
        for observation in value.warm_denial_checks:
            self.assertTrue(all(observation["conditions"].values()))
            self.assertEqual(observation["denialElapsedMonotonicNs"], 130_000_000)
        # The former three catalog reads alone exceeded this unchanged window.
        self.assertGreater(3 * value.catalog_latency_ms, 1794)

    def test_warm_cas_must_match_current_loaded_policy_before_capture(self):
        for changed in ("policy_hash", "loaded_policy_hash", "activation"):
            value = Harness()

            def catalog(snapshot):
                if value.dispatches == 4:
                    snapshot["policy"][changed] = "pending" if changed == "activation" else "sha256:" + "f" * 64

            value.catalog_hook = catalog
            with self.subTest(changed=changed), self.assertRaisesRegex(checker.CheckFailure, "warm CAS"):
                self.run_lifecycle(value)
            self.assertNotIn("warm:before_app1_revoke", value.trace)
            self.assertFalse(any(route.endswith("/revoke") for route, _ in value.posts))

    def test_bad_warm_post_receipts_never_retry_or_reach_denial(self):
        changes = {
            "stale": lambda result: None,
            "revision": lambda result: result.update(revision=True),
            "hash": lambda result: result["policy"].update(policy_hash="untrusted"),
            "sequence": lambda result: result["policy"].update(sequence=3),
            "id": lambda result: result["application"].update(id="other-app"),
            "version": lambda result: result["application"].update(version=1),
            "affected": lambda result: result.update(affected_rule_ids=["rule2"]),
            "unexpected-token": lambda result: result.update(client_token="D" * 64),
        }
        for label, change in changes.items():
            value = Harness()

            def post(route, result, status):
                if route == "/applications/revoke":
                    change(result)
                    return 409 if label == "stale" else status
                return status

            value.post_hook = post
            with self.subTest(label=label), self.assertRaises(checker.CheckFailure):
                self.run_lifecycle(value)
            position = value.trace.index("post:/applications/revoke")
            self.assertNotIn("headers403", value.trace[position + 1:])
            self.assertEqual(sum(route == "/applications/revoke" for route, _ in value.posts), 1)
            self.assertEqual(len(value.mutations), 5)

    def test_rotation_token_and_identity_validation_precede_old_token_denial(self):
        changes = [lambda result: result.update(client_token="not-a-token"),
            lambda result: result.update(client_token="A" * 64),
            lambda result: result["application"].update(principal_id="other-principal"),
            lambda result: result["application"].update(token_generation=1)]
        for change in changes:
            value = Harness()

            def post(route, result, status):
                if route.endswith("/rotate-token"):
                    change(result)
                return status

            value.post_hook = post
            with self.subTest(change=changes.index(change)), self.assertRaises(checker.CheckFailure):
                self.run_lifecycle(value)
            position = value.trace.index("post:/applications/rotate-token")
            self.assertNotIn("headers403", value.trace[position + 1:])
            self.assertEqual(len(value.mutations), 6)

    def test_gate_barrier_requires_exact_health_and_shadow_not_post_activation(self):
        for changed in ("health", "shadow"):
            value = Harness()

            def health(result):
                if value.sequence == 4:
                    if changed == "health":
                        result["policy_hash"] = "sha256:" + "f" * 64
                    else:
                        result["policy_shadow"]["operator_policy_sha256"] = "sha256:" + "f" * 64

            value.health_hook = health
            with self.subTest(changed=changed), self.assertRaisesRegex(checker.CheckFailure, "bounded poll stop"):
                self.run_lifecycle(value)
            position = value.trace.index("post:/applications/revoke")
            self.assertNotIn("headers403", value.trace[position + 1:])
            self.assertEqual(len(value.mutations), 5)

    def test_late_denial_still_fails_without_recording_the_mutation(self):
        value = Harness()
        value.header_latency_ms = 1800
        with self.assertRaisesRegex(checker.CheckFailure, "captured lease expiry"):
            self.run_lifecycle(value)
        self.assertEqual(value.warm_denial_checks[0]["failedConjuncts"], [
            "wall_before_original_expiry", "monotonic_before_original_window"])
        self.assertEqual(len(value.mutations), 5)
        self.assertEqual(value.dispatches, 4)

    def test_changed_counter_still_blocks_finalization_after_timely_headers(self):
        value = Harness()
        original_count = value.count

        def count():
            number = original_count()
            if value.warm_denial_checks and value.warm_denial_checks[-1]["headersValidated"]:
                return number + 1
            return number

        value.count = count
        with self.assertRaisesRegex(checker.CheckFailure, "upstream_count_unchanged"):
            self.run_lifecycle(value)
        self.assertEqual(value.warm_denial_checks[0]["failedConjuncts"], ["upstream_count_unchanged"])
        self.assertEqual(value.warm_observations, [])
        self.assertEqual(len(value.mutations), 5)

    def test_fresh_persistence_drift_fails_after_timely_denial(self):
        changes = {
            "revision": lambda snapshot: snapshot.update(revision=8),
            "hash": lambda snapshot: snapshot["policy"].update(policy_hash="sha256:" + "f" * 64),
            "sequence": lambda snapshot: snapshot["policy"].update(sequence=5),
            "version": lambda snapshot: snapshot["applications"][0].update(version=3),
            "missing": lambda snapshot: snapshot["applications"].pop(0),
            "sibling": lambda snapshot: snapshot["access_rules"][1].update(enforcement="revoked"),
            "credential": lambda snapshot: snapshot["credentials"][0].update(version=2),
        }
        for label, change in changes.items():
            value = Harness()

            def catalog(snapshot):
                if value.warm_observations:
                    change(snapshot)

            value.catalog_hook = catalog
            with self.subTest(label=label), self.assertRaises(checker.CheckFailure):
                self.run_lifecycle(value)
            self.assertEqual(len(value.warm_observations), 1)
            self.assertEqual(len(value.mutations), 5)
            self.assertNotIn("warm_app1_revoked_403_no_dispatch_while_app2_still_200", value.results)
            self.assertEqual(value.dispatches, 4)

    def test_rotation_persistence_failure_precedes_new_token_dispatch(self):
        for field, replacement in (("token_generation", 1), ("token_status", "expired"),
                ("principal_id", "changed-principal")):
            value = Harness()

            def catalog(snapshot):
                if len(value.warm_observations) == 2:
                    snapshot["applications"][1][field] = replacement

            value.catalog_hook = catalog
            with self.subTest(field=field), self.assertRaises(checker.CheckFailure):
                self.run_lifecycle(value)
            self.assertEqual(value.dispatches, 5)
            self.assertEqual(len(value.mutations), 6)
            self.assertNotIn("app2_old_token_403_no_dispatch_new_token_200_shared_credential_unchanged", value.results)


if __name__ == "__main__":
    unittest.main()
