#!/usr/bin/env python3
"""Pure/mocked acceptance-harness tests: no sockets, containers or fixture data."""
from copy import deepcopy
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, mock_open, patch

try:
    from scripts import check_operator_catalog as checker
    from scripts import prepare_operator_catalog_fixture as fixture
except ModuleNotFoundError:
    import check_operator_catalog as checker
    import prepare_operator_catalog_fixture as fixture


SOURCE = Path("/srv/catchplate-fast/projects/serverware-operator-workspace")
BINARY = Path("/srv/catchplate-fast/projects/serverware-operator-artifacts/sha256-" + fixture.BINARY_SHA256 + "/serverware-decision-gate")
INITIALIZER = Path("/srv/catchplate-fast/projects/serverware-operator-audit-integration/scripts/private_operator_audit/initialize.py")
ROOT = fixture.SCRATCH / "serverware-catalog-private.Review01"


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.config = fixture.build(SOURCE, BINARY, INITIALIZER, ROOT, "172.16.249.48/28")

    def check(self, value):
        fixture.validate(value, SOURCE, BINARY, INITIALIZER, ROOT)

    def test_exact_internal_services_and_addresses(self):
        self.assertEqual(set(self.config["services"]), {"initialize", "serverware", "demo-upstream", "decision-gate-rs"})
        self.assertEqual(self.config["services"]["serverware"]["networks"]["fixture"]["ipv4_address"], "172.16.249.51")
        self.assertEqual(self.config["services"]["decision-gate-rs"]["networks"]["fixture"]["ipv4_address"], "172.16.249.52")
        self.assertEqual(self.config["services"]["initialize"]["network_mode"], "none")
        self.assertTrue(self.config["networks"]["fixture"]["internal"])
        self.check(self.config)

    def test_manifest_deterministic(self):
        self.assertEqual(self.config, fixture.build(SOURCE, BINARY, INITIALIZER, ROOT, "172.16.249.48/28"))

    def test_extra_swap_refused_for_every_service(self):
        for name in self.config["services"]:
            config = deepcopy(self.config)
            self.assertEqual(config["services"][name]["memswap_limit"], config["services"][name]["mem_limit"])
            config["services"][name]["memswap_limit"] = "2g"
            with self.subTest(service=name), self.assertRaises(ValueError):
                self.check(config)

    def test_bad_root_or_subnet_refused(self):
        for root, subnet in ((Path("/tmp/catalog"), "172.16.249.48/28"),
                             (ROOT, "10.0.0.0/28"), (ROOT, "172.16.249.0/24")):
            with self.subTest(root=root, subnet=subnet), self.assertRaises(ValueError):
                fixture.build(SOURCE, BINARY, INITIALIZER, root, subnet)

    def test_ports_external_network_and_privilege_refused(self):
        for key, value in (("ports", ["9090:9090"]), ("privileged", True), ("env_file", [".env"]),
                           ("networks", {"fixture": {}, "outbound": {}}), ("cap_add", ["NET_ADMIN"])):
            config = deepcopy(self.config)
            config["services"]["decision-gate-rs"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(config)
        config = deepcopy(self.config)
        config["networks"]["fixture"]["internal"] = False
        with self.assertRaises(ValueError):
            self.check(config)

    def test_live_mount_and_writable_source_refused(self):
        for volume in (fixture.bind(Path("/srv/catchplate-fast/homelab_data/serverware-operator-demo"), "/data"),
                       fixture.bind(SOURCE, "/app", False)):
            config = deepcopy(self.config)
            config["services"]["serverware"]["volumes"].append(volume)
            with self.assertRaises(ValueError):
                self.check(config)

    def test_control_destination_image_and_relay_refused(self):
        config = deepcopy(self.config)
        config["services"]["decision-gate-rs"]["environment"]["SERVERWARE_CONTROL_PLANE_AUDIT_URL"] = "http://elsewhere/audit"
        with self.assertRaises(ValueError):
            self.check(config)
        config = deepcopy(self.config)
        config["services"]["serverware"]["image"] = "unreviewed:latest"
        with self.assertRaises(ValueError):
            self.check(config)
        config = deepcopy(self.config)
        config["services"]["serverware"]["command"] = ["python", "relay.py"]
        with self.assertRaises(ValueError):
            self.check(config)


class AcceptanceTests(unittest.TestCase):
    def check(self):
        value = checker.OperatorCatalogCheck.__new__(checker.OperatorCatalogCheck)
        value.issued_tokens = []
        value.credential, value.admin_token, value.wrong_token, value.client_token = "provider-secret", "admin-secret", "wrong-secret", None
        value.control, value.control_ca = object(), None
        value.mutations, value.results = [], []
        value.warm_observations = []
        return value

    def test_every_previously_issued_token_is_redacted(self):
        value = self.check()
        value.issued_tokens = ["A" * 40, "B" * 40]
        value.client_token = value.issued_tokens[-1]
        value.clean(b'{"safe":true}', allow_client_token=True)
        for token in (*value.issued_tokens, value.credential, value.admin_token):
            with self.assertRaises(checker.CheckFailure):
                value.clean(token.encode(), allow_client_token=True)

    def test_denied_token_requires_unchanged_count(self):
        value = self.check()
        value.count, value.tunnel = Mock(side_effect=[4, 5]), Mock()
        with self.assertRaises(checker.CheckFailure):
            value.denied_without_dispatch("fake")
        value.tunnel.assert_called_once_with("fake", expected_status=403)

    def warm_fixture(self):
        value = self.check()
        value.policy_hash = "sha256:" + "a" * 64
        value.args = SimpleNamespace(expected_binary_sha256="sha256:" + "b" * 64)
        application, rule, credential = {"principal_id": "app1"}, {"route_id": "rule1"}, {"id": "credential1"}
        health = {"policy_hash": value.policy_hash, "credential_leases": 2, "credential_generation_hot_scopes": 2,
            "credential_lease_earliest_expiry_epoch_ms": 105000}
        event = {"purpose": "dispatchSecret", "principal_id": "app1", "route_id": "rule1", "credential_id": "credential1",
            "policy_hash": value.policy_hash, "data_plane_binary_digest": value.args.expected_binary_sha256,
            "issued_at_epoch_ms": 99500, "expires_at_epoch_ms": 104500}
        value.health = Mock(return_value=health)
        value.audit = Mock(return_value=[{"id": 10, "event_type": "data_plane.credential_lease.issued", "event": event}])
        return value, application, rule, credential, health, event

    def test_live_lease_requires_unexpired_scope_receipt_not_just_counts(self):
        for scenario in ("valid", "expired-health", "expired-scope", "wrong-scope", "short-window", "missing-health"):
            value, application, rule, credential, health, event = self.warm_fixture()
            if scenario == "expired-health":
                health["credential_lease_earliest_expiry_epoch_ms"] = 99999
            elif scenario == "expired-scope":
                event["expires_at_epoch_ms"] = 99999
            elif scenario == "wrong-scope":
                event["principal_id"] = "other-app"
            elif scenario == "short-window":
                event["expires_at_epoch_ms"] = 100500
            elif scenario == "missing-health":
                health["credential_lease_earliest_expiry_epoch_ms"] = None
            with self.subTest(scenario=scenario), patch.object(checker.time, "time_ns", return_value=100000_000000), \
                    patch.object(checker.time, "monotonic_ns", return_value=200000_000000):
                if scenario == "valid":
                    warm = value.observe_live_lease("before-revoke", application, rule, credential, minimum_scopes=2)
                    self.assertEqual(warm["denialDeadlineEpochMs"], 104500)
                    self.assertEqual(warm["scopedLeaseAuditEventId"], 10)
                else:
                    with self.assertRaises(checker.CheckFailure):
                        value.observe_live_lease("before-revoke", application, rule, credential, minimum_scopes=2)

    def test_denial_must_precede_original_expiry_on_both_clocks(self):
        for wall_ms, elapsed_ms, permitted in ((104000, 4000, True), (104500, 4500, False),
                                              (104000, 5000, False), (99000, 1000, False)):
            value = self.check()
            value.count, value.tunnel = Mock(return_value=4), Mock()
            warm = {"capturedAtEpochMs": 100000, "denialDeadlineEpochMs": 104500, "_captured_monotonic_ns": 200000_000000}
            with self.subTest(wall_ms=wall_ms, elapsed_ms=elapsed_ms), \
                    patch.object(checker.time, "time_ns", return_value=wall_ms * 1_000_000), \
                    patch.object(checker.time, "monotonic_ns", return_value=(200000 + elapsed_ms) * 1_000_000):
                if permitted:
                    value.denied_without_dispatch("fake", warm=warm)
                    self.assertEqual(value.warm_observations[0]["denialVerifiedAtEpochMs"], wall_ms)
                    self.assertNotIn("_captured_monotonic_ns", value.warm_observations[0])
                else:
                    with self.assertRaises(checker.CheckFailure):
                        value.denied_without_dispatch("fake", warm=warm)

    def audit_fixture(self):
        scopes = [("app1", "rule1", "policy1")] * 2 + [("app2", "rule2", "policy1")] * 2
        scopes += [("app2", "rule2", "policy2"), ("app2", "rule2", "policy3")]
        rows = []
        for number, scope in enumerate(scopes, 1):
            attempt = "sha256:" + str(number) * 64
            for kind, outcome in (("credential.release_started", "release_started"), ("response.released", "released")):
                event = dict(zip(("principal_id", "route_id", "policy_hash"), scope))
                event.update(attempt_id=attempt, flow_id=attempt, method="GET", outcome=outcome)
                if outcome == "released":
                    event["upstream_status"] = 200
                rows.append({"id": len(rows) + 1, "event_type": "data_plane." + kind, "event": event})
        return rows, checker.Counter(scopes)

    def test_six_request_pairs_preserve_repeated_stage_multiplicity(self):
        rows, needed = self.audit_fixture()
        actual, pairs = checker.release_attempt_pairs(rows, needed)
        self.assertEqual(actual, needed)
        self.assertEqual(len(pairs), 6)
        actual, pairs = checker.release_attempt_pairs(rows[2:], needed)
        self.assertNotEqual(actual, needed)
        self.assertEqual(len(pairs), 5)
        actual, _ = checker.release_attempt_pairs(rows[:-1], needed)
        self.assertNotEqual(actual, needed)

    def test_duplicate_or_mismatched_audit_identity_cannot_satisfy_multiplicity(self):
        for scenario in ("duplicate-row", "duplicate-attempt", "wrong-flow", "missing-attempt", "wrong-status", "extra-start"):
            rows, needed = self.audit_fixture()
            if scenario == "duplicate-row":
                rows.append(deepcopy(rows[0]))
            elif scenario == "duplicate-attempt":
                rows[2]["event"]["attempt_id"] = rows[0]["event"]["attempt_id"]
                rows[2]["event"]["flow_id"] = rows[0]["event"]["flow_id"]
            elif scenario == "wrong-flow":
                rows[0]["event"]["flow_id"] = "sha256:" + "0" * 64
            elif scenario == "missing-attempt":
                rows[0]["event"].pop("attempt_id")
            elif scenario == "wrong-status":
                rows[1]["event"]["upstream_status"] = 500
            else:
                extra = deepcopy(rows[0])
                extra["id"] = 20
                extra["event"].update(attempt_id="sha256:" + "0" * 64, flow_id="sha256:" + "0" * 64)
                rows.append(extra)
            with self.subTest(scenario=scenario), self.assertRaises(checker.CheckFailure):
                checker.release_attempt_pairs(rows, needed)

    def test_global_counter_detects_other_run(self):
        value = self.check()
        value.upstream, value.upstream_ca = object(), None
        value.json_request, value.upstream_count = Mock(return_value=(200, {"count": 2})), Mock(return_value=1)
        with self.assertRaises(checker.CheckFailure):
            value.count()

    def test_mutation_requires201_and_preserves_store_only_policy(self):
        for status, changed_hash in ((201, False), (200, False), (201, True)):
            value = self.check()
            original = {"revision": 1, "policy": {"policy_hash": "sha256:" + "a" * 64, "sequence": 1}}
            following = deepcopy(original)
            following.update(revision=2, credentials=[{"id": "id1", "version": 1}])
            if changed_hash:
                following["policy"]["policy_hash"] = "sha256:" + "b" * 64
            value.catalog = Mock(side_effect=[original, following])
            value.json_request = Mock(return_value=(status, {"credential": {"id": "id1", "version": 1},
                "revision": 2, "policy": following["policy"]}))
            options = dict(collection="credentials", result_key="credential", event="created", creates=True)
            if status == 201 and not changed_hash:
                value.mutate("/credentials", {}, **options)
                self.assertEqual(value.json_request.call_args.kwargs["payload"]["expected_revision"], 1)
            else:
                with self.assertRaises(checker.CheckFailure):
                    value.mutate("/credentials", {}, **options)

    def test_claim_failure_precedes_transport_construction(self):
        args = SimpleNamespace(expected_binary_sha256="sha256:" + "a" * 64, timeout_seconds=60,
            fixture_marker_file=Path("/private-audit-fixture.json"), run_claim_file=Path("/data") / checker.CLAIM_NAME)
        with patch.object(checker, "claim_fixture", side_effect=checker.CheckFailure("already claimed")), \
                patch.object(checker, "OperatorCatalogCheck") as transport:
            self.assertFalse(checker.run_checks(args)["ok"])
            transport.assert_not_called()

    def test_claim_exclusive_durable_and_repeat_refusal(self):
        marker, claim = Path("/private-audit-fixture.json"), Path("/data") / checker.CLAIM_NAME
        marker_info = SimpleNamespace(st_mode=0o100400, st_uid=os.geteuid(), st_nlink=1, st_size=100)
        parent_info = SimpleNamespace(st_mode=0o40700, st_uid=os.geteuid())
        for repeat in (False, True):
            calls = [10, FileExistsError()] if repeat else [10, 11, 12]
            with patch.object(Path, "resolve", lambda value: value), patch.object(Path, "stat", return_value=parent_info), \
                    patch.object(checker.os, "open", side_effect=calls) as opened, \
                    patch.object(checker.os, "fstat", return_value=marker_info), \
                    patch.object(checker.os, "read", return_value=json.dumps(checker.MARKER).encode()), \
                    patch.object(checker.os, "close"), patch.object(checker.os, "fdopen", mock_open()), \
                    patch.object(checker.os, "fsync") as synced:
                if repeat:
                    with self.assertRaises(checker.CheckFailure):
                        checker.claim_fixture(marker, claim)
                    synced.assert_not_called()
                else:
                    checker.claim_fixture(marker, claim)
                    self.assertEqual(synced.call_count, 2)
                flags = opened.call_args_list[1].args[1]
                self.assertEqual(flags & (os.O_EXCL | os.O_NOFOLLOW), os.O_EXCL | os.O_NOFOLLOW)


if __name__ == "__main__":
    unittest.main(verbosity=2)
