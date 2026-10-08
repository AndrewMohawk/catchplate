#!/usr/bin/env python3
"""Pure/mocked acceptance-harness tests: no sockets, containers or fixture data."""
from copy import deepcopy
from collections import Counter
import ast
import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, mock_open, patch

try:
    from scripts import check_operator_catalog as checker
    from scripts import prepare_operator_catalog_fixture as fixture
    from scripts import operator_catalog_feature_checks as features
except ModuleNotFoundError:
    import check_operator_catalog as checker
    import prepare_operator_catalog_fixture as fixture
    import operator_catalog_feature_checks as features


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
        return rows, Counter(scopes)

    def test_reflection_terminal_pairs_are_distinct_from_success(self):
        rows, needed = self.audit_fixture()
        scope = ("features", "rule3", "policy4")
        needed[scope] = 1
        blocked = Counter({scope: 2})
        for number, outcome in ((7, "released"), (8, "blocked"), (9, "blocked")):
            attempt = "sha256:" + str(number) * 64
            for terminal in (False, True):
                event = dict(zip(("principal_id", "route_id", "policy_hash"), scope))
                event.update(attempt_id=attempt, flow_id=attempt, method="GET",
                    outcome=outcome if terminal else "release_started")
                if terminal:
                    event["upstream_status"] = 200
                    if outcome == "blocked":
                        event["response_validation"] = {"ok": False, "error": "response_credential_reflection"}
                kind = "response." + outcome if terminal else "credential.release_started"
                rows.append({"id": len(rows) + 1, "event_type": "data_plane." + kind, "event": event})
        actual, pairs = features.release_attempt_pairs(rows, needed, blocked)
        self.assertEqual(actual, needed)
        self.assertEqual(len(pairs), 9)
        self.assertEqual(sum(pair["outcome"] == "blocked" for pair in pairs.values()), 2)
        with self.assertRaises(checker.CheckFailure):
            features.release_attempt_pairs(rows, needed)  # Blocked responses cannot stand in for a success.
        rows[-1]["event"]["response_validation"]["error"] = "other-error"
        with self.assertRaises(checker.CheckFailure):
            features.release_attempt_pairs(rows, needed, blocked)

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


class FeatureTests(unittest.TestCase):
    def test_full_json_and_decoded_only_oracles(self):
        authorization = "Bearer synthetic-operator-" + "A" * 40
        self.assertEqual(features.fixture_body("full", authorization, matched=True, proxy_seen=False), features.FULL_JSON)
        self.assertNotEqual(features.fixture_body("full", authorization, matched=False, proxy_seen=False), features.FULL_JSON)
        self.assertNotEqual(features.fixture_body("full", authorization, matched=True, proxy_seen=True), features.FULL_JSON)
        raw = features.fixture_body("reflect_raw", authorization, matched=True, proxy_seen=False)
        decoded = features.fixture_body("reflect_decoded", authorization, matched=True, proxy_seen=False)
        self.assertIn(authorization.encode(), raw)
        self.assertNotIn(authorization.encode(), decoded)
        self.assertEqual(json.loads(decoded)["credential_reflection"], authorization)
        for case in ("reflect_raw", "reflect_decoded"):
            with self.assertRaises(checker.CheckFailure):
                features.fixture_body(case, "Bearer not-a-synthetic-key", matched=True, proxy_seen=False)

    def test_fixture_echo_defaults_unchanged_and_new_cases_opt_in(self):
        tree = ast.parse((SOURCE / "scripts/demo_upstream.py").read_text())
        function = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef) and node.name == "echo")
        function.decorator_list, function.returns = [], None
        function.args.args[0].annotation = None
        authorization = "Bearer synthetic-operator-" + "A" * 40
        digest = "sha256:" + features.hashlib.sha256(authorization.encode()).hexdigest()
        record = Mock()
        class Response:
            def __init__(self, *, content, media_type):
                self.body, self.media_type = content, media_type
        context = {"_record_request": record, "request_view": lambda request: {"method": "GET", "path": "/echo",
            "query": dict(request.query_params), "authorization": authorization, "authorization_sha256": digest},
            "hashlib": features.hashlib, "hmac": __import__("hmac"), "Response": Response}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "fixture-echo-only", "exec"), context)
        for case in (None, "unknown", "full", "reflect_raw", "reflect_decoded"):
            query = {"expectedAuthorizationSha256": digest}
            if case is not None:
                query["catalogProof"] = case
            request = SimpleNamespace(headers={}, query_params=query)
            value = asyncio.run(context["echo"](request))
            if case in {None, "unknown"}:
                self.assertIsInstance(value, dict)
                self.assertNotIn("credential_reflection", value)
                self.assertNotIn("authorization", value)
            else:
                self.assertEqual(value.media_type, "application/json")
                self.assertEqual(value.body, features.fixture_body(case, authorization, matched=True, proxy_seen=False))
        self.assertEqual(record.call_count, 5)

    def feature_fixture(self):
        value = SimpleNamespace(run_id="operator-check-test", credential="synthetic-operator-" + "A" * 40,
            policy_hash="sha256:" + "a" * 64, successes=[], mutations=[], results=[], dispatches=6,
            args=SimpleNamespace(expected_binary_sha256="sha256:" + "b" * 64))
        credential = {"id": "credential1", "version": 1}
        def mutate(route, payload, **_):
            if route == "/applications":
                return {"id": "app3", "principal_id": "principal3"}, "one-time-token", {}
            self.assertEqual(payload["allowed_headers"], ["accept", "user-agent"])
            self.assertEqual(payload["credential_input"], "replace_exact")
            return {**payload, "id": "rule3", "route_id": "operator.rule3"}, None, {}
        value.mutate, value.wait_catalog_loaded = mutate, Mock()
        value.count, value.audit = lambda: value.dispatches, lambda: []
        value.catalog = lambda: {"credentials": [credential]}
        value.resource = lambda *_: {**credential, "status": "active", "active_rule_count": 2}
        seen = []
        def request(check, path, supplied):
            seen.append((path, supplied))
            if supplied != "Bearer serverware-placeholder-operator-check-test":
                code = "credential_existing_header_missing" if supplied is None else "credential_existing_header_mismatch"
                return 403, {"allowed": False, "action": "deny", "payload": {"error": code}}, b"{}"
            value.dispatches += 1
            if "catalogProof=full" in path:
                return 200, json.loads(features.FULL_JSON), features.FULL_JSON
            return 502, {"error": "response_credential_reflection"}, b'{"error":"response_credential_reflection"}'
        return value, credential, seen, request

    def test_feature_phase_has_three_dispatches_two_denials_and_no_header_allowlist_bypass(self):
        value, credential, seen, request = self.feature_fixture()
        with patch.object(features, "request", side_effect=request), patch.object(features, "checkpoint") as checkpoint:
            self.assertEqual(features.run_features(value, credential), ("app3", "rule3"))
        self.assertEqual(value.dispatches, 9)
        self.assertEqual(len(seen), 5)
        self.assertEqual(len(value.successes), 1)
        self.assertEqual(len(value.blocked_responses), 2)
        self.assertEqual(len(value.negative_observations), 2)
        self.assertEqual([call.args[1] for call in checkpoint.call_args_list], ["negative-phase", "features"])

    def test_denial_with_no_dispatch_or_release_start_but_scoped_lease_fails(self):
        value, credential, seen, request = self.feature_fixture()
        value.audit = lambda: [{"id": "lease-row", "event_hash": "sha256:" + "c" * 64,
            "event_type": "data_plane.credential_lease.issued", "event": {
                "purpose": "dispatchSecret", "principal_id": "principal3", "route_id": "operator.rule3",
                "credential_id": credential["id"], "policy_hash": value.policy_hash,
                "data_plane_binary_digest": value.args.expected_binary_sha256}}]
        with patch.object(features, "request", side_effect=request), patch.object(features, "checkpoint"), \
                self.assertRaisesRegex(checker.CheckFailure, "scoped dispatchSecret credential lease"):
            features.run_features(value, credential)
        self.assertEqual(len(seen), 1)
        self.assertEqual(value.dispatches, 6)
        self.assertEqual(value.negative_observations[0]["issuedLeaseAuditEventIds"], ["lease-row"])

    def test_negative_cutoff_reconciliation_uses_exact_rows_not_uuid_order(self):
        scope = {"purpose": "dispatchSecret", "principal_id": "principal3", "route_id": "operator.rule3",
            "credential_id": "credential1", "policy_hash": "sha256:" + "a" * 64,
            "data_plane_binary_digest": "sha256:" + "b" * 64}
        sibling = {"id": "ffffffff-row", "event_hash": "sha256:" + "c" * 64,
            "event_type": "data_plane.credential_lease.issued", "event": {**scope, "principal_id": "sibling"}}
        value = SimpleNamespace(negative_observations=[], audit=lambda: [sibling])
        features.record_negative_phase(value, "credential_existing_header_missing", scope)
        later = {"id": "00000000-row", "event_hash": "sha256:" + "d" * 64,
            "event_type": "data_plane.credential_lease.issued", "event": scope}
        features.reconcile_negative_phases(value, [sibling, later])
        with self.assertRaisesRegex(checker.CheckFailure, "appeared in the final audit chain"):
            features.reconcile_negative_phases(value, [{**sibling, "event": scope}, later])
        with self.assertRaisesRegex(checker.CheckFailure, "did not survive"):
            features.reconcile_negative_phases(value, [later])
        with self.assertRaisesRegex(checker.CheckFailure, "saturated"):
            features.audit_cutoff([sibling] * 500)

    def test_failure_counters_remain_strict_and_safe_evidence_survives(self):
        value = AcceptanceTests().check()
        value.successes, value.mutations, value.observations = [], [], []
        value.warm_observations = [{"capturedAtEpochMs": 1000, "denialVerifiedAtEpochMs": 1500}]
        value.audit = Mock(return_value=[])
        value.health = Mock(return_value={"audit": {"dropped": 0, "required_failed": 0, "send_failed": 3,
            "unexpected": "must-not-copy"}})
        with self.assertRaises(checker.CheckFailure):
            features.verify_audit(value)
        saved = features.safe_evidence(value)
        self.assertEqual(saved["auditCounters"]["send_failed"], 3)
        self.assertNotIn("unexpected", saved["auditCounters"])
        self.assertEqual(saved["warmLeaseInvalidations"], value.warm_observations)

    def test_observation_checkpoint_is_exclusive_fsynced_and_does_not_claim_acceptance(self):
        value = AcceptanceTests().check()
        value.args = SimpleNamespace(run_claim_file=Path("/data/.operator-catalog-acceptance.claim"))
        info = SimpleNamespace(st_mode=0o40700, st_uid=os.geteuid())
        opened_file = mock_open()
        with patch.object(Path, "stat", return_value=info), patch.object(Path, "resolve", lambda path: path), \
                patch.object(features.os, "open", side_effect=[10, 11]) as opened, \
                patch.object(features.os, "fdopen", opened_file), patch.object(features.os, "fsync") as synced, \
                patch.object(features.os, "close"):
            features.checkpoint(value, "lifecycle")
        self.assertEqual(synced.call_count, 2)
        self.assertTrue(opened.call_args_list[0].args[1] & os.O_EXCL)
        body = "".join(call.args[0] for call in opened_file().write.call_args_list)
        self.assertFalse(json.loads(body)["acceptanceComplete"])

    def test_diagnostic_parser_only_returns_fixed_safe_categories(self):
        line = ("audit_post_failure phase=initial stage=snapshot_changed outcome=outcome_unknown "
            "status=200 event_count=2 elapsed_ms=50 same_snapshot=false same_policy_sequence=false")
        self.assertEqual(features.parse_diagnostic(line)["stage"], "snapshot_changed")
        for invalid in (line + " raw-secret", line.replace("snapshot_changed", "raw-secret"),
                        line.replace("status=200", "status=raw-secret"), line + " phase=retry", "unrelated log"):
            self.assertIsNone(features.parse_diagnostic(invalid))


if __name__ == "__main__":
    unittest.main(verbosity=2)
