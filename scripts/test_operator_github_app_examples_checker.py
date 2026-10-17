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


def pair(number, *, scope=SCOPE, generation=1):
    attempt = "sha256:" + format(number, "064x")
    common = dict(zip(("principal_id", "route_id", "policy_hash"), scope))
    common.update(attempt_id=attempt, flow_id=attempt, credential_ref="credential", credential_version=generation,
        method="GET", body_sha256=checker.digest(b""), request_digest=WIRE["requestDigest"], operation_digest=WIRE["operationDigest"])
    return [{"id": "start-" + str(number), "event_type": START, "event": {**common, "outcome": "release_started"}},
        {"id": "release-" + str(number), "event_type": RELEASE, "event": {**common, "outcome": "released",
            "upstream_status": 200, "response_body_sha256": WIRE["responseBodySha256"], "response_body_bytes": 10,
            "response_validation": {"ok": True, "body_bytes_preserved": True, "mode": "bufferedJsonOrEmpty204V2"}}}]


def success():
    completed = [{"client": c, "phase": "read_initial", "exitCode": 0} for c in checker.fixture.examples.CLIENTS]
    completed += [{"client": c, "phase": p, "exitCode": 1} for c in checker.fixture.examples.CLIENTS for p in ("wrong_app", "wrong_repo")]
    completed += [{"client": c, "phase": "read_renewed", "exitCode": 0} for c in checker.fixture.examples.CLIENTS]
    completed += [{"client": c, "phase": "read_rotated", "exitCode": 0} for c in checker.fixture.examples.CLIENTS]
    completed += [{"client": c, "phase": "revoked", "exitCode": 1} for c in checker.fixture.examples.CLIENTS]
    return {"schema": checker.SCHEMA, "ok": True, "syntheticOnly": True, "actualExampleEntrypoints": True,
        "realGithubVerified": False, "productionReady": False,
        "initialCredentialGeneration": 1, "replacementCredentialGeneration": 2,
        "failedReplacementPreserved": True, "assignmentsPreserved": True,
        "assignedApplicationIds": ["10000000-0000-0000-0000-000000000001", "10000000-0000-0000-0000-000000000002"],
        "assignedRuleIds": ["20000000-0000-0000-0000-000000000001", "20000000-0000-0000-0000-000000000002"],
        "leaseExpiryWait": {"sourceLeaseTtlUpperBoundMs": 5000, "minimumPostCommitWaitMs": 5250,
            "actualPostCommitWaitMonotonicNs": 5_250_000_000, "remoteInvalidationAcknowledged": False,
            "inFlightRequestsRecalled": False},
        "providerAttempts": 18, "provisioningAttempts": 10, "releases": 18, "deniedBeforeDispatch": 9,
        "auditAttemptIds": ["sha256:" + format(n, "064x") for n in range(18)],
        "dispatchLeaseIds": ["one", "two", "three", "four"], "replacementAuditEventIds": ["replacement"],
        "completed": completed, "dataPlaneBinaryDigest": "sha256:" + "1" * 64, "goExampleSha256": "2" * 64,
        "exampleSourceSha256": {k: "3" * 64 for k in checker.stock.SOURCE_FILES},
        "pythonTrust": "client-only-union-not-independent-roots", "namedAuditInventory": {
            START: 18, RELEASE: 18, checker.DENIED: 3, CONNECT_DENIED: 6, checker.RELOAD: 4, checker.REPLACED: 1,
            "operator_catalog.credential.github_app_created": 1, "operator_catalog.application.created": 3,
            "operator_catalog.access_rule.github_created": 2, "operator_catalog.access_rule.revoked": 2,
            LEASE: 4, checker.CONNECT: 21},
        "mints": [{"ordinal": n + 1, "issuedAt": issued, "expiresAt": expiry,
            "signingKey": "B" if n == 2 else "A", "selection": "name" if n == 0 else "id",
            "permissions": dict(checker.fixture.PERMISSIONS)}
            for n, (issued, expiry) in enumerate(((1000, 1120), (1122, 4722), (1123, 4723)))]}


def replacement_catalogs():
    before = {"revision": 6, "policy": {"policy_hash": SCOPE[2], "sequence": 3,
        "loaded_policy_hash": SCOPE[2], "activation": "active"}, "credentials": [{"id": "credential",
        "version": 1, "credential_generation": 1, "active_rule_count": 2, "github_app": {"repository_id": "900"},
        "status": "active", "future_field": {"preserved": True}}],
        "applications": [{"id": "app1"}, {"id": "app2"}], "access_rules": [{"id": "rule1"}, {"id": "rule2"}]}
    after = deepcopy(before); after["revision"] += 1
    after["credentials"][0].update(version=2, credential_generation=2, key_replaced_at="2026-10-12T00:00:00+00:00")
    return before, after


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

    def test_revocation_changes_only_exact_derived_count_not_credential_authority(self):
        before = {"id": "credential", "name": "synthetic App", "created_at": "2026-10-12T00:00:00Z",
            "status": "active", "revoked_at": None, "version": 1, "auth_type": "bearer",
            "header_name": "Authorization", "active_rule_count": 1, "credential_generation": 1,
            "connection_type": "github_app_v1", "provider_id": "github",
            "github_app": {"app_id": "123", "installation_id": "456", "account_id": "700",
                "repository_id": "900", "repository": {"owner": "catchplate-fixture", "name": "operator-demo"},
                "issues_permission": "read", "token_refresh": "automatic"},
            "future_public_field": {"retained": [1, "unchanged"]}}
        after = {**deepcopy(before), "active_rule_count": 0}
        original = deepcopy((before, after))
        checker.validate_revoked_credential(before, after)
        self.assertEqual((before, after), original)
        for side, value in (("before", 0), ("before", 2), ("before", True), ("before", 1.0),
                ("after", 1), ("after", False), ("after", 0.0), ("after", None)):
            left, right = deepcopy(original)
            (left if side == "before" else right)["active_rule_count"] = value
            with self.subTest(side=side, count=value), self.assertRaises(checker.CheckFailure):
                checker.validate_revoked_credential(left, right)
        for field, value in (("credential_generation", 2), ("credential_generation", True),
                ("credential_generation", 1.0), ("id", "other"), ("status", "revoked"),
                ("version", 2), ("version", True), ("name", "changed"), ("created_at", "changed"),
                ("revoked_at", "changed"), ("auth_type", "header"), ("header_name", "X-Other"),
                ("connection_type", "github_token_v1"), ("provider_id", "other"),
                ("github_app", {**before["github_app"], "repository_id": "901"}),
                ("github_app", {**before["github_app"], "issues_permission": "write"}),
                ("future_public_field", {"retained": [True, "unchanged"]})):
            changed = {**deepcopy(after), field: value}
            with self.subTest(field=field, value=value), self.assertRaises(checker.CheckFailure):
                checker.validate_revoked_credential(before, changed)
        for changed in ({k: v for k, v in after.items() if k != "future_public_field"},
                {**after, "unexpected": True}):
            with self.assertRaises(checker.CheckFailure): checker.validate_revoked_credential(before, changed)

    def test_empty_policy_retains_one_expired_sentinel_and_no_credential_or_active_grant(self):
        from catchplate import operator_demo, operator_demo_store
        with patch.object(operator_demo, "settings", return_value={"allowed_upstreams": ["https://api.github.com"]}):
            policy = operator_demo_store._build([], 3, "sha256:" + "a" * 64)
        self.assertEqual(policy["credentials"], [])
        self.assertEqual(policy["defaults"]["action"], "deny")
        self.assertEqual(policy["defaults"]["failMode"], "closed")
        self.assertEqual(len(policy["principals"]), 1)
        principal = policy["principals"][0]
        self.assertEqual(principal["id"], "agent:operator-demo:empty")
        self.assertEqual(principal["proxyAuthorization"]["tokenId"], "empty")
        self.assertEqual(principal["proxyAuthorization"]["expiresAtEpochMs"], 1)
        self.assertEqual(len(policy["routes"]), 1)
        route = policy["routes"][0]
        self.assertEqual(route["id"], "operator.empty")
        self.assertEqual(route["principals"], [principal["id"]])
        self.assertEqual(route["match"]["methods"], ["GET"])
        self.assertEqual(route["match"]["paths"], ["/__catchplate_operator_demo_unconfigured__"])
        self.assertNotIn("credentialRef", route)
        self.assertEqual(route["adapter"]["config"]["credentialMode"], "none")
        self.assertEqual(route["adapter"]["config"]["noCredentialProof"], {
            "credentialRefAbsent": True, "secretInjectionDisabled": True,
            "sensitiveHeadersForwarded": False, "authorizationForwarded": False})

    def test_final_audit_accepts_only_exact_one_route_reload_and_unchanged_authority(self):
        check = object.__new__(checker.AppExamplesCheck)
        check.initial_policy_hash = "sha256:" + "a" * 64
        check.args = SimpleNamespace(expected_binary_sha256="sha256:" + "b" * 64)
        revoked_hash = "sha256:" + "9" * 64
        second = ("principal2", "route2", SCOPE[2])
        rows, check.wire = [], []
        for number in range(18):
            scope = second if number % 6 >= 4 else SCOPE
            generation = 2 if number >= 12 else 1
            rows += pair(number + 1, scope=scope, generation=generation)
            check.wire.append({**WIRE, "scope": scope, "generation": generation})
        check.pairs = checker.match_pairs(rows, check.wire, None, "credential")
        check.mutations = [(checker.REPLACED, "credential", SCOPE[2])]
        check.lease_scopes = {SCOPE, second}
        for kind, count in ((checker.DENIED, 3), (CONNECT_DENIED, 6), (checker.CONNECT, 21)):
            rows += [{"id": kind + str(n), "event_type": kind, "event": {
                "target": "api.github.com:443", "principal_id": SCOPE[0], "policy_hash": SCOPE[2]}}
                for n in range(count)]
        rows += [{"id": "lease" + str(n), "event_type": LEASE, "event": {
            "outcome": "issued", "status_code": 200, **dict(zip(("principal_id", "route_id", "policy_hash"), scope)),
            "credential_id": "credential", "data_plane_binary_digest": check.args.expected_binary_sha256,
            "purpose": "dispatchSecret", "expected_credential_version": generation,
            "issued_at_epoch_ms": 1000, "expires_at_epoch_ms": 6000}}
            for n, (scope, generation) in enumerate((s, g) for s in (SCOPE, second) for g in (1, 2))]
        check.reloads = [(check.initial_policy_hash, "first", 2, 1), ("first", SCOPE[2], 3, 2),
            (SCOPE[2], "partial-revoke", 4, 1), ("partial-revoke", revoked_hash, 5, 1)]
        rows += [{"id": "replacement", "event_type": checker.REPLACED, "event": {
            "resource_id": "credential", "previous_credential_generation": 1, "credential_generation": 2,
            "policy_hash": SCOPE[2]}}]
        rows += [{"id": "reload" + str(n), "event_type": checker.RELOAD, "event":
            dict(zip(("previous_policy_hash", "policy_hash", "policy_sequence", "routes"), transition))}
            for n, transition in enumerate(check.reloads)]
        check.audit = Mock(return_value=rows)
        check.control_json = Mock(return_value={"ok": True, "complete": True})
        check.audit_drained = Mock(return_value=True)
        with patch.object(checker.features, "audit_cutoff", side_effect=lambda value: {r["id"]: r["id"] for r in value}):
            result = check.audit_result({}, SCOPE, {"id": "credential"}, revoked_hash)
            self.assertEqual(len(result["auditAttemptIds"]), 18)
            check.control_json.assert_called_once_with("/api/audit/verify?limit=1000", authenticated=True)
            for field, value in (("routes", 0), ("routes", 2), ("policy_hash", SCOPE[2]),
                    ("previous_policy_hash", check.initial_policy_hash)):
                changed = deepcopy(rows)
                changed[-1]["event"][field] = value
                check.audit.return_value = changed
                with self.subTest(field=field, value=value), self.assertRaises(checker.CheckFailure):
                    check.audit_result({}, SCOPE, {"id": "credential"}, revoked_hash)
            for kind in ("lease_ttl", "missing_scope", "wrong_generation", "extra_replacement", "wrong_replacement"):
                changed = deepcopy(rows)
                lease = next(r for r in changed if r["event_type"] == LEASE)
                if kind == "lease_ttl": lease["event"]["expires_at_epoch_ms"] += 1
                elif kind == "missing_scope": changed.remove(lease)
                elif kind == "wrong_generation": lease["event"]["expected_credential_version"] = True
                elif kind == "extra_replacement": changed.append(next(r for r in changed if r["event_type"] == checker.REPLACED))
                else: next(r for r in changed if r["event_type"] == checker.REPLACED)["event"]["credential_generation"] = 3
                check.audit.return_value = changed
                with self.subTest(kind=kind), self.assertRaises(checker.CheckFailure):
                    check.audit_result({}, SCOPE, {"id": "credential"}, revoked_hash)

    def test_generation_aware_canonical_oracle_matches_retained_v1_and_separates_v2(self):
        row = {"target": checker.fixture.examples.target("node", 1), "semanticHeaders": {"accept": "application/vnd.github+json"}}
        first = checker.canonical_digests(row, SCOPE, "credential", "127.0.0.1", 1)
        self.assertEqual(first, checker.stock.canonical_digests(row, SCOPE, "credential", "127.0.0.1"))
        second = checker.canonical_digests(row, SCOPE, "credential", "127.0.0.1", 2)
        self.assertTrue(all(a != b for a, b in zip(first, second)))
        for bad in (True, 0, 3, "2"):
            with self.assertRaises(checker.CheckFailure): checker.canonical_digests(row, SCOPE, "credential", "127.0.0.1", bad)
        wire = [{**WIRE, "scope": SCOPE, "generation": 2}]
        self.assertEqual(len(checker.match_pairs(pair(1, generation=2), wire, None, "credential")), 1)
        with self.assertRaises(checker.CheckFailure): checker.match_pairs(pair(1), wire, None, "credential")

    def test_replacement_preserves_every_binding_assignment_policy_and_unknown_field(self):
        before, after = replacement_catalogs()
        checker.validate_replacement(before, after, "credential")
        for kind in ("revision", "policy", "application", "rule", "binding", "generation", "version", "count", "future", "time", "extra"):
            changed = deepcopy(after)
            if kind == "revision": changed["revision"] += 1
            elif kind == "policy": changed["policy"]["sequence"] += 1
            elif kind == "application": changed["applications"][0]["token_generation"] = 2
            elif kind == "rule": changed["access_rules"].pop()
            elif kind == "binding": changed["credentials"][0]["github_app"]["repository_id"] = "901"
            elif kind == "generation": changed["credentials"][0]["credential_generation"] = True
            elif kind == "version": changed["credentials"][0]["version"] = 3
            elif kind == "count": changed["credentials"][0]["active_rule_count"] = 1
            elif kind == "future": changed["credentials"][0]["future_field"] = None
            elif kind == "time": changed["credentials"][0]["key_replaced_at"] = "2026-10-12"
            else: changed["unexpected"] = True
            with self.subTest(kind=kind), self.assertRaises((checker.CheckFailure, ValueError)):
                checker.validate_replacement(before, changed, "credential")
        final = deepcopy(after["credentials"][0]); final["active_rule_count"] = 0
        checker.validate_revoked_credential(after["credentials"][0], final, generation=2, active_rules=2)

    def test_failed_candidate_is_one_post_no_mint_no_catalog_or_mutation_audit_change(self):
        before, _ = replacement_catalogs()
        observed = {"auth": [1, 2, 3], "mints": [1], "attempts": []}
        for kind in ("none", "status", "binding", "mint", "audit"):
            check = object.__new__(checker.AppExamplesCheck)
            check.control, check.control_ca, check.policy_hash, check.replacement_pem = None, None, SCOPE[2], "PRIVATE-CANARY"
            after = deepcopy(before)
            if kind == "binding": after["credentials"][0]["github_app"]["repository_id"] = "901"
            check.warm_cas_snapshot = Mock(side_effect=[before, after])
            check.observe = Mock(side_effect=[observed, {**observed, "auth": [1, 2, 3, 4], "mints": [1, 2] if kind == "mint" else [1]}])
            check.audit = Mock(side_effect=[[], [{"id": "unexpected", "event_type": checker.REPLACED}] if kind == "audit" else []])
            check.json_request = Mock(return_value=(409 if kind == "status" else 503,
                {"detail": "GitHub App verification failed; check app, installation and repository permissions"}))
            with patch.object(checker.features, "audit_cutoff", side_effect=lambda rows: {r["id"]: r for r in rows}):
                if kind == "none": check.failed_replacement("credential")
                else:
                    with self.assertRaises(checker.CheckFailure): check.failed_replacement("credential")
            self.assertEqual(check.json_request.call_count, 1)
            call = check.json_request.call_args
            self.assertEqual(call.args[1], "/api/operator-demo/credentials/github-app/replace-key")
            self.assertEqual(call.kwargs["method"], "POST")
            self.assertEqual(set(call.kwargs["payload"]), {"id", "expected_revision", "expected_policy_hash",
                "expected_credential_generation", "private_key_pem"})

    def test_replacement_real_submit_once_then_fresh_join_and_original_deadline_wait(self):
        before, after = replacement_catalogs()
        check = object.__new__(checker.AppExamplesCheck)
        check.control, check.control_ca, check.replacement_pem = None, None, "PRIVATE-CANARY"
        check.mutations, check.policy_hash, check.clean = [], SCOPE[2], Mock()
        check.warm_cas_snapshot = Mock(side_effect=[before, after])
        receipt = {"credential": after["credentials"][0], "revision": after["revision"], "policy": after["policy"],
            "key_replacement": {"previous_credential_generation": 1, "credential_generation": 2,
                "cache_invalidation": "local_completed", "in_flight_requests": "not_recalled"}}
        check.json_request = Mock(return_value=(200, receipt)); check.unchanged = Mock()
        now = [0.0]
        check.timeout = Mock(return_value=4.0)
        def sleep(seconds):
            self.assertGreater(seconds, 0); self.assertLessEqual(seconds, 0.25); now[0] += seconds
        with patch.object(checker.time, "monotonic", side_effect=lambda: now[0]), patch.object(checker.time, "sleep", side_effect=sleep):
            self.assertEqual(check.replace_and_wait("credential"), after)
        self.assertEqual(check.json_request.call_count, 1)
        self.assertEqual(now[0], 5.25)
        self.assertEqual(check.mutations, [(checker.REPLACED, "credential", SCOPE[2])])
        check.unchanged.assert_called_once_with(after)
        self.assertIs(check.wait_evidence["inFlightRequestsRecalled"], False)
        check.warm_cas_snapshot = Mock(return_value=before)
        original = checker.CheckFailure("fixed uncertain transport")
        check.json_request.reset_mock(); check.json_request.side_effect = original
        with patch.object(checker.time, "sleep") as slept, self.assertRaises(checker.CheckFailure) as caught:
            check.replace_and_wait("credential")
        self.assertIs(caught.exception, original); slept.assert_not_called()
        self.assertEqual(check.json_request.call_count, 1)

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
        for kind in ("old_key", "generation", "assignment", "wait", "recall", "failed_candidate", "replacement_audit", "inventory", "mint_scope"):
            changed = deepcopy(value)
            if kind == "old_key": changed["mints"][2]["signingKey"] = "A"
            elif kind == "generation": changed["replacementCredentialGeneration"] = 1
            elif kind == "assignment": changed["assignedApplicationIds"][1] = changed["assignedApplicationIds"][0]
            elif kind == "wait": changed["leaseExpiryWait"]["actualPostCommitWaitMonotonicNs"] -= 1
            elif kind == "recall": changed["leaseExpiryWait"]["inFlightRequestsRecalled"] = True
            elif kind == "failed_candidate": changed["failedReplacementPreserved"] = False
            elif kind == "replacement_audit": changed["replacementAuditEventIds"] = []
            elif kind == "inventory": changed["namedAuditInventory"].pop(CONNECT_DENIED)
            else: changed["mints"][2]["permissions"]["issues"] = "write"
            with self.subTest(kind=kind), self.assertRaises(checker.CheckFailure): checker.validate_success_result(changed)


if __name__ == "__main__":
    unittest.main()
