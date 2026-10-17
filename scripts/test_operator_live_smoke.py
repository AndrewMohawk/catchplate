#!/usr/bin/env python3
"""Pure live-smoke guard tests; no network, catalog, containers or provider."""
from copy import deepcopy
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

try:
    from scripts import check_operator_live_smoke as smoke
except ModuleNotFoundError:
    import check_operator_live_smoke as smoke


POLICY = "sha256:" + "a" * 64
REQUEST = "sha256:" + "b" * 64
OPERATION = "sha256:" + "c" * 64
ATTEMPT = "sha256:" + "d" * 64
SCOPE = ("new-principal", "new-route", POLICY)
EXPECTED_PIN = "sha256:" + "f" * 64
OTHER_PIN = "sha256:" + "e" * 64
WITHHELD_REQUEST = "sha256:" + "1" * 64
WITHHELD_ATTEMPT = "sha256:" + "2" * 64
MARKERS = {"upstreamDispatch": "response_received", "providerOutcome": "unknown",
    "retryProviderRequest": False, "providerOperationMayHaveCommitted": True}


def catalog():
    value = {"proxy_url": "https://catchplate-proxy.example.com", "capabilities": {"credential_types": ["bearer"],
        "request_body_modes": ["preserve_json_v1"], "response_modes": ["unfiltered_json_or_empty_v2"],
        "credential_input_modes": ["replace_exact"]}, "limits": {}}
    for key in smoke.COLLECTIONS:
        value[key] = [{"id": key}]
        value["limits"][key] = {"active": 1, "active_max": 10, "retained": 1, "retained_max": 10}
    return value


def observed_catalog():
    value = catalog()
    value.update(revision=16, policy={"policy_hash": POLICY, "sequence": 7,
        "loaded_policy_hash": POLICY, "activation": "active"})
    value["observed_activity"] = {"schema": "catchplate.operatorAccountActivity/v1",
        "status": "available", "observed_at_epoch_ms": 1000, "chain_verification": "not_checked",
        "window": {"row_limit": 256, "event_byte_limit": 16384, "byte_limit": 2097152,
            "rows_scanned": 12, "bytes_read": 0, "has_older_rows": False,
            "byte_budget_exhausted": False, "oversized_events": 0, "invalid_events": 0,
            "unmatched_responses": 0, "incomplete": False},
        "accounts": [{"credential_id": "credentials", "last_successful_response": None,
            "last_refresh_success": None, "last_refresh_failure": None, "last_refresh_outcome": "unobserved"}]}
    return value


def response():
    document = {"method": "POST", "path": "/echo", "authorization_present": True,
        "authorization_scheme": "Bearer", "authorization_matches_expected": True,
        "proxy_authorization_seen": False, "query": {"_data_plane_token_seen": False, "_cookie_seen": False}}
    body = smoke.json.dumps(document).encode()
    headers = [("X-Catchplate-Policy-Hash", POLICY), ("X-Catchplate-Response-Body-SHA256", smoke.sha(body)),
               ("X-Catchplate-Request-Digest", REQUEST), ("X-Catchplate-Operation-Digest", OPERATION)]
    return document, headers, body


def audit_fixture():
    _, headers, body = response()
    positive = smoke.response_evidence("positive", 200, headers, body, POLICY)
    event = dict(zip(("principal_id", "route_id", "policy_hash"), SCOPE), method="POST", body_sha256=smoke.sha(smoke.BODY),
        request_digest=REQUEST, operation_digest=OPERATION, attempt_id=ATTEMPT, flow_id=ATTEMPT)
    rows = [{"id": "start", "event_type": smoke.START, "event": {**event, "outcome": "release_started"}},
            {"id": "release", "event_type": smoke.RELEASE, "event": {**event, "outcome": "released", "upstream_status": 200,
                "response_body_sha256": smoke.sha(body), "response_body_bytes": len(body),
                "response_validation": {"ok": True, "mode": "bufferedJsonOrEmpty204V2", "body_bytes_preserved": True}}}]
    rows.extend({"id": "connect" + str(number), "event_type": smoke.CONNECT, "event": {"principal_id": SCOPE[0],
        "policy_hash": POLICY, "method": "CONNECT", "target": smoke.AUTHORITY, "outcome": "established"}} for number in range(3))
    rows.extend({"id": case, "event_type": smoke.DENIED, "event": {"route_id": SCOPE[1], "method": "POST",
        "outcome": "denied", "error": reason}} for case, reason in smoke.ERRORS.items())
    return rows, positive


def withheld_response():
    return {"error": "response_credential_reflection", "upstream_status": 200, **MARKERS}


def withheld_audit_fixture():
    rows, positive = audit_fixture()
    withheld = smoke.response_evidence("withheld", 409, [], smoke.json.dumps(withheld_response()).encode(), POLICY)
    origin = b"https://demo-upstream:8443"
    event = dict(zip(("principal_id", "route_id", "policy_hash"), SCOPE), method="POST",
        body_sha256=smoke.sha(smoke.BODY), request_digest=WITHHELD_REQUEST, operation_digest=OPERATION,
        attempt_id=WITHHELD_ATTEMPT, flow_id=WITHHELD_ATTEMPT,
        url={"origin_sha256": smoke.sha(origin), "origin_bytes": len(origin),
            "path_sha256": smoke.sha(b"/echo"), "path_bytes": 5, "query_keys": []})
    rows.extend([
        {"id": "withheld-start", "event_type": smoke.START, "event": {**event, "outcome": "release_started"}},
        {"id": "withheld-block", "event_type": smoke.BLOCK, "event": {**event, "outcome": "blocked",
            "upstream_status": 200, "response_validation": {"ok": False, "error": "response_credential_reflection"}, **MARKERS}},
        {"id": "connect3", "event_type": smoke.CONNECT, "event": {"principal_id": SCOPE[0],
            "policy_hash": POLICY, "method": "CONNECT", "target": smoke.AUTHORITY, "outcome": "established"}},
    ])
    return rows, positive, withheld


def run_fixture(enabled, *, withheld_error=None, withheld_arrivals=1):
    """Exercise actual run ordering; every external boundary is synthetic."""
    check = smoke.LiveSmoke.__new__(smoke.LiveSmoke)
    check.check_withheld_response = enabled
    check.args = SimpleNamespace(expected_binary_sha256=EXPECTED_PIN, admin_token_file=Path("/not-read"))
    check.run_id, check.results, check.feature_observations, check.token_retained = "synthetic-run", [], [], False
    check.plans = [{"name": "synthetic-run-" + kind} for _, _, kind in smoke.CREATIONS]
    check.additions = {key: [] for key in smoke.COLLECTIONS}
    check.credential, check.client_token = "synthetic-test-secret", None
    check.clean = Mock()
    check.health, check.drained, check.audit = Mock(), Mock(return_value=True), Mock(return_value=[])
    initial = observed_catalog()
    current = deepcopy(initial)
    check.catalog = Mock(return_value=initial)
    check.wait_catalog_loaded = Mock(side_effect=lambda label: (initial if label == "live_baseline_loaded" else current, None))
    check.warm_cas_snapshot = Mock(side_effect=lambda: deepcopy(current))
    check.verify_audit = Mock(return_value={"syntheticAuditBoundary": True})
    calls, arrivals = [], [0]
    check.counts = Mock(side_effect=lambda: (100 + arrivals[0], arrivals[0]))

    def mutate(route, payload, **kwargs):
        calls.append(("mutation", route))
        collection = kwargs["collection"]
        record = {**payload, "id": "new-" + collection, "status": "active"}
        if collection == "applications": record["principal_id"] = SCOPE[0]
        if collection == "access_rules": record["route_id"] = SCOPE[1]
        current[collection].append(record)
        current["revision"] += 1
        if collection == "access_rules": current["policy"]["sequence"] += 1
        if collection == "credentials":
            current["observed_activity"]["accounts"].append({"credential_id": record["id"],
                "last_successful_response": None, "last_refresh_success": None,
                "last_refresh_failure": None, "last_refresh_outcome": "unobserved"})
        check.additions[collection].append(record["id"])
        return record, "synthetic-client-token" if collection == "applications" else None, {}

    def dispatch(dummy, *, withheld=False):
        calls.append(("dispatch", "withheld" if withheld else dummy))
        if withheld:
            arrivals[0] += withheld_arrivals
            if withheld_error is not None: raise withheld_error
            return 409, [], smoke.json.dumps(withheld_response()).encode()
        if dummy != smoke.DUMMY:
            code = smoke.ERRORS["missing" if dummy is None else "wrong"]
            return 403, [], smoke.json.dumps({"allowed": False, "action": "deny", "payload": {"error": code}}).encode()
        arrivals[0] += 1
        _, headers, body = response()
        return 200, headers, body

    check.mutate, check.dispatch = Mock(side_effect=mutate), Mock(side_effect=dispatch)
    return check, calls, current


class LiveSmokeTests(unittest.TestCase):
    def test_selected_v2_contract_requires_a_caller_supplied_pin(self):
        self.assertFalse(hasattr(smoke, "PIN"))
        self.assertEqual(smoke.RESPONSE_MODE, "unfiltered_json_or_empty_v2")
        self.assertEqual(smoke.RESPONSE_VALIDATION_MODE, "bufferedJsonOrEmpty204V2")
        self.assertEqual(smoke.CREATIONS, (("/credentials", "credentials", "credential"),
            ("/applications", "applications", "application"), ("/access-rules", "access_rules", "access_rule")))

    def test_capability_and_capacity_guards(self):
        value = catalog()
        smoke.preflight_catalog(value)
        for target in ("capability", "capacity", "proxy"):
            altered = deepcopy(value)
            if target == "capability": altered["capabilities"]["request_body_modes"] = []
            elif target == "capacity": altered["limits"]["credentials"]["retained"] = 10
            else: altered["proxy_url"] = "http://172.16.249.20:9090"
            with self.subTest(target=target), self.assertRaises(smoke.CheckFailure):
                smoke.preflight_catalog(altered)

    def test_v1_only_missing_or_malformed_response_capability_refused(self):
        for modes in (["unfiltered_json_or_empty_v1"], [], None, "unfiltered_json_or_empty_v2"):
            value = catalog()
            value["capabilities"]["response_modes"] = modes
            with self.subTest(modes=modes), self.assertRaises(smoke.CheckFailure):
                smoke.preflight_catalog(value)
        value = catalog()
        value["capabilities"]["response_modes"].insert(0, "unfiltered_json_or_empty_v1")
        smoke.preflight_catalog(value)  # Legacy capability may coexist, never be selected.

    def test_new_rule_payload_and_created_saved_contract_require_v2(self):
        expected = {"name": "synthetic-rule", "application_id": "synthetic-app", "credential_id": "synthetic-credential",
            "upstream_url": "https://" + smoke.AUTHORITY + "/echo", "methods": ["POST"],
            "request_fields": [], "response_fields": [], "request_body_mode": "preserve_json_v1",
            "response_mode": "unfiltered_json_or_empty_v2", "credential_input": "replace_exact", "placeholder": smoke.DUMMY,
            "query_keys": ["expectedAuthorizationSha256"], "allowed_headers": ["accept", "user-agent"]}
        self.assertEqual(smoke.access_rule_values("synthetic-rule", "synthetic-app", "synthetic-credential"), expected)
        smoke.require_rule_contract({**expected, "id": "new-rule", "status": "active"}, expected)
        for field, value in (("response_mode", "unfiltered_json_or_empty_v1"), ("response_mode", None),
                             ("request_body_mode", None), ("response_fields", ["allowed"]), ("placeholder", "wrong")):
            altered = {**expected, field: value}
            with self.subTest(field=field, value=value), self.assertRaises(smoke.CheckFailure):
                smoke.require_rule_contract(altered, expected)
        legacy = {**expected, "response_mode": "unfiltered_json_or_empty_v1"}
        with self.assertRaises(smoke.CheckFailure):
            smoke.require_rule_contract(legacy, legacy)

    def test_runtime_health_refuses_old_or_missing_binary_pin(self):
        check = smoke.LiveSmoke.__new__(smoke.LiveSmoke)
        check.args = SimpleNamespace(expected_binary_sha256=EXPECTED_PIN)
        check.management, check.management_ca = object(), None
        health = {"ok": True, "policy_shadow_serving_ready": True,
            "policy_shadow": {"mode": "operator-demo", "enabled": False, "readiness": False, "production_custody_bound": False},
            "data_plane_binary_digest": EXPECTED_PIN, "policy_trust_root_source": "attested-control-plane",
            "policy_signing_key_id": "synthetic-key", "connect_mitm_interceptor": True,
            "audit": {"enabled": True}, "release_authorization": {"enabled": False}}
        check.json_request = Mock(return_value=(200, health))
        self.assertEqual(check.health(), health)
        for pin in (OTHER_PIN, None):
            check.json_request.return_value = (200, {**health, "data_plane_binary_digest": pin})
            with self.subTest(pin=pin), self.assertRaises(smoke.CheckFailure):
                check.health()

    def test_all_existing_public_fields_and_resource_sets_preserved(self):
        before = {key: [{"id": "old-" + key, "version": 2, "status": "active"}] for key in smoke.COLLECTIONS}
        additions = {key: ["new-" + key] for key in smoke.COLLECTIONS}
        after = {key: before[key] + [{"id": additions[key][0]}] for key in smoke.COLLECTIONS}
        smoke.preserved_rows(before, after, additions)
        for mode in ("field", "removed", "extra"):
            changed = deepcopy(after)
            if mode == "field": changed["credentials"][0]["version"] = 3
            elif mode == "removed": changed["credentials"].pop(0)
            else: changed["credentials"].append({"id": "unexpected"})
            with self.subTest(mode=mode), self.assertRaises(smoke.CheckFailure):
                smoke.preserved_rows(before, changed, additions)

    def test_catalog_comparison_allows_only_readonly_activity_changes(self):
        before = observed_catalog()
        after = deepcopy(before)
        activity = after["observed_activity"]
        activity["observed_at_epoch_ms"] = 2000
        activity["window"].update(rows_scanned=15, bytes_read=500)
        activity["accounts"][0]["last_successful_response"] = {
            "event_id": ATTEMPT, "recorded_at_epoch_ms": 1500, "credential_version": 1,
            "application_id": "00000000-0000-4000-8000-000000000001",
            "rule_id": "00000000-0000-4000-8000-000000000002"}
        smoke.require_catalog_unchanged(before, after, "changed")
        self.assertNotEqual(before["observed_activity"], after["observed_activity"])
        self.assertIn("observed_activity", after)  # Comparison does not mutate its inputs.

    def test_catalog_comparison_rejects_every_other_root_or_resource_change(self):
        before = observed_catalog()
        changes = (
            lambda row: row["credentials"][0].update(status="revoked"),
            lambda row: row["applications"][0].update(token_generation=2),
            lambda row: row["access_rules"][0].update(methods=["DELETE"]),
            lambda row: row["policy"].update(policy_hash=OTHER_PIN),
            lambda row: row["policy"].update(loaded_policy_hash=None),
            lambda row: row.update(revision=17),
            lambda row: row["limits"]["credentials"].update(retained=2),
            lambda row: row["capabilities"].update(other=True),
            lambda row: row.update(proxy_url="https://other.example"),
            lambda row: row.update(unexpected_field=True),
        )
        for index, change in enumerate(changes):
            after = deepcopy(before)
            change(after)
            with self.subTest(index=index), self.assertRaises(smoke.CheckFailure):
                smoke.require_catalog_unchanged(before, after, "changed")

    def test_catalog_activity_exclusion_requires_exact_readonly_shape(self):
        changes = (
            lambda row: row.pop("observed_activity"),
            lambda row: row["observed_activity"].update(schema="other"),
            lambda row: row["observed_activity"].update(chain_verification="verified"),
            lambda row: row["observed_activity"].update(observed_at_epoch_ms=True),
            lambda row: row["observed_activity"].update(authority={}),
            lambda row: row["observed_activity"]["window"].update(row_limit=1000),
            lambda row: row["observed_activity"]["window"].update(incomplete=1),
            lambda row: row["observed_activity"]["accounts"][0].update(secret="not permitted"),
            lambda row: row["observed_activity"]["accounts"][0].update(credential_id="other"),
        )
        for index, change in enumerate(changes):
            after = observed_catalog()
            change(after)
            with self.subTest(index=index), self.assertRaises(smoke.CheckFailure):
                smoke.require_catalog_unchanged(observed_catalog(), after, "changed")

    def test_proxy_uses_system_trust_not_interception_ca(self):
        endpoint = SimpleNamespace(host="catchplate-proxy.example.com", scheme="https", port=443)
        with patch.object(smoke.ssl, "create_default_context", return_value="system-context") as create:
            self.assertEqual(smoke.LiveSmoke._optional_ca(None, endpoint), "system-context")
            create.assert_called_once_with()
            with self.assertRaises(smoke.CheckFailure):
                smoke.LiveSmoke._optional_ca(Path("/private/mitm-ca.pem"), endpoint)
        endpoint.scheme = "http"
        with self.assertRaises(smoke.CheckFailure): smoke.LiveSmoke._optional_ca(None, endpoint)

    def test_positive_injection_and_wire_commitments_required(self):
        document, headers, body = response()
        result = smoke.response_evidence("positive", 200, headers, body, POLICY)
        self.assertEqual(result["requestDigest"], REQUEST)
        self.assertEqual(result["responseMode"], "unfiltered_json_or_empty_v2")
        for field in ("authorization_matches_expected", "proxy_authorization_seen"):
            changed = deepcopy(document)
            changed[field] = not changed[field]
            with self.subTest(field=field), self.assertRaises(smoke.CheckFailure):
                smoke.response_evidence("positive", 200, headers, smoke.json.dumps(changed).encode(), POLICY)
        with self.assertRaises(smoke.CheckFailure):
            smoke.response_evidence("positive", 200, headers + [headers[0]], body, POLICY)

    def test_negative_requires_exact_placeholder_guard(self):
        for case, code in smoke.ERRORS.items():
            body = smoke.json.dumps({"allowed": False, "action": "deny", "payload": {"error": code}}).encode()
            self.assertEqual(smoke.response_evidence(case, 403, [], body, POLICY)["error"], code)
            with self.assertRaises(smoke.CheckFailure): smoke.response_evidence(case, 502, [], body, POLICY)
        with self.assertRaises(smoke.CheckFailure):
            smoke.response_evidence("missing", 403, [], b'{"allowed":false,"action":"deny","payload":{"error":"other"}}', POLICY)

    def test_one_audit_pair_three_connects_two_distinct_denials(self):
        rows, positive = audit_fixture()
        complete, counts, _, attempts = smoke.scoped_audit(rows, SCOPE, positive)
        self.assertTrue(complete)
        self.assertEqual(counts[smoke.CONNECT], 3)
        self.assertEqual(attempts, [ATTEMPT])
        self.assertNotIn(smoke.BLOCK, counts)  # Default receipt inventory remains unchanged.
        self.assertFalse(smoke.scoped_audit(rows[:-1], SCOPE, positive)[0])

    def test_audit_rejects_wrong_commitment_extra_release_or_block(self):
        for mode in ("commitment", "extra", "block"):
            rows, positive = audit_fixture()
            if mode == "commitment": rows[1]["event"]["request_digest"] = POLICY
            elif mode == "extra": rows.append(deepcopy(rows[1]))
            else: rows[1]["event_type"] = smoke.BLOCK
            with self.subTest(mode=mode), self.assertRaises(smoke.CheckFailure):
                smoke.scoped_audit(rows, SCOPE, positive)

    def test_release_audit_requires_exact_v2_mode_and_preserved_body_claim(self):
        for validation in ({"ok": True}, {"ok": True, "mode": "bufferedJsonOrEmpty204V1", "body_bytes_preserved": True},
                {"ok": True, "mode": "bufferedJsonOrEmpty204V2", "body_bytes_preserved": False},
                {"ok": True, "mode": "bufferedJsonOrEmpty204V2"},
                {"ok": False, "mode": "bufferedJsonOrEmpty204V2", "body_bytes_preserved": True}):
            rows, positive = audit_fixture()
            rows[1]["event"]["response_validation"] = validation
            with self.subTest(validation=validation), self.assertRaises(smoke.CheckFailure):
                smoke.scoped_audit(rows, SCOPE, positive)
        rows, positive = audit_fixture()
        positive["responseMode"] = "unfiltered_json_or_empty_v1"
        with self.assertRaises(smoke.CheckFailure):
            smoke.scoped_audit(rows, SCOPE, positive)

    def test_receipt_names_v2_and_keeps_echo_proof_limits(self):
        check = smoke.LiveSmoke.__new__(smoke.LiveSmoke)
        check.run_id, check.results, check.plans = "synthetic-run", [], []
        check.args = SimpleNamespace(expected_binary_sha256=EXPECTED_PIN)
        check.feature_observations, check.token_retained = [], False
        check.clean = Mock()
        for ok in (False, True):
            result = check.receipt(ok)
            self.assertEqual(result["dataPlaneBinaryDigest"], EXPECTED_PIN)
            self.assertEqual(result["responseMode"], "unfiltered_json_or_empty_v2")
            self.assertEqual(result["auditResponseMode"], "bufferedJsonOrEmpty204V2")
            for field in ("rawBodyPreservationVerified", "empty204Verified", "browserTransactionVerified",
                          "externalDnsVerified", "productionReady", "resourcesAutomaticallyCleaned"):
                self.assertIs(result[field], False)

    def test_existing_unrelated_audit_not_mistaken_for_smoke(self):
        rows, positive = audit_fixture()
        rows.append({"id": "old-user", "event_type": smoke.RELEASE, "event": {"principal_id": "existing-user"}})
        self.assertTrue(smoke.scoped_audit(rows, SCOPE, positive)[0])

    def test_no_execution_flag_prevents_network_constructor(self):
        with patch.object(smoke, "LiveSmoke") as constructor:
            result = smoke.run_checks(SimpleNamespace(execute=False, timeout_seconds=120,
                expected_binary_sha256=EXPECTED_PIN))
            self.assertFalse(result["ok"])
            constructor.assert_not_called()

    def test_missing_or_malformed_expected_pin_refuses_before_claim_or_constructor(self):
        inputs = [{}] + [{"expected_binary_sha256": value} for value in (
            None, "", "f" * 64, "sha256:" + "F" * 64, "sha256:" + "f" * 63,
            "sha256:" + "f" * 65, EXPECTED_PIN + "\n", 123)]
        for values in inputs:
            args = SimpleNamespace(execute=True, timeout_seconds=120,
                run_claim_file=Path("/private/.operator-live-smoke.claim"), **values)
            with self.subTest(values=values), patch.object(smoke, "LiveSmoke") as constructor, \
                    patch.object(smoke, "private_output") as claim:
                result = smoke.run_checks(args)
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"], "explicit expected binary SHA256 required")
                constructor.assert_not_called()
                claim.assert_not_called()

    def test_cli_expected_pin_is_mandatory(self):
        argv = ["check_operator_live_smoke.py", "--execute", "--admin-token-file", "/private/admin",
            "--ca-file", "/private/ca", "--upstream-ca-file", "/private/upstream-ca",
            "--run-claim-file", "/private/.operator-live-smoke.claim"]
        with patch("sys.argv", argv), patch("sys.stderr", new=StringIO()) as errors, \
                patch.object(smoke, "run_checks") as run, self.assertRaises(SystemExit) as caught:
            smoke.main()
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("--expected-binary-sha256", errors.getvalue())
        run.assert_not_called()

    def test_claim_durably_precedes_api_run(self):
        order = []
        check = Mock(run_id="run", plans=[{"name": "synthetic"}])
        check.run.side_effect = lambda: order.append("run") or {"ok": True}
        args = SimpleNamespace(execute=True, timeout_seconds=120, expected_binary_sha256=EXPECTED_PIN,
            run_claim_file=Path("/private/.operator-live-smoke.claim"))
        with patch.object(smoke, "LiveSmoke", return_value=check) as constructor, \
                patch.object(smoke, "private_output", side_effect=lambda *args: order.append("claim")), \
                patch.object(Path, "exists", return_value=False), patch.object(Path, "is_symlink", return_value=False):
            self.assertTrue(smoke.run_checks(args)["ok"])
        self.assertEqual(order, ["claim", "run"])
        constructor.assert_called_once_with(args)
        self.assertEqual(args.proxy_url, smoke.PROXY)
        self.assertEqual(args.expected_binary_sha256, EXPECTED_PIN)
        self.assertIsNone(args.proxy_ca_file)

    def test_uncertain_mutation_remains_named_and_is_not_retried(self):
        check = smoke.LiveSmoke.__new__(smoke.LiveSmoke)
        check.plans = [{"route": "/credentials", "collection": "credentials", "name": "declared-synthetic", "state": "not_submitted"}]
        with patch.object(smoke.OperatorCatalogCheck, "submit_mutation", side_effect=TimeoutError) as submit:
            with self.assertRaises(TimeoutError): check.submit_mutation({}, "/credentials", {"name": "declared-synthetic"})
            self.assertEqual(check.plans[0]["state"], "submitted_response_uncertain")
            with self.assertRaises(smoke.CheckFailure): check.submit_mutation({}, "/credentials", {"name": "declared-synthetic"})
            submit.assert_called_once()

    def test_one_time_token_only_written_to_private_sibling(self):
        check = smoke.LiveSmoke.__new__(smoke.LiveSmoke)
        check.plans = [{"route": "/applications", "collection": "applications", "name": "synthetic-app", "state": "not_submitted"}]
        check.additions, check.token_retained = {"applications": []}, False
        check.args = SimpleNamespace(run_claim_file=Path("/private/.operator-live-smoke.claim"))
        identifier, token = "00000000-0000-4000-8000-000000000001", "synthetic-one-time-token"
        with patch.object(smoke.OperatorCatalogCheck, "submit_mutation", return_value=({"id": identifier}, token, {})), \
                patch.object(smoke, "private_output") as output:
            check.submit_mutation({}, "/applications", {"name": "synthetic-app"})
            output.assert_called_once_with(Path("/private/.operator-live-smoke-client.token"), (token + "\n").encode())
        self.assertTrue(check.token_retained)
        self.assertNotIn(token, smoke.json.dumps(check.plans))

    def test_private_output_exclusive_0600_and_synced(self):
        info = SimpleNamespace(st_mode=0o40700, st_uid=smoke.os.geteuid())
        stream = MagicMock()
        stream.__enter__.return_value = stream
        stream.fileno.return_value = 7
        with patch.object(Path, "resolve", lambda path: path), patch.object(Path, "is_symlink", return_value=False), \
                patch.object(Path, "stat", return_value=info), patch.object(smoke.os, "open", side_effect=[7, 8]) as opened, \
                patch.object(smoke.os, "fdopen", return_value=stream), patch.object(smoke.os, "fsync") as synced, \
                patch.object(smoke.os, "close"):
            smoke.private_output(Path("/private/.operator-live-smoke-client.token"), b"synthetic\n")
        self.assertEqual(opened.call_args_list[0].args[2], 0o600)
        self.assertTrue(opened.call_args_list[0].args[1] & smoke.os.O_EXCL)
        self.assertTrue(opened.call_args_list[0].args[1] & smoke.os.O_NOFOLLOW)
        self.assertEqual([item.args[0] for item in synced.call_args_list], [7, 8])

    def test_withheld_rule_is_explicit_and_changes_only_owned_query_keys(self):
        original = smoke.access_rule_values("rule", "app", "credential")
        selected = smoke.access_rule_values("rule", "app", "credential", check_withheld_response=True)
        self.assertEqual(selected, {**original, "query_keys": ["expectedAuthorizationSha256", "reflectCredential"]})
        for value in (1, 0, None, "true"):
            with self.subTest(value=value), self.assertRaises(smoke.CheckFailure):
                smoke.access_rule_values("rule", "app", "credential", check_withheld_response=value)

    def test_withheld_wire_requires_exact_conflict_and_typed_unknown_outcome(self):
        value = withheld_response()
        observed = smoke.response_evidence("withheld", 409, [], smoke.json.dumps(value).encode(), POLICY)
        self.assertEqual({key: observed[key] for key in MARKERS}, MARKERS)
        for status in (200, 403, 502, 503):
            with self.subTest(status=status), self.assertRaises(smoke.CheckFailure):
                smoke.response_evidence("withheld", status, [], smoke.json.dumps(value).encode(), POLICY)
        changes = [(key, None) for key in value] + [("upstreamDispatch", "attempted"),
            ("providerOutcome", "committed"), ("retryProviderRequest", 0),
            ("providerOperationMayHaveCommitted", 1), ("upstream_status", 201),
            ("error", "other"), ("extra", "synthetic-secret-canary")]
        for key, wrong in changes:
            with self.subTest(key=key, wrong=wrong), self.assertRaises(smoke.CheckFailure):
                smoke.response_evidence("withheld", 409, [], smoke.json.dumps({**value, key: wrong}).encode(), POLICY)
        duplicate = (smoke.json.dumps(value)[:-1] + ',"retryProviderRequest":false}').encode()
        with self.assertRaises(smoke.CheckFailure):
            smoke.response_evidence("withheld", 409, [], duplicate, POLICY)

    def test_withheld_audit_requires_second_distinct_complete_pair(self):
        rows, positive, withheld = withheld_audit_fixture()
        complete, counts, _, attempts = smoke.scoped_audit(rows, SCOPE, positive, withheld)
        self.assertTrue(complete)
        self.assertEqual((counts[smoke.CONNECT], counts[smoke.DENIED], counts[smoke.START],
            counts[smoke.RELEASE], counts[smoke.BLOCK]), (4, 2, 2, 1, 1))
        self.assertEqual(attempts, sorted([ATTEMPT, WITHHELD_ATTEMPT]))
        with self.assertRaises(smoke.CheckFailure): smoke.scoped_audit(rows, SCOPE, positive)
        for missing in ("withheld-start", "withheld-block", "connect3"):
            self.assertFalse(smoke.scoped_audit([row for row in rows if row["id"] != missing], SCOPE, positive, withheld)[0])

    def test_withheld_audit_rejects_marker_coercion_wrong_scope_or_extra_effect(self):
        changes = [(key, None) for key in MARKERS] + [("retryProviderRequest", 0),
            ("providerOperationMayHaveCommitted", 1), ("upstreamDispatch", "attempted"),
            ("providerOutcome", "committed"), ("upstream_status", 201), ("outcome", "released"),
            ("request_digest", REQUEST), ("operation_digest", EXPECTED_PIN), ("attempt_id", ATTEMPT),
            ("flow_id", ATTEMPT), ("policy_hash", EXPECTED_PIN), ("body_sha256", EXPECTED_PIN),
            ("url", {}), ("response_validation", {"ok": False, "error": "other"}),
            ("response_validation", {"ok": 0, "error": "response_credential_reflection"})]
        for key, wrong in changes:
            rows, positive, withheld = withheld_audit_fixture()
            rows[-2]["event"][key] = wrong
            with self.subTest(key=key, wrong=wrong), self.assertRaises(smoke.CheckFailure):
                smoke.scoped_audit(rows, SCOPE, positive, withheld)
        for kind in (smoke.START, smoke.BLOCK, smoke.RELEASE):
            rows, positive, withheld = withheld_audit_fixture()
            duplicate = deepcopy(next(row for row in rows if row["event_type"] == kind))
            duplicate["id"] = "extra-effect"
            rows.append(duplicate)
            with self.subTest(kind=kind), self.assertRaises(smoke.CheckFailure):
                smoke.scoped_audit(rows, SCOPE, positive, withheld)

    def test_actual_run_keeps_default_order_and_adds_only_one_final_opt_in_request(self):
        for enabled in (False, True):
            check, calls, current = run_fixture(enabled)
            with self.subTest(enabled=enabled), patch.object(smoke, "token_file", return_value="synthetic-admin"), \
                    patch.object(smoke.features, "audit_cutoff", return_value={}), \
                    patch.object(smoke.features, "record_negative_phase") as negatives:
                result = check.run()
            expected = [("mutation", route) for route, _, _ in smoke.CREATIONS]
            expected += [("dispatch", dummy) for _, dummy in smoke.CASES]
            if enabled: expected.append(("dispatch", "withheld"))
            self.assertEqual(calls, expected)
            self.assertEqual(negatives.call_count, 2)
            self.assertEqual((result["upstreamDispatches"], result["responsesReleased"], result["responsesBlocked"]),
                (1 + int(enabled), 1, int(enabled)))
            self.assertEqual("withheldResponseCheckRequested" in result, enabled)
            self.assertEqual(current["revision"], 19)
            self.assertEqual(current["policy"]["sequence"], 8)
            self.assertEqual(check.mutate.call_count, 3)
            check.verify_audit.assert_called_once()

    def test_withheld_failure_is_not_retried_or_claimed_successful(self):
        original = TimeoutError("synthetic transport failure")
        check, calls, _ = run_fixture(True, withheld_error=original)
        with patch.object(smoke, "token_file", return_value="synthetic-admin"), \
                patch.object(smoke.features, "audit_cutoff", return_value={}), \
                patch.object(smoke.features, "record_negative_phase"), self.assertRaises(TimeoutError) as caught:
            check.run()
        self.assertIs(caught.exception, original)
        self.assertEqual(check.dispatch.call_count, 4)
        check.verify_audit.assert_not_called()
        receipt = check.receipt(False)
        self.assertIs(receipt["ok"], False)
        self.assertIs(receipt["withheldResponseCheckRequested"], True)
        self.assertNotIn("responsesBlocked", receipt)
        self.assertEqual(receipt["requestObservations"][-1], {"case": "withheld",
            "upstreamCountBefore": 101, "runCountBefore": 1, "upstreamCountAfter": 102, "runCountAfter": 2})
        self.assertEqual(calls[-1], ("dispatch", "withheld"))

    def test_withheld_count_must_increase_by_exactly_one(self):
        for count in (0, 2):
            check, _, _ = run_fixture(True, withheld_arrivals=count)
            with self.subTest(count=count), patch.object(smoke, "token_file", return_value="synthetic-admin"), \
                    patch.object(smoke.features, "audit_cutoff", return_value={}), \
                    patch.object(smoke.features, "record_negative_phase"), self.assertRaises(smoke.CheckFailure):
                check.run()
            self.assertEqual(check.dispatch.call_count, 4)
            check.verify_audit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
