#!/usr/bin/env python3
"""Pure live-smoke guard tests; no network, catalog, containers or provider."""
from copy import deepcopy
from io import BytesIO
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


def response():
    document = {"method": "POST", "path": "/echo", "authorization_present": True,
        "authorization_scheme": "Bearer", "authorization_matches_expected": True,
        "proxy_authorization_seen": False, "query": {"_data_plane_token_seen": False, "_cookie_seen": False}}
    body = smoke.json.dumps(document).encode()
    headers = [("X-Serverware-Policy-Hash", POLICY), ("X-Serverware-Response-Body-SHA256", smoke.sha(body)),
               ("X-Serverware-Request-Digest", REQUEST), ("X-Serverware-Operation-Digest", OPERATION)]
    return document, headers, body


def audit_fixture():
    _, headers, body = response()
    positive = smoke.response_evidence("positive", 200, headers, body, POLICY)
    event = dict(zip(("principal_id", "route_id", "policy_hash"), SCOPE), method="POST", body_sha256=smoke.sha(smoke.BODY),
        request_digest=REQUEST, operation_digest=OPERATION, attempt_id=ATTEMPT, flow_id=ATTEMPT)
    rows = [{"id": "start", "event_type": smoke.START, "event": {**event, "outcome": "release_started"}},
            {"id": "release", "event_type": smoke.RELEASE, "event": {**event, "outcome": "released", "upstream_status": 200,
                "response_body_sha256": smoke.sha(body), "response_body_bytes": len(body), "response_validation": {"ok": True}}}]
    rows.extend({"id": "connect" + str(number), "event_type": smoke.CONNECT, "event": {"principal_id": SCOPE[0],
        "policy_hash": POLICY, "method": "CONNECT", "target": smoke.AUTHORITY, "outcome": "established"}} for number in range(3))
    rows.extend({"id": case, "event_type": smoke.DENIED, "event": {"route_id": SCOPE[1], "method": "POST",
        "outcome": "denied", "error": reason}} for case, reason in smoke.ERRORS.items())
    return rows, positive


class LiveSmokeTests(unittest.TestCase):
    def test_capability_and_capacity_guards(self):
        value = {"proxy_url": "https://serverware-proxy.example.com", "capabilities": {"credential_types": ["bearer"],
            "request_body_modes": ["preserve_json_v1"], "response_modes": ["unfiltered_json_or_empty_v1"],
            "credential_input_modes": ["replace_exact"]}, "limits": {}}
        for key in smoke.COLLECTIONS:
            value[key] = [{"id": key}]
            value["limits"][key] = {"active": 1, "active_max": 10, "retained": 1, "retained_max": 10}
        smoke.preflight_catalog(value)
        for target in ("capability", "capacity", "proxy"):
            altered = deepcopy(value)
            if target == "capability": altered["capabilities"]["request_body_modes"] = []
            elif target == "capacity": altered["limits"]["credentials"]["retained"] = 10
            else: altered["proxy_url"] = "http://172.16.249.20:9090"
            with self.subTest(target=target), self.assertRaises(smoke.CheckFailure):
                smoke.preflight_catalog(altered)

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

    def test_proxy_uses_system_trust_not_interception_ca(self):
        endpoint = SimpleNamespace(host="serverware-proxy.example.com", scheme="https", port=443)
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
        self.assertFalse(smoke.scoped_audit(rows[:-1], SCOPE, positive)[0])

    def test_audit_rejects_wrong_commitment_extra_release_or_block(self):
        for mode in ("commitment", "extra", "block"):
            rows, positive = audit_fixture()
            if mode == "commitment": rows[1]["event"]["request_digest"] = POLICY
            elif mode == "extra": rows.append(deepcopy(rows[1]))
            else: rows[1]["event_type"] = smoke.BLOCK
            with self.subTest(mode=mode), self.assertRaises(smoke.CheckFailure):
                smoke.scoped_audit(rows, SCOPE, positive)

    def test_existing_unrelated_audit_not_mistaken_for_smoke(self):
        rows, positive = audit_fixture()
        rows.append({"id": "old-user", "event_type": smoke.RELEASE, "event": {"principal_id": "existing-user"}})
        self.assertTrue(smoke.scoped_audit(rows, SCOPE, positive)[0])

    def test_no_execution_flag_prevents_network_constructor(self):
        with patch.object(smoke, "LiveSmoke") as constructor:
            result = smoke.run_checks(SimpleNamespace(execute=False, timeout_seconds=120))
            self.assertFalse(result["ok"])
            constructor.assert_not_called()

    def test_claim_durably_precedes_api_run(self):
        order = []
        check = Mock(run_id="run", plans=[{"name": "synthetic"}])
        check.run.side_effect = lambda: order.append("run") or {"ok": True}
        args = SimpleNamespace(execute=True, timeout_seconds=120, run_claim_file=Path("/private/.operator-live-smoke.claim"))
        with patch.object(smoke, "LiveSmoke", return_value=check), \
                patch.object(smoke, "private_output", side_effect=lambda *args: order.append("claim")), \
                patch.object(Path, "exists", return_value=False), patch.object(Path, "is_symlink", return_value=False):
            self.assertTrue(smoke.run_checks(args)["ok"])
        self.assertEqual(order, ["claim", "run"])
        self.assertEqual(args.proxy_url, smoke.PROXY)
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


if __name__ == "__main__":
    unittest.main()
