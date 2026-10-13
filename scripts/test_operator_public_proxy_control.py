#!/usr/bin/env python3
"""Inert controller contracts: real local receipts/oracles, simulated API only.

No sockets, subprocesses, database/custody activation or live acceptance.
"""
from copy import deepcopy
import ast
import inspect
import json
import os
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import operator_public_proxy_control as control
from scripts import check_operator_public_proxy as client


def offline(event, _):
    if event.startswith("socket.") or event in {"subprocess.Popen", "os.system", "os.posix_spawn"}:
        raise RuntimeError("Network and subprocesses forbidden")


sys.addaudithook(offline)
APP = "11111111-1111-4111-8111-111111111111"
RULE = "33333333-3333-4333-8333-333333333333"
H = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64


def baseline():
    return {"credentials": [{"id": control.CREDENTIAL, "name": control.CREDENTIAL_NAME, "status": "active", "active_rule_count": 1}],
        "applications": [], "access_rules": [], "allowed_upstreams": control.ORIGINS, "proxy_url": control.smoke.PROXY,
        "revision": 81, "policy": {"policy_hash": H, "sequence": 31}}


def owned():
    value = deepcopy(baseline())
    value["credentials"][0]["active_rule_count"] = 2
    value["applications"] = [{"id": APP, "name": "new-app", "status": "active", "version": 1}]
    value["access_rules"] = [{"id": RULE, "name": "new-rule", "status": "active", "version": 1}]
    value.update(revision=83, policy={"policy_hash": H2, "sequence": 32})
    return value


def audit_input():
    config = {"run_id": "public-proxy-" + "a" * 32, "application_id": APP, "credential_id": control.CREDENTIAL,
        "rule_id": RULE, "policy_hash": H, "ca_sha256": H2}
    result = {"schema": "serverware.publicProxySmokeResult/v1", "ok": True, "mode": "positive", **config,
        "peer": "203.0.113.10", "connect_status": 200, "http_status": 200, "proxy_tls_verify_result": 0,
        "request_digest": "sha256:" + "3" * 64, "operation_digest": "sha256:" + "4" * 64,
        "response_body_sha256": "sha256:" + "5" * 64, "response_body_bytes": 200}
    scope = {"principal_id": "agent:operator-demo:" + APP, "route_id": "operator." + RULE, "policy_hash": H}
    event = {**scope, "attempt_id": H2, "flow_id": H2, "method": "POST", "credential_ref": control.CREDENTIAL,
        "credential_version": 1, "body_sha256": control.smoke.sha(control.BODY), "request_digest": result["request_digest"],
        "operation_digest": result["operation_digest"], "outcome": "release_started"}
    release = {**event, "outcome": "released", "upstream_status": 200, "response_body_sha256": result["response_body_sha256"],
        "response_body_bytes": 200, "response_validation": {"ok": True, "mode": control.smoke.RESPONSE_VALIDATION_MODE, "body_bytes_preserved": True}}
    lease = {**scope, "purpose": "dispatchSecret", "credential_id": control.CREDENTIAL, "expected_credential_version": 1,
        "outcome": "issued", "status_code": 200, "data_plane_binary_digest": control.BINARY}
    events = [{"id": "start", "event_type": control.smoke.START, "event": event},
        {"id": "release", "event_type": control.smoke.RELEASE, "event": release},
        {"id": "lease", "event_type": control.smoke.LEASE, "event": lease}]
    return config, result, events


class ControllerControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.job = Path(self.temp.name).resolve()
        self.owner = control.Control.__new__(control.Control)
        self.owner.job, self.owner.run_id = self.job, "public-proxy-" + "a" * 32
        self.owner.issued_tokens = []
        self.owner.credential = self.owner.client_token = self.owner.wrong_token = self.owner.admin_token = None

    def test_actual_client_literals_and_result_roster(self):
        self.assertEqual(control.BODY, client.BODY)
        self.assertEqual(control.DUMMY, client.DUMMY)
        config, result, events = audit_input()
        self.assertEqual(set(result), control.RESULT_FIELDS)
        self.assertEqual(control.join_result(config, result, events, 1)["event_ids"], ["start", "release", "lease"])

    def test_private_exclusive_receipts_and_unsafe_files(self):
        self.owner.save("receipt.json", {"ok": True})
        self.assertEqual((self.job / "receipt.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.owner.load("receipt.json"), {"ok": True})
        with self.assertRaises(FileExistsError):
            self.owner.save("receipt.json", {"ok": False})
        os.link(self.job / "receipt.json", self.job / "hardlink")
        with self.assertRaises(control.smoke.CheckFailure):
            self.owner.load("receipt.json")
        (self.job / "link").symlink_to(self.job / "receipt.json")
        with self.assertRaises(control.smoke.CheckFailure):
            self.owner.load("link")

    def test_preserves_all_prior_rows_only_exact_derived_counter(self):
        before, after = baseline(), owned()
        control.preserve(before, after, APP, RULE)
        for collection, field, value in (("credentials", "name", "changed"), ("credentials", "active_rule_count", 3)):
            bad = deepcopy(after)
            bad[collection][0][field] = value
            with self.assertRaises(control.smoke.CheckFailure):
                control.preserve(before, bad, APP, RULE)
        after["access_rules"][0]["status"] = "revoked"
        after["credentials"][0]["active_rule_count"] = 1
        control.preserve(before, after, APP, RULE)
        after["credentials"].append({"id": "unplanned"})
        with self.assertRaises(control.smoke.CheckFailure):
            control.preserve(before, after, APP, RULE)

    def test_real_cas_helper_claims_before_send_and_never_replays(self):
        before = baseline()
        resource = {"id": APP, "version": 1}
        reply = {"application": resource, "client_token": "t" * 43, "revision": 82, "policy": before["policy"]}
        current = {**before, "revision": 82, "applications": [resource]}
        calls = []
        def api(*args, **kwargs):
            self.assertEqual(self.owner.load("create-app.claim.json")["revision"], 81)
            self.assertEqual(kwargs["payload"]["expected_revision"], 81)
            self.assertEqual(kwargs["payload"]["expected_policy_hash"], H)
            calls.append(kwargs)
            return 201, deepcopy(reply)
        self.owner.control = object()
        self.owner.control_ca = None
        self.owner.json_request = api
        self.owner.loaded = lambda value: current
        invoke = lambda: self.owner.post("create-app", before, "/applications", {"name": "new"}, result_key="application", creates=True, token=True)
        self.assertEqual(invoke()[1], "t" * 43)
        with self.assertRaises(FileExistsError):
            invoke()
        self.assertEqual(len(calls), 1)

    def test_unknown_post_or_uncertain_reply_cannot_repeat(self):
        with self.assertRaises(control.smoke.CheckFailure):
            self.owner.post("other", baseline(), "/credentials", {}, result_key="credential")
        self.assertEqual(list(self.job.iterdir()), [])
        with patch.object(control.OperatorCatalogCheck, "submit_mutation", side_effect=TimeoutError) as send:
            for _ in range(2):
                with self.assertRaises((TimeoutError, FileExistsError)):
                    self.owner.post("create-rule", baseline(), "/access-rules", {}, result_key="access_rule", creates=True, authority_changed=True)
            self.assertEqual(send.call_count, 1)
        self.assertFalse((self.job / "create-rule.response.json").exists())

    def test_exact_two_owned_revocations_no_credential_mutation(self):
        current = owned()
        config = {"application_id": APP, "rule_id": RULE}
        self.owner.retained = lambda: ({"catalog": baseline()}, {"catalog": deepcopy(current)}, config)
        self.owner.loaded = lambda value: deepcopy(current)
        self.owner.chain = lambda: None
        calls = []
        def post(label, before, route, payload, **kwargs):
            calls.append((route, payload))
            collection = "access_rules" if label == "revoke-rule" else "applications"
            current[collection][0]["status"] = "revoked"
            current["credentials"][0]["active_rule_count"] = 1
            return current[collection][0], None, deepcopy(current)
        self.owner.post = post
        with patch.object(control.smoke, "require_catalog_unchanged", side_effect=lambda before, after, message: self.assertEqual(before, after)):
            self.assertTrue(self.owner.revoke()["credential_unchanged"])
            with self.assertRaises(FileExistsError):
                self.owner.revoke()
        self.assertEqual(calls, [("/access-rules/revoke", {"id": RULE}), ("/applications/revoke", {"id": APP})])

    def test_audit_generation_binding_and_duplicate_refusals(self):
        config, result, events = audit_input()
        for index, key, value in ((0, "credential_version", 2), (1, "request_digest", H2), (2, "expected_credential_version", 2), (2, "data_plane_binary_digest", H)):
            bad = deepcopy(events)
            bad[index]["event"][key] = value
            with self.assertRaises(control.smoke.CheckFailure):
                control.join_result(config, result, bad, 1)
        for bad in (events + [events[0]], events[:2]):
            with self.assertRaises(control.smoke.CheckFailure):
                control.join_result(config, result, bad, 1)
        for arrivals in (0, 2):
            with self.assertRaises(control.smoke.CheckFailure):
                control.join_result(config, result, events, arrivals)

    def test_revoked_result_closed_fields_and_no_extra_arrival(self):
        config, result, events = audit_input()
        result.update(mode="revoked", connect_status=403, http_status=0)
        for key in ("request_digest", "operation_digest", "response_body_sha256", "response_body_bytes"):
            result[key] = None
        self.assertEqual(control.join_result(config, result, events, 1)["connect_status"], 403)
        result["private"] = "unrecognized"
        with self.assertRaises(control.smoke.CheckFailure):
            control.join_result(config, result, events, 1)

    def test_incomplete_status_is_get_only_and_custody_does_not_bootstrap(self):
        self.owner.catalog = lambda: {"credentials": [], "applications": [{"id": APP, "name": self.owner.run_id + "-application", "status": "active"}], "access_rules": []}
        self.assertEqual(self.owner.status()["state"], "incomplete_no_replay")
        self.assertEqual(list(self.job.iterdir()), [])
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(control.smoke.CheckFailure):
            self.owner.authorization_hash()

    def test_managed_read_admission_precedes_configured_import_no_activation(self):
        # Structural join only: does not substitute success for a custody guard.
        tree = ast.parse(textwrap.dedent(inspect.getsource(control.Control.authorization_hash)))
        statements = tree.body[0].body
        bootstrap = next(index for index, node in enumerate(statements)
            if isinstance(node, ast.Expr) and ast.unparse(node) == "managed.bootstrap()")
        imported = next(index for index, node in enumerate(statements)
            if isinstance(node, ast.ImportFrom) and node.module == "serverware" and any(alias.name == "db" for alias in node.names))
        self.assertLess(bootstrap, imported)
        self.assertIn("managed.selected() is False", ast.unparse(statements[bootstrap + 1]))
        calls = [ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertFalse(any(name.endswith((".activate", ".initialize", ".init_db", ".startup_transaction", ".committed")) for name in calls))
        self.assertLess(next(index for index, node in enumerate(statements) if "len(read(key" in ast.unparse(node)), bootstrap)

    def test_failure_reports_only_class_and_bounded_code_locations(self):
        secret = "PRIVATE-NOT-FOR-LOGS"
        try:
            raise ValueError(secret)
        except ValueError as error:
            result = control.failure("prepare", error)
        self.assertEqual(result["error_type"], "ValueError")
        self.assertTrue(0 < len(result["frames"]) <= 8)
        self.assertEqual(set(result["frames"][0]), {"file", "function", "line"})
        self.assertNotIn(secret, json.dumps(result))


if __name__ == "__main__":
    unittest.main()
