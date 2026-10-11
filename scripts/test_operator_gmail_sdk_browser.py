"""Inert stdio/receipt/recipe controls, not browser, provider or Docker proof."""
from copy import deepcopy
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import operator_gmail_sdk_browser as bridge
from scripts import prepare_operator_gmail_sdk_fixture as recipe
from scripts import run_operator_gmail_sdk_fixture as runner
from scripts import test_operator_gmail_sdk_recipe as topology
from scripts import test_operator_gmail_sdk_checker as oracle
from scripts.check_operator_demo import CheckFailure


BEFORE = {"revision": 4, "policy": {"sequence": 1, "policy_hash": oracle.sha(890)}}
APP, CREDENTIAL, RULE = oracle.uid(2), oracle.uid(1), oracle.uid(4)
PAYLOAD = bridge.expected_payload(BEFORE, APP, CREDENTIAL)
RAW = json.dumps(PAYLOAD, indent=1).encode()


def frame(method="POST", path=bridge.GRANT, raw=RAW, number=3):
    return {"type": "request", "id": number, "method": method, "path": path,
        "headers": {"content-type": "application/json", "origin": bridge.ORIGIN},
        "body": base64.b64encode(raw).decode()}


class BrowserBridgeTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(subprocess, "Popen", side_effect=AssertionError("no child execution")))
        self.enterContext(patch.object(socket, "socket", side_effect=AssertionError("no network")))

    def test_single_post_exact_selection_cas_and_original_bytes(self):
        self.assertEqual(bridge.validate_request(frame(), PAYLOAD, posted=False, documents=1, catalogs=1), RAW)
        for change in ({"application_id": oracle.uid(3)}, {"placeholder": "insert"},
                       {"expected_revision": True}, {"expected_policy_hash": oracle.sha(891)}):
            value = frame(raw=json.dumps({**PAYLOAD, **change}).encode())
            with self.subTest(change=change), self.assertRaises(CheckFailure):
                bridge.validate_request(value, PAYLOAD, posted=False, documents=1, catalogs=1)
        for posted, documents, catalogs in ((True, 1, 1), (False, 0, 1), (False, 1, 0)):
            with self.assertRaises(CheckFailure):
                bridge.validate_request(frame(), PAYLOAD, posted=posted, documents=documents, catalogs=catalogs)

    def test_closed_routes_headers_and_strict_json(self):
        for change in ({"path": "/api/operator-demo/applications"}, {"method": "PUT"},
                       {"headers": {"authorization": "not-a-secret"}}, {"body": "?"},
                       {"headers": {"origin": bridge.ORIGIN, "content-type": "text/plain"}}):
            with self.subTest(change=change), self.assertRaises((CheckFailure, ValueError)):
                bridge.validate_request({**frame(), **change}, PAYLOAD, posted=False, documents=1, catalogs=1)
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.assertRaises((CheckFailure, ValueError)):
                bridge.strict_json(raw)
        for path in (bridge.CATALOG + "?x=1", "/api/audit", "https://gmail.googleapis.com"):
            with self.assertRaises(CheckFailure):
                bridge.validate_request(frame("GET", path, b""), PAYLOAD, posted=False, documents=0, catalogs=0)

    def test_nonblocking_partial_frame_and_deadline_no_readline(self):
        selected = Mock()
        selected.select.side_effect = [[1], []]
        with patch.object(bridge.os, "read", return_value=b'{"type":'), self.assertRaises(CheckFailure):
            bridge.read_frame(999, selected, b"", time.monotonic() + 1)
        selected.select.side_effect = [[1], [1]]
        with patch.object(bridge.os, "read", side_effect=[b'{"id":', b'1}\n{"id":2}\n']):
            first, rest = bridge.read_frame(999, selected, b"", time.monotonic() + 1)
            second, tail = bridge.read_frame(999, selected, rest, time.monotonic() + 1)
        self.assertEqual((first, second, tail), ({"id": 1}, {"id": 2}, b""))
        with patch.object(bridge.os, "read", return_value=b"x" * (bridge.MAX_FRAME + 1)), self.assertRaises(CheckFailure):
            selected.select.side_effect = None; selected.select.return_value = [1]
            bridge.read_frame(999, selected, b"", time.monotonic() + 1)

    def test_original_deadline_and_alarm_restored_without_extension_on_both_outcomes(self):
        for failure in (False, True):
            check = SimpleNamespace(deadline=140)
            def inside(*_):
                self.assertEqual(check.deadline, 120)
                if failure: raise CheckFailure("synthetic refusal")
                return "accepted"
            with patch.object(bridge.time, "monotonic", side_effect=[100, 107]), \
                 patch.object(bridge.signal, "getitimer", return_value=(40, 0)), \
                 patch.object(bridge.signal, "setitimer") as timer, \
                 patch.object(bridge, "_create_permission", side_effect=inside):
                if failure:
                    with self.assertRaises(CheckFailure): bridge.create_permission(check, {}, {})
                else: self.assertEqual(bridge.create_permission(check, {}, {}), "accepted")
                self.assertEqual(check.deadline, 140)
                self.assertEqual([call.args[1] for call in timer.call_args_list], [20, 33])

    def test_actual_frame_loop_one_post_and_independent_catalog_finalize(self):
        result = {"revision": 5, "policy": {"sequence": 2, "policy_hash": oracle.sha(900)},
            "access_rule": {"id": RULE, "application_id": APP, "credential_id": CREDENTIAL}}
        after = {**result, "access_rules": [result["access_rule"]]}
        frames = [frame("GET", "/", b"", 1), frame("GET", bridge.CATALOG, b"", 2), frame(),
            frame("GET", bridge.CATALOG, b"", 4), {"type": "done", "id": 5}]
        read, write = os.pipe()
        try:
            os.write(write, b"".join(json.dumps(value).encode() + b"\n" for value in frames)); os.close(write); write = None
            check = SimpleNamespace(deadline=time.monotonic() + 1,
                catalog=Mock(side_effect=[BEFORE, BEFORE, after]), finalize_mutation=Mock())
            def response(_check, request, raw):
                if request["method"] == "POST":
                    self.assertEqual(raw, RAW)
                    return 201, [], json.dumps(result).encode()
                return 200, [], b"<html>fixture</html>" if request["path"] == "/" else json.dumps(after).encode()
            with patch.object(bridge.sys, "stdin", SimpleNamespace(fileno=lambda: read)), \
                 patch.object(bridge, "exchange", side_effect=response) as transport, patch.object(bridge, "emit") as emit:
                rule, actual = bridge._create_permission(check, {"id": APP}, {"id": CREDENTIAL})
            self.assertEqual((rule, actual), (result["access_rule"], result))
            self.assertEqual(sum(call.args[1]["method"] == "POST" for call in transport.call_args_list), 1)
            check.finalize_mutation.assert_called_once_with(result, after, collection="access_rules",
                result_key="access_rule", event="operator_catalog.access_rule.created")
            proof = emit.call_args.args[0]["permission"]
            self.assertEqual((proof["grantPosts"], proof["catalogGets"], proof["requestSha256"]), (1, 2, bridge.sha(RAW)))
            self.assertTrue(os.get_blocking(read))
        finally:
            os.close(read)
            if write is not None: os.close(write)

    def test_raw_exchange_preserves_bytes_and_never_returns_admin_token(self):
        response = Mock(status=201)
        response.read.return_value = b'{"public":true}'
        response.getheaders.return_value = [("Content-Type", "application/json"), ("Cache-Control", "no-store")]
        connection = Mock(); connection.getresponse.return_value = response
        check = SimpleNamespace(control=SimpleNamespace(host="fixture.test", port=443, connect=Mock()),
            timeout=lambda: 1, control_ca=object(), admin_token="synthetic-admin-canary", transient_values=[], clean=Mock())
        with patch.object(bridge.http.client, "HTTPConnection", return_value=connection):
            self.assertEqual(bridge.exchange(check, frame(), RAW)[2], response.read.return_value)
        self.assertIs(connection.request.call_args.kwargs["body"], RAW)
        self.assertEqual(connection.request.call_args.kwargs["headers"]["X-Serverware-Admin-Token"], check.admin_token)
        self.assertEqual(connection.request.call_args.kwargs["headers"]["origin"], bridge.ORIGIN)
        self.assertNotIn(check.admin_token, str(response.getheaders.return_value))
        connection.close.assert_called_once()

    def test_opt_in_is_only_stdin_and_checker_flag_no_default_recipe_change(self):
        original = recipe.build(*topology.ARGS, **topology.PINS)
        enabled = recipe.build(*topology.ARGS, **topology.PINS, browser_permission=True)
        expected = deepcopy(original)
        expected["services"]["check"]["stdin_open"] = True
        expected["services"]["check"]["command"].append("--browser-permission")
        self.assertEqual(enabled, expected)
        self.assertEqual(recipe.build(*topology.ARGS, **topology.PINS, browser_permission=False), original)
        for value in (1, "yes", None):
            with self.assertRaises(ValueError): recipe.build(*topology.ARGS, **topology.PINS, browser_permission=value)

    def test_exact_owned_unit_cleanup_even_after_launcher_exit_no_default_unit_calls(self):
        run = runner.GmailSdkRun(SimpleNamespace())
        with patch.object(run, "command", side_effect=AssertionError("default touched systemd")):
            self.assertTrue(run.browser_cleanup())
        run.browser_unit = "serverware-gmail-sdk-private-123456abcdef-browser.service"
        run.browser_unit_armed = True
        with patch.object(run, "browser_units", side_effect=[True, False]), \
             patch.object(run, "command", return_value=b"") as command, patch.object(run, "save") as save:
            self.assertTrue(run.browser_cleanup())
            self.assertEqual(command.call_args.args[1], ["systemctl", "--user", "stop", run.browser_unit])
            self.assertTrue(save.call_args.args[1]["clean"])
        with patch.object(run, "browser_units", return_value=True), patch.object(run, "command",
                return_value=b"ActiveState=active\nMainPID=123\nControlGroup=/retained\n"), self.assertRaises(ValueError):
            run.browser_cleanup()

    def test_absent_unit_preflight_requires_exact_sentinel_and_successful_command(self):
        run = runner.GmailSdkRun(SimpleNamespace(source=Path("/synthetic/source")))
        run.project = "serverware-gmail-sdk-private-11ea48cffa22"
        candidate = run.project + "-browser.service"
        pins = {runner.NODE: runner.NODE_SHA256, runner.CHROME: runner.CHROME_SHA256}
        with patch.object(Path, "is_file", return_value=True), patch.object(Path, "is_symlink", return_value=False), \
             patch.object(recipe.base, "digest", side_effect=lambda file: pins.get(file, "a" * 64)), \
             patch.object(run, "browser_units", return_value=False) as loaded, patch.object(run, "save") as save:
            with patch.object(run, "command", return_value=b"default.target static -\n") as command:
                run.browser_preflight(recipe)
                command.assert_called_once_with("browser-unit-files-before", ["systemctl", "--user", "list-unit-files",
                    "--no-legend", "--no-pager", candidate, "default.target"], 3)
                loaded.assert_called_once_with("browser-unit-before")
                self.assertEqual(save.call_args.args[1]["unit"], candidate)
            for output in (b"", b"default.target static\n", b"default.target enabled enabled\n",
                    b"default.target static -\nother.service static -\n",
                    ("default.target static -\n" + candidate + " static -\n").encode(),
                    b"default.target static -\n\n", b"\xff"):
                save.reset_mock()
                with self.subTest(output=output), patch.object(run, "command", return_value=output), self.assertRaises(ValueError):
                    run.browser_preflight(recipe)
                save.assert_not_called()
            save.reset_mock()
            with patch.object(run, "command", side_effect=ValueError("synthetic systemd failure")), self.assertRaises(ValueError):
                run.browser_preflight(recipe)
            save.assert_not_called()
            loaded.return_value = True
            with patch.object(run, "command") as command, self.assertRaises(ValueError):
                run.browser_preflight(recipe)
            command.assert_not_called()

    def test_joined_receipt_keeps_all_sdk_controls_and_binds_actual_grant(self):
        sdk = oracle.success_result(oracle.commitments(oracle.provider_documents()["refreshed"]))
        proof = {"schema": bridge.SCHEMA, "submitted": PAYLOAD, "requestSha256": bridge.sha(RAW),
            "responseSha256": oracle.sha(2), "htmlSha256": oracle.sha(3), "ruleId": RULE,
            "revision": 5, "policyHash": sdk["policyHash"], "grantPosts": 1, "catalogGets": 2}
        browser = {"postCount": 1, "getCount": 3, "pageErrors": 0, "consoleErrors": 0, "refusedRequests": 0,
            "browserClosed": True, "selectedApplicationId": APP, "selectedCredentialId": CREDENTIAL, "savedRuleId": RULE,
            **{key: proof[key] for key in ("requestSha256", "responseSha256", "htmlSha256")},
            "steps": ["saved_account", "saved_basic_app", "official_sdk_default", "review", "grant", "saved_setup"],
            "screenshots": [{"file": name, "sha256": oracle.sha(4)} for name in ("review.png", "saved.png")]}
        value = {"schema": bridge.JOINED_SCHEMA, "ok": True, "browserPermissionVerified": True,
            "syntheticOAuthProgrammatic": True, "externalSsoVerified": False, "browser": browser, "permission": proof, "sdk": sdk}
        self.assertTrue(bridge.validate_joined_result(value))
        for section, key, replacement in (("browser", "postCount", True), ("browser", "selectedApplicationId", oracle.uid(9)),
                ("permission", "requestSha256", oracle.sha(22)), ("permission", "grantPosts", 2),
                ("sdk", "browserUiVerified", True), ("sdk", "providerAttempts", 7), ("sdk", "automaticRefreshes", 0)):
            bad = deepcopy(value); bad[section][key] = replacement
            with self.subTest(section=section, key=key), self.assertRaises(CheckFailure): bridge.validate_joined_result(bad)


if __name__ == "__main__": unittest.main()
