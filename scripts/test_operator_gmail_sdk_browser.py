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
APP_EXPIRY = 4102444800000
APP_VALUE = {"id": APP, "token_expires_at_epoch_ms": APP_EXPIRY}
RULE_VALUE = {"id": RULE, "application_id": APP, "credential_id": CREDENTIAL}
APP_TOKEN = "a" * 43  # Synthetic application token; never sent to the browser.
PAYLOAD = bridge.expected_payload(BEFORE, APP, CREDENTIAL)
RAW = json.dumps(PAYLOAD, indent=1).encode()
INTENT_VALUE = {"apiVersion": "catchplate.operatorGoogleConsent/v1", "productionReady": False,
    "protectedActivationSupported": False, "limits": {"active": 32, "retained": 1024},
    "intents": [{"id": oracle.uid(12), "name": "fixture-account", "provider_id": "google",
        "permission_preset": "gmail_readonly", "scopes": ["email", "https://www.googleapis.com/auth/gmail.readonly", "openid"],
        "created_at": "2026-10-11T00:00:00+00:00", "expires_at_epoch": 1791700000,
        "status": "connected", "credential_id": CREDENTIAL}]}


def copied_recipe(*, inner="/client-trust/inner-ca.pem", outer="/client-trust/outer-ca.pem"):
    """Independent literal recipe oracle, not the production JS builder/parser."""
    quote = lambda value: "'" + value.replace("'", "'\\''") + "'"
    child = "\n".join([
        "set -eu", "IFS= read -r CATCHPLATE_PROXY_TOKEN", "exec </dev/null", "unset PWD OLDPWD SHLVL _",
        "export CATCHPLATE_PROXY_TOKEN",
        "export CATCHPLATE_PROXY_URL='https://catchplate-gmail-proxy.example.com'",
        "export CATCHPLATE_APP_ID='" + APP + "'", "export CATCHPLATE_CA_FILE=" + quote(inner),
        *(["export CATCHPLATE_PROXY_CA_FILE=" + quote(outer)] if outer else []), "exec ./gmail-example"])
    return ("# Gmail SDK job (Bash): run from examples/google-gmail-go with the reviewed ./gmail-example already built.\n"
        "# Prepare dependencies/build before supplying the app token. This recipe does not download or build anything.\n"
        "# Set CATCHPLATE_PROXY_TOKEN privately first. Never use a Google token. Both TLS checks remain enabled.\n"
        "# catchplate.gmailSdkClient/v1\n"
        f"# access_rule_id: {RULE}\n# token_expires_at_epoch_ms: {APP_EXPIRY}\n"
        "(\n  set +x\n  set -eu\n  case \"${CATCHPLATE_PROXY_TOKEN-}\" in\n"
        "    ''|*[!A-Za-z0-9_-]*) printf '%s\\n' 'Set the issued Catchplate application token privately' >&2; exit 1 ;;\n"
        "  esac\n"
        '  [ "${#CATCHPLATE_PROXY_TOKEN}" -eq 43 ] || { printf \'%s\\n\' \'Set the issued Catchplate application token privately\' >&2; exit 1; }\n'
        '  printf \'%s\\n\' "$CATCHPLATE_PROXY_TOKEN" |\n'
        "    /usr/bin/env -i LANG=C.UTF-8 /bin/sh -c " + quote(child) + "\n)").encode()


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

    def test_exact_single_intents_get_and_closed_connected_metadata(self):
        request = frame("GET", bridge.INTENTS, b"", 3)
        self.assertEqual(bridge.validate_request(request, PAYLOAD, posted=False, documents=1, catalogs=1, intents=0), b"")
        for change in ({"intents": 1}, {"posted": True}, {"documents": 0}, {"catalogs": 0}):
            values = {"posted": False, "documents": 1, "catalogs": 1, "intents": 0, **change}
            with self.subTest(change=change), self.assertRaises(CheckFailure): bridge.validate_request(request, PAYLOAD, **values)
        for request in (frame("POST", bridge.INTENTS), frame("GET", bridge.INTENTS + "?id=other", b""),
                        frame("GET", bridge.INTENTS, b"body")):
            with self.assertRaises(CheckFailure): bridge.validate_request(request, PAYLOAD, posted=False, documents=1, catalogs=1)
        credential = {"id": CREDENTIAL, "name": "fixture-account"}
        bridge.validate_intents(json.dumps(INTENT_VALUE).encode(), credential)
        for key in ("state", "authorizationUrl", "code", "nonce", "access_token", "client_secret", "state_digest"):
            bad = deepcopy(INTENT_VALUE); bad["intents"][0][key] = "secret-canary"
            with self.subTest(key=key), self.assertRaises(CheckFailure): bridge.validate_intents(json.dumps(bad).encode(), credential)
        for key, value in (("status", "awaiting_consent"), ("credential_id", oracle.uid(33)), ("name", "other"),
                           ("expires_at_epoch", True), ("scopes", [])):
            bad = deepcopy(INTENT_VALUE); bad["intents"][0][key] = value
            with self.subTest(key=key), self.assertRaises(CheckFailure): bridge.validate_intents(json.dumps(bad).encode(), credential)
        bad = deepcopy(INTENT_VALUE); bad["intents"].append(deepcopy(bad["intents"][0]))
        with self.assertRaises(CheckFailure): bridge.validate_intents(json.dumps(bad).encode(), credential)

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
            "access_rule": RULE_VALUE}
        after = {**result, "access_rules": [result["access_rule"]]}
        frames = [frame("GET", "/", b"", 1), frame("GET", bridge.CATALOG, b"", 2),
            frame("GET", bridge.INTENTS, b"", 3), frame("GET", bridge.CATALOG, b"", 4), frame(number=5),
            frame("GET", bridge.CATALOG, b"", 6),
            {"type": "done", "id": 7, "copiedRecipe": base64.b64encode(copied_recipe()).decode()}]
        read, write = os.pipe()
        try:
            os.write(write, b"".join(json.dumps(value).encode() + b"\n" for value in frames)); os.close(write); write = None
            check = SimpleNamespace(deadline=time.monotonic() + 1, client_token=APP_TOKEN,
                catalog=Mock(side_effect=[BEFORE, BEFORE, after]), finalize_mutation=Mock())
            def response(_check, request, raw):
                if request["path"] == bridge.INTENTS: return 200, [], json.dumps(INTENT_VALUE).encode()
                if request["method"] == "POST":
                    self.assertEqual(raw, RAW)
                    return 201, [], json.dumps(result).encode()
                return 200, [], b"<html>fixture</html>" if request["path"] == "/" else json.dumps(after).encode()
            with patch.object(bridge.sys, "stdin", SimpleNamespace(fileno=lambda: read)), \
                 patch.object(bridge, "exchange", side_effect=response) as transport, patch.object(bridge, "emit") as emit:
                rule, actual = bridge._create_permission(check, APP_VALUE, {"id": CREDENTIAL, "name": "fixture-account"})
            self.assertEqual((rule, actual), (result["access_rule"], result))
            self.assertEqual(sum(call.args[1]["method"] == "POST" for call in transport.call_args_list), 1)
            check.finalize_mutation.assert_called_once_with(result, after, collection="access_rules",
                result_key="access_rule", event="operator_catalog.access_rule.created")
            proof = emit.call_args.args[0]["permission"]
            self.assertEqual((proof["grantPosts"], proof["catalogGets"], proof["intentGets"], proof["requestSha256"]), (1, 3, 1, bridge.sha(RAW)))
            self.assertEqual((proof["copiedRecipeSha256"], proof["copiedRecipeBytes"]),
                (bridge.sha(copied_recipe()), len(copied_recipe())))
            self.assertEqual(check.browser_client_environment["CATCHPLATE_PROXY_TOKEN"], APP_TOKEN)
            self.assertNotIn(APP_TOKEN, repr(emit.call_args_list))
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
        self.assertEqual(connection.request.call_args.kwargs["headers"]["X-Catchplate-Admin-Token"], check.admin_token)
        self.assertEqual(connection.request.call_args.kwargs["headers"]["origin"], bridge.ORIGIN)
        self.assertNotIn(check.admin_token, str(response.getheaders.return_value))
        connection.close.assert_called_once()

    def test_opt_in_uses_matching_local_browser_endpoint_no_default_recipe_change(self):
        original = recipe.build(*topology.ARGS, **topology.PINS)
        enabled = recipe.build(*topology.ARGS, **topology.PINS, browser_permission=True)
        expected = deepcopy(original)
        expected["services"]["check"]["stdin_open"] = True
        expected["services"]["check"]["command"].append("--browser-permission")
        command = expected["services"]["check"]["command"]
        command[command.index("--proxy-url") + 1] = "https://catchplate-gmail-proxy.example.com"
        expected["services"]["initialize"]["command"][-1] = "browser-initialize"
        expected["services"]["edge"]["command"][-1] = "browser-edge"
        expected["services"]["basic-pki"]["command"] += ["--proxy-hostname", "catchplate-gmail-proxy.example.com"]
        for service in ("catchplate", "decision-gate-rs"):
            expected["services"][service]["environment"]["CATCHPLATE_OPERATOR_DEMO_PROXY_URL"] = "https://catchplate-gmail-proxy.example.com"
        self.assertEqual(enabled, expected)
        self.assertEqual(recipe.build(*topology.ARGS, **topology.PINS, browser_permission=False), original)
        for value in (1, "yes", None):
            with self.assertRaises(ValueError): recipe.build(*topology.ARGS, **topology.PINS, browser_permission=value)

    def test_exact_owned_unit_cleanup_even_after_launcher_exit_no_default_unit_calls(self):
        run = runner.GmailSdkRun(SimpleNamespace())
        with patch.object(run, "command", side_effect=AssertionError("default touched systemd")):
            self.assertTrue(run.browser_cleanup())
        run.browser_unit = "catchplate-gmail-sdk-private-123456abcdef-browser.service"
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
        run.project = "catchplate-gmail-sdk-private-11ea48cffa22"
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
            "revision": 5, "policyHash": sdk["policyHash"], "grantPosts": 1, "catalogGets": 3, "intentGets": 1,
            "copiedRecipeSha256": bridge.sha(copied_recipe()), "copiedRecipeBytes": len(copied_recipe())}
        browser = {"postCount": 1, "getCount": 5, "pageErrors": 0, "consoleErrors": 0, "refusedRequests": 0,
            "browserClosed": True, "selectedApplicationId": APP, "selectedCredentialId": CREDENTIAL, "savedRuleId": RULE,
            **{key: proof[key] for key in ("requestSha256", "responseSha256", "htmlSha256", "copiedRecipeSha256", "copiedRecipeBytes")},
            "steps": ["saved_account", "saved_basic_app", "official_sdk_default", "review", "grant", "saved_setup", "copy_sdk_recipe"],
            "screenshots": [{"file": name, "sha256": oracle.sha(4)} for name in ("review.png", "saved.png")]}
        value = {"schema": bridge.JOINED_SCHEMA, "ok": True, "browserPermissionVerified": True,
            "browserClientHandoffVerified": True,
            "syntheticOAuthProgrammatic": True, "externalSsoVerified": False, "browser": browser, "permission": proof, "sdk": sdk}
        self.assertTrue(bridge.validate_joined_result(value))
        for section, key, replacement in (("browser", "postCount", True), ("browser", "selectedApplicationId", oracle.uid(9)),
                ("permission", "requestSha256", oracle.sha(22)), ("permission", "grantPosts", 2),
                ("permission", "intentGets", True), ("permission", "intentGets", 0), ("permission", "catalogGets", 2),
                ("permission", "copiedRecipeSha256", oracle.sha(88)), ("permission", "copiedRecipeBytes", True),
                ("browser", "copiedRecipeBytes", 0), ("browser", "copiedRecipeSha256", "not-a-hash"),
                ("browser", "steps", browser["steps"][:-1]),
                ("sdk", "browserUiVerified", True), ("sdk", "providerAttempts", 7), ("sdk", "automaticRefreshes", 0)):
            bad = deepcopy(value); bad[section][key] = replacement
            with self.subTest(section=section, key=key), self.assertRaises(CheckFailure): bridge.validate_joined_result(bad)
        bad = deepcopy(value); bad["browserClientHandoffVerified"] = False
        with self.assertRaises(CheckFailure): bridge.validate_joined_result(bad)

    def test_closed_copied_recipe_extracts_actual_assignments_and_no_secret(self):
        parsed = bridge.parse_copied_recipe(copied_recipe())
        self.assertEqual(parsed, {"access_rule_id": RULE, "token_expires_at_epoch_ms": APP_EXPIRY,
            "environment": {"LANG": "C.UTF-8", "CATCHPLATE_PROXY_URL": "https://catchplate-gmail-proxy.example.com",
                "CATCHPLATE_APP_ID": APP, "CATCHPLATE_CA_FILE": "/client-trust/inner-ca.pem",
                "CATCHPLATE_PROXY_CA_FILE": "/client-trust/outer-ca.pem"}})
        environment = bridge.copied_client_environment(copied_recipe(), application=APP_VALUE, rule=RULE_VALUE, token=APP_TOKEN)
        self.assertEqual(environment, {**parsed["environment"], "CATCHPLATE_PROXY_TOKEN": APP_TOKEN})
        self.assertNotIn(APP_TOKEN.encode(), copied_recipe())
        # Shell-looking path characters remain literal data; the joined fixture
        # then refuses paths other than its two pinned CA mounts.
        unusual = "/tmp/CA's $(no_command); $HOME.pem"
        self.assertEqual(bridge.parse_copied_recipe(copied_recipe(inner=unusual))["environment"]["CATCHPLATE_CA_FILE"], unusual)
        with self.assertRaises(CheckFailure):
            bridge.copied_client_environment(copied_recipe(inner=unusual), application=APP_VALUE, rule=RULE_VALUE, token=APP_TOKEN)
        self.assertNotIn("CATCHPLATE_PROXY_CA_FILE", bridge.parse_copied_recipe(copied_recipe(outer=""))["environment"])

    def test_copied_recipe_refuses_changed_commands_fields_and_saved_identity(self):
        original = copied_recipe()
        for raw in (b"", original + b"\n", original + b"\nexec evil", b"x" * 8193, b"\xff", original.replace(b"\n", b"\r\n"),
                original.replace(b"set +x", b"set -x"), original.replace(b"env -i", b"env"),
                original.replace(b"exec ./gmail-example", b"exec ./other-client"),
                original.replace(b"exec </dev/null", b"exec <&0"), original.replace(b"unset PWD OLDPWD SHLVL _", b"# skipped"),
                original.replace(b"export CATCHPLATE_CA_FILE=", b"export HOME="),
                original.replace(b"export CATCHPLATE_APP_ID=", b"export CATCHPLATE_APP_ID=evil;"),
                original.replace(b"export CATCHPLATE_PROXY_TOKEN", b"export CATCHPLATE_PROXY_TOKEN=wrong"),
                original.replace(str(APP_EXPIRY).encode(), b"9007199254740992")):
            with self.subTest(raw_hash=bridge.sha(raw)), self.assertRaises((CheckFailure, UnicodeError)):
                bridge.parse_copied_recipe(raw)
        for raw, app, rule, token in ((copied_recipe(outer=""), APP_VALUE, RULE_VALUE, APP_TOKEN),
                (original.replace(b"https://catchplate-gmail-proxy.example.com", b"https://catchplate-proxy.example.com"), APP_VALUE, RULE_VALUE, APP_TOKEN),
                (original.replace(b"https://catchplate-gmail-proxy.example.com", b"https://proxy.operator-basic.example.test:8443"), APP_VALUE, RULE_VALUE, APP_TOKEN),
                (original.replace(APP.encode(), oracle.uid(22).encode()), APP_VALUE, RULE_VALUE, APP_TOKEN),
                (original.replace(RULE.encode(), oracle.uid(23).encode()), APP_VALUE, RULE_VALUE, APP_TOKEN),
                (original, {**APP_VALUE, "token_expires_at_epoch_ms": APP_EXPIRY + 1}, RULE_VALUE, APP_TOKEN),
                (original, APP_VALUE, {**RULE_VALUE, "application_id": oracle.uid(33)}, APP_TOKEN),
                (original, APP_VALUE, RULE_VALUE, "short")):
            with self.subTest(raw_hash=bridge.sha(raw)), self.assertRaises(CheckFailure):
                bridge.copied_client_environment(raw, application=app, rule=rule, token=token)
        with patch.object(bridge.time, "time_ns", return_value=APP_EXPIRY * 1_000_000), self.assertRaises(CheckFailure):
            bridge.copied_client_environment(original, application=APP_VALUE, rule=RULE_VALUE, token=APP_TOKEN)

    def test_actual_client_boundary_uses_copied_environment_and_only_explicit_control_changes(self):
        checker = oracle.checker
        environment = bridge.copied_client_environment(copied_recipe(), application=APP_VALUE, rule=RULE_VALUE, token=APP_TOKEN)
        instance = checker.GmailSdkCheck.__new__(checker.GmailSdkCheck)
        instance.args = SimpleNamespace(browser_permission=True)
        instance.deadline = time.monotonic() + 29
        instance.current_files, instance.clean, instance.completed = Mock(), Mock(), []
        instance.browser_client_environment = environment
        with patch.object(checker, "client_environment", side_effect=AssertionError("independent environment used")), \
             patch.object(checker, "run_example") as run:
            for phase in checker.PHASES:
                positive = phase in ("first", "refreshed")
                run.return_value = (0, checker.SUCCESS, b"") if positive else (1, b"", checker.DENIAL)
                application, token = (oracle.uid(3), "b" * 43) if phase == "wrong_app" else (APP, APP_TOKEN)
                instance.client(phase, {"id": application}, token)
                passed, budget = run.call_args.args
                expected = dict(environment)
                if phase == "wrong_outer_ca":
                    expected["CATCHPLATE_CA_FILE"], expected["CATCHPLATE_PROXY_CA_FILE"] = (
                        environment["CATCHPLATE_PROXY_CA_FILE"], environment["CATCHPLATE_CA_FILE"])
                elif phase == "wrong_inner_ca":
                    expected["CATCHPLATE_CA_FILE"] = environment["CATCHPLATE_PROXY_CA_FILE"]
                    expected["CATCHPLATE_PROXY_CA_FILE"] = "/client-trust/combined-ca.pem"
                elif phase == "wrong_app": expected.update(CATCHPLATE_APP_ID=application, CATCHPLATE_PROXY_TOKEN=token)
                self.assertEqual(passed, expected)
                self.assertIsNot(passed, environment)
                self.assertTrue(0 < budget <= 29)
            self.assertEqual(run.call_count, 6)
        self.assertEqual(environment["CATCHPLATE_APP_ID"], APP)
        self.assertEqual(environment["CATCHPLATE_CA_FILE"], "/client-trust/inner-ca.pem")
        self.assertEqual([row["phase"] for row in instance.completed], list(checker.PHASES))

    def test_missing_or_mismatched_handoff_never_falls_back_or_launches(self):
        checker = oracle.checker
        instance = checker.GmailSdkCheck.__new__(checker.GmailSdkCheck)
        instance.args = SimpleNamespace(browser_permission=True)
        instance.current_files = Mock()
        with patch.object(checker, "client_environment", side_effect=AssertionError("fallback")), \
             patch.object(checker, "run_example") as launch, self.assertRaises(CheckFailure):
            instance.client("first", {"id": APP}, APP_TOKEN)
        launch.assert_not_called()
        environment = bridge.copied_client_environment(copied_recipe(), application=APP_VALUE, rule=RULE_VALUE, token=APP_TOKEN)
        for phase, app, token in (("first", oracle.uid(3), APP_TOKEN), ("refreshed", APP, "b" * 43),
                ("wrong_app", APP, APP_TOKEN), ("unknown", APP, APP_TOKEN)):
            with self.subTest(phase=phase), self.assertRaises(CheckFailure):
                bridge.copied_phase_environment(environment, application=app, token=token, phase=phase)


if __name__ == "__main__": unittest.main()
