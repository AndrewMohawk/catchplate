"""Offline engine checks. No provider requests, credentials, or application DB."""
from copy import deepcopy
import json
from pathlib import Path
import pickle
import sys
import tempfile
import unittest
from unittest.mock import patch

import operations as engine


def no_network(event, _args):
    if event.startswith("socket.") or event in {"subprocess.Popen", "os.system"}:
        raise AssertionError("Operation engine tests must not open sockets or child processes")


sys.addaudithook(no_network)
TOKEN = "private-proxy-token-fixture:@/?#%"
APP = "12345678-1234-4234-8234-123456789abc"


def configuration(provider, operation):
    scope = {item["key"]: item.get("default", item.get("placeholder")) for item in operation["scope_fields"]}
    if "model" in scope:
        scope["model"] = "vendor/fixture-model" if provider["id"] == "openrouter" else "fixture-model"
    return {"application_id": APP, "access_rule_id": "00000000-0000-4000-8000-000000000002",
        "proxy_authentication": "basic_and_bearer_v1", "proxy_username": APP,
        "proxy_password": TOKEN, "token_expires_at_epoch_ms": 2**53 - 1,
        "proxy_url": "https://proxy.example.test:8443", "ca_file": "./fixture-ca.pem",
        "app_preset": provider["id"], "app_operation": operation["id"], "scope": scope,
        "upstream_url": operation["origin"] + operation["path_template"].format(**scope),
        "methods": operation["methods"], "credential_input": "replace_exact",
        "response_mode": "unfiltered_json_or_empty_v2",
        "request_headers": {provider["header_name"]: provider["placeholder"], **operation.get("request_headers", {})},
        "query_keys": operation["query_keys"],
        "request_query": engine._resolve(operation.get("example_query", {}), scope),
        "client_recipe": {"automatic_retries": 0}}


def arguments(provider):
    if provider in {"openai", "anthropic", "gemini", "openrouter"}:
        return {"prompt": "A short answer, please."}
    if provider in {"slack", "discord"}:
        return {"text": "Deployment complete."}
    if provider == "resend":
        return {"subject": "Deployment", "text": "Complete."}
    return {}


class OperationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="serverware-mcp-engine-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.configs, self.values = {}, {}
        for provider in engine._PRESETS.values():
            for operation in provider["operations"]:
                alias = provider["id"] + "_" + operation["id"]
                self.configs[alias] = self.directory / (alias + ".json")
                self.values[alias] = configuration(provider, operation)
                self.save(alias)
        self.operations = engine.OperationSet(self.configs, allow_actions=set(self.configs),
            console_origin="https://console.example.test/")

    def save(self, alias):
        self.configs[alias].write_text(json.dumps(self.values[alias]), encoding="utf-8")

    def prepare(self, alias, args=None, **kwargs):
        value = self.values[alias]
        args = arguments(value["app_preset"]) if args is None else args
        if value["methods"] == ["POST"] and not kwargs:
            kwargs = {"action": True, "confirmed": True}
        return self.operations.prepare(alias, args, **kwargs)

    def test_all_fifteen_operations_are_typed_and_prepare_without_transport(self):
        descriptors = self.operations.describe()
        self.assertEqual(len(descriptors), 15)
        self.assertEqual(len({item["provider"] for item in descriptors}), 12)
        self.assertNotIn(TOKEN, json.dumps(descriptors))
        self.assertNotIn(str(self.directory), json.dumps(descriptors))
        self.assertNotIn(APP, json.dumps(descriptors))
        for descriptor in descriptors:
            with self.subTest(operation=descriptor["id"]):
                self.assertEqual(set(descriptor), {"id", "provider", "label", "effect", "scope", "input_schema", "limits"})
                self.assertFalse(descriptor["input_schema"]["additionalProperties"])
                prepared = self.prepare(descriptor["id"])
                self.assertEqual(prepared.console_origin, "https://console.example.test")
                self.assertNotIn(TOKEN, repr(prepared))
                self.assertEqual(prepared._config["upstream_url"], self.values[descriptor["id"]]["upstream_url"])
                if descriptor["effect"] == "read":
                    self.assertIsNone(prepared._body)
                else:
                    self.assertIsInstance(json.loads(prepared._body), dict)
        self.assertNotIn("serverware.db", sys.modules)

    def test_action_requires_operator_enablement_and_exact_confirmation(self):
        alias = "slack_post_message"
        disabled = engine.OperationSet(self.configs, allow_actions=set(), console_origin=None)
        with self.assertRaises(engine.OperationError):
            disabled.prepare(alias, {"text": "hello"}, action=True, confirmed=True)
        for flags in ({}, {"action": True}, {"confirmed": True}, {"action": 1, "confirmed": True}):
            with self.subTest(flags=flags), self.assertRaises(engine.OperationError):
                self.operations.prepare(alias, {"text": "hello"}, **flags)
        for flags in ({"action": True}, {"confirmed": True}):
            with self.assertRaises(engine.OperationError):
                self.operations.prepare("stripe_balance", {}, **flags)

    def test_fixed_scope_and_wire_controls_are_never_caller_arguments(self):
        checks = {"openai_responses_text_v1": ["model", "stream", "store", "tools"],
            "slack_post_message": ["channel", "url", "headers"],
            "discord_create_message": ["channel_id", "allowed_mentions"],
            "resend_send_email": ["sender", "recipient", "to", "from", "bcc"],
            "sentry_project_issues": ["project", "organization", "upstream_url"]}
        for alias, fields in checks.items():
            for key in fields:
                args = {**arguments(self.values[alias]["app_preset"]), key: "not-allowed"}
                with self.subTest(alias=alias, key=key), self.assertRaises(engine.OperationError):
                    self.prepare(alias, args)
        body = json.loads(self.prepare("slack_post_message")._body)
        self.assertEqual(body["channel"], self.values["slack_post_message"]["scope"]["channel"])
        self.assertIs(body["unfurl_links"], False)
        self.assertEqual(json.loads(self.prepare("discord_create_message")._body)["allowed_mentions"], {"parse": []})

    def test_ai_messages_and_limits_are_strict_and_canonical(self):
        for provider, operation in (("anthropic", "messages_text_v1"), ("gemini", "generate_text_v1"), ("openrouter", "chat_text_v1")):
            alias = provider + "_" + operation
            valid = {"messages": [{"role": "user", "content": "Hello 🌍"}], "output_tokens": 16}
            first, second = self.prepare(alias, valid), self.prepare(alias, dict(reversed(list(valid.items()))))
            self.assertEqual(first._body, second._body)
            for bad in ({**valid, "prompt": "also"}, {}, {"messages": []},
                    {"messages": [{"role": "user", "content": [{"text": "nested"}]}]},
                    {"prompt": "hello", "output_tokens": True}, {"prompt": "hello", "output_tokens": 4097},
                    {"prompt": "a" * 4097}, {"messages": [{"role": "tool", "content": "unsafe"}]}):
                with self.subTest(provider=provider, bad=bad), self.assertRaises(engine.OperationError):
                    self.prepare(alias, bad)
        body = json.loads(self.prepare("openai_responses_text_v1")._body)
        self.assertIs(body["store"], False)
        self.assertIs(body["stream"], False)

    def test_queries_are_bounded_and_cannot_override_fixed_project(self):
        prepared = self.prepare("sentry_project_issues", {"limit": 10, "query": "is:unresolved issue"})
        self.assertEqual(prepared._query, ("limit=10", "query=is:unresolved issue"))
        target = engine._http.request_url(prepared._config, prepared._query)
        self.assertIn("project=12345", target)
        self.assertIn("query=is%3Aunresolved%20issue", target)
        for args in ({"limit": 0}, {"limit": 101}, {"limit": "10"}, {"query": "x" * 2049}):
            with self.assertRaises(engine.OperationError):
                self.prepare("sentry_project_issues", args)

    def test_config_is_reloaded_and_corrupt_or_expired_scope_is_refused(self):
        alias = "openai_responses_text_v1"
        original = deepcopy(self.values[alias])
        for change in ({"token_expires_at_epoch_ms": 1}, {"upstream_url": "https://api.openai.com/v1/files"},
                       {"query_keys": ["unexpected"]}, {"request_query": {"model": "other"}},
                       {"request_headers": {"Authorization": "Bearer " + TOKEN}},
                       {"scope": {"model": "fixture-model", "max_output_tokens": True}}):
            self.values[alias] = {**deepcopy(original), **change}
            self.save(alias)
            with self.subTest(change=change), self.assertRaises(engine.OperationError) as error:
                self.prepare(alias)
            self.assertNotIn(TOKEN, str(error.exception))
            self.assertIsNone(error.exception.__cause__)
            self.assertIsNone(error.exception.__context__)
        with self.assertRaises(engine.OperationError):
            self.operations.describe()

    def test_execute_is_one_shot_picklable_and_passes_through_bounded_428(self):
        prepared = pickle.loads(pickle.dumps(self.prepare("slack_post_message")))
        response = {"status": 428, "response": {"approval_url": "/approvals/fixture", "allowed": False}}
        with patch.object(engine._http, "check_versions"), patch.object(engine._http, "execute_body", return_value=response) as execute:
            self.assertEqual(prepared.execute(), response)
            self.assertEqual(execute.call_args.args[2], True)
            with self.assertRaises(engine.OperationError):
                prepared.execute()
            execute.assert_called_once()
        read = self.prepare("stripe_balance")
        with patch.object(engine._http, "check_versions"), patch.object(engine._http, "execute_body", side_effect=engine._http.RequestExecutionError()) as execute:
            with self.assertRaises(engine._http.RequestExecutionError):
                read.execute()
            with self.assertRaises(engine.OperationError):
                read.execute()
            execute.assert_called_once()

    def test_prepared_expiry_and_returned_descriptors_cannot_change_scope(self):
        prepared = self.prepare("slack_post_message")
        prepared._config["token_expires_at_epoch_ms"] = 1
        with patch.object(engine._http, "execute_body") as execute:
            with self.assertRaises(engine.OperationError):
                prepared.execute()
            execute.assert_not_called()
        descriptor = next(item for item in self.operations.describe() if item["id"] == "slack_post_message")
        descriptor["scope"]["channel"] = "C9999999999"
        descriptor["input_schema"]["properties"]["channel"] = {"type": "string"}
        body = json.loads(self.prepare("slack_post_message")._body)
        self.assertNotEqual(body["channel"], descriptor["scope"]["channel"])
        with self.assertRaises(engine.OperationError):
            self.prepare("slack_post_message", {"text": "hello", "channel": "C9999999999"})

    def test_public_provider_identity_is_fixed_and_survives_pickling(self):
        for alias, expected in (("slack_post_message", "slack"), ("cloudflare_zones", "cloudflare")):
            prepared = pickle.loads(pickle.dumps(self.prepare(alias)))
            self.assertEqual(prepared.provider, expected)
        # This is the normalized private shape returned by the closed legacy
        # adapter; the HTTP POST remains semantically a read.
        prepared = engine.PreparedRequest("chain.alchemy_chain_id", "read", None,
            {"operation_bundle": "alchemy_chain_status_read_v1", "methods": ["POST"]}, b"{}", ())
        self.assertEqual(pickle.loads(pickle.dumps(prepared)).provider, "alchemy")
        self.assertNotIn(TOKEN, prepared.provider)

    def test_invalid_alias_origin_unknown_operation_and_input_fail_closed(self):
        for aliases, enabled, origin in (({"bad.name": next(iter(self.configs.values()))}, set(), None),
                (self.configs, {"missing"}, None), (self.configs, set(), "https://user:secret@console.test"),
                (self.configs, set(), "https://console.test/path")):
            with self.assertRaises(engine.OperationError):
                engine.OperationSet(aliases, allow_actions=enabled, console_origin=origin)
        for name, args in (("missing", {}), ("stripe_balance.extra", {}), ("stripe_balance", []),
                           ("stripe_balance", {"bad": float("nan")})):
            with self.assertRaises(engine.OperationError):
                self.operations.prepare(name, args)


if __name__ == "__main__":
    unittest.main()
