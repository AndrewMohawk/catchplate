"""Typed legacy adapters with intercepted transports only; no provider calls."""
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qsl, urlsplit

import certifi
import requests
from requests.adapters import HTTPAdapter

import legacy


def no_effect(event, _args):
    if event.startswith("socket.") or event in {"subprocess.Popen", "os.system"}:
        raise AssertionError("Offline adapter test attempted an external operation")


sys.addaudithook(no_effect)
TOKEN = "private_application_token_canary"
APP = "12345678-1234-4234-8234-123456789abc"


def configuration(family):
    base = {"application_id": APP, "access_rule_id": "00000000-0000-4000-8000-000000000002",
        "proxy_authentication": "basic_and_bearer_v1", "proxy_username": APP, "proxy_password": TOKEN,
        "proxy_url": "https://proxy.example.test:8443", "token_expires_at_epoch_ms": 2**53 - 1,
        "ca_file": "./serverware-ca.pem", "credential_input": "replace_exact", "methods": ["GET"]}
    if family in {"github_read", "github_write"}:
        base.update(operation_bundle="github_issues_" + ("read" if family == "github_read" else "write") + "_v1",
            repository={"owner": "fixture-owner", "name": "fixture-repo"},
            upstream_url="https://api.github.com/repos/fixture-owner/fixture-repo/issues",
            response_mode="unfiltered_json_or_empty_v2", request_body_mode="preserve_json_v1", query_mode="githubRestV1",
            request_headers={"Authorization": "token serverware-github-placeholder-v1"},
            methods=["GET"] if family == "github_read" else ["GET", "POST"])
    elif family == "gmail":
        base.update(operation_bundle="gmail_read_v1", age_policy={"mode": "unrestricted"}, query_mode="orderedFormV1",
            upstream_url="https://gmail.googleapis.com/gmail/v1/users/me/messages", response_mode="gmail_read_json_v1",
            request_headers={"Authorization": "Bearer serverware-gmail-placeholder-v1"})
    elif family == "alchemy":
        base.update(operation_bundle="alchemy_chain_status_read_v1", chain="eth-sepolia",
            rpc_methods=["eth_chainId", "eth_blockNumber"], upstream_url="https://eth-sepolia.g.alchemy.com/v2",
            response_mode="alchemy_rpc_read_json_v1", methods=["POST"],
            request_headers={"Authorization": "Bearer serverware-alchemy-placeholder-v1", "Content-Type": "application/json"})
    elif family == "x_lookup":
        base.update(operation_bundle="x_username_read_v1", username="fixture_user",
            upstream_url="https://api.x.com/2/users/by/username/fixture_user", response_mode="x_app_read_json_v1",
            request_headers={"Authorization": "Bearer serverware-x-placeholder-v1"})
    elif family == "x_post":
        base.update(operation_bundle="x_text_post_v1", upstream_url="https://api.x.com/2/tweets",
            response_mode="x_post_json_v1", methods=["POST"],
            request_headers={"Authorization": "Bearer serverware-x-post-placeholder-v1"})
    else:
        base.update(operation_bundle="npm_metadata_read_v1", upstream_url="https://registry.npmjs.org/",
            packages=["@fixture/package", "unscoped"], client_recipe={"package": "@fixture/package"},
            response_mode="npm_metadata_json_v1", request_headers={"Authorization": "Bearer serverware-npm-placeholder-v1"})
    return base


def response(prepared, value=None, status=200):
    result = requests.Response()
    result.status_code = status
    result.headers["Content-Type"] = "application/json"
    result._content = json.dumps({"fixture": True} if value is None else value).encode()
    result._content_consumed = True
    result.request, result.url = prepared, prepared.url
    return result


class LegacyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="serverware-mcp-legacy-offline-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.path = self.root / "client.private.json"
        self.ca = self.root / "serverware-ca.pem"
        self.ca.write_bytes(re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            Path(certifi.where()).read_bytes(), re.S).group())

    def load(self, family="github_write", changes=None):
        value = {**configuration(family), **(changes or {})}
        self.path.write_text(json.dumps(value), encoding="utf-8")
        return legacy.load_configuration(self.path)

    def prepare(self, family, operation, args=None):
        return legacy.prepare(self.load(family), "fixture." + operation, "fixture", args or {})

    def test_all_families_load_private_scope_and_publish_only_safe_descriptors(self):
        expected = {"github_read": 3, "github_write": 5, "gmail": 2, "alchemy": 2,
            "x_lookup": 1, "x_post": 1, "npm": 1}
        for family, count in expected.items():
            with self.subTest(family=family):
                config = self.load(family)
                rows = legacy.describe(config, "fixture")
                self.assertEqual(len(rows), count)
                self.assertNotIn(TOKEN, json.dumps(rows))
                self.assertNotIn("proxy_password", json.dumps(rows))
                self.assertEqual(config["ca_file"], str(self.ca))
                self.assertEqual(config["_config_path"], str(self.path))
                self.assertTrue(all(row["input_schema"]["additionalProperties"] is False for row in rows))
        self.assertTrue(all(row["effect"] == "read" for row in legacy.describe(self.load("alchemy"), "fixture")))
        self.assertEqual(legacy.describe(self.load("x_post"), "fixture")[0]["effect"], "action")

    def test_config_expiry_identity_authority_and_unsupported_families_fail_closed(self):
        for changes in ({"proxy_username": "wrong"}, {"application_id": "bad"}, {"proxy_url": "http://proxy.test"},
                {"token_expires_at_epoch_ms": 0}, {"upstream_url": "https://api.github.com/repos/other/repo/issues"},
                {"repository": {"owner": "fixture-owner", "name": ".."}}, {"methods": ["POST"]},
                {"request_headers": {"Authorization": TOKEN}}, {"request_headers": {"Authorization": "token serverware-github-placeholder-v1", "X-Private": TOKEN}},
                {"operation_bundle": "npm_install_v1"}, {"operation_bundle": "npm_publish_v1"},
                {"operation_bundle": "aws_s3_v1"}, {"query_mode": "orderedFormV1"}):
            with self.subTest(keys=list(changes)), self.assertRaises(legacy.LegacyConfigurationError) as error:
                self.load(changes=changes)
            self.assertNotIn(TOKEN, str(error.exception))
            self.assertIsNone(error.exception.__context__)
        config = self.load()
        with patch.object(legacy.time, "time_ns", return_value=(2**53 - 1) * 1000000), \
                self.assertRaises(legacy.LegacyArgumentError):
            legacy.prepare(config, "fixture.github_get_issue", "fixture", {"issue_number": 1})
        with self.assertRaises(legacy.LegacyConfigurationError):
            self.load("gmail", {"query_mode": "legacy", "credential_input": "insert"})

    def test_github_read_and_write_targets_are_repo_fixed_and_json_deterministic(self):
        config, body, query = self.prepare("github_write", "github_list_issues", {"per_page": 5, "labels": "help wanted,bug"})
        self.assertEqual(body, None)
        self.assertEqual(query, ())
        self.assertEqual(parse_qsl(urlsplit(config["upstream_url"]).query), [
            ("page", "1"), ("per_page", "5"), ("state", "open"), ("sort", "updated"),
            ("direction", "desc"), ("labels", "help wanted,bug")])
        config, body, _ = self.prepare("github_write", "github_get_issue", {"issue_number": 42})
        self.assertTrue(config["upstream_url"].endswith("/issues/42"))
        config, body, _ = self.prepare("github_write", "github_list_comments", {"issue_number": 42, "page": 2})
        self.assertIn("/issues/42/comments?page=2&", config["upstream_url"])
        a = self.prepare("github_write", "github_create_issue", {"title": "Reviewed", "body": "A body\n"})
        b = self.prepare("github_write", "github_create_issue", {"body": "A body\n", "title": "Reviewed"})
        self.assertEqual(a[1], b[1])
        self.assertEqual(a[0]["methods"], ["POST"])
        self.assertEqual(json.loads(a[1]), {"title": "Reviewed", "body": "A body\n"})
        config, body, _ = self.prepare("github_write", "github_create_comment", {"issue_number": 42, "body": "Reviewed reply"})
        self.assertTrue(config["upstream_url"].endswith("/issues/42/comments"))
        self.assertEqual(json.loads(body), {"body": "Reviewed reply"})
        with self.assertRaises(legacy.LegacyArgumentError):
            self.prepare("github_read", "github_create_issue", {"title": "No write permission"})

    def test_gmail_ordered_repeated_selectors_survive_actual_requests_preparation(self):
        config, body, query = self.prepare("gmail", "gmail_list_messages", {
            "max_results": 5, "label_ids": ["INBOX", "UNREAD", "INBOX"], "q": "from:someone@example.test is:unread", "page_token": "opaque/+="})
        expected = [("maxResults", "5"), ("includeSpamTrash", "false"), ("labelIds", "INBOX"),
            ("labelIds", "UNREAD"), ("labelIds", "INBOX"), ("q", "from:someone@example.test is:unread"), ("pageToken", "opaque/+=")]
        self.assertEqual(parse_qsl(urlsplit(config["upstream_url"]).query), expected)
        seen = []
        def send(_adapter, prepared, **_kwargs):
            seen.append(prepared)
            return response(prepared)
        with patch.object(HTTPAdapter, "send", send):
            legacy._HTTP.execute_body(config, body, False, query)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].url, config["upstream_url"])
        config, body, query = self.prepare("gmail", "gmail_get_message", {
            "message_id": "abc_DEF-123", "metadata_headers": ["Subject", "From", "Subject"]})
        self.assertEqual(parse_qsl(urlsplit(config["upstream_url"]).query), [
            ("format", "metadata"), ("metadataHeaders", "Subject"), ("metadataHeaders", "From"), ("metadataHeaders", "Subject")])
        self.assertEqual(body, None)
        self.assertEqual(query, ())

    def test_gmail_recent_policy_advertises_bound_without_rewriting_query(self):
        policy = {"mode": "recent_internal_date_v1", "max_age_days": 7}
        with patch.object(legacy.time, "time_ns", return_value=1800000000001000000):
            loaded = self.load("gmail", {"age_policy": policy})
            descriptors = legacy.describe(loaded, "mail")
        self.assertEqual(descriptors[0]["scope"]["age_policy"], policy)
        properties = descriptors[0]["input_schema"]["properties"]
        self.assertEqual(properties["max_results"]["maximum"], 32)
        self.assertEqual(properties["q"]["examples"], ["after:1799395201"])
        configured, _, _ = legacy.prepare(loaded, "mail.gmail_list_messages", "mail", {})
        self.assertEqual(parse_qsl(urlsplit(configured["upstream_url"]).query), [("maxResults", "10"), ("includeSpamTrash", "false")])
        args = {"max_results": 32, "label_ids": ["INBOX", "UNREAD", "INBOX"],
            "q": "older_than:10y OR after:1799395201", "page_token": "opaque/+="}
        configured, _, _ = legacy.prepare(loaded, "mail.gmail_list_messages", "mail", args)
        self.assertEqual(parse_qsl(urlsplit(configured["upstream_url"]).query), [
            ("maxResults", "32"), ("includeSpamTrash", "false"), ("labelIds", "INBOX"),
            ("labelIds", "UNREAD"), ("labelIds", "INBOX"), ("q", args["q"]), ("pageToken", "opaque/+=")])
        with self.assertRaises(legacy.LegacyArgumentError):
            legacy.prepare(loaded, "mail.gmail_list_messages", "mail", {"max_results": 33})
        import operations
        collection = operations.OperationSet({"mail": self.path}, allow_actions=set(), console_origin=None)
        self.assertEqual(collection.describe()[0]["scope"]["age_policy"], policy)
        with self.assertRaises(operations.OperationError):
            collection.prepare("mail.gmail_list_messages", {"max_results": 33})
        self.assertEqual(collection.prepare("mail.gmail_list_messages", args)._config["upstream_url"],
            configured["upstream_url"])
        configured, _, _ = legacy.prepare(loaded, "mail.gmail_get_message", "mail",
            {"message_id": "one", "metadata_headers": ["Subject", "From", "Subject"]})
        self.assertEqual(parse_qsl(urlsplit(configured["upstream_url"]).query), [
            ("format", "metadata"), ("metadataHeaders", "Subject"), ("metadataHeaders", "From"), ("metadataHeaders", "Subject")])
        self.assertEqual(configured["age_policy"], policy)
        for bad in [None, {}, {"mode": "unrestricted", "max_age_days": 7},
                *({"mode": "recent_internal_date_v1", "max_age_days": value} for value in (0, True, "7", 1.5, 3651))]:
            with self.assertRaises(legacy.LegacyConfigurationError):
                self.load("gmail", {"age_policy": bad})
        absent = configuration("gmail")
        absent.pop("age_policy")
        self.path.write_text(json.dumps(absent))
        loaded = legacy.load_configuration(self.path)
        self.assertEqual(legacy.describe(loaded, "mail")[0]["scope"]["age_policy"], {"mode": "unrestricted"})
        self.assertEqual(legacy.describe(loaded, "mail")[0]["input_schema"]["properties"]["max_results"]["maximum"], 500)

    def test_typed_arguments_cannot_choose_paths_headers_methods_tokens_or_outside_scope(self):
        cases = [("github_write", "github_get_issue", {"issue_number": "../other"}),
            ("github_write", "github_list_issues", {"per_page": True}),
            ("github_write", "github_list_issues", {"per_page": 101}),
            ("github_write", "github_create_issue", {"title": "", "body": "text"}),
            ("gmail", "gmail_get_message", {"message_id": "../other"}),
            ("gmail", "gmail_get_message", {"message_id": "id", "format": "raw"}),
            ("gmail", "gmail_get_message", {"message_id": "id", "metadata_headers": ["Bad Header"]}),
            ("gmail", "gmail_list_messages", {"label_ids": ["INBOX"] * 33}),
            ("gmail", "gmail_list_messages", {"q": "bad\\query"}),
            ("alchemy", "alchemy_chain_id", {"method": "eth_sendTransaction"}),
            ("x_lookup", "x_lookup_username", {"username": "other"}),
            ("x_post", "x_create_post", {"text": "A" * 16385}),
            ("npm", "npm_metadata", {"package": "outside"})]
        for family, operation, args in cases:
            with self.subTest(family=family, operation=operation), self.assertRaises(legacy.LegacyArgumentError):
                self.prepare(family, operation, args)
        for key in ("url", "method", "headers", "config_path", "token", "body_path"):
            with self.assertRaises(legacy.LegacyArgumentError):
                self.prepare("github_write", "github_get_issue", {"issue_number": 1, key: TOKEN})

    def test_alchemy_fixed_read_rpc_and_x_text_only_exact_once(self):
        for suffix, rpc in (("alchemy_chain_id", "eth_chainId"), ("alchemy_block_number", "eth_blockNumber")):
            config, body, _ = self.prepare("alchemy", suffix)
            self.assertEqual(config["upstream_url"], "https://eth-sepolia.g.alchemy.com/v2")
            self.assertEqual(json.loads(body), {"jsonrpc": "2.0", "id": 1, "method": rpc, "params": []})
        config, body, _ = self.prepare("x_post", "x_create_post", {"text": "Reviewed Unicode: ☃"})
        seen = []
        def send(_adapter, prepared, **_kwargs):
            seen.append(prepared)
            return response(prepared, {"data": {"id": "123"}}, 201)
        with patch.object(HTTPAdapter, "send", send):
            result = legacy._HTTP.execute_body(config, body, True)
        self.assertEqual(len(seen), 1)
        self.assertEqual(result["status"], 201)
        self.assertEqual(seen[0].body, body)
        self.assertEqual(seen[0].headers["Authorization"], "Bearer serverware-x-post-placeholder-v1")

    def test_npm_scoped_metadata_uses_only_fixed_contained_existing_client(self):
        config, body, query = self.prepare("npm", "npm_metadata")
        self.assertIsNone(body)
        self.assertEqual(query, ())
        self.assertEqual(config["_legacy_runner"], "npm_metadata")
        self.assertEqual(config["_npm_node_executable"], legacy.NODE_EXECUTABLE)
        summary = {"ok": True, "operation": "view", "package": "@fixture/package", "version": "1.2.3", "tarballFetched": False}
        with patch.dict(os.environ, {"SERVERWARE_MCP_CALL_TEMP": str(self.root)}, clear=True), \
                patch.object(legacy.os, "getsid", return_value=os.getpid()), \
                patch.object(legacy.os, "getpgrp", return_value=os.getpid()), \
                patch.object(legacy, "NODE_EXECUTABLE", None), \
                patch.object(legacy.subprocess, "run", return_value=SimpleNamespace(returncode=0, stderr=b"", stdout=json.dumps(summary).encode())) as run:
            self.assertEqual(legacy.execute_external(config), {"status": 200, "response": summary})
        command = run.call_args.args[0]
        self.assertEqual(command, [legacy.NODE_EXECUTABLE, str(legacy.NPM_CLIENT), "--config", str(self.path), "view"])
        self.assertNotIn(TOKEN, " ".join(command))
        self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": str(self.root), "SERVERWARE_MCP_CONTAINED_WORKER": "1"})
        self.assertFalse(run.call_args.kwargs["start_new_session"])
        self.assertEqual(run.call_args.kwargs["timeout"], 25)
        for result in (SimpleNamespace(returncode=1, stderr=TOKEN.encode(), stdout=b""),
                SimpleNamespace(returncode=0, stderr=b"", stdout=TOKEN.encode())):
            with patch.dict(os.environ, {"SERVERWARE_MCP_CALL_TEMP": str(self.root)}, clear=True), \
                    patch.object(legacy.os, "getsid", return_value=os.getpid()), \
                    patch.object(legacy.os, "getpgrp", return_value=os.getpid()), \
                    patch.object(legacy.subprocess, "run", return_value=result), self.assertRaises(legacy.NpmMetadataError) as error:
                legacy.execute_external(config)
            self.assertNotIn(TOKEN, str(error.exception))
            self.assertIsNone(error.exception.__context__)
        with patch.dict(os.environ, {}, clear=True), patch.object(legacy.subprocess, "run") as run, \
                self.assertRaises(legacy.NpmMetadataError):
            legacy.execute_external(config)
        run.assert_not_called()

    def test_downloaded_npm_runtime_hints_are_inert_and_prepare_overwrites_them(self):
        config = self.load("npm", {"_npm_node_executable": "/untrusted/command", "_legacy_runner": "arbitrary"})
        self.assertNotIn("_npm_node_executable", config)
        self.assertNotIn("_legacy_runner", config)
        prepared, _, _ = legacy.prepare(config, "fixture.npm_metadata", "fixture", {})
        self.assertEqual(prepared["_npm_node_executable"], legacy.NODE_EXECUTABLE)
        self.assertEqual(prepared["_legacy_runner"], "npm_metadata")

    def test_actual_operation_set_integrates_legacy_discovery_intent_and_expiry(self):
        import operations
        paths = {}
        for alias, family in (("github", "github_write"), ("gmail", "gmail"), ("alchemy", "alchemy"), ("npm", "npm")):
            paths[alias] = self.root / (alias + ".json")
            paths[alias].write_text(json.dumps(configuration(family)), encoding="utf-8")
        collection = operations.OperationSet(paths, allow_actions={"github"}, console_origin=None)
        descriptors = collection.describe()
        self.assertEqual(len(descriptors), 10)
        self.assertNotIn(TOKEN, json.dumps(descriptors))
        for identifier, args in (("github.github_get_issue", {"issue_number": 1}),
                ("gmail.gmail_get_message", {"message_id": "a", "metadata_headers": ["From", "Subject"]}),
                ("alchemy.alchemy_chain_id", {}), ("npm.npm_metadata", {})):
            selected = collection.prepare(identifier, args)
            self.assertEqual(selected.effect, "read")
        with self.assertRaises(operations.OperationError):
            collection.prepare("github.github_create_issue", {"title": "reviewed"})
        selected = collection.prepare("github.github_create_issue", {"title": "reviewed"}, action=True, confirmed=True)
        self.assertEqual(selected.effect, "action")
        seen = []
        def send(_adapter, prepared, **_kwargs):
            seen.append(prepared)
            return response(prepared)
        with patch.object(HTTPAdapter, "send", send):
            self.assertEqual(collection.prepare("alchemy.alchemy_block_number", {}).execute()["status"], 200)
            self.assertEqual(selected.execute()["status"], 200)
            with self.assertRaises(operations.OperationError):
                selected.execute()
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0].method, "POST")
        paths["gmail"].write_text(json.dumps({**configuration("gmail"), "token_expires_at_epoch_ms": 0}), encoding="utf-8")
        with self.assertRaises(operations.OperationError):
            collection.prepare("gmail.gmail_list_messages", {})


if __name__ == "__main__":
    unittest.main()
