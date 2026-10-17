"""Local-only rebrand controls; no providers, SDK execution or real credentials."""
from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

import migrate_client_config as migration


def no_external(event, _args):
    if event.startswith("socket.") or event in {"subprocess.Popen", "os.system"}:
        raise AssertionError("Local migration must not contact a service or launch a process")


sys.addaudithook(no_external)
APP = "12345678-1234-4234-8234-123456789abc"
RULE = "00000000-0000-4000-8000-000000000002"
TOKEN = "private_serverware-token-marker_MUST_REMAIN_IDENTICAL"
ROOT = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def configuration(provider="gitlab"):
    header, prefix = migration.COMMON[provider]
    return {"application_id": APP, "access_rule_id": RULE, "proxy_authentication": "basic_and_bearer_v1",
        "proxy_username": APP, "proxy_password": TOKEN, "token_expires_at_epoch_ms": 2**53 - 1,
        "proxy_url": "https://serverware-proxy.example.test", "ca_file": "./serverware-ca.pem",
        "proxy_ca_file": None, "app_preset": provider, "app_operation": "project_issues",
        "scope": {"project_id": "12345", "label": "serverware-unchanged-user-text"},
        "upstream_url": "https://gitlab.com/api/v4/projects/12345/issues", "methods": ["GET"],
        "credential_input": "replace_exact", "response_mode": "unfiltered_json_or_empty_v2",
        "request_headers": {header: prefix + "serverware-" + provider + "-placeholder-v1"},
        "request_query": {"search": "serverware"}, "request_body": {"text": "serverware is user content"},
        "client_recipe": {"automatic_retries": 0, "sdk_auth_token": "serverware-" + provider + "-placeholder-v1"}}


class MigrationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="catchplate-client-migration-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / "old.private.json"
        self.destination = self.root / "new.private.json"

    def write(self, value):
        self.source.write_text(json.dumps(value))
        self.source.chmod(0o600)

    def test_all_common_placeholders_change_but_private_and_user_data_do_not(self):
        for provider, (header, prefix) in migration.COMMON.items():
            original = configuration(provider)
            value = migration.convert(original, self.root)
            self.assertEqual(value["request_headers"][header], prefix + "catchplate-" + provider + "-placeholder-v1")
            self.assertEqual(value["client_recipe"]["sdk_auth_token"], "catchplate-" + provider + "-placeholder-v1")
            for field in ("proxy_password", "proxy_url", "token_expires_at_epoch_ms", "application_id",
                    "access_rule_id", "scope", "request_query", "request_body", "methods", "upstream_url"):
                self.assertEqual(value[field], original[field], field)
            self.assertEqual(value["ca_file"], str(self.root / "serverware-ca.pem"))
            self.assertEqual(original, configuration(provider), "conversion does not mutate input")

    def test_legacy_families_use_only_their_exact_known_marker(self):
        for bundle, (provider, prefix) in migration.BUNDLES.items():
            original = configuration()
            for field in ("app_preset", "app_operation", "scope"):
                original.pop(field)
            original.update(operation_bundle=bundle, request_headers={"Authorization": prefix +
                "serverware-" + provider + "-placeholder-v1"}, client_recipe={"sdk_auth_token":
                "serverware-" + provider + "-placeholder-v1"})
            value = migration.convert(original, self.root)
            self.assertEqual(value["request_headers"]["Authorization"], prefix + "catchplate-" + provider + "-placeholder-v1")
            original["request_headers"]["Authorization"] = "Bearer custom-serverware-value"
            with self.assertRaises(ValueError):
                migration.convert(original, self.root)

    def test_gmail_recipe_keeps_binding_and_optional_ca_semantics(self):
        for version in ("v1", "v2"):
            for proxy_ca in (None, "./serverware-outer.pem"):
                value = configuration()
                for field in ("app_preset", "app_operation", "scope"):
                    value.pop(field)
                value.update(operation_bundle="gmail_read_v1", proxy_ca_file=proxy_ca,
                    age_policy={"mode": "recent_internal_date_v1", "max_age_days": 30},
                    request_headers={"Authorization": "Bearer serverware-gmail-placeholder-v1"})
                env = {"LANG": "C.UTF-8", "SERVERWARE_PROXY_URL": value["proxy_url"],
                    "SERVERWARE_APP_ID": APP, "SERVERWARE_PROXY_TOKEN": TOKEN, "SERVERWARE_CA_FILE": value["ca_file"]}
                if proxy_ca is not None:
                    env["SERVERWARE_PROXY_CA_FILE"] = proxy_ca
                value["client_recipe"] = {"schema": "serverware.gmailSdkClient/" + version,
                    "clear_environment": True, "environment": env, "access_rule_id": RULE,
                    "token_expires_at_epoch_ms": value["token_expires_at_epoch_ms"]}
                converted = migration.convert(value, self.root, proxy_url="https://catchplate-proxy.example.test")
                recipe = converted["client_recipe"]
                self.assertEqual(recipe["schema"], "catchplate.gmailSdkClient/" + version)
                self.assertEqual(converted["age_policy"], value["age_policy"])
                self.assertEqual(recipe["environment"]["CATCHPLATE_PROXY_TOKEN"], TOKEN)
                self.assertEqual(recipe["environment"]["CATCHPLATE_PROXY_URL"], converted["proxy_url"])
                self.assertEqual(recipe["environment"]["CATCHPLATE_CA_FILE"], converted["ca_file"])
                self.assertEqual("CATCHPLATE_PROXY_CA_FILE" in recipe["environment"], proxy_ca is not None)
                value["client_recipe"]["environment"]["CATCHPLATE_PROXY_TOKEN"] = "collision"
                with self.assertRaises(ValueError):
                    migration.convert(value, self.root)

    def test_output_is_private_exclusive_and_current_common_loader_accepts_it(self):
        self.write(configuration())
        original = self.source.read_bytes()
        migration.migrate(self.source, self.destination)
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o600)
        self.assertEqual(self.source.read_bytes(), original)
        request = load("migration_common_request", ROOT / "common-apps/request.py")
        loaded = request.load_configuration(self.destination)
        self.assertEqual(loaded["proxy_password"], TOKEN)
        with self.assertRaises(FileExistsError):
            migration.migrate(self.source, self.destination)
        with self.assertRaises(FileExistsError):
            migration.migrate(self.source, self.source)
        self.assertEqual(self.source.read_bytes(), original)

    def test_converted_github_download_is_accepted_by_current_mcp_loader(self):
        value = configuration()
        for field in ("app_preset", "app_operation", "scope"):
            value.pop(field)
        value.update(operation_bundle="github_issues_read_v1", query_mode="githubRestV1",
            request_body_mode="preserve_json_v1", repository={"owner": "fixture", "name": "serverware"},
            upstream_url="https://api.github.com/repos/fixture/serverware/issues",
            request_headers={"Authorization": "token serverware-github-placeholder-v1"},
            client_recipe={"sdk_auth_token": "serverware-github-placeholder-v1"})
        self.write(value)
        migration.migrate(self.source, self.destination)
        legacy = load("migration_mcp_legacy", ROOT / "mcp/legacy.py")
        config = legacy.load_configuration(self.destination)
        self.assertEqual(config["proxy_password"], TOKEN)
        self.assertEqual(config["repository"], value["repository"])
        self.assertEqual(len(legacy.describe(config, "issues")), 3)

    def test_symlinks_public_inputs_and_malformed_json_are_refused(self):
        self.write(configuration())
        link = self.root / "link.json"
        link.symlink_to(self.source)
        with self.assertRaises(OSError):
            migration.migrate(link, self.destination)
        self.destination.symlink_to(self.source)
        with self.assertRaises(FileExistsError):
            migration.migrate(self.source, self.destination)
        self.source.chmod(0o644)
        with self.assertRaises(ValueError):
            migration.read_configuration(self.source)
        self.source.chmod(0o600)
        for text in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":1e999}', 'x' * (migration.LIMIT + 1)):
            self.source.write_text(text)
            with self.assertRaises(ValueError):
                migration.read_configuration(self.source)

    def test_signed_managed_ecr_custom_or_invalid_proxy_require_new_handoff(self):
        for field, content in (("schema", "serverware.awsEcrPublicationClient/v1"),
                ("schema", "serverware.managedClientSetup/v1"), ("expected_policy_hash", "sha256:" + "0" * 64),
                ("signature", "untouched"), ("policy_hash", "sha256:" + "0" * 64)):
            with self.assertRaises(ValueError):
                migration.convert({**configuration(), field: content}, self.root)
        custom = configuration()
        custom.pop("app_preset")
        with self.assertRaises(ValueError):
            migration.convert(custom, self.root)
        for url in ("http://proxy.example.test", "https://token@proxy.example.test", "https://proxy.example.test/path",
                "https://proxy.example.test?x=1", "https://proxy.example.test/#secret"):
            with self.assertRaises(ValueError):
                migration.convert(configuration(), self.root, proxy_url=url)

    def test_expiry_is_preserved_not_extended_and_errors_never_print_contents(self):
        value = configuration()
        value["token_expires_at_epoch_ms"] = 1
        self.write(value)
        with patch("sys.stdout", io.StringIO()) as out, patch("sys.stderr", io.StringIO()) as err:
            code = migration.main(["--input", str(self.source), "--output", str(self.destination)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(self.destination.read_bytes())["token_expires_at_epoch_ms"], 1)
        self.assertNotIn(TOKEN, out.getvalue() + err.getvalue())
        value["request_headers"]["PRIVATE-TOKEN"] = TOKEN
        self.write(value)
        with patch("sys.stdout", io.StringIO()) as out, patch("sys.stderr", io.StringIO()) as err:
            code = migration.main(["--input", str(self.source), "--output", str(self.destination)])
        self.assertEqual(code, 2)
        self.assertNotIn(TOKEN, out.getvalue() + err.getvalue())
        self.assertIn("No request was sent", err.getvalue())

    def test_known_intent_env_names_change_but_no_write_intent_is_added(self):
        value = configuration()
        value["client_recipe"]["required_local_environment"] = ["SERVERWARE_X_POST_TEXT", "SERVERWARE_X_POST_CONFIRM"]
        result = migration.convert(value, self.root)
        self.assertEqual(result["client_recipe"]["required_local_environment"],
            ["CATCHPLATE_X_POST_TEXT", "CATCHPLATE_X_POST_CONFIRM"])
        self.assertNotIn("confirmed", result)
        self.assertNotIn("execute_write", result)


if __name__ == "__main__":
    unittest.main()
