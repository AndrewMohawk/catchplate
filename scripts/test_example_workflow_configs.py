"""Execute only inactive examples' local config blocks, never Actions/providers.

Uses stdlib Python and the existing Node runtime. The exact embedded JavaScript
loads each real client's validator; sockets, DNS, fetch and subprocesses refuse.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
CA = ""
SECRET = "A" * 43
EXAMPLES = {
    "github-issues-node": "github_issues_read_v1",
    "google-gmail-node": "gmail_read_v1",
    "x-username-node": "x_username_read_v1",
    "alchemy-chain-status-node": "alchemy_chain_status_read_v1",
}
NO_NETWORK = """
import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
const refuse = () => { throw new Error('Test forbids network and child processes'); };
net.Socket.prototype.connect = refuse;
tls.connect = dns.lookup = dns.resolve = globalThis.fetch = refuse;
for (const key of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) childProcess[key] = refuse;
syncBuiltinESMExports();
"""


def configuration(directory):
    app = "11111111-2222-4333-8444-555555555555"
    rule = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    value = {"application_id": app, "access_rule_id": rule,
        "proxy_authentication": "basic_and_bearer_v1", "proxy_username": app,
        "proxy_password": SECRET, "token_expires_at_epoch_ms": 2**53 - 1,
        "proxy_url": "https://proxy.example.test:443", "ca_file": "./downloaded-ca.pem",
        "proxy_ca_file": None, "operation_bundle": EXAMPLES[directory], "methods": ["GET"],
        "credential_input": "replace_exact", "request_body": {"command": "never-execute"},
        "client_recipe": {"command": "never-execute"}}
    if directory == "github-issues-node":
        value.update(repository={"owner": "fixture-owner", "name": "fixture-repo"},
            upstream_url="https://api.github.com/repos/fixture-owner/fixture-repo/issues")
    elif directory == "google-gmail-node":
        value.update(upstream_url="https://gmail.googleapis.com/gmail/v1/users/me/messages",
            query_mode="orderedFormV1", age_policy={"mode": "recent_internal_date_v1", "max_age_days": 1})
        value["client_recipe"].update(schema="catchplate.gmailSdkClient/v2", access_rule_id=rule,
            token_expires_at_epoch_ms=value["token_expires_at_epoch_ms"], environment={
                "CATCHPLATE_APP_ID": app, "CATCHPLATE_PROXY_URL": value["proxy_url"],
                "CATCHPLATE_PROXY_TOKEN": SECRET, "CATCHPLATE_CA_FILE": value["ca_file"],
                "CATCHPLATE_PROXY_CA_FILE": None, "NODE_OPTIONS": "never-execute"})
    elif directory == "x-username-node":
        value.update(upstream_url="https://api.x.com/2/users/by/username/fixture_user",
            username="fixture_user", response_mode="x_app_read_json_v1")
    else:
        value.update(upstream_url="https://eth-mainnet.g.alchemy.com/v2", chain="eth-mainnet",
            methods=["POST"], rpc_methods=["eth_chainId", "eth_blockNumber"], response_mode="alchemy_rpc_read_json_v1")
    return value


def materializer(source):
    match = re.search(r"          node --input-type=module <<'NODE'\n(.*?)\n          NODE\n", source, re.S)
    if match is None:
        raise AssertionError("Expected one fixed local materializer")
    return textwrap.dedent(match[1])


class WorkflowConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global CA, NODE
        if NODE is None:
            raise RuntimeError("Existing Node runtime required; this test never installs it")
        # Resolve the actual runtime once, before cleaning the child environment:
        # an operator's PATH entry may be a shell wrapper requiring HOME.
        selected = json.loads(subprocess.run([NODE, "--input-type=module", "-e",
            "import {rootCertificates} from 'node:tls'; console.log(JSON.stringify({node:process.execPath,ca:rootCertificates[0]}));"],
            check=True, text=True, capture_output=True, timeout=5).stdout)
        NODE, CA = selected["node"], selected["ca"]

    def run_block(self, name, value, directory, *, extra=False, ca=None):
        source = (ROOT / "examples" / name / "workflow.example.yml").read_text()
        tail = " list" if name == "github-issues-node" else ""
        self.assertIn('node client.mjs --config "$private_dir/client.private.json"' + tail + ' >', source)
        arguments = ["--config", str(directory / "client.private.json"), *(["list"] if tail else [])]
        program = NO_NETWORK + materializer(source) + "\n" + (
            "import {parseArguments} from './client.mjs';\n"
            "if (!process.exitCode) {\n"
            f" const selected = parseArguments({json.dumps(arguments)});\n"
            " if (selected.configPath !== join(process.env.CATCHPLATE_CI_PRIVATE_DIR, 'client.private.json')) throw new Error('Fixed path lost');\n"
            " if (selected.operation !== undefined && selected.operation !== 'list') throw new Error('Write invocation refused');\n"
            " process.stdout.write('validated-read-config\\n');\n}\n")
        return subprocess.run([NODE, "--input-type=module"], input=program, text=True, capture_output=True,
            timeout=8, cwd=ROOT / "examples" / name, env={"PATH": os.defpath,
                "CATCHPLATE_CI_PRIVATE_DIR": str(directory), "CATCHPLATE_CLIENT_CONFIG_JSON": json.dumps(value),
                "CATCHPLATE_CA_PEM": CA if ca is None else ca, "CATCHPLATE_PROXY_CA_PEM": CA if extra else ""})

    def test_exact_blocks_validate_downloads_keep_scope_and_use_private_fixed_paths(self):
        for name in EXAMPLES:
            for extra in (False, True):
                with self.subTest(example=name, outer_ca=extra), tempfile.TemporaryDirectory(prefix="catchplate-workflow-") as temporary:
                    directory = Path(temporary)
                    value = configuration(name)
                    result = self.run_block(name, value, directory, extra=extra)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, "validated-read-config\n")
                    self.assertEqual(result.stderr, "")
                    loaded = json.loads((directory / "client.private.json").read_text())
                    expected = json.loads(json.dumps(value))
                    expected.update(ca_file="catchplate-ca.pem", proxy_ca_file="proxy-ca.pem" if extra else None)
                    if name == "github-issues-node":
                        expected["client_recipe"]["proxy_ca_file"] = expected["proxy_ca_file"]
                    if name == "google-gmail-node":
                        expected["client_recipe"]["environment"].update(CATCHPLATE_CA_FILE=expected["ca_file"],
                            CATCHPLATE_PROXY_CA_FILE=expected["proxy_ca_file"])
                    self.assertEqual(loaded, expected)
                    names = {"client.private.json", "catchplate-ca.pem"} | ({"proxy-ca.pem"} if extra else set())
                    self.assertEqual({path.name for path in directory.iterdir()}, names)
                    self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in directory.iterdir()))
                    self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_bad_downloads_and_cas_refuse_without_secret_output(self):
        for name in EXAMPLES:
            for invalid in ("expiry", "bundle", "ca"):
                with self.subTest(example=name, invalid=invalid), tempfile.TemporaryDirectory(prefix="catchplate-workflow-") as temporary:
                    value = configuration(name)
                    if invalid == "expiry":
                        value["token_expires_at_epoch_ms"] = 1
                    if invalid == "bundle":
                        value["operation_bundle"] = "write-or-arbitrary-request"
                    result = self.run_block(name, value, Path(temporary), ca=SECRET if invalid == "ca" else None)
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, "Invalid private client configuration or public CA inputs; no request sent.\n")
                    self.assertNotIn(SECRET, result.stderr)

    def test_workflows_remain_manual_read_only_and_materialize_after_install(self):
        for name in EXAMPLES:
            with self.subTest(example=name):
                source = (ROOT / "examples" / name / "workflow.example.yml").read_text()
                self.assertIn("# INACTIVE SAMPLE", source)
                self.assertIn("on:\n  workflow_dispatch:\n", source)
                self.assertIn("github.event.repository.default_branch", source)
                self.assertIn("permissions:\n  contents: read\n", source)
                self.assertIn("persist-credentials: false", source)
                self.assertLess(source.index("run: npm ci --ignore-scripts --no-audit --no-fund"),
                    source.index("secrets.CATCHPLATE_CLIENT_CONFIG_JSON"))
                self.assertIn("trap cleanup EXIT", source)
                self.assertIn("if: always()", source)
                self.assertNotIn("secrets.CATCHPLATE_PROXY_TOKEN", source)
                self.assertNotIn("vars.CATCHPLATE_", source)
                self.assertNotIn("pull_request", source)
                self.assertNotIn("upload-artifact", source)
                self.assertNotIn("create-issue", source)
                self.assertNotIn("create-comment", source)
                blocks = re.findall(r"^        run: \|\n((?:^          .*\n|^\n)+)", source, re.M)
                self.assertEqual(len(blocks), 2)
                for block in blocks:
                    result = subprocess.run(["bash", "-n"], input=textwrap.dedent(block), text=True,
                        capture_output=True, timeout=5, check=False)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_cleanup_removes_only_fixed_files_in_its_owned_directory(self):
        for name in EXAMPLES:
            with self.subTest(example=name), tempfile.TemporaryDirectory(prefix="catchplate-workflow-cleanup-") as temporary:
                source = (ROOT / "examples" / name / "workflow.example.yml").read_text()
                cleanup = textwrap.dedent(re.findall(r"^        run: \|\n((?:^          .*\n|^\n)+)", source, re.M)[-1])
                prefix = re.search(r'"\$RUNNER_TEMP"/(catchplate-[a-z]+-read\.)\?{8}', cleanup).group(1)
                directory = Path(tempfile.mkdtemp(prefix=prefix, dir=temporary))
                for filename in ("client.private.json", "catchplate-ca.pem", "proxy-ca.pem", "response.private.json"):
                    (directory / filename).write_text("synthetic private file")
                environment = {"PATH": os.defpath, "RUNNER_TEMP": temporary, "CATCHPLATE_CI_PRIVATE_DIR": str(directory)}
                cleaned = subprocess.run(["bash"], input=cleanup, text=True, capture_output=True,
                    env=environment, timeout=5, check=False)
                self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
                self.assertFalse(directory.exists())
                other = Path(temporary) / "unrelated"
                other.mkdir()
                retained = other / "client.private.json"
                retained.write_text("must remain")
                refused = subprocess.run(["bash"], input=cleanup, text=True, capture_output=True,
                    env={**environment, "CATCHPLATE_CI_PRIVATE_DIR": str(other)}, timeout=5, check=False)
                self.assertEqual(refused.returncode, 1)
                self.assertEqual(retained.read_text(), "must remain")


if __name__ == "__main__":
    unittest.main()
