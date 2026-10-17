"""Focused official-SDK stdio acceptance using only fixed synthetic operations.

Run with the environment installed from requirements.lock. No provider network,
real credentials, app database, or deployment is used by this test harness.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import multiprocessing
import io
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import anyio
from mcp import Client, StdioServerParameters
import server

SECRET = "synthetic-proxy-secret-that-must-never-be-returned"
APPROVAL_ID = "12345678-1234-4234-8234-123456789abc"
_PINNED_NODE = Path.home() / ".nvm/versions/node/v25.5.0/bin/node"
NODE_EXECUTABLE = str(_PINNED_NODE) if _PINNED_NODE.is_file() else shutil.which("node")


def decision():
    path = "/approvals/" + APPROVAL_ID
    return {"allowed": False, "action": "approval_required", "status_code": 428,
        "approval_id": APPROVAL_ID, "approval_url": path,
        "payload": {"error": "host_trusted_approval_required", "approval_status": "pending",
            "approval_id": APPROVAL_ID, "approval_url": path,
            "retry_semantics": "explicit_identical_request_after_approval", "private": SECRET}}


def _no_provider(event, _arguments):
    if event in {"socket.connect", "socket.getaddrinfo"}:
        raise AssertionError("Synthetic MCP tests must not contact any network provider")


@dataclass(repr=False)
class FixturePrepared:
    operation_id: str
    case: str
    log: str
    effect: str = "read"
    console_origin: str | None = "https://console.example.test"
    provider: str | None = None

    def execute(self):
        sys.addaudithook(_no_provider)
        child = None
        if self.case in {"wait", "descendant"}:
            # Fixed local child, no model-specified executable/arguments. It must
            # stay in the worker's owned process group and disappear on cleanup.
            child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(60)"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if self.case == "node_wait":
            launcher = (Path(__file__).resolve().parents[1] / "npm-registry/client.mjs").as_uri()
            code = ("import {invokeWorker} from " + json.dumps(launcher) + ";"
                "import {spawn} from 'node:child_process';import {appendFileSync} from 'node:fs';"
                "const launch=(command,args,options)=>{const child=spawn(command,args,options);"
                "appendFileSync(process.argv[1],JSON.stringify({pid:child.pid})+'\\n');return child;};"
                "await invokeWorker(process.execPath,['-e','setTimeout(()=>{},60000)'],"
                "{env:{}},launch,15000,()=>{},true);")
            child = subprocess.Popen([NODE_EXECUTABLE, "--input-type=module", "-e", code, self.log + ".node"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(self.log, "a", encoding="utf-8") as output:
            output.write(json.dumps({"case": self.case, "pid": os.getpid(), "group": os.getpgrp(),
                "child": child.pid if child else None, "scratch": os.environ["CATCHPLATE_MCP_CALL_TEMP"]}) + "\n")
        if self.case in {"wait", "node_wait"}:
            time.sleep(60)
        if self.case == "exception":
            raise RuntimeError("https://user:" + SECRET + "@proxy.example.test/private")
        if self.case in {"approval", "bad_approval"}:
            value = decision()
            if self.case == "bad_approval":
                value["approval_url"] = "https://evil.example.test/" + SECRET
            return {"status": 428, "response": value}
        if self.case == "provider_error":
            return {"status": 500, "response": {"error": SECRET}}
        if self.case == "large":
            return {"status": 200, "response": "a" * (server.MAX_RESULT_BYTES + 1)}
        if self.case == "slack_error":
            return {"status": 200, "response": {"ok": False, "error": SECRET}}
        return {"status": 200, "response": {"synthetic": True, "case": self.case}}


class FixtureOperations:
    def __init__(self, log, allow_actions=True):
        self.log = str(log)
        self.allow_actions = allow_actions

    def describe(self):
        return [{"id": identifier, "provider": "synthetic", "label": "Synthetic operation",
            "effect": effect, "scope": {}, "input_schema": {"type": "object", "additionalProperties": False,
                "properties": {"case": {"type": "string"}}, "required": ["case"]},
            "limits": {"automatic_retries": 0}} for identifier, effect in
            (("fixture_read", "read"), ("fixture_action", "action"))]

    def prepare(self, operation_id, arguments, *, action=False, confirmed=False):
        if (operation_id not in {"fixture_read", "fixture_action"} or type(arguments) is not dict
                or set(arguments) != {"case"} or arguments["case"] not in {
                    "ok", "approval", "bad_approval", "provider_error", "exception", "large",
                    "wait", "descendant", "node_wait", "slack_error"}):
            raise ValueError("Invalid input with " + SECRET)
        if operation_id == "fixture_action":
            if not self.allow_actions or action is not True or confirmed is not True:
                raise ValueError(SECRET)
        elif action is not False or confirmed is not False:
            raise ValueError(SECRET)
        return FixturePrepared(operation_id, arguments["case"], self.log,
            effect="action" if action else "read", provider="slack" if arguments["case"] == "slack_error" else None)


@dataclass(repr=False)
class EngineFixturePrepared:
    prepared: object
    log: str

    @property
    def operation_id(self):
        return self.prepared.operation_id

    @property
    def console_origin(self):
        return self.prepared.console_origin

    @property
    def provider(self):
        return self.prepared.provider

    def execute(self):
        import operations
        sys.addaudithook(_no_provider)
        def synthetic_transport(config, body, send, query):
            with open(self.log, "a", encoding="utf-8") as output:
                output.write(json.dumps({"provider": config["app_preset"], "send": send,
                    "body": json.loads(body) if body else None, "query": list(query)}) + "\n")
            return {"status": 200, "response": {"synthetic": True}}
        # The only stub is the final wire boundary. Real configuration loading,
        # scope/body validation, action gate, one-shot execution and pin checks run.
        with patch.object(operations._http, "execute_body", synthetic_transport):
            return self.prepared.execute()


class EngineFixtureOperations:
    def __init__(self, directory):
        import operations
        directory = Path(directory)
        self.log = str(directory / "engine-calls.jsonl")
        self.engine = operations.OperationSet({key: directory / (key + ".json") for key in ("balance", "message")},
            allow_actions={"message"}, console_origin="https://console.example.test")

    def describe(self):
        return self.engine.describe()

    def prepare(self, *args, **kwargs):
        return EngineFixturePrepared(self.engine.prepare(*args, **kwargs), self.log)


def engine_configuration(provider_id):
    import operations
    app = operations._PRESETS[provider_id]
    operation = app["operations"][0]
    scope = {field["key"]: field.get("default", field.get("placeholder")) for field in operation["scope_fields"]}
    app_id = "12345678-1234-4234-8234-123456789abc"
    return {"application_id": app_id, "access_rule_id": "00000000-0000-4000-8000-000000000002",
        "proxy_authentication": "basic_and_bearer_v1", "proxy_username": app_id,
        "proxy_password": SECRET, "token_expires_at_epoch_ms": 2**53 - 1,
        "proxy_url": "https://proxy.example.test:8443", "ca_file": "./synthetic-ca.pem",
        "app_preset": provider_id, "app_operation": operation["id"], "scope": scope,
        "upstream_url": operation["origin"] + operation["path_template"].format(**scope),
        "methods": operation["methods"], "credential_input": "replace_exact",
        "response_mode": "unfiltered_json_or_empty_v2",
        "request_headers": {app["header_name"]: app["placeholder"], **operation.get("request_headers", {})},
        "query_keys": operation["query_keys"],
        "request_query": operations._resolve(operation.get("example_query", {}), scope),
        "client_recipe": {"automatic_retries": 0}}


def records(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


def running(pid):
    try:
        # A short-lived reparented zombie has stopped executing; its parent/init
        # owns reaping. The MCP Python leader itself is always joined by server.
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        return state != "Z"
    except FileNotFoundError:
        return False


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="catchplate-mcp-protocol-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.log = self.directory / "calls.jsonl"

    def parameters(self, *, allow=True, timeout=3.0):
        return StdioServerParameters(command=sys.executable,
            args=["-I", "-B", str(Path(__file__).resolve()), "--fixture-stdio", str(self.log),
                "enabled" if allow else "disabled", str(timeout)], env={"PATH": os.defpath})

    async def call(self, client, case, *, action=False, **kwargs):
        tool = "perform_action" if action else "read_operation"
        arguments = {"operation_id": "fixture_action" if action else "fixture_read", "arguments": {"case": case}}
        if action:
            arguments["confirmed"] = True
        arguments.update(kwargs)
        return await client.call_tool(tool, arguments, read_timeout_seconds=10.0)

    def assert_clean(self):
        for record in records(self.log):
            self.assertEqual(record["pid"], record["group"])
            self.assertFalse(running(record["pid"]))
            if record["child"]:
                self.assertFalse(running(record["child"]))
            self.assertFalse(Path(record["scratch"]).exists())

    def test_real_stdio_discovery_read_action_and_confirmation(self):
        async def exercise():
            async with Client(self.parameters()) as client:
                tools = (await client.list_tools()).tools
                by_name = {tool.name: tool for tool in tools}
                self.assertEqual(set(by_name), {"list_operations", "read_operation", "perform_action"})
                self.assertTrue(by_name["list_operations"].annotations.read_only_hint)
                self.assertFalse(by_name["list_operations"].annotations.open_world_hint)
                self.assertTrue(by_name["read_operation"].annotations.read_only_hint)
                self.assertFalse(by_name["perform_action"].annotations.read_only_hint)
                self.assertFalse(by_name["perform_action"].annotations.idempotent_hint)
                self.assertTrue(by_name["perform_action"].annotations.destructive_hint)
                self.assertEqual(by_name["perform_action"].input_schema["properties"]["confirmed"]["const"], True)
                self.assertIn("status", by_name["read_operation"].output_schema["properties"])
                listed = await client.call_tool("list_operations", {})
                self.assertEqual(len(listed.structured_content["operations"]), 2)
                self.assertFalse(self.log.exists())
                for confirmation in (False, 1, "true", None):
                    denied = await self.call(client, "ok", action=True, confirmed=confirmation)
                    self.assertTrue(denied.is_error)
                unknown = await self.call(client, "ok", operation_id="missing")
                extra = await self.call(client, "ok", arguments={"case": "ok", "url": "https://evil.example.test"})
                self.assertEqual(unknown.structured_content["status"], "refused")
                self.assertEqual(extra.structured_content["status"], "refused")
                self.assertFalse(self.log.exists())
                for action in (False, True):
                    result = await self.call(client, "ok", action=action)
                    self.assertFalse(result.is_error)
                    self.assertEqual(result.structured_content["status"], "ok")
                    self.assertTrue(result.structured_content["untrusted_response"])
                    self.assertFalse(result.structured_content["automatic_retry"])
            self.assertEqual(len(records(self.log)), 2)
        anyio.run(exercise)
        self.assert_clean()

    def test_startup_action_gate_and_oversized_payload_prevent_dispatch(self):
        async def exercise():
            async with Client(self.parameters(allow=False)) as client:
                denied = await self.call(client, "ok", action=True)
                self.assertEqual(denied.structured_content["status"], "refused")
                large = await self.call(client, "ok", arguments={"case": "a" * 65537})
                self.assertEqual(large.structured_content["status"], "refused")
                self.assertFalse(self.log.exists())
        anyio.run(exercise)

    def test_approval_and_errors_are_structured_sanitized_and_never_retried(self):
        async def exercise():
            async with Client(self.parameters()) as client:
                result = await self.call(client, "approval", action=True)
                body = result.structured_content
                self.assertTrue(result.is_error)
                self.assertEqual(body["status"], "approval_required")
                self.assertEqual(body["approval_path"], "/approvals/" + APPROVAL_ID)
                self.assertEqual(body["approval_url"], "https://console.example.test/approvals/" + APPROVAL_ID)
                self.assertIn("identical", body["message"])
                self.assertIsNone(body["response"])
                self.assertNotIn(SECRET, result.model_dump_json())
                for case in ("bad_approval", "provider_error", "exception", "large", "slack_error"):
                    result = await self.call(client, case)
                    self.assertTrue(result.is_error)
                    self.assertIn(result.structured_content["status"], {"provider_error", "outcome_unknown"})
                    self.assertNotIn(SECRET, result.model_dump_json())
                    self.assertNotIn("evil.example.test", result.model_dump_json())
            self.assertEqual(len(records(self.log)), 6)
        anyio.run(exercise)
        self.assert_clean()

    def test_deadline_and_success_cleanup_descendants(self):
        async def exercise():
            async with Client(self.parameters(timeout=1.5)) as client:
                result = await self.call(client, "wait", action=True)
                self.assertTrue(result.is_error)
                self.assertEqual(result.structured_content["status"], "outcome_unknown")
                self.assertIn("deadline", result.structured_content["message"])
                result = await self.call(client, "descendant")
                self.assertFalse(result.is_error)
            self.assertEqual(len(records(self.log)), 2)
        anyio.run(exercise)
        self.assert_clean()

    def test_cancellation_releases_only_after_group_cleanup_and_busy_does_not_queue(self):
        async def exercise():
            async with Client(self.parameters(timeout=4.0)) as client:
                with anyio.CancelScope() as call_scope:
                    async with anyio.create_task_group() as group:
                        async def request():
                            await self.call(client, "wait", action=True)
                        group.start_soon(request)
                        with anyio.fail_after(3):
                            while not records(self.log):
                                await anyio.sleep(0.02)
                        result = await self.call(client, "ok", action=True)
                        self.assertEqual(result.structured_content["status"], "busy")
                        self.assertEqual(len(records(self.log)), 1)
                        call_scope.cancel()
                # Client task cancellation sends MCP cancellation. Allow its
                # bounded cleanup to finish before checking dispatch/accounting.
                await anyio.sleep(0.4)
                result = await self.call(client, "ok")
                self.assertFalse(result.is_error)
            self.assertEqual(len(records(self.log)), 2)
        anyio.run(exercise)
        self.assert_clean()

    def test_worker_independent_deadline_kills_its_group_without_parent_cleanup(self):
        context = multiprocessing.get_context("spawn")
        received, sent = context.Pipe(duplex=False)
        scratch = self.directory / "owned-worker-scratch"
        scratch.mkdir(mode=0o700)
        worker = context.Process(target=server._execute_worker,
            args=(FixturePrepared("fixture_action", "wait", str(self.log), effect="action"),
                sent, str(scratch), 0.3))
        worker.start()
        sent.close()
        try:
            self.assertTrue(received.poll(3))
            self.assertEqual(received.recv_bytes(), b'{"ready":true}')
            worker.join(3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(worker.exitcode, -signal.SIGKILL)
            entries = records(self.log)
            self.assertEqual(len(entries), 1)
            self.assertFalse(running(entries[0]["child"]))
        finally:
            if worker.is_alive():
                os.killpg(worker.pid, signal.SIGKILL)
                worker.join(2)
            received.close()
            worker.close()

    @unittest.skipUnless(NODE_EXECUTABLE, "Optional npm launcher requires an installed Node runtime")
    def test_actual_npm_launcher_contains_its_real_node_descendant(self):
        async def exercise():
            async with Client(self.parameters(timeout=1.5)) as client:
                result = await self.call(client, "node_wait")
                self.assertEqual(result.structured_content["status"], "outcome_unknown")
                self.assertIn("deadline", result.structured_content["message"])
            entries = records(Path(str(self.log) + ".node"))
            self.assertEqual(len(entries), 1, "Production contained launcher must create one real local Node child")
            self.assertFalse(running(entries[0]["pid"]))
        anyio.run(exercise)
        self.assert_clean()

    def test_provider_specific_business_errors_are_not_success(self):
        for provider, body in (("slack", {"ok": False, "error": SECRET}),
                ("cloudflare", {"success": False, "errors": [{"message": SECRET}]}),
                ("alchemy", {"jsonrpc": "2.0", "id": 1, "error": {"message": SECRET}})):
            result = server._translate({"status": 200, "response": body}, "configured", None, provider)
            self.assertTrue(result.is_error)
            self.assertEqual(result.structured_content["status"], "provider_error")
            self.assertNotIn(SECRET, result.model_dump_json())
        ordinary = server._translate({"status": 200, "response": {"error": "a legitimate document field"}},
            "configured", None, "notion")
        self.assertFalse(ordinary.is_error)

    def test_cli_help_and_invalid_configuration_are_safe(self):
        script = str(Path(server.__file__).resolve())
        help_result = subprocess.run([sys.executable, "-I", "-B", script, "--help"],
            capture_output=True, timeout=10, check=False)
        self.assertEqual(help_result.returncode, 0)
        self.assertIn(b"--allow-actions", help_result.stdout)
        self.assertIn(b"--print-client-config", help_result.stdout)
        invalid = subprocess.run([sys.executable, "-I", "-B", script, "--config", "fixture=" + str(self.directory / SECRET), "--check"],
            capture_output=True, timeout=10, check=False)
        self.assertEqual(invalid.returncode, 1)
        self.assertNotIn(SECRET.encode(), invalid.stderr + invalid.stdout)
        self.assertNotIn(b"Traceback", invalid.stderr)

    def test_print_client_config_preserves_paths_without_secrets_or_network(self):
        directory = self.directory / "private files with spaces"
        directory.mkdir()
        for alias, provider in (("balance", "stripe"), ("message", "slack")):
            (directory / (alias + " file.json")).write_text(json.dumps(engine_configuration(provider)), encoding="utf-8")
        configurations = [item for alias in ("balance", "message")
            for item in ("--config", alias + "=" + str(directory / (alias + " file.json")))]
        script = str(Path(server.__file__).resolve())
        # Exercise the real CLI with a socket/DNS audit hook, not a fake loader.
        command = [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--network-free-cli"]
        printed = subprocess.run(command + configurations + ["--print-client-config"],
            capture_output=True, timeout=10, check=False)
        self.assertEqual(printed.returncode, 0, printed.stderr)
        self.assertEqual(printed.stderr, b"")
        value = json.loads(printed.stdout)
        self.assertEqual(set(value), {"mcpServers"})
        launch = value["mcpServers"]["catchplate"]
        self.assertEqual(launch, {"command": str(Path(sys.executable).absolute()),
            "args": ["-I", "-B", script] + configurations})
        self.assertNotIn(SECRET.encode(), printed.stdout)
        self.assertNotIn(b"proxy.example.test", printed.stdout)
        self.assertNotIn(b"--allow-actions", printed.stdout)
        # The generated command is directly usable; no shell parsing required.
        checked = subprocess.run([launch["command"], *launch["args"], "--check"],
            capture_output=True, timeout=10, check=False)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(json.loads(checked.stdout)["operations"], 2)
        async def exercise():
            async with Client(StdioServerParameters(**launch, env={"PATH": os.defpath})) as client:
                self.assertEqual({tool.name for tool in (await client.list_tools()).tools},
                    {"list_operations", "read_operation", "perform_action"})
                refused = await client.call_tool("perform_action", {"operation_id": "message",
                    "arguments": {"text": "not sent"}, "confirmed": True})
                self.assertEqual(refused.structured_content["status"], "refused")
        anyio.run(exercise)
        enabled = subprocess.run(command + configurations + ["--allow-actions", "message",
            "--console-origin", "https://console.example.test/", "--print-client-config"],
            capture_output=True, timeout=10, check=False)
        self.assertEqual(enabled.returncode, 0, enabled.stderr)
        args = json.loads(enabled.stdout)["mcpServers"]["catchplate"]["args"]
        self.assertEqual(args[-4:], ["--allow-actions", "message", "--console-origin", "https://console.example.test"])
        self.assertNotIn(SECRET.encode(), enabled.stdout)

    def test_print_client_config_validates_locally_and_keeps_venv_interpreter(self):
        configuration = self.directory / "balance.json"
        configuration.write_text(json.dumps(engine_configuration("stripe")), encoding="utf-8")
        argv = ["server.py", "--config", "balance=" + str(configuration), "--print-client-config"]
        captured = io.StringIO()
        # Resolving this path's symlink would lose the venv; preserve it verbatim.
        selected = str(self.directory / "virtual environment" / "bin" / "python")
        with patch.object(sys, "argv", argv), patch.object(sys, "executable", selected), \
                patch.object(server, "create_server", side_effect=AssertionError("Must not start MCP")), redirect_stdout(captured):
            server.main()
        self.assertEqual(json.loads(captured.getvalue())["mcpServers"]["catchplate"]["command"], selected)
        command = [sys.executable, "-I", "-B", str(Path(server.__file__).resolve())]
        for suffix in (["--config", "balance=" + str(configuration), "--allow-actions", "unknown", "--print-client-config"],
                ["--config", "balance=" + str(self.directory / SECRET), "--print-client-config"],
                ["--config", "balance=" + str(configuration), "--check", "--print-client-config"]):
            failed = subprocess.run(command + suffix, capture_output=True, timeout=10, check=False)
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(failed.stdout, b"")
            self.assertNotIn(SECRET.encode(), failed.stderr)

    def test_real_engine_through_stdio_and_cli_check_without_provider_transport(self):
        for alias, provider in (("balance", "stripe"), ("message", "slack")):
            (self.directory / (alias + ".json")).write_text(json.dumps(engine_configuration(provider)), encoding="utf-8")
        script = str(Path(server.__file__).resolve())
        checked = subprocess.run([sys.executable, "-I", "-B", script, "--config",
            "balance=" + str(self.directory / "balance.json"), "--check"], capture_output=True, timeout=10)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(json.loads(checked.stdout), {"status": "configured", "operations": 1,
            "transport": "stdio", "provider_calls": 0})
        params = StdioServerParameters(command=sys.executable,
            args=["-I", "-B", str(Path(__file__).resolve()), "--engine-stdio", str(self.directory)], env={"PATH": os.defpath})
        async def exercise():
            async with Client(params) as client:
                descriptors = (await client.call_tool("list_operations", {})).structured_content["operations"]
                self.assertEqual({item["id"] for item in descriptors}, {"balance", "message"})
                self.assertNotIn(SECRET, json.dumps(descriptors))
                for name, arguments in (("read_operation", {"operation_id": "balance", "arguments": {}}),
                        ("perform_action", {"operation_id": "message", "arguments": {"text": "Hello"}, "confirmed": True})):
                    result = await client.call_tool(name, arguments, read_timeout_seconds=10.0)
                    self.assertFalse(result.is_error, result.model_dump_json())
                    self.assertTrue(result.structured_content["response"]["synthetic"])
                denied = await client.call_tool("perform_action", {"operation_id": "message",
                    "arguments": {"text": "Hello", "channel": "other"}, "confirmed": True})
                self.assertEqual(denied.structured_content["status"], "refused")
        anyio.run(exercise)
        dispatched = records(self.directory / "engine-calls.jsonl")
        self.assertEqual(len(dispatched), 2)
        self.assertIs(dispatched[0]["send"], False)
        self.assertIs(dispatched[1]["send"], True)
        self.assertEqual(dispatched[1]["body"]["text"], "Hello")
        self.assertEqual(dispatched[1]["body"]["channel"], engine_configuration("slack")["scope"]["channel"])


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--network-free-cli":
        import runpy
        sys.addaudithook(_no_provider)
        sys.argv = [str(Path(server.__file__).resolve()), *sys.argv[2:]]
        runpy.run_path(sys.argv[0], run_name="__main__")
    elif len(sys.argv) == 5 and sys.argv[1] == "--fixture-stdio":
        server.create_server(FixtureOperations(sys.argv[2], sys.argv[3] == "enabled"),
            timeout=float(sys.argv[4])).run(transport="stdio")
    elif len(sys.argv) == 3 and sys.argv[1] == "--engine-stdio":
        server.create_server(EngineFixtureOperations(sys.argv[2])).run(transport="stdio")
    else:
        unittest.main()
