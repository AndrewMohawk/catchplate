#!/usr/bin/env python3
"""Actual pinned SDK serialization, using in-memory transports only.

This is not provider acceptance or a proxy/TLS test. No API key is required.
Run with the dedicated examples/common-apps/requirements-ai.txt environment.
"""
from __future__ import annotations

import importlib.util
from importlib.metadata import version
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


example = module("ai_example", "examples/common-apps/ai_python.py")
presets = module("ai_presets", "serverware/operator_common_apps_ai.py")


def configuration(provider):
    operation, url = example.OPERATIONS[provider]
    model = "vendor/fixture-model" if provider == "openrouter" else "fixture-model"
    return {"app_preset": provider, "app_operation": operation,
        "upstream_url": url.format(model=model), "methods": ["POST"],
        "scope": {"model": model, "max_output_tokens": 128}}


def response_body(provider):
    if provider == "openai":
        return {"id": "resp_fixture", "object": "response", "created_at": 0, "model": "fixture-model",
            "status": "completed", "output": [{"id": "msg_fixture", "type": "message", "role": "assistant",
                "status": "completed", "content": [{"type": "output_text", "text": "Hello", "annotations": []}]}]}
    if provider == "anthropic":
        return {"id": "msg_fixture", "type": "message", "role": "assistant", "model": "fixture-model",
            "content": [{"type": "text", "text": "Hello"}], "stop_reason": "end_turn",
            "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}
    if provider == "gemini":
        return {"candidates": [{"content": {"role": "model", "parts": [{"text": "Hello"}]}, "finishReason": "STOP"}]}
    return {"id": "chatcmpl_fixture", "object": "chat.completion", "created": 0,
        "model": "vendor/fixture-model", "choices": [{"index": 0, "finish_reason": "stop",
            "message": {"role": "assistant", "content": "Hello"}}]}


def capture(provider, *, status=200, response=None):
    if provider == "gemini":
        import httpx as http
    else:
        import httpx2 as http
    seen = []

    def handler(request):
        seen.append({"method": request.method, "url": str(request.url),
            "headers": dict(request.headers), "body": json.loads(request.content)})
        body = response if response is not None else response_body(provider) if status == 200 else {
            "error": {"message": "Synthetic rate limit", "type": "rate_limit_error", "code": 429}}
        return http.Response(status, json=body)

    client = http.Client(transport=http.MockTransport(handler), trust_env=False,
        follow_redirects=False, timeout=30, headers={"accept-encoding": "identity"})
    return client, seen


class StockSDKTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def test_pinned_libraries(self):
        self.assertEqual({name: version(name) for name in example.PINS}, example.PINS)

    def test_four_actual_sdk_requests(self):
        for provider in example.OPERATIONS:
            with self.subTest(provider=provider):
                client, seen = capture(provider)
                result = example.infer(configuration(provider), "Hi", client=client)
                self.assertEqual(result["text"], "Hello")
                self.assertEqual(len(seen), 1)
                wire = seen[0]
                self.assertEqual(wire["method"], "POST")
                self.assertEqual(wire["url"], configuration(provider)["upstream_url"])
                preset = next(row for row in presets.PRESETS if row["id"] == provider)
                headers = wire["headers"]
                self.assertEqual(headers[preset["header_name"].lower()], preset["placeholder"])
                self.assertEqual(headers["accept-encoding"], "identity")
                framing = {"host", "content-type", "content-length", "connection", "accept-encoding",
                    preset["header_name"].lower()}
                self.assertFalse(set(headers) - framing - set(preset["operations"][0]["allowed_headers"]))
                if provider == "gemini":
                    self.assertEqual(wire["body"], {"contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
                        "generationConfig": {"maxOutputTokens": 128}})
                else:
                    self.assertIs(wire["body"]["stream"], False)
                    self.assertEqual(wire["body"]["model"], configuration(provider)["scope"]["model"])
                    field = "max_output_tokens" if provider == "openai" else "max_tokens"
                    self.assertEqual(wire["body"][field], 128)
                    if provider == "openai":
                        self.assertIs(wire["body"]["store"], False)
                        self.assertEqual(wire["body"]["input"], "Hi")
                    else:
                        self.assertEqual(wire["body"]["messages"], [{"role": "user", "content": "Hi"}])
                    if provider == "anthropic":
                        self.assertEqual(headers["anthropic-version"], "2023-06-01")

    def test_retryable_error_still_makes_only_one_attempt(self):
        for provider in example.OPERATIONS:
            with self.subTest(provider=provider):
                client, seen = capture(provider, status=429)
                with self.assertRaises(Exception):
                    example.infer(configuration(provider), "Hi", client=client)
                self.assertEqual(len(seen), 1)

    def test_anthropic_without_home_uses_private_profile_and_restores_environment(self):
        import httpx2
        from anthropic.lib.credentials import _constants

        for previous in (None, "/never-read-ambient-anthropic-profile"):
            for status in (200, 429):
                with self.subTest(previous=previous, status=status):
                    if previous is None:
                        os.environ.pop("ANTHROPIC_CONFIG_DIR", None)
                    else:
                        os.environ["ANTHROPIC_CONFIG_DIR"] = previous
                    paths = []

                    def handler(request):
                        directory = Path(os.environ["ANTHROPIC_CONFIG_DIR"])
                        self.assertNotEqual(str(directory), previous)
                        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
                        self.assertEqual(list(directory.iterdir()), [])
                        self.assertNotIn("HOME", os.environ)
                        self.assertEqual(request.headers["x-api-key"], "serverware-anthropic-placeholder-v1")
                        paths.append(directory)
                        return httpx2.Response(status, json=response_body("anthropic") if status == 200 else {
                            "error": {"type": "rate_limit_error", "message": "Synthetic refusal"}})

                    client = httpx2.Client(transport=httpx2.MockTransport(handler), trust_env=False,
                        headers={"accept-encoding": "identity"})
                    with patch.object(Path, "home", side_effect=RuntimeError("No passwd home")), \
                            patch.object(_constants, "_read_active_config_pointer",
                                side_effect=AssertionError("Ambient profile read refused")):
                        if status == 200:
                            self.assertEqual(example.infer(configuration("anthropic"), "Hi", client=client)["text"], "Hello")
                        else:
                            with self.assertRaises(Exception):
                                example.infer(configuration("anthropic"), "Hi", client=client)
                    self.assertEqual(len(paths), 1)
                    self.assertFalse(paths[0].exists())
                    self.assertEqual(os.environ.get("ANTHROPIC_CONFIG_DIR"), previous)

    def test_four_sdk_approval_responses_keep_only_safe_review_path(self):
        identifier = "c72b3ace-e45f-4743-9c43-06f46c03e97e"
        path = "/approvals/" + identifier
        body = {"allowed": False, "action": "approval_required", "status_code": 428,
            "approval_id": identifier, "approval_url": path,
            "payload": {"error": "host_trusted_approval_required", "approval_id": identifier,
                "approval_url": path, "approval_status": "pending",
                "retry_semantics": "explicit_identical_request_after_approval"},
            "untrusted_extra": "never-echo-provider-or-auth-data"}
        for provider in example.OPERATIONS:
            with self.subTest(provider=provider):
                client, seen = capture(provider, status=428, response=body)
                result = example.infer(configuration(provider), "Hi", client=client)
                self.assertEqual(result["status"], "approval_required")
                self.assertEqual(result["http_status"], 428)
                self.assertEqual(result["approval_path"], path)
                self.assertNotIn("never-echo", json.dumps(result))
                self.assertNotIn("text", result)
                self.assertEqual(len(seen), 1)
                unsafe = {**body, "approval_url": "https://other.example/"}
                client, seen = capture(provider, status=428, response=unsafe)
                with self.assertRaises(Exception):
                    example.infer(configuration(provider), "Hi", client=client)
                self.assertEqual(len(seen), 1)

    def test_scope_refused_before_dispatch(self):
        for provider in example.OPERATIONS:
            config = configuration(provider)
            for modified in ({**config, "upstream_url": "https://other.example/"},
                    {**config, "methods": ["GET"]},
                    {**config, "scope": {**config["scope"], "max_output_tokens": True}},
                    {**config, "scope": {**config["scope"], "max_output_tokens": 4097}}):
                with self.subTest(provider=provider, modified=modified):
                    client, seen = capture(provider)
                    with client, self.assertRaises(ValueError):
                        example.infer(modified, "Hi", client=client)
                    self.assertEqual(seen, [])

    def test_openrouter_excludes_auto_router_and_suffixed_tools(self):
        config = configuration("openrouter")
        for model in ("openrouter/auto", "openrouter/free", "vendor/model:online", "vendor/model:free"):
            with self.subTest(model=model), self.assertRaises(ValueError):
                example.validate_scope({**config, "scope": {**config["scope"], "model": model}}, "Hi")

    def test_proxy_and_destination_have_distinct_verified_contexts(self):
        config = {"proxy_url": "https://proxy.example", "proxy_username": "application",
            "proxy_password": "synthetic-only", "ca_file": "/inner.pem", "proxy_ca_file": "/outer.pem"}
        for provider in ("openai", "gemini"):
            if provider == "gemini":
                import httpx as http
            else:
                import httpx2 as http
            contexts = [ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)]
            with patch.object(example, "_context", side_effect=contexts) as context, \
                    patch.object(http, "HTTPTransport", wraps=http.HTTPTransport) as transport:
                with example.http_client(config, provider):
                    pass
                self.assertEqual([call.args for call in context.call_args_list], [("/outer.pem",), ("/inner.pem",)])
                self.assertIs(transport.call_args.kwargs["verify"], contexts[1])
                self.assertIs(transport.call_args.kwargs["proxy"].ssl_context, contexts[0])
                self.assertEqual(transport.call_args.kwargs["retries"], 0)
                self.assertIs(transport.call_args.kwargs["trust_env"], False)
                for item in contexts:
                    self.assertTrue(item.check_hostname)
                    self.assertEqual(item.verify_mode, ssl.CERT_REQUIRED)

    def test_cli_requires_explicit_send(self):
        result = subprocess.run([sys.executable, str(ROOT / "examples/common-apps/ai_python.py"),
            "--config", "/does/not/exist", "--prompt", "Hi"], capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"--send", result.stderr)

    def test_shared_download_loader_resolves_ca_paths(self):
        application = "f5e131bf-c28a-4f97-8e54-1ac269607dce"
        with tempfile.TemporaryDirectory(prefix="serverware-ai-config-") as directory:
            path = Path(directory) / "client.json"
            for provider in example.OPERATIONS:
                preset = next(row for row in presets.PRESETS if row["id"] == provider)
                config = {**configuration(provider), "application_id": application,
                    "access_rule_id": "c72b3ace-e45f-4743-9c43-06f46c03e97e",
                    "proxy_authentication": "basic_and_bearer_v1", "proxy_username": application,
                    "proxy_password": "synthetic-proxy-token", "proxy_url": "https://proxy.example",
                    "token_expires_at_epoch_ms": time.time_ns() // 1000000 + 60000,
                    "ca_file": "serverware-ca.pem", "proxy_ca_file": None,
                    "credential_input": "replace_exact", "response_mode": "unfiltered_json_or_empty_v2",
                    "request_headers": {preset["header_name"]: preset["placeholder"],
                        **preset["operations"][0].get("request_headers", {})}}
                path.write_text(json.dumps(config), encoding="utf-8")
                loaded = example.load_configuration(path)
                example.validate_scope(loaded, "Hi")
                self.assertEqual(loaded["ca_file"], str(Path(directory) / "serverware-ca.pem"))
                self.assertIsNone(loaded["proxy_ca_file"])


if __name__ == "__main__":
    unittest.main()
