"""Offline checks using actual SDK serializers; no provider calls or credentials."""
import asyncio
import copy
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import certifi
import httpx
from multidict import CIMultiDict, CIMultiDictProxy
from yarl import URL

spec = importlib.util.spec_from_file_location("service_example", Path(__file__).with_name("services_python.py"))
example = importlib.util.module_from_spec(spec)
spec.loader.exec_module(example)


def config(provider, operation, scope=None):
    scope = scope or {}
    template, _, keys = example.OPERATIONS[provider, operation]
    return {"app_preset": provider, "app_operation": operation, "scope": scope,
        "upstream_url": template.format(**scope), "methods": ["POST" if provider == "slack" else "GET"],
        "request_query": {}, "query_keys": list(keys), "ca_file": certifi.where(), "proxy_ca_file": None,
        "proxy_url": "https://proxy.example.test", "proxy_username": "public-application",
        "proxy_password": "private-serverware-test-token", "_proxy_url": "https://public-application:private-serverware-test-token@proxy.example.test"}


class FakeSlackSession:
    """Documented session injection seam; the real SDK builds the request."""
    seen = []
    payload = {"ok": True, "channel": "C0123456789", "ts": "123.456"}
    status = 200
    redirect = False
    connection_error = False
    request_calls = 0
    closed = False

    def __init__(self, **options):
        self.options = options

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        self.closed = True

    def request(self, method, url, **kwargs):
        FakeSlackSession.request_calls += 1
        owner = self

        class Context:
            async def __aenter__(self):
                trace = owner.options["trace_configs"][0]
                params = SimpleNamespace(method=method, url=URL(url), headers=kwargs["headers"])
                for callback in trace.on_request_start:
                    await callback(owner, None, params)
                FakeSlackSession.seen.append((method, url, kwargs, owner.options))
                if FakeSlackSession.connection_error:
                    from aiohttp import ClientConnectionError
                    raise ClientConnectionError("private-serverware-test-token")
                if FakeSlackSession.redirect:
                    for callback in trace.on_request_redirect:
                        await callback(owner, None, params)
                response_class = owner.options["response_class"]
                response = response_class.__new__(response_class)
                response.status = FakeSlackSession.status
                response._headers = CIMultiDictProxy(CIMultiDict({"Content-Type": "application/json"}))
                response._cache = {}
                response._stored_content_type = None

                class Content:
                    async def iter_chunked(self, size):
                        raw = json.dumps(FakeSlackSession.payload).encode()
                        for offset in range(0, len(raw), size):
                            yield raw[offset:offset + size]

                response.content = Content()
                return response

            async def __aexit__(self, *_):
                return False

        return Context()


class ServicesSDKTests(unittest.TestCase):
    def setUp(self):
        pem = Path(certifi.where()).read_bytes()
        certificate = pem[pem.index(b"-----BEGIN CERTIFICATE-----"):].split(b"-----END CERTIFICATE-----", 1)[0] + b"-----END CERTIFICATE-----\n"
        patcher = patch.object(example.common, "public_ca", return_value=certificate)
        patcher.start()
        self.addCleanup(patcher.stop)

    def capture(self, configuration, payload, query=(), status=200):
        seen = []

        def handle(request):
            seen.append(request)
            return httpx.Response(status, json=payload)

        result = example.execute(configuration, query=query, transport=httpx.MockTransport(handle))
        self.assertEqual(len(seen), 1)
        self.assertEqual(result["response"], payload)
        return result, seen[0]

    def test_actual_notion_page_and_cursor_serialization(self):
        identifier = "01234567-89ab-cdef-0123-456789abcdef"
        result, request = self.capture(config("notion", "retrieve_page", {"page_id": identifier}),
            {"object": "page", "id": identifier})
        self.assertTrue(result["ok"])
        self.assertEqual(request.headers["notion-version"], "2026-03-11")
        self.assertNotIn("content-type", request.headers)
        result, request = self.capture(config("notion", "block_children", {"block_id": identifier}),
            {"object": "list", "results": [], "has_more": True, "next_cursor": "next"},
            ["start_cursor=cursor value+", "page_size=1"])
        self.assertEqual(request.url.query, b"page_size=1&start_cursor=cursor%20value%2B")
        self.assertTrue(result["response"]["has_more"])

    def test_actual_stripe_balance_and_customer_filters(self):
        result, request = self.capture(config("stripe", "balance"),
            {"object": "balance", "available": [], "pending": [], "livemode": False})
        self.assertTrue(result["ok"])
        self.assertEqual(request.headers["authorization"], "Bearer serverware-stripe-placeholder-v1")
        self.assertNotIn("content-type", request.headers)
        self.assertIn("stripe-version", request.headers)
        result, request = self.capture(config("stripe", "customers"),
            {"object": "list", "data": [], "has_more": True, "url": "/v1/customers"},
            ["limit=1", "email=team+test@example.com", "ending_before=cus_before"])
        self.assertEqual(request.url.query, b"email=team%2Btest%40example.com&ending_before=cus_before&limit=1")
        self.assertTrue(result["response"]["has_more"])

    def test_actual_cloudflare_metadata_and_first_page_only(self):
        payload = {"success": True, "errors": [], "messages": [], "result": [],
            "result_info": {"page": 1, "per_page": 1, "count": 0, "total_pages": 2, "total_count": 1}}
        for operation, scope in [("zones_sdk_v1", {}), ("dns_records_sdk_v1", {"zone_id": "0" * 32})]:
            result, request = self.capture(config("cloudflare", operation, scope), payload,
                ["per_page=1", "page=1"])
            self.assertTrue(result["ok"])
            self.assertEqual(request.url.query, b"page=1&per_page=1")
            self.assertEqual(request.headers["api-version"], "2026-10-15")
            self.assertEqual(request.headers["x-stainless-retry-count"], "0")
            self.assertEqual(request.headers["x-stainless-async"], "false")
            self.assertNotIn("content-type", request.headers)
            self.assertNotIn("x-stainless-raw-response", request.headers)

    def test_sdk_http_and_application_errors_are_not_retried(self):
        cases = [(config("notion", "retrieve_page", {"page_id": "01234567-89ab-cdef-0123-456789abcdef"}),
                {"object": "error", "status": 429, "code": "rate_limited", "message": "limited"}, 429),
            (config("stripe", "balance"), {"error": {"type": "api_error", "message": "unavailable"}}, 503),
            (config("cloudflare", "zones_sdk_v1"), {"success": False, "errors": [{"code": 1000}], "result": []}, 200)]
        for configuration, payload, status in cases:
            result, _ = self.capture(configuration, payload, status=status)
            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], status)

    def test_scope_body_and_query_validation_before_dispatch(self):
        refused = []
        good = config("stripe", "customers")
        for change in [{"upstream_url": "https://api.stripe.com/v1/refunds"}, {"methods": ["POST"]}, {"scope": {"account": "other"}}]:
            refused.append(({**good, **change}, None, (), False))
        refused.extend([(good, None, ["limit=1", "limit=2"], False), (good, b"{}", (), False),
            (good, None, ["unknown=x"], False), (good, None, ["limit=101"], False)])
        for configuration, body, query, intent in refused:
            with self.assertRaisesRegex(ValueError, "SDK request failed"):
                example.execute(configuration, body, query, intent,
                    transport=httpx.MockTransport(lambda _: self.fail("Unexpected dispatch")))

    def test_transport_scope_guard_bounds_and_sanitized_failures(self):
        configuration = config("stripe", "balance")
        client, guard = example.http_client(configuration, configuration["upstream_url"],
            transport=httpx.MockTransport(lambda _: self.fail("Unexpected dispatch")))
        with client, self.assertRaises(ValueError):
            client.get("https://api.stripe.com/v1/customers")
        self.assertFalse(guard.attempted)
        for handler in [lambda _: (_ for _ in ()).throw(RuntimeError(configuration["proxy_password"])),
                lambda _: httpx.Response(200, json={"oversized": "x" * (1024 * 1024)})]:
            with self.assertRaises(ValueError) as captured:
                example.execute(configuration, transport=httpx.MockTransport(handler))
            self.assertNotIn(configuration["proxy_password"], str(captured.exception))
            self.assertIsNone(captured.exception.__context__)
            self.assertIsNone(captured.exception.__cause__)

    def test_actual_slack_serialization_and_application_error(self):
        configuration = config("slack", "post_message", {"channel": "C0123456789"})
        body = json.dumps({"channel": "C0123456789", "text": "Deployment completed.",
            "unfurl_links": False, "unfurl_media": False}).encode()
        for payload in [{"ok": True, "ts": "123.456"}, {"ok": False, "error": "channel_not_found"}]:
            FakeSlackSession.seen, FakeSlackSession.payload, FakeSlackSession.redirect = [], payload, False
            result = example.execute(configuration, body, execute_write=True, session_factory=FakeSlackSession)
            self.assertEqual(result["ok"], payload["ok"])
            self.assertEqual(len(FakeSlackSession.seen), 1)
            method, url, arguments, options = FakeSlackSession.seen[0]
            self.assertEqual(method, "POST")
            self.assertEqual(url, configuration["upstream_url"])
            self.assertEqual(arguments["json"], json.loads(body))
            self.assertEqual(arguments["headers"]["Authorization"], "Bearer serverware-slack-placeholder-v1")
            self.assertFalse(options["trust_env"])
        for intent, wrong_body in [(False, body), (True, b"{}"), (True, body.replace(b"C0123456789", b"C9999999999"))]:
            with self.assertRaises(ValueError):
                example.execute(configuration, wrong_body, execute_write=intent, session_factory=FakeSlackSession)
        FakeSlackSession.seen, FakeSlackSession.redirect = [], True
        with self.assertRaises(ValueError):
            example.execute(configuration, body, execute_write=True, session_factory=FakeSlackSession)
        self.assertEqual(len(FakeSlackSession.seen), 1)
        FakeSlackSession.redirect = False

    def test_validated_approval_path_survives_sdk_error(self):
        identifier = "01234567-89ab-4def-8123-456789abcdef"
        path = "/approvals/" + identifier
        payload = {"allowed": False, "action": "approval_required", "status_code": 428,
            "approval_id": identifier, "approval_url": path, "payload": {"approval_id": identifier,
                "approval_url": path, "error": "host_trusted_approval_required", "approval_status": "pending",
                "retry_semantics": "explicit_identical_request_after_approval"}}
        result, _ = self.capture(config("stripe", "balance"), payload, status=428)
        self.assertEqual(result["approval_path"], path)
        self.assertFalse(result["ok"])
        bad = copy.deepcopy(payload)
        bad["approval_url"] = "https://outside.example/"
        with self.assertRaises(ValueError):
            example.execute(config("stripe", "balance"), transport=httpx.MockTransport(lambda _: httpx.Response(428, json=bad)))

    def test_pins_and_clean_child_launch(self):
        for package, pin in example.PINS.items():
            self.assertEqual(example.version(package), pin)
        with patch.object(example.subprocess, "run", return_value=SimpleNamespace(returncode=0,
                stdout=b'{"provider":"stripe","status":403,"response":{},"ok":false}')) as run:
            result = example.launch(config("stripe", "balance"), None, [], False)
            self.assertFalse(result["ok"])
            self.assertEqual(run.call_args.kwargs["env"], {})
            self.assertEqual(run.call_args.args[0][1:3], ["-I", "-B"])

    def test_child_approval_result_keeps_zero_exit_and_propagates_through_launch(self):
        configuration = config("stripe", "balance")
        identifier = "01234567-89ab-4def-8123-456789abcdef"
        path = "/approvals/" + identifier
        payload = {"allowed": False, "action": "approval_required", "status_code": 428,
            "approval_id": identifier, "approval_url": path, "payload": {"approval_id": identifier,
                "approval_url": path, "error": "host_trusted_approval_required", "approval_status": "pending",
                "retry_semantics": "explicit_identical_request_after_approval"}}
        result = example.response_result("stripe", 428, json.dumps(payload).encode())
        incoming = io.TextIOWrapper(io.BytesIO(json.dumps({"configuration": configuration,
            "body": None, "query": [], "execute_write": False}).encode()))
        output = io.StringIO()
        with patch.object(example.sys, "argv", ["services_python.py", "--child"]), \
                patch.object(example.sys, "stdin", incoming), patch.dict(example.os.environ, {}, clear=True), \
                patch.object(example, "execute", return_value=result), redirect_stdout(output):
            child_exit = example.main()
        self.assertEqual(child_exit, 0)
        with patch.object(example.subprocess, "run", return_value=SimpleNamespace(
                returncode=child_exit, stdout=output.getvalue().encode())):
            propagated = example.launch(configuration, None, [], False)
        self.assertEqual(propagated, result)
        self.assertEqual(propagated["approval_path"], path)
        self.assertFalse(propagated["ok"])

    def test_slack_sdk_rejecting_recorded_success_becomes_safe_failure(self):
        configuration = config("slack", "post_message", {"channel": "C0123456789"})
        body = json.dumps({"channel": "C0123456789", "text": "Deployment completed.",
            "unfurl_links": False, "unfurl_media": False}).encode()
        # The raw 201 JSON initially appears successful; Slack's actual response
        # validator requires HTTP 200 and raises after the body was recorded.
        FakeSlackSession.status, FakeSlackSession.payload = 201, {"ok": True, "ts": "123.456"}
        FakeSlackSession.request_calls = 0
        try:
            result = example.execute(configuration, body, execute_write=True, session_factory=FakeSlackSession)
            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], 201)
            self.assertEqual(result["error"], "SDK could not interpret the response")
            self.assertEqual(result["response"], FakeSlackSession.payload)
            self.assertEqual(FakeSlackSession.request_calls, 1)
        finally:
            FakeSlackSession.status = 200

    def test_slack_no_connection_retry_and_cloudflare_no_ambient_auth(self):
        configuration = config("slack", "post_message", {"channel": "C0123456789"})
        body = json.dumps({"channel": "C0123456789", "text": "Deployment completed.",
            "unfurl_links": False, "unfurl_media": False}).encode()
        FakeSlackSession.request_calls, FakeSlackSession.connection_error = 0, True
        try:
            with self.assertRaises(ValueError) as captured:
                example.execute(configuration, body, execute_write=True, session_factory=FakeSlackSession)
            self.assertEqual(FakeSlackSession.request_calls, 1)
            self.assertNotIn(configuration["proxy_password"], str(captured.exception))
            self.assertIsNone(captured.exception.__context__)
        finally:
            FakeSlackSession.connection_error = False
        with patch.dict(example.os.environ, {"CLOUDFLARE_API_KEY": "ambient-provider-key"}):
            with self.assertRaises(ValueError):
                example.execute(config("cloudflare", "zones_sdk_v1"),
                    transport=httpx.MockTransport(lambda _: self.fail("Ambient credential dispatched")))


if __name__ == "__main__":
    unittest.main()
