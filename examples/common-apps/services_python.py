"""One scoped call with Slack, Notion, Stripe or Cloudflare's Python SDK.

Notion's maintained Python SDK is third-party. No pagination iterator, provider
key, automatic retry or implicit write is used. See requirements-services.txt.
"""
from __future__ import annotations

import argparse
import asyncio
import importlib.util
from importlib.metadata import version
import json
import logging
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
from urllib.parse import parse_qsl, urlsplit
from uuid import UUID

_spec = importlib.util.spec_from_file_location("services_common", Path(__file__).with_name("request.py"))
common = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(common)
load_configuration = common.load_configuration
PINS = {"slack-sdk": "3.45.0", "notion-client": "3.1.0", "stripe": "16.0.0",
    "cloudflare": "5.9.0", "aiohttp": "3.14.5", "httpx": "0.28.1"}
FAILURE = "SDK request failed. Inspect the Catchplate audit log. No automatic retry was sent; a sent write may have an unknown outcome."
SDK_LOGGER = logging.getLogger("catchplate.services.sdk")
SDK_LOGGER.disabled = True
OPERATIONS = {
    ("slack", "post_message"): ("https://slack.com/api/chat.postMessage", "channel", ()),
    ("notion", "retrieve_page"): ("https://api.notion.com/v1/pages/{page_id}", "page_id", ()),
    ("notion", "block_children"): ("https://api.notion.com/v1/blocks/{block_id}/children", "block_id", ("page_size", "start_cursor")),
    ("stripe", "balance"): ("https://api.stripe.com/v1/balance", None, ()),
    ("stripe", "customers"): ("https://api.stripe.com/v1/customers", None, ("email", "ending_before", "limit", "starting_after")),
    ("cloudflare", "zones_sdk_v1"): ("https://api.cloudflare.com/client/v4/zones", None, ("direction", "name", "order", "page", "per_page", "status")),
    ("cloudflare", "dns_records_sdk_v1"): ("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records", "zone_id", ("direction", "name", "order", "page", "per_page", "type")),
}
READ_HEADERS = {"host", "authorization", "accept", "accept-encoding", "accept-language",
    "connection", "sec-fetch-mode", "user-agent"}
PROVIDER_HEADERS = {
    "notion": {"notion-version"},
    "stripe": {"stripe-version", "x-stripe-client-user-agent"},
    "cloudflare": {"api-version", "x-stainless-lang", "x-stainless-package-version", "x-stainless-os",
        "x-stainless-arch", "x-stainless-runtime", "x-stainless-runtime-version", "x-stainless-async",
        "x-stainless-retry-count", "x-stainless-read-timeout"},
}


def validate(config, body=None, query=(), execute_write=False):
    provider, operation = config.get("app_preset"), config.get("app_operation")
    if (provider, operation) not in OPERATIONS:
        raise ValueError("Choose a supported SDK permission; Cloudflare needs a new SDK v1 permission")
    template, scope_key, keys = OPERATIONS[provider, operation]
    scope = config.get("scope")
    if type(scope) is not dict or set(scope) != ({scope_key} if scope_key else set()):
        raise ValueError("Invalid permission scope")
    if scope_key:
        value = scope[scope_key]
        pattern = (r"[CGD][A-Z0-9]{8,31}" if provider == "slack" else r"[0-9a-f]{32}" if provider == "cloudflare"
            else r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
        if type(value) is not str or re.fullmatch(pattern, value) is None:
            raise ValueError("Invalid permission scope value")
    method = "POST" if provider == "slack" else "GET"
    if config.get("upstream_url") != template.format(**scope) or config.get("methods") != [method]:
        raise ValueError("SDK target differs from permission")
    selected = {**config, "query_keys": list(keys)}
    url = common.request_url(selected, query)
    params = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True, strict_parsing=True))
    for key, value in params.items():
        if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Invalid query value")
        if key in {"limit", "page_size", "per_page", "page"}:
            maximum = 10000 if key == "page" else 100
            if re.fullmatch(r"[1-9][0-9]{0,4}", value) is None or not 1 <= int(value) <= maximum:
                raise ValueError("Pagination value outside example limits")
            params[key] = int(value)
    if "starting_after" in params and "ending_before" in params:
        raise ValueError("Choose one pagination direction")
    if type(execute_write) is not bool:
        raise ValueError("Explicit write intent must be boolean")
    arguments = None
    if method == "POST":
        if not execute_write or type(body) is not bytes or not 0 < len(body) <= common.MAX_BODY_BYTES:
            raise ValueError("Slack requires a reviewed body and --execute-write")
        arguments = common.strict_json(body.decode("utf-8"))
        allowed = {"channel", "text", "thread_ts", "mrkdwn", "unfurl_links", "unfurl_media"}
        if (type(arguments) is not dict or not set(arguments) <= allowed
                or arguments.get("channel") != scope["channel"]
                or type(arguments.get("text")) is not str or not 1 <= len(arguments["text"]) <= 4000
                or arguments.get("unfurl_links") is not False or arguments.get("unfurl_media") is not False
                or "mrkdwn" in arguments and type(arguments["mrkdwn"]) is not bool
                or "thread_ts" in arguments and (type(arguments["thread_ts"]) is not str
                    or re.fullmatch(r"[0-9.]{1,32}", arguments["thread_ts"]) is None)):
            raise ValueError("Slack body differs from the selected text-message permission")
    elif body is not None or execute_write:
        raise ValueError("This operation is read-only")
    return provider, operation, params, url, arguments


def context(ca_file=None):
    import certifi
    result = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    result.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca_file is None:
        result.load_verify_locations(cafile=certifi.where())
    else:
        result.load_verify_locations(cadata=common.public_ca(ca_file).decode("ascii"))
    return result


def response_result(provider, status, raw):
    limit = common.MAX_RESPONSE_BYTES if 200 <= status < 300 else common.MAX_BODY_BYTES
    if len(raw) > limit:
        raise ValueError("Response exceeded bound")
    value = common.strict_json(raw.decode("utf-8"))
    if type(value) is not dict:
        raise ValueError("A JSON object response is required")
    ok = 200 <= status < 300 and not (provider == "slack" and value.get("ok") is not True
        or provider == "cloudflare" and value.get("success") is not True)
    result = {"provider": provider, "status": status, "response": value, "ok": ok}
    if status == 428:
        payload = value.get("payload", {})
        identifier = value.get("approval_id")
        try:
            path = "/approvals/" + str(UUID(identifier))
            valid = (str(UUID(identifier)) == identifier and value.get("allowed") is False
                and value.get("action") == "approval_required" and value.get("status_code") == 428
                and value.get("approval_url") == path and payload.get("approval_url") == path
                and payload.get("approval_id") == identifier
                and payload.get("error") == "host_trusted_approval_required"
                and payload.get("approval_status") == "pending"
                and payload.get("retry_semantics") == "explicit_identical_request_after_approval")
        except (ValueError, TypeError, AttributeError):
            valid = False
        if not valid:
            raise ValueError("Invalid approval response")
        result.update(approval_path=path, instruction="Open this path on the Catchplate console. After approval, explicitly rerun the identical command and unchanged body. Nothing is retried automatically.")
    return result


def http_client(config, expected_url, *, transport=None):
    """Documented HTTPX transport hook: scope check, canonical query, one send.

    Only query encoding/order changes; method, path, values and SDK headers are
    never expanded or silently removed. The proxy remains the policy authority.
    """
    import httpx
    provider = config["app_preset"]
    if transport is None:
        proxy = httpx.Proxy(config["proxy_url"], auth=(config["proxy_username"], config["proxy_password"]),
            ssl_context=context(config.get("proxy_ca_file")))
        transport = httpx.HTTPTransport(proxy=proxy, verify=context(config["ca_file"]), trust_env=False, retries=0)

    class ScopedTransport(httpx.BaseTransport):
        def __init__(self):
            self.attempted = False
            self.result = None

        def handle_request(self, request):
            expected, actual = urlsplit(expected_url), urlsplit(str(request.url))
            pairs = parse_qsl(actual.query, keep_blank_values=True, strict_parsing=True)
            if (self.attempted or request.method != "GET" or request.content
                    or actual._replace(query="") != expected._replace(query="")
                    or len(dict(pairs)) != len(pairs)
                    or sorted(pairs) != sorted(parse_qsl(expected.query, keep_blank_values=True))
                    or not set(request.headers) <= READ_HEADERS | PROVIDER_HEADERS[provider]
                    or request.headers.get("authorization") != "Bearer catchplate-" + provider + "-placeholder-v1"):
                raise ValueError("SDK request differs from the selected operation")
            request.url = httpx.URL(expected_url)
            self.attempted = True
            response = transport.handle_request(request)
            try:
                if "application/json" not in response.headers.get("content-type", "").lower():
                    raise ValueError("JSON response required")
                chunks, size = [], 0
                limit = common.MAX_RESPONSE_BYTES if 200 <= response.status_code < 300 else common.MAX_BODY_BYTES
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > limit:
                        raise ValueError("Response exceeded bound")
                    chunks.append(chunk)
                raw = b"".join(chunks)
                self.result = response_result(provider, response.status_code, raw)
                return httpx.Response(response.status_code, headers=response.headers, content=raw, request=request)
            finally:
                response.close()

        def close(self):
            transport.close()

    guard = ScopedTransport()
    client = httpx.Client(transport=guard, trust_env=False, follow_redirects=False, timeout=30.0,
        headers={"accept-encoding": "identity"})
    return client, guard


def invoke_sdk(config, operation, params, client):
    """Ordinary SDK methods; do not iterate returned pagination objects."""
    provider = config["app_preset"]
    token = "catchplate-" + provider + "-placeholder-v1"
    if provider == "notion":
        from notion_client import Client
        # A Notion context manager would replace the supplied HTTPX client.
        sdk = Client(client=client, auth=token, notion_version="2026-03-11", retry=False, timeout_ms=30000,
            logger=SDK_LOGGER)
        if operation == "retrieve_page":
            sdk.pages.retrieve(page_id=config["scope"]["page_id"])
        else:
            sdk.blocks.children.list(block_id=config["scope"]["block_id"], **params)
    elif provider == "stripe":
        import stripe
        # Documented SDK opt-out: no telemetry files, home-directory lookup or
        # request-history metadata in this isolated one-call client.
        stripe.enable_telemetry = False

        class ScopedHTTPClient(stripe.HTTPClient):
            name = "httpx"

            def request(self, method, url, headers, post_data=None):
                if post_data:
                    raise ValueError("Read-only Stripe operation")
                response = client.request(method, url, headers=headers)
                return response.content, response.status_code, response.headers

        sdk = stripe.StripeClient(token, max_network_retries=0, http_client=ScopedHTTPClient())
        if operation == "balance":
            sdk.v1.balance.retrieve()
        else:
            sdk.v1.customers.list(params)
    else:
        from cloudflare import Cloudflare
        # CLI execution is isolated already. Direct helper callers must not let
        # SDK-specific auth/header overrides introduce ambient credentials.
        if any(name.startswith("CLOUDFLARE_") for name in os.environ):
            raise ValueError("Run the CLI with its clean SDK environment")
        sdk = Cloudflare(api_token=token, api_version="2026-10-15", max_retries=0,
            timeout=30.0, http_client=client)
        if operation == "zones_sdk_v1":
            sdk.zones.list(**params)
        else:
            sdk.dns.records.list(zone_id=config["scope"]["zone_id"], **params)


async def slack_call(config, arguments, *, session_factory=None):
    import aiohttp
    from slack_sdk.web.async_client import AsyncWebClient
    result = None
    attempted = False
    trace = aiohttp.TraceConfig()

    async def start(_session, _context, params):
        nonlocal attempted
        if attempted or params.method != "POST" or str(params.url) != config["upstream_url"]:
            raise ValueError("One exact Slack call is permitted")
        attempted = True

    async def redirect(*_):
        raise ValueError("Redirects are not permitted")

    trace.on_request_start.append(start)
    trace.on_request_redirect.append(redirect)

    class BoundedJSONResponse(aiohttp.ClientResponse):
        async def json(self, **_kwargs):
            nonlocal result
            if self.content_type != "application/json":
                raise ValueError("JSON response required")
            chunks, size = [], 0
            limit = common.MAX_RESPONSE_BYTES if 200 <= self.status < 300 else common.MAX_BODY_BYTES
            async for chunk in self.content.iter_chunked(8192):
                size += len(chunk)
                if size > limit:
                    raise ValueError("Response exceeded bound")
                chunks.append(chunk)
            result = response_result("slack", self.status, b"".join(chunks))
            return result["response"]

        async def read(self):
            raise ValueError("Only bounded JSON responses are supported")

    # aiohttp's documented HTTPS-proxy support uses the SAME verified context
    # for both TLS layers, unlike HTTPX's separate proxy/destination roots.
    tls = context()
    tls.load_verify_locations(cadata=common.public_ca(config["ca_file"]).decode("ascii"))
    if config.get("proxy_ca_file"):
        tls.load_verify_locations(cadata=common.public_ca(config["proxy_ca_file"]).decode("ascii"))
    factory = session_factory or aiohttp.ClientSession
    async with factory(trust_env=False, trace_configs=[trace], response_class=BoundedJSONResponse,
            cookie_jar=aiohttp.DummyCookieJar(), auto_decompress=False,
            timeout=aiohttp.ClientTimeout(total=30, connect=5), headers={"Accept-Encoding": "identity"}) as session:
        sdk = AsyncWebClient(token="catchplate-slack-placeholder-v1", session=session,
            ssl=tls, proxy=config["_proxy_url"], timeout=30, retry_handlers=[], trust_env_in_session=False,
            logger=SDK_LOGGER)
        try:
            await sdk.chat_postMessage(**arguments)
        except Exception:
            if result is None:
                raise
            if result["ok"]:
                result.update(ok=False, error="SDK could not interpret the response")
    if result is None:
        raise ValueError("SDK produced no JSON response")
    return result


def execute(config, body=None, query=(), execute_write=False, *, transport=None, session_factory=None):
    """Validated one-call execution; injected transports are offline-test seams."""
    result = None
    try:
        provider, operation, params, url, arguments = validate(config, body, query, execute_write)
        if provider == "slack":
            return asyncio.run(slack_call(config, arguments, session_factory=session_factory))
        client, guard = http_client(config, url, transport=transport)
        with client:
            try:
                invoke_sdk(config, operation, params, client)
            except Exception:
                if guard.result is None:
                    raise
                if guard.result["ok"]:
                    guard.result.update(ok=False, error="SDK could not interpret the response")
        result = guard.result
        if result is None:
            raise ValueError("SDK produced no response")
    except Exception:
        pass
    if result is None:
        # No transport exception, private URL or credential survives chaining.
        raise ValueError(FAILURE)
    return result


def launch(config, body, query, execute_write):
    validate(config, body, query, execute_write)
    common.check_versions()
    if any(version(package) != pin for package, pin in PINS.items()):
        raise ValueError("Install requirements-services.txt in a Python 3.12 virtual environment")
    payload = json.dumps({"configuration": config, "body": body.decode("utf-8") if body else None,
        "query": query, "execute_write": execute_write}).encode()
    if len(payload) > 196608:
        raise ValueError("Input exceeded bound")
    completed = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--child"],
        input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={}, timeout=45, check=False)
    if completed.returncode or len(completed.stdout) > 2 * common.MAX_RESPONSE_BYTES:
        raise ValueError(FAILURE)
    return common.strict_json(completed.stdout)


def main():
    logging.disable(logging.CRITICAL)
    child = sys.argv[1:] == ["--child"]
    if child:
        if set(os.environ) - {"LC_CTYPE"}:
            raise ValueError("Clean environment required")
        payload = common.strict_json(sys.stdin.buffer.read(196609))
        body = payload["body"]
        result = execute(payload["configuration"], body.encode("utf-8") if body is not None else None,
            payload["query"], payload["execute_write"])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--config", required=True)
        parser.add_argument("--query", action="append", default=[], metavar="KEY=VALUE")
        parser.add_argument("--body", help="Reviewed Slack JSON message file")
        parser.add_argument("--execute-write", action="store_true")
        args = parser.parse_args()
        config = load_configuration(args.config)
        if args.body and not args.execute_write:
            parser.error("A body requires explicit --execute-write; nothing was sent")
        body = common.read_file(args.body, common.MAX_BODY_BYTES) if args.body else None
        result = launch(config, body, args.query, args.execute_write)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if child or result["ok"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print(FAILURE, file=sys.stderr)
        raise SystemExit(1)
