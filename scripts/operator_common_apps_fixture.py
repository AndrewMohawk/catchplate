"""Fixed synthetic providers in the existing network-none test namespace.

No real DNS, provider traffic, credentials, or general-purpose echo endpoint.
The existing GitHub namespace helper owns the single public-looking loopback
address; the ordinary guided fixture still supplies the proxy and empty store.
The optional SDK profile has eight exact operations and valid SDK envelopes.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import signal
import ssl
import time
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from scripts import operator_github_fixture_network as isolated
from scripts import operator_guided_fixture_network as guided

PROVIDERS = ("api.openai.com", "api.anthropic.com", "discord.com")
BASE_HOSTS = guided.HOSTS
HOSTS = (BASE_HOSTS + (isolated.FIXTURE_IP + " api.github.com " + " ".join(PROVIDERS) + "\n").encode())
TOKEN = "synthetic-common-apps-credential-not-a-real-provider-token"
MODEL, CHANNEL = "fixture-model", "123456789012345678"
SPECS = {
    "openai": {"host": PROVIDERS[0], "path": "/v1/responses", "operation": "responses_text_v1",
        "header": "Authorization", "placeholder": "Bearer catchplate-openai-placeholder-v1",
        "injected": "Bearer " + TOKEN, "body": {"model": MODEL, "input": "Hi",
            "max_output_tokens": 16, "stream": False, "store": False}},
    "anthropic": {"host": PROVIDERS[1], "path": "/v1/messages", "operation": "messages_text_v1",
        "header": "x-api-key", "placeholder": "catchplate-anthropic-placeholder-v1", "injected": TOKEN,
        "body": {"model": MODEL, "messages": [{"role": "user", "content": "Hi"}],
            "max_tokens": 16, "stream": False}},
    "discord": {"host": PROVIDERS[2], "path": "/api/v10/channels/" + CHANNEL + "/messages",
        "operation": "create_message", "header": "Authorization",
        "placeholder": "Bot catchplate-discord-placeholder-v1", "injected": "Bot " + TOKEN,
        "body": {"content": "Deployment completed.", "allowed_mentions": {"parse": []}}},
}
PAGE = "01234567-89ab-cdef-0123-456789abcdef"
ZONE = "0123456789abcdef0123456789abcdef"
SDK_SPECS = {
    "openai": {**SPECS["openai"], "scope": {"model": MODEL, "max_output_tokens": 16}},
    "anthropic": {**SPECS["anthropic"], "scope": {"model": MODEL, "max_output_tokens": 16},
        "request_headers": {"anthropic-version": "2023-06-01"}},
    "gemini": {"host": "generativelanguage.googleapis.com", "path": "/v1beta/models/" + MODEL + ":generateContent",
        "operation": "generate_text_v1", "header": "x-goog-api-key", "placeholder": "catchplate-gemini-placeholder-v1",
        "injected": TOKEN, "scope": {"model": MODEL, "max_output_tokens": 16},
        "body": {"contents": [{"role": "user", "parts": [{"text": "Hi"}]}], "generationConfig": {"maxOutputTokens": 16}}},
    "openrouter": {"host": "openrouter.ai", "path": "/api/v1/chat/completions", "operation": "chat_text_v1",
        "header": "Authorization", "placeholder": "Bearer catchplate-openrouter-placeholder-v1", "injected": "Bearer " + TOKEN,
        "scope": {"model": "vendor/" + MODEL, "max_output_tokens": 16},
        "body": {"model": "vendor/" + MODEL, "messages": [{"role": "user", "content": "Hi"}], "max_tokens": 16, "stream": False}},
    "slack": {"host": "slack.com", "path": "/api/chat.postMessage", "operation": "post_message",
        "header": "Authorization", "placeholder": "Bearer catchplate-slack-placeholder-v1", "injected": "Bearer " + TOKEN,
        "scope": {"channel": "C0123456789"}, "body": {"channel": "C0123456789", "text": "Deployment completed.",
            "unfurl_links": False, "unfurl_media": False}},
    "notion": {"host": "api.notion.com", "path": "/v1/blocks/" + PAGE + "/children", "operation": "block_children", "method": "GET",
        "header": "Authorization", "placeholder": "Bearer catchplate-notion-placeholder-v1", "injected": "Bearer " + TOKEN,
        "scope": {"block_id": PAGE}, "body": None, "request_headers": {"Notion-Version": "2026-03-11"},
        "query": {"page_size": "1", "start_cursor": "11111111-2222-4333-8444-555555555555"}},
    "stripe": {"host": "api.stripe.com", "path": "/v1/customers", "operation": "customers", "method": "GET",
        "header": "Authorization", "placeholder": "Bearer catchplate-stripe-placeholder-v1", "injected": "Bearer " + TOKEN,
        "scope": {}, "body": None, "query": {"limit": "1", "starting_after": "cus_fixture_start"}},
    "cloudflare": {"host": "api.cloudflare.com", "path": "/client/v4/zones/" + ZONE + "/dns_records",
        "operation": "dns_records_sdk_v1", "method": "GET", "header": "Authorization",
        "placeholder": "Bearer catchplate-cloudflare-placeholder-v1", "injected": "Bearer " + TOKEN,
        "scope": {"zone_id": ZONE}, "body": None, "query": {"page": "1", "per_page": "1"},
        "sdk_headers": {"api-version": "2026-10-15"}},
}
SDK_PROVIDERS = tuple(sorted({spec["host"] for spec in SDK_SPECS.values()}))


def sdk_response(name):
    if name == "openai":
        return {"id": "resp_fixture", "object": "response", "created_at": 0, "model": MODEL, "status": "completed",
            "output": [{"id": "msg_fixture", "type": "message", "role": "assistant", "status": "completed",
                "content": [{"type": "output_text", "text": "Hello", "annotations": []}]}]}
    if name == "anthropic":
        return {"id": "msg_fixture", "type": "message", "role": "assistant", "model": MODEL,
            "content": [{"type": "text", "text": "Hello"}], "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1}}
    if name == "gemini":
        return {"candidates": [{"content": {"role": "model", "parts": [{"text": "Hello"}]}, "finishReason": "STOP"}]}
    if name == "openrouter":
        return {"id": "chatcmpl_fixture", "object": "chat.completion", "created": 0, "model": "vendor/" + MODEL,
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "Hello"}}]}
    if name == "slack":
        return {"ok": True, "channel": "C0123456789", "ts": "1700000000.000001", "message": {"text": "Deployment completed."}}
    if name == "notion":
        return {"object": "list", "results": [{"object": "block", "id": PAGE, "type": "paragraph",
            "paragraph": {"rich_text": []}, "has_children": False}], "has_more": True,
            "next_cursor": "66666666-7777-4888-8999-aaaaaaaaaaaa", "type": "block", "block": {}}
    if name == "stripe":
        return {"object": "list", "url": "/v1/customers", "data": [{"id": "cus_fixture_next", "object": "customer",
            "email": "fixture@example.test"}], "has_more": True}
    assert name == "cloudflare"
    return {"success": True, "errors": [], "messages": [], "result": [{"id": "a" * 32, "type": "A",
        "name": "fixture.example", "content": "192.0.2.1", "proxied": False, "ttl": 300}],
        "result_info": {"page": 1, "per_page": 1, "count": 1, "total_count": 2, "total_pages": 2}}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def configure_network(sdk_smoke=False):
    hosts = (BASE_HOSTS + (isolated.FIXTURE_IP + " api.github.com " + " ".join(SDK_PROVIDERS) + "\n").encode()) if sdk_smoke else HOSTS
    isolated.HOSTS, isolated.PROXY_HOST = hosts, guided.PROXY_HOST
    guided.HOSTS = hosts


def assert_isolated(sdk_smoke=False):
    configure_network(sdk_smoke)
    isolated.assert_isolated_network()
    import socket
    for host in SDK_PROVIDERS if sdk_smoke else PROVIDERS:
        assert {row[4][0] for row in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)} == {isolated.FIXTURE_IP}


def setup(sdk_smoke=False):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    assert os.geteuid() == 10001
    isolated.assert_isolated_network(attached=False)
    configure_network(sdk_smoke)
    guided.prepare_files()
    root = Path("/upstream-data/demo-upstream")
    assert root.is_dir() and not list(root.iterdir())
    now = datetime.now(timezone.utc)
    key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic common apps fixture CA")])
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), True).sign(key, hashes.SHA256()))
    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, PROVIDERS[0])])
    leaf = (x509.CertificateBuilder().subject_name(leaf_subject).issuer_name(subject).public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host) for host in (SDK_PROVIDERS if sdk_smoke else PROVIDERS)]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False).sign(key, hashes.SHA256()))
    for name, raw in {"ca.pem": ca.public_bytes(serialization.Encoding.PEM),
        "cert.pem": leaf.public_bytes(serialization.Encoding.PEM),
        "key.pem": leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())}.items():
        guided.write_once(root / name, raw)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(4)

    def send(self, status, value):
        body = encoded(value)
        self.send_response_only(status)
        for key, value in (("Content-Type", "application/json"), ("Content-Length", str(len(body))), ("Connection", "close")):
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self):
        if self.path == "/_fixture/observations":
            return self.send(200, {"total": self.server.total, "attempts": self.server.attempts})
        self.do_POST()

    def do_POST(self):
        if self.server.sdk_smoke:
            return self.sdk_request()
        self.server.total += 1
        name = next((name for name, spec in SPECS.items()
            if self.headers.get("Host") == spec["host"] and self.path == spec["path"]), None)
        row = {"case": name, "accepted": False}
        if self.server.total <= 12:
            self.server.attempts.append(row)
        try:
            assert self.command == "POST" and name is not None and self.server.total <= 12
            spec = SPECS[name]
            fields = [(key.lower(), value) for key, value in self.headers.raw_items()]
            assert len(fields) <= 12 and len(dict(fields)) == len(fields)
            headers = dict(fields)
            expected = {"host", "content-type", "content-length", "accept", "user-agent", spec["header"].lower()}
            if name == "anthropic":
                expected.add("anthropic-version")
                assert headers.get("anthropic-version") == "2023-06-01"
            assert expected <= set(headers) <= expected | {"connection", "accept-encoding"}
            assert headers[spec["header"].lower()] == spec["injected"]
            assert headers["accept"] == "application/json" and headers["content-type"] == "application/json"
            assert headers.get("accept-encoding", "identity") == "identity"
            assert headers.get("connection", "close") in {"close", "keep-alive"}
            assert headers["user-agent"] == self.server.user_agent
            expected_body = encoded(spec["body"])
            assert headers["content-length"] == str(len(expected_body))
            raw = self.rfile.read(len(expected_body))
            assert raw == expected_body
            row.update(accepted=True, authStyle={"openai": "Bearer", "anthropic": "x-api-key", "discord": "Bot"}[name],
                bodySha256="sha256:" + hashlib.sha256(raw).hexdigest())
            self.send(200, {"synthetic": True, "provider": name, "result": "fixed fixture response"})
        except (AssertionError, ValueError, OSError):
            self.send(400, {"error": "synthetic_provider_rejected"})

    def sdk_request(self):
        """Validate what the actual SDK sent, without rewriting its transport."""
        from catchplate.operator_common_apps_ai import PRESETS as AI_PRESETS
        from catchplate.operator_common_apps_services import PRESETS as SERVICE_PRESETS

        self.server.total += 1
        target = urlsplit(self.path)
        name = next((name for name, spec in SDK_SPECS.items()
            if self.headers.get("Host") == spec["host"] and target.path == spec["path"]), None)
        row = {"case": name, "accepted": False}
        if self.server.total <= 16:
            self.server.attempts.append(row)
        try:
            assert name is not None and self.server.total <= 8
            spec = SDK_SPECS[name]
            preset = next(p for p in [*AI_PRESETS, *SERVICE_PRESETS] if p["id"] == name)
            operation = next(p for p in preset["operations"] if p["id"] == spec["operation"])
            assert self.command == spec.get("method", "POST")
            query = parse_qsl(target.query, keep_blank_values=True, strict_parsing=True)
            assert len(query) == len(dict(query)) and dict(query) == spec.get("query", {})
            assert target.query == urlencode(sorted(spec.get("query", {}).items()), quote_via=quote, safe="")
            fields = [(key.lower(), value) for key, value in self.headers.raw_items()]
            assert len(fields) <= 32 and len(dict(fields)) == len(fields)
            headers = dict(fields)
            allowed = set(operation["allowed_headers"]) | {"host", "content-type", "content-length",
                "connection", "accept-encoding", spec["header"].lower()}
            assert set(headers) <= allowed and headers[spec["header"].lower()] == spec["injected"]
            assert headers.get("accept-encoding", "identity") == "identity"
            assert headers.get("connection", "close") in {"close", "keep-alive"}
            for key, value in {**spec.get("request_headers", {}), **spec.get("sdk_headers", {})}.items():
                assert headers.get(key.lower()) == value
            assert headers.get("x-stainless-retry-count", "0") == "0"
            length = headers.get("content-length", "0")
            assert length.isdecimal() and 0 <= int(length) <= 65536
            raw = self.rfile.read(int(length)) if int(length) else b""
            if spec["body"] is None:
                assert not raw
            else:
                assert headers.get("content-type", "").split(";")[0].strip().lower() == "application/json"
                def pairs(values):
                    assert len(values) == len(dict(values))
                    return dict(values)
                value = json.loads(raw, object_pairs_hook=pairs,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
                assert encoded(value) == encoded(spec["body"])
            assert "catchplate-" + name + "-placeholder-v1" not in str(fields)
            row.update(accepted=True, authStyle=spec["header"], bodySha256="sha256:" + hashlib.sha256(raw).hexdigest(),
                method=self.command, path=target.path, query=dict(query), rawQuery=target.query, headerNames=sorted(headers),
                userAgent=headers.get("user-agent"), retryCount=headers.get("x-stainless-retry-count"))
            self.send(200, sdk_response(name))
        except (AssertionError, ValueError, OSError, StopIteration):
            self.send(400, {"error": "synthetic_provider_rejected"})


def serve(*, mcp_smoke=False, sdk_smoke=False):
    assert_isolated(sdk_smoke)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/data/demo-upstream/cert.pem", "/data/demo-upstream/key.pem")
    signal.alarm(300)
    with HTTPServer((isolated.FIXTURE_IP, 443), Handler) as server:
        server.total, server.attempts, server.timeout = 0, [], 0.5
        server.sdk_smoke = sdk_smoke
        server.user_agent = "catchplate-common-apps-example/1.0" if mcp_smoke else "catchplate-common-apps-fixture/1"
        server.socket = context.wrap_socket(server.socket, server_side=True)
        until = time.monotonic() + 290
        while time.monotonic() < until:
            server.handle_request()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("setup", "network", "edge", "provider"))
    parser.add_argument("--mcp-smoke", action="store_true")
    parser.add_argument("--sdk-smoke", action="store_true")
    args = parser.parse_args()
    selected = args.operation
    if args.mcp_smoke and (selected != "provider" or args.sdk_smoke):
        parser.error("--mcp-smoke requires the provider operation")
    os.umask(0o077)
    configure_network(args.sdk_smoke)
    if selected == "setup":
        signal.alarm(20)
        setup(args.sdk_smoke)
    elif selected == "network":
        isolated.keep_namespace()
    elif selected == "edge":
        guided.edge()
    else:
        serve(mcp_smoke=args.mcp_smoke, sdk_smoke=args.sdk_smoke)
