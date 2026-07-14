#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, replace
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.oauth_provider_simulator import OAuthProviderSimulator  # noqa: E402


MAX_ASGI_REQUEST_BYTES = 128 * 1024
MAX_ASGI_RESPONSE_BYTES = 1024 * 1024
MAX_PROVIDER_RESPONSE_BYTES = 64 * 1024
DATA_PLANE_TOKEN = "oauth-http-flow-credential-lease-token"
DATA_PLANE_DIGEST = "sha256:" + "d" * 64
POLICY_HASH = "sha256:" + "a" * 64
GOOGLE_SCOPES = ["openid", "email", "https://www.googleapis.com/auth/gmail.readonly"]
X_SCOPES = ["tweet.read", "users.read", "offline.access"]


@dataclass(frozen=True)
class ASGIResponse:
    status_code: int
    raw_headers: tuple[tuple[str, str], ...]
    content: bytes

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.content)

    def header(self, name: str) -> str | None:
        normalized = name.lower()
        for key, value in reversed(self.raw_headers):
            if key.lower() == normalized:
                return value
        return None

    def headers_all(self, name: str) -> list[str]:
        normalized = name.lower()
        return [value for key, value in self.raw_headers if key.lower() == normalized]


class ASGIHTTPClient:
    """Small bounded ASGI transport that preserves secure response cookies."""

    def __init__(self, app: Any, *, base_url: str) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("ASGI test base URL must be HTTPS")
        self.app = app
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or 443
        self.cookies: dict[str, str] = {}
        self._runner = asyncio.Runner()
        self._started = False
        self._lifespan: Any | None = None

    def start(self) -> None:
        if not self._started:
            self._lifespan = self.app.router.lifespan_context(self.app)
            self._runner.run(self._lifespan.__aenter__())
            self._started = True

    def close(self) -> None:
        if self._started:
            assert self._lifespan is not None
            self._runner.run(self._lifespan.__aexit__(None, None, None))
            self._started = False
            self._lifespan = None
        self._runner.close()

    def __enter__(self) -> ASGIHTTPClient:
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def set_cookie(self, name: str, value: str) -> None:
        if not name or any(character in name for character in "\r\n;="):
            raise ValueError("invalid test cookie name")
        self.cookies[name] = value

    def request(
        self,
        method: str,
        target: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: Any | None = None,
        body: bytes | None = None,
    ) -> ASGIResponse:
        if json_body is not None and body is not None:
            raise ValueError("request cannot contain both JSON and raw body")
        request_headers = dict(headers or {})
        if json_body is not None:
            body = json.dumps(json_body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        body = body or b""
        if len(body) > MAX_ASGI_REQUEST_BYTES:
            raise AssertionError("test attempted to send an oversized ASGI request")
        if body:
            request_headers["Content-Length"] = str(len(body))
        if self.cookies:
            request_headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in sorted(self.cookies.items()))
        response = self._runner.run(self._request(method.upper(), target, request_headers, body))
        if len(response.content) > MAX_ASGI_RESPONSE_BYTES:
            raise AssertionError("ASGI endpoint returned an oversized response")
        self._update_cookies(response.headers_all("set-cookie"))
        return response

    async def _request(
        self,
        method: str,
        target: str,
        headers: dict[str, str],
        body: bytes,
    ) -> ASGIResponse:
        parsed = urllib.parse.urlsplit(target)
        if parsed.scheme:
            if parsed.scheme != self.scheme or parsed.hostname != self.host or (parsed.port or 443) != self.port:
                raise ValueError("ASGI request target escaped the configured origin")
            path = parsed.path or "/"
            query = parsed.query
        else:
            relative = urllib.parse.urlsplit(target)
            path = relative.path or "/"
            query = relative.query
        raw_headers: list[tuple[bytes, bytes]] = [(b"host", f"{self.host}:{self.port}".encode("ascii"))]
        for name, value in headers.items():
            if any(character in name + value for character in "\r\n"):
                raise ValueError("ASGI request header contains a control character")
            raw_headers.append((name.lower().encode("ascii"), value.encode("latin-1")))
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method,
            "scheme": self.scheme,
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": query.encode("ascii"),
            "root_path": "",
            "headers": raw_headers,
            "client": ("127.0.0.1", 12345),
            "server": (self.host, self.port),
            "state": {},
        }
        received = False
        response_status: int | None = None
        response_headers: tuple[tuple[str, str], ...] = ()
        chunks = bytearray()

        async def receive() -> dict[str, Any]:
            nonlocal received
            if not received:
                received = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            nonlocal response_status, response_headers
            if message["type"] == "http.response.start":
                if response_status is not None:
                    raise AssertionError("ASGI application emitted duplicate response start")
                response_status = int(message["status"])
                response_headers = tuple(
                    (name.decode("latin-1"), value.decode("latin-1"))
                    for name, value in message.get("headers", [])
                )
                return
            if message["type"] != "http.response.body" or response_status is None:
                raise AssertionError(f"unexpected ASGI response frame: {message['type']}")
            chunks.extend(message.get("body", b""))
            if len(chunks) > MAX_ASGI_RESPONSE_BYTES:
                raise AssertionError("ASGI response exceeded the test transport bound")

        await self.app(scope, receive, send)
        if response_status is None:
            raise AssertionError("ASGI application did not start a response")
        return ASGIResponse(response_status, response_headers, bytes(chunks))

    def _update_cookies(self, set_cookie_headers: list[str]) -> None:
        for header in set_cookie_headers:
            parsed = SimpleCookie()
            parsed.load(header)
            for name, morsel in parsed.items():
                if morsel["max-age"] == "0" or not morsel.value:
                    self.cookies.pop(name, None)
                else:
                    self.cookies[name] = morsel.value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def configure_environment(data_dir: Path, simulator: OAuthProviderSimulator) -> None:
    values = {
        "SERVERWARE_DATA_DIR": str(data_dir),
        "SERVERWARE_RELEASE_CHANNEL": "dev",
        "SERVERWARE_PUBLIC_URL": "https://serverware.test",
        "SERVERWARE_KEY_RELEASE_REQUIRED": "0",
        "SERVERWARE_METADATA_STORE_BACKEND": "sqlite",
        "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite",
        "SERVERWARE_GRANT_STORE_BACKEND": "sqlite",
        "SERVERWARE_CONTROL_PLANE_TWO_PERSON_REQUIRED": "1",
        "SERVERWARE_CONTROL_PLANE_TWO_PERSON_ACTIONS": "credential.oauth.activate,credential.delete",
        "SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED": "0",
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_ID": simulator.GOOGLE_CLIENT_ID,
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET": simulator.GOOGLE_CLIENT_SECRET,
        "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI": "https://serverware.test/api/oauth/callback/google",
        "SERVERWARE_X_OAUTH_CLIENT_ID": simulator.X_CLIENT_ID,
        "SERVERWARE_X_OAUTH_CLIENT_SECRET": simulator.X_CLIENT_SECRET,
        "SERVERWARE_X_OAUTH_REDIRECT_URI": "https://serverware.test/api/oauth/callback/x",
        "SERVERWARE_DATA_PLANE_INSTANCE_ID": "spiffe://test.serverware/decision-gate/oauth-http-flow",
        "SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN": DATA_PLANE_TOKEN,
        "SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST": DATA_PLANE_DIGEST,
        "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED": "0",
        "SERVERWARE_AUDIT_ANCHOR_URL": "",
        "SERVERWARE_DECISION_GATE_BASE": "",
        "SSL_CERT_FILE": str(simulator.ca_cert_path),
    }
    for name in (
        "SERVERWARE_METADATA_STORE_POSTGRES_DSN",
        "SERVERWARE_AUDIT_STORE_POSTGRES_DSN",
        "SERVERWARE_GRANT_STORE_POSTGRES_DSN",
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE",
        "SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE",
    ):
        os.environ.pop(name, None)
    os.environ.update(values)


def https_request(
    request: urllib.request.Request,
    *,
    context: Any,
) -> tuple[int, dict[str, str], bytes]:
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=context))
    try:
        response = opener.open(request, timeout=5)
    except urllib.error.HTTPError as exc:
        status = exc.code
        headers = {name.lower(): value for name, value in exc.headers.items()}
        body = exc.read(MAX_PROVIDER_RESPONSE_BYTES + 1)
    else:
        with response:
            status = int(response.status)
            headers = {name.lower(): value for name, value in response.headers.items()}
            body = response.read(MAX_PROVIDER_RESPONSE_BYTES + 1)
    if len(body) > MAX_PROVIDER_RESPONSE_BYTES:
        raise AssertionError("OAuth simulator response exceeded its public bound")
    return status, headers, body


def provider_redirect(simulator: OAuthProviderSimulator, authorization_url: str) -> str:
    request = urllib.request.Request(authorization_url, headers={"Accept": "text/html"}, method="GET")
    status, headers, body = https_request(request, context=simulator.client_ssl_context)
    simulator.assert_no_token_values(body)
    location = headers.get("location")
    if status != 302 or not location:
        raise AssertionError(f"provider authorization did not redirect: HTTP {status}")
    simulator.assert_no_token_values(location)
    parsed = urllib.parse.urlsplit(location)
    if parsed.scheme != "https" or parsed.netloc != "serverware.test" or len(location) > 8192:
        raise AssertionError(f"provider redirected outside the expected callback origin: {location}")
    return location


def provider_form_request(
    simulator: OAuthProviderSimulator,
    url: str,
    form: dict[str, str],
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    encoded = urllib.parse.urlencode(form).encode("ascii")
    if len(encoded) > 16 * 1024:
        raise AssertionError("provider form request exceeded the test bound")
    request_headers = {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})}
    request = urllib.request.Request(url, data=encoded, headers=request_headers, method="POST")
    status, _, body = https_request(request, context=simulator.client_ssl_context)
    return status, body


def expect_status(response: ASGIResponse, expected: int, label: str) -> None:
    if response.status_code != expected:
        raise AssertionError(f"{label}: expected HTTP {expected}, got {response.status_code}: {response.text[:500]}")


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def main() -> None:
    with tempfile.TemporaryDirectory() as raw_tmp:
        tmp = Path(raw_tmp)
        with OAuthProviderSimulator(tmp / "provider") as simulator:
            configure_environment(tmp / "serverware", simulator)

            from fastapi import HTTPException, Request

            from serverware import app as app_module
            from serverware import db, oauth
            from serverware.auth import AdminIdentity, require_admin
            from serverware.policy_bundle import CredentialPolicy, PolicySnapshot, RoutePolicy

            original_providers = oauth._providers
            configured = original_providers()
            google_urls = simulator.provider_urls("google")
            x_urls = simulator.provider_urls("x")
            google_provider = replace(configured["google"], **google_urls)
            x_provider = replace(configured["x"], **x_urls)
            oauth._providers = lambda: {"google": google_provider, "x": x_provider, "twitter": x_provider}

            original_request_bytes = oauth.request_bytes

            def trusted_provider_request(request: Any, **kwargs: Any) -> Any:
                kwargs["context"] = simulator.client_ssl_context
                return original_request_bytes(request, **kwargs)

            oauth.request_bytes = trusted_provider_request

            identities = {
                "operator": AdminIdentity(
                    "user:operator",
                    frozenset({"credential_owner", "policy_author", "auditor"}),
                    "test-actor-header",
                ),
                "reviewer": AdminIdentity(
                    "user:reviewer",
                    frozenset({"credential_owner", "auditor"}),
                    "test-actor-header",
                ),
                "outsider": AdminIdentity(
                    "user:outsider",
                    frozenset({"credential_owner"}),
                    "test-actor-header",
                ),
            }

            def test_require_admin(request: Request) -> AdminIdentity:
                actor = request.headers.get("X-Test-Actor", "")
                identity = identities.get(actor)
                if identity is None:
                    raise HTTPException(status_code=401, detail="recognized test actor required")
                return identity

            test_require_admin.__annotations__["request"] = Request
            app_module.app.dependency_overrides[require_admin] = test_require_admin
            snapshot_box: dict[str, PolicySnapshot | None] = {"value": None}
            app_module.get_policy_snapshot = lambda: snapshot_box["value"]
            app_module._start_oauth_revocation_reconciler = lambda: None
            db.init_db()

            asgi_responses: list[ASGIResponse] = []

            def request(
                client: ASGIHTTPClient,
                method: str,
                target: str,
                *,
                actor: str | None = None,
                json_body: Any | None = None,
                extra_headers: dict[str, str] | None = None,
            ) -> ASGIResponse:
                headers = dict(extra_headers or {})
                if actor:
                    headers["X-Test-Actor"] = actor
                response = client.request(method, target, headers=headers, json_body=json_body)
                simulator.assert_no_token_values(response.content)
                for value in response.headers_all("location") + response.headers_all("set-cookie"):
                    simulator.assert_no_token_values(value)
                asgi_responses.append(response)
                return response

            def start_authorization(
                client: ASGIHTTPClient,
                *,
                provider: str,
                name: str,
                scopes: list[str] | None = None,
                credential_id: str | None = None,
            ) -> tuple[dict[str, Any], str, str, str]:
                payload: dict[str, Any] = {"provider": provider, "credentialName": name}
                if scopes is not None:
                    payload["scopes"] = scopes
                if credential_id is not None:
                    payload["credentialId"] = credential_id
                response = request(client, "POST", "/api/oauth/start", actor="operator", json_body=payload)
                expect_status(response, 200, f"{provider} authorization start")
                started = response.json()
                state = started.get("state")
                if not isinstance(state, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}", state) is None:
                    raise AssertionError(f"{provider} authorization start returned malformed state")
                cookie_name = oauth.browser_cookie_name(state)
                set_cookie_headers = response.headers_all("set-cookie")
                if len(set_cookie_headers) != 1:
                    raise AssertionError(f"{provider} authorization start returned unexpected cookies")
                parsed_cookie = SimpleCookie()
                parsed_cookie.load(set_cookie_headers[0])
                morsel = parsed_cookie.get(cookie_name)
                if morsel is None:
                    raise AssertionError(f"{provider} authorization did not bind its state cookie")
                if (
                    not morsel["secure"]
                    or not morsel["httponly"]
                    or morsel["samesite"].lower() != "lax"
                    or morsel["path"] != "/"
                    or morsel["domain"]
                    or not morsel["max-age"].isdigit()
                    or not 1 <= int(morsel["max-age"]) <= 600
                ):
                    raise AssertionError(f"{provider} OAuth cookie attributes are unsafe: {morsel.OutputString()}")
                state_payload = json.loads(oauth.OAUTH_STATE_PATH.read_text(encoding="utf-8"))
                record = state_payload.get("states", {}).get(state)
                if not isinstance(record, dict) or not isinstance(record.get("code_verifier"), str):
                    raise AssertionError(f"{provider} OAuth state did not retain a PKCE verifier")
                return started, cookie_name, morsel.value, record["code_verifier"]

            def callback_from_location(client: ASGIHTTPClient, location: str) -> ASGIResponse:
                parsed = urllib.parse.urlsplit(location)
                target = parsed.path + ("?" + parsed.query if parsed.query else "")
                response = request(client, "GET", target)
                if response.header("cache-control") != "no-store":
                    raise AssertionError("OAuth callback response was cacheable")
                return response

            def pending_named(client: ASGIHTTPClient, name: str) -> dict[str, Any]:
                response = request(client, "GET", "/api/oauth/pending", actor="operator")
                expect_status(response, 200, "pending OAuth listing")
                matches = [item for item in response.json()["pendingCredentials"] if item.get("name") == name]
                if len(matches) != 1:
                    raise AssertionError(f"expected one pending OAuth credential named {name!r}: {matches}")
                return matches[0]

            def approve_and_activate(
                client: ASGIHTTPClient,
                pending: dict[str, Any],
                *,
                exercise_denials: bool,
            ) -> dict[str, Any]:
                pending_id = str(pending["id"])
                activate_path = f"/api/oauth/pending/{pending_id}/activate"
                if exercise_denials:
                    wrong_requester = request(client, "POST", activate_path, actor="reviewer", json_body={})
                    expect_status(wrong_requester, 403, "wrong requester pending activation")
                approval_required = request(client, "POST", activate_path, actor="operator", json_body={})
                expect_status(approval_required, 428, "pending activation approval request")
                detail = approval_required.json().get("detail")
                approval_id = detail.get("approvalId") if isinstance(detail, dict) else None
                if not isinstance(approval_id, str):
                    raise AssertionError("pending activation did not identify its approval")
                if exercise_denials:
                    self_approval = request(
                        client,
                        "POST",
                        f"/api/control-plane/approvals/{approval_id}/approve",
                        actor="operator",
                        json_body={"note": "must fail"},
                    )
                    expect_status(self_approval, 403, "self approval")
                approved = request(
                    client,
                    "POST",
                    f"/api/control-plane/approvals/{approval_id}/approve",
                    actor="reviewer",
                    json_body={"note": "exact account reviewed"},
                )
                expect_status(approved, 200, "distinct reviewer approval")
                if approved.json().get("approved_by") != "user:reviewer":
                    raise AssertionError("approval was not attributed to the distinct reviewer")
                activated = request(
                    client,
                    "POST",
                    activate_path,
                    actor="operator",
                    json_body={"mfa": {"approvalId": approval_id}},
                )
                expect_status(activated, 200, "approved pending activation")
                if activated.json().get("approval", {}).get("status") != "consumed":
                    raise AssertionError("OAuth activation did not consume its approval")
                replay = request(
                    client,
                    "POST",
                    activate_path,
                    actor="operator",
                    json_body={"mfa": {"approvalId": approval_id}},
                )
                expect_status(replay, 404, "one-use pending activation replay")
                return activated.json()["credential"]

            def disconnect_credential(
                client: ASGIHTTPClient,
                credential_id: str,
                *,
                label: str,
            ) -> None:
                approval_required = request(
                    client,
                    "DELETE",
                    f"/api/credentials/{credential_id}",
                    actor="operator",
                    json_body={},
                )
                expect_status(approval_required, 428, f"{label} disconnect approval request")
                detail = approval_required.json().get("detail")
                approval_id = detail.get("approvalId") if isinstance(detail, dict) else None
                if not isinstance(approval_id, str):
                    raise AssertionError(f"{label} disconnect did not identify its approval")
                approved = request(
                    client,
                    "POST",
                    f"/api/control-plane/approvals/{approval_id}/approve",
                    actor="reviewer",
                    json_body={"note": f"{label} disconnect reviewed"},
                )
                expect_status(approved, 200, f"{label} disconnect reviewer approval")
                disconnected = request(
                    client,
                    "DELETE",
                    f"/api/credentials/{credential_id}",
                    actor="operator",
                    json_body={"mfa": {"approvalId": approval_id}},
                )
                expect_status(disconnected, 200, f"{label} disconnect")
                if disconnected.json() != {"deleted": True, "providerRevoked": True}:
                    raise AssertionError(
                        f"{label} disconnect did not revoke the provider grant: {disconnected.json()}"
                    )
                if db.get_credential(credential_id) is not None:
                    raise AssertionError(f"disconnected {label} OAuth credential remained active")

            with ASGIHTTPClient(app_module.app, base_url="https://serverware.test") as client:
                unauthenticated = request(client, "GET", "/api/oauth/providers")
                expect_status(unauthenticated, 401, "missing test actor")
                unknown_actor = request(client, "GET", "/api/oauth/providers", actor="unknown")
                expect_status(unknown_actor, 401, "unknown test actor")

                providers_response = request(client, "GET", "/api/oauth/providers", actor="operator")
                expect_status(providers_response, 200, "OAuth provider listing")
                providers = {item["id"]: item for item in providers_response.json()["providers"]}
                if set(providers) != {"google", "x"} or not all(item["configured"] for item in providers.values()):
                    raise AssertionError(f"OAuth providers were not configured: {providers}")
                for provider_id in ("google", "x"):
                    expected_urls = simulator.provider_urls(provider_id)
                    listed = providers[provider_id]
                    if (
                        listed["authorizationUrl"] != expected_urls["authorization_url"]
                        or listed["tokenUrl"] != expected_urls["token_url"]
                        or listed["identityUrl"] != expected_urls["identity_url"]
                    ):
                        raise AssertionError(
                            f"{provider_id} provider definitions were not patched to HTTPS simulator URLs"
                        )

                google_name = "Google exact-account test"
                simulator.queue_authorization_outcome("google", "success")
                started, _, _, verifier = start_authorization(
                    client,
                    provider="google",
                    name=google_name,
                    scopes=GOOGLE_SCOPES,
                )
                location = provider_redirect(simulator, started["authorizationUrl"])
                callback_query = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
                code = callback_query.get("code", [None])[0]
                if not isinstance(code, str):
                    raise AssertionError("Google authorization redirect omitted its code")
                callback = callback_from_location(client, location)
                expect_status(callback, 200, "Google OAuth callback")
                if "OAuth account verified" not in callback.text or "operator@example.test" not in callback.text:
                    raise AssertionError("Google callback did not stage the exact verified account")

                replay_status, replay_body = provider_form_request(
                    simulator,
                    simulator.provider_urls("google")["token_url"],
                    {
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": "https://serverware.test/api/oauth/callback/google",
                        "client_id": simulator.GOOGLE_CLIENT_ID,
                        "client_secret": simulator.GOOGLE_CLIENT_SECRET,
                        "code_verifier": verifier,
                    },
                )
                if replay_status != 400 or json.loads(replay_body).get("error") != "invalid_grant":
                    raise AssertionError("OAuth simulator accepted a replayed authorization code")

                pending = pending_named(client, google_name)
                review = pending.get("review") or {}
                if (
                    review.get("provider") != "google"
                    or review.get("provider_subject") != "google-subject-001"
                    or review.get("provider_account") != "operator@example.test"
                    or review.get("scopes") != sorted(GOOGLE_SCOPES)
                ):
                    raise AssertionError(f"pending OAuth activation was not exact-account bound: {review}")
                google_credential = approve_and_activate(client, pending, exercise_denials=True)
                google_credential_id = str(google_credential["id"])

                google_reconnect = request(
                    client,
                    "POST",
                    "/api/oauth/start",
                    actor="operator",
                    json_body={
                        "provider": "google",
                        "credentialName": google_name,
                        "credentialId": google_credential_id,
                    },
                )
                expect_status(google_reconnect, 409, "Google in-place reconnect rejection")
                google_reconnect_detail = google_reconnect.json().get("detail", "")
                if (
                    "Disconnect this credential" not in google_reconnect_detail
                    or "connect" not in google_reconnect_detail
                ):
                    raise AssertionError(
                        f"Google reconnect did not require disconnect then connect: {google_reconnect_detail}"
                    )

                simulator.queue_authorization_outcome("google", "denial")
                denied_start, denied_cookie_name, denied_cookie_value, _ = start_authorization(
                    client,
                    provider="google",
                    name="Denied Google test",
                    scopes=GOOGLE_SCOPES,
                )
                denied_location = provider_redirect(simulator, denied_start["authorizationUrl"])
                denied = callback_from_location(client, denied_location)
                expect_status(denied, 400, "provider denial callback")
                if "OAuth denied" not in denied.text:
                    raise AssertionError("provider denial was not represented as a denial")
                state_after_denial = json.loads(oauth.OAUTH_STATE_PATH.read_text(encoding="utf-8"))
                if denied_start["state"] in state_after_denial.get("states", {}):
                    raise AssertionError("provider denial did not consume OAuth state")
                client.set_cookie(denied_cookie_name, denied_cookie_value)
                denied_replay = callback_from_location(client, denied_location)
                expect_status(denied_replay, 400, "provider denial state replay")
                if "unknown or expired" not in denied_replay.text:
                    raise AssertionError("provider denial replay did not fail as consumed state")
                disconnect_credential(client, google_credential_id, label="Google")

                x_name = "X reconnect and refresh test"
                simulator.queue_authorization_outcome("x", "success")
                x_start, _, _, _ = start_authorization(
                    client,
                    provider="x",
                    name=x_name,
                    scopes=X_SCOPES,
                )
                x_location = provider_redirect(simulator, x_start["authorizationUrl"])
                x_callback = callback_from_location(client, x_location)
                expect_status(x_callback, 200, "X OAuth callback")
                if "OAuth account verified" not in x_callback.text or "@operator_x" not in x_callback.text:
                    raise AssertionError("X callback did not stage the exact verified account")
                x_pending = pending_named(client, x_name)
                x_review = x_pending.get("review") or {}
                if (
                    x_review.get("provider") != "x"
                    or x_review.get("provider_subject") != "x-subject-001"
                    or x_review.get("provider_account") != "@operator_x"
                    or x_review.get("scopes") != sorted(X_SCOPES)
                ):
                    raise AssertionError(f"pending X activation was not exact-account bound: {x_review}")
                x_credential = approve_and_activate(client, x_pending, exercise_denials=False)
                x_credential_id = str(x_credential["id"])
                x_initial_version = int(x_credential["credential_version"])
                x_initial_stored = db.get_credential(x_credential_id, include_secret=True)
                if x_initial_stored is None:
                    raise AssertionError("initial X credential could not be reloaded")
                x_initial_secret = json.loads(x_initial_stored["secret"])

                route = RoutePolicy(
                    id="oauth.refresh.test",
                    principals=("agent:oauth-http-flow",),
                    host="provider.invalid",
                    port=443,
                    scheme="https",
                    methods=frozenset({"GET"}),
                    path_templates=("/",),
                    path_regexes=(re.compile(r"^/$"),),
                    credential_ref=x_credential_id,
                    adapter_type="generic.rest",
                    adapter_config={},
                )
                snapshot_box["value"] = PolicySnapshot(
                    raw={"metadata": {"id": "oauth-http-flow"}},
                    hash=POLICY_HASH,
                    principals={},
                    credentials={
                        x_credential_id: CredentialPolicy(
                            id=x_credential_id,
                            provider="x",
                            provider_subject="x-subject-001",
                            scopes=tuple(X_SCOPES),
                            injection={
                                "type": "bearer",
                                "header": "Authorization",
                                "field": "access_token",
                                "prefix": "Bearer ",
                            },
                        )
                    },
                    routes=(route,),
                )
                recipient_key = x25519.X25519PrivateKey.generate()
                recipient_public = recipient_key.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
                recipient_nonce = hashlib.sha256(b"oauth-http-flow-recipient-nonce").digest()
                lease = request(
                    client,
                    "POST",
                    "/api/data-plane/credential-leases",
                    json_body={
                        "apiVersion": "serverware.credentialLeaseRequest/v2",
                        "principalId": "agent:oauth-http-flow",
                        "routeId": route.id,
                        "credentialId": x_credential_id,
                        "recipientPublicKey": b64url(recipient_public),
                        "recipientKeyId": "sha256:" + hashlib.sha256(recipient_public).hexdigest(),
                        "recipientNonce": b64url(recipient_nonce),
                        "policyHash": POLICY_HASH,
                        "dataPlaneBinaryDigest": DATA_PLANE_DIGEST,
                        "maxTtlSeconds": 1,
                    },
                    extra_headers={"X-Serverware-Data-Plane-Token": DATA_PLANE_TOKEN},
                )
                expect_status(lease, 200, "managed X OAuth credential lease")
                x_refreshed = db.get_credential(x_credential_id)
                if x_refreshed is None or int(x_refreshed["credential_version"]) <= x_initial_version:
                    raise AssertionError("credential lease did not use the managed X OAuth refresh path")
                x_refreshed_version = int(x_refreshed["credential_version"])
                if simulator.observations()["counts"]["x"].get("refresh_exchanges") != 1:
                    raise AssertionError("X provider did not observe exactly one rotated refresh exchange")
                with db.connect() as connection:
                    refresh_retirement_rows = connection.execute(
                        "SELECT * FROM oauth_revocation_work WHERE provider_id = ? AND source = ?",
                        ("x", "refresh_superseded"),
                    ).fetchall()
                if len(refresh_retirement_rows) != 1 or refresh_retirement_rows[0]["status"] != "pending":
                    raise AssertionError("X refresh did not queue superseded token material")
                refresh_retirement = app_module._reconcile_oauth_revocations(limit=1)
                if refresh_retirement != {"claimed": 1, "revoked": 1, "failed": 0}:
                    raise AssertionError(f"superseded X refresh material did not reconcile: {refresh_retirement}")
                x_refreshed_stored = db.get_credential(x_credential_id, include_secret=True)
                if x_refreshed_stored is None:
                    raise AssertionError("refreshed X credential could not be reloaded")
                x_refreshed_secret = json.loads(x_refreshed_stored["secret"])
                for label, access_token, expected_status in (
                    ("superseded", x_initial_secret.get("access_token"), 401),
                    ("current", x_refreshed_secret.get("access_token"), 200),
                ):
                    identity_request = urllib.request.Request(
                        simulator.provider_urls("x")["identity_url"],
                        headers={"Authorization": f"Bearer {access_token}"},
                        method="GET",
                    )
                    identity_status, _, _ = https_request(
                        identity_request,
                        context=simulator.client_ssl_context,
                    )
                    if identity_status != expected_status:
                        raise AssertionError(
                            f"{label} X token had HTTP {identity_status} after refresh retirement"
                        )

                simulator.queue_authorization_outcome("x", "success")
                x_reconnect_start, _, _, _ = start_authorization(
                    client,
                    provider="x",
                    name=x_name,
                    credential_id=x_credential_id,
                )
                x_reconnect_location = provider_redirect(simulator, x_reconnect_start["authorizationUrl"])
                x_reconnect_callback = callback_from_location(client, x_reconnect_location)
                expect_status(x_reconnect_callback, 200, "X reconnect callback")
                x_reconnect_pending = pending_named(client, x_name)
                x_reconnect_review = x_reconnect_pending.get("review") or {}
                if (
                    x_reconnect_review.get("reconnect_credential_id") != x_credential_id
                    or x_reconnect_review.get("reconnect_credential_version") != x_refreshed_version
                ):
                    raise AssertionError(
                        f"X reconnect was not bound to the active generation: {x_reconnect_review}"
                    )
                x_reconnected = approve_and_activate(client, x_reconnect_pending, exercise_denials=False)
                if (
                    x_reconnected["id"] != x_credential_id
                    or int(x_reconnected["credential_version"]) <= x_refreshed_version
                ):
                    raise AssertionError("X reconnect did not preserve the credential ID and increase its version")

                with db.connect() as connection:
                    superseded_rows = connection.execute(
                        "SELECT * FROM oauth_revocation_work WHERE provider_id = ? AND source = ?",
                        ("x", "reconnect_superseded"),
                    ).fetchall()
                if len(superseded_rows) != 1 or superseded_rows[0]["status"] != "pending":
                    raise AssertionError("X reconnect did not queue superseded token material")
                simulator.assert_no_token_values(json.dumps(dict(superseded_rows[0]), sort_keys=True))
                superseded_reconciliation = app_module._reconcile_oauth_revocations(limit=1)
                if superseded_reconciliation != {"claimed": 1, "revoked": 1, "failed": 0}:
                    raise AssertionError(
                        f"superseded X OAuth material did not reconcile: {superseded_reconciliation}"
                    )
                with db.connect() as connection:
                    superseded_remaining = connection.execute(
                        "SELECT 1 FROM oauth_revocation_work WHERE id = ?",
                        (superseded_rows[0]["id"],),
                    ).fetchone()
                if superseded_remaining is not None:
                    raise AssertionError("reconciled superseded X OAuth work remained queued")
                x_after_superseded = simulator.observations()
                if x_after_superseded["counts"]["x"].get("successful_revocations") != 4:
                    raise AssertionError("superseded X access and refresh tokens were not both revoked")
                superseded_hints = {
                    event.get("token_type_hint")
                    for event in x_after_superseded["events"]
                    if event.get("provider") == "x" and event.get("type") == "token_revoked"
                }
                if superseded_hints != {"access_token", "refresh_token"}:
                    raise AssertionError(f"X superseded revocation omitted a token type: {superseded_hints}")

                disconnect_credential(client, x_credential_id, label="X")
                if simulator.observations()["counts"]["x"].get("successful_revocations") != 6:
                    raise AssertionError("X disconnect did not revoke distinct access and refresh tokens")

                simulator.queue_authorization_outcome("google", "scope_expansion")
                expanded_start, _, _, _ = start_authorization(
                    client,
                    provider="google",
                    name="Google expanded-scope rejection",
                    scopes=GOOGLE_SCOPES,
                )
                expanded_location = provider_redirect(simulator, expanded_start["authorizationUrl"])
                expanded_callback = callback_from_location(client, expanded_location)
                expect_status(expanded_callback, 400, "expanded-scope callback rejection")
                if "expanded or omitted" not in expanded_callback.text:
                    raise AssertionError("expanded provider scopes were not rejected fail closed")
                with db.connect() as connection:
                    revocation_rows = connection.execute(
                        "SELECT * FROM oauth_revocation_work WHERE provider_id = ? AND source = ?",
                        ("google", "authorization_code_exchange"),
                    ).fetchall()
                if len(revocation_rows) != 1 or revocation_rows[0]["status"] != "pending":
                    raise AssertionError("scope-expansion failure did not retain durable revocation work")
                simulator.assert_no_token_values(json.dumps(dict(revocation_rows[0]), sort_keys=True))
                reconciliation = app_module._reconcile_oauth_revocations(limit=1)
                if reconciliation != {"claimed": 1, "revoked": 1, "failed": 0}:
                    raise AssertionError(f"durable OAuth revocation did not reconcile: {reconciliation}")
                with db.connect() as connection:
                    remaining = connection.execute(
                        "SELECT 1 FROM oauth_revocation_work WHERE id = ?",
                        (revocation_rows[0]["id"],),
                    ).fetchone()
                if remaining is not None:
                    raise AssertionError("reconciled OAuth revocation work remained queued")

                bootstrap = request(client, "GET", "/api/bootstrap", actor="operator")
                expect_status(bootstrap, 200, "credential listing")
                listed_ids = {item.get("id") for item in bootstrap.json().get("credentials", [])}
                if listed_ids.intersection({google_credential_id, x_credential_id}):
                    raise AssertionError("credential listing retained a disconnected OAuth credential")
                pending_listing = request(client, "GET", "/api/oauth/pending", actor="operator")
                expect_status(pending_listing, 200, "final pending OAuth listing")
                if pending_listing.json().get("pendingCredentials"):
                    raise AssertionError("terminal OAuth flow left a pending credential")
                audit = request(client, "GET", "/api/audit?limit=500", actor="reviewer")
                expect_status(audit, 200, "OAuth audit listing")
                audit_events = audit.json()
                audit_types = {item.get("event_type") for item in audit_events}
                required_audit_types = {
                    "credential.oauth_connected",
                    "credential.oauth_refreshed",
                    "credential.oauth_reconnected",
                    "credential.oauth_token_retirement_queued",
                    "credential.deleted",
                    "credential.oauth_exchange_revoked",
                }
                if not required_audit_types.issubset(audit_types):
                    missing_audits = sorted(required_audit_types - audit_types)
                    raise AssertionError(f"OAuth HTTP flow omitted audit events: {missing_audits}")

                observation_request = urllib.request.Request(simulator.observations_url, method="GET")
                observation_status, _, observation_body = https_request(
                    observation_request,
                    context=simulator.client_ssl_context,
                )
                if observation_status != 200:
                    raise AssertionError("simulator observations endpoint failed")
                simulator.assert_no_token_values(observation_body)
                observations = json.loads(observation_body)
                google_counts = observations["counts"]["google"]
                x_counts = observations["counts"]["x"]
                if google_counts.get("successful_revocations") != 2:
                    raise AssertionError("Google disconnect and rejected exchange were not both revoked")
                if x_counts.get("successful_revocations") != 6:
                    raise AssertionError("X refresh, reconnect, and disconnect token pairs were not fully revoked")
                if x_counts.get("authorization_code_exchanges") != 2:
                    raise AssertionError("X initial and reconnect confidential-client exchanges were not exercised")
                if x_counts.get("refresh_exchanges") != 1:
                    raise AssertionError("X managed credential refresh did not rotate exactly once")

                combined_public = b"\n".join(response.content for response in asgi_responses)
                simulator.assert_no_token_values(combined_public)
                simulator.assert_no_token_values(json.dumps(audit_events, sort_keys=True))
                simulator.assert_no_token_values(json.dumps(bootstrap.json(), sort_keys=True))
                simulator.assert_no_token_values(json.dumps(pending_listing.json(), sort_keys=True))

            app_module.app.dependency_overrides.pop(require_admin, None)
            oauth._providers = original_providers
            oauth.request_bytes = original_request_bytes

            final_counts = simulator.observations()["counts"]
            print(
                json.dumps(
                    {
                        "ok": True,
                        "asgiResponses": len(asgi_responses),
                        "google": final_counts["google"],
                        "x": final_counts["x"],
                    },
                    sort_keys=True,
                )
            )


if __name__ == "__main__":
    main()
