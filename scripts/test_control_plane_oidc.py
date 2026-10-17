#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
import sys
import tempfile
import time
import urllib.parse
from http.cookies import SimpleCookie
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_uint(value: int) -> str:
    return b64u(value.to_bytes((value.bit_length() + 7) // 8, "big"))


class FakeUrl:
    def __init__(self, path: str, scheme: str = "https"):
        self.path = path
        self.scheme = scheme


class FakeRequest:
    def __init__(
        self,
        token: str = "",
        *,
        method: str = "GET",
        path: str = "/api/bootstrap",
        cookies: dict[str, str] | None = None,
        csrf: str | None = None,
        headers: dict[str, str] | None = None,
        client_host: str = "127.0.0.1",
    ):
        self.headers = dict(headers or {})
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        if csrf:
            self.headers["X-Catchplate-CSRF-Token"] = csrf
        self.cookies = cookies or {}
        self.method = method
        self.url = FakeUrl(path)
        self.client = SimpleNamespace(host=client_host)


def sign_jwt(
    private_key: Any,
    *,
    kid: str,
    issuer: str,
    audience: str | list[str],
    roles: list[str],
    subject: str = "andrew",
    nonce: str | None = None,
    authorized_party: str | None = None,
) -> str:
    now = int(time.time())
    header = {"typ": "JWT", "alg": "RS256", "kid": kid}
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "exp": now + 300,
        "iat": now,
        "nbf": now - 5,
        "catchplate_roles": roles,
    }
    if nonce is not None:
        payload["nonce"] = nonce
    if authorized_party is not None:
        payload["azp"] = authorized_party
    signing_input = f"{b64u(json.dumps(header, separators=(',', ':'), sort_keys=True).encode())}.{b64u(json.dumps(payload, separators=(',', ':'), sort_keys=True).encode())}".encode(
        "ascii"
    )
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input.decode('ascii')}.{b64u(signature)}"


def registration_response(webauthn: Any, challenge: str) -> tuple[dict[str, Any], Any]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    public_key_cose = cbor2.dumps(
        {
            1: 2,
            3: -7,
            -1: 1,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
    )
    credential_id = os.urandom(32)
    auth_data = (
        webauthn._rp_hash()
        + bytes([webauthn.UP_FLAG | webauthn.UV_FLAG | webauthn.AT_FLAG])
        + (1).to_bytes(4, "big")
        + bytes(16)
        + len(credential_id).to_bytes(2, "big")
        + credential_id
        + public_key_cose
    )
    client_data = {
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": webauthn.WEBAUTHN_ORIGIN,
        "crossOrigin": False,
    }
    client_data_raw = json.dumps(
        client_data, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    attestation = cbor2.dumps(
        {"fmt": "none", "authData": auth_data, "attStmt": {}}
    )
    encoded_id = b64u(credential_id)
    return (
        {
            "id": encoded_id,
            "rawId": encoded_id,
            "type": "public-key",
            "transports": ["internal"],
            "response": {
                "clientDataJSON": b64u(client_data_raw),
                "attestationObject": b64u(attestation),
            },
        },
        private_key,
    )


def assertion_response(
    webauthn: Any,
    *,
    credential_id: str,
    private_key: Any,
    challenge: str,
    sign_count: int,
) -> dict[str, Any]:
    auth_data = (
        webauthn._rp_hash()
        + bytes([webauthn.UP_FLAG | webauthn.UV_FLAG])
        + sign_count.to_bytes(4, "big")
    )
    client_data_raw = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": webauthn.WEBAUTHN_ORIGIN,
            "crossOrigin": False,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    signature = private_key.sign(
        auth_data + hashlib.sha256(client_data_raw).digest(),
        ec.ECDSA(hashes.SHA256()),
    )
    return {
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "response": {
            "clientDataJSON": b64u(client_data_raw),
            "authenticatorData": b64u(auth_data),
            "signature": b64u(signature),
        },
    }


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        issuer = "https://idp.example"
        audience = "catchplate-control-plane"
        kid = "catchplate-oidc-test"
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = private_key.public_key().public_numbers()
        jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": kid,
                    "alg": "RS256",
                    "use": "sig",
                    "n": b64u_uint(numbers.n),
                    "e": b64u_uint(numbers.e),
                }
            ]
        }

        os.environ["CATCHPLATE_DATA_DIR"] = tmp
        os.environ["CATCHPLATE_METADATA_STORE_BACKEND"] = "sqlite"
        os.environ["CATCHPLATE_AUDIT_STORE_BACKEND"] = "sqlite"
        os.environ["CATCHPLATE_GRANT_STORE_BACKEND"] = "sqlite"
        os.environ["CATCHPLATE_OIDC_ENABLED"] = "1"
        os.environ["CATCHPLATE_OIDC_ISSUER"] = issuer
        os.environ["CATCHPLATE_OIDC_AUDIENCE"] = audience
        os.environ["CATCHPLATE_OIDC_JWKS_JSON"] = json.dumps(jwks, separators=(",", ":"), sort_keys=True)
        os.environ["CATCHPLATE_OIDC_ROLE_CLAIM"] = "catchplate_roles"
        os.environ["CATCHPLATE_OIDC_BROWSER_LOGIN_ENABLED"] = "1"
        os.environ["CATCHPLATE_OIDC_AUTHORIZATION_ENDPOINT"] = f"{issuer}/authorize"
        os.environ["CATCHPLATE_OIDC_TOKEN_ENDPOINT"] = f"{issuer}/token"
        os.environ["CATCHPLATE_OIDC_CLIENT_ID"] = audience
        os.environ["CATCHPLATE_OIDC_CLIENT_SECRET"] = "test-browser-oidc-client-secret"
        os.environ["CATCHPLATE_OIDC_REDIRECT_URI"] = "https://catchplate.test/api/auth/oidc/callback"
        os.environ["CATCHPLATE_ADMIN_TOKEN"] = "local-admin-token-for-csrf-test"
        os.environ["CATCHPLATE_KEY_RELEASE_REQUIRED"] = "0"
        os.environ["CATCHPLATE_DEV_AUTHENTICATOR"] = "1"

        from fastapi import HTTPException, Response

        from catchplate import auth, db, operator_oidc, webauthn
        from catchplate import app as app_module

        db.init_db()

        setup_target = "/?setup=123e4567-e89b-42d3-a456-426614174000"
        valid_return_targets = {
            "/": "/",
            "/approvals": "/approvals",
            "/approvals/approval.release_2026-07-16:primary": "/approvals/approval.release_2026-07-16:primary",
            "/approvals/" + "a" * 256: "/approvals/" + "a" * 256,
            setup_target: setup_target,
        }
        for candidate, expected in valid_return_targets.items():
            actual = app_module._operator_oidc_return_target(candidate)
            if actual != expected:
                raise AssertionError(
                    f"valid OIDC return target was not preserved: {candidate!r} -> {actual!r}"
                )
        invalid_return_targets = [
            None,
            "",
            "approvals/id",
            " https://attacker.invalid/approvals/id",
            "https://attacker.invalid/approvals/id",
            "http://catchplate.test/approvals/id",
            "//attacker.invalid/approvals/id",
            "/\\attacker.invalid/approvals/id",
            "\\\\attacker.invalid\\approvals\\id",
            "/approvals/id#https://attacker.invalid",
            "/approvals/id\x00suffix",
            "/approvals/id\r\nLocation: https://attacker.invalid",
            "/%2f%2fattacker.invalid/approvals/id",
            "/%5c%5cattacker.invalid/approvals/id",
            "/approvals/%2e%2e/%2e%2e",
            "/api/auth/status",
            "/approvals/",
            "/approvals/id?next=https://attacker.invalid",
            "/?setup=123e4567-e89b-42d3-a456-426614174000&next=/approvals/id",
            "/?setup=123e4567-e89b-42d3-a456-426614174000&setup=123e4567-e89b-42d3-a456-426614174000",
            "/?setup=123e4567-e89b-42d3-a456-426614174000#fragment",
            "/?setup=123E4567-E89B-42D3-A456-426614174000",
            "/?unsupported=value",
            "/?",
            "/approvals/" + "a" * 257,
            "/" + "a" * app_module._OIDC_RETURN_TARGET_MAX_BYTES,
        ]
        for candidate in invalid_return_targets:
            actual = app_module._operator_oidc_return_target(candidate)
            if actual != "/":
                raise AssertionError(
                    f"unsafe OIDC return target was accepted: {candidate!r} -> {actual!r}"
                )
        callback_parameters = inspect.signature(
            app_module.operator_oidc_callback
        ).parameters
        if "return_to" in callback_parameters or "return_target" in callback_parameters:
            raise AssertionError(
                "OIDC callback accepts a caller-controlled return target"
            )
        if (
            "new URLSearchParams({return_to: returnTo})" not in app_module.UI_HTML
            or "`${window.location.pathname}${window.location.search}`"
            not in app_module.UI_HTML
        ):
            raise AssertionError(
                "OIDC browser login does not preserve the current portal deep link"
            )

        token = sign_jwt(private_key, kid=kid, issuer=issuer, audience=audience, roles=["auditor", "policy_author"])
        identity = auth.require_admin(FakeRequest(token), x_catchplate_admin_token=None)
        if identity.user_id != "oidc:andrew" or identity.auth_method != "oidc-bearer":
            raise AssertionError(f"OIDC identity was not accepted: {identity}")
        if identity.roles != frozenset({"auditor", "policy_author"}):
            raise AssertionError(f"OIDC roles were not mapped from the role claim: {identity}")
        auth.require_role("auditor")(identity)

        csrf_request = FakeRequest(
            token,
            method="POST",
            path="/api/credentials",
            cookies={"catchplate_admin": auth.admin_token()},
        )
        auth.validate_csrf_request(csrf_request)

        bad_audience = sign_jwt(private_key, kid=kid, issuer=issuer, audience="wrong-audience", roles=["auditor"])
        try:
            auth.require_admin(FakeRequest(bad_audience), x_catchplate_admin_token=None)
        except HTTPException as exc:
            if exc.status_code != 401 or "audience mismatch" not in str(exc.detail):
                raise AssertionError(f"bad audience failed with wrong error: {exc.status_code} {exc.detail}") from exc
        else:
            raise AssertionError("OIDC token with bad audience was accepted")

        multiple_audiences = sign_jwt(
            private_key,
            kid=kid,
            issuer=issuer,
            audience=[audience, "another-client"],
            roles=["auditor"],
        )
        try:
            auth.require_admin(FakeRequest(multiple_audiences), x_catchplate_admin_token=None)
        except HTTPException as exc:
            if exc.status_code != 401 or "authorized party" not in str(exc.detail):
                raise AssertionError(f"missing azp failed with wrong error: {exc.status_code} {exc.detail}") from exc
        else:
            raise AssertionError("multi-audience OIDC token without azp was accepted")

        authorized_multiple_audiences = sign_jwt(
            private_key,
            kid=kid,
            issuer=issuer,
            audience=[audience, "another-client"],
            roles=["auditor"],
            authorized_party=audience,
        )
        if auth.require_admin(
            FakeRequest(authorized_multiple_audiences), x_catchplate_admin_token=None
        ).user_id != "oidc:andrew":
            raise AssertionError("multi-audience OIDC token with the expected azp was rejected")

        original_jwks = auth.OIDC_JWKS_JSON
        encryption_jwks = json.loads(original_jwks)
        encryption_jwks["keys"][0]["use"] = "enc"
        auth.OIDC_JWKS_JSON = json.dumps(encryption_jwks, separators=(",", ":"), sort_keys=True)
        auth._oidc_jwks.cache_clear()
        try:
            auth.require_admin(FakeRequest(token), x_catchplate_admin_token=None)
        except HTTPException as exc:
            if exc.status_code != 401 or "signatures" not in str(exc.detail):
                raise AssertionError(f"encryption-only JWK failed with wrong error: {exc.status_code} {exc.detail}") from exc
        else:
            raise AssertionError("encryption-only JWK was accepted for OIDC signatures")
        finally:
            auth.OIDC_JWKS_JSON = original_jwks
            auth._oidc_jwks.cache_clear()

        missing_roles = sign_jwt(private_key, kid=kid, issuer=issuer, audience=audience, roles=[])
        try:
            auth.require_admin(FakeRequest(missing_roles), x_catchplate_admin_token=None)
        except HTTPException as exc:
            if exc.status_code != 401 or "RBAC roles" not in str(exc.detail):
                raise AssertionError(f"missing roles failed with wrong error: {exc.status_code} {exc.detail}") from exc
        else:
            raise AssertionError("OIDC token without Catchplate roles was accepted")

        tampered = token.rsplit(".", 1)[0] + "." + b64u(b"bad-signature")
        try:
            auth.require_admin(FakeRequest(tampered), x_catchplate_admin_token=None)
        except HTTPException as exc:
            if exc.status_code != 401 or "signature" not in str(exc.detail):
                raise AssertionError(f"tampered token failed with wrong error: {exc.status_code} {exc.detail}") from exc
        else:
            raise AssertionError("OIDC token with bad signature was accepted")

        original_token_endpoint = operator_oidc.OIDC_TOKEN_ENDPOINT
        operator_oidc.OIDC_TOKEN_ENDPOINT = "https://tokens.attacker.invalid/token"
        try:
            operator_oidc.start_operator_login()
        except operator_oidc.OperatorOIDCError as exc:
            if "issuer origin" not in str(exc):
                raise AssertionError(f"cross-origin token endpoint failed incorrectly: {exc}") from exc
        else:
            raise AssertionError("cross-origin OIDC token endpoint was accepted")
        finally:
            operator_oidc.OIDC_TOKEN_ENDPOINT = original_token_endpoint

        started = operator_oidc.start_operator_login()
        authorization_query = dict(
            urllib.parse.parse_qsl(urllib.parse.urlsplit(started["authorization_url"]).query)
        )
        if (
            authorization_query.get("response_type") != "code"
            or authorization_query.get("code_challenge_method") != "S256"
            or not authorization_query.get("code_challenge")
            or not authorization_query.get("nonce")
            or "code_verifier" in started["authorization_url"]
        ):
            raise AssertionError(f"browser OIDC start is not Authorization Code + PKCE: {authorization_query}")

        original_request_bytes = operator_oidc.request_bytes
        browser_id_token = sign_jwt(
            private_key,
            kid=kid,
            issuer=issuer,
            audience=audience,
            roles=["auditor", "policy_author"],
            nonce=authorization_query["nonce"],
        )
        token_exchange_requests = []

        def fake_token_exchange(request, **kwargs):
            token_exchange_requests.append(request)
            return type(
                "TokenResponse",
                (),
                {
                    "status": 200,
                    "headers": {},
                    "body": json.dumps({"id_token": browser_id_token}).encode("utf-8"),
                },
            )()

        operator_oidc.request_bytes = fake_token_exchange
        try:
            completed = operator_oidc.complete_operator_login(
                state=authorization_query["state"],
                code="authorization-code",
                browser_nonce=started["browser_nonce"],
            )
            try:
                operator_oidc.complete_operator_login(
                    state=authorization_query["state"],
                    code="authorization-code-replay",
                    browser_nonce=started["browser_nonce"],
                )
            except operator_oidc.OperatorOIDCError as exc:
                if "already consumed" not in str(exc):
                    raise AssertionError(f"OIDC state replay failed incorrectly: {exc}") from exc
            else:
                raise AssertionError("browser OIDC state was replayed")
        finally:
            operator_oidc.request_bytes = original_request_bytes
        session_token = completed["session_token"]
        if (
            completed["identity"].auth_method != "oidc-session"
            or completed["session"]["status"] != "active"
            or session_token == browser_id_token
        ):
            raise AssertionError(f"browser OIDC login did not produce a verified session: {completed}")
        with db.connect() as conn:
            persisted_session = conn.execute(
                "SELECT * FROM oidc_browser_sessions WHERE id = ?",
                (completed["session"]["id"],),
            ).fetchone()
        persisted_values = json.dumps(dict(persisted_session), sort_keys=True)
        if browser_id_token in persisted_values or session_token in persisted_values:
            raise AssertionError("raw OIDC or browser session token was persisted")
        if len(token_exchange_requests) != 1:
            raise AssertionError("browser OIDC token endpoint was called more than once")
        exchange_body = urllib.parse.parse_qs(bytes(token_exchange_requests[0].data).decode("utf-8"))
        if not exchange_body.get("code_verifier") or exchange_body.get("code") != ["authorization-code"]:
            raise AssertionError(f"browser OIDC token exchange omitted PKCE: {exchange_body}")
        if not str(token_exchange_requests[0].headers.get("Authorization") or "").startswith("Basic "):
            raise AssertionError("browser OIDC token exchange did not authenticate the client")

        def complete_portal_login(
            *,
            return_to: str,
            expected_target: str,
            code: str,
            client_host: str,
        ) -> tuple[dict[str, str], str]:
            start_response = Response()
            start_payload = app_module.operator_oidc_start(
                start_response,
                FakeRequest(
                    path="/api/auth/oidc/start",
                    client_host=client_host,
                ),
                return_to=return_to,
            )
            authorization_url = str(start_payload["authorizationUrl"])
            authorization_query = dict(
                urllib.parse.parse_qsl(urllib.parse.urlsplit(authorization_url).query)
            )
            state_hash = (
                "sha256:"
                + hashlib.sha256(
                    authorization_query["state"].encode("ascii")
                ).hexdigest()
            )
            flow_cookie = SimpleCookie()
            flow_cookie.load(start_response.headers["set-cookie"])
            browser_nonce = flow_cookie["catchplate_oidc_flow"].value
            if expected_target != "/" and (
                expected_target in authorization_url
                or expected_target in json.dumps(start_payload, sort_keys=True)
                or expected_target in browser_nonce
            ):
                raise AssertionError(
                    "OIDC return target leaked into browser/provider state"
                )

            start_records = db.search_audit_events(
                event_type="control_plane.oidc_login.started",
                q=state_hash,
                limit=2,
                scan_limit=5000,
            )["items"]
            if (
                len(start_records) != 1
                or start_records[0]["event"].get("return_target") != expected_target
            ):
                raise AssertionError(
                    f"OIDC return target was not bound to server-side state: {start_records}"
                )

            id_token = sign_jwt(
                private_key,
                kid=kid,
                issuer=issuer,
                audience=audience,
                roles=["auditor", "policy_author"],
                nonce=authorization_query["nonce"],
            )
            exchanges: list[Any] = []

            def fake_portal_token_exchange(request, **kwargs):
                exchanges.append(request)
                return type(
                    "TokenResponse",
                    (),
                    {
                        "status": 200,
                        "headers": {},
                        "body": json.dumps({"id_token": id_token}).encode("utf-8"),
                    },
                )()

            with patch.object(
                operator_oidc,
                "request_bytes",
                side_effect=fake_portal_token_exchange,
            ):
                redirect = app_module.operator_oidc_callback(
                    FakeRequest(
                        path="/api/auth/oidc/callback",
                        cookies={"catchplate_oidc_flow": browser_nonce},
                    ),
                    state=authorization_query["state"],
                    code=code,
                )
            if (
                redirect.status_code != 303
                or redirect.headers.get("location") != expected_target
            ):
                raise AssertionError(
                    f"OIDC callback restored the wrong target: {redirect.status_code} {redirect.headers.get('location')}"
                )
            if len(exchanges) != 1:
                raise AssertionError(
                    "portal OIDC callback did not perform one token exchange"
                )
            return authorization_query, browser_nonce

        approval_query, approval_browser_nonce = complete_portal_login(
            return_to="/approvals/approval.release_2026-07-16:primary",
            expected_target="/approvals/approval.release_2026-07-16:primary",
            code="approval-return-authorization-code",
            client_host="198.51.100.50",
        )
        try:
            app_module.operator_oidc_callback(
                FakeRequest(
                    path="/api/auth/oidc/callback",
                    cookies={"catchplate_oidc_flow": approval_browser_nonce},
                ),
                state=approval_query["state"],
                code="approval-return-replay-code",
            )
        except HTTPException as exc:
            if exc.status_code != 401 or "already consumed" not in str(exc.detail):
                raise AssertionError(
                    f"portal OIDC return state replay failed incorrectly: {exc}"
                ) from exc
        else:
            raise AssertionError("portal OIDC return state was reusable")

        complete_portal_login(
            return_to=setup_target,
            expected_target=setup_target,
            code="setup-return-authorization-code",
            client_host="198.51.100.51",
        )
        complete_portal_login(
            return_to="https://attacker.invalid/approvals/stolen",
            expected_target="/",
            code="unsafe-return-authorization-code",
            client_host="198.51.100.52",
        )

        expired_response = Response()
        expired_start = app_module.operator_oidc_start(
            expired_response,
            FakeRequest(
                path="/api/auth/oidc/start",
                client_host="198.51.100.53",
            ),
            return_to="/approvals/expired-state",
        )
        expired_query = dict(
            urllib.parse.parse_qsl(
                urllib.parse.urlsplit(expired_start["authorizationUrl"]).query
            )
        )
        expired_cookie = SimpleCookie()
        expired_cookie.load(expired_response.headers["set-cookie"])
        expired_state_hash = (
            "sha256:"
            + hashlib.sha256(expired_query["state"].encode("ascii")).hexdigest()
        )
        with db.connect() as conn:
            conn.execute(
                "UPDATE oidc_login_states SET expires_at = ? WHERE id = ?",
                ("2000-01-01T00:00:00+00:00", expired_state_hash),
            )
        with patch.object(
            operator_oidc,
            "request_bytes",
            side_effect=AssertionError("expired OIDC state reached token exchange"),
        ):
            try:
                app_module.operator_oidc_callback(
                    FakeRequest(
                        path="/api/auth/oidc/callback",
                        cookies={
                            "catchplate_oidc_flow": expired_cookie[
                                "catchplate_oidc_flow"
                            ].value
                        },
                    ),
                    state=expired_query["state"],
                    code="expired-return-authorization-code",
                )
            except HTTPException as exc:
                if exc.status_code != 401 or "expired" not in str(exc.detail):
                    raise AssertionError(
                        f"expired portal OIDC return state failed incorrectly: {exc}"
                    ) from exc
            else:
                raise AssertionError("expired portal OIDC return state was accepted")

        cookie_identity = auth.require_admin(
            FakeRequest(cookies={auth.OIDC_SESSION_COOKIE_NAME: session_token}),
            x_catchplate_admin_token=None,
        )
        if cookie_identity.auth_method != "oidc-session" or cookie_identity.user_id != "oidc:andrew":
            raise AssertionError(f"verified OIDC session cookie was not accepted: {cookie_identity}")
        auth.OIDC_SESSION_WEBAUTHN_REQUIRED = True
        try:
            auth.require_admin(
                FakeRequest(cookies={auth.OIDC_SESSION_COOKIE_NAME: session_token}),
                x_catchplate_admin_token=None,
            )
        except HTTPException as exc:
            if exc.status_code != 401 or "not bound" not in str(exc.detail):
                raise AssertionError(f"unbound-session cutover failed incorrectly: {exc}") from exc
        else:
            raise AssertionError("unbound session survived WebAuthn-required cutover")
        finally:
            auth.OIDC_SESSION_WEBAUTHN_REQUIRED = False
        csrf_cookie = "csrf-cookie-value"
        try:
            auth.validate_csrf_request(
                FakeRequest(
                    method="POST",
                    path="/api/credentials",
                    cookies={auth.OIDC_SESSION_COOKIE_NAME: session_token, auth.CSRF_COOKIE_NAME: csrf_cookie},
                )
            )
        except HTTPException as exc:
            if exc.status_code != 403:
                raise AssertionError(f"OIDC session CSRF failed with {exc.status_code}") from exc
        else:
            raise AssertionError("cookie-authenticated OIDC mutation bypassed CSRF")
        auth.validate_csrf_request(
            FakeRequest(
                method="POST",
                path="/api/credentials",
                cookies={auth.OIDC_SESSION_COOKIE_NAME: session_token, auth.CSRF_COOKIE_NAME: csrf_cookie},
                csrf=csrf_cookie,
            )
        )

        try:
            auth.require_admin(
                FakeRequest(cookies={auth.OIDC_SESSION_COOKIE_NAME: browser_id_token}),
                x_catchplate_admin_token=None,
            )
        except HTTPException as exc:
            if exc.status_code != 401:
                raise AssertionError(f"legacy raw ID-token cookie failed incorrectly: {exc}") from exc
        else:
            raise AssertionError("legacy raw ID-token cookie remained accepted")

        operator_oidc.OIDC_SESSION_WEBAUTHN_REQUIRED = True
        pending_started = operator_oidc.start_operator_login()
        pending_query = dict(
            urllib.parse.parse_qsl(
                urllib.parse.urlsplit(pending_started["authorization_url"]).query
            )
        )
        pending_id_token = sign_jwt(
            private_key,
            kid=kid,
            issuer=issuer,
            audience=audience,
            roles=["auditor", "policy_author"],
            nonce=pending_query["nonce"],
        )

        def fake_pending_token_exchange(request, **kwargs):
            return type(
                "TokenResponse",
                (),
                {
                    "status": 200,
                    "headers": {},
                    "body": json.dumps({"id_token": pending_id_token}).encode("utf-8"),
                },
            )()

        operator_oidc.request_bytes = fake_pending_token_exchange
        try:
            pending = operator_oidc.complete_operator_login(
                state=pending_query["state"],
                code="pending-authorization-code",
                browser_nonce=pending_started["browser_nonce"],
            )
        finally:
            operator_oidc.request_bytes = original_request_bytes
            operator_oidc.OIDC_SESSION_WEBAUTHN_REQUIRED = False
        if pending["session"]["status"] != "pending_webauthn":
            raise AssertionError(f"WebAuthn-required session was not pending: {pending}")
        pending_token = pending["session_token"]
        try:
            auth.require_admin(
                FakeRequest(cookies={auth.OIDC_SESSION_COOKIE_NAME: pending_token}),
                x_catchplate_admin_token=None,
            )
        except HTTPException as exc:
            if exc.status_code != 401:
                raise AssertionError(f"pending session failed incorrectly: {exc}") from exc
        else:
            raise AssertionError("pending OIDC session was authorized before WebAuthn")
        try:
            auth.validate_csrf_request(
                FakeRequest(
                    method="POST",
                    path="/api/auth/session/webauthn/options",
                    cookies={auth.OIDC_SESSION_COOKIE_NAME: pending_token},
                )
            )
        except HTTPException as exc:
            if exc.status_code != 403:
                raise AssertionError(f"pending-session CSRF failed incorrectly: {exc}") from exc
        else:
            raise AssertionError("pending OIDC session bypassed CSRF")

        with (
            patch.object(auth.db, "get_oidc_browser_session", return_value=None) as lookup,
            patch.object(
                auth.db,
                "get_active_oidc_browser_session",
                side_effect=AssertionError("auth status performed a second session lookup"),
            ),
        ):
            missing_status = app_module.operator_auth_status(
                FakeRequest(
                    cookies={
                        auth.OIDC_SESSION_COOKIE_NAME: "random-missing-session-cookie"
                    }
                )
            )
        if missing_status.get("authenticated") or lookup.call_count != 0:
            raise AssertionError(
                f"malformed-cookie auth status touched metadata: {missing_status}"
            )

        first_enrollment_options = app_module.operator_session_webauthn_register_options(
            app_module.WebAuthnRegistrationStart(label="YubiKey"),
            FakeRequest(cookies={auth.OIDC_SESSION_COOKIE_NAME: pending_token}),
        )
        first_registration, first_private_key = registration_response(
            webauthn, first_enrollment_options["publicKey"]["challenge"]
        )
        credential = app_module.operator_session_webauthn_register_verify(
            app_module.WebAuthnRegistrationFinish(
                label="YubiKey", response=first_registration
            ),
            FakeRequest(cookies={auth.OIDC_SESSION_COOKIE_NAME: pending_token}),
        )
        pending_status = app_module.operator_auth_status(
            FakeRequest(cookies={auth.OIDC_SESSION_COOKIE_NAME: pending_token})
        )
        if pending_status.get("webauthnRequired") is not True:
            raise AssertionError(f"pending session status omitted WebAuthn: {pending_status}")
        superseded_binding_options = app_module.operator_session_webauthn_options(
            FakeRequest(cookies={auth.OIDC_SESSION_COOKIE_NAME: pending_token})
        )
        binding_options = app_module.operator_session_webauthn_options(
            FakeRequest(cookies={auth.OIDC_SESSION_COOKIE_NAME: pending_token})
        )
        if db.get_unused_webauthn_challenge(
            superseded_binding_options["publicKey"]["challenge"],
            challenge_type="oidc-session-binding",
            user_id="oidc:andrew",
        ) is not None:
            raise AssertionError("superseded OIDC binding challenge remained live")
        with db.connect() as conn:
            live_binding_count = conn.execute(
                "SELECT COUNT(*) AS count FROM webauthn_challenges "
                "WHERE challenge_type = 'oidc-session-binding' "
                "AND user_id = ? AND used_at IS NULL",
                ("oidc:andrew",),
            ).fetchone()["count"]
        if int(live_binding_count) != 1:
            raise AssertionError(
                f"OIDC binding challenge replacement left {live_binding_count} live rows"
            )
        for _ in range(db._OIDC_BINDING_CHALLENGE_USER_RATE_MAX - 2):
            binding_options = app_module.operator_session_webauthn_options(
                FakeRequest(cookies={auth.OIDC_SESSION_COOKIE_NAME: pending_token})
            )
        try:
            app_module.operator_session_webauthn_options(
                FakeRequest(cookies={auth.OIDC_SESSION_COOKIE_NAME: pending_token})
            )
        except HTTPException as exc:
            if exc.status_code != 409 or "rate limit" not in str(exc.detail):
                raise AssertionError(
                    f"OIDC binding challenge rate limit failed incorrectly: {exc}"
                ) from exc
        else:
            raise AssertionError("OIDC binding challenge rate limit was bypassed")
        assertion = assertion_response(
            webauthn,
            credential_id=first_registration["id"],
            private_key=first_private_key,
            challenge=binding_options["publicKey"]["challenge"],
            sign_count=2,
        )
        activation_payload = app_module.OIDCSessionWebAuthnVerify(response=assertion)
        activation_response = Response()
        with patch.object(
            activation_response,
            "set_cookie",
            side_effect=RuntimeError("injected commit-before-delivery failure"),
        ):
            try:
                app_module.operator_session_webauthn_verify(
                    activation_payload,
                    FakeRequest(
                        cookies={auth.OIDC_SESSION_COOKIE_NAME: pending_token}
                    ),
                    activation_response,
                )
            except RuntimeError as exc:
                if "commit-before-delivery" not in str(exc):
                    raise
            else:
                raise AssertionError("injected activation response loss did not fire")
        activation_response = Response()
        activated = app_module.operator_session_webauthn_verify(
            activation_payload,
            FakeRequest(cookies={auth.OIDC_SESSION_COOKIE_NAME: pending_token}),
            activation_response,
        )
        if not activated.get("authenticated"):
            raise AssertionError(f"WebAuthn session activation failed: {activated}")
        active_cookie = SimpleCookie()
        active_cookie.load(activation_response.headers["set-cookie"])
        active_token = active_cookie[auth.OIDC_SESSION_COOKIE_NAME].value
        if active_token == pending_token:
            raise AssertionError("pending OIDC session token was not rotated")
        try:
            app_module.operator_session_webauthn_verify(
                activation_payload,
                FakeRequest(cookies={auth.OIDC_SESSION_COOKIE_NAME: pending_token}),
                Response(),
            )
        except HTTPException as exc:
            if exc.status_code != 409:
                raise AssertionError(
                    f"activation delivery replay failed incorrectly: {exc}"
                ) from exc
        else:
            raise AssertionError("activation delivery receipt was reusable")
        try:
            auth.require_admin(
                FakeRequest(cookies={auth.OIDC_SESSION_COOKIE_NAME: pending_token}),
                x_catchplate_admin_token=None,
            )
        except HTTPException as exc:
            if exc.status_code != 401:
                raise AssertionError(f"rotated pending token failed incorrectly: {exc}") from exc
        else:
            raise AssertionError("pending OIDC token remained valid after activation")
        if auth.require_admin(
            FakeRequest(cookies={auth.OIDC_SESSION_COOKIE_NAME: active_token}),
            x_catchplate_admin_token=None,
        ).user_id != "oidc:andrew":
            raise AssertionError("WebAuthn-bound OIDC session was not activated")
        with db.connect() as conn:
            conn.execute(
                "UPDATE oidc_browser_sessions SET activation_trust_bundle_digest = ? WHERE id = ?",
                ("sha256:" + "f" * 64, pending["session"]["id"]),
            )
        try:
            auth.require_admin(
                FakeRequest(cookies={auth.OIDC_SESSION_COOKIE_NAME: active_token}),
                x_catchplate_admin_token=None,
            )
        except HTTPException as exc:
            if exc.status_code != 401 or "trust generation changed" not in str(exc.detail):
                raise AssertionError(f"trust-generation mismatch failed incorrectly: {exc}") from exc
        else:
            raise AssertionError("session survived a WebAuthn trust-generation mismatch")
        with db.connect() as conn:
            conn.execute(
                "UPDATE oidc_browser_sessions SET activation_trust_bundle_digest = NULL WHERE id = ?",
                (pending["session"]["id"],),
            )
        revoked = db.revoke_webauthn_credential(
            credential["id"],
            actor_id="oidc:andrew",
            reason="test session revocation",
        )
        if revoked.get("revoked_oidc_browser_session_count") != 1:
            raise AssertionError(f"credential revocation did not revoke its session: {revoked}")
        try:
            auth.require_admin(
                FakeRequest(cookies={auth.OIDC_SESSION_COOKIE_NAME: active_token}),
                x_catchplate_admin_token=None,
            )
        except HTTPException as exc:
            if exc.status_code != 401:
                raise AssertionError(f"revoked session failed incorrectly: {exc}") from exc
        else:
            raise AssertionError("credential-revoked OIDC session remained authorized")

        db.revoke_unbound_oidc_browser_sessions(
            actor_id="test:cutover",
            reason="test cutover cleanup",
        )
        with patch.object(db, "append_audit_event") as empty_cutover_audit:
            empty_cutover = db.revoke_unbound_oidc_browser_sessions(
                actor_id="test:cutover",
                reason="test cutover cleanup",
            )
        if empty_cutover["revoked_session_count"] != 0:
            raise AssertionError(f"empty cutover changed sessions: {empty_cutover}")
        empty_cutover_audit.assert_not_called()

        oidc_limits = (
            db._OIDC_LOGIN_GLOBAL_PENDING_MAX,
            db._OIDC_LOGIN_SOURCE_PENDING_MAX,
            db._OIDC_LOGIN_GLOBAL_RATE_MAX,
            db._OIDC_LOGIN_SOURCE_RATE_MAX,
        )
        try:
            with db.connect() as conn:
                conn.execute("DELETE FROM oidc_login_states")
                conn.execute("DELETE FROM oidc_login_rate_buckets")
            db._OIDC_LOGIN_GLOBAL_PENDING_MAX = 10
            db._OIDC_LOGIN_SOURCE_PENDING_MAX = 1
            db._OIDC_LOGIN_GLOBAL_RATE_MAX = 100
            db._OIDC_LOGIN_SOURCE_RATE_MAX = 100
            attacker_peer = "198.51.100.20"
            app_module.operator_oidc_start(
                Response(),
                FakeRequest(
                    path="/api/auth/oidc/start",
                    client_host=attacker_peer,
                    headers={"X-Forwarded-For": "203.0.113.10"},
                ),
            )
            try:
                app_module.operator_oidc_start(
                    Response(),
                    FakeRequest(
                        path="/api/auth/oidc/start",
                        client_host=attacker_peer,
                        headers={
                            "Forwarded": "for=192.0.2.44",
                            "X-Forwarded-For": "192.0.2.45",
                        },
                    ),
                )
            except HTTPException as exc:
                if exc.status_code != 429 or "source capacity" not in str(exc.detail):
                    raise AssertionError(
                        f"same-peer OIDC saturation failed incorrectly: {exc.status_code} {exc.detail}"
                    ) from exc
            else:
                raise AssertionError("spoofed forwarding headers bypassed the OIDC source capacity")
            app_module.operator_oidc_start(
                Response(),
                FakeRequest(
                    path="/api/auth/oidc/start",
                    client_host="198.51.100.21",
                    headers={"X-Forwarded-For": attacker_peer},
                ),
            )

            with db.connect() as conn:
                source_rows = conn.execute(
                    "SELECT DISTINCT source_key FROM oidc_login_states"
                ).fetchall()
                conn.execute("DELETE FROM oidc_login_states")
                conn.execute("DELETE FROM oidc_login_rate_buckets")
            if len(source_rows) != 2:
                raise AssertionError(f"OIDC source keys did not bind direct peers: {source_rows}")

            db._OIDC_LOGIN_SOURCE_PENDING_MAX = 10
            db._OIDC_LOGIN_SOURCE_RATE_MAX = 1
            app_module.operator_oidc_start(
                Response(),
                FakeRequest(
                    path="/api/auth/oidc/start",
                    client_host="198.51.100.25",
                    headers={"X-Forwarded-For": "203.0.113.25"},
                ),
            )
            try:
                app_module.operator_oidc_start(
                    Response(),
                    FakeRequest(
                        path="/api/auth/oidc/start",
                        client_host="198.51.100.25",
                        headers={"X-Forwarded-For": "203.0.113.26"},
                    ),
                )
            except HTTPException as exc:
                if exc.status_code != 429 or "source rate limit" not in str(exc.detail):
                    raise AssertionError(
                        f"source OIDC rate limit failed incorrectly: {exc.status_code} {exc.detail}"
                    ) from exc
            else:
                raise AssertionError("spoofed forwarding headers bypassed the OIDC source rate limit")
            app_module.operator_oidc_start(
                Response(),
                FakeRequest(path="/api/auth/oidc/start", client_host="198.51.100.26"),
            )

            with db.connect() as conn:
                conn.execute("DELETE FROM oidc_login_states")
                conn.execute("DELETE FROM oidc_login_rate_buckets")
            db._OIDC_LOGIN_SOURCE_RATE_MAX = 100
            db._OIDC_LOGIN_GLOBAL_PENDING_MAX = 1
            app_module.operator_oidc_start(
                Response(),
                FakeRequest(path="/api/auth/oidc/start", client_host="198.51.100.30"),
            )
            try:
                app_module.operator_oidc_start(
                    Response(),
                    FakeRequest(path="/api/auth/oidc/start", client_host="198.51.100.31"),
                )
            except HTTPException as exc:
                if exc.status_code != 503 or "state capacity" not in str(exc.detail):
                    raise AssertionError(
                        f"global OIDC capacity failed incorrectly: {exc.status_code} {exc.detail}"
                    ) from exc
            else:
                raise AssertionError("OIDC start exceeded the shared global state capacity")

            with db.connect() as conn:
                conn.execute("DELETE FROM oidc_login_states")
                conn.execute("DELETE FROM oidc_login_rate_buckets")
            db._OIDC_LOGIN_GLOBAL_PENDING_MAX = 10
            db._OIDC_LOGIN_GLOBAL_RATE_MAX = 1
            app_module.operator_oidc_start(
                Response(),
                FakeRequest(path="/api/auth/oidc/start", client_host="198.51.100.40"),
            )
            try:
                app_module.operator_oidc_start(
                    Response(),
                    FakeRequest(path="/api/auth/oidc/start", client_host="198.51.100.41"),
                )
            except HTTPException as exc:
                if exc.status_code != 429 or "global rate limit" not in str(exc.detail):
                    raise AssertionError(
                        f"global OIDC rate limit failed incorrectly: {exc.status_code} {exc.detail}"
                    ) from exc
            else:
                raise AssertionError("OIDC start exceeded the shared global rate limit")
        finally:
            (
                db._OIDC_LOGIN_GLOBAL_PENDING_MAX,
                db._OIDC_LOGIN_SOURCE_PENDING_MAX,
                db._OIDC_LOGIN_GLOBAL_RATE_MAX,
                db._OIDC_LOGIN_SOURCE_RATE_MAX,
            ) = oidc_limits
            with db.connect() as conn:
                conn.execute("DELETE FROM oidc_login_states")
                conn.execute("DELETE FROM oidc_login_rate_buckets")

    print(json.dumps({"control_plane_oidc": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
