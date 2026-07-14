#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


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
            self.headers["X-Serverware-CSRF-Token"] = csrf
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
        "serverware_roles": roles,
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


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        issuer = "https://idp.example"
        audience = "serverware-control-plane"
        kid = "serverware-oidc-test"
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

        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_OIDC_ENABLED"] = "1"
        os.environ["SERVERWARE_OIDC_ISSUER"] = issuer
        os.environ["SERVERWARE_OIDC_AUDIENCE"] = audience
        os.environ["SERVERWARE_OIDC_JWKS_JSON"] = json.dumps(jwks, separators=(",", ":"), sort_keys=True)
        os.environ["SERVERWARE_OIDC_ROLE_CLAIM"] = "serverware_roles"
        os.environ["SERVERWARE_OIDC_BROWSER_LOGIN_ENABLED"] = "1"
        os.environ["SERVERWARE_OIDC_AUTHORIZATION_ENDPOINT"] = f"{issuer}/authorize"
        os.environ["SERVERWARE_OIDC_TOKEN_ENDPOINT"] = f"{issuer}/token"
        os.environ["SERVERWARE_OIDC_CLIENT_ID"] = audience
        os.environ["SERVERWARE_OIDC_CLIENT_SECRET"] = "test-browser-oidc-client-secret"
        os.environ["SERVERWARE_OIDC_REDIRECT_URI"] = "https://serverware.test/api/auth/oidc/callback"
        os.environ["SERVERWARE_ADMIN_TOKEN"] = "local-admin-token-for-csrf-test"
        os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "0"

        from fastapi import HTTPException, Response

        from serverware import auth, db, operator_oidc
        from serverware import app as app_module

        db.init_db()

        token = sign_jwt(private_key, kid=kid, issuer=issuer, audience=audience, roles=["auditor", "policy_author"])
        identity = auth.require_admin(FakeRequest(token), x_serverware_admin_token=None)
        if identity.user_id != "oidc:andrew" or identity.auth_method != "oidc-bearer":
            raise AssertionError(f"OIDC identity was not accepted: {identity}")
        if identity.roles != frozenset({"auditor", "policy_author"}):
            raise AssertionError(f"OIDC roles were not mapped from the role claim: {identity}")
        auth.require_role("auditor")(identity)

        csrf_request = FakeRequest(
            token,
            method="POST",
            path="/api/credentials",
            cookies={"serverware_admin": auth.admin_token()},
        )
        auth.validate_csrf_request(csrf_request)

        bad_audience = sign_jwt(private_key, kid=kid, issuer=issuer, audience="wrong-audience", roles=["auditor"])
        try:
            auth.require_admin(FakeRequest(bad_audience), x_serverware_admin_token=None)
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
            auth.require_admin(FakeRequest(multiple_audiences), x_serverware_admin_token=None)
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
            FakeRequest(authorized_multiple_audiences), x_serverware_admin_token=None
        ).user_id != "oidc:andrew":
            raise AssertionError("multi-audience OIDC token with the expected azp was rejected")

        original_jwks = auth.OIDC_JWKS_JSON
        encryption_jwks = json.loads(original_jwks)
        encryption_jwks["keys"][0]["use"] = "enc"
        auth.OIDC_JWKS_JSON = json.dumps(encryption_jwks, separators=(",", ":"), sort_keys=True)
        auth._oidc_jwks.cache_clear()
        try:
            auth.require_admin(FakeRequest(token), x_serverware_admin_token=None)
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
            auth.require_admin(FakeRequest(missing_roles), x_serverware_admin_token=None)
        except HTTPException as exc:
            if exc.status_code != 401 or "RBAC roles" not in str(exc.detail):
                raise AssertionError(f"missing roles failed with wrong error: {exc.status_code} {exc.detail}") from exc
        else:
            raise AssertionError("OIDC token without Serverware roles was accepted")

        tampered = token.rsplit(".", 1)[0] + "." + b64u(b"bad-signature")
        try:
            auth.require_admin(FakeRequest(tampered), x_serverware_admin_token=None)
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
        if completed["identity"].auth_method != "oidc-session" or completed["id_token"] != browser_id_token:
            raise AssertionError(f"browser OIDC login did not produce a verified session: {completed}")
        if len(token_exchange_requests) != 1:
            raise AssertionError("browser OIDC token endpoint was called more than once")
        exchange_body = urllib.parse.parse_qs(bytes(token_exchange_requests[0].data).decode("utf-8"))
        if not exchange_body.get("code_verifier") or exchange_body.get("code") != ["authorization-code"]:
            raise AssertionError(f"browser OIDC token exchange omitted PKCE: {exchange_body}")
        if not str(token_exchange_requests[0].headers.get("Authorization") or "").startswith("Basic "):
            raise AssertionError("browser OIDC token exchange did not authenticate the client")

        cookie_identity = auth.require_admin(
            FakeRequest(cookies={auth.OIDC_SESSION_COOKIE_NAME: browser_id_token}),
            x_serverware_admin_token=None,
        )
        if cookie_identity.auth_method != "oidc-session" or cookie_identity.user_id != "oidc:andrew":
            raise AssertionError(f"verified OIDC session cookie was not accepted: {cookie_identity}")
        csrf_cookie = "csrf-cookie-value"
        try:
            auth.validate_csrf_request(
                FakeRequest(
                    method="POST",
                    path="/api/credentials",
                    cookies={auth.OIDC_SESSION_COOKIE_NAME: browser_id_token, auth.CSRF_COOKIE_NAME: csrf_cookie},
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
                cookies={auth.OIDC_SESSION_COOKIE_NAME: browser_id_token, auth.CSRF_COOKIE_NAME: csrf_cookie},
                csrf=csrf_cookie,
            )
        )

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
