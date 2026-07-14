from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from serverware import db
from serverware.auth import OIDCAccessDenied, OIDCAuthError, OIDCAuthoritativeStateError, oidc_identity_from_token
from serverware.config import (
    OIDC_AUTHORIZATION_ENDPOINT,
    OIDC_AUDIENCE,
    OIDC_BROWSER_LOGIN_ENABLED,
    OIDC_BROWSER_SCOPES,
    OIDC_CLIENT_ID,
    OIDC_CLIENT_SECRET,
    OIDC_ENABLED,
    OIDC_ISSUER,
    OIDC_LOGIN_STATE_TTL_SECONDS,
    OIDC_REDIRECT_URI,
    OIDC_SESSION_TTL_SECONDS,
    OIDC_TOKEN_AUTH_METHOD,
    OIDC_TOKEN_ENDPOINT,
)
from serverware.http_client import HttpClientError, request_bytes, validate_http_url


MAX_TOKEN_RESPONSE_BYTES = 256 * 1024
MAX_SESSION_ID_TOKEN_BYTES = 3500


class OperatorOIDCError(RuntimeError):
    pass


def browser_login_configured() -> bool:
    secret_ready = OIDC_TOKEN_AUTH_METHOD == "none" or bool(OIDC_CLIENT_SECRET)
    return bool(
        OIDC_ENABLED
        and OIDC_BROWSER_LOGIN_ENABLED
        and OIDC_ISSUER
        and OIDC_AUDIENCE
        and OIDC_AUTHORIZATION_ENDPOINT
        and OIDC_TOKEN_ENDPOINT
        and OIDC_CLIENT_ID
        and OIDC_CLIENT_ID == OIDC_AUDIENCE
        and OIDC_REDIRECT_URI
        and OIDC_BROWSER_SCOPES
        and secret_ready
    )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _https_origin(value: str, label: str) -> tuple[str, str, int]:
    validate_http_url(value, require_https=True)
    parsed = urllib.parse.urlsplit(value)
    if parsed.username or parsed.password or parsed.fragment:
        raise OperatorOIDCError(f"{label} URL contains forbidden components")
    port = parsed.port or 443
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port


def start_operator_login() -> dict[str, Any]:
    if not browser_login_configured():
        raise OperatorOIDCError("browser OIDC login is not fully configured")
    issuer_origin = _https_origin(OIDC_ISSUER, "OIDC issuer")
    if _https_origin(OIDC_AUTHORIZATION_ENDPOINT, "OIDC authorization endpoint") != issuer_origin:
        raise OperatorOIDCError("OIDC authorization endpoint must use the configured issuer origin")
    if _https_origin(OIDC_TOKEN_ENDPOINT, "OIDC token endpoint") != issuer_origin:
        raise OperatorOIDCError("OIDC token endpoint must use the configured issuer origin")
    _https_origin(OIDC_REDIRECT_URI, "OIDC redirect")
    if "openid" not in OIDC_BROWSER_SCOPES:
        raise OperatorOIDCError("browser OIDC scopes must include openid")
    if len(OIDC_BROWSER_SCOPES) > 20 or len(set(OIDC_BROWSER_SCOPES)) != len(OIDC_BROWSER_SCOPES):
        raise OperatorOIDCError("browser OIDC scopes are invalid")

    state = secrets.token_urlsafe(32)
    browser_nonce = secrets.token_urlsafe(32)
    oidc_nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    challenge = _b64url(hashlib.sha256(code_verifier.encode("ascii")).digest())
    persisted = db.create_oidc_login_state(
        state=state,
        browser_nonce=browser_nonce,
        code_verifier=code_verifier,
        oidc_nonce=oidc_nonce,
        ttl_seconds=OIDC_LOGIN_STATE_TTL_SECONDS,
    )
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": OIDC_CLIENT_ID,
            "redirect_uri": OIDC_REDIRECT_URI,
            "scope": " ".join(OIDC_BROWSER_SCOPES),
            "state": state,
            "nonce": oidc_nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return {
        "authorization_url": f"{OIDC_AUTHORIZATION_ENDPOINT}?{query}",
        "browser_nonce": browser_nonce,
        "state_hash": persisted["state_hash"],
        "expires_at": persisted["expires_at"],
    }


def _token_request(code: str, code_verifier: str) -> urllib.request.Request:
    body = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": OIDC_REDIRECT_URI,
        "client_id": OIDC_CLIENT_ID,
        "code_verifier": code_verifier,
    }
    headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    if OIDC_TOKEN_AUTH_METHOD == "client_secret_basic":
        raw = f"{OIDC_CLIENT_ID}:{OIDC_CLIENT_SECRET}".encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    elif OIDC_TOKEN_AUTH_METHOD == "client_secret_post":
        body["client_secret"] = OIDC_CLIENT_SECRET
    return urllib.request.Request(
        OIDC_TOKEN_ENDPOINT,
        data=urllib.parse.urlencode(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )


def complete_operator_login(
    *,
    state: str,
    code: str,
    browser_nonce: str,
) -> dict[str, Any]:
    if not browser_login_configured():
        raise OperatorOIDCError("browser OIDC login is not fully configured")
    if not isinstance(code, str) or not code or len(code.encode("utf-8")) > 16 * 1024:
        raise OperatorOIDCError("OIDC authorization code is invalid")
    try:
        consumed = db.consume_oidc_login_state(state=state, browser_nonce=browser_nonce)
    except db.MetadataStoreError as exc:
        raise OperatorOIDCError(str(exc)) from exc
    try:
        response = request_bytes(
            _token_request(code, consumed["code_verifier"]),
            timeout=20,
            max_bytes=MAX_TOKEN_RESPONSE_BYTES,
            require_https=True,
        )
        payload = json.loads(response.body.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise OperatorOIDCError(f"OIDC token exchange failed: HTTP {exc.code}") from exc
    except (HttpClientError, urllib.error.URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperatorOIDCError(f"OIDC token exchange failed: {exc}") from exc
    if not isinstance(payload, dict):
        raise OperatorOIDCError("OIDC token endpoint returned a non-object response")
    id_token = payload.get("id_token")
    if not isinstance(id_token, str) or not id_token or len(id_token.encode("utf-8")) > MAX_SESSION_ID_TOKEN_BYTES:
        raise OperatorOIDCError("OIDC token endpoint did not return a bounded id_token")
    try:
        identity = oidc_identity_from_token(
            id_token,
            expected_nonce=consumed["oidc_nonce"],
            auth_method="oidc-session",
        )
    except (OIDCAuthError, OIDCAccessDenied, OIDCAuthoritativeStateError) as exc:
        raise OperatorOIDCError(str(exc)) from exc
    if identity is None:
        raise OperatorOIDCError("OIDC identity is unavailable")
    try:
        payload_segment = id_token.split(".")[1]
        token_payload = json.loads(base64.urlsafe_b64decode(payload_segment + "=" * (-len(payload_segment) % 4)))
        expires_at = int(token_payload["exp"])
    except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise OperatorOIDCError("OIDC id_token expiry is invalid") from exc
    max_age = min(OIDC_SESSION_TTL_SECONDS, expires_at - int(time.time()))
    if max_age <= 0:
        raise OperatorOIDCError("OIDC id_token is already expired")
    return {
        "id_token": id_token,
        "identity": identity,
        "max_age": max_age,
        "expires_at": expires_at,
    }
