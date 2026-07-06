from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from serverware.config import (
    GOOGLE_OAUTH_CLIENT_ID,
    GOOGLE_OAUTH_CLIENT_SECRET,
    GOOGLE_OAUTH_REDIRECT_URI,
    OAUTH_STATE_PATH,
    OAUTH_STATE_TTL_SECONDS,
    X_OAUTH_CLIENT_ID,
    X_OAUTH_CLIENT_SECRET,
    X_OAUTH_REDIRECT_URI,
)


MAX_OAUTH_CREDENTIAL_NAME_BYTES = 200
MAX_OAUTH_METADATA_BYTES = 4096
MAX_OAUTH_METADATA_KEYS = 50


class OAuthError(RuntimeError):
    pass


@dataclass(frozen=True)
class OAuthProvider:
    id: str
    display_name: str
    authorization_url: str
    token_url: str
    client_id: str
    client_secret: str
    redirect_uri: str
    default_scopes: tuple[str, ...]
    token_auth: str
    auth_params: dict[str, str]
    metadata_provider: str

    @property
    def configured(self) -> bool:
        return bool(self.client_id and self.redirect_uri)


def _providers() -> dict[str, OAuthProvider]:
    x_provider = OAuthProvider(
        id="x",
        display_name="X / Twitter",
        authorization_url="https://twitter.com/i/oauth2/authorize",
        token_url="https://api.twitter.com/2/oauth2/token",
        client_id=X_OAUTH_CLIENT_ID,
        client_secret=X_OAUTH_CLIENT_SECRET,
        redirect_uri=X_OAUTH_REDIRECT_URI,
        default_scopes=("tweet.read", "users.read", "offline.access"),
        token_auth="basic" if X_OAUTH_CLIENT_SECRET else "none",
        auth_params={},
        metadata_provider="x.oauth2",
    )
    return {
        "google": OAuthProvider(
            id="google",
            display_name="Google",
            authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
            client_id=GOOGLE_OAUTH_CLIENT_ID,
            client_secret=GOOGLE_OAUTH_CLIENT_SECRET,
            redirect_uri=GOOGLE_OAUTH_REDIRECT_URI,
            default_scopes=("https://www.googleapis.com/auth/gmail.readonly",),
            token_auth="client_secret_post",
            auth_params={
                "access_type": "offline",
                "prompt": "consent",
                "include_granted_scopes": "true",
            },
            metadata_provider="google.oauth2",
        ),
        "x": x_provider,
        "twitter": x_provider,
    }


def normalize_provider_id(provider_id: str) -> str:
    normalized = provider_id.strip().lower()
    if normalized == "twitter":
        return "x"
    return normalized


def provider_for(provider_id: str) -> OAuthProvider:
    provider = _providers().get(provider_id.strip().lower())
    if not provider:
        raise OAuthError(f"unsupported OAuth provider: {provider_id}")
    return provider


def provider_status() -> list[dict[str, Any]]:
    seen: set[str] = set()
    items = []
    for provider in _providers().values():
        if provider.id in seen:
            continue
        seen.add(provider.id)
        items.append(
            {
                "id": provider.id,
                "displayName": provider.display_name,
                "configured": provider.configured,
                "authorizationUrl": provider.authorization_url,
                "tokenUrl": provider.token_url,
                "redirectUri": provider.redirect_uri,
                "defaultScopes": list(provider.default_scopes),
                "metadataProvider": provider.metadata_provider,
                "secretStorage": "encrypted credential secret",
                "recommendedInjection": {"type": "bearer", "field": "access_token"},
            }
        )
    return items


def _now() -> int:
    return int(time.time())


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _code_verifier() -> str:
    return _b64url(secrets.token_bytes(32))


def _code_challenge(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def _bounded_credential_name(name: str | None, default: str) -> str:
    value = (name or default).strip()
    if not value:
        raise OAuthError("OAuth credential name cannot be empty")
    if len(value.encode("utf-8")) > MAX_OAUTH_CREDENTIAL_NAME_BYTES:
        raise OAuthError("OAuth credential name is too large")
    return value


def _bounded_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    value = metadata or {}
    if not isinstance(value, dict):
        raise OAuthError("OAuth metadata must be an object")
    if len(value) > MAX_OAUTH_METADATA_KEYS:
        raise OAuthError("OAuth metadata has too many keys")
    try:
        encoded = json.dumps(value, separators=(",", ":"), sort_keys=True)
    except Exception as exc:
        raise OAuthError("OAuth metadata must be JSON serializable") from exc
    if len(encoded.encode("utf-8")) > MAX_OAUTH_METADATA_BYTES:
        raise OAuthError("OAuth metadata is too large")
    return value


def _read_states() -> dict[str, Any]:
    try:
        loaded = json.loads(OAUTH_STATE_PATH.read_text())
    except FileNotFoundError:
        return {"version": 1, "states": {}}
    except Exception:
        return {"version": 1, "states": {}}
    if not isinstance(loaded, dict):
        return {"version": 1, "states": {}}
    loaded.setdefault("version", 1)
    loaded.setdefault("states", {})
    if not isinstance(loaded["states"], dict):
        loaded["states"] = {}
    return loaded


def _write_states(payload: dict[str, Any]) -> None:
    OAUTH_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = OAUTH_STATE_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n")
    tmp.chmod(0o600)
    tmp.replace(OAUTH_STATE_PATH)
    try:
        OAUTH_STATE_PATH.chmod(0o600)
    except OSError:
        pass


def _prune_expired(payload: dict[str, Any]) -> None:
    now = _now()
    states = payload.setdefault("states", {})
    for state, record in list(states.items()):
        if not isinstance(record, dict) or int(record.get("expires_at_epoch", 0)) <= now:
            states.pop(state, None)


def create_authorization_url(
    *,
    provider_id: str,
    credential_name: str | None,
    scopes: list[str] | None,
    metadata: dict[str, Any] | None,
    actor_id: str,
    control_plane_mfa: dict[str, Any] | None = None,
    control_plane_approval: dict[str, Any] | None = None,
) -> dict[str, Any]:
    provider = provider_for(provider_id)
    if not provider.configured:
        raise OAuthError(f"{provider.display_name} OAuth is not configured")
    requested_scopes = [scope.strip() for scope in (scopes or list(provider.default_scopes)) if scope.strip()]
    if not requested_scopes:
        raise OAuthError("at least one OAuth scope is required")
    if len(requested_scopes) > 30 or any(len(scope) > 200 for scope in requested_scopes):
        raise OAuthError("OAuth scope list is too large")
    credential_label = _bounded_credential_name(
        credential_name,
        f"{provider.display_name} OAuth credential",
    )
    metadata_value = _bounded_metadata(metadata)

    verifier = _code_verifier()
    state = _b64url(secrets.token_bytes(32))
    expires_at = _now() + OAUTH_STATE_TTL_SECONDS
    record = {
        "provider": provider.id,
        "credential_name": credential_label,
        "scopes": requested_scopes,
        "metadata": metadata_value,
        "actor_id": actor_id,
        "control_plane_mfa": control_plane_mfa,
        "control_plane_approval": control_plane_approval,
        "code_verifier": verifier,
        "redirect_uri": provider.redirect_uri,
        "created_at_epoch": _now(),
        "expires_at_epoch": expires_at,
    }
    payload = _read_states()
    _prune_expired(payload)
    payload["states"][state] = record
    _write_states(payload)

    query = {
        "response_type": "code",
        "client_id": provider.client_id,
        "redirect_uri": provider.redirect_uri,
        "scope": " ".join(requested_scopes),
        "state": state,
        "code_challenge": _code_challenge(verifier),
        "code_challenge_method": "S256",
        **provider.auth_params,
    }
    return {
        "provider": provider.id,
        "authorizationUrl": f"{provider.authorization_url}?{urllib.parse.urlencode(query)}",
        "state": state,
        "expiresAtEpoch": expires_at,
        "redirectUri": provider.redirect_uri,
        "scopes": requested_scopes,
    }


def consume_state(*, provider_id: str, state: str) -> dict[str, Any]:
    provider = provider_for(provider_id)
    payload = _read_states()
    _prune_expired(payload)
    record = payload["states"].pop(state, None)
    _write_states(payload)
    if not isinstance(record, dict):
        raise OAuthError("OAuth state is unknown or expired")
    if record.get("provider") != provider.id:
        raise OAuthError("OAuth state provider mismatch")
    if int(record.get("expires_at_epoch", 0)) <= _now():
        raise OAuthError("OAuth state expired")
    return record


def _token_request_headers(provider: OAuthProvider) -> dict[str, str]:
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    if provider.token_auth == "basic":
        raw = f"{provider.client_id}:{provider.client_secret}".encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    return headers


def _token_request_body(provider: OAuthProvider, record: dict[str, Any], code: str) -> dict[str, str]:
    body = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": str(record.get("redirect_uri") or provider.redirect_uri),
        "client_id": provider.client_id,
        "code_verifier": str(record["code_verifier"]),
    }
    if provider.token_auth == "client_secret_post" and provider.client_secret:
        body["client_secret"] = provider.client_secret
    return body


def _post_token_request(provider: OAuthProvider, body: dict[str, str], headers: dict[str, str]) -> dict[str, Any]:
    encoded = urllib.parse.urlencode(body).encode("utf-8")
    request = urllib.request.Request(provider.token_url, data=encoded, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise OAuthError(f"OAuth token exchange failed: HTTP {exc.code} {detail}") from exc
    except Exception as exc:
        raise OAuthError(f"OAuth token exchange failed: {exc}") from exc
    if not isinstance(payload, dict):
        raise OAuthError("OAuth token endpoint returned a non-object response")
    return payload


def exchange_authorization_code(*, provider_id: str, code: str, state: str) -> dict[str, Any]:
    provider = provider_for(provider_id)
    record = consume_state(provider_id=provider.id, state=state)
    token_response = _post_token_request(
        provider,
        _token_request_body(provider, record, code),
        _token_request_headers(provider),
    )
    access_token = token_response.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise OAuthError("OAuth token endpoint did not return access_token")
    now = _now()
    expires_in = token_response.get("expires_in")
    expires_at_epoch_ms = None
    if isinstance(expires_in, (int, float)) and expires_in > 0:
        expires_at_epoch_ms = int((now + int(expires_in)) * 1000)
    scope_string = str(token_response.get("scope") or " ".join(record.get("scopes") or []))
    scopes = [scope for scope in scope_string.split(" ") if scope]
    token_secret = {
        "access_token": access_token,
        "refresh_token": token_response.get("refresh_token"),
        "token_type": token_response.get("token_type") or "Bearer",
        "scope": scope_string,
        "expires_at_epoch_ms": expires_at_epoch_ms,
    }
    token_secret = {key: value for key, value in token_secret.items() if value not in (None, "")}
    metadata = {
        **(record.get("metadata") or {}),
        "oauth": True,
        "provider": provider.metadata_provider,
        "provider_id": provider.id,
        "scopes": scopes,
        "token_type": token_secret.get("token_type", "Bearer"),
        "expires_at_epoch_ms": expires_at_epoch_ms,
        "created_by": record.get("actor_id"),
        "injection_field": "access_token",
    }
    return {
        "name": str(record.get("credential_name") or f"{provider.display_name} OAuth credential"),
        "kind": "oauth2",
        "secret": json.dumps(token_secret, separators=(",", ":"), sort_keys=True),
        "metadata": {key: value for key, value in metadata.items() if value is not None},
        "provider": provider.id,
        "scopes": scopes,
        "expiresAtEpochMs": expires_at_epoch_ms,
        "createdBy": record.get("actor_id"),
        "controlPlaneMfa": record.get("control_plane_mfa"),
        "controlPlaneApproval": record.get("control_plane_approval"),
    }
