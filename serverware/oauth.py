from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any

from serverware import db, oauth_application_owner as application_owner
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
from serverware.http_client import HttpClientError, request_bytes


MAX_OAUTH_CREDENTIAL_NAME_BYTES = 200
MAX_OAUTH_METADATA_BYTES = 4096
MAX_OAUTH_METADATA_KEYS = 50
MAX_OAUTH_CODE_BYTES = 4096
MAX_OAUTH_TOKEN_RESPONSE_BYTES = 256 * 1024
MAX_OAUTH_REFRESH_TOKEN_BYTES = 128 * 1024
MAX_OAUTH_TOKEN_LIFETIME_SECONDS = 366 * 24 * 60 * 60
OAUTH_REFRESH_SKEW_SECONDS = 60
OAUTH_BROWSER_COOKIE_PREFIX = "__Host-serverware-oauth-"
_OAUTH_STATE_RE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
_OAUTH_BROWSER_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_oauth_state_thread_lock = threading.RLock()


class OAuthError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        setup_session_id: str | None = None,
        actor_id: str | None = None,
        issuance_uncertain: bool = False,
    ) -> None:
        super().__init__(message)
        self.setup_session_id = setup_session_id
        self.actor_id = actor_id
        self.issuance_uncertain = issuance_uncertain


def browser_cookie_name(state: str) -> str:
    if not isinstance(state, str) or _OAUTH_STATE_RE.fullmatch(state) is None:
        raise OAuthError("OAuth state is malformed")
    return OAUTH_BROWSER_COOKIE_PREFIX + state


@dataclass(frozen=True)
class OAuthProvider:
    id: str
    display_name: str
    authorization_url: str
    token_url: str
    revocation_url: str
    identity_url: str
    client_id: str
    client_secret: str
    redirect_uri: str
    default_scopes: tuple[str, ...]
    token_response_scope_optional: bool
    token_auth: str
    auth_params: dict[str, str]
    metadata_provider: str

    @property
    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret and self.redirect_uri)


def _providers() -> dict[str, OAuthProvider]:
    x_id, x_secret, x_redirect = application_owner.parameters(
        "x", (X_OAUTH_CLIENT_ID, X_OAUTH_CLIENT_SECRET, X_OAUTH_REDIRECT_URI))
    google_id, google_secret, google_redirect = application_owner.parameters(
        "google", (GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET, GOOGLE_OAUTH_REDIRECT_URI))
    x_provider = OAuthProvider(
        id="x",
        display_name="X / Twitter",
        authorization_url="https://twitter.com/i/oauth2/authorize",
        token_url="https://api.twitter.com/2/oauth2/token",
        revocation_url="https://api.twitter.com/2/oauth2/revoke",
        identity_url="https://api.x.com/2/users/me?user.fields=id,name,username,verified",
        client_id=x_id,
        client_secret=x_secret,
        redirect_uri=x_redirect,
        default_scopes=("tweet.read", "users.read", "offline.access"),
        token_response_scope_optional=True,
        token_auth="basic" if x_secret or application_owner.measured_selected("x") else "none",
        auth_params={},
        metadata_provider="x.oauth2",
    )
    return {
        "google": OAuthProvider(
            id="google",
            display_name="Google",
            authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
            revocation_url="https://oauth2.googleapis.com/revoke",
            identity_url="https://openidconnect.googleapis.com/v1/userinfo",
            client_id=google_id,
            client_secret=google_secret,
            redirect_uri=google_redirect,
            default_scopes=(
                "openid",
                "email",
                "https://www.googleapis.com/auth/gmail.readonly",
            ),
            token_response_scope_optional=True,
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
    try:
        provider = _providers().get(provider_id.strip().lower())
    except application_owner.OAuthApplicationError as exc:
        raise OAuthError("OAuth application cold ownership is unavailable") from exc
    if not provider:
        raise OAuthError(f"unsupported OAuth provider: {provider_id}")
    return provider


def require_application_metadata(metadata, operation=None):
    """Require the actual independently enrolled application before local use."""
    if not isinstance(metadata, dict):
        raise OAuthError("OAuth application metadata is malformed")
    provider = provider_for(str(metadata.get("provider_id") or ""))
    try:
        retained = application_owner.bound(provider, metadata.get(application_owner.ASSOCIATION_KEY), operation)
        if retained is not None and metadata.get("oauth_client_id" if provider.id == "google" else "x_app_id") != provider.client_id:
            raise OAuthError("OAuth credential client does not match its enrolled application")
        return retained
    except application_owner.OAuthApplicationError as exc:
        raise OAuthError("OAuth credential does not belong to the current enrolled application") from exc


def require_application_review(review):
    if not isinstance(review, dict):
        raise OAuthError("OAuth application review is malformed")
    return _application_begin(provider_for(str(review.get("provider") or "")),
        review.get(application_owner.ASSOCIATION_KEY), bound=True)


def _application_begin(provider, association=None, *, bound=False):
    try:
        return (application_owner.bound(provider, association) if bound
            else application_owner.begin(provider, association=association))
    except application_owner.OAuthApplicationError as exc:
        raise OAuthError("OAuth application ownership could not be retained") from exc


def _application_check(operation):
    if operation is not None:
        try:
            operation.check()
        except application_owner.OAuthApplicationError as exc:
            raise OAuthError("OAuth application ownership expired or changed") from exc


def _require_application_lifecycle(operation):
    if operation is not None:
        _application_check(operation)
        # Temporary source checkpoint: atomic approval/credential/pending/audit
        # writes must be joined to a purpose-controlled writer, not split into
        # approval consumption followed by runtime credential DML.
        raise OAuthError("enrolled OAuth lifecycle requires the pending purpose-controlled atomic writer; no provider contact is authorized")


def require_application_consent(provider_id):
    # HTTP entry guard precedes legacy requester-assertion/approval mutations.
    _require_application_lifecycle(_application_begin(provider_for(provider_id)))


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
                "identityUrl": provider.identity_url,
                "redirectUri": provider.redirect_uri,
                "defaultScopes": list(provider.default_scopes),
                "metadataProvider": provider.metadata_provider,
                "secretStorage": "encrypted credential secret",
                "recommendedInjection": {"type": "bearer", "field": "access_token"},
            }
        )
    return items


def resolve_requested_scopes(
    provider_id: str, scopes: list[str] | None
) -> tuple[str, ...]:
    provider = provider_for(provider_id)
    raw_scopes = scopes if scopes else list(provider.default_scopes)
    requested: list[str] = []
    for scope in raw_scopes:
        if (
            not isinstance(scope, str)
            or not scope
            or scope != scope.strip()
            or any(character.isspace() for character in scope)
        ):
            raise OAuthError("OAuth scope list contains an invalid scope")
        requested.append(scope)
    if not requested:
        raise OAuthError("at least one OAuth scope is required")
    if len(requested) > 30 or any(len(scope) > 200 for scope in requested):
        raise OAuthError("OAuth scope list is too large")
    if len(requested) != len(set(requested)):
        raise OAuthError("OAuth scope list contains duplicate scopes")
    return tuple(sorted(requested))


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


def _bounded_reconnect_binding(
    provider: OAuthProvider,
    reconnect_binding: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if reconnect_binding is None:
        return None
    expected_fields = {
        "credential_id",
        "credential_version",
        "provider",
        "provider_subject",
        "provider_account",
    }
    if application_owner.require_started() is not None:
        expected_fields.add(application_owner.ASSOCIATION_KEY)
    if not isinstance(reconnect_binding, dict) or set(reconnect_binding) != expected_fields:
        raise OAuthError("OAuth reconnect binding is malformed")
    credential_version = reconnect_binding.get("credential_version")
    if (
        not isinstance(credential_version, int)
        or isinstance(credential_version, bool)
        or credential_version < 1
    ):
        raise OAuthError("OAuth reconnect credential version is invalid")
    if reconnect_binding.get("provider") != provider.id:
        raise OAuthError(
            "OAuth reconnect provider does not match the existing credential"
        )
    _application_begin(provider, reconnect_binding.get(application_owner.ASSOCIATION_KEY), bound=True)
    for label, key, maximum in (
        ("credential ID", "credential_id", 512),
        ("provider subject", "provider_subject", 512),
        ("provider account", "provider_account", 512),
    ):
        value = reconnect_binding.get(key)
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or len(value) > maximum
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise OAuthError(f"OAuth reconnect {label} is invalid")
    return dict(reconnect_binding)


def _canonical_setup_session_id(setup_session_id: str | None) -> str | None:
    if setup_session_id is None:
        return None
    if not isinstance(setup_session_id, str):
        raise OAuthError("OAuth setup session ID must be a canonical UUID")
    try:
        parsed = uuid.UUID(setup_session_id)
    except (ValueError, AttributeError) as exc:
        raise OAuthError("OAuth setup session ID must be a canonical UUID") from exc
    if str(parsed) != setup_session_id:
        raise OAuthError("OAuth setup session ID must be a canonical UUID")
    return setup_session_id


def _stored_setup_session_id(record: dict[str, Any]) -> str | None:
    if "setup_session_id" not in record:
        return None
    setup_session_id = record.get("setup_session_id")
    if setup_session_id is None:
        raise OAuthError("OAuth state setup session binding is malformed")
    try:
        return _canonical_setup_session_id(setup_session_id)
    except OAuthError as exc:
        raise OAuthError("OAuth state setup session binding is malformed") from exc


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


@contextlib.contextmanager
def _oauth_state_lock():
    OAUTH_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    lock_path = OAUTH_STATE_PATH.with_suffix(OAUTH_STATE_PATH.suffix + ".lock")
    with _oauth_state_thread_lock, lock_path.open("a+", encoding="utf-8") as lock_file:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _write_states(payload: dict[str, Any]) -> None:
    OAUTH_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        # All callers hold the existing state lock. A unique private sibling
        # avoids reusing a leftover temporary inode after interrupted writes.
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                dir=OAUTH_STATE_PATH.parent, prefix=".oauth-state-", delete=False) as output:
            temporary = output.name
            os.fchmod(output.fileno(), 0o600)
            output.write(json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, OAUTH_STATE_PATH)
        directory = os.open(OAUTH_STATE_PATH.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        # In particular, a directory-sync failure after replace is uncertain,
        # not success. State consumption cannot continue to provider contact.
        raise OAuthError("OAuth state persistence is uncertain; no automatic retry") from exc
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _prune_expired(payload: dict[str, Any]) -> None:
    now = _now()
    states = payload.setdefault("states", {})
    for state, record in list(states.items()):
        if (
            not isinstance(record, dict)
            or int(record.get("expires_at_epoch", 0)) <= now
        ):
            states.pop(state, None)


def create_authorization_url(
    *,
    provider_id: str,
    credential_name: str | None,
    scopes: list[str] | None,
    metadata: dict[str, Any] | None,
    actor_id: str,
    browser_nonce: str,
    control_plane_mfa: dict[str, Any] | None = None,
    control_plane_approval: dict[str, Any] | None = None,
    reconnect_binding: dict[str, Any] | None = None,
    setup_session_id: str | None = None,
    operator_catalog_intent_id: str | None = None,
) -> dict[str, Any]:
    provider = provider_for(provider_id)
    if not provider.configured:
        raise OAuthError(f"{provider.display_name} OAuth is not configured")
    operation = _application_begin(provider)
    _require_application_lifecycle(operation)
    requested_scopes = list(resolve_requested_scopes(provider_id, scopes))
    credential_label = _bounded_credential_name(
        credential_name,
        f"{provider.display_name} OAuth credential",
    )
    if operation is not None and reconnect_binding is not None and isinstance(metadata, dict):
        # Keep the old caller-metadata budget; the admitted association has its
        # own 8 KiB bound and still fits the database's unchanged 16 KiB total.
        metadata_value = {**_bounded_metadata({key: value for key, value in metadata.items()
            if key != application_owner.ASSOCIATION_KEY}),
            application_owner.ASSOCIATION_KEY: metadata.get(application_owner.ASSOCIATION_KEY)}
    else:
        metadata_value = _bounded_metadata(metadata)
    if application_owner.ASSOCIATION_KEY in metadata_value:
        if reconnect_binding is None:
            raise OAuthError("OAuth application ownership is not caller metadata")
        require_application_metadata(metadata_value, operation)
    reconnect_value = _bounded_reconnect_binding(provider, reconnect_binding)
    setup_session_value = _canonical_setup_session_id(setup_session_id)
    catalog_intent = _canonical_setup_session_id(operator_catalog_intent_id)
    if catalog_intent is not None and (provider.id != "google" or operation is not None
            or setup_session_value is not None or reconnect_value is not None or metadata_value):
        raise OAuthError("Operator Google consent binding refused")
    if (
        not isinstance(browser_nonce, str)
        or _OAUTH_BROWSER_NONCE_RE.fullmatch(browser_nonce) is None
    ):
        raise OAuthError("OAuth browser binding is malformed")

    verifier = _code_verifier()
    state = _b64url(secrets.token_bytes(32))
    expires_at = _now() + OAUTH_STATE_TTL_SECONDS
    record = {
        "provider": provider.id,
        "credential_name": credential_label,
        "scopes": requested_scopes,
        "metadata": metadata_value,
        "actor_id": actor_id,
        "browser_nonce_sha256": "sha256:"
        + hashlib.sha256(browser_nonce.encode("ascii")).hexdigest(),
        "control_plane_mfa": control_plane_mfa,
        "control_plane_approval": control_plane_approval,
        "reconnect": reconnect_value,
        "code_verifier": verifier,
        "redirect_uri": provider.redirect_uri,
        "created_at_epoch": _now(),
        "expires_at_epoch": expires_at,
    }
    if setup_session_value is not None:
        record["setup_session_id"] = setup_session_value
    if catalog_intent is not None:
        record["operator_catalog_intent_id"] = catalog_intent
    if operation is not None:
        record[application_owner.ASSOCIATION_KEY] = operation.association()
    _application_check(operation)
    with _oauth_state_lock():
        payload = _read_states()
        _prune_expired(payload)
        payload["states"][state] = record
        _write_states(payload)
    _application_check(operation)

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
    result = {
        "provider": provider.id,
        "authorizationUrl": f"{provider.authorization_url}?{urllib.parse.urlencode(query)}",
        "state": state,
        "expiresAtEpoch": expires_at,
        "redirectUri": provider.redirect_uri,
        "scopes": requested_scopes,
    }
    if setup_session_value is not None:
        result["setupSessionId"] = setup_session_value
    _application_check(operation)
    return result


def consume_state(
    *, provider_id: str, state: str, browser_nonce: str
) -> dict[str, Any]:
    provider = provider_for(provider_id)
    if not isinstance(state, str) or _OAUTH_STATE_RE.fullmatch(state) is None:
        raise OAuthError("OAuth state is malformed")
    if (
        not isinstance(browser_nonce, str)
        or _OAUTH_BROWSER_NONCE_RE.fullmatch(browser_nonce) is None
    ):
        raise OAuthError("OAuth browser binding is missing or malformed")
    expected_browser_hash = (
        "sha256:" + hashlib.sha256(browser_nonce.encode("ascii")).hexdigest()
    )
    with _oauth_state_lock():
        payload = _read_states()
        _prune_expired(payload)
        record = payload["states"].get(state)
        if not isinstance(record, dict):
            _write_states(payload)
            raise OAuthError("OAuth state is unknown or expired")
        if record.get("provider") != provider.id:
            raise OAuthError("OAuth state provider mismatch")
        if int(record.get("expires_at_epoch", 0)) <= _now():
            payload["states"].pop(state, None)
            _write_states(payload)
            raise OAuthError("OAuth state expired")
        stored_browser_hash = record.get("browser_nonce_sha256")
        if not isinstance(stored_browser_hash, str) or not hmac.compare_digest(
            stored_browser_hash,
            expected_browser_hash,
        ):
            raise OAuthError("OAuth browser binding mismatch")
        try:
            _stored_setup_session_id(record)
        except OAuthError:
            payload["states"].pop(state, None)
            _write_states(payload)
            raise
        payload["states"].pop(state, None)
        _write_states(payload)
    return record


def _token_request_headers(provider: OAuthProvider) -> dict[str, str]:
    application_owner.require_parent_material(provider.id)
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    if provider.token_auth == "basic":
        raw = f"{provider.client_id}:{provider.client_secret}".encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    return headers


def _token_request_body(
    provider: OAuthProvider, record: dict[str, Any], code: str
) -> dict[str, str]:
    application_owner.require_parent_material(provider.id)
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


def _refresh_token_request_body(
    provider: OAuthProvider, refresh_token: str
) -> dict[str, str]:
    application_owner.require_parent_material(provider.id)
    body = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    if provider.token_auth != "basic":
        body["client_id"] = provider.client_id
    if provider.token_auth == "client_secret_post" and provider.client_secret:
        body["client_secret"] = provider.client_secret
    return body


def _post_token_request(
    provider: OAuthProvider, body: dict[str, str], headers: dict[str, str], *, operation=None
) -> dict[str, Any]:
    application_owner.require_parent_material(provider.id)
    encoded = urllib.parse.urlencode(body).encode("utf-8")
    request = urllib.request.Request(
        provider.token_url, data=encoded, headers=headers, method="POST"
    )
    try:
        _application_check(operation)
        response = request_bytes(
            request,
            timeout=20 if operation is None else operation.timeout(),
            max_bytes=MAX_OAUTH_TOKEN_RESPONSE_BYTES,
            require_https=True,
        )
        payload = json.loads(response.body.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise OAuthError(f"OAuth token exchange failed: HTTP {exc.code}") from exc
    except (
        HttpClientError,
        urllib.error.URLError,
        TimeoutError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise OAuthError(
            f"OAuth token exchange failed with an uncertain provider outcome: {exc}",
            issuance_uncertain=True,
        ) from exc
    if not isinstance(payload, dict):
        raise OAuthError(
            "OAuth token endpoint returned a non-object response with an uncertain issuance outcome",
            issuance_uncertain=True,
        )
    return payload


def _fetch_provider_identity(
    provider: OAuthProvider, access_token: str, *, operation=None
) -> dict[str, Any]:
    request = urllib.request.Request(
        provider.identity_url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {access_token}",
        },
        method="GET",
    )
    try:
        _application_check(operation)
        response = request_bytes(
            request,
            timeout=20 if operation is None else operation.timeout(),
            max_bytes=64 * 1024,
            require_https=True,
        )
        payload = json.loads(response.body.decode("utf-8"))
        _application_check(operation)
    except urllib.error.HTTPError as exc:
        raise OAuthError(
            f"OAuth account identity lookup failed: HTTP {exc.code}"
        ) from exc
    except (
        HttpClientError,
        urllib.error.URLError,
        TimeoutError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise OAuthError(f"OAuth account identity lookup failed: {exc}") from exc
    if not isinstance(payload, dict):
        raise OAuthError(
            "OAuth account identity endpoint returned a non-object response"
        )

    if provider.id == "google":
        subject = payload.get("sub")
        if not isinstance(subject, str) or not subject:
            raise OAuthError(
                "Google account identity response is missing or has malformed sub"
            )
        email = payload.get("email")
        email_verified = (
            isinstance(email, str)
            and bool(email)
            and payload.get("email_verified") is True
        )
        return {
            "provider_subject": subject,
            "provider_account": email if email_verified else subject,
            "provider_identity_verified": True,
            "provider_email_verified": email_verified,
        }

    data = payload.get("data")
    if not isinstance(data, dict):
        raise OAuthError("X account identity response is missing data")
    subject = data.get("id")
    username = data.get("username")
    if (
        not isinstance(subject, str)
        or not subject
        or not isinstance(username, str)
        or not username
    ):
        raise OAuthError("X account identity response is missing id or username")
    return {
        "provider_subject": subject,
        "provider_account": "@" + username.lstrip("@"),
        "provider_identity_verified": True,
        "provider_profile_verified": data.get("verified") is True,
    }


def exchange_authorization_code(
    *,
    provider_id: str,
    code: str,
    state: str,
    browser_nonce: str,
) -> dict[str, Any]:
    provider = provider_for(provider_id)
    if not provider.configured:
        raise OAuthError(f"{provider.display_name} OAuth is not configured")
    _require_application_lifecycle(_application_begin(provider))
    if (
        not isinstance(code, str)
        or not code
        or len(code.encode("utf-8")) > MAX_OAUTH_CODE_BYTES
    ):
        raise OAuthError("OAuth authorization code is empty or too large")
    record = consume_state(
        provider_id=provider.id, state=state, browser_nonce=browser_nonce
    )
    # The browser/state check is consumed first. The durable catalog claim then
    # precedes cleanup reservation and every provider request; generic flows
    # retain their original owner when the operator profile is absent.
    from serverware import operator_catalog_oauth
    try:
        catalog_claim = operator_catalog_oauth.claim_consumed_state(record, state)
    except Exception as exc:
        raise OAuthError("Operator Google consent is unavailable or changed") from exc
    operation = _application_begin(provider, record.get(application_owner.ASSOCIATION_KEY), bound=True)
    if operation is not None and record.get("redirect_uri") != provider.redirect_uri:
        raise OAuthError("OAuth state redirect no longer matches the enrolled application")
    actor_id = str(record.get("actor_id") or "oauth-callback")
    try:
        if catalog_claim is not None:
            from serverware import operator_google_cleanup_store
            revocation_work_id = operator_google_cleanup_store.reserve_initial(
                intent_id=catalog_claim["id"], actor_id=actor_id)
        else:
            revocation_work_id = db.reserve_oauth_revocation_work(
                provider_id=provider.id, actor_id=actor_id, source="authorization_code_exchange")
    except (db.ManagedOAuthCredentialError, db.MetadataStoreError, ValueError) as exc:
        if catalog_claim is not None:
            operator_catalog_oauth.fail_state(provider.id, state, "exchange_failed")
        raise OAuthError(
            "OAuth token exchange is unavailable while revocation capacity is exhausted",
            setup_session_id=_stored_setup_session_id(record),
            actor_id=actor_id,
        ) from exc

    material_attached = False
    try:
        db.mark_oauth_exchange_started(revocation_work_id)
        token_response = _post_token_request(
            provider,
            _token_request_body(provider, record, code),
            _token_request_headers(provider),
            operation=operation,
        )
        revocable_secret = {
            key: value
            for key, value in {
                "access_token": token_response.get("access_token"),
                "refresh_token": token_response.get("refresh_token"),
                "token_type": token_response.get("token_type") or "Bearer",
            }.items()
            if isinstance(value, str) and value
        }
        if operation is not None:
            # Retain issued material before a post-contact deadline check can fail.
            revocable_secret[application_owner.ASSOCIATION_KEY] = record[application_owner.ASSOCIATION_KEY]
        if "access_token" in revocable_secret or "refresh_token" in revocable_secret:
            revocable_secret_json = json.dumps(
                revocable_secret,
                separators=(",", ":"),
                sort_keys=True,
            )
            try:
                db.attach_oauth_revocation_material(
                    revocation_work_id,
                    secret=revocable_secret_json,
                )
            except Exception as retention_exc:
                if catalog_claim is not None:
                    raise OAuthError("Operator Google issued material retention is uncertain",
                        issuance_uncertain=True) from retention_exc
                try:
                    revoke_oauth_token(
                        provider_id=provider.id,
                        token_secret=revocable_secret,
                    )
                except OAuthError as revocation_exc:
                    try:
                        db.attach_oauth_revocation_material(
                            revocation_work_id,
                            secret=revocable_secret_json,
                        )
                        material_attached = True
                    except Exception as retry_exc:
                        raise OAuthError(
                            "issued OAuth material could neither be retained nor revoked"
                        ) from retry_exc
                    raise OAuthError(
                        "issued OAuth material was retained after immediate revocation failed"
                    ) from revocation_exc
                else:
                    db.complete_oauth_revocation_work(revocation_work_id)
                    raise OAuthError(
                        "issued OAuth material was revoked because durable retention failed"
                    ) from retention_exc
            material_attached = True

        _application_check(operation)

        access_token = token_response.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise OAuthError("OAuth token endpoint did not return access_token")
        if len(access_token.encode("utf-8")) > MAX_OAUTH_REFRESH_TOKEN_BYTES:
            raise OAuthError("OAuth token endpoint returned an oversized access token")
        refresh_token = token_response.get("refresh_token")
        if not isinstance(refresh_token, str) or not refresh_token:
            raise OAuthError(
                "OAuth token endpoint did not return a refresh token; reconnect with offline access"
            )
        if len(refresh_token.encode("utf-8")) > MAX_OAUTH_REFRESH_TOKEN_BYTES:
            raise OAuthError("OAuth token endpoint returned an oversized refresh token")
        if "token_type" not in token_response:
            raise OAuthError("OAuth token endpoint did not return a token type")
        token_type = token_response["token_type"]
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise OAuthError("OAuth token endpoint returned an unsupported token type")
        provider_identity = _fetch_provider_identity(provider, access_token, operation=operation)
        if catalog_claim is not None:
            operator_google_cleanup_store.bind_identity(revocation_work_id, {
                "oauth": True, "provider": "google.oauth2", "provider_id": "google",
                "oauth_client_id": provider.client_id, **provider_identity})
        now = _now()
        expires_in = token_response.get("expires_in")
        if (
            not isinstance(expires_in, (int, float))
            or isinstance(expires_in, bool)
            or expires_in <= 0
            or expires_in > MAX_OAUTH_TOKEN_LIFETIME_SECONDS
        ):
            raise OAuthError(
                "OAuth token endpoint returned an invalid access-token lifetime"
            )
        expires_at_epoch_ms = int((now + int(expires_in)) * 1000)
        refresh_token_expires_at_epoch_ms = None
        refresh_token_expires_in = token_response.get("refresh_token_expires_in")
        if refresh_token_expires_in is not None and (
            not isinstance(refresh_token_expires_in, (int, float))
            or isinstance(refresh_token_expires_in, bool)
            or refresh_token_expires_in <= 0
            or refresh_token_expires_in > MAX_OAUTH_TOKEN_LIFETIME_SECONDS
        ):
            raise OAuthError(
                "OAuth token endpoint returned an invalid refresh-token lifetime"
            )
        if refresh_token_expires_in is not None:
            refresh_token_expires_at_epoch_ms = int(
                (now + int(refresh_token_expires_in)) * 1000
            )
        if "scope" in token_response:
            response_scope = token_response["scope"]
            if not isinstance(response_scope, str) or not response_scope:
                raise OAuthError("OAuth token endpoint returned an invalid scope")
            scope_string = response_scope
        else:
            if catalog_claim is not None:
                raise OAuthError("Operator Google token response omitted granted scopes")
            if not provider.token_response_scope_optional:
                raise OAuthError("OAuth token endpoint omitted its required scope")
            scope_string = " ".join(record.get("scopes") or [])
        scopes = [scope for scope in scope_string.split(" ") if scope]
        if catalog_claim is not None:
            # Retain scope_string in encrypted token storage as received.
            scopes = operator_catalog_oauth.canonical_granted_scopes(scope_string)
        requested_scopes = {
            scope
            for scope in record.get("scopes") or []
            if isinstance(scope, str) and scope
        }
        if not scopes or not set(scopes).issubset(requested_scopes):
            raise OAuthError(
                "OAuth token endpoint expanded or omitted the requested scope binding"
            )
        token_secret = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "scope": scope_string,
            "expires_at_epoch_ms": expires_at_epoch_ms,
            "refresh_token_expires_at_epoch_ms": refresh_token_expires_at_epoch_ms,
        }
        token_secret = {
            key: value for key, value in token_secret.items() if value not in (None, "")
        }
        if operation is not None:
            token_secret[application_owner.ASSOCIATION_KEY] = operation.association()
        secret = json.dumps(token_secret, separators=(",", ":"), sort_keys=True)
        db.attach_oauth_revocation_material(
            revocation_work_id,
            secret=secret,
        )
        material_attached = True
        metadata = {
            **(record.get("metadata") or {}),
            "oauth": True,
            "refreshable": True,
            "provider": provider.metadata_provider,
            "provider_id": provider.id,
            "scopes": scopes,
            "token_type": token_secret.get("token_type", "Bearer"),
            "expires_at_epoch_ms": expires_at_epoch_ms,
            "refresh_token_expires_at_epoch_ms": refresh_token_expires_at_epoch_ms,
            "created_by": record.get("actor_id"),
            "injection_field": "access_token",
            **provider_identity,
        }
        if provider.id == "x":
            metadata["x_app_id"] = provider.client_id
        elif provider.id == "google":
            metadata["oauth_client_id"] = provider.client_id
        if operation is not None:
            metadata[application_owner.ASSOCIATION_KEY] = operation.association()
        result = {
            "name": str(
                record.get("credential_name")
                or f"{provider.display_name} OAuth credential"
            ),
            "kind": "oauth2",
            "secret": secret,
            "metadata": {
                key: value for key, value in metadata.items() if value is not None
            },
            "provider": provider.id,
            "scopes": scopes,
            "expiresAtEpochMs": expires_at_epoch_ms,
            "createdBy": record.get("actor_id"),
            "controlPlaneMfa": record.get("control_plane_mfa"),
            "controlPlaneApproval": record.get("control_plane_approval"),
            "reconnect": record.get("reconnect"),
            "providerAccount": provider_identity["provider_account"],
            "providerSubject": provider_identity["provider_subject"],
            "revocationWorkId": revocation_work_id,
        }
        setup_session_id = _stored_setup_session_id(record)
        if setup_session_id is not None:
            result["setupSessionId"] = setup_session_id
        if operation is not None:
            result["_application_operation"] = operation
        if catalog_claim is not None:
            result["_operator_catalog_intent"] = catalog_claim
            result["_operator_google_work"] = revocation_work_id
        _application_check(operation)
        return result
    except Exception as exc:
        if catalog_claim is not None:
            from serverware import operator_google_cleanup
            outcome = (operator_google_cleanup.fence(revocation_work_id)
                if material_attached else operator_google_cleanup.retain_uncertain(
                    revocation_work_id, material_attached=False))
            if outcome.status == "deferred":
                # Known-family failure is recorded in the fence transaction.
                # An unfenced failure may mark consent unusable, but this
                # metadata-only disposition never grants cleanup eligibility.
                operator_catalog_oauth.fail_state(provider.id, state, "exchange_failed")
                if material_attached:
                    operator_google_cleanup.retain_uncertain(revocation_work_id, material_attached=True)
            failure = OAuthError("Operator Google exchange failed; inspect retained cleanup status",
                actor_id=actor_id, issuance_uncertain=not material_attached)
            failure.operator_google_outcome = outcome
            raise failure from exc
        if material_attached:
            try:
                db.mark_oauth_revocation_work_pending(
                    revocation_work_id,
                    error=str(exc)[:500] or type(exc).__name__,
                )
            except (db.ManagedOAuthCredentialError, db.MetadataStoreError, ValueError):
                # Held work automatically becomes due if callback processing cannot update it.
                pass
        elif isinstance(exc, OAuthError) and exc.issuance_uncertain:
            try:
                db.mark_oauth_issuance_uncertain(
                    revocation_work_id,
                    error=str(exc)[:500] or type(exc).__name__,
                )
            except (db.ManagedOAuthCredentialError, db.MetadataStoreError, ValueError):
                # An in-flight marker is retained and ages into issuance-uncertain.
                pass
        else:
            db.complete_oauth_revocation_work(revocation_work_id)
        if isinstance(exc, OAuthError):
            exc.setup_session_id = _stored_setup_session_id(record)
            exc.actor_id = actor_id
            raise
        if isinstance(
            exc, (db.ManagedOAuthCredentialError, db.MetadataStoreError, ValueError)
        ):
            raise OAuthError(
                str(exc),
                setup_session_id=_stored_setup_session_id(record),
                actor_id=actor_id,
            ) from exc
        raise


def refresh_access_token(
    *,
    provider_id: str,
    token_secret: dict[str, Any],
    metadata: dict[str, Any],
    now_epoch: int | None = None,
) -> dict[str, Any]:
    provider = provider_for(provider_id)
    if not provider.configured:
        raise OAuthError(f"{provider.display_name} OAuth is not configured")
    if not isinstance(token_secret, dict) or not isinstance(metadata, dict):
        raise OAuthError("OAuth credential is malformed")
    operation = require_application_metadata(metadata)
    _require_application_lifecycle(operation)
    from serverware import operator_catalog_oauth
    try:
        catalog_profile = operator_catalog_oauth.profile_for_refresh(metadata)
    except Exception as exc:
        raise OAuthError("Operator Google refresh account binding refused") from exc
    if token_secret.get(application_owner.ASSOCIATION_KEY) != metadata.get(application_owner.ASSOCIATION_KEY):
        raise OAuthError("OAuth token and metadata application ownership differ")
    refresh_token = token_secret.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token:
        raise OAuthError("OAuth credential has no refresh token; reconnect the account")
    if len(refresh_token.encode("utf-8")) > MAX_OAUTH_REFRESH_TOKEN_BYTES:
        raise OAuthError("OAuth refresh token is too large")
    existing_token_type = token_secret.get("token_type")
    if (
        not isinstance(existing_token_type, str)
        or existing_token_type.lower() != "bearer"
    ):
        raise OAuthError("OAuth credential has an unsupported token type")

    now = _now() if now_epoch is None else int(now_epoch)
    refresh_expires_at = token_secret.get("refresh_token_expires_at_epoch_ms")
    if refresh_expires_at is not None:
        if not isinstance(refresh_expires_at, int) or isinstance(
            refresh_expires_at, bool
        ):
            raise OAuthError("OAuth refresh-token expiry is malformed")
        if refresh_expires_at <= now * 1000:
            raise OAuthError("OAuth refresh token expired; reconnect the account")

    existing_scope = str(token_secret.get("scope") or "")
    existing_scopes = {
        scope
        for scope in (metadata.get("scopes") or existing_scope.split(" "))
        if isinstance(scope, str) and scope
    }
    if not existing_scopes:
        raise OAuthError("OAuth credential has no bound scopes")

    actor_id = str(metadata.get("created_by") or "oauth-refresh")
    try:
        if catalog_profile is not None:
            from serverware import operator_google_cleanup_store
            revocation_work_id = operator_google_cleanup_store.reserve_refresh(metadata=metadata, actor_id=actor_id)
        else:
            revocation_work_id = db.reserve_oauth_revocation_work(
                provider_id=provider.id, actor_id=actor_id, source="refresh_token_exchange")
    except (db.ManagedOAuthCredentialError, db.MetadataStoreError, ValueError) as exc:
        raise OAuthError(
            "OAuth refresh is unavailable while revocation capacity is exhausted"
        ) from exc

    from serverware.operator_google_token_response import (
        RejectedRefresh, UncertainRefreshResponse, request_refresh,
    )

    material_attached = False
    try:
        db.mark_oauth_exchange_started(revocation_work_id)
        reject_response = False
        if catalog_profile is None:
            token_response = _post_token_request(
                provider,
                _refresh_token_request_body(provider, refresh_token),
                _token_request_headers(provider),
                operation=operation,
            )
        else:
            # Only the admitted operator profile may classify a definite
            # refresh rejection. Native/legacy exchange contracts are unchanged.
            application_owner.require_parent_material(provider.id)
            _application_check(operation)
            try:
                token_response = request_refresh(
                    provider, _refresh_token_request_body(provider, refresh_token),
                    _token_request_headers(provider), work_id=revocation_work_id,
                    profile=catalog_profile, request=request_bytes,
                )
            except UncertainRefreshResponse as response_error:
                if not isinstance(response_error.payload, dict):
                    raise OAuthError("Operator Google refresh response is uncertain",
                        issuance_uncertain=True) from response_error
                # A contradictory error response can still contain issued
                # tokens. Retain them before refusing adoption, just as for a
                # malformed success response; never call this no-issuance.
                token_response = response_error.payload
                reject_response = True
        issued_secret = {
            key: value
            for key, value in {
                "access_token": token_response.get("access_token"),
                "refresh_token": token_response.get("refresh_token"),
                "token_type": token_response.get("token_type") or "Bearer",
            }.items()
            if isinstance(value, str) and value
        }
        if operation is not None:
            issued_secret[application_owner.ASSOCIATION_KEY] = metadata[application_owner.ASSOCIATION_KEY]
        issued_secret_json = json.dumps(
            issued_secret, separators=(",", ":"), sort_keys=True
        )
        if "access_token" in issued_secret or "refresh_token" in issued_secret:
            try:
                db.attach_oauth_revocation_material(
                    revocation_work_id,
                    secret=issued_secret_json,
                )
            except Exception as retention_exc:
                if catalog_profile is not None:
                    raise OAuthError("Operator Google refresh material retention is uncertain",
                        issuance_uncertain=True) from retention_exc
                try:
                    revoke_oauth_token(
                        provider_id=provider.id,
                        token_secret=issued_secret,
                    )
                except OAuthError as revocation_exc:
                    try:
                        db.attach_oauth_revocation_material(
                            revocation_work_id,
                            secret=issued_secret_json,
                        )
                        material_attached = True
                    except Exception as retry_exc:
                        raise OAuthError(
                            "issued OAuth refresh material could neither be retained nor revoked"
                        ) from retry_exc
                    raise OAuthError(
                        "issued OAuth refresh material was retained after immediate revocation failed"
                    ) from revocation_exc
                else:
                    db.complete_oauth_revocation_work(revocation_work_id)
                    raise OAuthError(
                        "issued OAuth refresh material was revoked because durable retention failed"
                    ) from retention_exc
            material_attached = True

        _application_check(operation)
        if reject_response:
            raise OAuthError("Operator Google refresh response is ambiguous",
                issuance_uncertain=not material_attached)

        access_token = token_response.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise OAuthError("OAuth refresh response did not return access_token")
        if "token_type" in token_response:
            token_type = token_response["token_type"]
        else:
            token_type = existing_token_type
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise OAuthError(
                "OAuth refresh response returned an unsupported token type"
            )
        expires_in = token_response.get("expires_in")
        if (
            not isinstance(expires_in, (int, float))
            or isinstance(expires_in, bool)
            or expires_in <= 0
            or expires_in > MAX_OAUTH_TOKEN_LIFETIME_SECONDS
        ):
            raise OAuthError(
                "OAuth refresh response returned an invalid access-token lifetime"
            )
        expires_at_epoch_ms = int((now + int(expires_in)) * 1000)

        if "scope" in token_response:
            response_scope = token_response["scope"]
            if not isinstance(response_scope, str) or not response_scope:
                raise OAuthError("OAuth refresh response returned an invalid scope")
            scope_string = response_scope
        else:
            scope_string = existing_scope or " ".join(sorted(existing_scopes))
        refreshed_scopes = {scope for scope in scope_string.split(" ") if scope}
        if catalog_profile is not None:
            refreshed_scopes = set(operator_catalog_oauth.canonical_granted_scopes(scope_string))
        if refreshed_scopes != existing_scopes:
            raise OAuthError(
                "OAuth refresh response changed the credential scope binding"
            )

        rotated_refresh_token = token_response.get("refresh_token")
        if rotated_refresh_token is None:
            rotated_refresh_token = refresh_token
        if not isinstance(rotated_refresh_token, str) or not rotated_refresh_token:
            raise OAuthError("OAuth refresh response returned an invalid refresh token")
        if len(rotated_refresh_token.encode("utf-8")) > MAX_OAUTH_REFRESH_TOKEN_BYTES:
            raise OAuthError(
                "OAuth refresh response returned an oversized refresh token"
            )

        refresh_token_expires_at_epoch_ms = refresh_expires_at
        refresh_token_expires_in = token_response.get("refresh_token_expires_in")
        if refresh_token_expires_in is not None:
            if (
                not isinstance(refresh_token_expires_in, (int, float))
                or isinstance(refresh_token_expires_in, bool)
                or refresh_token_expires_in <= 0
                or refresh_token_expires_in > MAX_OAUTH_TOKEN_LIFETIME_SECONDS
            ):
                raise OAuthError(
                    "OAuth refresh response returned an invalid refresh-token lifetime"
                )
            refresh_token_expires_at_epoch_ms = int(
                (now + int(refresh_token_expires_in)) * 1000
            )

        refreshed_secret = {
            **token_secret,
            "access_token": access_token,
            "refresh_token": rotated_refresh_token,
            "token_type": "Bearer",
            "scope": scope_string,
            "expires_at_epoch_ms": expires_at_epoch_ms,
        }
        if refresh_token_expires_at_epoch_ms is not None:
            refreshed_secret["refresh_token_expires_at_epoch_ms"] = (
                refresh_token_expires_at_epoch_ms
            )
        refreshed_metadata = {
            **metadata,
            "refreshable": True,
            "scopes": sorted(refreshed_scopes),
            "token_type": "Bearer",
            "expires_at_epoch_ms": expires_at_epoch_ms,
        }
        if refresh_token_expires_at_epoch_ms is not None:
            refreshed_metadata["refresh_token_expires_at_epoch_ms"] = (
                refresh_token_expires_at_epoch_ms
            )
        result = {
            "secret": json.dumps(
                refreshed_secret, separators=(",", ":"), sort_keys=True
            ),
            "metadata": refreshed_metadata,
            "expiresAtEpochMs": expires_at_epoch_ms,
            "scopes": sorted(refreshed_scopes),
            "refreshTokenRotated": rotated_refresh_token != refresh_token,
            "revocationWorkId": revocation_work_id,
            "revocationSecret": issued_secret_json,
        }
        if operation is not None:
            result["_application_operation"] = operation
        if catalog_profile is not None:
            result["_operator_google_work"] = revocation_work_id
        _application_check(operation)
        return result
    except RejectedRefresh as exc:
        from serverware import operator_google_cleanup
        # This receipt proves only provider rejection of this one request.
        # Whether the local audit/empty-reservation retirement committed is a
        # separate result; neither outcome authorizes another token exchange.
        disposition = operator_google_cleanup.retire_definite_refresh_rejection(exc)
        failure = OAuthError("Google rejected the refresh request; inspect account status and audit logs",
            actor_id=actor_id, issuance_uncertain=False)
        failure.operator_refresh_rejection = disposition
        raise failure from exc
    except Exception as exc:
        if catalog_profile is not None:
            from serverware import operator_google_cleanup
            outcome = (operator_google_cleanup.fence(revocation_work_id, reason="refresh_failed")
                if material_attached else operator_google_cleanup.retain_uncertain(
                    revocation_work_id, material_attached=False))
            if outcome.status == "deferred" and material_attached:
                operator_google_cleanup.retain_uncertain(revocation_work_id, material_attached=True)
            failure = OAuthError("Operator Google refresh failed; inspect retained cleanup status",
                actor_id=actor_id, issuance_uncertain=not material_attached)
            failure.operator_google_outcome = outcome
            raise failure from exc
        if material_attached:
            try:
                db.mark_oauth_revocation_work_pending(
                    revocation_work_id,
                    error=str(exc)[:500] or type(exc).__name__,
                )
            except (db.ManagedOAuthCredentialError, db.MetadataStoreError, ValueError):
                pass
        elif isinstance(exc, OAuthError) and exc.issuance_uncertain:
            try:
                db.mark_oauth_issuance_uncertain(
                    revocation_work_id,
                    error=str(exc)[:500] or type(exc).__name__,
                )
            except (db.ManagedOAuthCredentialError, db.MetadataStoreError, ValueError):
                pass
        else:
            db.complete_oauth_revocation_work(revocation_work_id)
        if isinstance(exc, OAuthError):
            raise
        if isinstance(
            exc, (db.ManagedOAuthCredentialError, db.MetadataStoreError, ValueError)
        ):
            raise OAuthError(str(exc)) from exc
        raise


def revoke_oauth_token(
    *, provider_id: str, token_secret: dict[str, Any], _operator_cleanup_work_id: str | None = None
) -> dict[str, Any]:
    provider = provider_for(provider_id)
    if not provider.configured:
        raise OAuthError(f"{provider.display_name} OAuth is not configured")
    if not isinstance(token_secret, dict):
        raise OAuthError("OAuth credential is malformed")
    from serverware import operator_google_cleanup
    if (_operator_cleanup_work_id is not None
            or operator_google_cleanup.operator_context(provider.id, work_id=_operator_cleanup_work_id)):
        try:
            if provider.id != "google":
                raise ValueError("operator cleanup provider differs from its owner")
            operator_google_cleanup.require_provider_io_unlocked()
            operator_google_cleanup._store().require_permit(
                work_id=_operator_cleanup_work_id, secret=token_secret)
        except Exception as exc:
            raise OAuthError("Operator Google revocation requires a committed matching cleanup fence") from exc
    operation = _application_begin(provider, token_secret.get(application_owner.ASSOCIATION_KEY), bound=True)
    _require_application_lifecycle(operation)
    if provider.id == "x":
        token_requests: list[tuple[str, str]] = []
        for token_type_hint in ("access_token", "refresh_token"):
            if token_type_hint not in token_secret:
                continue
            token = token_secret[token_type_hint]
            if not isinstance(token, str) or not token:
                raise OAuthError(f"OAuth credential has an invalid {token_type_hint}")
            if len(token.encode("utf-8")) > MAX_OAUTH_REFRESH_TOKEN_BYTES:
                raise OAuthError("OAuth revocation token is too large")
            token_requests.append((token_type_hint, token))
    else:
        token = token_secret.get("refresh_token") or token_secret.get("access_token")
        token_type_hint = (
            "refresh_token" if token_secret.get("refresh_token") else "access_token"
        )
        if not isinstance(token, str) or not token:
            raise OAuthError("OAuth credential has no revocable token")
        if len(token.encode("utf-8")) > MAX_OAUTH_REFRESH_TOKEN_BYTES:
            raise OAuthError("OAuth revocation token is too large")
        token_requests = [(token_type_hint, token)]
    if not token_requests:
        raise OAuthError("OAuth credential has no revocable token")

    for token_type_hint, token in token_requests:
        body = {"token": token, "token_type_hint": token_type_hint}
        if provider.id == "x" and provider.token_auth != "basic":
            body["client_id"] = provider.client_id
        request = urllib.request.Request(
            provider.revocation_url,
            data=urllib.parse.urlencode(body).encode("utf-8"),
            headers=_token_request_headers(provider),
            method="POST",
        )
        try:
            _application_check(operation)
            response = request_bytes(
                request,
                timeout=20 if operation is None else operation.timeout(),
                max_bytes=64 * 1024,
                require_https=True,
            )
        except urllib.error.HTTPError as exc:
            raise OAuthError(f"OAuth token revocation failed: HTTP {exc.code}") from exc
        except (HttpClientError, urllib.error.URLError, TimeoutError, OSError) as exc:
            raise OAuthError(f"OAuth token revocation failed: {exc}") from exc
        if response.status < 200 or response.status >= 300:
            raise OAuthError(f"OAuth token revocation failed: HTTP {response.status}")
        _application_check(operation)

    token_type_hints = [token_type_hint for token_type_hint, _ in token_requests]
    return {
        "provider": provider.id,
        "revoked": True,
        "token_type_hint": token_type_hints[-1],
        "token_type_hints": token_type_hints,
    }
