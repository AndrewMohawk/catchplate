"""One-shot, permission-preserving reauthorization of an active Google account.

Browser consent does not freeze refresh. The consumed callback must claim the
exact reviewed generation before contacting Google; issued material then stays
in non-revoking encrypted custody until atomic same-account adoption. This is
not initial enrollment, generic reconnect, grant cleanup, or native OAuth.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Annotated

from pydantic import Field, field_validator

from serverware import db, oauth
from serverware import operator_google_reauthorization_store as durable
from serverware.operator_catalog_inputs import RevisionInput, _identifier
from serverware.operator_publication import exclusive

_MARKER = "operator_google_reauthorization_id"
_JSON_MEDIA = re.compile(
    r'application/json(?:[ \t]*;[ \t]*charset[ \t]*=[ \t]*(?:utf-8|utf8|"utf-8"|"utf8"))?[ \t]*',
    re.IGNORECASE | re.ASCII)
_FAILURE = "Google reauthorization did not complete; inspect its saved status; do not retry the callback"


class ReauthorizeInput(RevisionInput):
    operation_id: str = Field(min_length=36, max_length=36)
    credential_id: str = Field(min_length=36, max_length=36)
    expected_credential_generation: int = Field(ge=1, lt=9_007_199_254_740_991)
    affected_rule_ids: list[Annotated[str, Field(min_length=36, max_length=36)]] = Field(max_length=64)
    _ids = field_validator("operation_id", "credential_id")(_identifier)

    @field_validator("affected_rule_ids")
    @classmethod
    def exact_rules(cls, values):
        if values != sorted(set(values)):
            raise ValueError("affected rules must be unique and sorted")
        for value in values:
            _identifier(value)
        return values


def _admit():
    from serverware import operator_demo_store
    operator_demo_store._require()
    from serverware.operator_catalog_oauth_profile import require_profile
    return require_profile()


def _write(function, *args, **kwargs):
    # Never called around HTTP. Unknown commits are observed, not repeated.
    with exclusive():
        with db.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            result = function(conn, *args, **kwargs)
            conn.commit()
            return result


def review(credential_id, actor_id):
    _admit()
    with db.connect() as conn:
        conn.execute("BEGIN")
        return durable.review(conn, credential_id, actor_id)


def status(operation_id, actor_id):
    _admit()
    with db.connect() as conn:
        conn.execute("BEGIN")
        operation = durable.get(conn, operation_id, actor_id)
        if operation is None:
            return None
        if operation["status"] == "adopted":
            operation = durable.observe_adoption(conn, operation_id, actor_id)
        return durable.public(operation)


def _failure(operation_id, actor_id, *, reason, change=True):
    # No generic cleanup fallback. Failure to record a disposition leaves the
    # durable reservation/barrier in place and never authorizes another exchange.
    if change:
        try:
            _write(durable.fail, operation_id, actor_id, reason=reason)
        except Exception:
            pass
    try:
        operation = status(operation_id, actor_id)
    except Exception:
        operation = None
    if operation is None:
        # A locator is not an adoption receipt. Preserve owned callback dispatch
        # even when storage cannot currently produce a verified public status.
        operation = {"operation_id": operation_id, "status": "unknown"}
    return oauth.OAuthError(_FAILURE, actor_id=actor_id, issuance_uncertain=True,
        operator_google_reauthorization=operation)


def start(payload, actor_id, browser_nonce):
    profile = _admit()
    # Revalidate even internal callers; no permissive DTO or POST replay.
    payload = ReauthorizeInput.model_validate(payload.model_dump() if isinstance(payload, ReauthorizeInput) else payload)
    from serverware import operator_google_managed_readiness as readiness
    # No publication or SQLite ownership may cross the gate observation.
    managed_readiness = readiness.capture_start()
    operation = _write(durable.begin, payload, actor_id, managed_readiness=managed_readiness)
    identifier = payload.operation_id
    started = None
    try:
        public = durable.public(operation)
        started = oauth.create_authorization_url(provider_id="google",
            credential_name=public["name"], scopes=list(profile.scopes), metadata={},
            actor_id=actor_id, browser_nonce=browser_nonce,
            operator_google_reauthorization_id=identifier,
            operator_google_reauthorization_expires_at_epoch=operation["binding"]["expires_at_epoch"])
        if (started["provider"] != "google" or started["scopes"] != list(profile.scopes)
                or started["redirectUri"] != profile.redirect_uri
                or oauth._OAUTH_STATE_RE.fullmatch(started["state"]) is None):
            raise ValueError("Google reauthorization state refused")
        digest = "sha256:" + hashlib.sha256(started["state"].encode("ascii")).hexdigest()
        _write(durable.bind_started, identifier, actor_id, state_digest=digest,
            expires_at_epoch=started["expiresAtEpoch"])
        observed = status(identifier, actor_id)
        if observed is None or observed["status"] != "awaiting_consent":
            raise ValueError("Google reauthorization start not observed")
        return {**started, "operatorGoogleReauthorization": observed}
    except Exception:
        if started is not None:
            try:
                oauth.consume_state(provider_id="google", state=started["state"], browser_nonce=browser_nonce)
            except Exception:
                pass
        raise _failure(identifier, actor_id, reason="start_failed") from None


def _bound(conn, record, state):
    profile = _admit()
    identifier, actor_id = record.get(_MARKER), record.get("actor_id")
    operation = durable.get(conn, identifier, actor_id)
    if operation is None:
        raise ValueError("Google reauthorization state refused")
    binding = operation["binding"]
    digest = "sha256:" + hashlib.sha256(state.encode("ascii")).hexdigest()
    if (operation["status"] != "awaiting_consent" or not isinstance(operation["state_digest"], str)
            or not hmac.compare_digest(operation["state_digest"], digest)
            or record.get("provider") != "google" or record.get("credential_name") != binding["name"]
            or record.get("scopes") != binding["scopes"] or record.get("scopes") != list(profile.scopes)
            or record.get("redirect_uri") != profile.redirect_uri
            or binding["profile_binding_digest"] != profile.binding_digest
            or binding["oauth_client_id"] != profile.client_id
            or record.get("metadata") != {} or record.get("reconnect") is not None
            or any(key in record for key in ("operator_catalog_intent_id", "setup_session_id",
                oauth.application_owner.ASSOCIATION_KEY))):
        raise ValueError("Google reauthorization state refused")
    return operation, digest


def deny_consumed(record, state):
    # The caller already consumed browser/state. Denial cannot claim work or
    # touch credentials, assignments, initial enrollment, or provider endpoints.
    def deny(conn):
        operation, _ = _bound(conn, record, state)
        return durable.fail(conn, operation["operation_id"], operation["actor_id"], reason="consent_denied")
    return durable.public(_write(deny))


def _claim(record, state):
    def claim(conn):
        operation, digest = _bound(conn, record, state)
        return durable.claim(conn, operation["operation_id"], operation["actor_id"], state_digest=digest)
    return _write(claim)


def _capture(provider, record, code):
    """Capture bounded responses before MIME/status checks can discard tokens."""
    profile = _admit()
    if (provider.id != "google" or provider.client_id != profile.client_id
            or provider.redirect_uri != profile.redirect_uri
            or provider.token_url != "https://oauth2.googleapis.com/token"
            or provider.identity_url != "https://openidconnect.googleapis.com/v1/userinfo"
            or provider.token_auth != "client_secret_post"):
        raise ValueError("Google reauthorization provider refused")
    request = urllib.request.Request(provider.token_url,
        data=urllib.parse.urlencode(oauth._token_request_body(provider, record, code)).encode("utf-8"),
        headers=oauth._token_request_headers(provider), method="POST")
    try:
        # These statuses authorize capture, NOT success, adoption or retirement.
        response = oauth.request_bytes(request, timeout=20, max_bytes=oauth.MAX_OAUTH_TOKEN_RESPONSE_BYTES,
            require_https=True, expected_statuses=tuple(range(200, 600)))
    except urllib.error.HTTPError as error:
        error.close()  # Never read an unknown stream through an unbounded fallback.
        raise ValueError("Google reauthorization provider outcome is uncertain") from None
    raw = getattr(response, "body", None)
    if not isinstance(raw, bytes) or len(raw) > oauth.MAX_OAUTH_TOKEN_RESPONSE_BYTES:
        raise ValueError("Google reauthorization response refused")
    # A parsed token-bearing object reaches custody before stricter acceptance
    # checks. Malformed/non-object responses leave the in-flight work unresolved.
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Google reauthorization response refused")
    return response, payload


def _lifetime(value):
    return (type(value) in (int, float) and 0 < value <= oauth.MAX_OAUTH_TOKEN_LIFETIME_SECONDS
        and math.isfinite(value))


def _candidate(payload, now):
    # Non-raising projection: capture first, validate afterwards. This is the
    # sole encrypted material write, already containing eventual expiry fields.
    secret = {key: value for key in ("access_token", "refresh_token", "scope")
        if isinstance(value := payload.get(key), str) and value}
    secret["token_type"] = "Bearer"
    for source, target in (("expires_in", "expires_at_epoch_ms"),
            ("refresh_token_expires_in", "refresh_token_expires_at_epoch_ms")):
        if _lifetime(payload.get(source)):
            secret[target] = int((now + int(payload[source])) * 1000)
    return secret


def _validate_response(response, payload, secret, binding):
    from serverware.http_client import _strict_json_loads
    from serverware.operator_catalog_oauth import canonical_granted_scopes
    raw_headers = getattr(response, "raw_headers", ())
    if (not isinstance(raw_headers, (tuple, list)) or len(raw_headers) > 100
            or any(not isinstance(pair, (tuple, list)) or len(pair) != 2
                or not all(isinstance(value, str) for value in pair) for pair in raw_headers)):
        raise ValueError("Google reauthorization response refused")
    media = [value for key, value in raw_headers if key.lower() == "content-type"]
    if (type(response.status) is not int or response.status != 200 or len(media) != 1
            or len(media[0]) > 256 or _JSON_MEDIA.fullmatch(media[0]) is None
            or _strict_json_loads(response.body) != payload or "error" in payload):
        raise ValueError("Google reauthorization response refused")
    for key in ("access_token", "refresh_token"):
        if (key not in secret or len(secret[key].encode("utf-8")) > oauth.MAX_OAUTH_REFRESH_TOKEN_BYTES):
            raise ValueError("Google reauthorization token refused")
    if (not isinstance(payload.get("token_type"), str) or payload["token_type"].lower() != "bearer"
            or not _lifetime(payload.get("expires_in"))
            or payload.get("refresh_token_expires_in") is not None
                and not _lifetime(payload["refresh_token_expires_in"])
            or canonical_granted_scopes(payload.get("scope")) != binding["scopes"]):
        raise ValueError("Google reauthorization permissions or lifetime refused")


def _adopt(operation, actor_id, metadata):
    identifier = operation["operation_id"]
    expected_receipt = None
    try:
        with exclusive():
            with db.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                durable.stage_candidate(conn, identifier, actor_id, metadata=metadata)
                expected_receipt = durable.adopt(conn, identifier, actor_id)
                conn.commit()
    except Exception:
        # An ambiguous commit is read back once; never rerun token exchange or
        # adoption. A missing/mismatched durable receipt stays review-required.
        if expected_receipt is None:
            raise
        with db.connect() as conn:
            conn.execute("BEGIN")
            return durable.public(durable.observe_adoption(conn, identifier, actor_id,
                expected_receipt=expected_receipt))
    with db.connect() as conn:
        conn.execute("BEGIN")
        return durable.public(durable.observe_adoption(conn, identifier, actor_id,
            expected_receipt=expected_receipt))


def exchange_consumed(provider, record, code, state):
    identifier, actor_id = record.get(_MARKER), record.get("actor_id")
    claimed = False
    try:
        operation = _claim(record, state)
        claimed = True
        binding, work_id = operation["binding"], operation["work_id"]
        # claim committed the reservation and in-flight marker before this first
        # network operation. There is no SQLite transaction/publication lock here.
        response, payload = _capture(provider, record, code)
        secret = _candidate(payload, oauth._now())
        if "access_token" in secret or "refresh_token" in secret:
            db.attach_oauth_revocation_material(work_id,
                secret=json.dumps(secret, sort_keys=True, separators=(",", ":"), allow_nan=False))
        _validate_response(response, payload, secret, binding)
        identity = oauth._fetch_provider_identity(provider, secret["access_token"])
        if (identity.get("provider_identity_verified") is not True
                or identity.get("provider_subject") != binding["provider_subject"]
                or identity.get("provider_account") != binding["provider_account"]):
            raise ValueError("Google reauthorization account identity refused")
        # Preserve original created_by, oauth_intent_id and every other immutable
        # metadata field. This actor belongs to the operation/audit, not enrollment.
        metadata = dict(binding["original_metadata"])
        for key in ("expires_at_epoch_ms", "refresh_token_expires_at_epoch_ms"):
            metadata.pop(key, None)
            if key in secret:
                metadata[key] = secret[key]
        metadata["token_type"] = "Bearer"
        return {"_operator_google_reauthorization": _adopt(operation, actor_id, metadata)}
    except Exception:
        raise _failure(identifier, actor_id,
            reason="exchange_failed" if claimed else "state_changed") from None
