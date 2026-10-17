"""Source-constructed enrolled refresh material, never a provider-authorship proof.

Only the retained client may contact after its definite protected claim. Parsing
issued tokens is for bounded retention; replacement normalization happens later.
"""
from __future__ import annotations

import base64
import json
import math
import time
import urllib.parse
import urllib.request

from catchplate import authority_oauth_refresh as profile
from catchplate import crypto, db, oauth
from catchplate import oauth_application_owner as applications
from catchplate.http_client import HttpDeadline, request_bytes

MAX_REPLY_BYTES = 96 * 1024
MAX_ORIGINAL_BYTES = 190 * 1024


def json_object(raw, maximum):
    profile.require(type(raw) is bytes and 1 <= len(raw) <= maximum)
    def pairs(values):
        result = {}
        for key, value in values:
            profile.require(key not in result)
            result[key] = value
        return result
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
        parse_constant=lambda _: profile.require(False))
    profile.require(type(value) is dict)
    return value


def _text(value, maximum):
    profile.require(type(value) is str and 1 <= len(value.encode("utf-8")) <= maximum)
    return value


def _epoch(value):
    profile.require(type(value) is int and 1 <= value <= 9_223_372_036_854_775)
    return value


def _scopes(value):
    profile.require(type(value) is str and value)
    items = value.split(" ")
    profile.require(1 <= len(items) <= 128 and len(set(items)) == len(items))
    for item in items:
        profile.require(item == item.strip() and not any(ord(char) < 33 or ord(char) == 127 for char in item))
        _text(item, 1024)
    return frozenset(items)


def current(row):
    """Read exact ciphertext originals; no SQL mutation or lifecycle helper."""
    profile.credential_original(row)
    profile.require(row["kind"] == "oauth2" and row["lifecycle_status"] == "active")
    metadata = json_object(row["metadata"].encode("utf-8"), 32 * 1024)
    db.validate_managed_oauth_account_identity(metadata)
    profile.require(metadata.get("oauth") is True and metadata.get("refreshable") is True)
    token = json_object(crypto.decrypt_secret_envelope(row).encode("utf-8"), MAX_ORIGINAL_BYTES)
    _text(token.get("access_token"), 64 * 1024)
    _text(token.get("refresh_token"), oauth.MAX_OAUTH_REFRESH_TOKEN_BYTES)
    profile.require(type(token.get("token_type")) is str and token["token_type"].lower() == "bearer"
        and token.get(applications.ASSOCIATION_KEY) == metadata.get(applications.ASSOCIATION_KEY))
    scopes = _scopes(token.get("scope"))
    profile.require(type(metadata.get("scopes")) is list and len(metadata["scopes"]) == len(scopes)
        and all(type(item) is str for item in metadata["scopes"]) and frozenset(metadata["scopes"]) == scopes
        and _epoch(token.get("expires_at_epoch_ms")) == _epoch(metadata.get("expires_at_epoch_ms")))
    refresh_expiry = token.get("refresh_token_expires_at_epoch_ms")
    profile.require(metadata.get("refresh_token_expires_at_epoch_ms") == refresh_expiry)
    if refresh_expiry is not None:
        _epoch(refresh_expiry)
    return token, metadata


def token_request(provider, token):
    refresh_token = _text(token.get("refresh_token"), oauth.MAX_OAUTH_REFRESH_TOKEN_BYTES)
    body = urllib.parse.urlencode(oauth._refresh_token_request_body(provider, refresh_token)).encode("utf-8")
    request = urllib.request.Request(provider.token_url, data=body,
        headers=oauth._token_request_headers(provider), method="POST")
    commitment = {"schema": "catchplate.oauthRefreshContact/v1", "url": provider.token_url,
        "method": "POST", "bodySha256": profile.sha256(body),
        "headersSha256": profile.sha256(profile.canonical(dict(request.header_items())))}
    return request, profile.sha256(profile.canonical(commitment))


def contact(request, operation, *, deadline_ns):
    operation.check()
    response = request_bytes(request, timeout=operation.timeout(), max_bytes=MAX_REPLY_BYTES,
        require_https=True, expected_statuses=tuple(range(200, 600)),
        deadline=HttpDeadline(deadline_ns / 1_000_000_000))
    received = time.time_ns()
    headers = [list(pair) for pair in response.raw_headers]
    profile.require(len(profile.canonical(headers)) <= 8 * 1024)
    original = profile.canonical({"status": response.status, "rawHeaders": headers,
        "bodyBase64url": base64.urlsafe_b64encode(response.body).rstrip(b"=").decode("ascii")})
    profile.require(len(original) <= MAX_ORIGINAL_BYTES)
    # No post-contact owner check here discards returned bytes. The same owner
    # must next attempt retention with its remaining original budget.
    return response, original, received


def issued_original(response, association):
    """Extract bounded token material only; this does not admit a replacement."""
    try:
        payload = json_object(response.body, MAX_REPLY_BYTES)
        value = {key: item for key, item in payload.items()
            if key in {"access_token", "refresh_token"} and type(item) is str
            and 1 <= len(item.encode("utf-8")) <= oauth.MAX_OAUTH_REFRESH_TOKEN_BYTES}
        if not value:
            return None
        value["token_type"] = "Bearer"
        value[applications.ASSOCIATION_KEY] = association
        original = profile.canonical(value)
        profile.require(len(original) <= MAX_ORIGINAL_BYTES)
        return original
    except (TypeError, ValueError, UnicodeError, OverflowError):
        return None


def replacement(response, received_at_ns, provider, token, metadata):
    """Normalize only after definite raw/issued retention, using receipt time."""
    profile.require(200 <= response.status < 300 and type(received_at_ns) is int)
    payload = json_object(response.body, MAX_REPLY_BYTES)
    access = _text(payload.get("access_token"), 64 * 1024)
    token_type = payload.get("token_type", token["token_type"])
    profile.require(type(token_type) is str and token_type.lower() == "bearer")
    def expiry(key):
        value = payload.get(key)
        profile.require(type(value) in (int, float) and math.isfinite(value)
            and 1 <= value <= oauth.MAX_OAUTH_TOKEN_LIFETIME_SECONDS)
        return _epoch(received_at_ns // 1_000_000 + int(value) * 1000)
    expires = expiry("expires_in")
    scope = payload.get("scope", token["scope"])
    profile.require(_scopes(scope) == _scopes(token["scope"]))
    refresh = _text(payload.get("refresh_token", token["refresh_token"]), oauth.MAX_OAUTH_REFRESH_TOKEN_BYTES)
    refresh_expires = token.get("refresh_token_expires_at_epoch_ms")
    if "refresh_token_expires_in" in payload:
        refresh_expires = expiry("refresh_token_expires_in")
    value = {**token, "access_token": access, "refresh_token": refresh,
        "token_type": "Bearer", "scope": scope, "expires_at_epoch_ms": expires}
    updated = {**metadata, "refreshable": True, "token_type": "Bearer",
        "scopes": sorted(_scopes(scope)), "expires_at_epoch_ms": expires}
    if refresh_expires is not None:
        value["refresh_token_expires_at_epoch_ms"] = refresh_expires
        updated["refresh_token_expires_at_epoch_ms"] = refresh_expires
    profile.require(db.validate_managed_oauth_account_identity(updated)
        == db.validate_managed_oauth_account_identity(metadata)
        and updated[applications.ASSOCIATION_KEY] == metadata[applications.ASSOCIATION_KEY]
        and len(profile.canonical(updated)) <= 32 * 1024)
    original = profile.canonical(value)
    profile.require(len(original) <= MAX_ORIGINAL_BYTES)
    retired = None
    profile.require(provider.id in {"google", "x"})
    if provider.id == "x":
        changed = {key: token[key] for key in ("access_token", "refresh_token") if token[key] != value[key]}
        if changed:
            retired = profile.canonical({**changed, "token_type": "Bearer",
                applications.ASSOCIATION_KEY: metadata[applications.ASSOCIATION_KEY]})
            profile.require(len(retired) <= MAX_ORIGINAL_BYTES)
    # Google grant-family revocation is never a superseded-token operation.
    return original, updated, retired
