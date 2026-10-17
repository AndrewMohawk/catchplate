"""Actual enrolled provider exchange material; no provider-authorship verdict.

Only the retained cold client calls this module after its definite one-use claim.
No token, raw reply or private request is logged or returned to the browser.
"""
from __future__ import annotations

import base64
import json
import math
import time
import urllib.parse
import urllib.request

from catchplate import authority_oauth_exchange as profile
from catchplate import db, oauth
from catchplate.http_client import HttpDeadline, request_bytes

MAX_REPLY_BYTES = 96 * 1024
MAX_RAW_ORIGINAL = 190 * 1024


def _pairs(items):
    result = {}
    for key, value in items:
        profile.require(key not in result)
        result[key] = value
    return result


def token_request(provider, state, code):
    profile.require(type(code) is str and 1 <= len(code.encode("utf-8")) <= oauth.MAX_OAUTH_CODE_BYTES
        and state["redirectUri"] == provider.redirect_uri)
    body = oauth._token_request_body(provider,
        {"redirect_uri": state["redirectUri"], "code_verifier": state["codeVerifier"]}, code)
    headers = oauth._token_request_headers(provider)
    encoded = urllib.parse.urlencode(body).encode("utf-8")
    request = urllib.request.Request(provider.token_url, data=encoded, headers=headers, method="POST")
    commitment = {"schema": "catchplate.oauthExchangeContact/v1", "url": provider.token_url,
        "method": "POST", "bodySha256": profile.sha256(encoded),
        "headersSha256": profile.sha256(profile.canonical(dict(request.header_items())))}
    return request, profile.sha256(profile.canonical(commitment))


def contact(request, operation, *, deadline_ns):
    operation.check()
    # All final HTTP statuses are retained. A non-2xx reply is not a definite
    # no-issuance proof and never restores a consumed exchange claim.
    response = request_bytes(request, timeout=operation.timeout(), max_bytes=MAX_REPLY_BYTES,
        require_https=True, expected_statuses=tuple(range(200, 600)),
        deadline=HttpDeadline(deadline_ns / 1_000_000_000))
    raw_headers = [list(pair) for pair in response.raw_headers]
    profile.require(len(profile.canonical(raw_headers)) <= 8 * 1024)
    original = profile.canonical({"status": response.status, "rawHeaders": raw_headers,
        "bodyBase64url": base64.urlsafe_b64encode(response.body).rstrip(b"=").decode("ascii")})
    profile.require(len(original) <= MAX_RAW_ORIGINAL)
    # Do not discard returned bytes through a post-contact deadline check. The
    # caller must next attempt bounded retention under its original owner.
    return response, original


def _token_text(value):
    return type(value) is str and 1 <= len(value.encode("utf-8")) <= oauth.MAX_OAUTH_REFRESH_TOKEN_BYTES


def token_original(response, state):
    """Normalize once before retention; malformed material cannot be staged."""
    payload = None
    try:
        payload = json.loads(response.body.decode("utf-8"), object_pairs_hook=_pairs,
            parse_constant=lambda _: profile.require(False))
        profile.require(type(payload) is dict)
        access, refresh = payload.get("access_token"), payload.get("refresh_token")
        profile.require(200 <= response.status < 300 and _token_text(access) and _token_text(refresh)
            and type(payload.get("token_type")) is str and payload["token_type"].lower() == "bearer")
        now_ms = time.time_ns() // 1_000_000
        def expiry(name, required):
            value = payload.get(name)
            if value is None and not required:
                return None
            profile.require(type(value) in (int, float) and math.isfinite(value)
                and 0 < value <= oauth.MAX_OAUTH_TOKEN_LIFETIME_SECONDS)
            return now_ms + int(value) * 1000
        expires, refresh_expires = expiry("expires_in", True), expiry("refresh_token_expires_in", False)
        scope = payload.get("scope")
        if scope is None:
            provider = oauth.provider_for(state["providerId"])
            profile.require(provider.token_response_scope_optional)
            scope = " ".join(state["scopes"])
        profile.require(type(scope) is str and scope and all(part for part in scope.split(" ")))
        scopes = scope.split(" ")
        profile.require(len(scopes) == len(set(scopes)) and set(scopes) <= set(state["scopes"]))
        value = {"access_token": access, "refresh_token": refresh, "token_type": "Bearer", "scope": scope,
            "expires_at_epoch_ms": expires, "oauth_application_owner": state["oauth_application_owner"]}
        if refresh_expires is not None:
            value["refresh_token_expires_at_epoch_ms"] = refresh_expires
        original = profile.canonical(value)
        profile.require(len(original) <= MAX_RAW_ORIGINAL)
        return original, value, True
    except (TypeError, ValueError, KeyError, UnicodeError, OverflowError):
        # A bounded usable token can still be kept for later, separately
        # authorized revocation. This local marker is never sent as authority.
        if type(payload) is dict:
            value = {name: payload[name] for name in ("access_token", "refresh_token")
                if _token_text(payload.get(name))}
            if value:
                value.update(token_type="Bearer", oauth_application_owner=state["oauth_application_owner"])
                original = profile.canonical(value)
                if len(original) <= MAX_RAW_ORIGINAL:
                    return original, value, False
        return None, None, False


def review_after_retention(provider, state, token, operation):
    # Only the actual retained response's access token enters this fixed
    # configured identity endpoint. Its unsigned response is not O02 evidence.
    identity = oauth._fetch_provider_identity(provider, token["access_token"], operation=operation)
    scopes = sorted(token["scope"].split(" "))
    metadata = {**state["metadata"], "oauth": True, "refreshable": True,
        "provider": provider.metadata_provider, "provider_id": provider.id, "scopes": scopes,
        "token_type": "Bearer", "expires_at_epoch_ms": token["expires_at_epoch_ms"],
        "created_by": state["requesterId"], "injection_field": "access_token", **identity,
        "oauth_application_owner": state["oauth_application_owner"]}
    if "refresh_token_expires_at_epoch_ms" in token:
        metadata["refresh_token_expires_at_epoch_ms"] = token["refresh_token_expires_at_epoch_ms"]
    metadata["oauth_client_id" if provider.id == "google" else "x_app_id"] = provider.client_id
    metadata = db.validate_credential_metadata(metadata)
    provider_id, subject, account = db.validate_managed_oauth_account_identity(metadata)
    review = {"credential_type": "oauth2", "provider": provider_id, "provider_subject": subject,
        "provider_account": account, "scopes": scopes, "credential_name": state["credentialName"],
        "metadata_keys": sorted(metadata), "expires_at_epoch_ms": token["expires_at_epoch_ms"],
        "oauth_application_owner": state["oauth_application_owner"]}
    if provider.id == "x":
        review["x_app_id"] = provider.client_id
    db._validate_oauth_activation_review(review=review, metadata=metadata, name=state["credentialName"],
        kind="oauth2", provider_id=provider_id, provider_subject=subject,
        target_credential_id=None, target_credential_version=None)
    operation.check()
    return metadata, review
