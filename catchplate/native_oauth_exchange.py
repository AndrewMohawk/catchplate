"""Confidential initial-exchange material used only by the measured helper.

These pure encodings are not consent, provider permission, or a storage
receipt. The actual owner admits those originals before any token contact.
No browser cookie, authorization code, PKCE verifier or token is a public
output of the control-plane adapter.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import math
import os
import re
import urllib.parse
import uuid

from catchplate import native_oauth_refresh as material

STATE_SCHEMA = "catchplate.nativeOAuthExchangeState/v1"
INTENT_SCHEMA = "catchplate.nativeOAuthExchangeIntent/v1"
CONTACT_SCHEMA = "catchplate.nativeOAuthExchangeContact/v1"
COOKIE_PREFIX = "__Host-catchplate-native-oauth-"
MAX_STATE = 64 * 1024
MAX_CODE = 4096
MAX_IDENTITY_REPLY = 64 * 1024
AUTHORIZATION = {"google": "https://accounts.google.com/o/oauth2/v2/auth",
                 "x": "https://twitter.com/i/oauth2/authorize"}
IDENTITY = {"google": ("openidconnect.googleapis.com", "/v1/userinfo"),
            "x": ("api.x.com", "/2/users/me?user.fields=id,name,username,verified")}
INTENT_FIELDS = frozenset({"schema", "providerId", "requesterId", "credentialName", "scopes", "metadata", "credentialPolicy"})
STATE_FIELDS = frozenset({"schema", "exchangeId", "state", "browserNonceSha256", "codeVerifier",
    "providerId", "requesterId", "credentialName", "scopes", "metadata", "redirectUri",
    "issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs",
    "enrollmentSha256", "oauth_application_owner", "credentialPolicy", "limits", "portalOrigin", "callbackOrigin"})


def text(value, maximum):
    material.text(value, maximum)
    material.require(value == value.strip() and not any(ord(char) < 32 or ord(char) == 127 for char in value))
    return value


def identifier(value):
    material.require(type(value) is str and str(uuid.UUID(value)) == value)
    return value


def origin(value):
    text(value, 2048)
    parsed = urllib.parse.urlsplit(value)
    material.require(parsed.scheme == "https" and parsed.hostname and parsed.username is None and parsed.password is None
        and parsed.path == "" and parsed.query == "" and parsed.fragment == "" and parsed.netloc == parsed.netloc.lower()
        and parsed.port is None and not parsed.netloc.endswith(":443"))
    return value


def callback_uri(callback_origin, provider):
    material.require(provider in AUTHORIZATION)
    return origin(callback_origin) + "/oauth/callback/" + provider


def artifact_id(exchange_id, purpose):
    identifier(exchange_id)
    material.require(purpose in {"state", "response", "callback", "identity"})
    # State/reply and final token id/AAD agree with the protected existing
    # pending/activation contracts. New callback/identity are separate artifacts.
    return str(uuid.uuid5(uuid.UUID(exchange_id), "catchplate.oauthExchangeArtifact/v1:" + purpose))


def association(enrollment_original, payload):
    return {"schema": "catchplate.oauthApplicationAssociation/v1", "enrollmentSha256": material.sha(enrollment_original),
        **{name: payload[name] for name in ("deploymentId", "applicationId", "providerId", "providerFamilyNamespace",
            "providerFamilyGeneration", "clientId", "redirectUri", "providerConfigurationSha256")}}


def intent(value):
    material.require(type(value) is dict and set(value) == INTENT_FIELDS and value["schema"] == INTENT_SCHEMA
        and value["providerId"] in AUTHORIZATION)
    text(value["requesterId"], 512); text(value["credentialName"], 256)
    scopes = value["scopes"]
    material.require(type(scopes) is list and 1 <= len(scopes) <= 128 and scopes == sorted(set(scopes)))
    material.scopes(" ".join(scopes))
    metadata = value["metadata"]
    material.require(type(metadata) is dict and len(metadata) <= 50 and len(material.canonical(metadata)) <= 4096
        and material.ASSOCIATION not in metadata and type(value["credentialPolicy"]) is dict)
    return value


def prepare(intent_value, *, enrollment_original, callback_origin, portal_origin, limits, issued_ns,
            contact_expires_ns, retention_expires_ns, pending_expires_ns):
    """Create private draft only; actual requester MFA must bind its original."""
    value = intent(intent_value)
    enrollment = material.document(enrollment_original, 32768, exact=False)["payload"]
    material.require(value["providerId"] == enrollment["providerId"]
        and callback_uri(callback_origin, value["providerId"]) == enrollment["redirectUri"]
        and origin(portal_origin) != origin(callback_origin))
    for epoch in (issued_ns, contact_expires_ns, retention_expires_ns, pending_expires_ns):
        material.integer(epoch)
    material.require(enrollment["issuedAtEpochNs"] <= issued_ns < contact_expires_ns
        <= retention_expires_ns <= pending_expires_ns <= enrollment["expiresAtEpochNs"]
        and contact_expires_ns - issued_ns <= 600_000_000_000
        and retention_expires_ns - contact_expires_ns <= 600_000_000_000
        and pending_expires_ns - contact_expires_ns <= 3_600_000_000_000
        and type(limits) is dict and set(limits) == {"pendingCapacity", "revocationCapacity"})
    for bound in limits.values():
        material.integer(bound, maximum=64)
    exchange = str(uuid.uuid4())
    state_text = uuid.UUID(exchange).hex + "_" + material.encoded(os.urandom(32))
    nonce, verifier = material.encoded(os.urandom(32)), material.encoded(os.urandom(32))
    state = {"schema": STATE_SCHEMA, "exchangeId": exchange, "state": state_text,
        "browserNonceSha256": material.sha(nonce.encode("ascii")), "codeVerifier": verifier,
        **{name: value[name] for name in ("providerId", "requesterId", "credentialName", "scopes", "credentialPolicy")},
        "metadata": {**value["metadata"], material.ASSOCIATION: association(enrollment_original, enrollment)},
        "redirectUri": enrollment["redirectUri"], "issuedAtEpochNs": issued_ns, "contactExpiresAtEpochNs": contact_expires_ns,
        "retentionExpiresAtEpochNs": retention_expires_ns, "pendingExpiresAtEpochNs": pending_expires_ns,
        "enrollmentSha256": material.sha(enrollment_original), "oauth_application_owner": association(enrollment_original, enrollment),
        "limits": limits, "portalOrigin": portal_origin, "callbackOrigin": callback_origin}
    raw = material.canonical(state)
    private_state(raw)
    return raw, nonce


def private_state(raw):
    state = material.document(raw, MAX_STATE)
    material.require(set(state) == STATE_FIELDS and state["schema"] == STATE_SCHEMA)
    identifier(state["exchangeId"])
    material.require(re.fullmatch(r"[0-9a-f]{32}_[A-Za-z0-9_-]{43}", state["state"]) is not None
        and state["state"][:32] == uuid.UUID(state["exchangeId"]).hex
        and re.fullmatch(r"[A-Za-z0-9_-]{43}", state["codeVerifier"]) is not None
        and state["redirectUri"] == callback_uri(state["callbackOrigin"], state["providerId"]))
    material.digest(state["browserNonceSha256"]); material.digest(state["enrollmentSha256"])
    origin(state["portalOrigin"])
    return state


def cookie_name(exchange_id):
    return COOKIE_PREFIX + uuid.UUID(identifier(exchange_id)).hex


def require_browser(state, cookie):
    material.require(type(cookie) is str and re.fullmatch(r"[A-Za-z0-9_-]{43}", cookie) is not None
        and hmac.compare_digest(material.sha(cookie.encode("ascii")), state["browserNonceSha256"]))


def authorization_url(state, client):
    material.require(client["providerId"] == state["providerId"] and client["redirectUri"] == state["redirectUri"])
    query = {"response_type": "code", "client_id": client["clientId"], "redirect_uri": state["redirectUri"],
        "scope": " ".join(state["scopes"]), "state": state["state"], "code_challenge_method": "S256",
        "code_challenge": material.encoded(hashlib.sha256(state["codeVerifier"].encode("ascii")).digest())}
    if state["providerId"] == "google":
        query.update(access_type="offline", prompt="consent", include_granted_scopes="true")
    return AUTHORIZATION[state["providerId"]] + "?" + urllib.parse.urlencode(query)


def token_request(state, client, code):
    material.text(code, MAX_CODE)
    material.require(state["providerId"] == client["providerId"] and state["redirectUri"] == client["redirectUri"])
    body = {"grant_type": "authorization_code", "code": code, "redirect_uri": state["redirectUri"],
        "client_id": client["clientId"], "code_verifier": state["codeVerifier"]}
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    if state["providerId"] == "google":
        body["client_secret"] = client["clientSecret"]
    else:
        headers["Authorization"] = "Basic " + base64.b64encode((client["clientId"] + ":" + client["clientSecret"]).encode("utf-8")).decode("ascii")
    raw = urllib.parse.urlencode(body).encode("utf-8")
    material.require(len(raw) <= 32768)
    host, path = material.ENDPOINTS[state["providerId"]]
    commitment = {"schema": CONTACT_SCHEMA, "url": "https://" + host + path, "method": "POST",
        "bodySha256": material.sha(raw), "headersSha256": material.sha(material.canonical(headers))}
    return host, path, headers, raw, material.sha(material.canonical(commitment))


def token_original(status, body, received_ns, state):
    """Normalize only after durable raw/issued capture; never renew expiry."""
    material.require(type(status) is int and 200 <= status < 300)
    payload = material.document(body, material.MAX_REPLY, exact=False)
    access = material.text(payload.get("access_token"), 128 * 1024)
    refresh = material.text(payload.get("refresh_token"), 128 * 1024)
    material.require(type(payload.get("token_type")) is str and payload["token_type"].lower() == "bearer")
    material.integer(received_ns)
    def expiry(name, required):
        if name not in payload and not required:
            return None
        value = payload.get(name)
        material.require(type(value) in (int, float) and math.isfinite(value) and 0 < value <= material.MAX_LIFETIME)
        return material.integer(received_ns // 1_000_000 + int(value) * 1000, maximum=9_223_372_036_854_775)
    expires, refresh_expires = expiry("expires_in", True), expiry("refresh_token_expires_in", False)
    scope = payload.get("scope", " ".join(state["scopes"]))
    material.require(material.scopes(scope) <= frozenset(state["scopes"]))
    value = {"access_token": access, "refresh_token": refresh, "token_type": "Bearer", "scope": scope,
        "expires_at_epoch_ms": expires, material.ASSOCIATION: state[material.ASSOCIATION]}
    if refresh_expires is not None:
        value["refresh_token_expires_at_epoch_ms"] = refresh_expires
    original = material.canonical(value)
    material.require(len(original) <= material.MAX_ORIGINAL)
    return original, value


def identity_request(provider, token):
    material.require(provider in IDENTITY)
    host, path = IDENTITY[provider]
    headers = {"Accept": "application/json", "Authorization": "Bearer " + material.text(token["access_token"], 128 * 1024)}
    return host, path, headers


def identity_metadata(provider, body):
    payload = material.document(body, MAX_IDENTITY_REPLY, exact=False)
    if provider == "google":
        subject = text(payload.get("sub"), 512)
        email = payload.get("email")
        verified = type(email) is str and bool(email) and payload.get("email_verified") is True
        account = text(email, 512) if verified else subject
        return {"provider_subject": subject, "provider_account": account,
            "provider_identity_verified": True, "provider_email_verified": verified}
    material.require(provider == "x" and type(payload.get("data")) is dict)
    data = payload["data"]
    subject, username = text(data.get("id"), 512), text(data.get("username"), 511)
    return {"provider_subject": subject, "provider_account": "@" + username.lstrip("@"),
        "provider_identity_verified": True, "provider_profile_verified": data.get("verified") is True}
