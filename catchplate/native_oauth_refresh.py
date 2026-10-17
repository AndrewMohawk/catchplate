"""Fixed confidential OAuth refresh formats shared with the measured helper.

Encryption producers are offline provisioning tools, not runtime RPCs. These
data checks do not grant contact, prove storage, or authenticate a provider.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import urllib.parse
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APPLICATION = "catchplate.nativeOAuthApplicationMaterial/v1"
APPLICATION_DOMAIN = b"catchplate/native-oauth-application-material/v1\0"
CLIENT = "catchplate.oauthClientMaterial/v1"
ASSOCIATION = "oauth_application_owner"
MAX_REPLY = 96 * 1024
MAX_ORIGINAL = 190 * 1024
APPLICATION_PAD = 32768
MAX_LIFETIME = 366 * 24 * 60 * 60
ENDPOINTS = {"google": ("oauth2.googleapis.com", "/token"),
             "x": ("api.twitter.com", "/2/oauth2/token")}
ENVELOPE_FIELDS = frozenset({"encrypted_secret", "encrypted_dek", "secret_nonce",
    "secret_ciphertext", "secret_kek_id", "credential_version", "secret_updated_at"})


def require(value, message="measured OAuth refresh original or scope differs"):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def digest(value):
    require(type(value) is str and len(value) == 71 and value.startswith("sha256:")
        and all(char in "0123456789abcdef" for char in value[7:]) and value[7:] != "0" * 64)
    return value


def text(value, maximum):
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= maximum)
    return value


def integer(value, minimum=1, maximum=2**63 - 1):
    require(type(value) is int and minimum <= value <= maximum)
    return value


def encoded(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decoded(value, maximum, exact=None):
    require(type(value) is str and 0 < len(value) <= (maximum * 4 + 2) // 3)
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    require(encoded(raw) == value and len(raw) <= maximum and (exact is None or len(raw) == exact))
    return raw


def document(raw, maximum, *, exact=True):
    require(type(raw) is bytes and 0 < len(raw) <= maximum)
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value)
            value[key] = item
        return value
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
        parse_constant=lambda _: require(False))
    require(type(value) is dict and (not exact or canonical(value) == raw))
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop(); count += 1
        require(depth <= 32 and count <= 8192)
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is float:
            require(math.isfinite(item))
    return value


def application_header(value, payload, enrollment_sha256):
    fields = {"apiVersion", "enrollmentSha256", "clientMaterialSha256", "providerId",
        "clientId", "redirectUri", "secretKekId", "nonce", "ciphertext"}
    require(type(value) is dict and set(value) == fields and value["apiVersion"] == APPLICATION
        and value["enrollmentSha256"] == digest(enrollment_sha256)
        and value["clientMaterialSha256"] == payload["clientMaterialSha256"]
        and value["providerId"] == payload["providerId"] in ENDPOINTS
        and value["clientId"] == payload["clientId"] and value["redirectUri"] == payload["redirectUri"])
    digest(value["clientMaterialSha256"])
    key_id = value["secretKekId"]
    require(type(key_id) is str and key_id.startswith("attested-memory-kek:")
        and len(key_id) == 44 and all(char in "0123456789abcdef" for char in key_id[-24:]))
    decoded(value["nonce"], 12, 12)
    decoded(value["ciphertext"], APPLICATION_PAD + 16, APPLICATION_PAD + 16)
    return {name: value[name] for name in fields - {"nonce", "ciphertext"}}


def seal_application(client_original, enrollment_original, kek, kek_sha256):
    """Explicit independent confidential provisioner; never called by HTTP."""
    require(type(kek) is bytes and len(kek) == 32 and hmac.compare_digest(sha(kek), digest(kek_sha256)))
    enrollment = document(enrollment_original, 65536)
    payload = enrollment["payload"]
    client = document(client_original, 24576)
    require(set(client) == {"schema", "providerId", "clientId", "clientSecret", "redirectUri"}
        and client["schema"] == CLIENT and sha(client_original) == payload["clientMaterialSha256"])
    text(client["clientSecret"], 8192)
    for name in ("providerId", "clientId", "redirectUri"):
        require(client[name] == payload[name])
    header = {"apiVersion": APPLICATION, "enrollmentSha256": sha(enrollment_original),
        "clientMaterialSha256": payload["clientMaterialSha256"], "providerId": payload["providerId"],
        "clientId": payload["clientId"], "redirectUri": payload["redirectUri"],
        "secretKekId": "attested-memory-kek:" + kek_sha256[7:31]}
    nonce = os.urandom(12)
    padded = len(client_original).to_bytes(4, "big") + client_original + bytes(APPLICATION_PAD - 4 - len(client_original))
    value = {**header, "nonce": encoded(nonce), "ciphertext": encoded(AESGCM(kek).encrypt(
        nonce, padded, APPLICATION_DOMAIN + canonical(header)))}
    application_header(value, payload, sha(enrollment_original))
    return value


def open_application(value, payload, enrollment_sha256, secret_kek_id, kek):
    header = application_header(value, payload, enrollment_sha256)
    require(header["secretKekId"] == secret_kek_id)
    padded = kek.decrypt(decoded(value["nonce"], 12, 12),
        decoded(value["ciphertext"], APPLICATION_PAD + 16, APPLICATION_PAD + 16),
        APPLICATION_DOMAIN + canonical(header))
    length = int.from_bytes(padded[:4], "big")
    require(len(padded) == APPLICATION_PAD and 0 < length <= 24576 and not any(padded[4 + length:]))
    raw = padded[4:4 + length]
    require(sha(raw) == payload["clientMaterialSha256"])
    client = document(raw, 24576)
    require(set(client) == {"schema", "providerId", "clientId", "clientSecret", "redirectUri"} and client["schema"] == CLIENT)
    for name in ("providerId", "clientId", "redirectUri"):
        require(client[name] == payload[name])
    text(client["clientSecret"], 8192)
    return client


def _stored(value, maximum, exact=None):
    text(value, ((maximum + 2) // 3) * 4)
    raw = base64.b64decode(value, altchars=b"-_", validate=True)
    require(base64.urlsafe_b64encode(raw).decode("ascii") == value and len(raw) <= maximum
        and (exact is None or len(raw) == exact))
    return raw


def open_original(item_id, envelope, version, secret_kek_id, kek):
    require(type(envelope) is dict and set(envelope) == ENVELOPE_FIELDS
        and envelope["encrypted_secret"] == "envelope:v2" and envelope["credential_version"] == integer(version)
        and envelope["secret_kek_id"] == secret_kek_id)
    wrapped = envelope["encrypted_dek"].split(":")
    nonce = envelope["secret_nonce"].split(":"); ciphertext = envelope["secret_ciphertext"].split(":")
    require(len(wrapped) == 3 and len(nonce) == len(ciphertext) == 2
        and wrapped[0] == nonce[0] == ciphertext[0] == "v1")
    dek = kek.decrypt(_stored(wrapped[1], 12, 12), _stored(wrapped[2], 48, 48),
        f"catchplate:dek:{item_id}:v{version}".encode("utf-8"))
    require(len(dek) == 32)
    raw = AESGCM(dek).decrypt(_stored(nonce[1], 12, 12), _stored(ciphertext[1], MAX_ORIGINAL + 16),
        f"catchplate:secret:{item_id}:v{version}".encode("utf-8"))
    require(0 < len(raw) <= MAX_ORIGINAL)
    return raw


def seal_original(item_id, raw, version, secret_kek_id, kek, epoch_ns):
    integer(version); integer(epoch_ns)
    require(type(raw) is bytes and 0 < len(raw) <= MAX_ORIGINAL)
    dek, key_nonce, secret_nonce = os.urandom(32), os.urandom(12), os.urandom(12)
    padded = lambda value: base64.urlsafe_b64encode(value).decode("ascii")
    wrapped = kek.encrypt(key_nonce, dek, f"catchplate:dek:{item_id}:v{version}".encode("utf-8"))
    ciphertext = AESGCM(dek).encrypt(secret_nonce, raw, f"catchplate:secret:{item_id}:v{version}".encode("utf-8"))
    stamp = datetime.fromtimestamp(epoch_ns // 1_000_000_000, timezone.utc).replace(microsecond=epoch_ns % 1_000_000_000 // 1000).isoformat()
    result = {"encrypted_secret": "envelope:v2", "encrypted_dek": "v1:" + padded(key_nonce) + ":" + padded(wrapped),
        "secret_nonce": "v1:" + padded(secret_nonce), "secret_ciphertext": "v1:" + padded(ciphertext),
        "secret_kek_id": secret_kek_id, "credential_version": version, "secret_updated_at": stamp}
    require(open_original(item_id, result, version, secret_kek_id, kek) == raw)
    return result


def scopes(value):
    text(value, 128 * 1025)
    items = value.split(" ")
    require(1 <= len(items) <= 128 and len(set(items)) == len(items))
    for item in items:
        text(item, 1024)
        require(not any(ord(char) < 33 or ord(char) == 127 for char in item))
    return frozenset(items)


def current(raw, metadata, association):
    token = document(raw, MAX_ORIGINAL, exact=False)
    text(token.get("access_token"), 64 * 1024); text(token.get("refresh_token"), 128 * 1024)
    require(type(token.get("token_type")) is str and token["token_type"].lower() == "bearer"
        and token.get(ASSOCIATION) == metadata.get(ASSOCIATION) == association
        and metadata.get("oauth") is True and metadata.get("refreshable") is True)
    original_scopes = scopes(token.get("scope"))
    require(type(metadata.get("scopes")) is list and len(metadata["scopes"]) == len(original_scopes)
        and frozenset(metadata["scopes"]) == original_scopes
        and integer(token.get("expires_at_epoch_ms")) == metadata.get("expires_at_epoch_ms")
        and token.get("refresh_token_expires_at_epoch_ms") == metadata.get("refresh_token_expires_at_epoch_ms"))
    if token.get("refresh_token_expires_at_epoch_ms") is not None:
        integer(token["refresh_token_expires_at_epoch_ms"])
    return token


def token_request(client, token):
    provider = client["providerId"]
    require(provider in ENDPOINTS)
    body = {"grant_type": "refresh_token", "refresh_token": text(token.get("refresh_token"), 128 * 1024)}
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    if provider == "google":
        body.update(client_id=client["clientId"], client_secret=client["clientSecret"])
    else:
        headers["Authorization"] = "Basic " + base64.b64encode((client["clientId"] + ":" + client["clientSecret"]).encode("utf-8")).decode("ascii")
    raw = urllib.parse.urlencode(body).encode("utf-8")
    require(len(raw) <= 32768)
    host, path = ENDPOINTS[provider]
    commitment = {"schema": "catchplate.nativeOAuthRefreshContact/v1", "url": "https://" + host + path,
        "method": "POST", "bodySha256": sha(raw), "headersSha256": sha(canonical(headers))}
    return host, path, headers, raw, sha(canonical(commitment))


def issued_original(body, association):
    try:
        payload = document(body, MAX_REPLY, exact=False)
        values = {key: item for key, item in payload.items() if key in {"access_token", "refresh_token"}
            and type(item) is str and 0 < len(item.encode("utf-8")) <= 128 * 1024}
        if not values:
            return None
        raw = canonical({**values, "token_type": "Bearer", ASSOCIATION: association})
        require(len(raw) <= MAX_ORIGINAL)
        return raw
    except (ValueError, TypeError, UnicodeError, OverflowError):
        return None


def replacement(status, body, received_ns, provider, token, metadata):
    """Called only after independently authenticated durable capture receipt."""
    require(type(status) is int and 200 <= status < 300)
    integer(received_ns)
    payload = document(body, MAX_REPLY, exact=False)
    access = text(payload.get("access_token"), 64 * 1024)
    token_type = payload.get("token_type", token["token_type"])
    require(type(token_type) is str and token_type.lower() == "bearer")
    def expiry(name):
        value = payload.get(name)
        require(type(value) in (int, float) and math.isfinite(value) and 1 <= value <= MAX_LIFETIME)
        return integer(received_ns // 1_000_000 + int(value) * 1000, maximum=9_223_372_036_854_775)
    expires = expiry("expires_in")
    scope = payload.get("scope", token["scope"])
    require(scopes(scope) == scopes(token["scope"]))
    refresh = text(payload.get("refresh_token", token["refresh_token"]), 128 * 1024)
    refresh_expiry = token.get("refresh_token_expires_at_epoch_ms")
    if "refresh_token_expires_in" in payload:
        refresh_expiry = expiry("refresh_token_expires_in")
    value = {**token, "access_token": access, "refresh_token": refresh,
        "token_type": "Bearer", "scope": scope, "expires_at_epoch_ms": expires}
    updated = {**metadata, "refreshable": True, "token_type": "Bearer", "scopes": sorted(scopes(scope)), "expires_at_epoch_ms": expires}
    if refresh_expiry is not None:
        value["refresh_token_expires_at_epoch_ms"] = updated["refresh_token_expires_at_epoch_ms"] = refresh_expiry
    require(len(canonical(updated)) <= 32768)
    original = canonical(value); require(len(original) <= MAX_ORIGINAL)
    retired = None
    require(provider in ENDPOINTS)
    if provider == "x":
        changed = {name: token[name] for name in ("access_token", "refresh_token") if token[name] != value[name]}
        if changed:
            retired = canonical({**changed, "token_type": "Bearer", ASSOCIATION: metadata[ASSOCIATION]})
            require(len(retired) <= MAX_ORIGINAL)
    return original, updated, retired
