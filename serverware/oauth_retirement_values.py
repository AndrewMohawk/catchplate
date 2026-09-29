"""Shared OAuth retirement/envelope data grammar, without control-plane imports.

These predicates confer no authority: callers retain their distinct signed
purposes, assignments, currentness checks and contact/recovery state machines.
Only the standard library belongs in this immutable helper-image dependency.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlsplit

GRANT_SCHEMA = "serverware.oauthRevocationAuthorization/v1"
GRANT_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "authorizationId", "configurationDigest", "deploymentId",
    "exchangeId", "exchangeRowSha256", "workRowSha256", "enrollmentSha256", "historicalEnrollmentRootSpkiSha256",
    "tokenEnvelopeSha256", "tokenSecretSha256", "providerId", "clientId", "clientMaterialSha256", "providerConfiguration",
    "tokenPurposes", "issuedAtEpochNs", "expiresAtEpochNs"})
PROVIDER_FIELDS = frozenset({"providerId", "authorizationUrl", "tokenUrl", "revocationUrl", "identityUrl", "tokenAuth",
    "defaultScopes", "authParams", "metadataProvider", "tokenResponseScopeOptional"})
ENVELOPE_FIELDS = frozenset({"encrypted_secret", "encrypted_dek", "secret_nonce", "secret_ciphertext", "secret_kek_id", "credential_version", "secret_updated_at"})
MAX_GRANT_BYTES = 64 * 1024
MAX_ENVELOPE_BYTES = 256 * 1024


def _require(value):
    if not value:
        raise ValueError("OAuth activation originals are not exact")


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def text(value, bound):
    _require(type(value) is str and value == value.strip() and 1 <= len(value.encode("utf-8")) <= bound
        and not any(ord(c) < 32 or ord(c) == 127 for c in value))
    return value


def timestamp(value):
    _require(type(value) is str)
    result = datetime.fromisoformat(value)
    _require(result.tzinfo is not None and result.utcoffset() == timedelta(0))
    return result


def envelope(value):
    _require(type(value) is dict and set(value) == ENVELOPE_FIELDS)
    _require(type(value["credential_version"]) is int and value["credential_version"] == 1)
    _require(value["encrypted_secret"] == "envelope:v2")
    for field in ENVELOPE_FIELDS - {"credential_version"}:
        text(value[field], MAX_ENVELOPE_BYTES)
    timestamp(value["secret_updated_at"])
    _require(len(_canonical(value)) <= MAX_ENVELOPE_BYTES)
    return dict(value)


def revocation_payload(value):
    _require(type(value) is dict and set(value) == GRANT_FIELDS and value["schema"] == GRANT_SCHEMA
        and value["purpose"] == "retained-oauth-revocation" and value["providerId"] in {"google", "x"})
    for field in ("authorizationId", "exchangeId"):
        _require(type(value[field]) is str and re.fullmatch(r"[0-9a-f-]{36}", value[field]) is not None)
        _require(str(uuid.UUID(value[field])) == value[field])
    for field in ("configurationDigest", "exchangeRowSha256", "workRowSha256", "enrollmentSha256",
            "historicalEnrollmentRootSpkiSha256", "tokenEnvelopeSha256", "tokenSecretSha256", "clientMaterialSha256"):
        _require(type(value[field]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value[field]) is not None)
        _require(value[field] != "sha256:" + "0" * 64)
    _require(type(value["deploymentId"]) is str
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value["deploymentId"]) is not None)
    text(value["sourceRevision"], 128)
    text(value["clientId"], 2048)
    purposes = value["tokenPurposes"]
    _require(type(purposes) is list and purposes in (["access_token"], ["refresh_token"], ["access_token", "refresh_token"])
        and (value["providerId"] == "x" or len(purposes) == 1))
    provider = value["providerConfiguration"]
    _require(type(provider) is dict and set(provider) == PROVIDER_FIELDS and provider["providerId"] == value["providerId"]
        and provider["tokenAuth"] in {"basic", "client_secret_post", "none"} and type(provider["tokenResponseScopeOptional"]) is bool)
    for name in ("authorizationUrl", "tokenUrl", "revocationUrl", "identityUrl"):
        url = urlsplit(text(provider[name], 4096))
        _require(url.scheme == "https" and url.hostname and not url.username and not url.password and not url.fragment)
    text(provider["metadataProvider"], 256)
    _require(type(provider["defaultScopes"]) is list and 1 <= len(provider["defaultScopes"]) <= 30)
    for scope in provider["defaultScopes"]:
        text(scope, 200)
    _require(type(provider["authParams"]) is dict and len(provider["authParams"]) <= 16)
    for key, item in provider["authParams"].items():
        text(key, 128)
        text(item, 2048)
    for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
        _require(type(value[field]) is int and 1 <= value[field] <= 2**63 - 1)
    _require(value["issuedAtEpochNs"] < value["expiresAtEpochNs"] <= value["issuedAtEpochNs"] + 300_000_000_000)
    _require(len(_canonical(value)) <= MAX_GRANT_BYTES - 512)
    return value
