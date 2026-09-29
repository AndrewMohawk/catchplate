"""Closed automatic due-refresh originals; application enrollment is not permission."""
from __future__ import annotations

import base64
import json
import re
import uuid
from collections.abc import Mapping

from serverware import authority_oauth_exchange as exchange

canonical, require, digest, sha256 = exchange.canonical, exchange.require, exchange.digest, exchange.sha256
identifier, text, timestamp, enrollment_bytes = exchange.identifier, exchange.text, exchange.timestamp, exchange.enrollment_bytes
OP_CLAIM = "oauth.refresh.claim"
OP_RETAIN = "oauth.refresh.retain"
OP_COMMIT = "oauth.refresh.commit"
OPERATIONS = frozenset({OP_CLAIM, OP_RETAIN, OP_COMMIT})
TABLE = "oauth_refresh_reservations"
ISSUED_SOURCE = "enrolled-oauth-refresh-issued/v1"
SUPERSEDED_SOURCE = "enrolled-oauth-refresh-superseded/v1"
FIELDS = frozenset({"credential_id", "enrollment_original", "request"})
ENVELOPE_FIELDS = exchange.ENVELOPE_FIELDS
CREDENTIAL_FIELDS = frozenset({"id", "name", "kind", "encrypted_secret", "encrypted_dek", "secret_nonce", "secret_ciphertext", "secret_kek_id", "credential_version", "secret_updated_at", "metadata", "lifecycle_status", "revocation_error", "revocation_requested_at", "created_at", "updated_at"})
GENERATION_FIELDS = frozenset({"credential_id", "last_version", "updated_at"})
ROW_FIELDS = frozenset({"id", "credential_id", "credential_version", "provider_id", "enrollment_original",
    "credential_original_json", "generation_original_json", "limits_json", "claim_request_digest", "owner_nonce_sha256",
    "status", "contact_request_sha256", "issued_work_id", "superseded_work_id", "issued_at_epoch_ns",
    "contact_expires_at_epoch_ns", "retention_expires_at_epoch_ns", "received_at_epoch_ns", "raw_response_sha256",
    "raw_response_envelope_json", "issued_material_sha256", "issued_material_envelope_json", "replacement_secret_sha256",
    "replacement_credential_sha256", "superseded_material_sha256", "created_at", "updated_at"})
_ROW_INTS = frozenset({"credential_version", "issued_at_epoch_ns", "contact_expires_at_epoch_ns", "retention_expires_at_epoch_ns", "received_at_epoch_ns"})
_ROW_NULLABLE = frozenset({"superseded_work_id", "received_at_epoch_ns", "raw_response_sha256", "raw_response_envelope_json",
    "issued_material_sha256", "issued_material_envelope_json", "replacement_secret_sha256", "replacement_credential_sha256", "superseded_material_sha256"})
_COMMON = frozenset({"expectedVersion", "limits"})
REQUEST_FIELDS = {
    OP_CLAIM: _COMMON | {"credentialRowSha256", "generationRowSha256", "ownerNonceSha256", "issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "contactRequestSha256", "reservedIssuedEnvelope", "reservedSupersededEnvelope", "currentnessBarrierSha256"},
    OP_RETAIN: _COMMON | {"refreshRowSha256", "ownerNonce", "receivedAtEpochNs", "rawResponseSha256", "rawResponseEnvelope", "issuedMaterialSha256", "issuedMaterialEnvelope"},
    OP_COMMIT: _COMMON | {"refreshRowSha256", "ownerNonce", "replacementSecretSha256", "replacementEnvelope", "replacementMetadata", "supersededMaterialSha256", "supersededEnvelope"},
}
MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_ROW_BYTES = 2 * 1024 * 1024
MAX_ENVELOPE_BYTES = exchange.MAX_ENVELOPE_BYTES
MAX_TOKEN_LIFETIME_SECONDS = 366 * 24 * 60 * 60


def limits(value):
    require(type(value) is dict and set(value) == {"dueWithinSeconds", "operationMaxSeconds", "revocationCapacity"})
    for name, maximum in (("dueWithinSeconds", 300), ("operationMaxSeconds", 30), ("revocationCapacity", 64)):
        require(type(value[name]) is int and 1 <= value[name] <= maximum)
    return dict(value)


def _version(value):
    require(type(value) is int and 1 <= value <= 2**63 - 1)
    return value


def _uuid(value):
    identifier(value)
    require(str(uuid.UUID(value)) == value)
    return value


def refresh_id(credential_id, current_version):
    _uuid(credential_id)
    _version(current_version)
    return str(uuid.uuid5(uuid.UUID(credential_id), "serverware.oauthRefresh/v1:" + str(current_version)))


def artifact_id(refresh, purpose):
    _uuid(refresh)
    require(purpose in {"response", "issued", "superseded"})
    return str(uuid.uuid5(uuid.UUID(refresh), "serverware.oauthRefreshArtifact/v1:" + purpose))


def envelope(value, expected_version):
    require(type(expected_version) is int and 1 <= expected_version <= 2**63 - 1
        and type(value) is dict and set(value) == ENVELOPE_FIELDS
        and type(value["credential_version"]) is int and value["credential_version"] == expected_version
        and value["encrypted_secret"] == "envelope:v2")
    for name in ENVELOPE_FIELDS - {"credential_version"}:
        text(value[name], MAX_ENVELOPE_BYTES)
    timestamp(value["secret_updated_at"])
    require(len(canonical(value)) <= MAX_ENVELOPE_BYTES)
    return dict(value)


def credential_original(row):
    value = dict(row)
    require(set(value) == CREDENTIAL_FIELDS)
    _uuid(value["id"])
    _version(value["credential_version"])
    for name, item in value.items():
        if name != "credential_version":
            require(type(item) is str or item is None and name in {"revocation_error", "revocation_requested_at"})
    raw = canonical(value)
    require(len(raw) <= 512 * 1024)
    return raw


def generation_original(row):
    value = dict(row)
    require(set(value) == GENERATION_FIELDS and type(value["updated_at"]) is str)
    _uuid(value["credential_id"])
    _version(value["last_version"])
    return canonical(value)


def row_original(row):
    value = dict(row)
    require(set(value) == ROW_FIELDS)
    for name, item in value.items():
        if item is None:
            require(name in _ROW_NULLABLE)
        elif name in _ROW_INTS:
            require(type(item) is int and 1 <= item <= 2**63 - 1)
        else:
            require(type(item) is str)
    raw = canonical(value)
    require(len(raw) <= MAX_ROW_BYTES)
    return raw


def row_digest(row):
    return sha256(row_original(row))


def document(raw, maximum):
    require(type(raw) is bytes and 2 <= len(raw) <= maximum)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    result = json.loads(raw.decode("ascii"), object_pairs_hook=pairs, parse_constant=lambda _: require(False))
    require(type(result) is dict and canonical(result) == raw)
    return result


def _nonce(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]{43}", value) is not None)
    raw = base64.urlsafe_b64decode(value + "=")
    require(len(raw) == 32 and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)
    return raw


def request_binding(operation, request):
    require(operation in OPERATIONS and type(request) is dict and set(request) == REQUEST_FIELDS[operation])
    version = _version(request["expectedVersion"])
    require(version < 2**63 - 1)
    bounds = limits(request["limits"])
    if operation == OP_CLAIM:
        for name in ("credentialRowSha256", "generationRowSha256", "ownerNonceSha256", "contactRequestSha256", "currentnessBarrierSha256"):
            digest(request[name])
        for name in ("issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs"):
            require(type(request[name]) is int and 1 <= request[name] <= 2**63 - 1)
        require(request["issuedAtEpochNs"] < request["contactExpiresAtEpochNs"] <= request["retentionExpiresAtEpochNs"]
            <= request["issuedAtEpochNs"] + bounds["operationMaxSeconds"] * 1_000_000_000)
        envelope(request["reservedIssuedEnvelope"], 1)
        if request["reservedSupersededEnvelope"] is not None:
            envelope(request["reservedSupersededEnvelope"], 1)
    else:
        digest(request["refreshRowSha256"])
        _nonce(request["ownerNonce"])
        if operation == OP_RETAIN:
            require(type(request["receivedAtEpochNs"]) is int and 1 <= request["receivedAtEpochNs"] <= 2**63 - 1)
            digest(request["rawResponseSha256"])
            envelope(request["rawResponseEnvelope"], 1)
            require((request["issuedMaterialSha256"] is None) == (request["issuedMaterialEnvelope"] is None))
            if request["issuedMaterialEnvelope"] is not None:
                digest(request["issuedMaterialSha256"])
                envelope(request["issuedMaterialEnvelope"], 1)
        else:
            digest(request["replacementSecretSha256"])
            envelope(request["replacementEnvelope"], version + 1)
            require(type(request["replacementMetadata"]) is dict and len(canonical(request["replacementMetadata"])) <= 32 * 1024)
            require((request["supersededMaterialSha256"] is None) == (request["supersededEnvelope"] is None))
            if request["supersededEnvelope"] is not None:
                digest(request["supersededMaterialSha256"])
                envelope(request["supersededEnvelope"], 1)
    return dict(request)


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping)
        and set(value) == FIELDS | ({"businessIntent"} if typed else set()))
    _uuid(value["credential_id"])
    enrollment_bytes(value["enrollment_original"])
    request_binding(operation, value["request"])
    result = {name: value[name] for name in FIELDS}
    require(len(canonical(result)) <= MAX_ARGUMENT_BYTES)
    return result


def request_digest(operation, value):
    from serverware import authority_request_commitment as commitment
    return commitment.oauth_refresh_request_digest(operation, value)
