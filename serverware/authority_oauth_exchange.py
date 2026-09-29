"""Closed enrolled OAuth exchange originals. Data validation is not authority."""
from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Mapping
from datetime import datetime, timedelta

from serverware import authority_oauth_activation as activation

canonical = activation.canonical
require = activation.require
digest = activation.digest
identifier = activation.identifier
policy = activation.policy
enrollment_bytes = activation.enrollment_bytes
ACTION = "credential.oauth.exchange"
OPTIONS_SCHEMA = "serverware.oauthExchangeConsentOptions/v1"
OP_PREPARE = "oauth.exchange.prepare"
OP_CLAIM = "oauth.exchange.claim"
OP_RETAIN = "oauth.exchange.retain"
OP_STAGE = "oauth.pending.stage"
OPERATIONS = frozenset({OP_PREPARE, OP_CLAIM, OP_RETAIN, OP_STAGE})
ASSERTION_OPERATIONS = frozenset({OP_PREPARE})
FIELDS = activation.FIELDS
TABLE = "oauth_exchange_reservations"
ENVELOPE_FIELDS = frozenset({"encrypted_secret", "encrypted_dek", "secret_nonce", "secret_ciphertext", "secret_kek_id", "credential_version", "secret_updated_at"})
PREPARE_FIELDS = frozenset({"exchangeId", "stateSha256", "browserNonceSha256", "pkceVerifierSha256", "stateOriginalSha256", "stateEnvelope", "reservedEnvelope", "providerId", "redirectUri", "credentialName", "scopes", "metadata", "issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs", "enrollmentSha256", "limits"})
POSSESSION_FIELDS = frozenset({"exchangeId", "exchangeRowSha256", "state", "browserNonce", "limits"})
REQUEST_FIELDS = {OP_PREPARE: PREPARE_FIELDS,
    OP_CLAIM: POSSESSION_FIELDS | {"codeSha256", "contactRequestSha256"},
    OP_RETAIN: POSSESSION_FIELDS | {"rawResponseSha256", "rawResponseEnvelope", "tokenSecretSha256", "tokenEnvelope"},
    OP_STAGE: POSSESSION_FIELDS | {"metadata", "review", "payloadDigest", "tokenSecretSha256"}}
ROW_FIELDS = frozenset({"id", "provider_id", "requester_id", "enrollment_original", "credential_policy_json", "consent_json", "status", "claim_request_digest", "code_sha256", "contact_request_sha256", "raw_response_sha256", "raw_response_envelope_json", "token_secret_sha256", "token_envelope_json", "created_at", "updated_at"})
NULLABLE = frozenset({"claim_request_digest", "code_sha256", "contact_request_sha256", "raw_response_sha256", "raw_response_envelope_json", "token_secret_sha256", "token_envelope_json"})
MAX_ENVELOPE_BYTES = 256 * 1024
MAX_ARGUMENT_BYTES = 768 * 1024
MAX_ROW_BYTES = 1024 * 1024


def sha256(raw):
    require(type(raw) is bytes)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def artifact_id(exchange_id, purpose):
    identifier(exchange_id)
    require(purpose in {"state", "response"})
    return str(uuid.uuid5(uuid.UUID(exchange_id), "serverware.oauthExchangeArtifact/v1:" + purpose))


def text(value, bound):
    require(type(value) is str and value == value.strip() and 1 <= len(value.encode("utf-8")) <= bound
        and not any(ord(c) < 32 or ord(c) == 127 for c in value))
    return value


def timestamp(value):
    require(type(value) is str)
    result = datetime.fromisoformat(value)
    require(result.tzinfo is not None and result.utcoffset() == timedelta(0))
    return result


def envelope(value):
    require(type(value) is dict and set(value) == ENVELOPE_FIELDS)
    require(type(value["credential_version"]) is int and value["credential_version"] == 1)
    require(value["encrypted_secret"] == "envelope:v2")
    for field in ENVELOPE_FIELDS - {"credential_version"}:
        text(value[field], MAX_ENVELOPE_BYTES)
    timestamp(value["secret_updated_at"])
    require(len(canonical(value)) <= MAX_ENVELOPE_BYTES)
    return dict(value)


def request_binding(operation, value):
    require(operation in OPERATIONS and type(value) is dict and set(value) == REQUEST_FIELDS[operation])
    identifier(value["exchangeId"])
    if operation == OP_PREPARE:
        for field in ("stateSha256", "browserNonceSha256", "pkceVerifierSha256", "stateOriginalSha256", "enrollmentSha256"):
            digest(value[field])
        envelope(value["stateEnvelope"])
        envelope(value["reservedEnvelope"])
        require(value["providerId"] in {"google", "x"})
        text(value["redirectUri"], 4096)
        text(value["credentialName"], 256)
        scopes = value["scopes"]
        require(type(scopes) is list and 1 <= len(scopes) <= 128 and all(type(scope) is str for scope in scopes)
            and len(set(scopes)) == len(scopes))
        for scope in scopes:
            text(scope, 1024)
        require(type(value["metadata"]) is dict and len(canonical(value["metadata"])) <= 32 * 1024)
        for field in ("issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs"):
            require(type(value[field]) is int and 1 <= value[field] <= 9_223_372_036_854_775_807)
        issued, contact, retention, pending = (value[field] for field in ("issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs"))
        require(issued < contact <= issued + 600_000_000_000 and contact <= retention <= contact + 600_000_000_000
            and retention <= pending <= contact + 3_600_000_000_000)
    else:
        digest(value["exchangeRowSha256"])
        for field in ("state", "browserNonce"):
            require(type(value[field]) is str and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value[field]) is not None)
        if operation == OP_CLAIM:
            digest(value["codeSha256"])
            digest(value["contactRequestSha256"])
        elif operation == OP_RETAIN:
            digest(value["rawResponseSha256"])
            envelope(value["rawResponseEnvelope"])
            require((value["tokenSecretSha256"] is None) == (value["tokenEnvelope"] is None))
            if value["tokenEnvelope"] is not None:
                digest(value["tokenSecretSha256"])
                envelope(value["tokenEnvelope"])
        else:
            digest(value["payloadDigest"])
            digest(value["tokenSecretSha256"])
            require(type(value["metadata"]) is dict and len(canonical(value["metadata"])) <= 32 * 1024)
            require(type(value["review"]) is dict and len(canonical(value["review"])) <= 16 * 1024)
    limits = value["limits"]
    require(type(limits) is dict and set(limits) == {"pendingCapacity", "revocationCapacity"})
    require(all(type(item) is int and 1 <= item <= 64 for item in limits.values()))
    return dict(value)


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping))
    allowed = FIELDS | ({"businessIntent", "authn_evidence"} if typed else set())
    require(FIELDS <= set(value) <= allowed and (not typed or "businessIntent" in value))
    request = request_binding(operation, value["request"])
    require(value["action"] == ACTION and value["resource_id"] == request["exchangeId"]
        and value["approval_id"] is None and digest(value["payload_digest"]) == sha256(canonical(request)))
    actor = text(value["actor_id"], 512)
    require(actor.startswith("oidc:"))
    policy(value["credential_policy"])
    raw = enrollment_bytes(value["enrollment_original"])
    if operation == OP_PREPARE:
        require(sha256(raw) == request["enrollmentSha256"])
    originals = {name: value[name] for name in FIELDS}
    require(len(canonical(originals)) <= MAX_ARGUMENT_BYTES)
    return originals


def row_original(row):
    value = dict(row)
    require(set(value) == ROW_FIELDS)
    require(all((item is None and name in NULLABLE) or type(item) is str for name, item in value.items()))
    raw = canonical(value)
    require(len(raw) <= MAX_ROW_BYTES)
    return raw


def row_digest(row):
    return sha256(row_original(row))


def request_digest(operation, value):
    from serverware import authority_request_commitment as commitment
    return commitment.oauth_exchange_request_digest(operation, value)
