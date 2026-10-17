"""Exact current cleanup grants and retained transport data; no success DTO."""
from __future__ import annotations

import base64
import json
import re
import uuid
from collections.abc import Mapping

from catchplate import authority_oauth_exchange as exchange
from catchplate import oauth_retirement_values as values

canonical, require, digest, sha256 = exchange.canonical, exchange.require, exchange.digest, exchange.sha256
identifier, text = exchange.identifier, exchange.text
OP_CLAIM = "oauth.revocation.claim"
OP_CONTACT = "oauth.revocation.contact"
OP_FINISH = "oauth.revocation.finish"
OPERATIONS = frozenset({OP_CLAIM, OP_CONTACT, OP_FINISH})
GRANT_SCHEMA = values.GRANT_SCHEMA
SIGNED_GRANT_SCHEMA = "catchplate.signedOAuthRevocationAuthorization/v1"
TRANSPORT_SCHEMA = "catchplate.oauthRevocationTransport/v1"
GRANT_FIELDS = values.GRANT_FIELDS
PROVIDER_FIELDS = values.PROVIDER_FIELDS
FIELDS = frozenset({"work_id", "authorization_original", "enrollment_original", "historical_root_original", "request"})
JOURNAL_TABLE = "oauth_revocation_reservations"
ATTEMPT_TABLE = "oauth_revocation_attempts"
JOURNAL_FIELDS = frozenset({"id", "authorization_original", "authorization_sha256", "exchange_row_sha256", "original_work_json", "owner_nonce_sha256", "status", "created_at", "expires_at", "updated_at"})
ATTEMPT_FIELDS = frozenset({"id", "work_id", "token_purpose", "contact_request_sha256", "status", "transport_original", "transport_sha256", "created_at", "updated_at"})
WORK_FIELDS = frozenset({"id", "provider_id", "actor_id", "source", "encrypted_secret", "encrypted_dek", "secret_nonce", "secret_ciphertext", "secret_kek_id", "credential_version", "secret_updated_at", "status", "attempts", "last_error", "next_attempt_at", "lease_owner", "lease_until", "created_at", "updated_at"})
MAX_GRANT_BYTES = values.MAX_GRANT_BYTES
MAX_TRANSPORT_BYTES = 128 * 1024
MAX_ARGUMENT_BYTES = 384 * 1024


def b64(raw):
    require(type(raw) is bytes)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64(value, maximum):
    require(type(value) is str and 1 <= len(value) <= (maximum * 4 + 2) // 3
        and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None)
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    require(1 <= len(raw) <= maximum and b64(raw) == value)
    return raw


def document(raw, maximum):
    require(type(raw) is bytes and 2 <= len(raw) <= maximum)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs,
        parse_constant=lambda _: require(False))
    def visit(item, depth=0):
        require(depth <= 8)
        if type(item) is dict:
            require(len(item) <= 32)
            for child in item.values():
                visit(child, depth + 1)
        elif type(item) is list:
            require(len(item) <= 128)
            for child in item:
                visit(child, depth + 1)
        else:
            require(item is None or type(item) in (str, int, bool))
    visit(value)
    require(type(value) is dict and canonical(value) == raw)
    return value


def payload(value):
    return values.revocation_payload(value)


def grant_document(raw):
    value = document(raw, MAX_GRANT_BYTES)
    require(set(value) == {"schema", "payload", "signatureBase64Url"} and value["schema"] == SIGNED_GRANT_SCHEMA)
    payload(value["payload"])
    require(len(unb64(value["signatureBase64Url"], 64)) == 64)
    return value


def sign_authorization(value, signing_key):
    """Administrative producer; possession is not selection of a trust root."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from catchplate import authority_contract
    payload(value)
    require(isinstance(signing_key, Ed25519PrivateKey)
        and value["sourceRevision"] == authority_contract.SOURCE_REVISION)
    raw = canonical(value)
    result = canonical({"schema": SIGNED_GRANT_SCHEMA, "payload": json.loads(raw),
        "signatureBase64Url": b64(signing_key.sign(GRANT_SCHEMA.encode("ascii") + b"\0" + raw))})
    require(len(result) <= MAX_GRANT_BYTES)
    return result


def work_original(row):
    value = dict(row)
    require(set(value) == WORK_FIELDS)
    for name, item in value.items():
        if name in {"attempts", "credential_version"}:
            require(type(item) is int and 0 <= item <= 2**63 - 1)
        else:
            require(type(item) is str or item is None and name in {"last_error", "lease_owner", "lease_until"})
    raw = canonical(value)
    require(len(raw) <= 512 * 1024)
    return raw


def journal_original(row):
    value = dict(row)
    require(set(value) == JOURNAL_FIELDS and all(type(item) is str for item in value.values()))
    raw = canonical(value)
    require(len(raw) <= 1024 * 1024)
    return raw


def attempt_id(work_id, purpose):
    identifier(work_id)
    require(purpose in {"access_token", "refresh_token"})
    return str(uuid.uuid5(uuid.UUID(work_id), "catchplate.oauthRevocationAttempt/v1:" + purpose))


def attempt_original(row):
    value = dict(row)
    require(set(value) == ATTEMPT_FIELDS and all(type(item) is str or item is None
        and name in {"transport_original", "transport_sha256"} for name, item in value.items()))
    raw = canonical(value)
    require(len(raw) <= 256 * 1024)
    return raw


def transport(raw, expected_request):
    value = document(raw, MAX_TRANSPORT_BYTES)
    require(set(value) == {"schema", "contactRequestSha256", "status", "rawHeaders", "bodyBase64url", "errorCode"}
        and value["schema"] == TRANSPORT_SCHEMA and value["contactRequestSha256"] == expected_request)
    if value["status"] is None:
        require(value["rawHeaders"] is None and value["bodyBase64url"] is None and value["errorCode"] == "transport-unknown")
        return "unknown"
    require(type(value["status"]) is int and 200 <= value["status"] <= 599 and value["errorCode"] is None
        and type(value["rawHeaders"]) is list and len(value["rawHeaders"]) <= 128)
    for pair in value["rawHeaders"]:
        require(type(pair) is list and len(pair) == 2 and all(type(item) is str for item in pair))
    require(len(canonical(value["rawHeaders"])) <= 8 * 1024)
    require(value["bodyBase64url"] == "" or len(unb64(value["bodyBase64url"], 64 * 1024)) <= 64 * 1024)
    return "accepted" if 200 <= value["status"] < 300 else "rejected"


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping))
    allowed = FIELDS | ({"businessIntent"} if typed else set())
    require(set(value) == allowed)
    identifier(value["work_id"])
    grant = grant_document(unb64(value["authorization_original"], MAX_GRANT_BYTES))["payload"]
    require(grant["exchangeId"] == value["work_id"])
    original = exchange.enrollment_bytes(value["enrollment_original"])
    require(sha256(original) == grant["enrollmentSha256"])
    unb64(value["historical_root_original"], 4096)
    request = value["request"]
    required = {"ownerNonceSha256"} if operation == OP_CLAIM else {"journalRowSha256", "ownerNonce", "tokenPurpose", "contactRequestSha256"} if operation == OP_CONTACT else {"journalRowSha256", "ownerNonce", "attemptRowSha256", "tokenPurpose", "transportOriginal"}
    require(type(request) is dict and set(request) == required)
    if operation == OP_CLAIM:
        digest(request["ownerNonceSha256"])
    else:
        require(len(unb64(request["ownerNonce"], 32)) == 32)
        digest(request["journalRowSha256"])
        require(request["tokenPurpose"] in grant["tokenPurposes"])
        if operation == OP_CONTACT:
            digest(request["contactRequestSha256"])
        else:
            digest(request["attemptRowSha256"])
            unb64(request["transportOriginal"], MAX_TRANSPORT_BYTES)
    result = {name: value[name] for name in FIELDS}
    require(len(canonical(result)) <= MAX_ARGUMENT_BYTES)
    return result


def request_digest(operation, value):
    from catchplate import authority_request_commitment as commitment
    return commitment.oauth_revocation_request_digest(operation, value)
