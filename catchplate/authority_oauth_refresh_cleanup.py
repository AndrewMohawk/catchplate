"""Independent family-retirement permission; refresh history is not permission."""
from __future__ import annotations

import json
import uuid
from collections.abc import Mapping

from catchplate import authority_oauth_refresh as refresh
from catchplate import authority_oauth_revocation as retained

canonical, require, digest, sha256 = retained.canonical, retained.require, retained.digest, retained.sha256
b64, unb64, document = retained.b64, retained.unb64, retained.document
identifier, text = retained.identifier, retained.text
work_original, attempt_original = retained.work_original, retained.attempt_original
transport, TRANSPORT_SCHEMA = retained.transport, retained.TRANSPORT_SCHEMA
WORK_FIELDS, ATTEMPT_FIELDS = retained.WORK_FIELDS, retained.ATTEMPT_FIELDS
MAX_GRANT_BYTES, MAX_TRANSPORT_BYTES = retained.MAX_GRANT_BYTES, retained.MAX_TRANSPORT_BYTES
MAX_ARGUMENT_BYTES = 384 * 1024
OP_CLAIM = "oauth.refresh-cleanup.claim"
OP_CONTACT = "oauth.refresh-cleanup.contact"
OP_FINISH = "oauth.refresh-cleanup.finish"
OPERATIONS = frozenset({OP_CLAIM, OP_CONTACT, OP_FINISH})
GRANT_SCHEMA = "catchplate.oauthRefreshCleanupAuthorization/v1"
SIGNED_GRANT_SCHEMA = "catchplate.signedOAuthRefreshCleanupAuthorization/v1"
JOURNAL_TABLE = "oauth_refresh_cleanup_reservations"
ATTEMPT_TABLE = "oauth_refresh_cleanup_attempts"
GRANT_FIELDS = (retained.GRANT_FIELDS - {"exchangeId", "exchangeRowSha256"}) | {
    "refreshId", "refreshVersion", "refreshRowSha256", "workId", "workSource", "credentialId", "credentialVersion",
    "credentialRowSha256", "generationRowSha256", "historicalBarrierSha256", "familyScope"}
FIELDS = retained.FIELDS
JOURNAL_FIELDS = (retained.JOURNAL_FIELDS - {"exchange_row_sha256"}) | {
    "refresh_row_sha256", "original_credential_json", "original_generation_json", "currentness_barrier_sha256",
    "claim_request_digest"}


def payload(value):
    require(type(value) is dict and set(value) == GRANT_FIELDS and value["schema"] == GRANT_SCHEMA
        and value["purpose"] == "oauth-refresh-family-retirement" and value["providerId"] in {"google", "x"})
    # Reuse only the closed common data predicates, never exchange permission.
    common = {name: value[name] for name in retained.GRANT_FIELDS - {"schema", "purpose", "exchangeId", "exchangeRowSha256"}}
    retained.payload({**common, "schema": retained.GRANT_SCHEMA, "purpose": "retained-oauth-revocation",
        "exchangeId": value["refreshId"], "exchangeRowSha256": value["refreshRowSha256"]})
    for name in ("refreshId", "workId", "credentialId"):
        identifier(value[name]); require(str(uuid.UUID(value[name])) == value[name])
    refresh._version(value["credentialVersion"])
    refresh._version(value["refreshVersion"])
    require(value["credentialVersion"] == value["refreshVersion"] + int(value["workSource"] == refresh.SUPERSEDED_SOURCE))
    for name in ("refreshRowSha256", "credentialRowSha256", "generationRowSha256", "historicalBarrierSha256"):
        digest(value[name]); require(value[name] != "sha256:" + "0" * 64)
    require(value["workSource"] in {refresh.ISSUED_SOURCE, refresh.SUPERSEDED_SOURCE}
        and (value["workSource"] != refresh.SUPERSEDED_SOURCE or value["providerId"] == "x"))
    scope = value["familyScope"]
    require(type(scope) is dict and set(scope) == {"profile", "familyId", "providerSubject", "providerAccount", "externalFamilyRetirementAuthorized"}
        and scope["profile"] == "provider-family-retirement-v1" and scope["externalFamilyRetirementAuthorized"] is True)
    for name in ("familyId", "providerSubject", "providerAccount"):
        text(scope[name], 512)
    require(len(canonical(value)) <= MAX_GRANT_BYTES - 512)
    return value


def grant_document(raw):
    value = document(raw, MAX_GRANT_BYTES)
    require(set(value) == {"schema", "payload", "signatureBase64Url"} and value["schema"] == SIGNED_GRANT_SCHEMA)
    payload(value["payload"])
    require(len(unb64(value["signatureBase64Url"], 64)) == 64)
    return value


def sign_authorization(value, signing_key):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from catchplate import authority_contract
    payload(value)
    require(isinstance(signing_key, Ed25519PrivateKey) and value["sourceRevision"] == authority_contract.SOURCE_REVISION)
    raw = canonical(value)
    result = canonical({"schema": SIGNED_GRANT_SCHEMA, "payload": json.loads(raw),
        "signatureBase64Url": b64(signing_key.sign(GRANT_SCHEMA.encode("ascii") + b"\0" + raw))})
    require(len(result) <= MAX_GRANT_BYTES)
    return result


def journal_original(row):
    value = dict(row)
    require(set(value) == JOURNAL_FIELDS and all(type(item) is str for item in value.values()))
    raw = canonical(value)
    require(len(raw) <= 2 * 1024 * 1024)
    return raw


def attempt_id(work_id, purpose):
    identifier(work_id)
    require(purpose in {"access_token", "refresh_token"})
    return str(uuid.uuid5(uuid.UUID(work_id), "catchplate.oauthRefreshCleanupAttempt/v1:" + purpose))


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping)
        and set(value) == FIELDS | ({"businessIntent"} if typed else set()))
    grant = grant_document(unb64(value["authorization_original"], MAX_GRANT_BYTES))["payload"]
    require(value["work_id"] == grant["workId"])
    require(sha256(refresh.enrollment_bytes(value["enrollment_original"])) == grant["enrollmentSha256"])
    unb64(value["historical_root_original"], 4096)
    request = value["request"]
    fields = ({"ownerNonceSha256", "currentnessBarrierSha256"} if operation == OP_CLAIM else
        {"journalRowSha256", "ownerNonce", "tokenPurpose", "contactRequestSha256"} if operation == OP_CONTACT else
        {"journalRowSha256", "ownerNonce", "attemptRowSha256", "tokenPurpose", "transportOriginal"})
    require(type(request) is dict and set(request) == fields)
    if operation == OP_CLAIM:
        digest(request["ownerNonceSha256"]); digest(request["currentnessBarrierSha256"])
    else:
        require(len(unb64(request["ownerNonce"], 32)) == 32 and request["tokenPurpose"] in grant["tokenPurposes"])
        digest(request["journalRowSha256"])
        if operation == OP_CONTACT:
            digest(request["contactRequestSha256"])
        else:
            digest(request["attemptRowSha256"]); unb64(request["transportOriginal"], MAX_TRANSPORT_BYTES)
    result = {name: value[name] for name in FIELDS}
    require(len(canonical(result)) <= MAX_ARGUMENT_BYTES)
    return result


def request_digest(operation, value):
    from catchplate import authority_request_commitment as commitment
    return commitment.oauth_refresh_cleanup_request_digest(operation, value)
