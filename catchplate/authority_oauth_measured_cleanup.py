"""Closed measured family-retirement originals; no issuance permission.

The ordinary cleanup grant and its source labels remain separate. Native proof
is required on every phase, and recovery has no contact or mutation command.
"""
from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from catchplate import authority_oauth_refresh_cleanup as ordinary
from catchplate import authority_oauth_measured_refresh as measured
from catchplate import native_oauth_refresh as material

canonical, require, digest, sha256 = ordinary.canonical, ordinary.require, ordinary.digest, ordinary.sha256
b64, unb64, document = ordinary.b64, ordinary.unb64, ordinary.document
refresh = ordinary.refresh
work_original = ordinary.work_original
journal_original, attempt_id = ordinary.journal_original, ordinary.attempt_id
WORK_FIELDS, ATTEMPT_FIELDS = ordinary.WORK_FIELDS, ordinary.ATTEMPT_FIELDS
JOURNAL_TABLE, ATTEMPT_TABLE = ordinary.JOURNAL_TABLE, ordinary.ATTEMPT_TABLE
MAX_GRANT_BYTES = ordinary.MAX_GRANT_BYTES
MAX_TRANSPORT_BYTES = 384 * 1024
MAX_ARGUMENT_BYTES = 1024 * 1024
ISSUED_SOURCE, SUPERSEDED_SOURCE = measured.ISSUED_SOURCE, measured.SUPERSEDED_SOURCE
OP_INSPECT = "oauth.measured-refresh-cleanup.inspect"
OP_CLAIM = "oauth.measured-refresh-cleanup.claim"
OP_CONTACT = "oauth.measured-refresh-cleanup.contact"
OP_FINISH = "oauth.measured-refresh-cleanup.finish"
OP_RECOVER = "oauth.measured-refresh-cleanup.recover"
OPERATIONS = frozenset({OP_INSPECT, OP_CLAIM, OP_CONTACT, OP_FINISH, OP_RECOVER})
GRANT_SCHEMA = "catchplate.oauthMeasuredRefreshCleanupAuthorization/v1"
SIGNED_GRANT_SCHEMA = "catchplate.signedOAuthMeasuredRefreshCleanupAuthorization/v1"
STATEMENT = "catchplate.nativeOAuthRefreshCleanupStatement/v1"
SIGN_OPERATION = "nativeOAuthRefreshCleanup.sign/v1"
SIGNATURE_DOMAIN = STATEMENT.encode("ascii") + b"\0"
ATTESTATION_DOMAIN = b"catchplate/native-oauth-refresh-cleanup-attestation/v1\0"
TRANSPORT_SCHEMA = "catchplate.nativeOAuthRefreshCleanupTransport/v1"
TABLE = "oauth_measured_refresh_cleanup_custody"
GRANT_FIELDS = ordinary.GRANT_FIELDS | {"custodyRowSha256", "applicationMaterialSha256", "providerTlsRootSha256", "holderId"}
FIELDS = ordinary.FIELDS | {"control_plane_configuration_digest", "assignment_original", "evidence"}
ROW_FIELDS = frozenset({"id", "authorization_sha256", "claim_original_json", "contact_originals_json", "finish_originals_json", "created_at", "updated_at"})
STATEMENT_FIELDS = (measured.STATEMENT_FIELDS - {"refreshId"}) | {"workId", "authorizationSha256"}


def payload(value):
    require(type(value) is dict and set(value) == GRANT_FIELDS and value["schema"] == GRANT_SCHEMA
        and value["purpose"] == "measured-oauth-refresh-family-retirement")
    require(value["workSource"] in {ISSUED_SOURCE, SUPERSEDED_SOURCE})
    # Only common scalar/data predicates are shared. Signature admission below
    # always uses the unmodified measured original and its distinct domain.
    view = {name: value[name] for name in ordinary.GRANT_FIELDS}
    view.update(schema=ordinary.GRANT_SCHEMA, purpose="oauth-refresh-family-retirement",
        workSource=refresh.ISSUED_SOURCE if value["workSource"] == ISSUED_SOURCE else refresh.SUPERSEDED_SOURCE)
    ordinary.payload(view)
    for name in ("custodyRowSha256", "applicationMaterialSha256", "providerTlsRootSha256", "holderId"):
        digest(value[name]); require(value[name] != "sha256:" + "0" * 64)
    require(len(canonical(value)) <= MAX_GRANT_BYTES - 512)
    return value


def grant_document(raw):
    value = document(raw, MAX_GRANT_BYTES)
    require(set(value) == {"schema", "payload", "signatureBase64Url"} and value["schema"] == SIGNED_GRANT_SCHEMA)
    payload(value["payload"]); require(len(unb64(value["signatureBase64Url"], 64)) == 64)
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


def row_original(row):
    value = dict(row)
    require(set(value) == ROW_FIELDS and all(type(item) is str for item in value.values()))
    raw = canonical(value); require(len(raw) <= 4 * 1024 * 1024)
    return raw


def attempt_original(row):
    value = dict(row)
    require(set(value) == ATTEMPT_FIELDS and all(type(item) is str or item is None
        and name in {"transport_original", "transport_sha256"} for name, item in value.items()))
    raw = canonical(value)
    require(len(raw) <= 512 * 1024)
    return raw


def input_sha256(values):
    return sha256(canonical({name: values[name] for name in FIELDS - {"evidence"}}))


def transport(raw, request_sha256):
    value = document(raw, MAX_TRANSPORT_BYTES)
    require(set(value) == {"schema", "requestSha256", "status", "receivedAtEpochNs", "rawResponseSha256", "rawResponseEnvelope"}
        and value["schema"] == TRANSPORT_SCHEMA and value["requestSha256"] == request_sha256)
    material.integer(value["receivedAtEpochNs"])
    digest(value["rawResponseSha256"])
    refresh.envelope(value["rawResponseEnvelope"], 1)
    status = value["status"]
    require(status is None or type(status) is int and 200 <= status <= 599)
    return "unknown" if status is None else "accepted" if 200 <= status < 300 else "rejected"


def response_id(work_id, purpose):
    require(purpose in {"access_token", "refresh_token"})
    return str(uuid.uuid5(uuid.UUID(work_id), "catchplate.measuredRefreshCleanupResponse/v1:" + purpose))


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping)
        and set(value) == FIELDS | ({"businessIntent"} if typed else set()))
    grant = grant_document(unb64(value["authorization_original"], MAX_GRANT_BYTES))["payload"]
    require(value["work_id"] == grant["workId"]
        and sha256(refresh.enrollment_bytes(value["enrollment_original"])) == grant["enrollmentSha256"])
    digest(value["control_plane_configuration_digest"])
    if operation != OP_RECOVER:
        require(value["control_plane_configuration_digest"] == grant["configurationDigest"])
    unb64(value["historical_root_original"], 4096)
    require(value["assignment_original"] is None or type(value["assignment_original"]) is dict)
    request = value["request"]
    names = ({"issuedAtEpochNs", "expiresAtEpochNs"} if operation in {OP_INSPECT, OP_RECOVER} else
        {"ownerNonceSha256", "currentnessBarrierSha256"} if operation == OP_CLAIM else
        {"journalRowSha256", "ownerNonce", "tokenPurpose", "contactRequestSha256"} if operation == OP_CONTACT else
        {"journalRowSha256", "ownerNonce", "attemptRowSha256", "tokenPurpose", "transportOriginal"})
    require(type(request) is dict and set(request) == names)
    if operation in {OP_INSPECT, OP_RECOVER}:
        material.integer(request["issuedAtEpochNs"]); material.integer(request["expiresAtEpochNs"])
        require(0 < request["expiresAtEpochNs"] - request["issuedAtEpochNs"] <= 30_000_000_000)
    elif operation == OP_CLAIM:
        digest(request["ownerNonceSha256"]); digest(request["currentnessBarrierSha256"])
    else:
        require(len(unb64(request["ownerNonce"], 32)) == 32 and request["tokenPurpose"] in grant["tokenPurposes"])
        digest(request["journalRowSha256"])
        if operation == OP_CONTACT:
            digest(request["contactRequestSha256"])
        else:
            digest(request["attemptRowSha256"]); unb64(request["transportOriginal"], MAX_TRANSPORT_BYTES)
    evidence = value["evidence"]
    require(type(evidence) is dict and set(evidence) == {"statement", "signature", "nativeKeyEvidence"})
    statement = evidence["statement"]
    require(type(statement) is dict and set(statement) == STATEMENT_FIELDS and statement["apiVersion"] == STATEMENT
        and statement["phase"] == operation.rsplit(".", 1)[-1]
        and statement["workId"] == grant["workId"] and statement["credentialId"] == grant["credentialId"]
        and statement["credentialVersion"] == grant["credentialVersion"]
        and statement["authorizationSha256"] == sha256(unb64(value["authorization_original"], MAX_GRANT_BYTES))
        and statement["inputSha256"] == input_sha256(value) and statement["enrollmentSha256"] == grant["enrollmentSha256"]
        and statement["providerId"] == grant["providerId"] and statement["deploymentId"] == grant["deploymentId"])
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        material.integer(statement[name])
    require(0 < statement["expiresAtEpochNs"] - statement["issuedAtEpochNs"] <= 30_000_000_000)
    if operation != OP_RECOVER:
        require(statement["holderId"] == grant["holderId"]
            and grant["issuedAtEpochNs"] <= statement["issuedAtEpochNs"] < statement["expiresAtEpochNs"] <= grant["expiresAtEpochNs"])
    require(len(unb64(statement["challenge"], 32)) == 32 and type(evidence["signature"]) is str
        and evidence["signature"].startswith("ed25519:") and len(unb64(evidence["signature"][8:], 64)) == 64)
    native = evidence["nativeKeyEvidence"]
    require(type(native) is dict and set(native) == {"apiVersion", "responseProofPublicKey", "attestationDocumentB64"}
        and native["apiVersion"] == "catchplate.nativeResponseProofKeyEvidence/v1"
        and len(unb64(native["responseProofPublicKey"], 32)) == 32)
    unb64(native["attestationDocumentB64"], 12 * 1024)
    result = {name: value[name] for name in FIELDS}
    require(len(canonical(result)) <= MAX_ARGUMENT_BYTES)
    return result


def request_digest(operation, value):
    from catchplate import authority_request_commitment as commitment
    return commitment.oauth_measured_cleanup_request_digest(operation, value)
