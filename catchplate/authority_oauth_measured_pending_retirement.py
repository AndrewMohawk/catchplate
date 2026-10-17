"""Closed originals for independently authorized staged-pending family retirement.

These data predicates grant no permission. Actual authority roles separately
verify the purpose signature, native assignment and authenticated row originals.
The pending target is never a refresh work item or a fictitious credential.
"""
from __future__ import annotations

import json
import uuid
from collections.abc import Mapping

from catchplate import authority_oauth_revocation as retained
from catchplate import authority_oauth_refresh as refresh
from catchplate import authority_oauth_measured_refresh as measured
from catchplate import native_oauth_refresh as material

canonical, require, digest, sha256 = retained.canonical, retained.require, retained.digest, retained.sha256
b64, unb64, document = retained.b64, retained.unb64, retained.document
OP_INSPECT = "oauth.measured-pending-retirement.inspect"
OP_CLAIM = "oauth.measured-pending-retirement.claim"
OP_CONTACT = "oauth.measured-pending-retirement.contact"
OP_FINISH = "oauth.measured-pending-retirement.finish"
OP_RECOVER = "oauth.measured-pending-retirement.recover"
OPERATIONS = frozenset({OP_INSPECT, OP_CLAIM, OP_CONTACT, OP_FINISH, OP_RECOVER})
GRANT_SCHEMA = "catchplate.oauthMeasuredPendingRetirementAuthorization/v1"
SIGNED_GRANT_SCHEMA = "catchplate.signedOAuthMeasuredPendingRetirementAuthorization/v1"
PURPOSE = "measured-oauth-staged-pending-family-retirement"
STATEMENT = "catchplate.nativeOAuthPendingRetirementStatement/v1"
SIGN_OPERATION = "nativeOAuthPendingRetirement.sign/v1"
SIGNATURE_DOMAIN = STATEMENT.encode("ascii") + b"\0"
ATTESTATION_DOMAIN = b"catchplate/native-oauth-pending-retirement-attestation/v1\0"
TRANSPORT_SCHEMA = "catchplate.nativeOAuthPendingRetirementTransport/v1"
HTTP_SCHEMA = "catchplate.nativeOAuthPendingRetirementRequest/v1"
HTTP_RESPONSE = "catchplate.nativeOAuthPendingRetirementResponse/v1"
RUNTIME_RESPONSE = "catchplate.policyAuthorityMeasuredPendingRetirementRuntimeResponse/v1"
HTTP_PATH = "/api/data-plane/oauth-pending-retirement"
TABLE = "oauth_measured_pending_retirement_custody"
JOURNAL_TABLE = "oauth_pending_retirement_reservations"
ATTEMPT_TABLE = "oauth_pending_retirement_attempts"
FAMILY_TABLE = "oauth_pending_family_retirements"
MAX_GRANT_BYTES = 64 * 1024
MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_TRANSPORT_BYTES = 384 * 1024
MAX_ROW_BYTES = 4 * 1024 * 1024
MAX_AFFECTED_LINEAGES = 24
MAX_HTTP_REQUEST = 3 * 1024 * 1024
MAX_HTTP_RESPONSE = 8 * 1024 * 1024

GRANT_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "authorizationId", "configurationDigest",
    "deploymentId", "exchangeId", "exchangeRowSha256", "custodyRowSha256", "pendingId", "initialPendingRowSha256",
    "currentPendingRowSha256", "stageArgumentsSha256", "enrollmentSha256", "historicalEnrollmentRootSpkiSha256",
    "tokenEnvelopeSha256", "tokenSecretSha256", "providerId", "clientId", "clientMaterialSha256", "providerConfiguration",
    "tokenPurposes", "familyScope", "affectedLineages", "applicationMaterialSha256", "providerTlsRootSha256",
    "holderId", "reason", "issuedAtEpochNs", "expiresAtEpochNs"})
FIELDS = frozenset({"pending_id", "authorization_original", "enrollment_original", "historical_root_original",
    "control_plane_configuration_digest", "assignment_original", "request", "evidence"})
LINEAGE_FIELDS = frozenset({"credentialId", "credentialVersion", "credentialRowSha256", "generationRowSha256"})
BARRIER_FIELDS = frozenset({"credentialId", "credentialVersion", "barrierSha256"})
STATEMENT_FIELDS = (measured.STATEMENT_FIELDS - {"refreshId", "credentialId", "credentialVersion"}) | {
    "pendingId", "authorizationSha256"}
REQUEST_FIELDS = {
    OP_INSPECT: frozenset({"issuedAtEpochNs", "expiresAtEpochNs"}),
    OP_RECOVER: frozenset({"issuedAtEpochNs", "expiresAtEpochNs"}),
    OP_CLAIM: frozenset({"ownerNonceSha256", "currentnessBarriers"}),
    OP_CONTACT: frozenset({"journalRowSha256", "ownerNonce", "tokenPurpose", "contactRequestSha256"}),
    OP_FINISH: frozenset({"journalRowSha256", "ownerNonce", "attemptRowSha256", "tokenPurpose", "transportOriginal"}),
}
HTTP_REQUEST_FIELDS = frozenset({"apiVersion", "operation", "arguments"})
HTTP_RESPONSE_FIELDS = frozenset({"apiVersion", "requestOriginal", "responseOriginal", "currentnessBarriers"})
RESULT_FIELDS = frozenset({"ok", "operation", "requestDigest", "auditEventDigest", "idempotentReplay", "payload"})
OBSERVATION_FIELDS = frozenset({"status", "exchangeOriginal", "measuredExchangeOriginal", "initialPendingOriginal",
    "currentPendingOriginal", "enrollmentOriginal", "stageArgumentsOriginal", "normalizedEnvelopeOriginal",
    "normalizedTokenSha256", "affectedLineages", "journalOriginal", "custodyOriginal", "attemptOriginals"})
AFFECTED_ORIGINAL_FIELDS = frozenset({"credentialOriginal", "generationOriginal"})
MUTATION_RESULT_FIELDS = frozenset({"journalOriginal", "attemptOriginal", "custodyOriginal"})
TRANSPORT_FIELDS = frozenset({"schema", "requestSha256", "status", "receivedAtEpochNs", "rawResponseSha256", "rawResponseEnvelope"})
JOURNAL_FIELDS = frozenset({"id", "authorization_original", "authorization_sha256", "original_pending_json",
    "original_affected_json", "currentness_barriers_json", "claim_request_digest", "owner_nonce_sha256", "status",
    "created_at", "expires_at", "updated_at"})
ATTEMPT_FIELDS = (retained.ATTEMPT_FIELDS - {"work_id"}) | {"pending_id"}
ROW_FIELDS = frozenset({"id", "authorization_sha256", "claim_original_json", "contact_originals_json",
    "finish_originals_json", "created_at", "updated_at"})
FAMILY_FIELDS = frozenset({"id", "provider_id", "provider_subject", "authorization_sha256", "pending_id",
    "claim_request_digest", "created_at"})


def _uuid(value):
    require(type(value) is str and str(uuid.UUID(value)) == value)
    return value


def lineages(values):
    from catchplate import oauth_pending_retirement_values as portable
    return portable.lineages(values)


def barriers(values, affected):
    lineages(affected)
    require(type(values) is list and len(values) == len(affected))
    for actual, expected in zip(values, affected):
        require(type(actual) is dict and set(actual) == BARRIER_FIELDS
            and actual["credentialId"] == expected["credentialId"]
            and type(actual["credentialVersion"]) is int
            and actual["credentialVersion"] == expected["credentialVersion"])
        digest(actual["barrierSha256"]); require(actual["barrierSha256"] != "sha256:" + "0" * 64)
    return values


def payload(value):
    from catchplate import oauth_pending_retirement_values as portable
    return portable.payload(value)


def grant_document(raw):
    from catchplate import oauth_pending_retirement_values as portable
    return portable.grant_document(raw)


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


def input_sha256(values):
    return sha256(canonical({name: values[name] for name in FIELDS - {"evidence"}}))


def array_document(raw, maximum):
    require(type(raw) is bytes and 2 <= len(raw) <= maximum)
    wrapped = document(b'{"items":' + raw + b'}', maximum + 10)
    require(set(wrapped) == {"items"} and type(wrapped["items"]) is list and canonical(wrapped["items"]) == raw)
    return wrapped["items"]


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping)
        and set(value) == FIELDS | ({"businessIntent"} if typed else set()))
    grant = grant_document(unb64(value["authorization_original"], MAX_GRANT_BYTES))["payload"]
    require(value["pending_id"] == grant["pendingId"]
        and sha256(refresh.enrollment_bytes(value["enrollment_original"])) == grant["enrollmentSha256"])
    digest(value["control_plane_configuration_digest"])
    if operation != OP_RECOVER:
        require(value["control_plane_configuration_digest"] == grant["configurationDigest"])
    unb64(value["historical_root_original"], 4096)
    require(value["assignment_original"] is None or type(value["assignment_original"]) is dict)
    request = value["request"]
    require(type(request) is dict and set(request) == REQUEST_FIELDS[operation])
    if operation in {OP_INSPECT, OP_RECOVER}:
        material.integer(request["issuedAtEpochNs"]); material.integer(request["expiresAtEpochNs"])
        require(0 < request["expiresAtEpochNs"] - request["issuedAtEpochNs"] <= 30_000_000_000)
    elif operation == OP_CLAIM:
        digest(request["ownerNonceSha256"]); barriers(request["currentnessBarriers"], grant["affectedLineages"])
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
        and statement["phase"] == operation.rsplit(".", 1)[-1] and statement["pendingId"] == grant["pendingId"]
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


def transport(raw, request_sha256):
    value = document(raw, MAX_TRANSPORT_BYTES)
    require(set(value) == TRANSPORT_FIELDS and value["schema"] == TRANSPORT_SCHEMA
        and value["requestSha256"] == request_sha256)
    material.integer(value["receivedAtEpochNs"]); digest(value["rawResponseSha256"])
    refresh.envelope(value["rawResponseEnvelope"], 1)
    status = value["status"]
    require(status is None or type(status) is int and 200 <= status <= 599)
    return "unknown" if status is None else "accepted" if 200 <= status < 300 else "rejected"


def _row(row, fields, maximum):
    value = dict(row)
    require(set(value) == fields and all(type(item) is str for item in value.values()))
    _uuid(value["id"])
    raw = canonical(value); require(len(raw) <= maximum)
    return raw


def journal_original(row):
    return _row(row, JOURNAL_FIELDS, 2 * 1024 * 1024)


def row_original(row):
    return _row(row, ROW_FIELDS, MAX_ROW_BYTES)


def attempt_original(row):
    value = dict(row)
    require(set(value) == ATTEMPT_FIELDS and all(type(item) is str or item is None
        and name in {"transport_original", "transport_sha256"} for name, item in value.items()))
    _uuid(value["id"]); _uuid(value["pending_id"])
    raw = canonical(value); require(len(raw) <= 512 * 1024)
    return raw


def attempt_id(pending_id, purpose):
    _uuid(pending_id); require(purpose in {"access_token", "refresh_token"})
    return str(uuid.uuid5(uuid.UUID(pending_id), "catchplate.oauthPendingRetirementAttempt/v1:" + purpose))


def response_id(pending_id, purpose):
    _uuid(pending_id); require(purpose in {"access_token", "refresh_token"})
    return str(uuid.uuid5(uuid.UUID(pending_id), "catchplate.measuredPendingRetirementResponse/v1:" + purpose))


def request_digest(operation, value):
    from catchplate import authority_request_commitment as commitment
    return commitment.oauth_measured_pending_retirement_request_digest(operation, value)
