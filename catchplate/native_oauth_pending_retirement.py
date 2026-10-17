"""Separate measured staged-pending retirement data and fixed TLS contact.

No authority/store imports enter the measured helper image. Grant signatures,
exact writer originals and its retained owner authorize each phase separately.
The shared request encoder below supplies bytes, never retirement permission.
"""
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from catchplate import native_oauth_refresh as m
from catchplate.native_oauth_cleanup import Contact as _RetirementContact, ENDPOINTS, request

CHANNEL = "catchplate.nativeOAuthPendingRetirementChannel/v1"
CONFIG = "catchplate.nativeOAuthPendingRetirementConfiguration/v1"
TLS = "catchplate.nativeOAuthPendingRetirementTls/v1"
STATEMENT = "catchplate.nativeOAuthPendingRetirementStatement/v1"
GRANT_SCHEMA = "catchplate.oauthMeasuredPendingRetirementAuthorization/v1"
SIGNED_GRANT = "catchplate.signedOAuthMeasuredPendingRetirementAuthorization/v1"
TRANSPORT_SCHEMA = "catchplate.nativeOAuthPendingRetirementTransport/v1"
POLICY_FIELD = "oauthMeasuredPendingRetirementPolicy"
POLICY = "catchplate.oauthMeasuredPendingRetirementAuthorityPolicy/v1"
MAX_GRANT_BYTES = 64 * 1024
MAX_AFFECTED_LINEAGES = 24
GRANT_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "authorizationId", "configurationDigest", "deploymentId",
    "exchangeId", "exchangeRowSha256", "custodyRowSha256", "pendingId", "initialPendingRowSha256", "currentPendingRowSha256",
    "stageArgumentsSha256", "enrollmentSha256", "historicalEnrollmentRootSpkiSha256", "tokenEnvelopeSha256", "tokenSecretSha256",
    "providerId", "clientId", "clientMaterialSha256", "providerConfiguration", "tokenPurposes", "familyScope", "affectedLineages",
    "applicationMaterialSha256", "providerTlsRootSha256", "holderId", "reason", "issuedAtEpochNs", "expiresAtEpochNs"})
OBSERVATION_FIELDS = frozenset({"status", "exchangeOriginal", "measuredExchangeOriginal", "initialPendingOriginal", "currentPendingOriginal",
    "enrollmentOriginal", "stageArgumentsOriginal", "normalizedEnvelopeOriginal", "normalizedTokenSha256", "affectedLineages",
    "journalOriginal", "custodyOriginal", "attemptOriginals"})
STATEMENT_FIELDS = frozenset({"apiVersion", "phase", "holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId",
    "deploymentId", "instanceId", "providerId", "enrollmentSha256", "pendingId", "authorizationSha256", "inputSha256",
    "challenge", "policyHash", "dataPlaneBinarySha256", "issuedAtEpochNs", "expiresAtEpochNs"})


def identifier(value):
    m.require(type(value) is str and str(uuid.UUID(value)) == value)
    return value


def lineages(values):
    from catchplate import oauth_pending_retirement_values as portable
    return portable.lineages(values)


def barriers(values, affected):
    lineages(affected)
    m.require(type(values) is list and len(values) == len(affected))
    for actual, expected in zip(values, affected):
        m.require(type(actual) is dict and set(actual) == {"credentialId", "credentialVersion", "barrierSha256"}
            and actual["credentialId"] == expected["credentialId"] and type(actual["credentialVersion"]) is int
            and actual["credentialVersion"] == expected["credentialVersion"])
        m.digest(actual["barrierSha256"]); m.require(actual["barrierSha256"] != "sha256:" + "0" * 64)
    return values


def grant_document(raw):
    from catchplate import oauth_pending_retirement_values as portable
    return portable.grant_document(raw)


def _spki(key):
    return m.sha(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


def policy_key(policy, payload, root):
    from catchplate import oauth_pending_retirement_policy as admission
    key = admission.validate_policy(policy, payload=payload, root_key=root)
    m.require(key is not None)
    return key


def verify_grant(values, *, key, configuration_digest, source_revision, deployment_id, now_epoch_ns, historical=False):
    from catchplate import oauth_pending_retirement_policy as admission
    # Keep the native receipt's original narrower enrollment bound; the CP
    # shared verifier independently retains its existing 64 KiB maximum.
    m.decoded(values["enrollment_original"], 32768)
    return admission.verify_grant(values, key=key, configuration_digest=configuration_digest,
        source_revision=source_revision, deployment_id=deployment_id, now_epoch_ns=now_epoch_ns, historical=historical)


def _row(row, fields, maximum, nullable=()):
    m.require(type(row) is dict and set(row) == set(fields.split())
        and all(type(value) is str or name in nullable and value is None for name, value in row.items()))
    identifier(row["id"])
    raw = m.canonical(row); m.require(len(raw) <= maximum); return raw


def journal_original(row):
    return _row(row, "id authorization_original authorization_sha256 original_pending_json original_affected_json "
        "currentness_barriers_json claim_request_digest owner_nonce_sha256 status created_at expires_at updated_at", 4 * 1024 * 1024)


def row_original(row):
    return _row(row, "id authorization_sha256 claim_original_json contact_originals_json finish_originals_json created_at updated_at", 8 * 1024 * 1024)


def attempt_original(row):
    identifier(row["pending_id"])
    return _row(row, "id pending_id token_purpose contact_request_sha256 status transport_original transport_sha256 created_at updated_at",
        512 * 1024, {"transport_original", "transport_sha256"})


def attempt_id(pending_id, purpose):
    m.require(purpose in {"access_token", "refresh_token"})
    return str(uuid.uuid5(uuid.UUID(identifier(pending_id)), "catchplate.oauthPendingRetirementAttempt/v1:" + purpose))


def response_id(pending_id, purpose):
    m.require(purpose in {"access_token", "refresh_token"})
    return str(uuid.uuid5(uuid.UUID(identifier(pending_id)), "catchplate.measuredPendingRetirementResponse/v1:" + purpose))


def transport(raw, request_sha):
    value = m.document(raw, 384 * 1024)
    m.require(set(value) == {"schema", "requestSha256", "status", "receivedAtEpochNs", "rawResponseSha256", "rawResponseEnvelope"}
        and value["schema"] == TRANSPORT_SCHEMA and value["requestSha256"] == request_sha)
    m.integer(value["receivedAtEpochNs"]); m.digest(value["rawResponseSha256"])
    m.require(type(value["rawResponseEnvelope"]) is dict and set(value["rawResponseEnvelope"]) == m.ENVELOPE_FIELDS)
    status = value["status"]
    m.require(status is None or type(status) is int and 200 <= status <= 599)
    return "unknown" if status is None else "accepted" if 200 <= status < 300 else "rejected"


class Contact(_RetirementContact):
    _event = TLS
