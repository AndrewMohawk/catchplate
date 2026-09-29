"""Separate measured staged-pending retirement data and fixed TLS contact.

No authority/store imports enter the measured helper image. Grant signatures,
exact writer originals and its retained owner authorize each phase separately.
The shared request encoder below supplies bytes, never retirement permission.
"""
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from serverware import native_oauth_refresh as m
from serverware.native_oauth_cleanup import Contact as _RetirementContact, ENDPOINTS, request

CHANNEL = "serverware.nativeOAuthPendingRetirementChannel/v1"
CONFIG = "serverware.nativeOAuthPendingRetirementConfiguration/v1"
TLS = "serverware.nativeOAuthPendingRetirementTls/v1"
STATEMENT = "serverware.nativeOAuthPendingRetirementStatement/v1"
GRANT_SCHEMA = "serverware.oauthMeasuredPendingRetirementAuthorization/v1"
SIGNED_GRANT = "serverware.signedOAuthMeasuredPendingRetirementAuthorization/v1"
TRANSPORT_SCHEMA = "serverware.nativeOAuthPendingRetirementTransport/v1"
POLICY_FIELD = "oauthMeasuredPendingRetirementPolicy"
POLICY = "serverware.oauthMeasuredPendingRetirementAuthorityPolicy/v1"
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
    m.require(type(values) is list and len(values) <= MAX_AFFECTED_LINEAGES)
    ids = []
    for entry in values:
        m.require(type(entry) is dict and set(entry) == {"credentialId", "credentialVersion", "credentialRowSha256", "generationRowSha256"})
        ids.append(identifier(entry["credentialId"]))
        m.integer(entry["credentialVersion"], maximum=2**63 - 1); m.require(entry["credentialVersion"] > 0)
        for name in ("credentialRowSha256", "generationRowSha256"):
            m.digest(entry[name]); m.require(entry[name] != "sha256:" + "0" * 64)
    m.require(ids == sorted(set(ids)))
    return values


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
    value = m.document(raw, MAX_GRANT_BYTES)
    m.require(set(value) == {"schema", "payload", "signatureBase64Url"} and value["schema"] == SIGNED_GRANT)
    grant = value["payload"]
    m.require(type(grant) is dict and set(grant) == GRANT_FIELDS and grant["schema"] == GRANT_SCHEMA
        and grant["purpose"] == "measured-oauth-staged-pending-family-retirement"
        and grant["reason"] in {"cancelled", "expired", "rejected"} and grant["providerId"] in ENDPOINTS
        and grant["tokenPurposes"] in [["access_token"], ["refresh_token"], ["access_token", "refresh_token"]])
    for name, item in grant.items():
        if name.endswith("Sha256") or name in {"configurationDigest", "holderId"}:
            m.digest(item); m.require(item != "sha256:" + "0" * 64)
    for name in ("authorizationId", "exchangeId", "pendingId"):
        identifier(grant[name])
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        m.integer(grant[name])
    m.require(0 < grant["expiresAtEpochNs"] - grant["issuedAtEpochNs"] <= 300_000_000_000)
    if grant["providerId"] == "google":
        m.require(len(grant["tokenPurposes"]) == 1)
    scope = grant["familyScope"]
    m.require(type(scope) is dict and set(scope) == {"profile", "familyId", "providerSubject", "providerAccount", "externalFamilyRetirementAuthorized"}
        and scope["profile"] == "provider-family-retirement-v1" and scope["externalFamilyRetirementAuthorized"] is True)
    for name in ("familyId", "providerSubject", "providerAccount"):
        m.text(scope[name], 512)
    lineages(grant["affectedLineages"])
    m.decoded(value["signatureBase64Url"], 64, 64)
    return value


def _spki(key):
    return m.sha(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


def policy_key(policy, payload, root):
    m.require(type(policy) is dict and set(policy) == {"schema", "grantRootPublicKeyBase64Url", "grantRootSpkiSha256",
        "controlPlaneConfigurationDigest", "deploymentId", "trustRoots", "assignments"} and policy["schema"] == POLICY)
    key = Ed25519PublicKey.from_public_bytes(m.decoded(policy["grantRootPublicKeyBase64Url"], 32, 32))
    pin = _spki(key)
    m.require(pin == policy["grantRootSpkiSha256"] and pin != _spki(root)
        and type(policy["assignments"]) is list and 1 <= len(policy["assignments"]) <= 32)
    for role in payload["roles"].values():
        m.require(pin not in role.values())
    for name, other in payload.items():
        if name != POLICY_FIELD and type(other) is dict:
            m.require(pin not in other.values())
    return key


def verify_grant(values, *, key, configuration_digest, source_revision, deployment_id, now_epoch_ns, historical=False):
    signed = grant_document(m.decoded(values["authorization_original"], MAX_GRANT_BYTES)); grant = signed["payload"]
    m.require(grant["deploymentId"] == deployment_id)
    if not historical:
        m.require(grant["configurationDigest"] == configuration_digest and grant["sourceRevision"] == source_revision
            and grant["issuedAtEpochNs"] <= now_epoch_ns < grant["expiresAtEpochNs"])
    key.verify(m.decoded(signed["signatureBase64Url"], 64, 64), GRANT_SCHEMA.encode("ascii") + b"\0" + m.canonical(grant))
    root_raw = m.decoded(values["historical_root_original"], 4096)
    historical_key = serialization.load_pem_public_key(root_raw)
    m.require(isinstance(historical_key, Ed25519PublicKey) and historical_key.public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo) == root_raw and _spki(historical_key) == grant["historicalEnrollmentRootSpkiSha256"]
        and _spki(historical_key) != _spki(key))
    enrollment_raw = m.decoded(values["enrollment_original"], 32768)
    original = m.document(enrollment_raw, 32768, exact=False); application = original["payload"]
    m.require(m.sha(enrollment_raw) == grant["enrollmentSha256"] and application["deploymentId"] == grant["deploymentId"]
        and application["providerId"] == grant["providerId"] and application["clientId"] == grant["clientId"]
        and application["clientMaterialSha256"] == grant["clientMaterialSha256"]
        and application["providerConfigurationSha256"] == m.sha(m.canonical(grant["providerConfiguration"])))
    historical_key.verify(m.decoded(original["signatureBase64Url"], 64, 64),
        b"serverware.oauthApplicationEnrollment/v1\0" + m.canonical(application))
    return grant, application


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
    return str(uuid.uuid5(uuid.UUID(identifier(pending_id)), "serverware.oauthPendingRetirementAttempt/v1:" + purpose))


def response_id(pending_id, purpose):
    m.require(purpose in {"access_token", "refresh_token"})
    return str(uuid.uuid5(uuid.UUID(identifier(pending_id)), "serverware.measuredPendingRetirementResponse/v1:" + purpose))


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
