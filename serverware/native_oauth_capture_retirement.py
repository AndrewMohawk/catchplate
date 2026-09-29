"""Closed pre-subject capture retirement data and fixed TLS contact primitives.

This opt-in purpose retires the complete local provider scope. No subject,
pending credential, token isolation or provider-success claim is invented.
"""
import json
import uuid
from collections.abc import Mapping

from serverware import native_oauth_refresh as material
from serverware import oauth_retirement_values as scalar
from serverware.native_oauth_cleanup import Contact as _Contact, request

canonical, require, digest, sha256 = material.canonical, material.require, material.digest, material.sha
b64, unb64, document = material.encoded, material.decoded, material.document
CHANNEL = "serverware.nativeOAuthCaptureRetirementChannel/v1"
CONFIG = "serverware.nativeOAuthCaptureRetirementConfiguration/v1"
TLS = "serverware.nativeOAuthCaptureRetirementTls/v1"
FIELD = "oauthMeasuredCaptureRetirementPolicy"
POLICY_SCHEMA = "serverware.oauthMeasuredCaptureRetirementAuthorityPolicy/v1"
GRANT_SCHEMA = "serverware.oauthMeasuredCaptureRetirementAuthorization/v1"
SIGNED_GRANT_SCHEMA = "serverware.signedOAuthMeasuredCaptureRetirementAuthorization/v1"
PURPOSE = "measured-oauth-pre-subject-provider-retirement"
STATEMENT = "serverware.nativeOAuthCaptureRetirementStatement/v1"
SIGN_OPERATION = "nativeOAuthCaptureRetirement.sign/v1"
SIGNATURE_DOMAIN = STATEMENT.encode("ascii") + b"\0"
ATTESTATION_DOMAIN = b"serverware/native-oauth-capture-retirement-attestation/v1\0"
TRANSPORT_SCHEMA = "serverware.nativeOAuthCaptureRetirementTransport/v1"
HTTP_SCHEMA = "serverware.nativeOAuthCaptureRetirementRequest/v1"
HTTP_RESPONSE = "serverware.nativeOAuthCaptureRetirementResponse/v1"
RUNTIME_RESPONSE = "serverware.policyAuthorityMeasuredCaptureRetirementRuntimeResponse/v1"
HTTP_PATH = "/api/data-plane/oauth-capture-retirement"
OP_INSPECT = "oauth.measured-capture-retirement.inspect"
OP_CLAIM = "oauth.measured-capture-retirement.claim"
OP_CONTACT = "oauth.measured-capture-retirement.contact"
OP_FINISH = "oauth.measured-capture-retirement.finish"
OP_RECOVER = "oauth.measured-capture-retirement.recover"
OPERATIONS = frozenset({OP_INSPECT, OP_CLAIM, OP_CONTACT, OP_FINISH, OP_RECOVER})
TABLE = "oauth_measured_capture_retirement_custody"
JOURNAL_TABLE = "oauth_capture_retirement_reservations"
ATTEMPT_TABLE = "oauth_capture_retirement_attempts"
SOURCES = frozenset({"measured-oauth-exchange/v1", "measured-oauth-setup-exchange/v1"})
MAX_GRANT_BYTES = 64 * 1024
MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_TRANSPORT_BYTES = 384 * 1024
MAX_ROW_BYTES = 6 * 1024 * 1024
MAX_HTTP_REQUEST = 3 * 1024 * 1024
MAX_HTTP_RESPONSE = 8 * 1024 * 1024
MAX_AFFECTED_LINEAGES = 16
MAX_POPULATION = 32
GRANT_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "authorizationId", "configurationDigest",
    "deploymentId", "exchangeId", "workSource", "exchangeRowSha256", "custodyRowSha256", "workRowSha256",
    "captureArgumentsSha256", "enrollmentSha256", "historicalEnrollmentRootSpkiSha256", "rawResponseSha256",
    "rawResponseEnvelopeSha256", "tokenEnvelopeSha256", "tokenSecretSha256", "providerId", "clientId",
    "clientMaterialSha256", "providerConfiguration", "tokenPurposes", "retirementScope", "affectedLineages",
    "setupSessionId", "setupInitialSha256", "setupStartedSha256", "setupCurrentSha256", "applicationMaterialSha256",
    "providerTlsRootSha256", "holderId", "reason", "issuedAtEpochNs", "expiresAtEpochNs"})
FIELDS = frozenset({"exchange_id", "authorization_original", "enrollment_original", "historical_root_original",
    "control_plane_configuration_digest", "assignment_original", "request", "evidence"})
LINEAGE_FIELDS = frozenset({"credentialId", "credentialVersion", "credentialRowSha256", "generationRowSha256"})
BARRIER_FIELDS = frozenset({"credentialId", "credentialVersion", "barrierSha256"})
STATEMENT_FIELDS = frozenset({"apiVersion", "phase", "holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId",
    "deploymentId", "instanceId", "providerId", "enrollmentSha256", "exchangeId", "authorizationSha256", "inputSha256",
    "challenge", "policyHash", "dataPlaneBinarySha256", "issuedAtEpochNs", "expiresAtEpochNs"})
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
OBSERVATION_FIELDS = frozenset({"status", "exchangeOriginal", "issuanceCustodyOriginal", "workOriginal",
    "captureArgumentsOriginal", "enrollmentOriginal", "setupOriginal", "affectedLineages", "journalOriginal",
    "custodyOriginal", "attemptOriginals"})
MUTATION_RESULT_FIELDS = frozenset({"journalOriginal", "attemptOriginal", "custodyOriginal"})
JOURNAL_FIELDS = frozenset({"id", "work_source", "authorization_original", "authorization_sha256", "original_work_json",
    "original_affected_json", "currentness_barriers_json", "claim_request_digest", "owner_nonce_sha256", "status",
    "created_at", "expires_at", "updated_at"})
ATTEMPT_FIELDS = frozenset({"id", "exchange_id", "token_purpose", "contact_request_sha256", "status",
    "transport_original", "transport_sha256", "created_at", "updated_at"})
ROW_FIELDS = frozenset({"id", "authorization_sha256", "claim_original_json", "contact_originals_json",
    "finish_originals_json", "created_at", "updated_at"})


def identifier(value):
    require(type(value) is str and str(uuid.UUID(value)) == value)
    return value


def lineages(values):
    require(type(values) is list and len(values) <= MAX_AFFECTED_LINEAGES)
    ids = []
    for item in values:
        require(type(item) is dict and set(item) == LINEAGE_FIELDS)
        ids.append(identifier(item["credentialId"]))
        material.integer(item["credentialVersion"], maximum=2**63 - 1)
        digest(item["credentialRowSha256"]); digest(item["generationRowSha256"])
    require(ids == sorted(set(ids)))
    return values


def barriers(values, affected):
    lineages(affected)
    require(type(values) is list and len(values) == len(affected))
    for actual, expected in zip(values, affected):
        require(type(actual) is dict and set(actual) == BARRIER_FIELDS
            and actual["credentialId"] == expected["credentialId"]
            and type(actual["credentialVersion"]) is int and actual["credentialVersion"] == expected["credentialVersion"])
        digest(actual["barrierSha256"])
    return values


def payload(value):
    require(type(value) is dict and set(value) == GRANT_FIELDS and value["schema"] == GRANT_SCHEMA
        and value["purpose"] == PURPOSE and value["workSource"] in SOURCES
        and value["providerId"] in {"google", "x"} and value["reason"] in {"abandoned", "expired", "unusable"})
    for name in ("authorizationId", "exchangeId"):
        identifier(value[name])
    if value["workSource"] == "measured-oauth-setup-exchange/v1":
        identifier(value["setupSessionId"])
    else:
        require(value["setupSessionId"] is None)
    for name, item in value.items():
        if name.endswith("Sha256") or name in {"configurationDigest", "holderId"}:
            if name.startswith("setup") and value["workSource"] == "measured-oauth-exchange/v1":
                require(item is None)
            else:
                digest(item); require(item != "sha256:" + "0" * 64)
    for name in ("sourceRevision", "deploymentId", "clientId"):
        material.text(value[name], 512)
    material.integer(value["issuedAtEpochNs"]); material.integer(value["expiresAtEpochNs"])
    require(0 < value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= 300_000_000_000)
    require(value["retirementScope"] == {"profile": "complete-local-provider-retirement/v1",
        "providerId": value["providerId"], "allLocalApplicationsAndSubjects": True,
        "externalRelatedGrantImpactAuthorized": True, "automaticReopen": False})
    # Share only the existing provider/scalar data predicates. The actual
    # signature, purpose, scope and assignment below are never translated.
    scalar.revocation_payload({**{name: value[name] for name in scalar.GRANT_FIELDS - {"schema", "purpose"}},
        "schema": scalar.GRANT_SCHEMA, "purpose": "retained-oauth-revocation"})
    configuration = value["providerConfiguration"]
    from serverware.native_oauth_cleanup import ENDPOINTS
    host, path = ENDPOINTS[value["providerId"]]
    require(configuration["revocationUrl"] == "https://" + host + path)
    require(value["tokenPurposes"] in [["access_token"], ["refresh_token"], ["access_token", "refresh_token"]]
        and (value["providerId"] != "google" or len(value["tokenPurposes"]) == 1))
    lineages(value["affectedLineages"])
    require(len(canonical(value)) <= MAX_GRANT_BYTES - 512)
    return value


def grant_document(raw):
    value = document(raw, MAX_GRANT_BYTES)
    require(set(value) == {"schema", "payload", "signatureBase64Url"} and value["schema"] == SIGNED_GRANT_SCHEMA)
    payload(value["payload"]); unb64(value["signatureBase64Url"], 64, 64)
    return value


def sign_authorization(value, signing_key):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from serverware import authority_contract
    payload(value)
    require(isinstance(signing_key, Ed25519PrivateKey) and value["sourceRevision"] == authority_contract.SOURCE_REVISION)
    raw = canonical(value)
    result = canonical({"schema": SIGNED_GRANT_SCHEMA, "payload": json.loads(raw),
        "signatureBase64Url": b64(signing_key.sign(GRANT_SCHEMA.encode("ascii") + b"\0" + raw))})
    require(len(result) <= MAX_GRANT_BYTES)
    return result


def input_sha256(values):
    return sha256(canonical({name: values[name] for name in FIELDS - {"evidence"}}))


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping)
        and set(value) == FIELDS | ({"businessIntent"} if typed else set()))
    grant = grant_document(unb64(value["authorization_original"], MAX_GRANT_BYTES))["payload"]
    require(value["exchange_id"] == grant["exchangeId"]
        and sha256(unb64(value["enrollment_original"], 32768)) == grant["enrollmentSha256"])
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
        unb64(request["ownerNonce"], 32, 32); digest(request["journalRowSha256"])
        require(request["tokenPurpose"] in grant["tokenPurposes"])
        if operation == OP_CONTACT:
            digest(request["contactRequestSha256"])
        else:
            digest(request["attemptRowSha256"]); unb64(request["transportOriginal"], MAX_TRANSPORT_BYTES)
    proof = value["evidence"]
    require(type(proof) is dict and set(proof) == {"statement", "signature", "nativeKeyEvidence"})
    statement = proof["statement"]
    require(type(statement) is dict and set(statement) == STATEMENT_FIELDS and statement["apiVersion"] == STATEMENT
        and statement["phase"] == operation.rsplit(".", 1)[-1] and statement["exchangeId"] == grant["exchangeId"]
        and statement["authorizationSha256"] == sha256(unb64(value["authorization_original"], MAX_GRANT_BYTES))
        and statement["inputSha256"] == input_sha256(value) and statement["enrollmentSha256"] == grant["enrollmentSha256"]
        and statement["providerId"] == grant["providerId"] and statement["deploymentId"] == grant["deploymentId"])
    for name, item in statement.items():
        if name.endswith("Sha256") or name in {"holderId", "keyId", "controlPlaneResponseSigningKeyId", "policyHash"}:
            digest(item)
    material.text(statement["instanceId"], 4096); unb64(statement["bootId"], 32, 32)
    material.integer(statement["issuedAtEpochNs"]); material.integer(statement["expiresAtEpochNs"])
    require(0 < statement["expiresAtEpochNs"] - statement["issuedAtEpochNs"] <= 30_000_000_000)
    if operation != OP_RECOVER:
        require(statement["holderId"] == grant["holderId"]
            and grant["issuedAtEpochNs"] <= statement["issuedAtEpochNs"] < statement["expiresAtEpochNs"] <= grant["expiresAtEpochNs"])
    unb64(statement["challenge"], 32, 32)
    require(type(proof["signature"]) is str and proof["signature"].startswith("ed25519:")); unb64(proof["signature"][8:], 64, 64)
    native = proof["nativeKeyEvidence"]
    require(type(native) is dict and set(native) == {"apiVersion", "responseProofPublicKey", "attestationDocumentB64"}
        and native["apiVersion"] == "serverware.nativeResponseProofKeyEvidence/v1")
    unb64(native["responseProofPublicKey"], 32, 32); unb64(native["attestationDocumentB64"], 12288)
    result = {name: value[name] for name in FIELDS}
    require(len(canonical(result)) <= MAX_ARGUMENT_BYTES)
    return result


def _row(value, fields, maximum, nullable=()):
    value = dict(value)
    require(set(value) == fields and all(type(item) is str or name in nullable and item is None for name, item in value.items()))
    raw = canonical(value); require(len(raw) <= maximum); return raw


def row_original(value):
    return _row(value, ROW_FIELDS, MAX_ROW_BYTES)


def journal_original(value):
    return _row(value, JOURNAL_FIELDS, MAX_ROW_BYTES)


def attempt_original(value):
    return _row(value, ATTEMPT_FIELDS, 512 * 1024, {"transport_original", "transport_sha256"})


def attempt_id(exchange_id, purpose):
    identifier(exchange_id); require(purpose in {"access_token", "refresh_token"})
    return str(uuid.uuid5(uuid.UUID(exchange_id), "serverware.oauthCaptureRetirementAttempt/v1:" + purpose))


def response_id(exchange_id, purpose):
    identifier(exchange_id); require(purpose in {"access_token", "refresh_token"})
    return str(uuid.uuid5(uuid.UUID(exchange_id), "serverware.oauthCaptureRetirementResponse/v1:" + purpose))


def transport(raw, request_sha256):
    value = document(raw, MAX_TRANSPORT_BYTES)
    require(set(value) == {"schema", "requestSha256", "status", "receivedAtEpochNs", "rawResponseSha256", "rawResponseEnvelope"}
        and value["schema"] == TRANSPORT_SCHEMA and value["requestSha256"] == request_sha256)
    material.integer(value["receivedAtEpochNs"]); digest(value["rawResponseSha256"])
    require(type(value["rawResponseEnvelope"]) is dict and set(value["rawResponseEnvelope"]) == material.ENVELOPE_FIELDS
        and value["rawResponseEnvelope"]["credential_version"] == 1)
    scalar.envelope(value["rawResponseEnvelope"])
    status = value["status"]
    require(status is None or type(status) is int and 200 <= status <= 599)
    return "unknown" if status is None else "accepted" if 200 <= status < 300 else "rejected"


def request_digest(operation, value):
    from serverware import authority_request_commitment as commitment
    return commitment.oauth_measured_capture_retirement_request_digest(operation, value)


class Contact(_Contact):
    _event = TLS


def policy_key(policy, payload, root):
    # Both enclave receipt consumer and measured verifier/planner use this
    # exact independently signed purpose block, never the old cleanup policy.
    from serverware import authority_oauth_measured_capture_retirement_policy as admission
    return admission.validate_policy(policy, payload=payload, root_key=root)


def verify_grant(values, **kwargs):
    from serverware import authority_oauth_measured_capture_retirement_policy as admission
    return admission.verify_grant(values, **kwargs)
