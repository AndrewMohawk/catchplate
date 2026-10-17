"""Fixed measured revocation contact data; never a token export service."""
import base64
import urllib.parse
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from catchplate import native_oauth_refresh as m
from catchplate.native_oauth_refresh_tls import Contact as _RefreshContact

CHANNEL = "catchplate.nativeOAuthRefreshCleanupChannel/v1"
CONFIG = "catchplate.nativeOAuthRefreshCleanupConfiguration/v1"
TLS = "catchplate.nativeOAuthRefreshCleanupTls/v1"
ENDPOINTS = {"google": ("oauth2.googleapis.com", "/revoke"), "x": ("api.twitter.com", "/2/oauth2/revoke")}
MAX_GRANT_BYTES = 64 * 1024
ISSUED_SOURCE = "measured-oauth-refresh-issued/v1"
SUPERSEDED_SOURCE = "measured-oauth-refresh-superseded/v1"
TRANSPORT_SCHEMA = "catchplate.nativeOAuthRefreshCleanupTransport/v1"
GRANT_SCHEMA = "catchplate.oauthMeasuredRefreshCleanupAuthorization/v1"
GRANT_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "authorizationId", "configurationDigest", "deploymentId",
    "refreshId", "refreshVersion", "refreshRowSha256", "workId", "workSource", "credentialId", "credentialVersion",
    "credentialRowSha256", "generationRowSha256", "historicalBarrierSha256", "familyScope", "workRowSha256", "enrollmentSha256",
    "historicalEnrollmentRootSpkiSha256", "tokenEnvelopeSha256", "tokenSecretSha256", "providerId", "clientId",
    "clientMaterialSha256", "providerConfiguration", "tokenPurposes", "issuedAtEpochNs", "expiresAtEpochNs",
    "custodyRowSha256", "applicationMaterialSha256", "providerTlsRootSha256", "holderId"})


def grant_document(raw):
    value = m.document(raw, MAX_GRANT_BYTES)
    m.require(set(value) == {"schema", "payload", "signatureBase64Url"}
        and value["schema"] == "catchplate.signedOAuthMeasuredRefreshCleanupAuthorization/v1")
    grant = value["payload"]
    m.require(type(grant) is dict and set(grant) == GRANT_FIELDS and grant["schema"] == GRANT_SCHEMA
        and grant["purpose"] == "measured-oauth-refresh-family-retirement" and grant["providerId"] in ENDPOINTS
        and grant["workSource"] in {ISSUED_SOURCE, SUPERSEDED_SOURCE}
        and grant["tokenPurposes"] in [["access_token"], ["refresh_token"], ["access_token", "refresh_token"]])
    for name, item in grant.items():
        if name.endswith("Sha256") or name in {"configurationDigest", "holderId"}:
            m.digest(item)
    for name in ("authorizationId", "refreshId", "workId", "credentialId"):
        m.require(type(grant[name]) is str and str(uuid.UUID(grant[name])) == grant[name])
    for name in ("refreshVersion", "credentialVersion", "issuedAtEpochNs", "expiresAtEpochNs"):
        m.integer(grant[name])
    m.require(grant["credentialVersion"] == grant["refreshVersion"] + int(grant["workSource"] == SUPERSEDED_SOURCE)
        and 0 < grant["expiresAtEpochNs"] - grant["issuedAtEpochNs"] <= 300_000_000_000)
    if grant["providerId"] == "google":
        m.require(grant["workSource"] == ISSUED_SOURCE and len(grant["tokenPurposes"]) == 1)
    scope = grant["familyScope"]
    m.require(type(scope) is dict and set(scope) == {"profile", "familyId", "providerSubject", "providerAccount", "externalFamilyRetirementAuthorized"}
        and scope["profile"] == "provider-family-retirement-v1" and scope["externalFamilyRetirementAuthorized"] is True)
    m.decoded(value["signatureBase64Url"], 64, 64)
    return value


def _spki(key):
    return m.sha(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


def policy_key(policy, payload, root):
    m.require(type(policy) is dict and set(policy) == {"schema", "grantRootPublicKeyBase64Url", "grantRootSpkiSha256",
        "controlPlaneConfigurationDigest", "deploymentId", "trustRoots", "assignments"}
        and policy["schema"] == "catchplate.oauthMeasuredRefreshCleanupAuthorityPolicy/v1")
    key = Ed25519PublicKey.from_public_bytes(m.decoded(policy["grantRootPublicKeyBase64Url"], 32, 32))
    pin = _spki(key)
    m.require(pin == policy["grantRootSpkiSha256"] and pin != _spki(root)
        and type(policy["assignments"]) is list and 1 <= len(policy["assignments"]) <= 32)
    for role in payload["roles"].values():
        m.require(pin not in role.values())
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
        b"catchplate.oauthApplicationEnrollment/v1\0" + m.canonical(application))
    return grant, application


def _row(row, fields, maximum, nullable=()):
    m.require(type(row) is dict and set(row) == set(fields.split())
        and all(type(value) is str or name in nullable and value is None for name, value in row.items()))
    raw = m.canonical(row); m.require(len(raw) <= maximum); return raw


def journal_original(row):
    return _row(row, "id authorization_original authorization_sha256 refresh_row_sha256 original_work_json original_credential_json "
        "original_generation_json currentness_barrier_sha256 claim_request_digest owner_nonce_sha256 status created_at expires_at updated_at", 2 * 1024 * 1024)


def row_original(row):
    return _row(row, "id authorization_sha256 claim_original_json contact_originals_json finish_originals_json created_at updated_at", 4 * 1024 * 1024)


def attempt_original(row):
    return _row(row, "id work_id token_purpose contact_request_sha256 status transport_original transport_sha256 created_at updated_at",
        512 * 1024, {"transport_original", "transport_sha256"})


def attempt_id(work_id, purpose):
    m.require(purpose in {"access_token", "refresh_token"})
    return str(uuid.uuid5(uuid.UUID(work_id), "catchplate.oauthRefreshCleanupAttempt/v1:" + purpose))


def response_id(work_id, purpose):
    m.require(purpose in {"access_token", "refresh_token"})
    return str(uuid.uuid5(uuid.UUID(work_id), "catchplate.measuredRefreshCleanupResponse/v1:" + purpose))


def transport(raw, request_sha):
    value = m.document(raw, 384 * 1024)
    m.require(set(value) == {"schema", "requestSha256", "status", "receivedAtEpochNs", "rawResponseSha256", "rawResponseEnvelope"}
        and value["schema"] == TRANSPORT_SCHEMA and value["requestSha256"] == request_sha)
    m.integer(value["receivedAtEpochNs"]); m.digest(value["rawResponseSha256"])
    m.require(type(value["rawResponseEnvelope"]) is dict and set(value["rawResponseEnvelope"]) == m.ENVELOPE_FIELDS)
    status = value["status"]
    m.require(status is None or type(status) is int and 200 <= status <= 599)
    return "unknown" if status is None else "accepted" if 200 <= status < 300 else "rejected"


class Contact(_RefreshContact):
    _endpoints = ENDPOINTS
    _event = TLS


def request(grant, client, token, purpose):
    m.require(purpose in grant["tokenPurposes"] and purpose in {"access_token", "refresh_token"})
    m.text(token, 64 * 1024)
    provider = grant["providerId"]; host, path = ENDPOINTS[provider]
    m.require(grant["providerConfiguration"]["revocationUrl"] == "https://" + host + path
        and client["providerId"] == provider and client["clientId"] == grant["clientId"])
    form = {"token": token, "token_type_hint": purpose}
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    if grant["providerConfiguration"]["tokenAuth"] == "basic":
        raw = urllib.parse.quote(client["clientId"], safe="") + ":" + urllib.parse.quote(client["clientSecret"], safe="")
        headers["Authorization"] = "Basic " + base64.b64encode(raw.encode("ascii")).decode("ascii")
    elif provider == "x":
        form["client_id"] = client["clientId"]
    body = urllib.parse.urlencode(form).encode("ascii")
    m.require(len(body) <= 32768)
    commitment = m.sha(m.canonical({"schema": "catchplate.oauthRevocationContact/v1", "url": "https://" + host + path,
        "method": "POST", "bodySha256": m.sha(body), "headersSha256": m.sha(m.canonical(headers))}))
    return host, path, headers, body, commitment
