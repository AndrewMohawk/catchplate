"""Private reconnect encodings; never an old issuance permission conversion."""
import os
import re
import uuid
from catchplate import native_oauth_refresh as m
from catchplate import native_oauth_exchange as provider

INTENT = "catchplate.nativeOAuthReconnectIntent/v1"
STATE = "catchplate.nativeOAuthReconnectState/v1"
GRANT = "catchplate.oauthFamilyReconnectAuthorization/v1"
SIGNED_GRANT = "catchplate.signedOAuthFamilyReconnectAuthorization/v1"
ACTION = "credential.oauth.measured-reconnect"
STATEMENT = "catchplate.nativeOAuthReconnectStatement/v1"
MAX_INTENT, MAX_STATE, MAX_GRANT = 8 * 1024 * 1024, 64 * 1024, 64 * 1024
LIMITS = {"affectedLineageCapacity": 7, "historyCapacity": 64, "authorizationMaxSeconds": 3600}
INTENT_FIELDS = provider.INTENT_FIELDS | {"authorizationOriginal", "fenceRequestOriginal", "fenceResponseOriginal"}
STATE_FIELDS = provider.STATE_FIELDS | {"reconnectBinding"}
BINDING_FIELDS = frozenset({"authorizationSha256", "fencedRowSha256", "credentialId", "credentialVersion",
    "providerSubject", "providerAccount", "expiresAtEpochNs"})
GRANT_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "authorizationId", "configurationDigest", "deploymentId",
    "credentialId", "credentialVersion", "credentialRowSha256", "generationRowSha256", "providerId", "providerSubject",
    "providerAccount", "clientId", "enrollmentSha256", "requesterId", "scopes", "metadataSha256", "familyScope", "affectedLineages",
    "issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs", "expiresAtEpochNs"})
HUMAN_FIELDS = frozenset({"action", "resource_id", "payload_digest", "actor_id", "request", "approval_id",
    "credential_policy", "enrollment_original", "authorization_original"})
ARGUMENT_FIELDS = HUMAN_FIELDS | {"control_plane_configuration_digest", "assignment_original", "native_evidence"}
STATEMENT_FIELDS = frozenset({"apiVersion", "phase", "holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId",
    "deploymentId", "instanceId", "providerId", "enrollmentSha256", "exchangeId", "inputSha256", "challenge", "policyHash",
    "dataPlaneBinarySha256", "callbackOrigin", "portalOrigin", "ingressLeafCertificateSha256", "ingressLeafSpkiSha256",
    "issuedAtEpochNs", "expiresAtEpochNs", "authorizationSha256", "fencedRowSha256"})


def array(raw, maximum):
    m.require(type(raw) is bytes and len(raw) <= maximum)
    value = m.document(b'{"items":' + raw + b'}', maximum + 10)["items"]
    m.require(type(value) is list)
    return value


def grant(raw):
    envelope = m.document(raw, MAX_GRANT)
    m.require(set(envelope) == {"schema", "payload", "signatureBase64Url"} and envelope["schema"] == SIGNED_GRANT)
    m.decoded(envelope["signatureBase64Url"], 64, 64)
    value = envelope["payload"]
    m.require(type(value) is dict and set(value) == GRANT_FIELDS and value["schema"] == GRANT
        and value["purpose"] == "measured-oauth-active-family-replacement" and value["providerId"] in provider.AUTHORIZATION)
    provider.identifier(value["authorizationId"]); provider.identifier(value["credentialId"])
    m.integer(value["credentialVersion"], maximum=2**63 - 2)
    for name in ("configurationDigest", "credentialRowSha256", "generationRowSha256", "enrollmentSha256", "metadataSha256"):
        m.digest(value[name])
    for name, maximum in (("sourceRevision", 128), ("deploymentId", 128), ("providerSubject", 512),
            ("providerAccount", 512), ("clientId", 2048), ("requesterId", 512)):
        m.text(value[name], maximum)
    m.require(value["requesterId"].startswith("oidc:"))
    scopes = value["scopes"]
    m.require(type(scopes) is list and 1 <= len(scopes) <= 128 and scopes == sorted(set(scopes)))
    m.scopes(" ".join(scopes))
    scope = value["familyScope"]
    m.require(type(scope) is dict and set(scope) == {"profile", "familyId", "externalFamilyReplacementAuthorized", "localInventoryProfile"}
        and scope["profile"] == "provider-family-replacement-v1" and scope["externalFamilyReplacementAuthorized"] is True
        and scope["localInventoryProfile"] == "complete-local-family-v1")
    m.text(scope["familyId"], 512)
    members = value["affectedLineages"]
    m.require(type(members) is list and 1 <= len(members) <= 7)
    for item in members:
        m.require(type(item) is dict and set(item) == {"credentialId", "credentialVersion", "credentialRowSha256", "generationRowSha256"})
        provider.identifier(item["credentialId"]); m.integer(item["credentialVersion"])
        m.digest(item["credentialRowSha256"]); m.digest(item["generationRowSha256"])
    m.require([item["credentialId"] for item in members] == sorted({item["credentialId"] for item in members}))
    target = [item for item in members if item["credentialId"] == value["credentialId"]]
    m.require(len(target) == 1 and all(target[0][name] == value[name] for name in target[0]))
    epochs = [m.integer(value[name]) for name in ("issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs",
        "pendingExpiresAtEpochNs", "expiresAtEpochNs")]
    issued, contact, retention, pending, end = epochs
    m.require(issued < contact <= retention <= pending <= end and end - issued <= 3600_000_000_000
        and contact - issued <= 600_000_000_000 and retention - contact <= 600_000_000_000 and pending - contact <= 3600_000_000_000)
    return envelope


def binding(value):
    m.require(type(value) is dict and set(value) == BINDING_FIELDS)
    m.digest(value["authorizationSha256"]); m.digest(value["fencedRowSha256"])
    provider.identifier(value["credentialId"]); m.integer(value["credentialVersion"], maximum=2**63 - 2)
    m.text(value["providerSubject"], 512); m.text(value["providerAccount"], 512); m.integer(value["expiresAtEpochNs"])
    return value


def intent(value):
    m.require(type(value) is dict and set(value) == INTENT_FIELDS and value["schema"] == INTENT
        and len(m.canonical(value)) <= MAX_INTENT)
    expected = grant(m.decoded(value["authorizationOriginal"], MAX_GRANT))["payload"]
    m.require(value["providerId"] == expected["providerId"] and value["requesterId"] == expected["requesterId"]
        and value["scopes"] == expected["scopes"] and type(value["metadata"]) is dict
        and m.sha(m.canonical(value["metadata"])) == expected["metadataSha256"] and type(value["credentialPolicy"]) is dict)
    m.text(value["credentialName"], 256)
    m.decoded(value["fenceRequestOriginal"], 2 * 1024 * 1024 + 65536)
    m.decoded(value["fenceResponseOriginal"], 6 * 1024 * 1024)
    return value


def private_state(raw):
    value = m.document(raw, MAX_STATE)
    m.require(set(value) == STATE_FIELDS and value["schema"] == STATE)
    bound = binding(value["reconnectBinding"])
    provider.identifier(value["exchangeId"])
    m.require(type(value["state"]) is str and re.fullmatch(r"[0-9a-f]{32}_[A-Za-z0-9_-]{43}", value["state"])
        and value["state"][:32] == uuid.UUID(value["exchangeId"]).hex)
    m.decoded(value["state"][33:], 32, 32); m.decoded(value["codeVerifier"], 32, 32)
    m.digest(value["browserNonceSha256"]); m.digest(value["enrollmentSha256"])
    m.require(value["redirectUri"] == provider.callback_uri(value["callbackOrigin"], value["providerId"])
        and provider.origin(value["portalOrigin"]) != value["callbackOrigin"]
        and type(value["metadata"]) is dict and value["metadata"].get(m.ASSOCIATION) == value[m.ASSOCIATION]
        and value["metadata"].get("provider_subject") == bound["providerSubject"]
        and value["metadata"].get("provider_account") == bound["providerAccount"])
    epochs = [m.integer(value[name]) for name in ("issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs")]
    m.require(epochs[0] < epochs[1] <= epochs[2] <= epochs[3] <= bound["expiresAtEpochNs"])
    return value


def prepare(value, *, authorization, journal_original, enrollment_original, callback_origin, portal_origin, limits, issued_ns):
    """Fresh entropy only after the actual owner has authenticated the fence."""
    intent(value)
    m.require(authorization == grant(m.decoded(value["authorizationOriginal"], MAX_GRANT))["payload"])
    enrollment = m.document(enrollment_original, 32768, exact=False)["payload"]
    association = provider.association(enrollment_original, enrollment)
    m.require(value["metadata"].get(m.ASSOCIATION) == association
        and enrollment["providerId"] == authorization["providerId"] and enrollment["clientId"] == authorization["clientId"]
        and enrollment["redirectUri"] == provider.callback_uri(callback_origin, authorization["providerId"])
        and provider.origin(portal_origin) != callback_origin and m.sha(enrollment_original) == authorization["enrollmentSha256"]
        and enrollment["issuedAtEpochNs"] <= issued_ns < authorization["contactExpiresAtEpochNs"]
        and authorization["expiresAtEpochNs"] <= enrollment["expiresAtEpochNs"])
    identifier = authorization["authorizationId"]
    nonce, verifier = m.encoded(os.urandom(32)), m.encoded(os.urandom(32))
    state = {"schema": STATE, "exchangeId": identifier, "state": uuid.UUID(identifier).hex + "_" + m.encoded(os.urandom(32)),
        "browserNonceSha256": m.sha(nonce.encode("ascii")), "codeVerifier": verifier,
        **{name: value[name] for name in ("providerId", "requesterId", "credentialName", "scopes", "metadata", "credentialPolicy")},
        "redirectUri": enrollment["redirectUri"], "issuedAtEpochNs": issued_ns,
        **{name: authorization[name] for name in ("contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs")},
        "enrollmentSha256": m.sha(enrollment_original), m.ASSOCIATION: association, "limits": limits,
        "portalOrigin": portal_origin, "callbackOrigin": callback_origin,
        "reconnectBinding": {"authorizationSha256": m.sha(m.decoded(value["authorizationOriginal"], MAX_GRANT)),
            "fencedRowSha256": m.sha(journal_original.encode("ascii")), **{name: authorization[name] for name in
                ("credentialId", "credentialVersion", "providerSubject", "providerAccount", "expiresAtEpochNs")}}}
    raw = m.canonical(state); private_state(raw)
    return raw, nonce
