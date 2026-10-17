"""Exact staged-pending retirement grant data, without CP/store dependencies.

The generic retirement data projection below supplies no permission. This
purpose retains its own full fields, original signature domain and family scope.
"""
from catchplate import oauth_retirement_values as common
from catchplate.oauth_retirement_policy_values import canonical, require, digest, unb64, uuid_value, document

GRANT_SCHEMA = "catchplate.oauthMeasuredPendingRetirementAuthorization/v1"
SIGNED_GRANT_SCHEMA = "catchplate.signedOAuthMeasuredPendingRetirementAuthorization/v1"
PURPOSE = "measured-oauth-staged-pending-family-retirement"
MAX_GRANT_BYTES = 64 * 1024
MAX_AFFECTED_LINEAGES = 24
GRANT_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "authorizationId", "configurationDigest",
    "deploymentId", "exchangeId", "exchangeRowSha256", "custodyRowSha256", "pendingId", "initialPendingRowSha256",
    "currentPendingRowSha256", "stageArgumentsSha256", "enrollmentSha256", "historicalEnrollmentRootSpkiSha256",
    "tokenEnvelopeSha256", "tokenSecretSha256", "providerId", "clientId", "clientMaterialSha256", "providerConfiguration",
    "tokenPurposes", "familyScope", "affectedLineages", "applicationMaterialSha256", "providerTlsRootSha256",
    "holderId", "reason", "issuedAtEpochNs", "expiresAtEpochNs"})
LINEAGE_FIELDS = frozenset({"credentialId", "credentialVersion", "credentialRowSha256", "generationRowSha256"})


def lineages(values):
    require(type(values) is list and len(values) <= MAX_AFFECTED_LINEAGES)
    ids = []
    for item in values:
        require(type(item) is dict and set(item) == LINEAGE_FIELDS)
        ids.append(uuid_value(item["credentialId"]))
        require(type(item["credentialVersion"]) is int and 1 <= item["credentialVersion"] <= 2**63 - 1)
        for name in ("credentialRowSha256", "generationRowSha256"):
            digest(item[name]); require(item[name] != "sha256:" + "0" * 64)
    require(ids == sorted(set(ids)))
    return values


def payload(value):
    require(type(value) is dict and set(value) == GRANT_FIELDS and value["schema"] == GRANT_SCHEMA
        and value["purpose"] == PURPOSE and value["reason"] in {"cancelled", "expired", "rejected"})
    projected = {name: value[name] for name in common.GRANT_FIELDS - {"schema", "purpose", "workRowSha256"}}
    common.revocation_payload({**projected, "schema": common.GRANT_SCHEMA, "purpose": "retained-oauth-revocation",
        "workRowSha256": value["currentPendingRowSha256"]})
    uuid_value(value["pendingId"])
    for name in ("custodyRowSha256", "initialPendingRowSha256", "currentPendingRowSha256", "stageArgumentsSha256",
            "applicationMaterialSha256", "providerTlsRootSha256", "holderId"):
        digest(value[name]); require(value[name] != "sha256:" + "0" * 64)
    scope = value["familyScope"]
    require(type(scope) is dict and set(scope) == {"profile", "familyId", "providerSubject", "providerAccount",
        "externalFamilyRetirementAuthorized"} and scope["profile"] == "provider-family-retirement-v1"
        and scope["externalFamilyRetirementAuthorized"] is True)
    for name in ("familyId", "providerSubject", "providerAccount"):
        common.text(scope[name], 512)
    lineages(value["affectedLineages"])
    require(len(canonical(value)) <= MAX_GRANT_BYTES - 512)
    return value


def grant_document(raw):
    value = document(raw, MAX_GRANT_BYTES)
    require(set(value) == {"schema", "payload", "signatureBase64Url"} and value["schema"] == SIGNED_GRANT_SCHEMA)
    payload(value["payload"]); unb64(value["signatureBase64Url"], 64, exact=64)
    return value
