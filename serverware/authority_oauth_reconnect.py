"""Closed family-replacement originals, never permission by data alone.

The actual signed policy, hardware approval, complete authenticated populations,
holder drains and retained native custody are independently admitted by callers.
Ordinary reconnect cannot succeed a retired or already-fenced family.
"""
from collections.abc import Mapping
import json
import uuid

from serverware import authority_oauth_activation as activation
from serverware import authority_oauth_refresh as refresh
from serverware import authority_oauth_measured_exchange as issuance
from serverware import authority_oauth_measured_pending_retirement as lineages_codec
from serverware import native_oauth_exchange as material
from serverware import native_oauth_refresh as common

canonical, require, digest, sha256 = common.canonical, common.require, common.digest, common.sha
document, encoded, decoded = common.document, common.encoded, common.decoded
GRANT_SCHEMA = "serverware.oauthFamilyReconnectAuthorization/v1"
SIGNED_GRANT_SCHEMA = "serverware.signedOAuthFamilyReconnectAuthorization/v1"
PURPOSE = "measured-oauth-active-family-replacement"
ACTION = "credential.oauth.reconnect"
NATIVE_ACTION = "credential.oauth.measured-reconnect"
OPTIONS_SCHEMA = "serverware.oauthReconnectApprovalOptions/v1"
PROVENANCE_SCHEMA = "serverware.oauthReconnectApprovalProvenance/v1"
ORIGINAL_SCHEMA = "serverware.oauthReconnectOriginal/v1"
INTENT_SCHEMA = "serverware.nativeOAuthReconnectIntent/v1"
STATE_SCHEMA = "serverware.nativeOAuthReconnectState/v1"
INTENT_RESPONSE = "serverware.nativeOAuthReconnectIntentResponse/v1"
REDIRECT_SCHEMA = "serverware.nativeOAuthReconnectAuthorizationRedirect/v1"
RECOVERY_REQUEST = "serverware.nativeOAuthReconnectRecoveryOriginalRequest/v1"
RECOVERY_RESPONSE = "serverware.nativeOAuthReconnectRecoveryOriginalResponse/v1"
NATIVE_CONFIGURATION = "serverware.nativeOAuthReconnectExchangeConfiguration/v1"
STATEMENT = "serverware.nativeOAuthReconnectStatement/v1"
SIGN_OPERATION = "nativeOAuthReconnectExchange.sign/v1"
SIGNATURE_DOMAIN = STATEMENT.encode("ascii") + b"\0"
ATTESTATION_DOMAIN = b"serverware/native-oauth-reconnect-attestation/v1\0"
HTTP_SCHEMA = "serverware.nativeOAuthReconnectRequest/v1"
HTTP_RESPONSE = "serverware.nativeOAuthReconnectResponse/v1"
RUNTIME_RESPONSE = "serverware.policyAuthorityMeasuredReconnectRuntimeResponse/v1"
HTTP_PATH = "/api/data-plane/oauth-reconnect"
HUMAN_PREFIX = "/api/oauth/reconnect"
OP_AUTHORIZE = "oauth.reconnect.authorize"
OP_FENCE = "oauth.reconnect.fence"
OP_REQUEST = "oauth.reconnect.activation-request"
OP_DECIDE = "oauth.reconnect.activation-decide"
OP_ACTIVATE = "oauth.reconnect.activate"
OP_PREPARE = "oauth.measured-reconnect.prepare"
OP_CLAIM = "oauth.measured-reconnect.claim"
OP_CAPTURE = "oauth.measured-reconnect.capture"
OP_STAGE = "oauth.measured-reconnect.stage"
OP_RECOVER = "oauth.measured-reconnect.recover"
OP_CANCEL = "oauth.measured-reconnect.cancel"
NATIVE_OPERATIONS = frozenset({OP_PREPARE, OP_CLAIM, OP_CAPTURE, OP_STAGE, OP_RECOVER, OP_CANCEL})
ASSERTION_OPERATIONS = frozenset({OP_AUTHORIZE, OP_REQUEST, OP_DECIDE, OP_ACTIVATE})
OPERATIONS = NATIVE_OPERATIONS | ASSERTION_OPERATIONS | {OP_FENCE}
JOURNAL_TABLE = "oauth_reconnect_authorizations"
TABLE = "oauth_measured_reconnect_custody"
MAX_AFFECTED_LINEAGES = 7
MAX_HISTORY_ROWS = 64
MAX_GRANT_BYTES = 64 * 1024
MAX_ARGUMENT_BYTES = 2 * 1024 * 1024
MAX_ROW_BYTES = 4 * 1024 * 1024
MAX_CANDIDATE_BYTES = 512 * 1024
MAX_HTTP_REQUEST = 3 * 1024 * 1024
MAX_HTTP_RESPONSE = 8 * 1024 * 1024
MAX_INTENT_BYTES = 8 * 1024 * 1024
INTENT_FIELDS = material.INTENT_FIELDS | {"authorizationOriginal", "fenceRequestOriginal", "fenceResponseOriginal"}
STATE_FIELDS = material.STATE_FIELDS | {"reconnectBinding"}
BINDING_FIELDS = frozenset({"authorizationSha256", "fencedRowSha256", "credentialId", "credentialVersion",
    "providerSubject", "providerAccount", "expiresAtEpochNs"})
NATIVE_CONFIGURATION_FIELDS = frozenset({"apiVersion", "sourceRevision", "authorityRootPublicKey", "authorityRootSpkiSha256",
    "controlPlaneConfigurationDigest", "deploymentId", "instanceId", "limits", "windows", "applications", "recoveryTargets",
    "identity", "callbackOrigin", "portalOrigin", "ingressLeafCertificateSha256", "ingressLeafSpkiSha256",
    "authorityConfigurationOriginal", "reconnectLimits"})
RECONNECT_LIMITS = {"affectedLineageCapacity": 7, "historyCapacity": 64, "authorizationMaxSeconds": 3600}
GRANT_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "authorizationId", "configurationDigest", "deploymentId",
    "credentialId", "credentialVersion", "credentialRowSha256", "generationRowSha256", "providerId", "providerSubject",
    "providerAccount", "clientId", "enrollmentSha256", "requesterId", "scopes", "metadataSha256", "familyScope",
    "affectedLineages", "issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs", "expiresAtEpochNs"})
HUMAN_FIELDS = activation.FIELDS | {"authorization_original"}
FIELDS = issuance.FIELDS | {"authorization_original"}
STATEMENT_FIELDS = issuance.STATEMENT_FIELDS | {"authorizationSha256", "fencedRowSha256"}
REQUEST_FIELDS = {operation: issuance.REQUEST_FIELDS["oauth.measured-exchange." + operation.rsplit(".", 1)[1]] | {"fencedRowSha256"}
    for operation in NATIVE_OPERATIONS}
REQUEST_FIELDS.update({
    OP_AUTHORIZE: frozenset({"credentialId", "credentialVersion", "authorizationSha256"}),
    OP_FENCE: frozenset({"authorizationRowSha256", "currentnessBarriers", "issuedAtEpochNs", "expiresAtEpochNs"}),
    **{operation: frozenset({"authorizationSha256", "candidateSha256"}) for operation in (OP_REQUEST, OP_DECIDE, OP_ACTIVATE)}})
JOURNAL_FIELDS = frozenset({"id", "authorization_original", "authorization_sha256", "enrollment_original", "actor_id",
    "credential_policy_json", "original_affected_json", "authorize_arguments_json", "authorize_request_digest",
    "currentness_barriers_json", "fence_arguments_json", "fence_request_digest", "status", "created_at",
    "admission_expires_at", "expires_at", "updated_at"})
ROW_FIELDS = (issuance.ROW_FIELDS - {"pending_original_json"}) | {"candidate_original_json", "commit_request_digest",
    "committed_credential_json", "predecessor_original_json"}
CANDIDATE_FIELDS = frozenset({"apiVersion", "authorizationSha256", "credentialId", "previousVersion", "exchangeId",
    "tokenSecretSha256", "tokenEnvelope", "metadata", "review", "payloadDigest", "createdAtEpochNs", "expiresAtEpochNs"})
ORIGINALS_FIELDS = frozenset({"journalOriginal", "exchangeOriginal", "custodyOriginal", "candidateOriginal"})
RESULT_FIELDS = frozenset({"ok", "operation", "requestDigest", "auditEventDigest", "idempotentReplay", "originals"})
LINEAGE_FIELDS = lineages_codec.LINEAGE_FIELDS
BARRIER_FIELDS = lineages_codec.BARRIER_FIELDS
AFFECTED_ORIGINAL_FIELDS = lineages_codec.AFFECTED_ORIGINAL_FIELDS


def identifier(value):
    require(type(value) is str and str(uuid.UUID(value)) == value)
    return value


def intent(value):
    """Closed review data; only the native owner verifies the signed fence."""
    require(type(value) is dict and set(value) == INTENT_FIELDS and value["schema"] == INTENT_SCHEMA
        and len(canonical(value)) <= MAX_INTENT_BYTES)
    raw = decoded(value["authorizationOriginal"], MAX_GRANT_BYTES)
    expected = grant_document(raw)["payload"]
    require(value["providerId"] == expected["providerId"] and value["requesterId"] == expected["requesterId"]
        and value["scopes"] == expected["scopes"] and type(value["metadata"]) is dict
        and sha256(canonical(value["metadata"])) == expected["metadataSha256"])
    material.text(value["credentialName"], 256)
    activation.policy(value["credentialPolicy"])
    decoded(value["fenceRequestOriginal"], MAX_ARGUMENT_BYTES + 65536)
    decoded(value["fenceResponseOriginal"], 6 * 1024 * 1024)
    return value


def reconnect_binding(value):
    require(type(value) is dict and set(value) == BINDING_FIELDS)
    for name in ("authorizationSha256", "fencedRowSha256"):
        digest(value[name])
    identifier(value["credentialId"]); refresh._version(value["credentialVersion"])
    require(value["credentialVersion"] < 2**63 - 1)
    material.text(value["providerSubject"], 512); material.text(value["providerAccount"], 512)
    common.integer(value["expiresAtEpochNs"])
    return value


def lineages(value):
    lineages_codec.lineages(value)
    require(1 <= len(value) <= MAX_AFFECTED_LINEAGES)
    return value


def barriers(value, affected):
    lineages(affected)
    return lineages_codec.barriers(value, affected)


def payload(value):
    require(type(value) is dict and set(value) == GRANT_FIELDS and value["schema"] == GRANT_SCHEMA
        and value["purpose"] == PURPOSE and value["providerId"] in {"google", "x"})
    for name in ("authorizationId", "credentialId"):
        identifier(value[name])
    refresh._version(value["credentialVersion"])
    require(value["credentialVersion"] < 2**63 - 1)
    for name in ("configurationDigest", "credentialRowSha256", "generationRowSha256", "enrollmentSha256", "metadataSha256"):
        digest(value[name]); require(value[name] != "sha256:" + "0" * 64)
    for name, bound in (("sourceRevision", 128), ("deploymentId", 128), ("providerSubject", 512),
            ("providerAccount", 512), ("clientId", 2048), ("requesterId", 512)):
        material.text(value[name], bound)
    require(value["requesterId"].startswith("oidc:"))
    scopes = value["scopes"]
    require(type(scopes) is list and 1 <= len(scopes) <= 128 and scopes == sorted(set(scopes)))
    common.scopes(" ".join(scopes))
    scope = value["familyScope"]
    require(type(scope) is dict and set(scope) == {"profile", "familyId", "externalFamilyReplacementAuthorized", "localInventoryProfile"}
        and scope["profile"] == "provider-family-replacement-v1" and scope["externalFamilyReplacementAuthorized"] is True
        and scope["localInventoryProfile"] == "complete-local-family-v1")
    material.text(scope["familyId"], 512)
    members = lineages(value["affectedLineages"])
    targets = [item for item in members if item["credentialId"] == value["credentialId"]]
    require(len(targets) == 1 and all(targets[0][name] == value[name]
        for name in ("credentialVersion", "credentialRowSha256", "generationRowSha256")))
    for name in ("issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs", "expiresAtEpochNs"):
        common.integer(value[name])
    issued, contact, retained, pending, end = (value[name] for name in
        ("issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs", "expiresAtEpochNs"))
    require(issued < contact <= retained <= pending <= end and contact - issued <= 600_000_000_000
        and retained - contact <= 600_000_000_000 and pending - contact <= 3600_000_000_000)
    require(0 < value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= 3600_000_000_000
        and len(canonical(value)) <= MAX_GRANT_BYTES - 512)
    return value


def grant_document(raw):
    value = document(raw, MAX_GRANT_BYTES)
    require(set(value) == {"schema", "payload", "signatureBase64Url"} and value["schema"] == SIGNED_GRANT_SCHEMA)
    payload(value["payload"]); decoded(value["signatureBase64Url"], 64, 64)
    return value


def sign_authorization(value, signing_key):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from serverware import authority_contract
    payload(value)
    require(isinstance(signing_key, Ed25519PrivateKey) and value["sourceRevision"] == authority_contract.SOURCE_REVISION)
    raw = canonical(value)
    result = canonical({"schema": SIGNED_GRANT_SCHEMA, "payload": json.loads(raw),
        "signatureBase64Url": encoded(signing_key.sign(GRANT_SCHEMA.encode("ascii") + b"\0" + raw))})
    require(len(result) <= MAX_GRANT_BYTES)
    return result


def request_binding(operation, value, grant):
    require(operation in OPERATIONS and type(value) is dict and set(value) == REQUEST_FIELDS[operation])
    if operation in NATIVE_OPERATIONS:
        require(value["exchangeId"] == grant["authorizationId"])
        digest(value["fencedRowSha256"])
        projected = {name: item for name, item in value.items() if name != "fencedRowSha256"}
        if operation == OP_STAGE:
            # Replacement AAD is the existing target ID / next generation, not
            # a version1 pending credential and not a translated old permission.
            identifier(value["exchangeId"]); issuance.limits(value["limits"])
            decoded(value["ownerNonce"], 32, 32)
            for name in ("exchangeRowSha256", "tokenSecretSha256", "identityRawSha256", "payloadDigest"):
                digest(value[name])
            refresh.envelope(value["tokenEnvelope"], grant["credentialVersion"] + 1)
            issuance.legacy.envelope(value["identityRawEnvelope"])
            require(type(value["metadata"]) is dict and len(canonical(value["metadata"])) <= 32768
                and type(value["review"]) is dict and len(canonical(value["review"])) <= 16384)
            if value["recoveryRequestDigest"] is not None:
                digest(value["recoveryRequestDigest"])
        else:
            issuance.request_binding("oauth.measured-exchange." + operation.rsplit(".", 1)[1], projected)
        if operation == OP_PREPARE:
            require(value["providerId"] == grant["providerId"] and value["enrollmentSha256"] == grant["enrollmentSha256"]
                and value["scopes"] == grant["scopes"] and all(value[name] == grant[name]
                    for name in ("contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs")))
    elif operation == OP_AUTHORIZE:
        require(value["credentialId"] == grant["credentialId"] and type(value["credentialVersion"]) is int
            and value["credentialVersion"] == grant["credentialVersion"])
        digest(value["authorizationSha256"])
    elif operation == OP_FENCE:
        digest(value["authorizationRowSha256"]); barriers(value["currentnessBarriers"], grant["affectedLineages"])
        common.integer(value["issuedAtEpochNs"]); common.integer(value["expiresAtEpochNs"])
        require(0 < value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= 30_000_000_000
            and value["expiresAtEpochNs"] <= grant["expiresAtEpochNs"])
    else:
        digest(value["authorizationSha256"]); digest(value["candidateSha256"])
    return dict(value)


def input_sha256(values):
    return sha256(canonical({name: values[name] for name in FIELDS - {"native_evidence"}}))


def evidence(value):
    require(type(value) is dict and set(value) == {"statement", "signature", "nativeKeyEvidence"})
    statement = value["statement"]
    require(type(statement) is dict and set(statement) == STATEMENT_FIELDS and statement["apiVersion"] == STATEMENT)
    # Pure scalar validation only; independent signature/domain verification is
    # mandatory on the original reconnect statement, never this projection.
    projection = {name: statement[name] for name in issuance.STATEMENT_FIELDS}
    projection["apiVersion"] = issuance.STATEMENT
    issuance.evidence({**value, "statement": projection})
    digest(statement["authorizationSha256"]); digest(statement["fencedRowSha256"])
    return value


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping))
    fields = FIELDS if operation in NATIVE_OPERATIONS else HUMAN_FIELDS
    allowed = fields | ({"businessIntent", "authn_evidence"} if typed else set())
    require(fields <= set(value) <= allowed and (not typed or "businessIntent" in value))
    raw = decoded(value["authorization_original"], MAX_GRANT_BYTES)
    grant = grant_document(raw)["payload"]
    request = request_binding(operation, value["request"], grant)
    require(value["resource_id"] == grant["authorizationId"]
        and value["action"] == (NATIVE_ACTION if operation in NATIVE_OPERATIONS else ACTION)
        and value["payload_digest"] == sha256(canonical(request)))
    material.text(value["actor_id"], 512); require(value["actor_id"].startswith("oidc:"))
    if operation != OP_DECIDE:
        require(value["actor_id"] == grant["requesterId"])
    activation.policy(value["credential_policy"])
    require(sha256(activation.enrollment_bytes(value["enrollment_original"])) == grant["enrollmentSha256"])
    if operation in {OP_DECIDE, OP_ACTIVATE}:
        identifier(value["approval_id"])
    else:
        require(value["approval_id"] is None)
    if operation in {OP_AUTHORIZE, OP_REQUEST, OP_DECIDE, OP_ACTIVATE}:
        require(request["authorizationSha256"] == sha256(raw))
    if operation in NATIVE_OPERATIONS:
        require(value["control_plane_configuration_digest"] == grant["configurationDigest"]
            and type(value["assignment_original"]) is dict)
        statement = evidence(value["native_evidence"])["statement"]
        require(statement["phase"] == ("draft" if operation == OP_PREPARE else operation.rsplit(".", 1)[1])
            and statement["exchangeId"] == grant["authorizationId"] and statement["authorizationSha256"] == sha256(raw)
            and statement["fencedRowSha256"] == request["fencedRowSha256"] and statement["inputSha256"] == input_sha256(value)
            and statement["providerId"] == grant["providerId"] and statement["enrollmentSha256"] == grant["enrollmentSha256"]
            and grant["issuedAtEpochNs"] <= statement["issuedAtEpochNs"] < statement["expiresAtEpochNs"] <= grant["expiresAtEpochNs"])
    result = {name: value[name] for name in fields}
    require(len(canonical(result)) <= MAX_ARGUMENT_BYTES)
    return result


def journal_original(row):
    value = dict(row)
    require(set(value) == JOURNAL_FIELDS and value["status"] in {"authorized", "fenced"})
    identifier(value["id"])
    nullable = {"currentness_barriers_json", "fence_arguments_json", "fence_request_digest"}
    for name, item in value.items():
        require(type(item) is str or item is None and name in nullable)
    require(all((value[name] is None) == (value["status"] == "authorized") for name in nullable))
    raw = canonical(value); require(len(raw) <= MAX_ROW_BYTES)
    return raw


def row_original(row):
    value = dict(row)
    require(set(value) == ROW_FIELDS and value["status"] in {"prepared", "claimed", "captured", "staged", "cancelled", "committed"})
    identifier(value["id"])
    for name, item in value.items():
        if name in {"received_at_epoch_ns", "recovery_expires_at_epoch_ns"} and item is not None:
            common.integer(item)
        else:
            require(type(item) is str or item is None)
    raw = canonical(value); require(len(raw) <= MAX_ROW_BYTES)
    return raw


def candidate_original(value, grant):
    require(type(value) is dict and set(value) == CANDIDATE_FIELDS
        and value["apiVersion"] == "serverware.oauthReconnectCandidate/v1"
        and value["credentialId"] == grant["credentialId"] and value["previousVersion"] == grant["credentialVersion"]
        and value["exchangeId"] == grant["authorizationId"])
    refresh.envelope(value["tokenEnvelope"], grant["credentialVersion"] + 1)
    for name in ("authorizationSha256", "tokenSecretSha256", "payloadDigest"):
        digest(value[name])
    for name in ("createdAtEpochNs", "expiresAtEpochNs"):
        common.integer(value[name])
    require(value["createdAtEpochNs"] < value["expiresAtEpochNs"] <= grant["expiresAtEpochNs"])
    raw = canonical(value); require(len(raw) <= MAX_CANDIDATE_BYTES)
    return raw


def request_digest(operation, value):
    from serverware import authority_request_commitment as commitment
    return commitment.oauth_reconnect_request_digest(operation, value)
