"""Closed initial-issuance originals; no enrollment or ciphertext verdicts."""
from __future__ import annotations

from collections.abc import Mapping
from serverware import authority_oauth_activation as activation
from serverware import authority_oauth_exchange as legacy
from serverware import native_oauth_exchange as material
from serverware import native_oauth_refresh as common

canonical, require, digest, sha256 = common.canonical, common.require, common.digest, common.sha
document, encoded, decoded = common.document, common.encoded, common.decoded
ACTION = "credential.oauth.measured-consent"
OPTIONS_SCHEMA = "serverware.nativeOAuthConsentOptions/v1"
STATEMENT = "serverware.nativeOAuthExchangeStatement/v1"
SIGN_OPERATION = "nativeOAuthExchange.sign/v1"
SIGNATURE_DOMAIN = STATEMENT.encode("ascii") + b"\0"
ATTESTATION_DOMAIN = b"serverware/native-oauth-exchange-attestation/v1\0"
OP_PREPARE = "oauth.measured-exchange.prepare"
OP_CLAIM = "oauth.measured-exchange.claim"
OP_CAPTURE = "oauth.measured-exchange.capture"
OP_STAGE = "oauth.measured-exchange.stage"
OP_RECOVER = "oauth.measured-exchange.recover"
OP_CANCEL = "oauth.measured-exchange.cancel"
OPERATIONS = frozenset({OP_PREPARE, OP_CLAIM, OP_CAPTURE, OP_STAGE, OP_RECOVER, OP_CANCEL})
ASSERTION_OPERATIONS = frozenset({OP_PREPARE})
TABLE = "oauth_measured_exchange_custody"
WORK_SOURCE = "measured-oauth-exchange/v1"
FIELDS = activation.FIELDS | {"control_plane_configuration_digest", "assignment_original", "native_evidence"}
PREPARE_FIELDS = legacy.PREPARE_FIELDS | {"pkceChallenge", "portalOrigin", "callbackOrigin"}
REQUEST_FIELDS = {
    OP_PREPARE: PREPARE_FIELDS,
    OP_CLAIM: frozenset({"exchangeId", "exchangeRowSha256", "ownerNonceSha256", "callbackSha256", "callbackEnvelope",
        "codeSha256", "contactRequestSha256", "limits"}),
    OP_CAPTURE: frozenset({"exchangeId", "exchangeRowSha256", "ownerNonce", "rawResponseSha256", "rawResponseEnvelope",
        "issuedMaterialSha256", "issuedMaterialEnvelope", "receivedAtEpochNs", "limits"}),
    OP_STAGE: frozenset({"exchangeId", "exchangeRowSha256", "ownerNonce", "tokenSecretSha256", "tokenEnvelope",
        "identityRawSha256", "identityRawEnvelope", "metadata", "review", "payloadDigest", "recoveryRequestDigest", "limits"}),
    OP_RECOVER: frozenset({"exchangeId", "custodyRowSha256", "captureInputSha256", "ownerNonceSha256",
        "issuedAtEpochNs", "expiresAtEpochNs", "limits"}),
    OP_CANCEL: frozenset({"exchangeId", "exchangeRowSha256", "callbackSha256", "callbackEnvelope", "limits"}),
}
STATEMENT_FIELDS = frozenset({"apiVersion", "phase", "holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId",
    "deploymentId", "instanceId", "providerId", "enrollmentSha256", "exchangeId", "inputSha256", "challenge",
    "policyHash", "dataPlaneBinarySha256", "callbackOrigin", "portalOrigin", "ingressLeafCertificateSha256",
    "ingressLeafSpkiSha256", "issuedAtEpochNs", "expiresAtEpochNs"})
ROW_FIELDS = frozenset({"id", "prepare_request_digest", "preparation_arguments_json", "claim_arguments_json",
    "capture_arguments_json", "stage_arguments_json", "cancel_arguments_json", "owner_nonce_sha256",
    "received_at_epoch_ns", "recovery_request_digest", "recovery_expires_at_epoch_ns", "recovery_arguments_json",
    "recovery_owner_nonce_sha256", "pending_original_json", "status", "created_at", "updated_at"})
NULLABLE = ROW_FIELDS - {"id", "prepare_request_digest", "preparation_arguments_json", "status", "created_at", "updated_at"}
MAX_ARGUMENT_BYTES = 2 * 1024 * 1024
MAX_ROW_BYTES = 4 * 1024 * 1024


def limits(value):
    require(type(value) is dict and set(value) == {"pendingCapacity", "revocationCapacity"})
    for bound in value.values():
        common.integer(bound, maximum=64)
    return value


def request_binding(operation, value):
    require(operation in OPERATIONS and type(value) is dict and set(value) == REQUEST_FIELDS[operation])
    material.identifier(value["exchangeId"])
    limits(value["limits"])
    if operation == OP_PREPARE:
        legacy.request_binding(legacy.OP_PREPARE, {name: value[name] for name in legacy.PREPARE_FIELDS})
        decoded(value["pkceChallenge"], 32, 32)
        require(value["pkceChallenge"] == encoded(bytes.fromhex(value["pkceVerifierSha256"][7:])))
        material.origin(value["portalOrigin"]); material.origin(value["callbackOrigin"])
        require(value["portalOrigin"] != value["callbackOrigin"]
            and value["redirectUri"] == material.callback_uri(value["callbackOrigin"], value["providerId"]))
    elif operation == OP_RECOVER:
        for name in ("custodyRowSha256", "captureInputSha256", "ownerNonceSha256"):
            digest(value[name])
        common.integer(value["issuedAtEpochNs"]); common.integer(value["expiresAtEpochNs"])
        require(0 < value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= 30_000_000_000)
    else:
        digest(value["exchangeRowSha256"])
        if operation in {OP_CLAIM, OP_CANCEL}:
            digest(value["callbackSha256"]); legacy.envelope(value["callbackEnvelope"])
        if operation == OP_CLAIM:
            for name in ("ownerNonceSha256", "codeSha256", "contactRequestSha256"):
                digest(value[name])
        elif operation == OP_CAPTURE:
            decoded(value["ownerNonce"], 32, 32)
            common.integer(value["receivedAtEpochNs"])
            digest(value["rawResponseSha256"]); legacy.envelope(value["rawResponseEnvelope"])
            require((value["issuedMaterialSha256"] is None) == (value["issuedMaterialEnvelope"] is None))
            if value["issuedMaterialEnvelope"] is not None:
                digest(value["issuedMaterialSha256"]); legacy.envelope(value["issuedMaterialEnvelope"])
        elif operation == OP_STAGE:
            decoded(value["ownerNonce"], 32, 32)
            for name in ("tokenSecretSha256", "identityRawSha256", "payloadDigest"):
                digest(value[name])
            legacy.envelope(value["tokenEnvelope"]); legacy.envelope(value["identityRawEnvelope"])
            require(type(value["metadata"]) is dict and len(canonical(value["metadata"])) <= 32768
                and type(value["review"]) is dict and len(canonical(value["review"])) <= 16384)
            if value["recoveryRequestDigest"] is not None:
                digest(value["recoveryRequestDigest"])
    return dict(value)


def evidence(value):
    from serverware import authority_credential_currentness as current
    require(type(value) is dict and set(value) == {"statement", "signature", "nativeKeyEvidence"})
    statement = value["statement"]
    require(type(statement) is dict and set(statement) == STATEMENT_FIELDS and statement["apiVersion"] == STATEMENT
        and statement["phase"] in {"draft", "claim", "capture", "stage", "recover", "cancel"}
        and statement["providerId"] in material.AUTHORIZATION)
    for name in ("holderId", "keyId", "controlPlaneResponseSigningKeyId", "enrollmentSha256", "inputSha256",
            "policyHash", "dataPlaneBinarySha256", "ingressLeafCertificateSha256", "ingressLeafSpkiSha256"):
        digest(statement[name])
    require(statement["holderId"] == current.holder_id(statement["bootId"], statement["keyId"]))
    material.identifier(statement["exchangeId"])
    material.origin(statement["callbackOrigin"]); material.origin(statement["portalOrigin"])
    material.text(statement["deploymentId"], 128); material.text(statement["instanceId"], 4096)
    decoded(statement["challenge"], 32, 32)
    common.integer(statement["issuedAtEpochNs"]); common.integer(statement["expiresAtEpochNs"])
    require(0 < statement["expiresAtEpochNs"] - statement["issuedAtEpochNs"] <= 30_000_000_000)
    require(type(value["signature"]) is str and value["signature"].startswith("ed25519:"))
    decoded(value["signature"][8:], 64, 64)
    native = value["nativeKeyEvidence"]
    require(type(native) is dict and set(native) == {"apiVersion", "responseProofPublicKey", "attestationDocumentB64"}
        and native["apiVersion"] == "serverware.nativeResponseProofKeyEvidence/v1")
    decoded(native["responseProofPublicKey"], 32, 32); decoded(native["attestationDocumentB64"], 12288)
    return value


def input_sha256(values):
    return sha256(canonical({name: values[name] for name in FIELDS - {"native_evidence"}}))


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping))
    allowed = FIELDS | ({"businessIntent", "authn_evidence"} if typed else set())
    require(FIELDS <= set(value) <= allowed and (not typed or "businessIntent" in value))
    request = request_binding(operation, value["request"])
    require(value["action"] == ACTION and value["resource_id"] == request["exchangeId"]
        and value["approval_id"] is None and digest(value["payload_digest"]) == sha256(canonical(request)))
    require(material.text(value["actor_id"], 512).startswith("oidc:"))
    activation.policy(value["credential_policy"])
    enrollment = activation.enrollment_bytes(value["enrollment_original"])
    digest(value["control_plane_configuration_digest"])
    require(value["assignment_original"] is None if operation == OP_PREPARE else type(value["assignment_original"]) is dict)
    statement = evidence(value["native_evidence"])["statement"]
    require(statement["phase"] == ("draft" if operation == OP_PREPARE else operation.rsplit(".", 1)[1])
        and statement["exchangeId"] == request["exchangeId"] and statement["enrollmentSha256"] == sha256(enrollment)
        and statement["inputSha256"] == input_sha256(value))
    if operation == OP_PREPARE:
        require(request["enrollmentSha256"] == sha256(enrollment)
            and all(statement[name] == request[name] for name in ("providerId", "callbackOrigin", "portalOrigin")))
    originals = {name: value[name] for name in FIELDS}
    require(len(canonical(originals)) <= MAX_ARGUMENT_BYTES)
    return originals


def row_original(row):
    value = dict(row)
    require(set(value) == ROW_FIELDS and value["status"] in {"prepared", "claimed", "captured", "staged", "cancelled"})
    material.identifier(value["id"]); digest(value["prepare_request_digest"])
    for name, item in value.items():
        if item is None:
            require(name in NULLABLE)
        elif name in {"received_at_epoch_ns", "recovery_expires_at_epoch_ns"}:
            common.integer(item)
        else:
            require(type(item) is str)
    raw = canonical(value)
    require(len(raw) <= MAX_ROW_BYTES)
    return raw


def request_digest(operation, value):
    from serverware import authority_request_commitment as commitment
    return commitment.oauth_measured_exchange_request_digest(operation, value)
