"""Closed measured due-refresh requests and retained ciphertext custody."""
from __future__ import annotations

import uuid
from collections.abc import Mapping
from serverware import authority_oauth_refresh as refresh
from serverware import native_oauth_refresh as material

canonical, require, digest, sha256 = material.canonical, material.require, material.digest, material.sha
document, encoded, decoded = material.document, material.encoded, material.decoded
OP_INSPECT = "oauth.measured-refresh.inspect"
OP_CLAIM = "oauth.measured-refresh.claim"
OP_CAPTURE = "oauth.measured-refresh.capture"
OP_COMMIT = "oauth.measured-refresh.commit"
OP_RECOVER = "oauth.measured-refresh.recover"
OPERATIONS = frozenset({OP_INSPECT, OP_CLAIM, OP_CAPTURE, OP_COMMIT, OP_RECOVER})
TABLE = "oauth_measured_refresh_custody"
ISSUED_SOURCE = "measured-oauth-refresh-issued/v1"
SUPERSEDED_SOURCE = "measured-oauth-refresh-superseded/v1"
STATEMENT = "serverware.nativeOAuthRefreshStatement/v1"
SIGN_OPERATION = "nativeOAuthRefresh.sign/v1"
SIGNATURE_DOMAIN = STATEMENT.encode("ascii") + b"\0"
ATTESTATION_DOMAIN = b"serverware/native-oauth-refresh-attestation/v1\0"
OUTER = frozenset({"credential_id", "enrollment_original", "control_plane_configuration_digest", "assignment_original", "request", "evidence"})
STATEMENT_FIELDS = frozenset({"apiVersion", "phase", "holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId",
    "deploymentId", "instanceId", "providerId", "enrollmentSha256", "credentialId", "credentialVersion",
    "refreshId", "inputSha256", "challenge", "policyHash", "dataPlaneBinarySha256", "issuedAtEpochNs", "expiresAtEpochNs"})
ROW_FIELDS = frozenset({"id", "credential_id", "credential_version", "enrollment_original", "assignment_original_json",
    "claim_evidence_original_json", "claim_request_json", "capture_evidence_original_json", "capture_request_json",
    "commit_evidence_original_json", "commit_request_json", "recovery_request_digest", "recovery_expires_at_epoch_ns",
    "recovery_evidence_original_json", "recovery_owner_nonce_sha256", "status", "created_at", "updated_at"})
NULLABLE = frozenset({"capture_evidence_original_json", "capture_request_json", "commit_evidence_original_json",
    "commit_request_json", "recovery_request_digest", "recovery_expires_at_epoch_ns", "recovery_evidence_original_json", "recovery_owner_nonce_sha256"})
MAX_ARGUMENT_BYTES = 2 * 1024 * 1024
MAX_ROW_BYTES = 4 * 1024 * 1024
_BASE_OPERATION = {OP_CLAIM: refresh.OP_CLAIM, OP_CAPTURE: refresh.OP_RETAIN, OP_COMMIT: refresh.OP_COMMIT}
_EXTRA_REQUEST = {
    OP_CLAIM: frozenset({"applicationMaterialSha256"}),
    OP_CAPTURE: frozenset(),
    OP_COMMIT: frozenset({"recoveryRequestDigest"}),
}


def row_original(row):
    value = dict(row)
    require(set(value) == ROW_FIELDS)
    require(str(uuid.UUID(value["id"])) == value["id"] and str(uuid.UUID(value["credential_id"])) == value["credential_id"])
    material.integer(value["credential_version"])
    require(value["status"] in {"claimed", "captured", "committed"})
    for name, item in value.items():
        if item is None:
            require(name in NULLABLE)
        elif name == "recovery_expires_at_epoch_ns":
            material.integer(item)
        elif name != "credential_version":
            require(type(item) is str)
    raw = canonical(value)
    require(len(raw) <= MAX_ROW_BYTES)
    return raw


def input_sha256(values):
    return sha256(canonical({name: values[name] for name in OUTER - {"evidence"}}))


def evidence(value):
    from serverware import authority_credential_currentness as currentness
    require(type(value) is dict and set(value) == {"statement", "signature", "nativeKeyEvidence"})
    statement = value["statement"]
    require(type(statement) is dict and set(statement) == STATEMENT_FIELDS and statement["apiVersion"] == STATEMENT
        and statement["phase"] in {name.rsplit(".", 1)[1] for name in OPERATIONS}
        and statement["providerId"] in material.ENDPOINTS)
    for name in ("holderId", "keyId", "controlPlaneResponseSigningKeyId", "enrollmentSha256", "inputSha256", "policyHash", "dataPlaneBinarySha256"):
        digest(statement[name])
    require(statement["holderId"] == currentness.holder_id(statement["bootId"], statement["keyId"]))
    decoded(statement["challenge"], 32, 32)
    material.text(statement["instanceId"], 4096); material.text(statement["deploymentId"], 128)
    refresh._uuid(statement["credentialId"])
    material.integer(statement["credentialVersion"], minimum=0)
    material.integer(statement["issuedAtEpochNs"]); material.integer(statement["expiresAtEpochNs"])
    require(0 < statement["expiresAtEpochNs"] - statement["issuedAtEpochNs"] <= 30_000_000_000)
    if statement["phase"] == "inspect":
        require(statement["credentialVersion"] == 0 and statement["refreshId"] is None)
    else:
        require(statement["credentialVersion"] > 0 and statement["refreshId"] == refresh.refresh_id(
            statement["credentialId"], statement["credentialVersion"]))
    signature = value["signature"]
    require(type(signature) is str and signature.startswith("ed25519:"))
    decoded(signature[8:], 64, 64)
    native = value["nativeKeyEvidence"]
    require(type(native) is dict and set(native) == {"apiVersion", "responseProofPublicKey", "attestationDocumentB64"}
        and native["apiVersion"] == "serverware.nativeResponseProofKeyEvidence/v1")
    decoded(native["responseProofPublicKey"], 32, 32)
    decoded(native["attestationDocumentB64"], 12 * 1024)
    return value


def request(operation, value):
    require(operation in OPERATIONS and type(value) is dict)
    if operation in _BASE_OPERATION:
        extra = _EXTRA_REQUEST[operation]
        require(set(value) == refresh.REQUEST_FIELDS[_BASE_OPERATION[operation]] | extra)
        refresh.request_binding(_BASE_OPERATION[operation], {name: item for name, item in value.items() if name not in extra})
        if operation == OP_CLAIM:
            digest(value["applicationMaterialSha256"])
        if operation == OP_COMMIT and value["recoveryRequestDigest"] is not None:
            digest(value["recoveryRequestDigest"])
    elif operation == OP_INSPECT:
        require(set(value) == {"issuedAtEpochNs", "expiresAtEpochNs", "applicationMaterialSha256", "limits", "recoveryVersion"})
        digest(value["applicationMaterialSha256"])
        refresh.limits(value["limits"])
        if value["recoveryVersion"] is not None:
            refresh._version(value["recoveryVersion"])
    else:
        require(set(value) == {"expectedVersion", "custodyRowSha256", "captureInputSha256", "ownerNonceSha256",
            "issuedAtEpochNs", "expiresAtEpochNs", "limits"})
        refresh._version(value["expectedVersion"])
        for name in ("custodyRowSha256", "captureInputSha256", "ownerNonceSha256"):
            digest(value[name])
        refresh.limits(value["limits"])
    if operation in {OP_INSPECT, OP_RECOVER}:
        material.integer(value["issuedAtEpochNs"]); material.integer(value["expiresAtEpochNs"])
        require(0 < value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= 30_000_000_000)
    return value


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping)
        and set(value) == OUTER | ({"businessIntent"} if typed else set()))
    refresh._uuid(value["credential_id"])
    refresh.enrollment_bytes(value["enrollment_original"])
    digest(value["control_plane_configuration_digest"])
    require(value["assignment_original"] is None if operation == OP_INSPECT else type(value["assignment_original"]) is dict)
    request(operation, value["request"])
    proof = evidence(value["evidence"])
    statement = proof["statement"]
    require(statement["phase"] == operation.rsplit(".", 1)[1]
        and statement["credentialId"] == value["credential_id"]
        and statement["credentialVersion"] == (0 if operation == OP_INSPECT else value["request"]["expectedVersion"])
        and statement["enrollmentSha256"] == sha256(refresh.enrollment_bytes(value["enrollment_original"]))
        and statement["inputSha256"] == input_sha256(value))
    require(len(canonical(value)) <= MAX_ARGUMENT_BYTES)
    # The shared typed-request admission independently checks businessIntent;
    # this shape projection never manufactures a replacement typed request.
    return {name: value[name] for name in OUTER}


def request_digest(operation, value):
    from serverware import authority_request_commitment as commitment
    return commitment.oauth_measured_refresh_request_digest(operation, value)
