"""Separate measured Setup issuance purpose and exact native originals.

No old measured-exchange permission or statement is converted into this one.
Only scalar/shape validators are shared with the old, still closed profile.
"""
from collections.abc import Mapping
from catchplate import authority_oauth_activation as activation
from catchplate import authority_oauth_measured_exchange as old
from catchplate import authority_oauth_setup as setup
from catchplate import native_oauth_exchange as material
from catchplate import native_oauth_refresh as common

canonical, require, digest, sha256 = common.canonical, common.require, common.digest, common.sha
document, encoded, decoded = common.document, common.encoded, common.decoded
ACTION = "credential.oauth.measured-setup-consent"
OPTIONS_SCHEMA = "catchplate.nativeOAuthSetupConsentOptions/v1"
STATEMENT = "catchplate.nativeOAuthSetupExchangeStatement/v1"
SIGN_OPERATION = "nativeOAuthSetupExchange.sign/v1"
SIGNATURE_DOMAIN = STATEMENT.encode("ascii") + b"\0"
ATTESTATION_DOMAIN = b"catchplate/native-oauth-setup-exchange-attestation/v1\0"
INTENT_SCHEMA = "catchplate.nativeOAuthExchangeIntent/v2"
STATE_SCHEMA = "catchplate.nativeOAuthExchangeState/v2"
HTTP_SCHEMA = "catchplate.nativeOAuthSetupExchangeRequest/v1"
HTTP_RESPONSE = "catchplate.nativeOAuthSetupExchangeResponse/v1"
RUNTIME_RESPONSE = "catchplate.policyAuthorityMeasuredSetupRuntimeResponse/v1"
INTENT_RESPONSE = "catchplate.nativeOAuthSetupIntentResponse/v1"
DRAFT_SCHEMA = "catchplate.nativeOAuthSetupDraft/v1"
HTTP_PATH = "/api/data-plane/oauth-setup-issuance"
HUMAN_PREFIX = "/api/setup/oauth/native"
OP_PREPARE = "oauth.measured-setup.prepare"
OP_CLAIM = "oauth.measured-setup.claim"
OP_CAPTURE = "oauth.measured-setup.capture"
OP_STAGE = "oauth.measured-setup.stage"
OP_RECOVER = "oauth.measured-setup.recover"
OP_CANCEL = "oauth.measured-setup.cancel"
OPERATIONS = frozenset({OP_PREPARE, OP_CLAIM, OP_CAPTURE, OP_STAGE, OP_RECOVER, OP_CANCEL})
ASSERTION_OPERATIONS = frozenset({OP_PREPARE})
TABLE = "oauth_measured_setup_custody"
WORK_SOURCE = "measured-oauth-setup-exchange/v1"
FIELDS = old.FIELDS
PREPARE_FIELDS = old.PREPARE_FIELDS | {"setupBinding"}
REQUEST_FIELDS = {operation: old.REQUEST_FIELDS["oauth.measured-exchange." + operation.rsplit(".", 1)[1]] | {"setupBinding"}
    for operation in OPERATIONS}
STATEMENT_FIELDS = old.STATEMENT_FIELDS | {"setupBindingSha256"}
SETUP_ROW_FIELDS = frozenset({"setup_initial_json", "setup_started_json", "setup_final_json"})
ROW_FIELDS = old.ROW_FIELDS | SETUP_ROW_FIELDS
NULLABLE = old.NULLABLE | SETUP_ROW_FIELDS
MAX_ARGUMENT_BYTES = old.MAX_ARGUMENT_BYTES
MAX_ROW_BYTES = 4 * 1024 * 1024
limits = old.limits


def request_binding(operation, value):
    require(operation in OPERATIONS and type(value) is dict and set(value) == REQUEST_FIELDS[operation])
    # This validates untrusted data shape only. Original bytes, operation,
    # signature domain and independent policy remain this distinct purpose.
    scalar_operation = "oauth.measured-exchange." + operation.rsplit(".", 1)[1]
    old.request_binding(scalar_operation, {name: value[name] for name in old.REQUEST_FIELDS[scalar_operation]})
    bound = setup.binding(value["setupBinding"])
    if operation == OP_PREPARE:
        require(value["pendingExpiresAtEpochNs"] <= bound["expiresAtEpochNs"])
    return dict(value)


def evidence(value):
    from catchplate import authority_credential_currentness as current
    require(type(value) is dict and set(value) == {"statement", "signature", "nativeKeyEvidence"})
    statement = value["statement"]
    require(type(statement) is dict and set(statement) == STATEMENT_FIELDS and statement["apiVersion"] == STATEMENT
        and statement["phase"] in {"draft", "claim", "capture", "stage", "recover", "cancel"}
        and statement["providerId"] in material.AUTHORIZATION)
    for name in ("holderId", "keyId", "controlPlaneResponseSigningKeyId", "enrollmentSha256", "inputSha256",
            "policyHash", "dataPlaneBinarySha256", "ingressLeafCertificateSha256", "ingressLeafSpkiSha256", "setupBindingSha256"):
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
        and native["apiVersion"] == "catchplate.nativeResponseProofKeyEvidence/v1")
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
    require(material.text(value["actor_id"], 512).startswith("oidc:")
        and request["setupBinding"]["ownerId"] == value["actor_id"]
        and request["setupBinding"]["currentAssigneeId"] in {None, value["actor_id"]})
    activation.policy(value["credential_policy"])
    enrollment = activation.enrollment_bytes(value["enrollment_original"])
    digest(value["control_plane_configuration_digest"])
    require(value["assignment_original"] is None if operation == OP_PREPARE else type(value["assignment_original"]) is dict)
    statement = evidence(value["native_evidence"])["statement"]
    require(statement["phase"] == ("draft" if operation == OP_PREPARE else operation.rsplit(".", 1)[1])
        and statement["exchangeId"] == request["exchangeId"] and statement["enrollmentSha256"] == sha256(enrollment)
        and statement["setupBindingSha256"] == sha256(canonical(request["setupBinding"]))
        and statement["inputSha256"] == input_sha256(value))
    if operation == OP_PREPARE:
        require(request["enrollmentSha256"] == sha256(enrollment)
            and all(statement[name] == request[name] for name in ("providerId", "callbackOrigin", "portalOrigin")))
    originals = {name: value[name] for name in FIELDS}
    require(len(canonical(originals)) <= MAX_ARGUMENT_BYTES)
    return originals


def row_original(row):
    value = dict(row)
    require(set(value) == ROW_FIELDS)
    old.row_original({name: value[name] for name in old.ROW_FIELDS})
    for name in SETUP_ROW_FIELDS:
        if value[name] is not None:
            require(type(value[name]) is str)
            raw = value[name].encode("ascii")
            require(setup.row_original(document(raw, setup.MAX_ROW_BYTES)) == raw)
    raw = canonical(value)
    require(len(raw) <= MAX_ROW_BYTES)
    return raw


def request_digest(operation, value):
    from catchplate import authority_request_commitment as commitment
    return commitment.oauth_measured_setup_request_digest(operation, value)
