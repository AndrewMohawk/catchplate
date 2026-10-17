"""Closed native READY/activation originals, separate from Fleet signatures.

Codecs confer no permission. Real request/prepare kernels authenticate complete
current populations, hardware assertions and independent signed configuration.
The native publisher separately admits the whole actual preparation proof.
"""
from collections.abc import Mapping
import uuid

from catchplate import authority_policy_canary as p
from catchplate import authority_publication_approval as assertions

FIELD = "policyCanaryNativeActivationPolicy"
POLICY = "catchplate.policyCanaryNativeActivationAuthorityPolicy/v1"
INTENT = "catchplate.nativePolicyActivationIntent/v1"
READY = "catchplate.nativePolicyReadyState/v1"
PREPARED = "catchplate.nativePolicyActivationPrepared/v1"
NATIVE_REQUEST = "catchplate.nativePolicyActivationRequest/v1"
PUBLICATION = "catchplate.nativePolicyActivationPublication/v1"
PUBLICATION_PURPOSE = "native-policy-activation-publication"
PUBLICATION_DOMAIN = "catchplate.nativePolicyActivationPublication.signature/v1"
HTTP = "catchplate.nativePolicyActivationHttp/v1"
PREFIX = "native-policy-activation."
ASSERTION_OPERATIONS = frozenset(PREFIX + phase for phase in ("request", "decide", "consume"))
OPERATIONS = ASSERTION_OPERATIONS | frozenset(PREFIX + phase for phase in ("record-inclusion", "finalize"))
ROLE = "policy_publisher"
ACTION = "policy.native.activate"
RESOURCE = "native-policy-activation"
PROVENANCE = "catchplate.nativePolicyActivationApprovalProvenance/v1"
RESPONSE_SCHEMA = "catchplate.policyAuthorityNativeActivationRuntimeResponse/v1"
RESULT_FIELDS = frozenset({"ok", "operation", "requestDigest", "auditEventDigest", "idempotentReplay",
    "approval", "preparedOriginal", "preparedSha256", "readyOriginal"})
PROOF_FIELDS = frozenset({"signedMeasuredPlanOriginal", "executorCompletionOriginal", "witnessRequestOriginal", "witnessResponseOriginal", "nativeEffectHoldOriginal"})
READY_TABLE = "policy_native_canary_ready"
HEAD_TABLE = "policy_native_canary_heads"
PREPARATION_TABLE = "policy_native_activation_preparations"
FINALIZATION_TABLE = "policy_native_activation_finalizations"
MAX_ORIGINAL = 1024 * 1024
MAX_NATIVE = 8 * 1024 * 1024
MAX_BEFORE = p.MAX_ARGUMENT
POLICY_FIELDS = frozenset({"schema", "deploymentId", "issuedAtEpochNs", "expiresAtEpochNs",
    "maximumActivationNanos", "canaries", "publicationKeys"})
INTENT_FIELDS = frozenset({"apiVersion", "activationId", "replayId", "canaryId", "readinessRequestId",
    "readinessResultSha256", "readinessCoreSha256", "readyStateSha256", "generationPublicationEnvelopeSha256",
    "generationId", "publicationBefore", "publicationAfter", "trustCheckpoint", "issuedAtUnixNanos", "expiresAtUnixNanos"})
PREPARED_FIELDS = frozenset({"apiVersion", "activationId", "replayId", "canaryId", "assignmentSha256",
    "assignmentPayloadSha256", "assignmentRevision", "authorityKeyIndependenceSha256", "generationId",
    "generationPublicationEnvelopeSha256", "readyStateSha256", "readinessRequestId", "readinessResultSha256",
    "readinessCoreSha256", "publicationBefore", "publicationAfter", "trustCheckpoint", "approvalOriginal",
    "readinessOriginal", "readyOriginal", "controlPlaneConfigurationSha256", "activationPolicySha256",
    "issuedAtUnixNanos", "expiresAtUnixNanos"})
NATIVE_FIELDS = frozenset({"apiVersion", "requestId", "replayId", "prepareRequestOriginal", "prepareResponseOriginal"})
PUBLICATION_FIELDS = frozenset({"apiVersion", "purpose", "activationId", "replayId", "requestSha256", "preparedSha256",
    "assignmentPayloadSha256", "generationId", "generationPublicationEnvelopeSha256", "publicationBefore",
    "publicationAfter", "trustCheckpoint", "durableStateSha256", "observedAtUnixNanos", "expiresAtUnixNanos",
    "signingKeyId", "signingKeySpkiSha256"})
FIELDS = frozenset({"actor_id", "control_plane_configuration_digest", "request", "approval_id",
    "approval_original", "credential_policy", "before_original", "activation_policy"})
READY_FIELDS = frozenset({"canary_id", "ready_revision", "ready_state_digest", "readiness_request_id",
    "readiness_record_sha256", "readiness_result_original", "ready_original", "configuration_digest",
    "activation_policy_sha256", "transition_digest", "created_at_epoch_ns", "expires_at_epoch_ns"})


def canonical_original(value, maximum=MAX_ORIGINAL):
    p.require(type(value) is str)
    original = value.encode("ascii")
    result = p.document(original, maximum)
    p.require(p.canonical(result) == original)
    return result


def publication_tuple(value, *, before):
    p.require(type(value) is dict and set(value) == ({"revision", "policySha256", "policySequence", "rollbackEpoch"}
        if before else {"policySha256", "policySequence", "rollbackEpoch"}))
    p.digest(value["policySha256"])
    for name in ("policySequence",) + (("revision",) if before else ()):
        p.epoch(value[name])
    p.require(type(value["rollbackEpoch"]) is int and 0 <= value["rollbackEpoch"] <= 2**63 - 1)
    return value


def completed_audit_originals(value):
    """Only the finalizer's exact canonical four-row list, not a new codec."""
    p.require(type(value) is str and value.isascii() and 2 <= len(value) <= MAX_ORIGINAL)
    # The shared document decoder deliberately admits object roots only. Keep
    # that contract: a fixed source wrapper uses its duplicate/depth/node checks.
    original = value.encode("ascii")
    wrapped = p.document(b'{"audits":' + original + b'}', MAX_ORIGINAL + 11)
    p.require(set(wrapped) == {"audits"} and type(wrapped["audits"]) is list and len(wrapped["audits"]) == 4
        and all(type(row) is dict for row in wrapped["audits"]) and p.canonical(wrapped["audits"]) == original)
    return wrapped["audits"]


def validate_policy(value, *, payload=None, root_key=None):
    if value is None:
        if payload is not None:
            p.require(not any(set(role.get("enabledOperations", ())) & OPERATIONS for role in payload["roles"].values()),
                "enabled native activation requires its independently signed policy")
        return None
    p.require(type(value) is dict and set(value) == POLICY_FIELDS and value["schema"] == POLICY)
    p.component(value["deploymentId"])
    issued, expires = p.epoch(value["issuedAtEpochNs"]), p.epoch(value["expiresAtEpochNs"])
    p.require(0 < expires - issued <= 86_400_000_000_000 and type(value["maximumActivationNanos"]) is int
        and 1_000_000_000 <= value["maximumActivationNanos"] <= 300_000_000_000)
    for name in ("canaries", "publicationKeys"):
        p.require(type(value[name]) is list and 1 <= len(value[name]) <= 32)
    identities = []
    for item in value["canaries"]:
        p.require(type(item) is dict and set(item) == {"canaryId", "assignmentSha256"})
        p.text(item["canaryId"], 256); p.digest(item["assignmentSha256"])
        identities.append((item["canaryId"], item["assignmentSha256"]))
    p.require(identities == sorted(set(identities)))
    keys = []
    for item in value["publicationKeys"]:
        p.require(type(item) is dict and set(item) == {"keyId", "publicKeyBase64Url"})
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives import serialization
        raw = p.decoded(item["publicKeyBase64Url"], 32, length=32)
        spki = Ed25519PublicKey.from_public_bytes(raw).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        p.require(p.digest(item["keyId"]) == p.sha256(spki))
        keys.append(item["keyId"])
    p.require(keys == sorted(set(keys)) and len(p.canonical(value)) <= 16384)
    return value


def intent(value):
    p.require(type(value) is dict and set(value) == INTENT_FIELDS and value["apiVersion"] == INTENT)
    for name in ("activationId", "replayId", "readinessRequestId"):
        p.identifier(value[name])
    p.require(value["activationId"] != value["replayId"])
    p.text(value["canaryId"], 256)
    for name in ("readinessResultSha256", "readinessCoreSha256", "readyStateSha256", "generationPublicationEnvelopeSha256", "generationId"):
        p.digest(value[name])
    before, after = publication_tuple(value["publicationBefore"], before=True), publication_tuple(value["publicationAfter"], before=False)
    p.require(before["revision"] < 2**63 - 1 and after["policySequence"] > before["policySequence"]
        and after["rollbackEpoch"] >= before["rollbackEpoch"] and after["policySha256"] != before["policySha256"])
    issued, expires = p.epoch(value["issuedAtUnixNanos"]), p.epoch(value["expiresAtUnixNanos"])
    p.require(0 < expires - issued <= 300_000_000_000 and type(value["trustCheckpoint"]) is dict
        and len(p.canonical(value)) <= 16384)
    return value


def arguments(operation, value, *, typed=False):
    p.require(operation in OPERATIONS and isinstance(value, Mapping))
    fields = FIELDS | ({"native_request", "publication_original"} if operation == PREFIX + "record-inclusion" else set())
    p.require(fields <= set(value) and set(value) <= fields | ({"businessIntent", "authn_evidence"} if typed else set())
        and (not typed or "businessIntent" in value))
    p.text(value["actor_id"], 512); p.require(value["actor_id"].startswith("oidc:")
        and not any(ord(char) <= 32 or ord(char) == 127 for char in value["actor_id"]))
    p.digest(value["control_plane_configuration_digest"]); intent(value["request"])
    assertions.policy(value["credential_policy"]); validate_policy(value["activation_policy"])
    p.require(value["activation_policy"] is not None)
    canonical_original(value["before_original"], MAX_BEFORE)
    if operation == PREFIX + "request":
        p.require(value["approval_id"] is None and value["approval_original"] is None)
    else:
        p.require(type(value["approval_id"]) is str and str(uuid.UUID(value["approval_id"])) == value["approval_id"])
        original = canonical_original(value["approval_original"], MAX_ORIGINAL)
        p.require(original["id"] == value["approval_id"])
    if operation == PREFIX + "record-inclusion":
        native_request(value["native_request"])
        canonical_original(value["publication_original"], 32768)
    p.require(len(p.canonical(dict(value))) <= MAX_NATIVE)
    return {name: value[name] for name in fields}


def request_digest(operation, value):
    from catchplate import authority_contract as contract
    from catchplate import authority_request_commitment as commitment
    values = arguments(operation, value, typed="businessIntent" in value)
    typed = {**values, "businessIntent": contract.synthesize_business_intent(operation, values)}
    material = {"schema": "catchplate.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": contract.operation_spec(operation)["handler"], "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": commitment._authorization_arguments(typed)}
    return commitment.framed_digest("catchplate.policyAuthorityV9Request/v1", p.canonical(material))


def verify_original(operation, value, *, configuration_payload, root_key, now_epoch_ns):
    from catchplate import authority_policy_canary_native_readiness as readiness
    from catchplate import authority_policy_canary_policy as configuration
    values = arguments(operation, value, typed="businessIntent" in value)
    p.require(values["control_plane_configuration_digest"] == configuration.full_configuration_digest(configuration_payload))
    selected = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    p.require(selected is not None and p.canonical(selected) == p.canonical(values["activation_policy"]))
    if operation not in ASSERTION_OPERATIONS:
        # Metadata settlement consumes the exact original held preparation and
        # definite in-window native receipt. It grants no new native contact and
        # does not refresh expired readiness or free an unknown effect.
        return
    p.require(selected["issuedAtEpochNs"] <= now_epoch_ns < selected["expiresAtEpochNs"])
    before = canonical_original(values["before_original"], MAX_BEFORE)
    rows = [row for row in before[p.TABLE] if row["request_id"] == values["request"]["readinessRequestId"]]
    p.require(len(rows) == 1)
    p.row_original(rows[0])
    # Independently admit the original readiness and each embedded finalization
    # purpose now; authenticated complete roots remain the planner's own job.
    readiness.verify_batch(rows[0]["batch_original"], configuration_payload=configuration_payload,
        root_key=root_key, now_epoch_ns=now_epoch_ns, before_original=values["before_original"])


def native_request(value):
    p.require(type(value) is dict and set(value) == NATIVE_FIELDS and value["apiVersion"] == NATIVE_REQUEST
        and len(p.canonical(value)) <= MAX_NATIVE)
    p.identifier(value["requestId"]); p.identifier(value["replayId"])
    p.require(value["requestId"] != value["replayId"])
    canonical_original(value["prepareRequestOriginal"], MAX_NATIVE)
    canonical_original(value["prepareResponseOriginal"], MAX_NATIVE)
    return value


def prepared(value):
    p.require(type(value) is dict and set(value) == PREPARED_FIELDS and value["apiVersion"] == PREPARED)
    for name in ("activationId", "replayId", "readinessRequestId"):
        p.identifier(value[name])
    p.epoch(value["assignmentRevision"])
    for name in ("assignmentSha256", "assignmentPayloadSha256", "authorityKeyIndependenceSha256", "generationId",
            "generationPublicationEnvelopeSha256", "readyStateSha256", "readinessResultSha256", "readinessCoreSha256",
            "controlPlaneConfigurationSha256", "activationPolicySha256"):
        p.digest(value[name])
    publication_tuple(value["publicationBefore"], before=True); publication_tuple(value["publicationAfter"], before=False)
    for name in ("approvalOriginal", "readinessOriginal", "readyOriginal"):
        canonical_original(value[name])
    p.require(p.epoch(value["issuedAtUnixNanos"]) < p.epoch(value["expiresAtUnixNanos"])
        and len(p.canonical(value)) <= MAX_ORIGINAL)
    return value
