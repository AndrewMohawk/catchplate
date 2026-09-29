"""Closed durable delivery slots, not permission inferred from observations.

One segmented original is one immutable HTTP body and one atomic preparation.
The segmentation never splits the admitted evidence batch or its effects.
"""
import hashlib
from collections.abc import Mapping

from serverware import authority_policy_canary as intake

canonical, require, digest, sha256 = intake.canonical, intake.require, intake.digest, intake.sha256
document, epoch, identifier, component = intake.document, intake.epoch, intake.identifier, intake.component
decoded = intake.decoded
OP_PREPARE = "policy.canary.delivery.prepare"
OP_CLAIM = "policy.canary.delivery.claim"
OP_RECOVER = "policy.canary.delivery.recover"
OPERATIONS = frozenset({OP_PREPARE, OP_CLAIM, OP_RECOVER})
HTTP_SCHEMA = "serverware.policyCanaryDeliveryRequest/v1"
HTTP_RESPONSE_SCHEMA = "serverware.policyCanaryDeliveryResponse/v1"
STATEMENT_SCHEMA = "serverware.nativeCanaryDeliveryStatement/v1"
RESPONSE_SCHEMA = "serverware.policyAuthorityCanaryDeliveryRuntimeResponse/v1"
COMPLETION_SCHEMA = "serverware.policyCanaryDeliveryCompletionOriginal/v1"
PATH = "/api/data-plane/policy-canary/delivery"
SLOTS = "policy_canary_delivery_slots"
HEADS = "policy_canary_delivery_heads"
PARTS = "policy_canary_delivery_parts"
TABLES = (SLOTS, HEADS, PARTS)
PART_BYTES = 64 * 1024
MAX_PARTS = 20
MAX_ARGUMENT = 3 * 1024 * 1024
MAX_COMPLETION = 768 * 1024
MAX_RESPONSE = 6 * 1024 * 1024
LIMITS = {"httpOriginalBytes": intake.MAX_HTTP, "argumentBytes": MAX_ARGUMENT,
    "completionOriginalBytes": MAX_COMPLETION, "responseBytes": MAX_RESPONSE,
    "partBytes": PART_BYTES, "parts": MAX_PARTS, "queryRows": 48, "mutations": 24, "workUnits": 8192}
FIELDS = frozenset({"control_plane_configuration_digest", "request", "native_evidence"})
REQUEST_FIELDS = {
    OP_PREPARE: frozenset({"httpOriginal", "expectedHeadSha256"}),
    OP_RECOVER: frozenset({"slotId", "httpSha256", "partCount"}),
    OP_CLAIM: frozenset({"slotId", "httpSha256", "partCount", "slotSha256", "headSha256",
        "prepareCompletionOriginal", "readCompletionOriginal"}),
}
STATEMENT_FIELDS = (intake.STATEMENT_FIELDS - {"batchSha256"}) | {
    "slotId", "requestSha256", "httpSha256", "originalExpiresAtEpochNs"}
SLOT_FIELDS = frozenset({"id", "head_id", "deployment_id", "canary_id", "instance_id",
    "holder_id", "native_boot_id", "key_id", "delivery_assignment_digest", "intake_assignment_digest",
    "canary_assignment_digest", "canary_boot_id", "configuration_digest", "http_sha256", "http_byte_count",
    "part_count", "status", "prepare_request_digest", "prepare_evidence_original", "claim_request_digest",
    "claim_evidence_original", "prepare_completion_sha256", "read_completion_sha256", "intake_request_digest",
    "intake_result_sha256", "issued_at_epoch_ns", "expires_at_epoch_ns", "created_at", "updated_at"})
HEAD_FIELDS = frozenset({"id", "deployment_id", "canary_id", "instance_id", "sequence", "slot_id", "status", "updated_at"})
PART_FIELDS = frozenset({"slot_id", "ordinal", "original", "original_sha256"})


def head_id(deployment, canary, instance):
    component(deployment); intake.text(canary, 256); component(instance)
    return sha256(b"serverware/canary-delivery-head/v1\0" + canonical([deployment, canary, instance]))


def http_original(original):
    require(type(original) is str)
    raw = original.encode("ascii")
    value = document(raw, intake.MAX_HTTP)
    require(set(value) == {"apiVersion", "batchOriginal", "nativeEvidence"} and value["apiVersion"] == intake.HTTP_SCHEMA)
    batch = intake.batch(value["batchOriginal"])
    evidence = intake.evidence(value["nativeEvidence"])
    signed = evidence["statement"]
    require(signed["operation"] == intake.OP_INTAKE and signed["requestId"] == batch["requestId"]
        and signed["canaryId"] == batch["canaryId"] and signed["batchSha256"] == sha256(value["batchOriginal"].encode("ascii")))
    return value


def parts(slot_id, original):
    identifier(slot_id); http_original(original)
    raw = original.encode("ascii")
    result = [{"slot_id": slot_id, "ordinal": index // PART_BYTES,
        "original": raw[index:index + PART_BYTES].decode("ascii"), "original_sha256": sha256(raw[index:index + PART_BYTES])}
        for index in range(0, len(raw), PART_BYTES)]
    require(1 <= len(result) <= MAX_PARTS)
    return result


def part_count(value):
    require(type(value) is int and 1 <= value <= MAX_PARTS)
    return value


def statement(value):
    require(type(value) is dict and set(value) == STATEMENT_FIELDS and value["apiVersion"] == STATEMENT_SCHEMA
        and value["operation"] in OPERATIONS)
    identifier(value["requestId"]); identifier(value["slotId"])
    # Sharing scalar identity validation does not admit an intake proof as a
    # delivery proof: the closed schema, operation and signature domain differ.
    common = {name: value[name] for name in intake.STATEMENT_FIELDS if name != "batchSha256"}
    intake.statement({**common, "apiVersion": intake.STATEMENT_SCHEMA, "operation": intake.OP_INTAKE,
        "batchSha256": value["httpSha256"]})
    digest(value["requestSha256"]); digest(value["httpSha256"]); epoch(value["originalExpiresAtEpochNs"])
    if value["operation"] != OP_RECOVER:
        require(value["expiresAtEpochNs"] <= value["originalExpiresAtEpochNs"])
    return value


def evidence(value):
    require(type(value) is dict and set(value) == {"statement", "signature", "nativeKeyEvidence", "clientCertificateDerBase64Url"})
    statement(value["statement"])
    require(type(value["signature"]) is str and value["signature"].startswith("ed25519:"))
    decoded(value["signature"][8:], 64, length=64)
    native = value["nativeKeyEvidence"]
    require(type(native) is dict and set(native) == {"apiVersion", "responseProofPublicKey", "attestationDocumentB64"}
        and native["apiVersion"] == "serverware.nativeResponseProofKeyEvidence/v1")
    decoded(native["responseProofPublicKey"], 32, length=32); decoded(native["attestationDocumentB64"], 12 * 1024)
    require(sha256(decoded(value["clientCertificateDerBase64Url"], 16 * 1024)) == value["statement"]["clientCertificateSha256"]
        and len(canonical(value)) <= 128 * 1024)
    return value


def signature_domain(operation):
    require(operation in OPERATIONS)
    return (STATEMENT_SCHEMA + "/" + operation.rsplit(".", 1)[1]).encode("ascii") + b"\0"


def attestation_nonce(value):
    evidence(value)
    operation = value["statement"]["operation"]
    domain = ("serverware/canary-delivery-" + operation.rsplit(".", 1)[1] + "-attestation/v1").encode("ascii")
    return hashlib.sha256(domain + b"\0" + decoded(value["statement"]["nonce"], 32, length=32)
        + hashlib.sha256(canonical(value["statement"])).digest() + decoded(value["signature"][8:], 64, length=64)).digest()


def completion_original(original):
    require(type(original) is str)
    value = document(original.encode("ascii"), MAX_COMPLETION)
    require(set(value) == {"schema", "requestOriginal", "responseOriginal"} and value["schema"] == COMPLETION_SCHEMA)
    require(type(value["requestOriginal"]) is str and type(value["responseOriginal"]) is str)
    document(value["requestOriginal"].encode("ascii"), MAX_ARGUMENT)
    document(value["responseOriginal"].encode("ascii"), MAX_RESPONSE)
    return value


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping)
        and set(value) == (FIELDS | {"businessIntent"} if typed else FIELDS))
    digest(value["control_plane_configuration_digest"])
    request = value["request"]
    require(type(request) is dict and set(request) == REQUEST_FIELDS[operation])
    signed = evidence(value["native_evidence"])["statement"]
    require(signed["operation"] == operation and signed["requestSha256"] == sha256(canonical(request)))
    if operation == OP_PREPARE:
        original = http_original(request["httpOriginal"])
        selected = original["nativeEvidence"]["statement"]
        require(signed["slotId"] == selected["requestId"] and signed["httpSha256"] == sha256(request["httpOriginal"].encode("ascii"))
            and signed["originalExpiresAtEpochNs"] == selected["expiresAtEpochNs"])
        if request["expectedHeadSha256"] is not None: digest(request["expectedHeadSha256"])
        for name in ("deploymentId", "instanceId", "canaryId", "canaryAssignmentSha256", "canaryBootId", "holderId", "bootId", "keyId",
                "controlPlaneResponseSigningKeyId", "policyHash", "dataPlaneBinarySha256", "clientCertificateSha256", "clientSpkiSha256", "workloadUri"):
            require(signed[name] == selected[name], "delivery preparation has no same-owner intake original")
    else:
        identifier(request["slotId"]); digest(request["httpSha256"]); part_count(request["partCount"])
        require(signed["slotId"] == request["slotId"] and signed["httpSha256"] == request["httpSha256"])
        if operation == OP_CLAIM:
            digest(request["slotSha256"]); digest(request["headSha256"])
            completion_original(request["prepareCompletionOriginal"]); completion_original(request["readCompletionOriginal"])
            require(len(request["prepareCompletionOriginal"].encode("ascii")) + len(request["readCompletionOriginal"].encode("ascii")) <= 2 * MAX_COMPLETION)
    result = {name: value[name] for name in FIELDS}
    require(len(canonical(result)) <= MAX_ARGUMENT)
    return result


def request_digest(operation, value):
    from serverware import authority_contract as contract
    from serverware import authority_request_commitment as commitment
    values = arguments(operation, value, typed="businessIntent" in value)
    typed = {**values, "businessIntent": contract.synthesize_business_intent(operation, values)}
    return commitment.framed_digest("serverware.policyAuthorityV9Request/v1", canonical({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": contract.operation_spec(operation)["handler"], "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": commitment._authorization_arguments(typed)}))


def row_original(table, row):
    fields = {SLOTS: SLOT_FIELDS, HEADS: HEAD_FIELDS, PARTS: PART_FIELDS}
    require(table in fields and type(row) is dict and set(row) == fields[table])
    if table == PARTS:
        identifier(row["slot_id"])
        require(type(row["ordinal"]) is int and 0 <= row["ordinal"] < MAX_PARTS and type(row["original"]) is str
            and 0 < len(row["original"].encode("ascii")) <= PART_BYTES and sha256(row["original"].encode("ascii")) == row["original_sha256"])
    elif table == HEADS:
        require(row["id"] == head_id(row["deployment_id"], row["canary_id"], row["instance_id"])
            and type(row["sequence"]) is int and 1 <= row["sequence"] <= 2**63 - 1 and row["status"] in {"prepared", "claimed", "consumed"})
        identifier(row["slot_id"]); intake.text(row["updated_at"], 128)
    else:
        identifier(row["id"]); part_count(row["part_count"])
        require(row["head_id"] == head_id(row["deployment_id"], row["canary_id"], row["instance_id"])
            and type(row["http_byte_count"]) is int and 0 < row["http_byte_count"] <= intake.MAX_HTTP
            and row["part_count"] == (row["http_byte_count"] + PART_BYTES - 1) // PART_BYTES
            and row["status"] in {"prepared", "claimed", "consumed"})
        for name in ("holder_id", "key_id", "delivery_assignment_digest", "intake_assignment_digest", "canary_assignment_digest",
                "canary_boot_id", "configuration_digest", "http_sha256", "prepare_request_digest"):
            digest(row[name])
        decoded(row["native_boot_id"], 32, length=32)
        evidence(document(row["prepare_evidence_original"].encode("ascii"), 128 * 1024))
        for name in ("claim_request_digest", "prepare_completion_sha256", "read_completion_sha256", "intake_request_digest", "intake_result_sha256"):
            if row[name] is not None: digest(row[name])
        require((row["claim_request_digest"] is None) is (row["status"] == "prepared")
            and (row["claim_evidence_original"] is None) is (row["status"] == "prepared")
            and (row["prepare_completion_sha256"] is None) is (row["status"] == "prepared")
            and (row["read_completion_sha256"] is None) is (row["status"] == "prepared")
            and (row["intake_request_digest"] is None) is (row["status"] != "consumed")
            and (row["intake_result_sha256"] is None) is (row["status"] != "consumed"))
        if row["claim_evidence_original"] is not None: evidence(document(row["claim_evidence_original"].encode("ascii"), 128 * 1024))
        require(0 < epoch(row["expires_at_epoch_ns"]) - epoch(row["issued_at_epoch_ns"]) <= 30_000_000_000)
        intake.text(row["created_at"], 128); intake.text(row["updated_at"], 128)
    raw = canonical(row)
    require(len(raw) <= 1024 * 1024)
    return raw


def reassemble(slot, rows):
    row_original(SLOTS, slot)
    require(type(rows) is list and len(rows) == slot["part_count"])
    for index, row in enumerate(rows):
        row_original(PARTS, row)
        require(row["slot_id"] == slot["id"] and row["ordinal"] == index)
    original = "".join(row["original"] for row in rows)
    require(len(original.encode("ascii")) == slot["http_byte_count"] and sha256(original.encode("ascii")) == slot["http_sha256"]
        and parts(slot["id"], original) == rows)
    return original


def result(value):
    require(type(value) is dict and set(value) == {"ok", "operation", "requestDigest", "auditEventDigest",
        "idempotentReplay", "status", "observation"} and value["ok"] is True and value["operation"] in OPERATIONS
        and value["idempotentReplay"] is False and value["status"] in {"unknown", "prepared", "claimed", "consumed"})
    digest(value["requestDigest"]); digest(value["auditEventDigest"])
    observation = value["observation"]
    require(type(observation) is dict and set(observation) == {"slotOriginal", "headOriginal", "httpOriginal", "intakeOriginal"})
    for field, table in (("slotOriginal", SLOTS), ("headOriginal", HEADS)):
        if observation[field] is not None:
            require(type(observation[field]) is str)
            row_original(table, document(observation[field].encode("ascii"), 1024 * 1024))
    if value["status"] == "unknown":
        require(observation["slotOriginal"] is None and observation["httpOriginal"] is None and observation["intakeOriginal"] is None)
    else:
        slot = document(observation["slotOriginal"].encode("ascii"), 1024 * 1024)
        require(slot["status"] == value["status"] and observation["headOriginal"] is not None)
        http_original(observation["httpOriginal"])
        require(sha256(observation["httpOriginal"].encode("ascii")) == slot["http_sha256"])
        require((observation["intakeOriginal"] is None) is (value["status"] != "consumed"))
        if observation["intakeOriginal"] is not None:
            intake.row_original(document(observation["intakeOriginal"].encode("ascii"), intake.MAX_RESPONSE))
    require(len(canonical(value)) <= MAX_ARGUMENT)
    return value
