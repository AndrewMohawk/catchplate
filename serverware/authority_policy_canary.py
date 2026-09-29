"""Closed native canary batch originals; data alone never admits an effect."""
import base64
import hashlib
import re
from collections.abc import Mapping

from serverware import authority_policy_candidate as candidate

canonical, require, digest, sha256 = candidate.canonical, candidate.require, candidate.digest, candidate.sha256
document, epoch, text = candidate.scalar.document, candidate.epoch, candidate.text
OP_INTAKE = "policy.canary.evidence-intake"
OP_INSPECT = "policy.canary.evidence-inspect"
OPERATIONS = frozenset({OP_INTAKE})
HTTP_SCHEMA = "serverware.policyCanaryControlledEvidence/v1"
BATCH_SCHEMA = "serverware.policyCanaryEvidenceOriginal/v1"
STATEMENT_SCHEMA = "serverware.nativeCanaryEvidenceIntakeStatement/v1"
RECEIVER_SCHEMA = "serverware.policyCanaryIntakeReceiverConfiguration/v1"
TABLE = "policy_canary_intake_batches"
MAX_ORIGINAL = 1024 * 1024
MAX_ARGUMENT = 3 * 1024 * 1024
MAX_HTTP = MAX_ORIGINAL + 192 * 1024
MAX_RESPONSE = 4 * 1024 * 1024
MAX_RESULT = 2 * 1024 * 1024
RESULT_SCHEMA = "serverware.policyCanaryControlledEvidenceResult/v1"
MAX_ROWS = 32
LIMITS = {"originalBytes": MAX_ORIGINAL, "argumentBytes": MAX_ARGUMENT, "tableRows": MAX_ROWS,
    "events": 128, "queryRows": 240, "mutations": 96, "workUnits": 8192}
KINDS = frozenset({"assignment", "canary-revision", "load-receipt", "runtime-attestation-handoff", "custody",
    "ingress", "active-decision", "shadow-observation", "instance-revision", "checkpoint", "compiler-analysis", "readiness"})
STATEMENT_FIELDS = frozenset({"apiVersion", "operation", "requestId", "deploymentId", "instanceId", "holderId", "bootId",
    "keyId", "controlPlaneResponseSigningKeyId", "policyHash", "dataPlaneBinarySha256", "purposeAssignmentSha256", "canaryId",
    "canaryAssignmentSha256", "canaryBootId", "batchSha256", "workloadUri", "clientCertificateSha256", "clientSpkiSha256", "nonce",
    "issuedAtEpochNs", "expiresAtEpochNs"})
FIELDS = frozenset({"control_plane_configuration_digest", "batch_original", "native_evidence", "before_original"})
ROW_FIELDS = frozenset({"request_id", "canary_id", "instance_id", "boot_id", "purpose_assignment_digest",
    "canary_assignment_digest", "configuration_digest", "batch_sha256", "batch_original", "native_evidence_original",
    "request_digest", "result_original", "audit_event_digest", "issued_at_epoch_ns", "expires_at_epoch_ns", "created_at"})


def component(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value) is not None)
    return value


def identifier(value):
    candidate.scalar.identifier(value)
    require(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", value) is not None)
    return value


def workload_uri(deployment, instance):
    return "spiffe://serverware.policy-canary/" + component(deployment) + "/" + component(instance)


def decoded(value, maximum, *, length=None):
    require(type(value) is str and 0 < len(value) <= (maximum * 4 + 2) // 3)
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    require(0 < len(raw) <= maximum and (length is None or len(raw) == length)
        and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)
    return raw


def batch(original):
    require(type(original) is str)
    raw = original.encode("ascii")
    value = document(raw, MAX_ORIGINAL)
    require(type(value) is dict and set(value) == {"apiVersion", "requestId", "canaryId", "events"}
        and value["apiVersion"] == BATCH_SCHEMA and canonical(value) == raw)
    identifier(value["requestId"]); text(value["canaryId"], 256)
    events = value["events"]
    require(type(events) is list and 1 <= len(events) <= LIMITS["events"])
    seen = set()
    for event in events:
        require(type(event) is dict and set(event) == {"kind", "record"} and event["kind"] in KINDS
            and type(event["record"]) is dict and event["record"].get("canary_id") == value["canaryId"])
        identity = (event["kind"], sha256(canonical(event["record"])))
        require(identity not in seen, "canary intake repeats a signed record")
        seen.add(identity)
    return value


def statement(value):
    require(type(value) is dict and set(value) == STATEMENT_FIELDS and value["apiVersion"] == STATEMENT_SCHEMA
        and value["operation"] in {OP_INTAKE, OP_INSPECT})
    identifier(value["requestId"]); component(value["deploymentId"]); component(value["instanceId"])
    text(value["canaryId"], 256)
    decoded(value["bootId"], 32, length=32)
    for name in ("holderId", "keyId", "controlPlaneResponseSigningKeyId", "policyHash", "dataPlaneBinarySha256",
            "purposeAssignmentSha256", "canaryAssignmentSha256", "canaryBootId", "batchSha256", "clientCertificateSha256", "clientSpkiSha256"):
        digest(value[name])
    decoded(value["nonce"], 32, length=32)
    issued, expires = epoch(value["issuedAtEpochNs"]), epoch(value["expiresAtEpochNs"])
    require(0 < expires - issued <= 30_000_000_000 and value["workloadUri"] == workload_uri(value["deploymentId"], value["instanceId"]))
    return value


def evidence(value):
    require(type(value) is dict and set(value) == {"statement", "signature", "nativeKeyEvidence", "clientCertificateDerBase64Url"})
    statement(value["statement"])
    require(type(value["signature"]) is str and value["signature"].startswith("ed25519:"))
    decoded(value["signature"].removeprefix("ed25519:"), 64, length=64)
    proof = value["nativeKeyEvidence"]
    require(type(proof) is dict and set(proof) == {"apiVersion", "responseProofPublicKey", "attestationDocumentB64"}
        and proof["apiVersion"] == "serverware.nativeResponseProofKeyEvidence/v1")
    decoded(proof["responseProofPublicKey"], 32, length=32)
    decoded(proof["attestationDocumentB64"], 12 * 1024)
    certificate = decoded(value["clientCertificateDerBase64Url"], 16 * 1024)
    require(sha256(certificate) == value["statement"]["clientCertificateSha256"]
        and len(canonical(value)) <= 128 * 1024)
    return value


def attestation_nonce(value):
    evidence(value)
    return hashlib.sha256(b"serverware/canary-evidence-intake-attestation/v1\0"
        + decoded(value["statement"]["nonce"], 32, length=32)
        + hashlib.sha256(canonical(value["statement"])).digest()
        + decoded(value["signature"].removeprefix("ed25519:"), 64, length=64)).digest()


def arguments(operation, value, *, typed=False):
    require(operation == OP_INTAKE and isinstance(value, Mapping)
        and set(value) == (FIELDS | {"businessIntent"} if typed else FIELDS))
    digest(value["control_plane_configuration_digest"])
    original = batch(value["batch_original"])
    proof = evidence(value["native_evidence"]); signed = proof["statement"]
    require(signed["operation"] == operation and signed["requestId"] == original["requestId"]
        and signed["canaryId"] == original["canaryId"] and signed["batchSha256"] == sha256(value["batch_original"].encode("ascii")))
    require(type(value["before_original"]) is str)
    snapshot = document(value["before_original"].encode("ascii"), MAX_ARGUMENT)
    require(type(snapshot) is dict and canonical(snapshot).decode("ascii") == value["before_original"])
    from serverware import authority_policy_canary_tables as tables
    tables.snapshot(snapshot, original["events"])
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


def result(value):
    require(type(value) is dict and set(value) == {"ok", "operation", "requestDigest", "auditEventDigest", "idempotentReplay", "accepted", "results"}
        and value["ok"] is True and value["operation"] == OP_INTAKE and value["idempotentReplay"] is False
        and type(value["accepted"]) is int and 1 <= value["accepted"] <= LIMITS["events"]
        and type(value["results"]) is list and len(value["results"]) == value["accepted"])
    digest(value["requestDigest"]); digest(value["auditEventDigest"])
    for item in value["results"]:
        require(type(item) is dict and set(item) == {"kind", "recordSha256", "storedOriginal"} and item["kind"] in KINDS)
        digest(item["recordSha256"])
        require(type(item["storedOriginal"]) is str)
        stored = document(item["storedOriginal"].encode("ascii"), MAX_RESPONSE)
        require(type(stored) is dict and canonical(stored).decode("ascii") == item["storedOriginal"])
    require(len(canonical(value)) <= MAX_RESULT)
    return value


def row_original(row):
    require(type(row) is dict and set(row) == ROW_FIELDS)
    identifier(row["request_id"]); text(row["canary_id"], 256); component(row["instance_id"]); digest(row["boot_id"])
    for name in ("purpose_assignment_digest", "canary_assignment_digest", "configuration_digest", "batch_sha256", "request_digest", "audit_event_digest"):
        digest(row[name])
    original = batch(row["batch_original"])
    proof = evidence(document(row["native_evidence_original"].encode("ascii"), 128 * 1024))
    held_result = result(document(row["result_original"].encode("ascii"), MAX_RESPONSE))
    signed = proof["statement"]
    require(canonical(proof).decode("ascii") == row["native_evidence_original"] and canonical(held_result).decode("ascii") == row["result_original"]
        and row["request_id"] == original["requestId"] == signed["requestId"] and row["canary_id"] == original["canaryId"] == signed["canaryId"]
        and row["batch_sha256"] == sha256(row["batch_original"].encode("ascii")) == signed["batchSha256"]
        and signed["operation"] == OP_INTAKE and row["instance_id"] == signed["instanceId"] and row["boot_id"] == signed["canaryBootId"]
        and row["purpose_assignment_digest"] == signed["purposeAssignmentSha256"] and row["canary_assignment_digest"] == signed["canaryAssignmentSha256"]
        and row["issued_at_epoch_ns"] == signed["issuedAtEpochNs"] and row["expires_at_epoch_ns"] == signed["expiresAtEpochNs"]
        and held_result["requestDigest"] == row["request_digest"] and held_result["auditEventDigest"] == row["audit_event_digest"])
    text(row["created_at"], 128)
    require(held_result["accepted"] == len(original["events"]) and all(outcome["kind"] == event["kind"]
        and outcome["recordSha256"] == sha256(canonical(event["record"])) for outcome, event in zip(held_result["results"], original["events"])))
    return canonical(row)
