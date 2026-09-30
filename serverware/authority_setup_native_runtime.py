"""One protected native capture attempt; never host or final Setup authority."""
import hashlib
from collections.abc import Mapping

from serverware import authority_setup_native_canary as canary

enrollment = canary.enrollment
canonical, require, digest, sha256 = canary.canonical, canary.require, canary.digest, canary.sha256
PREPARE, COMPLETE = "setup.native-runtime.prepare", "setup.native-runtime.complete"
OPERATIONS, ASSERTION_OPERATIONS = frozenset({PREPARE, COMPLETE}), frozenset({PREPARE})
TABLE = "setup_native_runtime_attempts"
HTTP, OPTIONS = "serverware.setupNativeRuntimeRequest/v1", "serverware.setupNativeRuntimeOptions/v1"
PREPARED = "serverware.setupNativeRuntimeAttempt/v1"
MAX_CAPTURE, MAX_ARGUMENT_BYTES, MAX_ROW_BYTES = 512 * 1024, 768 * 1024, 800 * 1024
FIELDS = frozenset({"actor_id", "control_plane_configuration_digest", "credential_policy", "association_original", "scope_original",
    "attempt_original", "capture_original_base64url"})
PREPARED_FIELDS = frozenset({"apiVersion", "attemptId", "sessionId", "associationSha256", "scopeSha256", "nonce",
    "principalId", "routeId", "policyHash", "credentialId", "credentialVersion", "clientRequestSha256",
    "issuedAtEpochNs", "expiresAtEpochNs"})
ROW_FIELDS = frozenset({"session_id", "revision", "phase", "owner_id", "association_sha256", "scope_original", "attempt_original",
    "attempt_sha256", "prepare_request_digest", "prepare_audit_id", "capture_original_base64url", "capture_sha256", "result_original",
    "complete_request_digest", "configuration_digest", "created_at", "completed_at"})
RESULT_FIELDS = frozenset({"apiVersion", "resultScope", "okForAction", "nativeHostVerified", "enrollmentComplete", "proxyReady",
    "attemptSha256", "captureSha256", "serverStatementSha256", "requestSha256", "operationSha256", "dispatchReceiptSha256",
    "responseBodySha256", "responseStatus", "collectorKeyId", "nativeKeyId", "attestationDocumentSha256"})


def association(text):
    require(type(text) is str and text.isascii())
    value = enrollment.setup.document(text.encode("ascii"), 32768)
    require(canary.row_original(value).decode("ascii") == text)
    return value


def prepared(text):
    require(type(text) is str and text.isascii())
    value = enrollment.setup.document(text.encode("ascii"), 8192)
    require(set(value) == PREPARED_FIELDS and value["apiVersion"] == PREPARED)
    for name in ("attemptId", "sessionId", "credentialId"):
        enrollment.setup.identifier(value[name])
    for name in ("associationSha256", "scopeSha256", "policyHash", "clientRequestSha256"):
        digest(value[name])
    for name in ("principalId", "routeId"):
        enrollment.setup.text(value[name], 1024)
    require(type(value["credentialVersion"]) is int and value["credentialVersion"] == 1
        and len(enrollment.original(value["nonce"], 32)) == 32)
    before, after = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    require(type(before) is int and type(after) is int and 0 < before < after <= 2**63 - 1
        and after - before <= 300_000_000_000)
    return value


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping))
    allowed = FIELDS | ({"businessIntent", "authn_evidence"} if typed else set())
    require(FIELDS <= set(value) <= allowed and (not typed or "businessIntent" in value))
    original = {name: value[name] for name in FIELDS}
    a = association(original["association_original"])
    require(type(value["scope_original"]) is str and value["scope_original"].isascii())
    from serverware import authority_setup_native_runtime_policy as policy
    scope = policy.scope(enrollment.setup.document(value["scope_original"].encode("ascii"), 32768))
    require(scope["sessionId"] == a["session_id"])
    require(a["owner_id"] == value["actor_id"] and a["configuration_digest"] == value["control_plane_configuration_digest"])
    enrollment.hardware.policy(value["credential_policy"])
    if operation == PREPARE:
        require(value["attempt_original"] is None and value["capture_original_base64url"] is None)
    else:
        attempt = prepared(value["attempt_original"])
        require(attempt["sessionId"] == a["session_id"] and attempt["associationSha256"] == sha256(value["association_original"].encode("ascii")))
        enrollment.original(value["capture_original_base64url"], MAX_CAPTURE)
    require(len(canonical(original)) <= MAX_ARGUMENT_BYTES)
    return original


def nonce(challenge, request_digest):
    """Original verified hardware challenge, consumed by the SAME prepare CAS."""
    digest(request_digest)
    raw = enrollment.original(challenge, 1024)
    require(32 <= len(raw) <= 1024)
    return enrollment.encoded(hashlib.sha256(b"serverware/setup-native-runtime-nonce/v1\0" + raw
        + bytes.fromhex(request_digest[7:])).digest())


def row_original(row):
    require(type(row) is dict and set(row) == ROW_FIELDS and type(row["revision"]) is int and row["revision"] in (0, 1))
    attempt = prepared(row["attempt_original"])
    require(type(row["scope_original"]) is str and row["scope_original"].isascii()
        and sha256(row["scope_original"].encode("ascii")) == attempt["scopeSha256"])
    from serverware import authority_setup_native_runtime_policy as policy
    scope = policy.scope(enrollment.setup.document(row["scope_original"].encode("ascii"), 32768))
    policy.attempt_scope(attempt, scope)
    require(row["session_id"] == attempt["sessionId"] and row["association_sha256"] == attempt["associationSha256"]
        and row["attempt_sha256"] == sha256(row["attempt_original"].encode("ascii"))
        and row["phase"] == ("capture_outcome_unknown" if row["revision"] == 0 else "runtime_evidence_recorded"))
    enrollment.setup.text(row["owner_id"], 1024)
    for name in ("configuration_digest", "prepare_request_digest"):
        digest(row[name])
    from serverware import authority_transition_quota as q
    require(row["prepare_audit_id"] == q._audit_identity(PREPARE, row["prepare_request_digest"]))
    require(enrollment.setup.epoch(row["created_at"]) == attempt["issuedAtEpochNs"])
    if row["revision"] == 0:
        require(all(row[name] is None for name in ("capture_original_base64url", "capture_sha256", "result_original", "complete_request_digest", "completed_at")))
    else:
        raw = enrollment.original(row["capture_original_base64url"], MAX_CAPTURE)
        require(sha256(raw) == row["capture_sha256"])
        digest(row["complete_request_digest"])
        result = result_original(row["result_original"])
        require(result["attemptSha256"] == row["attempt_sha256"] and result["captureSha256"] == row["capture_sha256"]
            and attempt["issuedAtEpochNs"] <= enrollment.setup.epoch(row["completed_at"]) < attempt["expiresAtEpochNs"])
    raw = canonical(row); require(len(raw) <= MAX_ROW_BYTES); return raw


def result_original(text):
    require(type(text) is str and text.isascii())
    value = enrollment.setup.document(text.encode("ascii"), 8192)
    require(set(value) == RESULT_FIELDS and value["apiVersion"] == "serverware.setupNativeRuntimeEvidence/v1"
        and value["resultScope"] == "trusted-collector-and-native-signatures-only"
        and all(value[name] is False for name in ("okForAction", "nativeHostVerified", "enrollmentComplete", "proxyReady"))
        and type(value["responseStatus"]) is int and 200 <= value["responseStatus"] <= 299)
    for name in RESULT_FIELDS - {"apiVersion", "resultScope", "okForAction", "nativeHostVerified", "enrollmentComplete", "proxyReady", "responseStatus"}:
        digest(value[name])
    return value


def public(row):
    if row is None:
        return None
    row_original(row)
    return {name: row[field] for name, field in (("revision", "revision"), ("phase", "phase"),
        ("attemptSha256", "attempt_sha256"), ("captureSha256", "capture_sha256"),
        ("prepareRequestDigest", "prepare_request_digest"), ("completeRequestDigest", "complete_request_digest"))}


def request_digest(operation, value):
    from serverware import authority_contract as contract, authority_request_commitment as commitment
    values = arguments(operation, value, typed="businessIntent" in value)
    typed = {**values, "businessIntent": contract.synthesize_business_intent(operation, values)}
    return commitment.framed_digest("serverware.policyAuthorityV9Request/v1", canonical({"schema": "serverware.policyAuthorityV9Authorization/v1",
        "operation": operation, "handler": contract.operation_spec(operation)["handler"], "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": commitment._authorization_arguments(typed)}))
