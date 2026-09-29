"""Fresh permission and historical original joins for known RBAC commits only.

No historical deadline becomes execution authority. A recovery authorization
selects exact originals; it is never a substitute for the protected commit.
"""
import base64
import re
from serverware import authority_rbac_currentness as wire

SCHEMA = "serverware.rbacWitnessRecoveryAuthorization/v1"
SIGNED_SCHEMA = "serverware.signedRbacWitnessRecoveryAuthorization/v1"
MAX_ORIGINAL = 8 * 1024 * 1024
FIELDS = frozenset({"schema", "purpose", "recoveryId", "sourceRevision", "configurationDigest",
    "enrollmentSha256", "databaseId", "deploymentId", "intentSha256", "requestSha256", "capabilityId",
    "planSha256", "beforeHeadSha256", "afterHeadSha256", "writerReceiptSha256", "resultSha256",
    "issuedAtEpochNs", "expiresAtEpochNs"})
DIGEST_FIELDS = FIELDS - {"schema", "purpose", "sourceRevision", "deploymentId", "issuedAtEpochNs", "expiresAtEpochNs"}


def decode(value, maximum=MAX_ORIGINAL):
    wire.require(type(value) is str and 0 < len(value) <= (maximum * 4 + 2) // 3
        and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None)
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    wire.require(len(raw) <= maximum and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)
    return raw


def authorization(original, policy):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    wire.require(policy["schema"] == wire.ENROLLMENT_V2_SCHEMA)
    value = wire.document(original, 16384)
    wire.require(type(value) is dict and set(value) == {"schema", "payload", "signatureBase64Url"}
        and value["schema"] == SIGNED_SCHEMA)
    grant = value["payload"]
    wire.require(type(grant) is dict and set(grant) == FIELDS and grant["schema"] == SCHEMA
        and grant["purpose"] == "complete-known-commit")
    for name in DIGEST_FIELDS: wire.digest(grant[name])
    for name in ("sourceRevision", "deploymentId"):
        wire.require(type(grant[name]) is str and 0 < len(grant[name]) <= 256
            and all(33 <= ord(char) < 127 for char in grant[name]))
    wire.integer(grant["issuedAtEpochNs"]); wire.integer(grant["expiresAtEpochNs"])
    wire.require(0 < grant["expiresAtEpochNs"] - grant["issuedAtEpochNs"] <= 300_000_000_000
        and grant["databaseId"] == policy["databaseId"] and grant["deploymentId"] == policy["deploymentId"])
    signature = decode(value["signatureBase64Url"], 64)
    wire.require(len(signature) == 64)
    key = Ed25519PublicKey.from_public_bytes(decode(policy["recoveryPublicKeyBase64Url"], 32))
    key.verify(signature, SCHEMA.encode("ascii") + b"\0" + wire.canonical(grant))
    return grant


def sign_authorization(payload, key, policy):
    """Offline independent recovery operator; not a runtime signing endpoint."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    wire.require(isinstance(key, Ed25519PrivateKey))
    original = wire.canonical({"schema": SIGNED_SCHEMA, "payload": payload,
        "signatureBase64Url": base64.urlsafe_b64encode(key.sign(SCHEMA.encode("ascii") + b"\0" + wire.canonical(payload))).rstrip(b"=").decode("ascii")})
    authorization(original, policy)
    return original


def intent(original, grant):
    value = wire.document(original, MAX_ORIGINAL)
    wire.require(type(value) is dict and set(value) == {"schema", "enrollmentSha256", "requestSha256", "capabilityId",
        "beforeHeadSha256", "beforeHead", "afterHead", "expiresAtEpochNs", "planSha256"}
        and value["schema"] == wire.INTENT_SCHEMA and wire.sha256(original) == grant["intentSha256"])
    for name in ("enrollmentSha256", "requestSha256", "capabilityId", "beforeHeadSha256", "planSha256"):
        wire.require(value[name] == grant[name])
    before, after = wire.head(value["beforeHead"]), wire.head(value["afterHead"])
    wire.require(before["enrollmentSha256"] == after["enrollmentSha256"] == grant["enrollmentSha256"]
        and wire.sha256(wire.canonical(before)) == grant["beforeHeadSha256"]
        and wire.sha256(wire.canonical(after)) == grant["afterHeadSha256"]
        and wire.after_head(before, after["state"]) == after)
    wire.integer(value["expiresAtEpochNs"])
    return value


def retained_bytes(row, stem):
    raw = decode(row["exact_" + stem + "_base64url"])
    wire.require(type(row["exact_" + stem + "_byte_count"]) is int
        and len(raw) == row["exact_" + stem + "_byte_count"]
        and wire.sha256(raw) == row["exact_" + stem + "_bytes_digest"])
    wire.document(raw, MAX_ORIGINAL)
    return raw


def known_commit(grant, pending, policy, *, capability, planner, envelope, receipt_row, consumed):
    """All five mappings must come from the actual held read-only transaction.

    This function returns data. The source owner alone holds the independent
    witness lock and can publish it. Missing rows and failed states are not
    evidence of nonexecution and are never terminalized here.
    """
    from serverware import authority_contract, authority_service, authority_planner
    rows = (capability, planner, envelope, receipt_row, consumed)
    wire.require(all(type(row) is dict for row in rows))
    wire.require(capability["status"] == envelope["status"] == "committed" and planner["status"] == "consumed"
        and capability["capability_protocol"] == planner["plan_protocol"] == "v3"
        and capability["capability_record_digest"] is None and planner["retained_record_digest"] is None
        and envelope["purpose"] == consumed["purpose"] == "execute-v9"
        and envelope["failure_code"] is None and envelope["failure_digest"] is None)
    plan_raw = retained_bytes(planner, "plan")
    wire.require(wire.sha256(plan_raw) == grant["planSha256"] == pending["planSha256"])
    plan = wire.document(plan_raw, MAX_ORIGINAL)
    required_plan = {"schema", "measuredPlan", "typedRequest", "selectedBusinessRows", "mutationPlan", "queryMultiproofs",
        "queryMultiproofsDigest", "plannerTrace", "plannerTraceDigest", "authorizationProjection", "webauthnEvidence",
        "expectedResult", "expectedResultDigest", "plannerIdentity", "rootTransition"}
    wire.require(type(plan) is dict and set(plan) == required_plan and plan["schema"] == authority_planner.PLANNER_RESPONSE_SCHEMA)
    measured = plan["measuredPlan"]
    wire.require(type(measured) is dict and measured["operation"] == "rbac.binding.mutate"
        and measured["capabilityId"] == grant["capabilityId"] and measured["requestDigest"] == grant["requestSha256"]
        and measured["sourceRevision"] == authority_contract.SOURCE_REVISION == grant["sourceRevision"])
    # These bytes were admitted before the original verifier reserved the
    # independent intent. Re-running the live planner validator would wrongly
    # require an expired execution deadline to become current again.
    request_raw, result_raw = retained_bytes(envelope, "request"), retained_bytes(envelope, "response")
    wire.require(request_raw == wire.canonical(plan["typedRequest"])
        and result_raw == retained_bytes(planner, "response") == wire.canonical(plan["expectedResult"])
        and wire.sha256(result_raw) == grant["resultSha256"]
        and type(receipt_row["result_json"]) is str and receipt_row["result_json"].encode("ascii") == result_raw)
    request = wire.document(request_raw, MAX_ORIGINAL)
    wire.require(request["operation"] == "rbac.binding.mutate" and request["requestDigest"] == grant["requestSha256"]
        and authority_planner.typed_request_digest(request) == grant["requestSha256"])
    raw = envelope["terminal_receipt_json"]
    wire.require(type(raw) is str and len(raw) <= 16384 and raw == planner["terminal_receipt_json"])
    receipt_raw = raw.encode("ascii")
    receipt = wire.document(receipt_raw, 16384)
    receipt_fields = {"schema", "capabilityId", "envelopeId", "plannerTransactionId", "authorizationProjectionDigest",
        "operation", "handlerName", "requestDigest", "resultDigest", "authorityRootSetBeforeDigest", "authorityRootSetAfterDigest",
        "authoritySnapshotDigest", "operationManifestDigest", "queryManifestDigest", "witnessReservationDigest", "witnessSequence",
        "deadlineMonotonicNs", "fence", "committedAtEpochNs", "sourceRevision"}
    wire.require(type(receipt) is dict and set(receipt) == receipt_fields and receipt["schema"] == "serverware.policyAuthorityWriterCommitReceipt/v2"
        and wire.sha256(receipt_raw) == grant["writerReceiptSha256"])
    domain = authority_service._domain_digest
    # The actual v9 result domain is source-owned, rather than inferred from
    # an HTTP response or a caller's success field.
    from serverware.authority_store.executor_v9 import compute_authority_v9_result_digest
    result_digest = compute_authority_v9_result_digest(result_raw)
    receipt_digest = domain("serverware.policyAuthorityWriterCommitReceipt/v2", receipt_raw)
    wire.require(envelope["terminal_receipt_digest"] == planner["terminal_receipt_digest"]
        == capability["commit_receipt_digest"] == receipt_row["commit_receipt_digest"] == receipt_digest
        and envelope["result_digest"] == capability["result_digest"] == receipt_row["result_digest"]
        == receipt["resultDigest"] == plan["expectedResultDigest"] == capability["expected_result_digest"] == result_digest)
    joins = {"capabilityId": "capability_id", "requestDigest": "request_digest", "operation": "operation",
        "envelopeId": "envelope_id", "deadlineMonotonicNs": "deadline_monotonic_ns", "fence": "fence"}
    for public, column in joins.items():
        wire.require(all(row[column] == receipt[public] for row in (capability, envelope, receipt_row)))
        if public != "capabilityId": wire.require(consumed[column] == receipt[public])
        if public != "envelopeId": wire.require(planner[column] == receipt[public])
    wire.require(receipt["operation"] == "rbac.binding.mutate" and receipt["capabilityId"] == grant["capabilityId"]
        and receipt["requestDigest"] == grant["requestSha256"]
        and receipt["plannerTransactionId"] == capability["planner_transaction_id"] == planner["planner_transaction_id"]
        == envelope["planner_transaction_id"] == measured["plannerTransactionId"]
        and receipt["authorizationProjectionDigest"] == capability["authorization_projection_digest"]
        == planner["authorization_projection_digest"] == envelope["authorization_projection_digest"]
        == measured["authorizationProjectionDigest"]
        and receipt["authoritySnapshotDigest"] == capability["authority_snapshot_digest"]
        == planner["authority_snapshot_digest"] == measured["authoritySnapshotDigest"]
        and capability["operation_id"] == planner["operation_id"] == envelope["operation_id"]
        == measured["operationId"] == request["operationId"]
        and envelope["parent_envelope_id"] == consumed["parent_envelope_id"] == planner["planner_transaction_id"]
        and receipt["authorityRootSetBeforeDigest"] == capability["authority_root_set_digest"] == planner["authority_root_set_before_digest"]
        and receipt["deadlineMonotonicNs"] == measured["deadlineMonotonicNs"]
        and receipt["fence"] == measured["fence"])
    for public, column in (("handlerName", "handler_name"), ("operationManifestDigest", "operation_manifest_digest"),
            ("queryManifestDigest", "query_manifest_digest"), ("witnessReservationDigest", "witness_reservation_digest"),
            ("witnessSequence", "witness_sequence")):
        wire.require(capability[column] == receipt_row[column] == receipt[public])
    wire.require(consumed["witness_receipt_digest"] == receipt["witnessReservationDigest"]
        and receipt["sourceRevision"] == receipt_row["source_revision"] == planner["source_revision"]
        == envelope["source_revision"] == grant["sourceRevision"])
    committed = receipt["committedAtEpochNs"]
    wire.integer(committed)
    wire.require(committed == receipt_row["committed_at_epoch_ns"] == capability["committed_at_epoch_ns"]
        == envelope["terminal_at_epoch_ns"] == planner["terminal_at_epoch_ns"] == consumed["consumed_at_epoch_ns"]
        and policy["issuedAtEpochNs"] <= committed < policy["expiresAtEpochNs"]
        and committed < pending["expiresAtEpochNs"] <= measured["deadlineEpochNs"]
        and committed < capability["deadline_epoch_ns"] == planner["deadline_epoch_ns"] == envelope["deadline_epoch_ns"] == measured["deadlineEpochNs"]
        and committed < capability["expires_at_epoch_ns"])
    transition = plan["rootTransition"]
    for stage, name in (("Before", "beforeHead"), ("After", "afterHead")):
        roots = transition["business" + stage + "Roots"]
        wire.require([item for item in roots if item["table"] in wire.TABLES] == pending[name]["state"]["roots"])
        field = "authorityRootSet" + stage + "Digest"
        digest = domain("serverware.policyAuthorityRootSet/v1", wire.canonical(roots))
        wire.require(receipt[field] == receipt_row["authority_root_set_" + stage.lower() + "_digest"] == digest)
    result = wire.document(result_raw, MAX_ORIGINAL)
    wire.require(result["generation"] == pending["afterHead"]["state"]["generation"]
        and result["state_digest"] == pending["afterHead"]["state"]["stateDigest"])
    return wire.canonical({"schema": wire.COMPLETION_SCHEMA, "enrollmentSha256": grant["enrollmentSha256"],
        "intentSha256": grant["intentSha256"], "requestSha256": grant["requestSha256"], "writerReceipt": receipt,
        "writerReceiptSha256": grant["writerReceiptSha256"], "resultBase64Url": base64.urlsafe_b64encode(result_raw).rstrip(b"=").decode("ascii"),
        "resultSha256": grant["resultSha256"]})
