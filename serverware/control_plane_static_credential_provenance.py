"""SELECT-only acquisition of committed public static-generation provenance.

Retained planner bytes are acquisition data, not a signed planner envelope or
a fresh native verdict. Their original native signature becomes historical
evidence only through the existing current-row/completed-outbox verifier. No
whole plan, ciphertext, assignment, private key or renewed interval is returned.
"""
import base64
import json

from serverware import authority_contract as contract
from serverware import authority_request_commitment as commitment
from serverware import authority_static_credential_create as creation
from serverware import authority_static_credential_rotate as rotation
from serverware import authority_static_credential_provenance as provenance
from serverware.authority_query_read_work import MAX_JSON_DEPTH, MAX_JSON_NODES

SCHEMA = "serverware.staticCredentialProvenanceObservation/v1"
MAX_PLAN_BYTES = contract.MAX_RESULT_BYTES
MAX_PLAN_ENCODED = (MAX_PLAN_BYTES * 4 + 2) // 3
_ROW_FIELDS = frozenset({"planner_transaction_id", "operation", "operation_id",
    "request_digest", "capability_id", "plan_protocol", "retained_record_digest",
    "status", "source_revision", "exact_plan_base64url", "exact_plan_bytes_digest",
    "exact_plan_byte_count"})
_PAYLOAD_FIELDS = frozenset({"schema", "measuredPlan", "typedRequest", "selectedBusinessRows",
    "mutationPlan", "queryMultiproofs", "queryMultiproofsDigest", "plannerTrace",
    "plannerTraceDigest", "authorizationProjection", "webauthnEvidence", "expectedResult",
    "expectedResultDigest", "plannerIdentity", "rootTransition"})
_PLAN_FIELDS = frozenset({"schema", "plannerTransactionId", "operation", "operationId",
    "requestDigest", "capabilityId", "sourceRevision", "authoritySchemaVersion",
    "operationContractDigest", "operationManifestDigest", "handlerContractDigest",
    "queryManifestDigest", "selectedBusinessRowsDigest", "mutationPlanDigest", "workUnits",
    "authorityRootSetBeforeDigest", "authorizationProjectionDigest", "authoritySnapshotDigest",
    "deadlineMonotonicNs", "deadlineEpochNs", "fence", "rootTransitionDigest"})


def _document(raw):
    creation.require(type(raw) is bytes and 2 <= len(raw) <= MAX_PLAN_BYTES)
    def pairs(items):
        value = {}
        for name, item in items:
            creation.require(name not in value)
            value[name] = item
        return value
    value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs,
        parse_constant=lambda _: creation.require(False))
    pending, nodes = [(value, 0)], 0
    while pending:
        item, depth = pending.pop(); nodes += 1
        creation.require(depth <= MAX_JSON_DEPTH and nodes <= MAX_JSON_NODES)
        if type(item) is dict:
            nodes += len(item)
            creation.require(nodes <= MAX_JSON_NODES)
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
    creation.require(type(value) is dict and creation.canonical(value) == raw)
    return value


def _acquire(row, *, credential_id, version, origin_digest, configuration_digest):
    """Decode the actual retained payload without pretending it is fresh authority."""
    from serverware import authority_static_credential_custody as create_custody
    from serverware import authority_static_credential_rotation_custody as rotate_custody

    codec, custody, field, schema, request_field = (
        (creation, create_custody, "staticCredentialCustodyEvidence", provenance.SCHEMA, "creationRequestDigest")
        if version == 1 else
        (rotation, rotate_custody, "staticCredentialRotationEvidence", provenance.ROTATION_SCHEMA, "rotationRequestDigest"))
    creation.require(type(row) is dict and set(row) == _ROW_FIELDS
        and row["status"] == "consumed" and row["plan_protocol"] == "v3"
        and row["retained_record_digest"] is None and row["operation"] == codec.OPERATION
        and row["request_digest"] == origin_digest and row["source_revision"] == contract.SOURCE_REVISION
        and type(row["exact_plan_byte_count"]) is int and 2 <= row["exact_plan_byte_count"] <= MAX_PLAN_BYTES)
    for name in ("planner_transaction_id", "operation_id", "request_digest", "capability_id", "exact_plan_bytes_digest"):
        creation.digest(row[name])
    encoded = row["exact_plan_base64url"]
    creation.require(type(encoded) is str and 2 <= len(encoded) <= MAX_PLAN_ENCODED
        and len(encoded) == (row["exact_plan_byte_count"] * 4 + 2) // 3)
    raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    creation.require(base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == encoded
        and len(raw) == row["exact_plan_byte_count"] and creation.sha256(raw) == row["exact_plan_bytes_digest"])
    payload = _document(raw)
    creation.require(set(payload) == _PAYLOAD_FIELDS | {field}
        and payload["schema"] == "serverware.policyAuthorityPlannerResponse/v3")
    plan, typed = payload["measuredPlan"], payload["typedRequest"]
    creation.require(type(plan) is dict and set(plan) == _PLAN_FIELDS
        and plan["schema"] == "serverware.policyAuthorityMeasuredPlan/v3"
        and type(typed) is dict and typed.get("operation") == codec.OPERATION
        and plan["sourceRevision"] == row["source_revision"]
        and type(plan["authoritySchemaVersion"]) is int and plan["authoritySchemaVersion"] == contract.SCHEMA_VERSION
        and plan["operationContractDigest"] == plan["operationManifestDigest"] == contract.OPERATION_MANIFEST_DIGEST
        and plan["handlerContractDigest"] == contract.handler_contract_digest(codec.OPERATION))
    for column, name in (("operation", "operation"), ("request_digest", "requestDigest"),
            ("operation_id", "operationId"), ("capability_id", "capabilityId"),
            ("planner_transaction_id", "plannerTransactionId")):
        creation.require(plan[name] == row[column])
    values = codec.arguments(codec.OPERATION, typed.get("arguments"), typed=True)
    creation.require(commitment._typed_request_digest(typed, work=None) == codec.request_digest(codec.OPERATION, values)
        == typed.get("requestDigest") == origin_digest
        and commitment.operation_id(codec.OPERATION, origin_digest) == typed.get("operationId") == row["operation_id"]
        and row["planner_transaction_id"] == commitment.framed_digest(
            "serverware.policyAuthorityPlannerTransaction/v1", row["operation_id"].encode("ascii"),
            origin_digest.encode("ascii"), row["capability_id"].encode("ascii"))
        and values["control_plane_configuration_digest"] == configuration_digest
        and values["request"]["credentialId"] == credential_id
        and values["request"]["credentialVersion"] == version)
    evidence = custody.authority_evidence(payload[field])
    statement, request = evidence["statement"], values["request"]
    native = codec.generation(request["nativeGenerationOriginal"])
    creation.require(statement["inputSha256"] == creation.sha256(creation.canonical(values))
        and statement["generationSha256"] == creation.sha256(request["nativeGenerationOriginal"].encode("ascii"))
        and statement["intentSha256"] == native["intentSha256"]
        and statement["actorId"] == values["actor_id"]
        and statement["controlPlaneConfigurationDigest"] == configuration_digest
        and statement["credentialId"] == credential_id and statement["credentialVersion"] == version
        and request["executionIssuedAtEpochNs"] <= statement["issuedAtEpochNs"]
        < statement["expiresAtEpochNs"] <= request["executionExpiresAtEpochNs"])
    if version > 1:
        for name in ("previousCredentialVersion", "previousCredentialSha256",
                "previousCurrentnessOriginRequestDigest", "predecessorBarrierSha256", "predecessorCurrentnessRootSha256"):
            creation.require(statement[name] == request[name])
        creation.require(statement["previousProvenanceSha256"] == creation.sha256(request["previousProvenanceOriginal"].encode("ascii")))
    # Exact projection of the originally retained three-field evidence. The
    # independently assigned runtime selection is not exposed or re-admitted.
    public = {name: evidence[name] for name in ("statement", "signature", "nativeKeyEvidence")}
    original = creation.canonical({"apiVersion": schema, request_field: origin_digest,
        "nativeEvidenceOriginal": creation.canonical(public).decode("ascii")}).decode("ascii")
    provenance.generation_original(original)
    return original


def lookup(owner, credential_id):
    """Return only historical public provenance for the actual current generation."""
    from serverware import db
    from serverware import control_plane_static_credential_rotation as http
    from serverware import control_plane_credential_currentness as currentness

    creation.require(type(owner) is http._Owner and not owner.dispatched and not owner.drain_started)
    creation.identifier(credential_id)
    owner.check()
    with db.connect() as connection:
        selected = connection.execute("SELECT credential_version FROM credentials WHERE id = ?", (credential_id,)).fetchone()
    creation.require(selected is not None)
    version = selected["credential_version"]
    creation.require(type(version) is int and 1 <= version <= 2**63 - 1)
    credential, generation, root = currentness._rows(credential_id, version)
    creation.require(credential["kind"] in creation.KINDS)
    operation = creation.OPERATION if version == 1 else rotation.OPERATION
    origin = root["origin_request_digest"]
    creation.digest(origin)
    owner.check()
    # Runtime already has SELECT on this protected table, not planner-writer
    # custody. Do not use its writer-only replay API or grant another role.
    with db.connect() as connection:
        rows = connection.execute(
            "SELECT planner_transaction_id, operation, operation_id, request_digest, capability_id, "
            "plan_protocol, retained_record_digest, status, source_revision, exact_plan_bytes_digest, "
            "exact_plan_byte_count, CASE WHEN exact_plan_byte_count BETWEEN 2 AND ? "
            "AND length(exact_plan_base64url) BETWEEN 2 AND ? THEN exact_plan_base64url "
            "ELSE NULL END AS exact_plan_base64url FROM policy_authority_planner_transactions "
            "WHERE operation = ? AND request_digest = ? AND status = 'consumed' LIMIT 2",
            (MAX_PLAN_BYTES, MAX_PLAN_ENCODED, operation, origin)).fetchall()
    creation.require(len(rows) == 1, "The current generation has no unique completed retained original")
    owner.check()
    original = _acquire(dict(rows[0]), credential_id=credential_id, version=version,
        origin_digest=origin, configuration_digest=owner.cold.binding.configuration_digest)
    owner.check()
    with db.connect() as connection:
        outbox = connection.execute("SELECT * FROM metadata_audit_outbox WHERE id = ?",
            (provenance.generation_outbox_id(original),)).fetchone()
    creation.require(outbox is not None)
    owner.check()
    deployment = provenance.verify_generation_rows(original, credential=credential,
        generation=generation, root=root, outbox=dict(outbox),
        configuration_digest=owner.cold.binding.configuration_digest, now_epoch_ns=owner.last_epoch)
    creation.require(deployment == owner.cold.payload[http.proof.FIELD]["deploymentId"]
        and credential["secret_kek_id"] == owner.policy["nativeSecretKekId"])
    owner.check()
    creation.require(currentness._rows(credential_id, version) == (credential, generation, root),
        "The current static generation changed during provenance acquisition")
    owner.check()
    return {"apiVersion": SCHEMA, "okForAction": False, "credentialId": credential_id,
        "credentialVersion": version, "originRequestDigest": origin,
        "provenanceOriginal": original, "provenanceSha256": creation.sha256(original.encode("ascii"))}
