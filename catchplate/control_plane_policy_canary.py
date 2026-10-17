"""Automatic machine intake under cold public authority and actual workload TLS.

The metadata reads are inputs/observations only. Only the actual cold custody
client can ask the independently admitted writer to commit the ordered batch.
Inspect never produces a writer receipt or permission to contact again.
"""
from catchplate import authority_contract as contract
from catchplate import authority_policy_canary as profile
from catchplate import authority_policy_canary_tables as tables
from catchplate import authority_primary_contract as primary
from catchplate import control_plane_custody_client as custody
from catchplate import control_plane_policy_canary_startup as startup
from catchplate import db

PREFIX, PATHS, MAX_REQUEST = startup.PREFIX, startup.PATHS, profile.MAX_HTTP


def _snapshot(owner, events):
    owner.check()
    result = {}
    with db.connect() as connection:
        profile.require(isinstance(connection, db.PostgresMetadataConnection), "controlled canary acquisition requires its actual PostgreSQL store")
        for table in tables.TABLES:
            owner.check()
            # Both identifiers and ordering come only from closed source
            # inventories. Caller records cannot select SQL or a partial scan.
            order = ", ".join(primary.PRIMARY_KEY_COLUMNS[table])
            remaining = profile.MAX_ARGUMENT - len(profile.canonical(result)) - 4096
            profile.require(remaining > 0)
            # Bound bytes in PostgreSQL before transferring any row originals.
            # This observation is not a completeness/authority proof; the
            # controlled planner independently proves the exact populations.
            bounded = connection.execute(
                "WITH canary_rows AS MATERIALIZED (SELECT row_to_json(source)::text AS original FROM " + table
                + " AS source ORDER BY " + order + " LIMIT ?), canary_budget AS (SELECT COUNT(*) AS row_count, "
                "COALESCE(SUM(octet_length(original)), 0) AS byte_count FROM canary_rows) "
                "SELECT row_count, CASE WHEN row_count <= ? AND byte_count <= ? THEN "
                "(SELECT json_build_object('rows', COALESCE(json_agg(original::json), '[]'::json))::text FROM canary_rows) ELSE NULL END AS originals "
                "FROM canary_budget", (profile.MAX_ROWS + 1, profile.MAX_ROWS, remaining)).fetchone()
            profile.require(bounded is not None and type(bounded["row_count"]) is int and 0 <= bounded["row_count"] <= profile.MAX_ROWS
                and type(bounded["originals"]) is str, "controlled canary retained row/byte capacity is exhausted")
            acquired = profile.document(bounded["originals"].encode("utf-8"), profile.MAX_ARGUMENT, exact=False)
            profile.require(set(acquired) == {"rows"})
            rows = acquired["rows"]
            profile.require(type(rows) is list and len(rows) == bounded["row_count"] and all(type(row) is dict for row in rows))
            result[table] = sorted(rows, key=lambda row: profile.canonical(tables.key(table, row)))
            profile.require(len(profile.canonical(result)) <= profile.MAX_ARGUMENT)
    tables.snapshot(result, events)
    owner.check()
    return profile.canonical(result).decode("ascii")


def _record(owner):
    owner.check()
    request_id = owner.statement["requestId"]
    profile.identifier(request_id)
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM policy_canary_intake_batches WHERE request_id = ?", (request_id,)).fetchone()
    owner.check()
    if row is None:
        return None
    row = dict(row)
    profile.row_original(row)
    signed = owner.statement
    profile.require(row["request_id"] == request_id and row["batch_original"] == owner.batch_original
        and row["batch_sha256"] == signed["batchSha256"] and row["canary_id"] == signed["canaryId"]
        and row["instance_id"] == signed["instanceId"] and row["boot_id"] == signed["canaryBootId"]
        and row["canary_assignment_digest"] == signed["canaryAssignmentSha256"]
        and row["purpose_assignment_digest"] == signed["purposeAssignmentSha256"]
        and row["configuration_digest"] == owner.owner.configuration_digest)
    original_native = profile.document(row["native_evidence_original"].encode("ascii"), 128 * 1024)["statement"]
    profile.require(all(original_native[name] == signed[name] for name in ("holderId", "bootId", "keyId", "deploymentId")),
        "different boot inspection needs separate historical/current recovery admission")
    return row


def on_request(request, body):
    profile.require(type(body) is bytes and 0 < len(body) <= MAX_REQUEST)
    value = profile.document(body, MAX_REQUEST)
    profile.require(type(value) is dict and set(value) == {"apiVersion", "batchOriginal", "nativeEvidence"}
        and value["apiVersion"] == profile.HTTP_SCHEMA)
    operation = profile.OP_INTAKE if request.url.path == PREFIX else profile.OP_INSPECT
    owner = startup.RequestOwner(request, value["batchOriginal"], value["nativeEvidence"], operation)
    batch = profile.batch(owner.batch_original)
    if operation == profile.OP_INTAKE:
        arguments = profile.arguments(operation, {"control_plane_configuration_digest": owner.owner.configuration_digest,
            "batch_original": owner.batch_original, "native_evidence": value["nativeEvidence"],
            "before_original": _snapshot(owner, batch["events"])})
        expected = profile.request_digest(operation, arguments)
        original = profile.canonical(arguments)
        owner.check()
        profile.require(not owner.dispatched)
        owner.dispatched = True  # Set before contact; an exception never retries.
        result = custody.ControlPlaneCustodyClient._request_authority(owner.owner.custody, operation=operation,
            input_value={"schema": "catchplate.policyAuthorityControlledWriterInput/v1", "handler": contract.operation_spec(operation)["handler"],
                "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST, "arguments": arguments}, deadline_ns=owner.deadline)
        owner.check()
        profile.result(result)
        profile.require(result["requestDigest"] == expected and profile.canonical(arguments) == original)
        row = _record(owner)
        profile.require(row is not None and row["request_digest"] == expected
            and row["native_evidence_original"].encode("ascii") == owner.evidence_original
            and row["result_original"] == profile.canonical(result).decode("ascii"), "definite intake result has no exact committed original")
    else:
        row = _record(owner)
        result = None if row is None else profile.result(profile.document(row["result_original"].encode("ascii"), profile.MAX_RESPONSE))
    response = {"apiVersion": profile.RESULT_SCHEMA, "requestId": batch["requestId"], "batchSha256": owner.statement["batchSha256"],
        "status": "unknown" if row is None else "committed", "result": result,
        "recordOriginal": None if row is None else profile.row_original(row).decode("ascii")}
    profile.require(len(profile.canonical(response)) <= profile.MAX_RESPONSE)
    owner.check()
    return response
