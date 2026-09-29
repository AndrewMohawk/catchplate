"""One recovery-only verifier startup, with no metadata effect entrypoint.

Lock order is independent witness exclusive head, then a bounded read-only
metadata snapshot. The live executor takes witness SHARE before metadata, so
its actual commit must finish before this recovery can observe its outcome.
"""
import os
import time
from serverware import authority_rbac_currentness as wire
from serverware import authority_rbac_recovery as recovery
from serverware.authority_rbac_witness import Connection

_PID = os.getpid()
_USED = False


def _witness_one(witness, sql, parameters):
    witness.check()
    remaining = max(1, (witness.deadline - time.monotonic_ns()) // 1_000_000)
    witness.connection.execute("SELECT pg_catalog.set_config('statement_timeout',%s,true),"
        "pg_catalog.set_config('idle_in_transaction_session_timeout',%s,true),pg_catalog.set_config('lock_timeout',%s,true)",
        (str(remaining), str(remaining), str(remaining)))
    row = witness.connection.execute(sql, parameters).fetchone()
    witness.check()
    return row


def _one(cursor, sql, value, owner, deadline):
    owner.check(); wire.require(time.monotonic_ns() < deadline)
    remaining = max(1, (deadline - time.monotonic_ns()) // 1_000_000)
    cursor.execute("SELECT pg_catalog.set_config('statement_timeout',%s,true),pg_catalog.set_config('lock_timeout',%s,true)",
        (str(remaining), str(remaining)))
    rows = cursor.execute(sql, (value,)).fetchall()
    owner.check(); wire.require(time.monotonic_ns() < deadline)
    wire.require(len(rows) == 1, "RBAC recovery has no exact protected committed original")
    return dict(rows[0])


def _read_commit(owner, deadline, pending):
    """The independently locked caller remains live until this snapshot closes."""
    import psycopg
    from psycopg.rows import dict_row
    from serverware import authority_service as service
    from serverware import control_plane_rbac_currentness as currentness
    from serverware.authority_store.verifier_read_sql import verifier_read_privilege_check
    owner.check()
    dsn = service._read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN")
    with psycopg.connect(dsn, row_factory=dict_row, connect_timeout=1,
            options="-c search_path=pg_catalog", sslmode="verify-full", ssl_min_protocol_version="TLSv1.3") as connection:
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                owner.check(); wire.require(time.monotonic_ns() < deadline)
                remaining = max(1, (deadline - time.monotonic_ns()) // 1_000_000)
                cursor.execute("SELECT pg_catalog.set_config('statement_timeout',%s,true),"
                    "pg_catalog.set_config('idle_in_transaction_session_timeout',%s,true),pg_catalog.set_config('lock_timeout',%s,true)",
                    (str(remaining), str(remaining), str(remaining)))
                identity = cursor.execute("SELECT current_user::text AS role,s.ssl,s.client_dn,s.client_serial::text AS client_serial,s.issuer_dn "
                    "FROM pg_catalog.pg_stat_ssl s WHERE s.pid=pg_catalog.pg_backend_pid()").fetchone()
                expected = owner.process.role_config
                wire.require(identity is not None and identity["role"] == expected["databaseRole"] and identity["ssl"] is True
                    and identity["client_dn"] == expected["tlsClientDn"] and identity["client_serial"] == expected["tlsClientSerial"]
                    and identity["issuer_dn"] == expected["tlsIssuerDn"], "RBAC recovery metadata TLS role differs")
                wire.require(cursor.execute(*verifier_read_privilege_check(role=expected["databaseRole"],
                    namespace="serverware_metadata")).fetchone() is None, "RBAC recovery metadata role is not the fixed read-only role")
                currentness._matching_roots(pending["afterHead"], currentness.metadata_roots(cursor, owner))
                grant = owner.recovery
                capability = _one(cursor,
                    "SELECT capability_id,capability_protocol,capability_record_digest,envelope_id,operation,operation_id,handler_name,request_digest,"
                    "operation_manifest_digest,query_manifest_digest,authority_snapshot_digest,authority_root_set_digest,witness_reservation_digest,witness_sequence,"
                    "deadline_monotonic_ns,deadline_epoch_ns,fence,status,result_digest,commit_receipt_digest,committed_at_epoch_ns,"
                    "expires_at_epoch_ns,expected_result_digest,planner_transaction_id,authorization_projection_digest "
                    "FROM serverware_metadata.policy_authority_writer_capabilities WHERE capability_id=%s AND operation='rbac.binding.mutate'",
                    grant["capabilityId"], owner, deadline)
                planner = _one(cursor,
                    "SELECT planner_transaction_id,plan_protocol,retained_record_digest,operation,operation_id,request_digest,capability_id,"
                    "authorization_projection_digest,authority_snapshot_digest,authority_root_set_before_digest,deadline_monotonic_ns,deadline_epoch_ns,fence,status,"
                    "exact_plan_base64url,exact_plan_bytes_digest,exact_plan_byte_count,exact_response_base64url,exact_response_bytes_digest,"
                    "exact_response_byte_count,terminal_receipt_json,terminal_receipt_digest,terminal_at_epoch_ns,source_revision "
                    "FROM serverware_metadata.policy_authority_planner_transactions WHERE planner_transaction_id=%s "
                    "AND operation='rbac.binding.mutate' AND octet_length(exact_plan_base64url)<=11184811 "
                    "AND octet_length(exact_response_base64url)<=11184811 AND octet_length(terminal_receipt_json)<=16384",
                    capability["planner_transaction_id"], owner, deadline)
                envelope = _one(cursor,
                    "SELECT envelope_id,parent_envelope_id,purpose,operation,operation_id,request_digest,capability_id,planner_transaction_id,"
                    "authorization_projection_digest,exact_request_base64url,exact_request_bytes_digest,exact_request_byte_count,"
                    "deadline_monotonic_ns,deadline_epoch_ns,fence,status,exact_response_base64url,exact_response_bytes_digest,"
                    "exact_response_byte_count,result_digest,terminal_receipt_json,terminal_receipt_digest,failure_code,failure_digest,"
                    "terminal_at_epoch_ns,source_revision FROM serverware_metadata.policy_authority_execution_envelopes WHERE envelope_id=%s "
                    "AND operation='rbac.binding.mutate' AND octet_length(exact_request_base64url)<=11184811 "
                    "AND octet_length(exact_response_base64url)<=11184811 AND octet_length(terminal_receipt_json)<=16384",
                    capability["envelope_id"], owner, deadline)
                receipt = _one(cursor,
                    "SELECT commit_receipt_digest,capability_id,envelope_id,operation,handler_name,request_digest,result_json,result_digest,"
                    "authority_root_set_before_digest,authority_root_set_after_digest,operation_manifest_digest,query_manifest_digest,"
                    "witness_reservation_digest,witness_sequence,deadline_monotonic_ns,fence,committed_at_epoch_ns,source_revision "
                    "FROM serverware_metadata.policy_authority_writer_receipts WHERE capability_id=%s AND operation='rbac.binding.mutate' "
                    "AND octet_length(result_json)<=8388608", grant["capabilityId"], owner, deadline)
                consumed = _one(cursor,
                    "SELECT envelope_id,parent_envelope_id,purpose,operation,request_digest,deadline_monotonic_ns,fence,consumed_at_epoch_ns,witness_receipt_digest "
                    "FROM serverware_metadata.policy_authority_consumed_envelopes WHERE envelope_id=%s AND operation='rbac.binding.mutate'",
                    capability["envelope_id"], owner, deadline)
                original = recovery.known_commit(grant, pending, owner.policy, capability=capability, planner=planner,
                    envelope=envelope, receipt_row=receipt, consumed=consumed)
                wire.require(len(original) <= recovery.MAX_ORIGINAL)
                currentness._matching_roots(pending["afterHead"], currentness.metadata_roots(cursor, owner))
                owner.check(); wire.require(time.monotonic_ns() < deadline)
    owner.check(); wire.require(time.monotonic_ns() < deadline)
    return original


def run(process):
    """Actual fresh verifier only; never accepts a caller verdict or locator."""
    global _USED
    from serverware import authority_service
    from serverware import control_plane_rbac_currentness as currentness
    wire.require(os.getpid() == _PID and not _USED and type(process) is authority_service.AuthorityProcess
        and process.role_name == "verifier")
    owner = process.rbac_currentness_owner
    wire.require(owner is currentness._owner and currentness._state == "started" and owner.process is process
        and owner.recovery is not None and owner.writer)
    _USED = True
    owner.check()
    deadline, grant = owner.limit(), owner.recovery
    with Connection(owner, deadline) as witness:
        # This exclusive lock waits for existing live executor SHARE brackets;
        # no metadata lock is acquired first and no writer is called here.
        observed = _witness_one(witness, "SELECT * FROM serverware_rbac_witness.recovery_head(%s)",
            (owner.enrollment_sha256,))
        wire.require(observed is not None and observed["enrollment_original"].encode("ascii") == owner.enrollment_original)
        head_raw = observed["head_original"].encode("ascii")
        head = wire.head(wire.document(head_raw, 16384))
        wire.require(wire.sha256(head_raw) == observed["head_sha256"])
        record = witness.record(grant["requestSha256"])
        wire.require(record is not None and record["intent_sha256"] == grant["intentSha256"])
        pending = recovery.intent(record["intent_original"].encode("ascii"), grant)
        was_complete = record["completion_original"] is not None
        if was_complete:
            wire.require(observed["pending_sha256"] is None and head == pending["afterHead"])
        else:
            wire.require(observed["pending_sha256"] == grant["intentSha256"] and head == pending["beforeHead"])
        original = _read_commit(owner, deadline, pending)
        witness.check()
        if was_complete:
            wire.require(record["completion_original"].encode("ascii") == original
                and record["completion_sha256"] == wire.sha256(original))
        else:
            result = _witness_one(witness, "SELECT * FROM serverware_rbac_witness.recover_complete(%s,%s,%s,%s,%s)",
                (owner.enrollment_sha256, grant["intentSha256"], owner.recovery_original.decode("ascii"),
                 original.decode("ascii"), wire.canonical(pending["afterHead"]).decode("ascii")))
            wire.require(result is not None and result["completion_original"].encode("ascii") == original
                and result["completion_sha256"] == wire.sha256(original)
                and result["recovery_original"].encode("ascii") == owner.recovery_original
                and result["recovery_sha256"] == wire.sha256(owner.recovery_original)
                and result["recovery_id"] == grant["recoveryId"])
        final, unresolved = witness.head()
        wire.require(final == pending["afterHead"] and unresolved is None)
        terminal = witness.record(grant["requestSha256"])
        wire.require(terminal is not None and terminal["completion_original"].encode("ascii") == original)
    # Publication only after external COMMIT and closing checks returned.
    # A lost ACK never triggers another completion attempt in this owner.
    owner.check()
    return {"schema": "serverware.rbacWitnessRecoveryObservation/v1", "okForAction": False,
        "status": "observed-complete" if was_complete else "recovered-known-commit",
        "enrollmentSha256": owner.enrollment_sha256, "authorizationSha256": wire.sha256(owner.recovery_original),
        "intentSha256": grant["intentSha256"], "completionSha256": wire.sha256(original), "headSha256": grant["afterHeadSha256"]}
