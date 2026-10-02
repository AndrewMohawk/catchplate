"""Actual purpose-fixed separately enrolled PostgreSQL witness connection owner.

This module does not accept a caller verdict or arbitrary SQL callback. The
writer handle is separately admitted only inside the actual authority verifier;
all other admitted consumers retain a read-only handle. No implicit enrollment,
absence-as-genesis, pending expiry, reset, repair or automatic retry exists.
Legacy enrollment claims independent administration; the separately signed
local profile explicitly does not. Both use the same actual cluster checks.
"""
import os
import time
from serverware import authority_rbac_currentness as wire
from serverware.authority_store import rbac_witness_sql as sql

MAX_COMMAND = 8 * 1024 * 1024


class Connection:
    def __init__(self, owner, deadline_ns):
        owner.check()
        wire.require(type(deadline_ns) is int and time.monotonic_ns() < deadline_ns <= owner.deadline)
        self.owner, self.deadline, self.pid = owner, deadline_ns, os.getpid()
        self.connection = None

    def check(self):
        self.owner.check()
        wire.require(self.pid == os.getpid() and time.monotonic_ns() < self.deadline)
        if self.connection is not None:
            wire.require(not self.connection.closed)

    def __enter__(self):
        import psycopg
        from psycopg.rows import dict_row
        self.check()
        self.connection = psycopg.connect(**self.owner.connection_parameters(), row_factory=dict_row, connect_timeout=1,
            autocommit=False, options="-c search_path=pg_catalog")
        try:
            self.check()
            remaining = max(1, (self.deadline-time.monotonic_ns())//1_000_000)
            self.connection.execute("SELECT pg_catalog.set_config('statement_timeout',%s,true),pg_catalog.set_config('idle_in_transaction_session_timeout',%s,true),pg_catalog.set_config('lock_timeout',%s,true)",
                (str(remaining), str(remaining), str(remaining)))
            self.connection.execute("SET LOCAL synchronous_commit=on")
            durability = self.connection.execute("SELECT pg_catalog.current_setting('fsync') AS fsync,pg_catalog.current_setting('full_page_writes') AS full_page_writes").fetchone()
            wire.require(durability is not None and durability["fsync"] == "on" and durability["full_page_writes"] == "on")
            identity = self.connection.execute("SELECT * FROM serverware_rbac_witness.identity()").fetchone()
            expected = self.owner.policy["writer" if self.owner.writer else "reader"]
            wire.require(identity is not None and identity["cluster_id"] == self.owner.policy["witnessClusterId"]
                and identity["database_name"] == self.owner.policy["endpoint"]["database"]
                and identity["role_name"] == expected["role"] and identity["tls"] is True
                and identity["tls_version"] == "TLSv1.3" and identity["client_dn"] == expected["clientDn"]
                and identity["client_serial"] == expected["clientSerial"] and identity["issuer_dn"] == expected["issuerDn"],
                "RBAC witness actual cluster/TLS/role differs from independent enrollment")
            bad = self.connection.execute("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=session_user AND "
                "(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit) "
                "UNION ALL SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=session_user) "
                "UNION ALL SELECT 1 FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database() AND "
                "(datdba=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=session_user) OR pg_catalog.has_database_privilege(session_user,oid,'CREATE,TEMPORARY')) "
                "UNION ALL SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname NOT LIKE 'pg_temp_%' AND "
                "pg_catalog.has_schema_privilege(session_user,oid,'CREATE') "
                "UNION ALL SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname='serverware_rbac_witness' AND c.relkind IN ('r','p') AND "
                "(pg_catalog.has_table_privilege(session_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')) LIMIT 1").fetchone()
            wire.require(bad is None, "RBAC witness client has unexpected role/database/schema/table privileges")
            functions = self.connection.execute("SELECT p.proname,pg_catalog.oidvectortypes(p.proargtypes) AS arguments,"
                "p.proowner::pg_catalog.regrole::text AS owner,p.prosecdef,p.proconfig,"
                "pg_catalog.has_function_privilege(session_user,p.oid,'EXECUTE') AS allowed "
                "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
                "WHERE n.nspname='serverware_rbac_witness' ORDER BY p.proname").fetchall()
            expected_functions = {("identity", ""): True, ("read_head", "text"): True, ("read_record", "text, text"): True,
                ("reserve", "text, text"): self.owner.writer, ("complete", "text, text, text, text"): self.owner.writer}
            if self.owner.policy["schema"] == wire.ENROLLMENT_V2_SCHEMA:
                expected_functions.update({("recovery_head", "text"): self.owner.writer,
                    ("recover_complete", "text, text, text, text, text"): self.owner.writer})
            wire.require(len(functions) == len(expected_functions))
            for function in functions:
                key = function["proname"], function["arguments"]
                wire.require(key in expected_functions and function["owner"] == sql.OWNER
                    and function["prosecdef"] is True and function["proconfig"] == ["search_path=pg_catalog"]
                    and function["allowed"] is expected_functions[key], "RBAC witness purpose-function ACL differs")
            self.check(); return self
        except BaseException:
            self.connection.close(); raise

    def __exit__(self, kind, error, traceback):
        try:
            if kind is None:
                self.check(); self.connection.commit()
                # A closing check failure after COMMIT is uncertainty. It must
                # not trigger another write or claim definite completion.
                self.check()
            else: self.connection.rollback()
        finally:
            self.connection.close()
        return False

    def head(self, *, allow_pending=False):
        self.check()
        row = self.connection.execute("SELECT * FROM serverware_rbac_witness.read_head(%s)", (self.owner.enrollment_sha256,)).fetchone()
        wire.require(row is not None and row["enrollment_original"] == self.owner.enrollment_original.decode("ascii"),
            "RBAC witness enrollment is absent or changed")
        value = wire.head(wire.document(row["head_original"].encode("ascii"), 16384))
        wire.require(wire.sha256(wire.canonical(value)) == row["head_sha256"]
            and value["enrollmentSha256"] == self.owner.enrollment_sha256)
        if row["pending_sha256"] is not None:
            wire.digest(row["pending_sha256"])
            wire.require(allow_pending, "RBAC independent witness retains an unresolved transition")
        self.check(); return value, row["pending_sha256"]

    def record(self, request_sha256):
        self.check(); wire.digest(request_sha256)
        row = self.connection.execute("SELECT * FROM serverware_rbac_witness.read_record(%s,%s)",
            (self.owner.enrollment_sha256, request_sha256)).fetchone()
        if row is None: return None
        original = row["intent_original"].encode("ascii")
        intent = wire.document(original, MAX_COMMAND)
        wire.require(wire.sha256(original) == row["intent_sha256"] and intent["requestSha256"] == request_sha256
            and intent["enrollmentSha256"] == self.owner.enrollment_sha256)
        if row["completion_original"] is not None:
            raw = row["completion_original"].encode("ascii")
            wire.require(wire.sha256(raw) == row["completion_sha256"])
            wire.document(raw, MAX_COMMAND)
        self.check(); return dict(row)

    def reserve(self, original):
        self.check(); self.owner.require_writer()
        intent = wire.document(original, MAX_COMMAND)
        wire.require(set(intent) == {"schema", "enrollmentSha256", "requestSha256", "capabilityId", "beforeHeadSha256",
            "beforeHead", "afterHead", "expiresAtEpochNs", "planSha256"} and intent["schema"] == wire.INTENT_SCHEMA)
        wire.require(intent["enrollmentSha256"] == self.owner.enrollment_sha256)
        for name in ("requestSha256", "capabilityId", "beforeHeadSha256", "planSha256"): wire.digest(intent[name])
        wire.head(intent["beforeHead"]); wire.head(intent["afterHead"])
        row = self.connection.execute("SELECT * FROM serverware_rbac_witness.reserve(%s,%s)",
            (self.owner.enrollment_sha256, original.decode("ascii"))).fetchone()
        wire.require(row is not None and row["intent_original"].encode("ascii") == original and row["intent_sha256"] == wire.sha256(original))
        self.check(); return dict(row)

    def complete(self, intent_sha256, original, after_head):
        self.check(); self.owner.require_writer(); wire.digest(intent_sha256)
        completion = wire.document(original, MAX_COMMAND); after = wire.canonical(wire.head(after_head))
        wire.require(set(completion) == {"schema", "enrollmentSha256", "intentSha256", "requestSha256", "writerReceipt", "writerReceiptSha256", "resultBase64Url", "resultSha256"}
            and completion["schema"] == wire.COMPLETION_SCHEMA and completion["enrollmentSha256"] == self.owner.enrollment_sha256
            and completion["intentSha256"] == intent_sha256)
        wire.require(wire.sha256(wire.canonical(completion["writerReceipt"])) == completion["writerReceiptSha256"])
        import base64
        encoded = completion["resultBase64Url"]
        wire.require(type(encoded) is str and len(encoded) <= MAX_COMMAND)
        raw_result = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        wire.require(base64.urlsafe_b64encode(raw_result).rstrip(b"=").decode("ascii") == encoded
            and wire.sha256(raw_result) == completion["resultSha256"])
        wire.document(raw_result, MAX_COMMAND)
        row = self.connection.execute("SELECT * FROM serverware_rbac_witness.complete(%s,%s,%s,%s)",
            (self.owner.enrollment_sha256, intent_sha256, original.decode("ascii"), after.decode("ascii"))).fetchone()
        wire.require(row is not None and row["completion_original"].encode("ascii") == original and row["completion_sha256"] == wire.sha256(original))
        self.check(); return dict(row)


def provision(connection, enrollment_original, root_original):
    """Offline owner connection only; no runtime/HTTP caller uses this function.

    Both initial state and stable database identity are offline root-signed.
    Legacy profiles require independent provisioning; the explicit local
    profile is development-only and makes no independent-administration claim.
    This is initial provisioning only. Any existing namespace refuses; it never
    updates a head, adopts observed DB state or repairs a rolled-back store.
    """
    from cryptography.hazmat.primitives import serialization
    root = serialization.load_pem_public_key(root_original)
    policy = wire.enrollment(enrollment_original, root)
    if policy["schema"] == wire.LOCAL_ENROLLMENT_SCHEMA:
        wire.require_local_development()
    import psycopg
    from psycopg.rows import dict_row
    wire.require(type(connection) is psycopg.Connection and not connection.closed and connection.info.transaction_status == 0
        and connection.row_factory is dict_row, "initial witness provisioning requires its own idle actual dict-row connection")
    opening = time.time_ns()
    wire.require(policy["issuedAtEpochNs"] <= opening < policy["expiresAtEpochNs"])
    deadline = time.monotonic_ns() + min(30_000_000_000, policy["expiresAtEpochNs"] - opening)
    enrollment_sha256 = wire.sha256(enrollment_original)
    initial = wire.canonical(wire.initial_head(enrollment_sha256, policy))
    with connection.transaction():
        connection.execute("SET LOCAL synchronous_commit=on")
        connection.execute("SET LOCAL statement_timeout='30s'")
        connection.execute("SET LOCAL lock_timeout='30s'")
        durability = connection.execute("SELECT pg_catalog.current_setting('fsync') AS fsync,pg_catalog.current_setting('full_page_writes') AS full_page_writes").fetchone()
        wire.require(durability is not None and durability["fsync"] == "on" and durability["full_page_writes"] == "on")
        identity = connection.execute("SELECT (pg_catalog.pg_control_system()).system_identifier::text AS cluster_id,pg_catalog.current_database() AS database").fetchone()
        wire.require(identity["cluster_id"] == policy["witnessClusterId"] and identity["database"] == policy["endpoint"]["database"])
        connection.execute("SELECT pg_catalog.pg_advisory_xact_lock(762398450291)")
        wire.require(connection.execute("SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='serverware_rbac_witness'").fetchone() is None,
            "RBAC witness provisioning refuses an existing or uncertain namespace")
        connection.execute(sql.DDL)
        if policy["schema"] == wire.ENROLLMENT_V2_SCHEMA:
            from serverware.authority_store import rbac_recovery_sql
            connection.execute(rbac_recovery_sql.DDL)
        connection.execute("INSERT INTO serverware_rbac_witness.enrollments(enrollment_sha256,database_id,enrollment_original,head_original,head_sha256,maximum_records) "
            "VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING", (enrollment_sha256, policy["databaseId"], enrollment_original.decode("ascii"),
                initial.decode("ascii"), wire.sha256(initial), policy["maximumRecords"]))
        row = connection.execute("SELECT enrollment_sha256,enrollment_original,head_original,pending_sha256,record_count FROM serverware_rbac_witness.enrollments WHERE database_id=%s FOR UPDATE", (policy["databaseId"],)).fetchone()
        wire.require(row is not None and row["enrollment_sha256"] == enrollment_sha256 and row["enrollment_original"].encode("ascii") == enrollment_original
            and row["head_original"].encode("ascii") == initial and row["pending_sha256"] is None and row["record_count"] == 0,
            "RBAC witness provisioning cannot reset or replace retained history")
        wire.require(time.monotonic_ns() < deadline and opening <= time.time_ns() < policy["expiresAtEpochNs"])
    wire.require(time.monotonic_ns() < deadline and opening <= time.time_ns() < policy["expiresAtEpochNs"])
