"""Append-only measured producer admission, pending originals and audit commit.

All records and events share the actual PostgreSQL audit connection/chain lock.
No generic metadata DML, update/delete privilege, or caller success flag.
"""
from serverware import db
from serverware import data_plane_audit_authority as wire

TABLE = "serverware_measured_audit_records"
DDL = """
CREATE TABLE IF NOT EXISTS serverware_audit.serverware_measured_audit_epochs (
    workload_id TEXT PRIMARY KEY,
    epoch_id TEXT NOT NULL UNIQUE,
    original_json TEXT NOT NULL CHECK (pg_catalog.octet_length(original_json) <= 4096),
    original_sha256 TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS serverware_audit.serverware_measured_audit_records (
    sequence BIGSERIAL PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    epoch_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('admit','pending','commit')),
    producer_sequence BIGINT NOT NULL CHECK (producer_sequence > 0),
    original_json TEXT NOT NULL CHECK (pg_catalog.octet_length(original_json) <= 2097152),
    original_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (epoch_id,kind,producer_sequence)
);
"""


def _load(row):
    if row is None: return None
    value = wire.document(row["original_json"].encode("ascii"), 2 * 1024 * 1024)
    wire.require(wire.sha256(wire.canonical(value)) == row["original_sha256"])
    return value


def _record(cur, epoch, kind, sequence, value):
    raw = wire.canonical(value)
    wire.require(len(raw) <= 2 * 1024 * 1024)
    record_id = wire.sha256(wire.canonical([epoch, kind, sequence]))
    cur.execute("INSERT INTO serverware_measured_audit_records (id,epoch_id,kind,producer_sequence,original_json,original_sha256,created_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s)", (record_id, epoch, kind, sequence, raw.decode("ascii"), wire.sha256(raw), db.iso_now()))


def _latest(cur, epoch, kind):
    return _load(cur.execute("SELECT original_json,original_sha256 FROM serverware_measured_audit_records "
        "WHERE epoch_id=%s AND kind=%s ORDER BY producer_sequence DESC LIMIT 1", (epoch, kind)).fetchone())


def _events(cur, request, pending):
    original = wire.envelope(pending["original"].encode("ascii"))
    s = original["statement"]
    events = request.validate_events(wire.decode(s["eventsBase64url"], wire.MAX_EVENTS))
    previous = cur.execute("SELECT event_hash FROM serverware_audit_events ORDER BY sequence DESC LIMIT 1").fetchone()
    previous = previous["event_hash"] if previous else None
    for item in events:
        identity = wire.sha256(wire.canonical([s["epochId"], item["eventId"]]))
        # New producer sequence, new rows only. Conflicts roll back this whole
        # transaction; a partial/mismatched old event set is never repaired.
        event = db._audit_event_for_storage(item["eventType"], item["event"])
        event_json = db.dumps(event); db._validate_audit_event_json(event_json)
        stamp = db.iso_now()
        event_hash = db._audit_hash(event_id=identity, event_type=item["eventType"], actor_type="measured-data-plane",
            actor_id=s["instanceId"], event_json=event_json, prev_event_hash=previous, created_at=stamp)
        cur.execute("INSERT INTO serverware_audit_events (id,event_type,actor_type,actor_id,event_json,storage_format_version,prev_event_hash,event_hash,created_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)", (identity,item["eventType"],"measured-data-plane",s["instanceId"],event_json,
                db._AUDIT_STORAGE_FORMAT_VERSION,previous,event_hash,stamp))
        previous = event_hash
    return len(events), previous


def transact(request):
    from serverware.control_plane_data_plane_audit import _Request
    wire.require(type(request) is _Request and db.audit_uses_postgres(), "measured audit requires its actual PostgreSQL owner")
    request.check()
    s, assignment = request.statement, request.assignment
    epoch = s["epochId"]
    with db._audit_pg_connect() as connection:
        with connection.transaction():
            with connection.cursor() as cur:
                # Bound every lock/SQL wait to the original request window.
                remaining = request.remaining_ms()
                cur.execute("SELECT pg_catalog.set_config('statement_timeout',%s,true),pg_catalog.set_config('idle_in_transaction_session_timeout',%s,true)",
                    (str(remaining),str(remaining)))
                db._lock_postgres_audit(connection, "chain")
                request.check()
                workload = wire.sha256(wire.canonical([s["deploymentId"], s["instanceId"]]))
                epoch_row = cur.execute("SELECT epoch_id,original_json,original_sha256 FROM serverware_measured_audit_epochs WHERE workload_id=%s", (workload,)).fetchone()
                if epoch_row is None:
                    wire.require(s["action"] == "hello" and assignment["previousAssignmentSha256"] is None
                        and s["sequence"] == 1 and s["previousBatchSha256"] is None)
                    epoch_original = wire.canonical({"deploymentId":s["deploymentId"],"instanceId":s["instanceId"],"epochId":epoch,
                        "initialAssignmentSha256":s["assignmentSha256"]})
                    cur.execute("INSERT INTO serverware_measured_audit_epochs (workload_id,epoch_id,original_json,original_sha256) VALUES (%s,%s,%s,%s)",
                        (workload,epoch,epoch_original.decode("ascii"),wire.sha256(epoch_original)))
                else:
                    epoch_original = _load(epoch_row)
                    wire.require(epoch_row["epoch_id"] == epoch and epoch_original["epochId"] == epoch
                        and epoch_original["deploymentId"] == s["deploymentId"] and epoch_original["instanceId"] == s["instanceId"],
                        "existing workload cannot start a new audit epoch or reset its head")
                admission, committed, pending = (_latest(cur,epoch,kind) for kind in ("admit","commit","pending"))
                sequence = 1 if committed is None else committed["sequence"] + 1
                previous = None if committed is None else committed["batchSha256"]
                if pending is not None and pending["sequence"] < sequence: pending = None
                wire.require(pending is None or pending["sequence"] == sequence, "audit pending history has a gap")
                if s["action"] == "hello":
                    if admission is None or admission["assignmentSha256"] != s["assignmentSha256"]:
                        wire.require(s["sequence"] == sequence == assignment["initialSequence"]
                            and s["previousBatchSha256"] == previous == assignment["previousBatchSha256"]
                            and assignment["previousAssignmentSha256"] == (None if admission is None else admission["assignmentSha256"])
                            and assignment["pendingBatchSha256"] == (None if pending is None else pending["batchSha256"]),
                            "restart lacks exact independently authorized head/pending continuation")
                        ordinal = 1 if admission is None else admission["ordinal"] + 1
                        admission = {"assignmentSha256":s["assignmentSha256"],"ordinal":ordinal,
                            "assignment":assignment,"helloOriginal":request.raw.decode("ascii")}
                        _record(cur,epoch,"admit",ordinal,admission)
                    else:
                        # Exact logical hello replay only. A later head cannot
                        # silently advance a newly restarted source owner.
                        wire.require(s["sequence"] == sequence and s["previousBatchSha256"] == previous)
                    response = {"status":"admitted", "sequence":sequence, "previousBatchSha256":previous,
                        "batchSha256":None if pending is None else pending["batchSha256"],
                        "pendingOriginal":None if pending is None else pending["original"],"accepted":0,"auditHeadSha256":None}
                else:
                    wire.require(admission is not None and admission["assignmentSha256"] == s["assignmentSha256"],
                        "audit epoch has no current measured assignment")
                    if s["action"] == "prepare":
                        digest = wire.sha256(request.raw)
                        if committed is not None and s["sequence"] == committed["sequence"]:
                            wire.require(digest == committed["batchSha256"])
                            response = {**committed,"status":"committed","pendingOriginal":None}
                        else:
                            wire.require(s["sequence"] == sequence and s["previousBatchSha256"] == previous)
                            request.validate_events(wire.decode(s["eventsBase64url"], wire.MAX_EVENTS))
                            if pending is None:
                                pending = {"sequence":sequence,"previousBatchSha256":previous,"batchSha256":digest,"original":request.raw.decode("ascii")}
                                _record(cur,epoch,"pending",sequence,pending)
                            else: wire.require(pending["original"] == request.raw.decode("ascii"), "pending audit original is immutable")
                            response = {"status":"prepared","sequence":sequence,"previousBatchSha256":previous,"batchSha256":digest,
                                "pendingOriginal":None,"accepted":0,"auditHeadSha256":None}
                    else:
                        if committed is not None and s["sequence"] == committed["sequence"]:
                            wire.require(s["batchSha256"] == committed["batchSha256"] and s["previousBatchSha256"] == committed["previousBatchSha256"])
                        else:
                            wire.require(s["sequence"] == sequence and s["previousBatchSha256"] == previous and pending is not None
                                and s["batchSha256"] == pending["batchSha256"])
                            request.check()
                            accepted, head = _events(cur,request,pending)
                            committed = {"sequence":sequence,"previousBatchSha256":previous,"batchSha256":pending["batchSha256"],
                                "accepted":accepted,"auditHeadSha256":head}
                            _record(cur,epoch,"commit",sequence,committed)
                        response = {**committed,"status":"committed","pendingOriginal":None}
                request.check()
        # Definite transaction commit before signing/return. A timeout here is
        # uncertainty; it never resets the record or permits another original.
        request.check()
    return {"apiVersion":"serverware.measuredAuditAck/v1","ok":True,"epochId":epoch,
        "assignmentSha256":s["assignmentSha256"],"requestSha256":wire.sha256(request.raw), **response}
