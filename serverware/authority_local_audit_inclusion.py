"""One genuinely observed, first-genesis audit inclusion on a trusted host.

This separate signer reads existing restricted PostgreSQL metadata and audit
connections. It never inserts an event, completes an outbox, initializes state,
or writes authority SQL. Empty inclusion state is an observed snapshot, not an
ongoing authority claim: the existing genesis-finalize transaction must still
verify its current rows, signatures and CAS. Co-location is not independently
administered or hardware-isolated custody. Continuations are unsupported.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
import re
import signal
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts.authority import native_pilot_authority_io as io
from serverware.authority_local_artifacts import document, sha
from serverware.authority_local_snapshot import _boot
from serverware import authority_local_audit_reader as reader

APPROVAL_SCHEMA = "serverware.authorityTrustedHostLocalFirstAuditInclusionApproval/v1"
PURPOSE = "sign-observed-first-genesis-audit-inclusion"
MAX_APPROVAL = 8192
MAX_DSN = 16384
MAX_WINDOW_NS = 30_000_000_000
MAX_AUDIT_ROWS = 256
MAX_AUDIT_BYTES = 32 * 1024 * 1024
MAX_KEYS = 32
_CANCEL = frozenset({signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
DSN_FIELDS = frozenset({"sha256", "database", "role", "host", "port", "transport"})
TABLES = ("policy_authority_genesis_finalizations", "policy_authority_audit_inclusion_heads",
          "policy_authority_audit_inclusion_receipts", "policy_high_water", "policy_publications")


def require(value, message="first local audit inclusion refused"):
    if not value:
        raise ValueError(message)


def digest(value):
    require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None)
    return value


def approval(raw):
    value = document(raw, MAX_APPROVAL)
    require(set(value) == {"schema", "purpose", "metadata", "audit", "genesisPreparationDigest", "policyHash",
        "auditStoreIdentityDigest", "auditSignerPublicKeyDigest", "rootKeySpkiDigest", "bootIdDigest",
        "issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"}
        and value["schema"] == APPROVAL_SCHEMA and value["purpose"] == PURPOSE)
    for name in ("genesisPreparationDigest", "policyHash", "auditStoreIdentityDigest",
                 "auditSignerPublicKeyDigest", "rootKeySpkiDigest", "bootIdDigest"):
        digest(value[name])
    require(value["auditSignerPublicKeyDigest"] != value["rootKeySpkiDigest"])
    for name in ("metadata", "audit"):
        selected = value[name]
        require(type(selected) is dict and set(selected) == DSN_FIELDS)
        digest(selected["sha256"])
        for field in ("role", "database"):
            require(type(selected[field]) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,62}", selected[field]) is not None)
        require(type(selected["host"]) is str and selected["host"] and len(selected["host"]) <= 255
            and selected["host"].isascii() and not any(c in selected["host"] for c in "\r\n\0, ")
            and type(selected["port"]) is int and 1 <= selected["port"] <= 65535)
        require(selected["transport"] in {"unix", "tls-verify-full"}
            and (selected["transport"] == "unix") == selected["host"].startswith("/"))
    require(value["metadata"]["role"] != value["audit"]["role"])
    require(value["metadata"]["role"] == reader.ROLE)
    for start, end in (("issuedAtBoottimeNs", "deadlineBoottimeNs"), ("issuedAtUnixNanos", "expiresAtUnixNanos")):
        require(type(value[start]) is type(value[end]) is int
            and 0 < value[start] < value[end] < 2**63 and value[end] - value[start] <= MAX_WINDOW_NS)
    return value


def _bounded_rows(rows, maximum=MAX_KEYS):
    require(type(rows) is list and len(rows) <= maximum and all(type(row) is dict for row in rows))
    return rows


def current_key(kind, keys, heads, revocations, runtime_keys, selected):
    """Pure joins over actual transaction originals; no caller key is trusted."""
    head = [row for row in heads if row["evidence_kind"] == kind]
    require(len(head) == 1)
    head = head[0]
    matching = [row for row in keys if row["evidence_kind"] == kind and row["key_revision"] == head["head_key_revision"]]
    require(len(matching) == 1)
    key = matching[0]
    require(key["signing_key_id"] == key["public_key_digest"] == head["head_public_key_digest"] == head["head_signing_key_id"]
        and key["public_key_digest"] != selected["rootKeySpkiDigest"]
        and not any(row["evidence_kind"] == kind and row["signing_key_id"] == key["signing_key_id"] for row in revocations)
        and not any(row["public_key_digest"] == key["public_key_digest"] and row["evidence_kind"] != kind for row in keys)
        and not any(row["public_key_digest"] == key["public_key_digest"] and row["role"] in {"export", "custody"} for row in runtime_keys))
    if kind == "audit_inclusion_receipt":
        require(key["public_key_digest"] == selected["auditSignerPublicKeyDigest"])
    return key, head


def original_binding(selected, *, preparation, verification, transition, outbox, keys, heads,
                     revocations, runtime_keys, audit_rows, now_unix_ns):
    """Validate source rows; callers cannot use this function to claim SQL IO."""
    from serverware import db
    from serverware import authority_transition_policy as legacy
    from serverware import authority_transition_policy_genesis as genesis
    from serverware import authority_policy_candidate_evidence as signatures
    for rows in (keys, heads, revocations, runtime_keys):
        _bounded_rows(rows)
    require(type(now_unix_ns) is int and selected["issuedAtUnixNanos"] <= now_unix_ns < selected["expiresAtUnixNanos"])
    require(preparation["genesis_preparation_digest"] == selected["genesisPreparationDigest"]
        and preparation["policy_hash"] == selected["policyHash"]
        and preparation["prepared_at_epoch_ns"] <= now_unix_ns < preparation["expires_at_epoch_ns"])
    base = {name: preparation[name] for name in legacy._GENESIS_RECORD_FIELDS}
    legacy._genesis_record(base)
    key, head = current_key("authority_genesis", keys, heads, revocations, runtime_keys, selected)
    verified_at = verification["verified_at_epoch_ns"]
    require(type(verified_at) is int and 0 < verified_at <= now_unix_ns)
    # The deliberately narrow first-install path refuses a changed signing
    # head; it does not infer historical key succession or renew evidence.
    old_sequence = max((row["revocation_sequence"] for row in revocations if row["revoked_at_epoch_ns"] <= verified_at), default=0)
    recomputed = signatures.verify_static_original(**genesis.evidence(genesis.PREPARE, base), key=key, key_head=head,
        revocation=None, revocation_sequence=old_sequence, verified_at_epoch_ns=verified_at)
    require(recomputed == verification and all(preparation[name] == recomputed[name]
        for name in ("evidence_kind", "verification_receipt_digest", "record_binding_digest")))
    require(transition["transition_digest"] == preparation["genesis_transition_digest"])
    actual_stage = genesis.stage(base, datetime.fromtimestamp(now_unix_ns // 1_000_000_000, timezone.utc))
    require(transition == actual_stage["transition"])
    expected = actual_stage["outbox"]
    require(all(outbox[name] == expected[name] for name in ("id", "event_type", "actor_type", "actor_id", "event_json", "event_digest"))
        and outbox["status"] == "audited" and outbox["claim_id"] is None
        and outbox["audit_event_hash"] is not None)
    require(type(audit_rows) is list and 0 < len(audit_rows) <= MAX_AUDIT_ROWS)
    previous, total, last_sequence = None, 0, 0
    for row in audit_rows:
        require(type(row) is dict and type(row["sequence"]) is int and row["sequence"] > last_sequence)
        total += len(db.dumps(row).encode("ascii"))
        require(total <= MAX_AUDIT_BYTES)
        previous = db._validated_audit_row_hash(row, previous, keyring=None)
        last_sequence = row["sequence"]
    actual = audit_rows[-1]
    require(actual["id"] == outbox["id"] and actual["event_hash"] == outbox["audit_event_hash"]
        and all(actual[name] == outbox[name] for name in ("event_type", "actor_type", "actor_id", "event_json"))
        and db._metadata_outbox_event_digest(actual["event_json"]) == transition["outbox_event_digest"])
    audit_key, audit_head = current_key("audit_inclusion_receipt", keys, heads, revocations, runtime_keys, selected)
    row = dict(transition_digest=transition["transition_digest"], outbox_id=outbox["id"],
        outbox_event_digest=outbox["event_digest"], audit_store_identity_digest=selected["auditStoreIdentityDigest"],
        audit_ledger_namespace=db._POLICY_AUTHORITY_AUDIT_LEDGER_NAMESPACE,
        audit_signer_public_key_digest=selected["auditSignerPublicKeyDigest"], audit_event_hash=actual["event_hash"],
        audit_sequence=1, previous_audit_event_hash=None)
    row["inclusion_root_digest"] = db._policy_authority_audit_inclusion_root(
        audit_store_identity_digest=row["audit_store_identity_digest"], audit_ledger_namespace=row["audit_ledger_namespace"],
        audit_signer_public_key_digest=row["audit_signer_public_key_digest"], audit_sequence=1, previous_root_digest=None,
        audit_event_hash=row["audit_event_hash"], outbox_event_digest=row["outbox_event_digest"], transition_digest=row["transition_digest"])
    return row, audit_key, audit_head, max((item["revocation_sequence"] for item in revocations), default=0)


def signed_original(row, key, head, sequence, private, *, issued, expires, now):
    from serverware import db
    from serverware import authority_transition_policy_genesis as genesis
    from serverware import authority_policy_candidate_evidence as signatures
    require(type(issued) is type(expires) is type(now) is int and 0 < issued <= now < expires)
    public = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    require(sha(public) == row["audit_signer_public_key_digest"] == key["public_key_digest"])
    domain = db._POLICY_AUTHORITY_EVIDENCE_DOMAINS["audit_inclusion_receipt"]
    payload = dict(issuedAtEpochNs=issued, expiresAtEpochNs=expires,
        record=db._candidate_authority_signed_record(row, current_prefix="inclusion_receipt"))
    payload_raw = db.dumps(payload).encode("ascii")
    message = b"\0".join((db._POLICY_AUTHORITY_SIGNATURE_FRAME, domain.encode("ascii"),
        db._POLICY_AUTHORITY_CANONICAL_PROFILE.encode("ascii"), payload_raw))
    signature = private.sign(message)
    from serverware import authority_artifact_spec as encoding
    envelope = dict(apiVersion=domain, kind="PolicyAuthorityAuditInclusion",
        canonicalProfile=db._POLICY_AUTHORITY_CANONICAL_PROFILE, signatureDomain=domain,
        payload=payload, payloadSha256=sha(payload_raw), signatureAlgorithm="Ed25519",
        signingKeyId=key["signing_key_id"], signingKeySpkiSha256=key["public_key_digest"],
        signature=encoding.strict_base64url_encode(signature))
    envelope_raw = db.dumps(envelope).encode("ascii")
    result = dict(row, inclusion_receipt_envelope_json=envelope_raw.decode("ascii"),
        inclusion_receipt_envelope_digest=sha(envelope_raw), inclusion_receipt_payload_json=payload_raw.decode("ascii"),
        inclusion_receipt_payload_digest=sha(payload_raw), signature_algorithm="Ed25519", signing_key_id=key["signing_key_id"],
        signature=envelope["signature"], signature_digest=sha(signature))
    require(set(result) == set(db._POLICY_AUTHORITY_AUDIT_INCLUSION_FIELDS))
    # Consumer's actual byte/signature calculation, not an issuer verdict row.
    signatures.verify_static_original(**genesis.evidence(genesis.FINALIZE, result), key=key, key_head=head,
        revocation=None, revocation_sequence=sequence, verified_at_epoch_ns=now)
    return db.dumps(result).encode("ascii")


def admit_signing_key(key, *, issued, expires, now):
    """Validate the observed purpose/time/public-key row before private reads."""
    from serverware import db
    require(key["evidence_kind"] == "audit_inclusion_receipt"
        and key["signature_domain"] == db._POLICY_AUTHORITY_EVIDENCE_DOMAINS["audit_inclusion_receipt"])
    for name in ("installed_at_epoch_ns", "not_before_epoch_ns", "not_after_epoch_ns", "max_clock_skew_ns", "max_evidence_age_ns"):
        require(type(key[name]) is int and 0 <= key[name] < 2**63)
    require(max(key["installed_at_epoch_ns"], key["not_before_epoch_ns"]) <= issued <= now < expires <= key["not_after_epoch_ns"]
        and now - issued <= key["max_evidence_age_ns"])
    raw = db._candidate_authority_b64url("observed audit key", key["public_key_base64url"], expected_bytes=32)
    public = Ed25519PublicKey.from_public_bytes(raw)
    require(sha(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        == key["public_key_digest"] == key["signing_key_id"])


class AuditInclusionError(RuntimeError):
    def __init__(self, owner):
        super().__init__("first local audit inclusion refused; retained owner may need cleanup")
        self.owner = owner


class LocalAuditInclusionIssuer:
    """Actual one-shot connection owner; no authority DML or output retries."""

    def __init__(self, *, approval_fd, approval_sha256, metadata_dsn_fd, audit_dsn_fd, signing_key_fd):
        io._process()
        fds = (approval_fd, metadata_dsn_fd, audit_dsn_fd, signing_key_fd)
        require(all(type(fd) is int and fd >= 3 for fd in fds) and len(set(fds)) == len(fds))
        self.fds, self.approval_fd = fds, approval_fd
        self.metadata_dsn_fd, self.audit_dsn_fd, self.signing_key_fd = metadata_dsn_fd, audit_dsn_fd, signing_key_fd
        self.identities = {fd: io._identity(os.fstat(fd)) for fd in fds}
        require(len({value[:2] for value in self.identities.values()}) == len(fds))
        self.raw = io.read_public(approval_fd, MAX_APPROVAL)
        require(sha(self.raw) == digest(approval_sha256))
        self.selected = approval(self.raw)
        self.pid, self.environment = os.getpid(), tuple(sorted(os.environ.items()))
        self.boot_ns, self.unix_ns = self.selected["issuedAtBoottimeNs"], self.selected["issuedAtUnixNanos"]
        self.effective_expiry = self.selected["expiresAtUnixNanos"]
        self.connections, self.secret_originals = [], {}
        self.used = self.closed = self.uncertain = False
        self.check()

    def check(self):
        io._process()
        require(os.getpid() == self.pid and tuple(sorted(os.environ.items())) == self.environment
            and not self.closed and not self.uncertain and _boot() == self.selected["bootIdDigest"])
        for fd, identity in self.identities.items():
            require(io._identity(os.fstat(fd)) == identity)
        require(io.read_public(self.approval_fd, MAX_APPROVAL) == self.raw)
        for fd, raw in self.secret_originals.items():
            io._input(fd, MAX_DSN, private=True)
            require(io.read_public(fd, MAX_DSN) == raw)
        boot, unix = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        require(self.boot_ns <= boot < self.selected["deadlineBoottimeNs"]
            and self.unix_ns <= unix < self.effective_expiry)
        self.boot_ns, self.unix_ns = boot, unix

    def _remaining(self):
        self.check()
        return max(1, min((self.selected["deadlineBoottimeNs"] - self.boot_ns) // 1_000_000,
                          (self.effective_expiry - self.unix_ns) // 1_000_000))

    def _configure(self, connection):
        remaining = str(self._remaining())
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_catalog.set_config('statement_timeout',%s,true), "
                "pg_catalog.set_config('lock_timeout',%s,true), "
                "pg_catalog.set_config('idle_in_transaction_session_timeout',%s,true)",
                (remaining, remaining, remaining))

    def _execute(self, cursor, sql, parameters=()):
        self._configure(cursor.connection)
        result = cursor.execute(sql, parameters)
        self.check()
        return result

    def _connect(self, name, fd):
        from serverware import db
        from psycopg.conninfo import conninfo_to_dict
        selected = self.selected[name]
        io._input(fd, MAX_DSN, private=True)
        raw = io.read_public(fd, MAX_DSN)
        require(sha(raw) == selected["sha256"])
        dsn = raw.decode("utf-8")
        require(dsn == dsn.strip() and dsn and not any(c in dsn for c in "\r\n\0"))
        parsed = conninfo_to_dict(dsn)
        require(not set(parsed) & {"service", "servicefile", "options"}
            and parsed.get("user") == selected["role"] and parsed.get("dbname") == selected["database"]
            and parsed.get("host") == selected["host"] and parsed.get("port") == str(selected["port"]))
        if selected["transport"] == "tls-verify-full":
            require(parsed.get("sslmode") == "verify-full")
        self.secret_originals[fd] = raw
        schema = "serverware_metadata" if name == "metadata" else "serverware_audit"
        remaining = self._remaining()
        require(remaining > 1000)
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, _CANCEL)
        try:
            connection = db._pinned_auxiliary_pg_connect(dsn=dsn, schema=schema,
                connect_timeout=min(2, remaining // 1000), runtime_role=selected["role"],
                label="first audit inclusion " + name, error_type=ValueError,
                retain_connection=self.connections.append)
        finally:
            # Any acquired connection is already retained before cancellation.
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        connection.rollback()
        with connection.cursor() as cursor:
            cursor.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            cursor.execute("SELECT pg_catalog.set_config('search_path',%s,true), "
                "pg_catalog.set_config('statement_timeout',%s,true), "
                "pg_catalog.set_config('lock_timeout',%s,true), "
                "pg_catalog.set_config('idle_in_transaction_session_timeout',%s,true)",
                (schema + ", pg_catalog", str(self._remaining()), str(self._remaining()), str(self._remaining())))
            identity = cursor.execute("SELECT current_user AS role, session_user AS session_role, "
                "pg_catalog.current_database() AS database, pg_catalog.current_setting('transaction_read_only') AS read_only, "
                "pg_catalog.current_setting('transaction_isolation') AS isolation, ssl.ssl "
                "FROM pg_catalog.pg_stat_ssl ssl WHERE ssl.pid=pg_catalog.pg_backend_pid()").fetchone()
            require(identity is not None and identity["role"] == identity["session_role"] == selected["role"]
                and identity["database"] == selected["database"] and identity["read_only"] == "on"
                and identity["isolation"] == "repeatable read"
                and (selected["transport"] != "tls-verify-full" or identity["ssl"] is True))
            if name == "metadata":
                require(cursor.execute(*reader.privilege_check()).fetchone() is None)
        self.check()
        return connection

    def issue(self):
        from serverware import db
        require(not self.used)
        self.used = True
        try:
            metadata = self._connect("metadata", self.metadata_dsn_fd)
            audit = self._connect("audit", self.audit_dsn_fd)
            with metadata.cursor() as cursor:
                for table in TABLES:
                    self.check()
                    # Table names are a source-owned constant, not caller SQL.
                    require(self._execute(cursor, "SELECT 1 FROM serverware_metadata." + table + " LIMIT 1").fetchone() is None,
                        "first inclusion refuses existing publication/finalization/inclusion history")
                preparation = self._execute(cursor, "SELECT * FROM serverware_metadata.policy_authority_genesis_preparations "
                    "WHERE genesis_preparation_digest=%s", (self.selected["genesisPreparationDigest"],)).fetchone()
                require(preparation is not None)
                transition = self._execute(cursor, "SELECT * FROM serverware_metadata.policy_authority_transition_audits "
                    "WHERE transition_digest=%s", (preparation["genesis_transition_digest"],)).fetchone()
                require(transition is not None)
                outbox = self._execute(cursor, "SELECT * FROM serverware_metadata.metadata_audit_outbox WHERE id=%s", (transition["outbox_id"],)).fetchone()
                verification = self._execute(cursor, "SELECT * FROM serverware_metadata.policy_authority_evidence_verifications "
                    "WHERE verification_receipt_digest=%s", (preparation["verification_receipt_digest"],)).fetchone()
                require(outbox is not None and verification is not None)
                populations = {}
                for name, table in (("keys", "policy_authority_trusted_keys"), ("heads", "policy_authority_trusted_key_heads"),
                        ("revocations", "policy_authority_trusted_key_revocations"), ("runtime_keys", "policy_runtime_role_keys")):
                    self.check()
                    populations[name] = _bounded_rows(self._execute(cursor, "SELECT * FROM serverware_metadata." + table + " LIMIT %s", (MAX_KEYS + 1,)).fetchall())
            with audit.cursor() as cursor:
                target = self._execute(cursor, "SELECT sequence FROM serverware_audit.serverware_audit_events WHERE id=%s", (outbox["id"],)).fetchone()
                require(target is not None and type(target["sequence"]) is int and target["sequence"] > 0)
            rows, total = [], 0
            with audit.cursor(name="first_genesis_inclusion_prefix") as cursor:
                self._configure(audit)
                cursor.execute("SELECT sequence,id,event_type,actor_type,actor_id,event_json,encrypted_canonical_event_json,"
                    "storage_format_version,prev_event_hash,event_hash,created_at FROM serverware_audit.serverware_audit_events "
                    "WHERE sequence<=%s ORDER BY sequence LIMIT %s", (target["sequence"], MAX_AUDIT_ROWS + 1))
                while True:
                    self._configure(audit)
                    row = cursor.fetchone()
                    if row is None: break
                    rows.append(row)
                    total += len(db.dumps(row).encode("ascii"))
                    require(len(rows) <= MAX_AUDIT_ROWS and total <= MAX_AUDIT_BYTES)
            self.check()
            row, key, head, sequence = original_binding(self.selected, preparation=preparation, verification=verification,
                transition=transition, outbox=outbox, audit_rows=rows, now_unix_ns=self.unix_ns, **populations)
            issued = self.selected["issuedAtUnixNanos"]
            expires = min(self.selected["expiresAtUnixNanos"], preparation["expires_at_epoch_ns"])
            self.effective_expiry = min(self.effective_expiry, expires)
            self.check()
            admit_signing_key(key, issued=issued, expires=expires, now=self.unix_ns)
            private = io.signing_key(self.signing_key_fd)
            try:
                self.check()
                raw = signed_original(row, key, head, sequence, private, issued=issued, expires=expires, now=self.unix_ns)
            finally:
                del private
            self.check()
            return raw
        except BaseException as error:
            raise AuditInclusionError(self) from error

    def close(self):
        if self.closed: return
        require(os.getpid() == self.pid and not self.uncertain)
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, _CANCEL)
        try:
            while self.connections:
                connection = self.connections[-1]
                try:
                    try: connection.rollback()
                    finally: connection.close()
                except BaseException as error:
                    # Keep even a possibly closed handle on uncertain failure;
                    # neither remove ownership nor attempt another close.
                    self.uncertain = True
                    raise AuditInclusionError(self) from error
                self.connections.pop()
            self.closed = True
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)

    def publish(self):
        raw = self.issue()
        io.write_public(raw, deadline_boottime_ns=self.selected["deadlineBoottimeNs"], check=self.check)
        self.check()
