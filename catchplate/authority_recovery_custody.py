"""Borrowed protected recovery originals and the real separate witness store.

No bootstrap, environment DSN fallback, key export, or witness-result callback
exists here. The caller owns the metadata transaction and every inherited FD.
Only the separate, purpose-selected witness connection is opened and closed.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import signal
import stat
import time

from catchplate import authority_recovery_configuration as selection
from catchplate import authority_revocation_configuration as measured
from catchplate.authority_query_read_work import _ValidationWork

_SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
_CONFIG = "CATCHPLATE_POLICY_AUTHORITY_CONFIG_FD"
_CONFIG_ROOT = "CATCHPLATE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD"
_SCHEMA = "catchplate_recovery_witness"
_CLAIMS = _SCHEMA + ".catchplate_recovery_authorization_claims"
_HEADS = _SCHEMA + ".catchplate_recovery_witness_heads"
_IDENTITY_SQL = (
    "SELECT (pg_catalog.pg_control_system()).system_identifier::text AS cluster_id,"
    "pg_catalog.current_database() AS database,pg_catalog.inet_server_addr()::text AS address,"
    "pg_catalog.inet_server_port() AS port,current_user::text AS role,session_user::text AS session_role,"
    "s.ssl,s.version,s.client_dn,s.client_serial::text AS client_serial,s.issuer_dn "
    "FROM pg_catalog.pg_stat_ssl s WHERE s.pid=pg_catalog.pg_backend_pid()")


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
        sort_keys=True, separators=(",", ":")).encode("ascii")


def _fd_identity(fd, maximum, *, expected_uid):
    selection.require(type(fd) is int and fd >= 3)
    value = os.fstat(fd)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
    selection.require(stat.S_ISREG(value.st_mode) and value.st_uid == expected_uid
        and stat.S_IMODE(value.st_mode) == 0o400 and value.st_nlink == 0
        and 1 <= value.st_size <= maximum and seals == _SEALS
        and flags & os.O_ACCMODE in (os.O_RDONLY, os.O_RDWR))
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns, flags, seals)


def _require_same_fd(fd, expected, maximum, *, expected_uid):
    selection.require(_fd_identity(fd, maximum, expected_uid=expected_uid) == expected)


class _HeldOriginal:
    """No duplication, reopen, close or descriptor-number adoption on failure."""
    def __init__(self, fd, maximum, work):
        self.fd, self.maximum = fd, maximum
        self.identity = _fd_identity(fd, maximum, expected_uid=0)
        work.charge(input_bytes=2 * self.identity[6])
        self.raw = os.pread(fd, maximum + 1, 0)
        selection.require(len(self.raw) == self.identity[6])
        self.check(work)

    def check(self, work):
        work.charge(input_bytes=self.identity[6])
        _require_same_fd(self.fd, self.identity, self.maximum, expected_uid=0)
        selection.require(os.pread(self.fd, self.maximum + 1, 0) == self.raw)


class _RecoveryCustody:
    def __init__(self):
        raise TypeError("recovery custody requires current measured original borrowing")

    @classmethod
    def _borrow(cls, *, selected, payload, configuration_digest, generation,
            runtime_role_identities, configuration_owner, observed_descriptors,
            metadata_connection, original_deadline_ns, check, work):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        import psycopg
        from psycopg.rows import dict_row
        from catchplate import authority_launch_guard as launch
        from catchplate.authority_service import MeasuredConfiguration, SIGNED_CONFIG_SCHEMA, _domain_digest

        selection.require(cls is _RecoveryCustody and type(work) is _ValidationWork
            and type(configuration_owner) is MeasuredConfiguration and callable(check)
            and type(metadata_connection) is psycopg.Connection
            and metadata_connection.row_factory is dict_row and not metadata_connection.closed
            and type(original_deadline_ns) is int
            and time.monotonic_ns() < original_deadline_ns < 2**63)
        measured.production._callback(work, check)
        active = measured.production._callback(work, lambda: launch.require_active("verifier"))
        selection.require(type(observed_descriptors) is dict)
        names = selection.CREDENTIAL_NAMES | {_CONFIG, _CONFIG_ROOT}
        selection.require(names <= observed_descriptors.keys())
        descriptors = {name: observed_descriptors[name] for name in names}
        selection.require(all(type(fd) is int and fd >= 3 for fd in descriptors.values())
            and len(set(descriptors.values())) == len(descriptors)
            and set(descriptors.values()) <= launch.retained_descriptors()
            and all(os.environ.get(name) == str(fd) for name, fd in descriptors.items()))
        self = object.__new__(cls)
        self._pid, self._closed, self._failed, self._claim_started = os.getpid(), False, False, False
        self._work, self._check_owner, self._launch = work, check, active
        self._configuration, self._digest, self._generation = configuration_owner, configuration_digest, generation
        self._runtime = runtime_role_identities
        self._metadata = metadata_connection
        self._backend_pid = metadata_connection.info.backend_pid
        self._selected_raw, self._policy_raw = _canonical(selected), _canonical(selected["policy"])
        work.charge(input_bytes=len(self._selected_raw) + len(self._policy_raw))
        self._selected = json.loads(self._selected_raw)
        self._role = dict(payload["roles"]["verifier"])
        selection.require((os.getuid(), os.getgid(), os.geteuid(), os.getegid())
            == (self._role["serviceUid"], self._role["serviceGid"],
                self._role["serviceUid"], self._role["serviceGid"]))
        self._fds = descriptors
        self._deadline = original_deadline_ns
        self._last_mono, self._last_epoch = time.monotonic_ns(), time.time_ns()
        self._expires = min(configuration_owner.history_archive.valid_until_epoch_ns,
            configuration_owner.attestation_evidence["payload"]["expiresAtEpochNs"])
        self._originals = {}
        limits = {"root": 4096, "dsn": 16384, "tlsRoot": 65536, "certificate": 65536, "key": 16384}
        for name, maximum in limits.items():
            self._originals[name] = _HeldOriginal(descriptors[selection.DESCRIPTORS[name]], maximum, work)
        self._configuration_original = _HeldOriginal(descriptors[_CONFIG], 4 * 1024 * 1024, work)
        self._configuration_root = _HeldOriginal(descriptors[_CONFIG_ROOT], 65536, work)
        selection.require(configuration_owner.original_bytes == self._configuration_original.raw
            and configuration_owner.digest == configuration_digest
            and configuration_owner.runtime_role_identities == runtime_role_identities)
        config_root = measured.production._callback(work, lambda:
            serialization.load_pem_public_key(self._configuration_root.raw))
        selection.require(isinstance(config_root, Ed25519PublicKey)
            and config_root.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                == configuration_owner.root_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        envelope = json.loads(self._configuration_original.raw)
        selection.require(type(envelope) is dict and set(envelope) == {"schema", "payload", "signature"}
            and envelope["schema"] == SIGNED_CONFIG_SCHEMA and envelope["payload"] == payload)
        from catchplate.authority_artifact_spec import strict_base64url_decode
        signature = strict_base64url_decode(envelope["signature"], name="recovery configuration signature", decoded_size=64)
        # Reuse the live verifier's exact signature domain, not the offline
        # issuer module (which also imports provisioning-only scripts).
        message = _domain_digest(SIGNED_CONFIG_SCHEMA, _canonical(payload)).encode("ascii")
        measured.production._callback(work, lambda: config_root.verify(signature, message))
        pins = selected["witness"]["originals"]
        for name, pin in (("root", selected["rootPublicPemSha256"]), ("dsn", pins["dsnSha256"]),
                ("tlsRoot", pins["tlsRootSha256"]), ("certificate", pins["certificateSha256"]),
                ("key", pins["keySha256"])):
            raw = self._originals[name].raw
            work.charge(hashes=1, input_bytes=len(raw))
            selection.require("sha256:" + hashlib.sha256(raw).hexdigest() == pin)
        public = measured.production._callback(work, lambda:
            serialization.load_pem_public_key(self._originals["root"].raw))
        selection.require(isinstance(public, Ed25519PublicKey))
        der = measured.production._callback(work, lambda: public.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        work.charge(hashes=1, input_bytes=len(der))
        selection.require("sha256:" + hashlib.sha256(der).hexdigest() == selected["policy"]["recovery_root_key_id"]
            and public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                == self._originals["root"].raw
            and public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                != config_root.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        selection.require(selected["policy"]["recovery_root_key_id"] not in
            {row["responseSigningSpkiDigest"] for row in payload["roles"].values()})
        witness_identity = selected["witness"]["identity"]
        selection.require(witness_identity["role"] not in {row["databaseRole"] for row in payload["roles"].values()}
            and witness_identity["clientDn"] not in {row["tlsClientDn"] for row in payload["roles"].values()})
        certificate = measured.production._callback(work, lambda:
            x509.load_pem_x509_certificate(self._originals["certificate"].raw))
        private = measured.production._callback(work, lambda:
            serialization.load_pem_private_key(self._originals["key"].raw, password=None))
        selection.require(certificate.public_key().public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo) == private.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        del private
        self.check()
        return self

    def check(self):
        from catchplate import authority_launch_guard as launch
        selection.require(not self._closed and not self._failed and os.getpid() == self._pid)
        now, epoch = time.monotonic_ns(), time.time_ns()
        selection.require(self._last_mono <= now < self._deadline and self._last_epoch <= epoch < self._expires)
        measured.production._callback(self._work, self._check_owner)
        selection.require(launch.require_active("verifier") == self._launch
            and (os.getuid(), os.getgid(), os.geteuid(), os.getegid())
                == (self._role["serviceUid"], self._role["serviceGid"],
                    self._role["serviceUid"], self._role["serviceGid"])
            and self._configuration.digest == self._digest
            and self._configuration.original_bytes == self._configuration_original.raw
            and self._configuration.runtime_role_identities == self._runtime
            and not self._metadata.closed and self._metadata.info.backend_pid == self._backend_pid
            and set(self._fds.values()) <= launch.retained_descriptors()
            and all(os.environ.get(name) == str(fd) for name, fd in self._fds.items()))
        generation = launch.generation()
        selection.require(all(generation[name] == value for name, value in self._generation.items()))
        for original in (*self._originals.values(), self._configuration_original, self._configuration_root):
            original.check(self._work)
        after, after_epoch = time.monotonic_ns(), time.time_ns()
        selection.require(now <= after < self._deadline and epoch <= after_epoch < self._expires)
        self._last_mono, self._last_epoch = after, after_epoch

    def _call(self, action):
        self.check()
        try:
            return measured.production._callback(self._work, action)
        finally:
            self.check()

    @property
    def root_public_key_original(self):
        self.check()
        return self._originals["root"].raw

    @property
    def policy(self):
        self.check()
        self._work.charge(input_bytes=len(self._policy_raw))
        return json.loads(self._policy_raw)

    def _metadata_identity(self):
        row = self._call(lambda: self._metadata.execute(_IDENTITY_SQL).fetchone())
        expected, role = self._selected["metadata"], self._role
        selection.require(row is not None
            and (row["cluster_id"], row["database"], row["address"], row["port"])
                == (expected["clusterId"], expected["database"], expected["serverAddress"], expected["serverPort"])
            and row["role"] == row["session_role"] == role["databaseRole"]
            and row["ssl"] is True and row["version"] == "TLSv1.3"
            and (row["client_dn"], row["client_serial"], row["issuer_dn"])
                == (role["tlsClientDn"], role["tlsClientSerial"], role["tlsIssuerDn"]))

    @contextlib.contextmanager
    def _parameters(self):
        from psycopg.conninfo import conninfo_to_dict
        self.check()
        selection.require(not any(name.startswith("PG") for name in os.environ))
        endpoint, identity = self._selected["witness"]["endpoint"], self._selected["witness"]["identity"]
        expected = dict(host=endpoint["host"], hostaddr=endpoint["address"], port=str(endpoint["port"]),
            dbname=endpoint["database"], user=identity["role"], sslmode="verify-full",
            ssl_min_protocol_version="TLSv1.3", ssl_max_protocol_version="TLSv1.3")
        dsn = self._originals["dsn"].raw.decode("ascii")
        selection.require(self._call(lambda: conninfo_to_dict(dsn)) == expected)
        parameters = dict(expected, passfile="/dev/null", password="", gssencmode="disable",
            application_name="catchplate-recovery-witness-v1")
        owned, projected = [], []
        cancellation = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}
        try:
            for parameter, name in (("sslrootcert", "tlsRoot"), ("sslcert", "certificate"), ("sslkey", "key")):
                self.check()
                raw = self._originals[name].raw
                previous = signal.pthread_sigmask(signal.SIG_BLOCK, cancellation)
                try:
                    fd = os.memfd_create("catchplate-recovery-" + name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
                    try:
                        info = os.fstat(fd)
                        owned.append((fd, info.st_dev, info.st_ino))
                    except BaseException:
                        os.close(fd)
                        raise
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous)
                offset = 0
                while offset < len(raw):
                    count = os.write(fd, raw[offset:])
                    selection.require(count > 0)
                    offset += count
                os.fchmod(fd, 0o400)
                fcntl.fcntl(fd, fcntl.F_ADD_SEALS, _SEALS)
                selection.require(os.pread(fd, len(raw) + 1, 0) == raw)
                projected.append((fd, len(raw), _fd_identity(fd, len(raw), expected_uid=os.geteuid())))
                parameters[parameter] = "/proc/self/fd/" + str(fd)
            self.check()
            for fd, maximum, identity in projected:
                _require_same_fd(fd, identity, maximum, expected_uid=os.geteuid())
            yield parameters
            self.check()
            for fd, maximum, identity in projected:
                _require_same_fd(fd, identity, maximum, expected_uid=os.geteuid())
        finally:
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, cancellation)
            try:
                for fd, device, inode in reversed(owned):
                    info = os.fstat(fd)
                    selection.require((info.st_dev, info.st_ino) == (device, inode))
                    os.close(fd)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)

    @contextlib.contextmanager
    def _connection(self):
        import psycopg
        from psycopg.rows import dict_row
        self._metadata_identity()
        connection = None
        try:
            with self._parameters() as parameters:
                remaining = self._deadline - time.monotonic_ns()
                selection.require(remaining > 0)
                connection = psycopg.connect(**parameters, row_factory=dict_row, autocommit=False,
                    connect_timeout=min(30, max(2, remaining // 1_000_000_000)), options="-c search_path=pg_catalog")
            # A late connect is closed before the first SQL statement.
            self.check()
            milliseconds = max(1, (self._deadline - time.monotonic_ns()) // 1_000_000)
            self._call(lambda: connection.execute("SELECT pg_catalog.set_config('statement_timeout',%s,true),"
                "pg_catalog.set_config('lock_timeout',%s,true),pg_catalog.set_config('idle_in_transaction_session_timeout',%s,true)",
                (str(milliseconds),) * 3))
            self._call(lambda: connection.execute("SET LOCAL synchronous_commit=on"))
            self._admit_witness(connection)
            self._metadata_identity()
            yield connection
            self._metadata_identity()
            self._call(connection.commit)
        except BaseException:
            self._failed = True
            raise
        finally:
            if connection is not None:
                connection.close()

    def _admit_witness(self, connection):
        target = self._selected["witness"]
        expected = target["identity"]
        row = self._call(lambda: connection.execute(_IDENTITY_SQL).fetchone())
        selection.require(row is not None
            and (row["cluster_id"], row["database"], row["address"], row["port"])
                == (expected["clusterId"], target["endpoint"]["database"], expected["serverAddress"], expected["serverPort"])
            and row["role"] == row["session_role"] == expected["role"]
            and row["ssl"] is True and row["version"] == "TLSv1.3"
            and (row["client_dn"], row["client_serial"], row["issuer_dn"])
                == (expected["clientDn"], expected["clientSerial"], expected["issuerDn"]))
        durability = self._call(lambda: connection.execute("SELECT pg_catalog.current_setting('fsync') AS fsync,"
            "pg_catalog.current_setting('full_page_writes') AS full_page_writes").fetchone())
        selection.require(durability is not None and durability["fsync"] == durability["full_page_writes"] == "on")
        bad = self._call(lambda: connection.execute(
            "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=session_user AND "
            "(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit) "
            "UNION ALL SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=session_user::pg_catalog.regrole "
            "UNION ALL SELECT 1 FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database() AND "
            "(datdba=session_user::pg_catalog.regrole OR pg_catalog.has_database_privilege(session_user,oid,'CREATE,TEMPORARY')) "
            "UNION ALL SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname NOT LIKE 'pg_temp_%' AND "
            "pg_catalog.has_schema_privilege(session_user,oid,'CREATE') "
            "UNION ALL SELECT 1 FROM pg_catalog.pg_namespace n CROSS JOIN LATERAL "
            "pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a "
            "WHERE n.nspname='catchplate_recovery_witness' AND a.privilege_type='CREATE' "
            "AND a.grantee<>n.nspowner LIMIT 1").fetchone())
        selection.require(bad is None)
        tables = self._call(lambda: connection.execute(
            "SELECT c.relname,c.relkind,c.relrowsecurity,c.relforcerowsecurity,c.relhastriggers,"
            "c.relhasrules,c.relhassubclass,c.relispartition,"
            "c.relowner=n.nspowner AS source_owned,c.relowner=session_user::pg_catalog.regrole AS client_owned,"
            "pg_catalog.has_table_privilege(session_user,c.oid,'SELECT') AS can_select,"
            "pg_catalog.has_table_privilege(session_user,c.oid,'INSERT') AS can_insert,"
            "pg_catalog.has_table_privilege(session_user,c.oid,'UPDATE') AS can_update,"
            "pg_catalog.has_table_privilege(session_user,c.oid,'DELETE,TRUNCATE,REFERENCES,TRIGGER') AS extra "
            "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname=%s AND c.relkind IN ('r','p','v','m','f') ORDER BY c.relname", (_SCHEMA,)).fetchall())
        selection.require([row["relname"] for row in tables] ==
            ["catchplate_recovery_authorization_claims", "catchplate_recovery_witness_heads"])
        for table in tables:
            selection.require(table["relkind"] == "r" and table["source_owned"] is True
                and all(table[name] is False for name in ("relrowsecurity", "relforcerowsecurity", "relhastriggers",
                    "relhasrules", "relhassubclass", "relispartition", "client_owned", "extra"))
                and all(table[name] is True for name in ("can_select", "can_insert", "can_update")))
        unique = self._call(lambda: connection.execute(
            "SELECT c.relname,k.contype,pg_catalog.array_agg(a.attname::text ORDER BY u.position) AS columns "
            "FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid "
            "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
            "JOIN pg_catalog.pg_index i ON i.indexrelid=k.conindid "
            "CROSS JOIN LATERAL pg_catalog.unnest(k.conkey) WITH ORDINALITY u(number,position) "
            "JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum=u.number "
            "WHERE n.nspname=%s AND k.contype IN ('p','u') AND k.convalidated AND NOT k.condeferrable "
            "AND i.indisunique AND i.indisvalid AND i.indisready "
            "GROUP BY c.relname,k.oid,k.contype", (_SCHEMA,)).fetchall())
        selection.require({(row["relname"], row["contype"], tuple(row["columns"])) for row in unique} == {
            ("catchplate_recovery_authorization_claims", "p", ("authorization_digest",)),
            ("catchplate_recovery_authorization_claims", "u", ("signature_digest",)),
            ("catchplate_recovery_authorization_claims", "u", ("statement_digest",)),
            ("catchplate_recovery_authorization_claims", "u", ("recovery_id",)),
            ("catchplate_recovery_witness_heads", "p", ("root_key_id", "user_id"))})

    def read_sequence(self, *, root_key_id, user_id):
        self.check()
        selection.require(root_key_id == self._selected["policy"]["recovery_root_key_id"])
        selection._text(user_id, 512)
        with self._connection() as connection:
            row = self._call(lambda: connection.execute("SELECT last_sequence FROM " + _HEADS
                + " WHERE root_key_id=%s AND user_id=%s", (root_key_id, user_id)).fetchone())
            sequence = 0 if row is None else row["last_sequence"]
            selection.require(type(sequence) is int and 0 <= sequence < 2**63 - 1)
        self.check()
        return sequence

    def claim(self, *, authorization_digest, signature_digest, statement_digest, recovery_id,
            ceremony_type, user_id, root_key_id, root_sequence):
        self.check()
        selection.require(not self._claim_started)
        for digest in (authorization_digest, signature_digest, statement_digest, root_key_id):
            selection._digest(digest)
        selection._text(recovery_id, 128)
        selection._text(user_id, 512)
        selection.require(root_key_id == self._selected["policy"]["recovery_root_key_id"]
            and ceremony_type in {"replacement-registration", "lost-active-key-decommission"}
            and type(root_sequence) is int and 1 <= root_sequence < 2**63)
        self._claim_started = True  # No replay after any attempted claim, including uncertainty.
        with self._connection() as connection:
            row = self._call(lambda: connection.execute("SELECT last_sequence FROM " + _HEADS
                + " WHERE root_key_id=%s AND user_id=%s FOR UPDATE", (root_key_id, user_id)).fetchone())
            if row is None:
                selection.require(root_sequence == 1)
                self._call(lambda: connection.execute("INSERT INTO " + _HEADS
                    + "(root_key_id,user_id,last_sequence) VALUES(%s,%s,%s)",
                    (root_key_id, user_id, root_sequence)))
            else:
                selection.require(type(row["last_sequence"]) is int and row["last_sequence"] + 1 == root_sequence)
                changed = self._call(lambda: connection.execute("UPDATE " + _HEADS
                    + " SET last_sequence=%s,updated_at=pg_catalog.clock_timestamp() "
                    "WHERE root_key_id=%s AND user_id=%s AND last_sequence=%s",
                    (root_sequence, root_key_id, user_id, root_sequence - 1)).rowcount)
                selection.require(changed == 1)
            claimed = self._call(lambda: connection.execute("INSERT INTO " + _CLAIMS
                + "(authorization_digest,signature_digest,statement_digest,recovery_id,ceremony_type,"
                "user_id,root_key_id,root_sequence) VALUES(%s,%s,%s,%s,%s,%s,%s,%s) RETURNING claimed_at",
                (authorization_digest, signature_digest, statement_digest, recovery_id, ceremony_type,
                    user_id, root_key_id, root_sequence)).fetchone())
            selection.require(claimed is not None and claimed["claimed_at"] is not None)
        self.check()

    def close(self):
        selection.require(os.getpid() == self._pid)
        self._closed = True  # Caller retains every original FD and metadata transaction.
