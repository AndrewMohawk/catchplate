"""Retained fixed-purpose PostgreSQL lock owner for an actual publication.

The app runtime role is never upgraded. This separate protected connection has
only one read/lock function and stays open through the sole file effect.
"""
from __future__ import annotations
import os
import time
from pathlib import Path

from serverware import db, policy_bundle as bundles
from serverware.authority_store import policy_file_read_sql as sql
from serverware import control_plane_admin_token_publication as files

DSN_PATH = "SERVERWARE_POLICY_FILE_MATERIALIZER_DSN_PATH"
DSN_SHA = "SERVERWARE_POLICY_FILE_MATERIALIZER_DSN_SHA256"


class CurrentPolicyAuthority:
    def __init__(self):
        raise TypeError("use the actual policy publication owner")

    @classmethod
    def open(cls, publication):
        from serverware.control_plane_policy_file_publication import PolicyFilePublication, _require, _sha
        _require(type(publication) is PolicyFilePublication and publication.consumed is not None
            and publication.authority is None)
        publication.check()
        owner = object.__new__(cls)
        owner.publication = publication
        owner.connection = owner.parent = owner.descriptor = None
        owner.original = None
        owner.configuration = (os.environ.get(DSN_PATH), os.environ.get(DSN_SHA))
        try:
            path, digest = owner.configuration
            _require(type(path) is str and Path(path).is_absolute() and type(digest) is str)
            owner.path, owner.basename, owner.parent, owner.parent_identity = bundles._open_secure_parent_directory(
                Path(path), label="policy materializer private DSN")
            owner.raw, value = files._read(owner.parent, owner.basename, 16 * 1024)
            _require(_sha(owner.raw) == digest)
            owner.identity = files._file_identity(value)
            _require(owner.path != publication.path and all(
                owner.identity[:2] != pin[4][:2] for pin in publication.pins))
            owner.descriptor = os.open(owner.basename, files._READ_FLAGS, dir_fd=owner.parent)
            _require(files._file_identity(os.fstat(owner.descriptor)) == owner.identity)
            dsn = owner.raw.decode("utf-8")
            _require(dsn == dsn.strip() and dsn and not any(c in dsn for c in "\r\n\x00"))
            remaining = publication.deadline - time.monotonic_ns()
            _require(remaining > 1_000_000_000)
            owner.connection = db._pinned_auxiliary_pg_connect(dsn=dsn, schema="serverware_metadata",
                connect_timeout=min(2, max(1, remaining // 1_000_000_000)), runtime_role=sql.ROLE,
                label="policy file materializer", error_type=ValueError)
            owner._configure()
            owner.check()
            return owner
        except BaseException:
            owner.close()
            raise

    def _contract(self):
        from serverware.control_plane_policy_file_publication import _require
        with self.connection.cursor() as cursor:
            _require(cursor.execute(*sql.privilege_check(namespace="serverware_metadata")).fetchone() is None)
            function = cursor.execute("SELECT p.prosrc, owner.rolname AS owner FROM pg_catalog.pg_proc p "
                "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace JOIN pg_catalog.pg_roles owner ON owner.oid=p.proowner "
                "WHERE n.nspname='serverware_metadata' AND p.proname=%s "
                "AND pg_catalog.oidvectortypes(p.proargtypes)='text, text'", (sql.FUNCTION,)).fetchone()
            _require(function is not None and function["prosrc"] == sql.body('"serverware_metadata"')
                and function["owner"] == db._METADATA_STORE_AUTHORITY_OWNER_ROLE)

    def _configure(self):
        from serverware.control_plane_policy_file_publication import _require
        remaining = (self.publication.deadline - time.monotonic_ns()) // 1_000_000
        _require(0 < remaining <= 30_000)
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT pg_catalog.set_config('lock_timeout', %s, true), "
                "pg_catalog.set_config('statement_timeout', %s, true), "
                "pg_catalog.set_config('idle_in_transaction_session_timeout', %s, true)",
                (str(min(500, remaining)) + "ms", str(remaining) + "ms", str(remaining) + "ms"))

    def check(self):
        from serverware.control_plane_policy_file_publication import _require, _signed, _sha
        from serverware.authority_policy_file_approval import canonical
        self.publication.check()
        _require(self.configuration == (os.environ.get(DSN_PATH), os.environ.get(DSN_SHA)))
        bundles._recheck_secure_parent_directory(self.path, label="policy materializer private DSN", expected=self.parent_identity)
        raw, value = files._read(self.parent, self.basename, 16 * 1024)
        _require(raw == self.raw and files._file_identity(value) == self.identity
            == files._file_identity(os.fstat(self.descriptor)))
        self._configure()
        self._contract()
        bound = self.publication.material_binding
        with self.connection.cursor() as cursor:
            row = cursor.execute("SELECT serverware_metadata.serverware_policy_file_current_lock(%s,%s) AS original",
                (bound["artifactEnvelopeSha256"], bound["policyHash"])).fetchone()
        original = row["original"]
        _require(type(original) is dict and set(original) == {"schema", "current", "artifact", "backendPid", "transactionId"}
            and original["schema"] == sql.CONTRACT and len(canonical(original)) <= 32 * 1024 * 1024
            and type(original["backendPid"]) is int and original["backendPid"] > 0
            and type(original["transactionId"]) is str and original["transactionId"].isdigit())
        current, artifact = original["current"], original["artifact"]
        _require(type(current) is dict and set(current) == {"policyId", "sequence", "rollbackEpoch", "policyHash",
            "preparationDigest", "finalizationDigest", "artifactEnvelopeSha256"}
            and all(current[key] == bound[key] for key in ("policyId", "sequence", "rollbackEpoch", "policyHash", "artifactEnvelopeSha256"))
            and artifact["artifact_envelope_digest"] == bound["artifactEnvelopeSha256"]
            and artifact["policy_bundle_digest"] == bound["policyBundleSha256"])
        for key in ("artifact_envelope", "artifact_payload"):
            encoded = artifact[key + "_json"]
            _require(type(encoded) is str and 0 < len(encoded.encode("utf-8")) <= 8 * 1024 * 1024
                and _sha(encoded.encode("utf-8")) == artifact[key + "_digest"])
        _, trust, actual = _signed(self.publication.raw)
        _require(trust == self.publication.trust and all(bound[key] == value for key, value in actual.items()))
        if self.original is None:
            self.original = original
        else:
            _require(original == self.original)
        self._configure()
        self._contract()
        self.publication.check()

    def close(self):
        connection, self.connection = self.connection, None
        try:
            if connection is not None:
                try:
                    connection.rollback()
                finally:
                    connection.close()
        finally:
            for name in ("descriptor", "parent"):
                value = getattr(self, name, None)
                setattr(self, name, None)
                if value is not None:
                    os.close(value)
