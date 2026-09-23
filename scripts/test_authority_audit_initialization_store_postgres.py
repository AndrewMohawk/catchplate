#!/usr/bin/env python3
"""Native local initialization storage, never externally anchored authority.

An explicitly acknowledged disposable PG16/UTF8 harness must provide one owned
mode-0700 Unix socket. No engine starts here. This fixture COMMITS a uniquely
named store DATABASE, owner/runtime roles and schema/enrollment/candidate so
reopen checks exercise real runtime logins and database transactions. The
prepared harness must allow these passwordless test-role Unix-socket logins;
failure is a precondition failure, never a skip or SET ROLE substitute. Cleanup
removes only the exact fixture-created database and roles after closing handles.
The separate metadata connection uses the existing rollback-only real DDL/tree
fixture; metadata transactions remain caller-owned throughout. Both connections
use one disposable cluster, not independently administered storage domains.

Real deterministic Ed25519 signatures and real stored rows/proofs are used.
Fixture-owner enrollment is setup, not a runtime enrollment/reset API. A local
record is not an off-host commit decision, external anchor, rollback-resistant
checkpoint, writer fence, one-use installation receipt or installer permission.
No DB facade, registry replacement or fabricated verifier is imported.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import unittest
import uuid
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

import psycopg
from psycopg import sql
from psycopg.pq import TransactionStatus


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware.native_postgres_results import run_native_fixture

from serverware import authority_audit_initialization_admission as admission
from serverware import authority_audit_initialization_postgres as reader
from serverware import authority_audit_initialization_store as store
from serverware import authority_contract
from serverware.authority_store.audit_initialization_store_sql import (
    audit_initialization_store_ddl, audit_initialization_store_grants,
)
from serverware.authority_store import initialization_store_access as access
import test_authority_audit_initialization_admission as admission_fixture
import test_authority_audit_initialization_postgres as metadata_fixture
from test_authority_audit_inventory import outbox_row
from test_authority_audit_initialization import AGGREGATE, IDENTITY, OUTBOX
from test_authority_radix_proof import wire_digest, wire_json
from test_webauthn_trust_projection_postgres import local_connection_parameters


CONNECTION_PARAMETERS: dict[str, str | int] | None = None
DISPOSABLE_CLUSTER_ACKNOWLEDGED = False
ENROLLMENTS = "initialization_enrollments"
CANDIDATES = "initialization_candidates"
WRONG_DIGEST = "sha256:" + "f" * 64
ENROLLMENT_SCHEMA = "serverware.metadataAuditInitializationStoreEnrollment/v1"
REQUEST_SCHEMA = "serverware.metadataAuditInitializationStoreRequest/v1"
CANDIDATE_SCHEMA = "serverware.metadataAuditInitializationStoredCandidate/v1"


def store_limits(**changes):
    values = dict(statement_timeout_ms=5_000, lock_timeout_ms=250, total_timeout_ms=60_000)
    values.update(changes)
    return store.StoreReadLimits(**values)


class AuditInitializationStorePostgresTests(unittest.TestCase):
    def setUp(self):
        if CONNECTION_PARAMETERS is None or not DISPOSABLE_CLUSTER_ACKNOWLEDGED:
            raise RuntimeError("requires --postgres-dsn and --disposable-cluster")
        self.connections = []
        suffix = uuid.uuid4().hex
        self.schema = "audit_init_store_" + suffix
        self.database = "audit_init_db_" + suffix
        self.runtime_role = "audit_init_run_" + suffix
        self.owner_role = "audit_init_own_" + suffix
        self.database_created = False
        self.roles_created = []
        self.metadata = None
        self.addCleanup(self.cleanup_owned_state)
        control = self.connect_admin(control=True, autocommit=True)
        environment = control.execute(
            "SELECT pg_catalog.inet_server_addr(), pg_catalog.getdatabaseencoding(), "
            "pg_catalog.current_setting('server_version_num')::integer, current_user=session_user, "
            "pg_catalog.current_setting('fsync'), pg_catalog.current_setting('full_page_writes'), "
            "pg_catalog.pg_is_in_recovery(), role_record.rolsuper "
            "FROM pg_catalog.pg_roles AS role_record WHERE role_record.rolname=current_user"
        ).fetchone()
        if (environment is None or environment[0] is not None or environment[1] != "UTF8"
                or not 160000 <= environment[2] < 170000 or environment[3] is not True
                or environment[4:] != ("on", "on", False, True)):
            raise RuntimeError("requires direct disposable superuser Unix-socket PG16/UTF8 with durable settings")
        for role, login in ((self.owner_role, "NOLOGIN"), (self.runtime_role, "LOGIN")):
            control.execute(sql.SQL(
                "CREATE ROLE {} {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOBYPASSRLS NOINHERIT"
            ).format(sql.Identifier(role), sql.SQL(login)))
            self.roles_created.append(role)
        control.execute(sql.SQL("CREATE DATABASE {} OWNER {} TEMPLATE template0 ENCODING 'UTF8'")
            .format(sql.Identifier(self.database), sql.Identifier(self.owner_role)))
        self.database_created = True
        # Never mutate the supplied/shared database's PUBLIC ACL. This database
        # was created above solely for this fixture and will be dropped below.
        control.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC, {}")
            .format(sql.Identifier(self.database), sql.Identifier(self.runtime_role)))
        control.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}")
            .format(sql.Identifier(self.database), sql.Identifier(self.runtime_role)))
        control.close()
        metadata_fixture.CONNECTION_PARAMETERS = CONNECTION_PARAMETERS
        self.metadata = metadata_fixture.AuditInitializationPostgresTests("runTest")
        self.metadata.setUp()
        self.signed = self.metadata.signed_fixture()
        expected = self.signed.expectation
        self.enrollment = store.LocalInitializationEnrollment(
            database_identity_digest=expected.database_identity_digest,
            database_generation_digest=expected.database_generation_digest,
            generation_sequence=1, generation_predecessor_digest=None,
            backend_incarnation_digest=admission_fixture.label_digest("fixture-store-incarnation"),
            source_contract_digest=expected.source_contract_digest,
            schema_contract_digest=expected.schema_contract_digest,
            initializer_measurement_digest=expected.initializer_measurement_digest,
            initialization_ancestry_digest=expected.initialization_ancestry_digest,
            trust=self.signed.trust,
        )
        admin = self.connect_admin()
        admin.execute(sql.SQL("CREATE SCHEMA {} AUTHORIZATION {}")
            .format(sql.Identifier(self.schema), sql.Identifier(self.owner_role)))
        admin.execute(sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(sql.Identifier(self.schema)))
        for statement in audit_initialization_store_ddl(self.schema):
            admin.execute(statement)
        for table in (ENROLLMENTS, CANDIDATES):
            admin.execute(sql.SQL("ALTER TABLE {} OWNER TO {}")
                .format(self.object(table), sql.Identifier(self.owner_role)))
        for statement in audit_initialization_store_grants(self.schema, self.runtime_role):
            admin.execute(statement)
        admin.execute(sql.SQL("GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO {}")
            .format(sql.Identifier(self.runtime_role)))
        observed = admin.execute(
            "SELECT database.oid, control.system_identifier::text, runtime.oid, owner.oid "
            "FROM pg_catalog.pg_database AS database "
            "CROSS JOIN pg_catalog.pg_control_system() AS control "
            "JOIN pg_catalog.pg_roles AS runtime ON runtime.rolname=%s "
            "JOIN pg_catalog.pg_roles AS owner ON owner.rolname=%s "
            "WHERE database.datname=pg_catalog.current_database()",
            (self.runtime_role, self.owner_role)).fetchone()
        self.assertIsNotNone(observed)
        self.store_identity = access.InitializationStoreDatabaseIdentity(
            namespace=self.schema, database_name=self.database, database_oid=observed[0],
            system_identifier=observed[1], runtime_role=self.runtime_role, runtime_role_oid=observed[2],
            owner_role=self.owner_role, owner_role_oid=observed[3],
            backend_incarnation_digest=self.enrollment.backend_incarnation_digest)
        # Deliberate owner provisioning for this isolated component. The tested
        # recorder must never manufacture this row when it is absent.
        admin.execute(sql.SQL(
            "INSERT INTO {} (database_identity_digest,enrollment_digest,enrollment_bytes,head_sequence,head_digest) "
            "VALUES (%s,%s,%s,0,%s)"
        ).format(self.object(ENROLLMENTS)), (expected.database_identity_digest,
            self.enrollment.digest, self.enrollment.canonical_bytes, self.enrollment.digest))
        admin.commit()
        admin.close()
        self.connection = self.connect()

    def connect(self, *, autocommit=False):
        parameters = {**CONNECTION_PARAMETERS, "dbname": self.database, "user": self.runtime_role}
        connection = psycopg.connect(**parameters, autocommit=autocommit)
        self.connections.append(connection)
        return connection

    def connect_admin(self, *, control=False, autocommit=False):
        parameters = dict(CONNECTION_PARAMETERS)
        if not control:
            parameters["dbname"] = self.database
        connection = psycopg.connect(**parameters, autocommit=autocommit)
        self.connections.append(connection)
        return connection

    def object(self, name):
        return sql.Identifier(self.schema, name)

    def renew_failed_store(self):
        # Every error after entry poisons this handle by closing it. A fresh
        # connection observes the retained outcome; no reset/reinsert fallback.
        self.assertTrue(self.connection.closed)
        self.connection = self.connect()

    def expected_enrollment(self):
        expected, trust = self.signed.expectation, self.signed.trust

        def pin(role):
            fixture_pin = self.signed.signing.pins[role]
            return {"role": role,
                "publicKeyDerHex": admission_fixture.spki(self.signed.signing.keys[role]).hex(),
                "authorityIdentityDigest": fixture_pin.authority_identity_digest,
                "measurementDigest": fixture_pin.measurement_digest,
                "attestationReceiptDigest": fixture_pin.attestation_receipt_digest}

        return {"schema": ENROLLMENT_SCHEMA,
            "databaseIdentityDigest": expected.database_identity_digest,
            "databaseGenerationDigest": expected.database_generation_digest,
            "generationSequence": 1, "generationPredecessorDigest": None,
            "backendIncarnationDigest": admission_fixture.label_digest("fixture-store-incarnation"),
            "counterIdentity": IDENTITY, "sourceContractDigest": expected.source_contract_digest,
            "schemaContractDigest": expected.schema_contract_digest,
            "initializerMeasurementDigest": expected.initializer_measurement_digest,
            "initializationAncestryDigest": expected.initialization_ancestry_digest,
            "trust": {"checkpointSigner": pin("checkpoint"), "authorizationSigner": pin("authorization"),
                "policyDigest": trust.policy_digest, "notBeforeEpochNs": trust.not_before_epoch_ns,
                "notAfterEpochNs": trust.not_after_epoch_ns, "maximumLifetimeNs": trust.maximum_lifetime_ns}}

    def expected_candidate(self):
        enrollment_digest = wire_digest(ENROLLMENT_SCHEMA, wire_json(self.expected_enrollment()))
        request = {"schema": REQUEST_SCHEMA, "enrollmentDigest": enrollment_digest,
            "checkpointHex": self.signed.checkpoint.hex(), "authorizationHex": self.signed.authorization.hex()}
        return {"schema": CANDIDATE_SCHEMA, "state": "RECORDED_UNANCHORED",
            "databaseIdentityDigest": self.signed.expectation.database_identity_digest,
            "enrollmentDigest": enrollment_digest,
            "requestDigest": wire_digest(REQUEST_SCHEMA, wire_json(request)),
            "predecessorHeadDigest": enrollment_digest, "localSequence": 1,
            "request": request, "evidence": self.metadata.expected_evidence(self.signed),
            "installationPermitted": False}

    def cleanup_owned_state(self):
        failures = []
        for connection in reversed(self.connections):
            try:
                if not connection.closed:
                    try:
                        connection.rollback()
                    finally:
                        connection.close()
            except Exception as exc:
                failures.append(exc)
        if self.metadata is not None:
            try:
                self.assertTrue(self.metadata.doCleanups(), "metadata rollback or close failed")
            except Exception as exc:
                failures.append(exc)
        if self.database_created or self.roles_created:
            # Never derive a DROP target from database contents, an environment
            # variable or a wildcard. Validate the exact random owned name.
            if (re.fullmatch(r"audit_init_db_[0-9a-f]{32}", self.database) is None
                    or any(re.fullmatch(r"audit_init_(?:run|own)_[0-9a-f]{32}", role) is None
                        for role in self.roles_created)
                    or self.database == CONNECTION_PARAMETERS["dbname"]):
                failures.append(AssertionError("refusing an unowned cleanup database or role"))
            else:
                cleanup = psycopg.connect(**CONNECTION_PARAMETERS, autocommit=True)
                try:
                    if self.database_created:
                        # No FORCE/terminate-backend fallback: a leaked handle
                        # must surface as a cleanup failure, not be concealed.
                        cleanup.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(self.database)))
                    for role in reversed(self.roles_created):
                        cleanup.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
                except Exception as exc:
                    failures.append(exc)
                finally:
                    cleanup.close()
        if failures:
            raise AssertionError("owned fixture cleanup failed") from failures[0]

    def snapshot(self):
        # Owner observation still works when a negative removes runtime SELECT.
        # It never substitutes for the recorder's actual runtime connection.
        observer = self.connect_admin()
        try:
            return {table: observer.execute(sql.SQL("SELECT * FROM {} ORDER BY database_identity_digest")
                .format(self.object(table))).fetchall() for table in (ENROLLMENTS, CANDIDATES)}
        finally:
            observer.rollback()
            observer.close()

    def owner_change(self, statement, parameters=()):
        admin = self.connect_admin()
        try:
            result = admin.execute(statement, parameters)
            count = result.rowcount
            admin.commit()
            return count
        finally:
            if not admin.closed:
                admin.rollback()
                admin.close()

    def record(self, checkpoint=None, authorization=None, *, connection=None, metadata_connection=None, **changes):
        arguments = dict(enrollment=self.enrollment, trust=self.signed.trust,
            expectation=self.signed.expectation, now_epoch_ns=self.signed.now,
            expected_outbox_root=self.metadata.outbox.root, expected_aggregate_root=self.metadata.aggregate.root,
            read_limits=metadata_fixture.read_limits(), store_limits=store_limits(), store_identity=self.store_identity,
            namespace=self.schema, metadata_namespace=self.metadata.store.schema)
        arguments.update(changes)
        return store.record_local_initialization_candidate(
            self.connection if connection is None else connection,
            self.metadata.connection if metadata_connection is None else metadata_connection,
            self.signed.checkpoint if checkpoint is None else checkpoint,
            self.signed.authorization if authorization is None else authorization, **arguments)

    def lookup(self, checkpoint=None, authorization=None, *, connection=None, **changes):
        arguments = dict(enrollment=self.enrollment, store_limits=store_limits(),
            store_identity=self.store_identity, namespace=self.schema)
        arguments.update(changes)
        return store.lookup_exact_local_initialization_candidate(
            self.connection if connection is None else connection,
            self.signed.checkpoint if checkpoint is None else checkpoint,
            self.signed.authorization if authorization is None else authorization, **arguments)

    def deny_catalog_change(self, change, restore, *, expected_error=None):
        """Committed owner drift, actual runtime denial, exact owner repair."""
        before = self.snapshot()
        self.owner_change(change)
        try:
            for action in (self.lookup, self.record):
                with self.subTest(action=action.__name__), self.assertRaises(access.InitializationStoreAdmissionError) as raised:
                    action()
                if expected_error is not None:
                    self.assertEqual(str(raised.exception), expected_error)
                self.assertEqual(self.snapshot(), before)
                self.renew_failed_store()
        finally:
            for statement in restore if type(restore) is tuple else (restore,):
                self.owner_change(statement)
        self.assertIsNone(self.lookup())

    def constraint_name(self, table, kind, keys):
        """Resolve only a constraint on this exact fixture-owned table."""
        admin = self.connect_admin()
        try:
            rows = admin.execute(
                "SELECT constraint_record.conname FROM pg_catalog.pg_constraint AS constraint_record "
                "JOIN pg_catalog.pg_class AS relation ON relation.oid=constraint_record.conrelid "
                "JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace "
                "WHERE namespace.nspname=%s AND relation.relname=%s "
                "AND constraint_record.contype=%s AND constraint_record.conkey=%s::pg_catalog.int2[] LIMIT 2",
                (self.schema, table, kind, keys)).fetchall()
            self.assertEqual(len(rows), 1)
            self.assertIs(type(rows[0][0]), str)
            return sql.Identifier(rows[0][0])
        finally:
            admin.rollback()
            admin.close()

    def test_runtime_login_and_exact_owner_grants_are_real_catalog_state(self):
        observed = self.connection.execute(
            "SELECT current_user, session_user, pg_catalog.current_database(), "
            "pg_catalog.has_database_privilege(current_user,pg_catalog.current_database(),'CONNECT'), "
            "pg_catalog.has_database_privilege(current_user,pg_catalog.current_database(),'CREATE,TEMP'), "
            "control.system_identifier::text FROM pg_catalog.pg_control_system() AS control"
        ).fetchone()
        self.assertEqual(observed, (self.runtime_role, self.runtime_role, self.database,
            True, False, self.store_identity.system_identifier))
        self.connection.rollback()
        admin = self.connect_admin()
        try:
            owners = admin.execute(
                "SELECT relation.relname,role.rolname FROM pg_catalog.pg_class AS relation "
                "JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace "
                "JOIN pg_catalog.pg_roles AS role ON role.oid=relation.relowner "
                "WHERE namespace.nspname=%s AND relation.relkind='r' ORDER BY relation.relname",
                (self.schema,)).fetchall()
            self.assertEqual(owners, [(CANDIDATES, self.owner_role), (ENROLLMENTS, self.owner_role)])
        finally:
            admin.rollback()
            admin.close()
        self.assertIsNone(self.lookup())
        result = self.record()
        self.assertEqual(self.lookup().canonical_bytes, result.canonical_bytes)

    def test_database_role_and_system_identifier_pins_are_checked_on_both_paths(self):
        before = self.snapshot()
        wrong_role_oid = next(value for value in (2**32 - 1, 2**32 - 2, 2**32 - 3)
            if value not in (self.store_identity.runtime_role_oid, self.store_identity.owner_role_oid))
        changes = (
            {"database_name": "wrong_" + uuid.uuid4().hex},
            {"database_oid": 1 if self.store_identity.database_oid != 1 else 2},
            {"system_identifier": "1" if self.store_identity.system_identifier != "1" else "2"},
            {"runtime_role_oid": wrong_role_oid},
            {"owner_role_oid": wrong_role_oid},
        )
        for change in changes:
            identity = replace(self.store_identity, **change)
            for action in (self.lookup, self.record):
                with self.subTest(change=change, action=action.__name__), self.assertRaises(
                        access.InitializationStoreAdmissionError):
                    action(store_identity=identity)
                self.assertEqual(self.snapshot(), before)
                self.renew_failed_store()
        # These cross-input bindings are rejected before entering a store TX.
        for change in ({"namespace": "wrong_" + uuid.uuid4().hex},
                       {"backend_incarnation_digest": WRONG_DIGEST}):
            for action in (self.lookup, self.record):
                with self.subTest(change=change, action=action.__name__), self.assertRaises(
                        store.LocalInitializationStoreError):
                    action(store_identity=replace(self.store_identity, **change))
                self.assertFalse(self.connection.closed)
                self.assertEqual(self.connection.info.transaction_status, TransactionStatus.IDLE)
        self.assertEqual(self.snapshot(), before)

    def test_effective_database_schema_table_column_and_grant_option_drift_denies(self):
        runtime, database, namespace = map(sql.Identifier, (self.runtime_role, self.database, self.schema))
        changes = (
            (sql.SQL("GRANT TEMP ON DATABASE {} TO PUBLIC").format(database),
             sql.SQL("REVOKE TEMP ON DATABASE {} FROM PUBLIC").format(database)),
            (sql.SQL("GRANT CREATE ON DATABASE {} TO {}").format(database, runtime),
             sql.SQL("REVOKE CREATE ON DATABASE {} FROM {}").format(database, runtime)),
            (sql.SQL("GRANT CREATE ON SCHEMA {} TO {}").format(namespace, runtime),
             sql.SQL("REVOKE CREATE ON SCHEMA {} FROM {}").format(namespace, runtime)),
            (sql.SQL("GRANT DELETE ON {} TO {}").format(self.object(CANDIDATES), runtime),
             sql.SQL("REVOKE DELETE ON {} FROM {}").format(self.object(CANDIDATES), runtime)),
            (sql.SQL("GRANT UPDATE(enrollment_bytes) ON {} TO {}").format(self.object(ENROLLMENTS), runtime),
             sql.SQL("REVOKE UPDATE(enrollment_bytes) ON {} FROM {}").format(self.object(ENROLLMENTS), runtime)),
            (sql.SQL("GRANT SELECT ON {} TO {} WITH GRANT OPTION").format(self.object(CANDIDATES), runtime),
             sql.SQL("REVOKE GRANT OPTION FOR SELECT ON {} FROM {}").format(self.object(CANDIDATES), runtime)),
        )
        for index, (change, restore) in enumerate(changes):
            with self.subTest(index=index):
                self.deny_catalog_change(change, restore)

    def test_public_and_redundant_column_reads_fail_raw_acl_closure_only(self):
        relation, runtime = self.object(CANDIDATES), sql.Identifier(self.runtime_role)
        changes = (
            (sql.SQL("GRANT SELECT ON {} TO PUBLIC").format(relation),
             sql.SQL("REVOKE SELECT ON {} FROM PUBLIC").format(relation)),
            (sql.SQL("GRANT SELECT(enrollment_digest) ON {} TO {}").format(relation, runtime),
             sql.SQL("REVOKE SELECT(enrollment_digest) ON {} FROM {}").format(relation, runtime)),
        )
        # Runtime already has full-table SELECT. Neither added read changes its
        # effective privileges, but each adds one forbidden raw entry (23 vs
        # the exact 22). Keep the original runtime table grant on restoration.
        for index, (change, restore) in enumerate(changes):
            with self.subTest(index=index):
                self.deny_catalog_change(change, restore,
                    expected_error="initialization store raw ACL count differs")

    def test_owner_and_runtime_flags_and_membership_both_directions_deny(self):
        runtime, owner = map(sql.Identifier, (self.runtime_role, self.owner_role))
        changes = (
            (sql.SQL("ALTER ROLE {} CREATEDB").format(runtime),
             sql.SQL("ALTER ROLE {} NOCREATEDB").format(runtime)),
            (sql.SQL("ALTER ROLE {} LOGIN").format(owner),
             sql.SQL("ALTER ROLE {} NOLOGIN").format(owner)),
            (sql.SQL("GRANT {} TO {}").format(owner, runtime),
             sql.SQL("REVOKE {} FROM {}").format(owner, runtime)),
            (sql.SQL("GRANT {} TO {}").format(runtime, owner),
             sql.SQL("REVOKE {} FROM {}").format(runtime, owner)),
        )
        for index, (change, restore) in enumerate(changes):
            with self.subTest(index=index):
                self.deny_catalog_change(change, restore)

    def test_extra_index_rls_and_relation_owner_drift_are_not_silent_repairs(self):
        extra = self.object("fixture_extra_index")
        changes = (
            (sql.SQL("CREATE INDEX {} ON {} (enrollment_digest)")
                .format(sql.Identifier("fixture_extra_index"), self.object(ENROLLMENTS)),
             sql.SQL("DROP INDEX {}").format(extra)),
            (sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(self.object(CANDIDATES)),
             sql.SQL("ALTER TABLE {} DISABLE ROW LEVEL SECURITY").format(self.object(CANDIDATES))),
            (sql.SQL("ALTER TABLE {} OWNER TO {}").format(self.object(CANDIDATES), sql.Identifier(self.runtime_role)),
             (sql.SQL("ALTER TABLE {} OWNER TO {}").format(self.object(CANDIDATES), sql.Identifier(self.owner_role)),
              *audit_initialization_store_grants(self.schema, self.runtime_role))),
        )
        for index, (change, restore) in enumerate(changes):
            with self.subTest(index=index):
                self.deny_catalog_change(change, restore)

    def test_external_composite_typed_table_cannot_substitute_for_source_relation(self):
        # PG16 ALTER TABLE OF requires exactly matching column names/types and
        # no inherited parent; existing source constraints may remain intact.
        # https://www.postgresql.org/docs/16/sql-altertable.html
        external_schema = "audit_init_type_" + uuid.uuid4().hex
        namespace = sql.Identifier(external_schema)
        composite = sql.Identifier(external_schema, "enrollment_shape")
        self.owner_change(sql.SQL("CREATE SCHEMA {} AUTHORIZATION {}")
            .format(namespace, sql.Identifier(self.owner_role)))
        type_created = False
        try:
            # Keep the extra composite outside the admitted store namespace so
            # this reaches the relation's reloftype guard, not extra-type count.
            self.owner_change(sql.SQL(
                "CREATE TYPE {} AS (database_identity_digest pg_catalog.text, "
                "enrollment_digest pg_catalog.text, enrollment_bytes pg_catalog.bytea, "
                "head_sequence pg_catalog.int8, head_digest pg_catalog.text)"
            ).format(composite))
            type_created = True
            self.owner_change(sql.SQL("ALTER TYPE {} OWNER TO {}")
                .format(composite, sql.Identifier(self.owner_role)))
            self.deny_catalog_change(
                sql.SQL("ALTER TABLE {} OF {}").format(self.object(ENROLLMENTS), composite),
                sql.SQL("ALTER TABLE {} NOT OF").format(self.object(ENROLLMENTS)),
                expected_error="initialization store structure differs: relation owner, persistence or type")
        finally:
            # No CASCADE or catalog surgery: dependent/unexpected state must
            # surface. Whole-fixture cleanup still owns this exact database.
            if type_created:
                self.owner_change(sql.SQL("DROP TYPE {}").format(composite))
            self.owner_change(sql.SQL("DROP SCHEMA {}").format(namespace))
        self.assertIsNone(self.lookup())

    def test_superuser_connection_and_missing_required_runtime_select_cannot_bypass_admission(self):
        before = self.snapshot()
        admin = self.connect_admin()
        with self.assertRaises(access.InitializationStoreAdmissionError):
            self.lookup(connection=admin)
        self.assertTrue(admin.closed)
        self.assertEqual(self.snapshot(), before)
        runtime = sql.Identifier(self.runtime_role)
        self.owner_change(sql.SQL("REVOKE SELECT ON {} FROM {}").format(self.object(ENROLLMENTS), runtime))
        try:
            # The initial ACCESS SHARE relation lock itself needs SELECT. This
            # is a genuine SQL permission failure, not a catalog-denial row.
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.record()
            self.renew_failed_store()
            self.assertEqual(self.snapshot(), before)
        finally:
            self.owner_change(sql.SQL("GRANT SELECT ON {} TO {}").format(self.object(ENROLLMENTS), runtime))
        self.assertIsNone(self.lookup())

    def test_source_check_expression_missing_and_unvalidated_constraint_drift_denies(self):
        relation = self.object(ENROLLMENTS)
        name = self.constraint_name(ENROLLMENTS, "c", [4])
        exact = sql.SQL("ADD CONSTRAINT {} CHECK (head_sequence = 0 OR head_sequence = 1)").format(name)
        cases = (
            (sql.SQL("ALTER TABLE {} DROP CONSTRAINT {}, ADD CONSTRAINT {} "
                     "CHECK (head_sequence = 0 OR head_sequence = 2)").format(relation, name, name),
             sql.SQL("ALTER TABLE {} DROP CONSTRAINT {}, {}").format(relation, name, exact),
             "source CHECK definition"),
            (sql.SQL("ALTER TABLE {} DROP CONSTRAINT {}").format(relation, name),
             sql.SQL("ALTER TABLE {} {}").format(relation, exact), "table shape"),
            (sql.SQL("ALTER TABLE {} DROP CONSTRAINT {}, {} NOT VALID").format(relation, name, exact),
             sql.SQL("ALTER TABLE {} VALIDATE CONSTRAINT {}").format(relation, name), "catalog flags"),
        )
        for index, (change, restore, detail) in enumerate(cases):
            with self.subTest(index=index):
                self.deny_catalog_change(change, restore,
                    expected_error="initialization store structure differs: " + detail)

    def test_disabled_internal_foreign_key_triggers_deny_before_record_or_lookup(self):
        # ALTER TABLE reaches real PostgreSQL internal FK triggers. There is
        # no pg_catalog UPDATE, test-only trigger exemption or fake verifier.
        for table in (ENROLLMENTS, CANDIDATES):
            with self.subTest(table=table):
                self.deny_catalog_change(
                    sql.SQL("ALTER TABLE {} DISABLE TRIGGER ALL").format(self.object(table)),
                    sql.SQL("ALTER TABLE {} ENABLE TRIGGER ALL").format(self.object(table)),
                    expected_error="initialization store structure differs: FK trigger identity")

    def test_replaced_foreign_key_internal_delete_action_is_not_source_equivalent(self):
        relation, parent = self.object(CANDIDATES), self.object(ENROLLMENTS)
        name = self.constraint_name(CANDIDATES, "f", [1, 2])
        replacement = sql.SQL(
            "ALTER TABLE {} DROP CONSTRAINT {}, ADD CONSTRAINT {} "
            "FOREIGN KEY (database_identity_digest,enrollment_digest) "
            "REFERENCES {} (database_identity_digest,enrollment_digest) {}"
        )
        # PostgreSQL recreates the actual internal FK triggers, including a
        # cascading-delete trigger. The earlier FK-contract guard rejects this
        # before the trigger-identity guard; do not claim the latter was reached.
        self.deny_catalog_change(
            replacement.format(relation, name, name, parent, sql.SQL("ON DELETE CASCADE")),
            replacement.format(relation, name, name, parent, sql.SQL("ON DELETE NO ACTION")),
            expected_error="initialization store structure differs: foreign-key contract")

    def test_existing_unused_enrollment_lookup_returns_none_without_manufacturing_candidate(self):
        before = self.snapshot()
        self.assertEqual(len(before[ENROLLMENTS]), 1)
        self.assertEqual(before[CANDIDATES], [])
        self.assertIsNone(self.lookup())
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.connection.info.transaction_status, TransactionStatus.IDLE)

    def test_real_record_commit_reopen_returns_exact_original_candidate_bytes(self):
        metadata_before = self.metadata.store.snapshot()
        expected_enrollment, expected = self.expected_enrollment(), self.expected_candidate()
        self.assertEqual(self.enrollment.canonical_bytes, wire_json(expected_enrollment))
        self.assertEqual(self.enrollment.digest, wire_digest(ENROLLMENT_SCHEMA, wire_json(expected_enrollment)))
        result = self.record()
        self.assertIs(type(result), store.StoredInitializationCandidate)
        self.assertEqual(result.json_projection(), expected)
        self.assertEqual(result.canonical_bytes, wire_json(expected))
        self.assertEqual(result.digest, wire_digest(CANDIDATE_SCHEMA, wire_json(expected)))
        self.assertIs(result.json_projection()["installationPermitted"], False)
        changed = result.json_projection()
        changed["evidence"].clear()
        self.assertEqual(result.canonical_bytes, wire_json(expected))
        self.assertEqual(self.connection.info.transaction_status, TransactionStatus.IDLE)
        persisted = self.snapshot()
        self.assertEqual(len(persisted[ENROLLMENTS]), 1)
        self.assertEqual(len(persisted[CANDIDATES]), 1)
        enrollment, candidate = persisted[ENROLLMENTS][0], persisted[CANDIDATES][0]
        self.assertEqual(enrollment[:3], (self.enrollment.database_identity_digest,
            self.enrollment.digest, self.enrollment.canonical_bytes))
        self.assertEqual(enrollment[3:], (1, result.digest))
        self.assertEqual(candidate[:2], (self.enrollment.database_identity_digest, self.enrollment.digest))
        self.assertEqual(candidate[2], expected["requestDigest"])
        self.assertEqual(candidate[3:], (result.digest, result.canonical_bytes))
        self.connection.close()
        reopened = self.connect()
        looked_up = self.lookup(connection=reopened)
        self.assertIs(type(looked_up), store.StoredInitializationCandidate)
        self.assertEqual(looked_up.canonical_bytes, result.canonical_bytes)
        self.assertEqual(looked_up.digest, result.digest)
        self.assertEqual(reopened.info.transaction_status, TransactionStatus.IDLE)
        self.assertEqual(self.metadata.store.snapshot(), metadata_before)
        self.assertEqual(self.metadata.connection.info.transaction_status, TransactionStatus.INTRANS)
        self.assertEqual(self.metadata.store.table_rows(AGGREGATE), [])

    def test_exact_record_replay_retains_original_bytes_after_metadata_evolution(self):
        self.metadata.seed(self.metadata.mixed(), [metadata_fixture.other_aggregate("store-replay-雪")])
        self.signed = self.metadata.signed_fixture()
        expected = self.expected_candidate()
        original = self.record()
        self.assertEqual(original.json_projection(), expected)
        self.assertEqual(original.digest, wire_digest(CANDIDATE_SCHEMA, wire_json(expected)))
        before = self.snapshot()
        metadata_txid = self.metadata.connection.execute("SELECT pg_catalog.txid_current()::text").fetchone()[0]
        # Mutate the real metadata tree after the first record. Retain the old
        # signed expectations deliberately: recomputing them now would fail.
        self.metadata.store.insert(OUTBOX, outbox_row("real-post-record-evolution"))
        current_root = self.metadata.store.stored_root(OUTBOX)
        self.assertNotEqual(current_root, self.metadata.outbox.root)
        repeated = self.record()
        self.assertEqual(repeated.canonical_bytes, original.canonical_bytes)
        self.assertEqual(repeated.digest, original.digest)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.metadata.store.stored_root(OUTBOX), current_root)
        self.assertEqual(self.metadata.connection.execute("SELECT pg_catalog.txid_current()::text").fetchone()[0], metadata_txid)
        self.assertEqual(self.metadata.connection.info.transaction_status, TransactionStatus.INTRANS)
        self.assertEqual(self.connection.info.transaction_status, TransactionStatus.IDLE)

    def test_expired_request_cannot_record_but_exact_lookup_retains_original_record(self):
        original, before = self.record(), self.snapshot()
        with self.assertRaises(admission.AuditInitializationAdmissionError):
            self.record(now_epoch_ns=100_000_000_000)
        self.assertEqual(self.connection.info.transaction_status, TransactionStatus.IDLE)
        self.assertEqual(self.snapshot(), before)
        looked_up = self.lookup(connection=self.connect())
        self.assertEqual(looked_up.canonical_bytes, original.canonical_bytes)
        self.assertEqual(looked_up.digest, original.digest)

    def test_exact_historical_lookup_does_not_relabel_retained_source_revision(self):
        original, before = self.record(), self.snapshot()
        original_revision = authority_contract.SOURCE_REVISION
        reopened = self.connect()
        # One deterministic compatibility substitution, not a new-release,
        # migration or registry simulation. Real signatures, SQL and retained
        # archival validation execute unchanged; only the current label differs.
        with patch.object(authority_contract, "SOURCE_REVISION", original_revision + ".fixture-next"):
            looked_up = self.lookup(connection=reopened)
            self.assertEqual(looked_up.canonical_bytes, original.canonical_bytes)
            self.assertEqual(looked_up.digest, original.digest)
            retained = looked_up.json_projection()["evidence"]
            self.assertEqual(retained["preparation"]["sourceRevision"], original_revision)
            self.assertEqual(retained["checkpoint"]["payload"]["sourceRevision"], original_revision)
            self.assertEqual(retained["authorization"]["payload"]["sourceRevision"], original_revision)
            self.assertEqual(retained["verifiedAtEpochNs"], self.signed.now)
        self.assertEqual(authority_contract.SOURCE_REVISION, original_revision)
        self.assertEqual(reopened.info.transaction_status, TransactionStatus.IDLE)
        self.assertEqual(self.snapshot(), before)

    def test_authentic_different_request_conflicts_without_replacing_committed_record(self):
        original = self.record()
        before = self.snapshot()
        checkpoint_payload = {**self.signed.checkpoint_payload, "issuedAtEpochNs": 11_000_000_000}
        pair = self.signed.signed_pair(checkpoint_payload=checkpoint_payload)
        self.assertIsNone(admission.validate_audit_initialization_intent(
            *pair, trust=self.signed.trust, expectation=self.signed.expectation,
            now_epoch_ns=self.signed.now, outbox_root=self.metadata.outbox.root,
            aggregate_root=self.metadata.aggregate.root))
        with self.assertRaises(store.LocalInitializationConflict):
            self.record(*pair)
        self.renew_failed_store()
        with self.assertRaises(store.LocalInitializationConflict):
            self.lookup(*pair)
        self.renew_failed_store()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.lookup().canonical_bytes, original.canonical_bytes)
        self.assertEqual(self.connection.info.transaction_status, TransactionStatus.IDLE)

    def test_missing_enrollment_fails_closed_without_automatic_enrollment(self):
        self.assertEqual(self.owner_change(sql.SQL("DELETE FROM {} WHERE database_identity_digest=%s")
            .format(self.object(ENROLLMENTS)), (self.enrollment.database_identity_digest,)), 1)
        for action in (self.lookup, self.record):
            with self.subTest(action=action.__name__), self.assertRaises(store.LocalInitializationStoreError):
                action()
            self.assertEqual(self.snapshot(), {ENROLLMENTS: [], CANDIDATES: []})
            self.renew_failed_store()

    def test_head_claim_without_candidate_is_not_an_unused_enrollment(self):
        self.assertEqual(self.owner_change(sql.SQL(
            "UPDATE {} SET head_sequence=1,head_digest=%s WHERE database_identity_digest=%s"
        ).format(self.object(ENROLLMENTS)), (WRONG_DIGEST, self.enrollment.database_identity_digest)), 1)
        before = self.snapshot()
        for action in (self.lookup, self.record):
            with self.subTest(action=action.__name__), self.assertRaises(store.LocalInitializationStoreError):
                action()
            self.assertEqual(self.snapshot(), before)
            self.renew_failed_store()

    def test_candidate_with_reset_unused_head_cannot_be_returned_or_overwritten(self):
        self.record()
        self.assertEqual(self.owner_change(sql.SQL(
            "UPDATE {} SET head_sequence=0,head_digest=enrollment_digest WHERE database_identity_digest=%s"
        ).format(self.object(ENROLLMENTS)), (self.enrollment.database_identity_digest,)), 1)
        before = self.snapshot()
        for action in (self.lookup, self.record):
            with self.subTest(action=action.__name__), self.assertRaises(store.LocalInitializationStoreError):
                action()
            self.assertEqual(self.snapshot(), before)
            self.renew_failed_store()

    def test_retained_candidate_byte_corruption_is_not_accepted_as_exact_replay(self):
        self.record()
        self.assertEqual(self.owner_change(sql.SQL(
            "UPDATE {} SET candidate_bytes=%s WHERE database_identity_digest=%s"
        ).format(self.object(CANDIDATES)), (b"{}", self.enrollment.database_identity_digest)), 1)
        before = self.snapshot()
        for action in (self.lookup, self.record):
            with self.subTest(action=action.__name__), self.assertRaises(store.LocalInitializationStoreError):
                action()
            self.assertEqual(self.snapshot(), before)
            self.renew_failed_store()

    def test_enrollment_bytes_must_match_exact_configured_generation_and_pins(self):
        before = self.snapshot()
        for changed in (
            replace(self.enrollment, database_generation_digest=WRONG_DIGEST),
            replace(self.enrollment, source_contract_digest=WRONG_DIGEST),
        ):
            with self.subTest(enrollment=changed.digest), self.assertRaises(store.LocalInitializationStoreError):
                self.lookup(enrollment=changed)
            self.assertEqual(self.snapshot(), before)
            self.renew_failed_store()
        with self.assertRaises(store.LocalInitializationStoreError):
            self.lookup(enrollment=replace(self.enrollment, backend_incarnation_digest=WRONG_DIGEST))
        self.assertFalse(self.connection.closed)
        self.assertEqual(self.connection.info.transaction_status, TransactionStatus.IDLE)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.owner_change(sql.SQL(
            "UPDATE {} SET enrollment_bytes=%s WHERE database_identity_digest=%s"
        ).format(self.object(ENROLLMENTS)), (b"{}", self.enrollment.database_identity_digest)), 1)
        corrupt = self.snapshot()
        with self.assertRaises(store.LocalInitializationStoreError):
            self.lookup()
        self.assertEqual(self.snapshot(), corrupt)
        self.renew_failed_store()

    def test_invalid_real_signatures_leave_store_idle_and_rows_unchanged(self):
        before = self.snapshot()
        for role in admission_fixture.ROLES:
            canonical = self.signed.checkpoint if role == "checkpoint" else self.signed.authorization
            other = "authorization" if role == "checkpoint" else "checkpoint"
            invalid = self.signed.signing.sign(role, json.loads(canonical)["payload"],
                key=self.signed.signing.keys[other])
            pair = (invalid, self.signed.authorization) if role == "checkpoint" else (self.signed.checkpoint, invalid)
            with self.subTest(role=role), self.assertRaises(admission.AuditInitializationAdmissionError):
                self.record(*pair)
            self.assertEqual(self.connection.info.transaction_status, TransactionStatus.IDLE)
            self.assertEqual(self.snapshot(), before)

    def test_actual_metadata_corruption_rolls_back_store_and_preserves_caller_transaction(self):
        row = outbox_row("store-rejects-real-corruption")
        self.metadata.seed([row])
        self.signed = self.metadata.signed_fixture()
        before = self.snapshot()
        self.metadata.without_tree_trigger(sql.SQL("UPDATE {} SET status=%s WHERE id=%s")
            .format(self.metadata.store.object(OUTBOX)), ("audited", row["id"]))
        with self.assertRaises(reader.AuditInitializationPostgresError):
            self.record()
        self.assertEqual(self.snapshot(), before)
        self.renew_failed_store()
        self.assertEqual(self.metadata.connection.info.transaction_status, TransactionStatus.INTRANS)
        self.metadata.assert_no_reader_cursor()

    def test_store_connection_requires_idle_non_autocommit_and_separate_metadata_session(self):
        before = self.snapshot()
        active = self.connect()
        active.execute("SELECT 1")
        with self.assertRaises(store.LocalInitializationStoreError):
            self.record(connection=active)
        self.assertEqual(active.info.transaction_status, TransactionStatus.INTRANS)
        active.rollback()
        automatic = self.connect(autocommit=True)
        with self.assertRaises(store.LocalInitializationStoreError):
            self.record(connection=automatic)
        self.assertEqual(automatic.info.transaction_status, TransactionStatus.IDLE)
        shared = self.connect()
        with self.assertRaises(store.LocalInitializationStoreError):
            self.record(connection=shared, metadata_connection=shared)
        self.assertEqual(shared.info.transaction_status, TransactionStatus.IDLE)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.metadata.connection.info.transaction_status, TransactionStatus.INTRANS)

    def test_store_limits_reject_non_integer_unbounded_and_zero_values(self):
        for field in ("statement_timeout_ms", "lock_timeout_ms", "total_timeout_ms"):
            for value in (None, True, 0, -1, 1.0, "1", 2**63):
                with self.subTest(field=field, value=value), self.assertRaises(store.LocalInitializationStoreError):
                    store_limits(**{field: value})
        before = self.snapshot()
        for value in (None, {}, {"statement_timeout_ms": 5000}):
            with self.subTest(value=value), self.assertRaises(store.LocalInitializationStoreError):
                self.record(store_limits=value)
            self.assertEqual(self.connection.info.transaction_status, TransactionStatus.IDLE)
        self.assertEqual(self.snapshot(), before)

    def test_actual_metadata_query_budget_failure_does_not_advance_store_head(self):
        before = self.snapshot()
        with self.assertRaises(reader.AuditInitializationPostgresError) as raised:
            self.record(read_limits=metadata_fixture.read_limits(max_queries=1))
        self.assertEqual(str(raised.exception), "offline preparation exceeded its query limit")
        self.assertEqual(self.snapshot(), before)
        self.renew_failed_store()
        self.assertEqual(self.metadata.connection.info.transaction_status, TransactionStatus.INTRANS)
        self.assertIsNone(self.lookup())

    def test_real_sql_head_failure_rolls_back_candidate_then_allows_exact_retry(self):
        # The historical method name is retained for coverage continuity. An
        # extra trigger now fails structural admission BEFORE candidate INSERT;
        # this no longer exercises post-write rollback or the trigger body.
        self.owner_change(sql.SQL(
            "CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ "
            "BEGIN RAISE EXCEPTION 'fixture rejects initialization head advance'; END; $$"
        ).format(self.object("fixture_reject_head_advance")))
        self.owner_change(sql.SQL(
            "CREATE TRIGGER fixture_reject_head_advance BEFORE UPDATE ON {} "
            "FOR EACH ROW EXECUTE FUNCTION {}()"
        ).format(self.object(ENROLLMENTS), self.object("fixture_reject_head_advance")))
        before = self.snapshot()
        with self.assertRaises(access.InitializationStoreAdmissionError) as raised:
            self.record()
        self.assertEqual(str(raised.exception), "initialization store structure differs: trigger inventory")
        self.assertEqual(self.snapshot(), before)
        self.renew_failed_store()
        self.assertEqual(self.metadata.connection.info.transaction_status, TransactionStatus.INTRANS)
        self.owner_change(sql.SQL("DROP TRIGGER fixture_reject_head_advance ON {}")
            .format(self.object(ENROLLMENTS)))
        self.owner_change(sql.SQL("DROP FUNCTION {}()").format(self.object("fixture_reject_head_advance")))
        self.assertIsNone(self.lookup())
        result = self.record()
        self.assertEqual(self.lookup().canonical_bytes, result.canonical_bytes)

    def test_actual_enrollment_lock_timeout_closes_handle_without_partial_record(self):
        before = self.snapshot()
        holder = self.connect()
        try:
            self.assertEqual(holder.execute(sql.SQL(
                "SELECT head_sequence FROM {} WHERE database_identity_digest=%s FOR UPDATE"
            ).format(self.object(ENROLLMENTS)), (self.enrollment.database_identity_digest,)).fetchone(), (0,))
            with self.assertRaises(psycopg.errors.LockNotAvailable) as raised:
                self.record(store_limits=store_limits(lock_timeout_ms=25))
            self.assertEqual(raised.exception.sqlstate, "55P03")
            self.assertTrue(self.connection.closed)
        finally:
            holder.rollback()
            holder.close()
        self.renew_failed_store()
        self.assertEqual(self.snapshot(), before)
        self.assertIsNone(self.lookup())
        # No retry ran inside the failing operation. A later explicit caller
        # attempt on a new handle uses the now-unlocked real enrollment.
        result = self.record()
        self.assertEqual(result.canonical_bytes, wire_json(self.expected_candidate()))


class LocalInitializationRepresentationTests(unittest.TestCase):
    """Pure representation controls; no DB setup, evidence or authority token."""

    def setUp(self):
        self.signing = admission_fixture.SigningFixture()
        self.trust = admission.AuditInitializationTrust(
            self.signing.pins["checkpoint"], self.signing.pins["authorization"],
            admission_fixture.label_digest("representation-policy"), 0, 200_000_000_000, 120_000_000_000)

    def enrollment(self, **changes):
        arguments = dict(database_identity_digest=admission_fixture.label_digest("representation-database"),
            database_generation_digest=admission_fixture.label_digest("representation-generation"),
            generation_sequence=1, generation_predecessor_digest=None,
            backend_incarnation_digest=admission_fixture.label_digest("representation-backend"),
            source_contract_digest=admission_fixture.label_digest("representation-source"),
            schema_contract_digest=admission_fixture.label_digest("representation-schema"),
            initializer_measurement_digest=admission_fixture.label_digest("representation-measurement"),
            initialization_ancestry_digest=admission_fixture.label_digest("representation-ancestry"), trust=self.trust)
        arguments.update(changes)
        return store.LocalInitializationEnrollment(**arguments)

    def identity(self, **changes):
        values = dict(namespace="fixture_store", database_name="fixture_database", database_oid=11,
            system_identifier="123456789", runtime_role="fixture_runtime", runtime_role_oid=12,
            owner_role="fixture_owner", owner_role_oid=13,
            backend_incarnation_digest=admission_fixture.label_digest("representation-backend"))
        values.update(changes)
        return access.InitializationStoreDatabaseIdentity(**values)

    def document(self):
        # Deliberately no signatures or proof stream: the data constructor may
        # accept this closed representation, but no recorder accepts it as input.
        return {"schema": CANDIDATE_SCHEMA, "state": "RECORDED_UNANCHORED",
            "databaseIdentityDigest": admission_fixture.label_digest("representation-database"),
            "enrollmentDigest": WRONG_DIGEST, "requestDigest": WRONG_DIGEST,
            "predecessorHeadDigest": WRONG_DIGEST, "localSequence": 1,
            "request": {}, "evidence": {}, "installationPermitted": False}

    def test_lossy_or_forbidden_json_and_raw_bounds_raise_public_store_error(self):
        baseline = self.document()
        for value in (1.0, 1.5, "\x00", "\ud800"):
            document = {**baseline, "evidence": {"componentValue": value}}
            with self.subTest(value=repr(value)), self.assertRaises(store.LocalInitializationStoreError) as raised:
                store.StoredInitializationCandidate(wire_json(document))
            self.assertIs(type(raised.exception), store.LocalInitializationStoreError)
        raw = wire_json(baseline)
        for value in (None, "{}", bytearray(raw), b"", b"x" * (4 * 1024 * 1024 + 1),
                      raw + b"\n", b"{}", b'{"schema":"duplicate",' + raw[1:]):
            with self.subTest(kind=type(value).__name__), self.assertRaises(store.LocalInitializationStoreError) as raised:
                store.StoredInitializationCandidate(value)
            self.assertIs(type(raised.exception), store.LocalInitializationStoreError)

    def test_local_candidate_state_is_closed_frozen_and_never_installation_permission(self):
        document = self.document()
        value = store.StoredInitializationCandidate(wire_json(document))
        self.assertEqual(value.digest, wire_digest(CANDIDATE_SCHEMA, wire_json(document)))
        self.assertIs(value.json_projection()["installationPermitted"], False)
        changed = value.json_projection()
        changed["state"] = "APPLIED"
        self.assertEqual(value.json_projection(), document)
        with self.assertRaises(FrozenInstanceError):
            value.canonical_bytes = b"{}"
        for field, changed_value in (("state", "COMMIT_DECIDED"), ("state", "APPLIED"), ("state", False),
                ("installationPermitted", True), ("installationPermitted", 0), ("installationPermitted", None),
                ("localSequence", True), ("localSequence", 0), ("localSequence", 2),
                ("predecessorHeadDigest", admission_fixture.label_digest("crossed-predecessor"))):
            with self.subTest(field=field, value=changed_value), self.assertRaises(store.LocalInitializationStoreError):
                store.StoredInitializationCandidate(wire_json({**document, field: changed_value}))

    def test_enrollment_owns_frozen_copies_of_original_trust_and_both_pins(self):
        enrollment = self.enrollment()
        original = enrollment.canonical_bytes
        self.assertIsNot(enrollment.trust, self.trust)
        self.assertIsNot(enrollment.trust.checkpoint_signer, self.trust.checkpoint_signer)
        self.assertIsNot(enrollment.trust.authorization_signer, self.trust.authorization_signer)
        object.__setattr__(self.trust, "policy_digest", WRONG_DIGEST)
        object.__setattr__(self.trust.checkpoint_signer, "measurement_digest", WRONG_DIGEST)
        object.__setattr__(self.trust.authorization_signer, "attestation_receipt_digest", WRONG_DIGEST)
        self.assertEqual(enrollment.canonical_bytes, original)
        self.assertEqual(enrollment.digest, wire_digest(ENROLLMENT_SCHEMA, original))
        projection = enrollment.json_projection()
        projection["trust"]["checkpointSigner"].clear()
        self.assertEqual(enrollment.canonical_bytes, original)
        with self.assertRaises(FrozenInstanceError):
            enrollment.generation_sequence = 2

    def test_constructor_bypassed_incomplete_or_mutable_pins_are_revalidated(self):
        pin = self.trust.checkpoint_signer
        malformed = [object.__new__(type(pin)),
            admission_fixture.bypassed_dataclass(pin, public_key_der=bytearray(pin.public_key_der)),
            admission_fixture.bypassed_dataclass(pin, measurement_digest=False),
            admission_fixture.bypassed_dataclass(pin, role="authorization")]
        for candidate in malformed:
            forged_trust = admission_fixture.bypassed_dataclass(self.trust, checkpoint_signer=candidate)
            with self.subTest(pin=type(candidate).__name__), self.assertRaises(store.LocalInitializationStoreError) as raised:
                self.enrollment(trust=forged_trust)
            self.assertIs(type(raised.exception), store.LocalInitializationStoreError)
        for value in (True, 0, -1, 1.0, "1"):
            with self.subTest(sequence=value), self.assertRaises(store.LocalInitializationStoreError):
                self.enrollment(generation_sequence=value)

    def test_database_identity_requires_exact_bounded_types_and_separate_roles(self):
        for field in ("namespace", "runtime_role", "owner_role"):
            for value in (None, True, b"fixture", "", "Upper", "x" * 64, "a\x00", "a.quoted", "雪"):
                with self.subTest(field=field, value=repr(value)), self.assertRaises(access.InitializationStoreAdmissionError):
                    self.identity(**{field: value})
        for field in ("database_oid", "runtime_role_oid", "owner_role_oid"):
            for value in (None, True, 0, -1, 1.0, "1", 2**32):
                with self.subTest(field=field, value=value), self.assertRaises(access.InitializationStoreAdmissionError):
                    self.identity(**{field: value})
        for value in (None, 1, True, "", "01", "-1", "1.0", str(2**64), "1" * 21):
            with self.subTest(system_identifier=value), self.assertRaises(access.InitializationStoreAdmissionError):
                self.identity(system_identifier=value)
        for value in (None, True, b"name", "", "a\x00", "\ud800", "雪" * 22):
            with self.subTest(database_name=repr(value)), self.assertRaises(access.InitializationStoreAdmissionError):
                self.identity(database_name=value)
        for value in (None, True, "sha256:" + "A" * 64, bytearray(WRONG_DIGEST.encode("ascii"))):
            with self.subTest(incarnation=repr(value)), self.assertRaises(access.InitializationStoreAdmissionError):
                self.identity(backend_incarnation_digest=value)
        for change in ({"owner_role": "fixture_runtime"}, {"owner_role_oid": 12}):
            with self.subTest(change=change), self.assertRaises(access.InitializationStoreAdmissionError):
                self.identity(**change)
        # These are bounded expectation primitives, not observed DB authority.
        self.assertEqual(self.identity(database_name="雪" * 21).database_name, "雪" * 21)
        self.assertEqual(self.identity(system_identifier=str(2**64 - 1)).system_identifier, str(2**64 - 1))

    def test_database_identity_copy_owns_inputs_and_public_lookup_revalidates_bypassed_contexts(self):
        original = self.identity()
        copied = store._copy(access.InitializationStoreDatabaseIdentity, original)
        self.assertIsNot(copied, original)
        self.assertEqual(copied, original)
        with self.assertRaises(FrozenInstanceError):
            copied.database_oid = 99
        object.__setattr__(original, "database_oid", 99)
        object.__setattr__(original, "backend_incarnation_digest", WRONG_DIGEST)
        self.assertEqual(copied, self.identity())
        wrong_type = "local initialization input has the wrong type"
        wrong_fields = "local initialization input is incomplete or invalid"
        malformed = ((None, wrong_type), ({}, wrong_type),
            (object.__new__(access.InitializationStoreDatabaseIdentity), wrong_fields),
            (admission_fixture.bypassed_dataclass(copied, database_oid=True), wrong_fields),
            (admission_fixture.bypassed_dataclass(copied, system_identifier=bytearray(b"123")), wrong_fields),
            (admission_fixture.bypassed_dataclass(copied, owner_role_oid=copied.runtime_role_oid), wrong_fields))
        for identity, diagnostic in malformed:
            # No DB stand-in: malformed context must fail before the real
            # public lookup could inspect its deliberately absent connection.
            with self.subTest(identity=type(identity).__name__), self.assertRaises(store.LocalInitializationStoreError) as raised:
                store.lookup_exact_local_initialization_candidate(None, b"", b"",
                    enrollment=self.enrollment(), store_limits=store_limits(),
                    store_identity=identity, namespace="fixture_store")
            self.assertIs(type(raised.exception), store.LocalInitializationStoreError)
            self.assertEqual(str(raised.exception), diagnostic)


class AuditInitializationStoreSourceTests(unittest.TestCase):
    def test_source_preflight_owned_transaction_commit_and_fixed_consumers_are_bound(self):
        """Supplemental source order, not crash/acknowledgment-loss execution."""
        path = ROOT / "serverware/authority_audit_initialization_store.py"
        self.assertLessEqual(path.stat().st_size, 64 * 1024)
        parsed = ast.parse(path.read_text(encoding="utf-8"))
        functions = {node.name: node for node in parsed.body if isinstance(node, ast.FunctionDef)}

        def calls(node, name):
            return [item for item in ast.walk(node) if isinstance(item, ast.Call)
                    and ast.unparse(item.func) == name]

        public = functions["record_local_initialization_candidate"]
        preflights = calls(public, "admission.validate_audit_initialization_intent")
        operations = calls(public, "_operation")
        self.assertEqual((len(preflights), len(operations)), (1, 1))
        self.assertLess(preflights[0].lineno, operations[0].lineno)
        self.assertEqual([ast.unparse(value) for value in operations[0].args],
                         ["store_connection", "limits", "started", "identity", "record"])
        self.assertFalse(calls(public, "store_connection.execute"))
        self.assertFalse(calls(public, "store_connection.cursor"))
        callbacks = [node for node in public.body if isinstance(node, ast.FunctionDef)]
        self.assertEqual([node.name for node in callbacks], ["record"])
        callback = callbacks[0]
        existing = calls(callback, "_existing")
        verifiers = calls(callback, "reader.verify_audit_initialization_evidence_from_postgres")
        self.assertEqual((len(existing), len(verifiers)), (2, 1))
        retained_return = callback.body[1]
        self.assertIsInstance(retained_return, ast.If)
        self.assertEqual(ast.unparse(retained_return.test), "retained is not None")
        self.assertEqual(ast.unparse(retained_return.body[0]), "return retained")
        self.assertLess(existing[0].lineno, retained_return.lineno)
        self.assertLess(retained_return.end_lineno, verifiers[0].lineno)
        self.assertLess(verifiers[0].lineno, existing[1].lineno)
        self.assertEqual([ast.unparse(value) for value in verifiers[0].args],
                         ["metadata_connection", "checkpoint_bytes", "authorization_bytes"])
        lookup = functions["lookup_exact_local_initialization_candidate"]
        self.assertFalse(calls(lookup, "admission.validate_audit_initialization_intent"))
        self.assertFalse(calls(lookup, "reader.verify_audit_initialization_evidence_from_postgres"))
        for function in (public, lookup):
            self.assertIn("store_identity", [argument.arg for argument in function.args.kwonlyargs])
            copies = [call for call in calls(function, "_copy")
                if ast.unparse(call.args[0]) == "access.InitializationStoreDatabaseIdentity"]
            self.assertEqual(len(copies), 1)
            self.assertEqual(ast.unparse(copies[0].args[1]), "store_identity")
            self.assertIn("identity.namespace != namespace", ast.unparse(function))
            self.assertIn("identity.backend_incarnation_digest != accepted.backend_incarnation_digest",
                ast.unparse(function))

        operation = functions["_operation"]
        self.assertIsInstance(operation.body[0], ast.If)
        self.assertIn("TransactionStatus.IDLE", ast.unparse(operation.body[0].test))
        guarded = next(node for node in operation.body if isinstance(node, ast.Try))
        sessions = calls(operation, "_Session")
        self.assertEqual(len(sessions), 1)
        self.assertEqual([ast.unparse(value) for value in sessions[0].args], ["None", "limits", "started"])
        preentry_checks = [node for node in operation.body if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call) and ast.unparse(node.value.func) == "session.remaining_ms"]
        self.assertEqual(len(preentry_checks), 1)
        self.assertLess(sessions[0].lineno, preentry_checks[0].lineno)
        self.assertLess(preentry_checks[0].lineno, guarded.lineno)
        transaction = guarded.body[0]
        self.assertIsInstance(transaction, ast.With)
        self.assertEqual([ast.unparse(item.context_expr) for item in transaction.items],
                         ["connection.transaction()"])
        self.assertEqual(ast.unparse(transaction.body[-1]), "committing = True")
        callback_calls = calls(transaction, "callback")
        self.assertEqual(len(callback_calls), 1)
        access_calls = calls(transaction, "access.admit_store_access")
        structure_calls = calls(transaction, "structure.admit_store_structure")
        self.assertEqual((len(access_calls), len(structure_calls)), (1, 1))
        for call in (*access_calls, *structure_calls):
            self.assertEqual([ast.unparse(argument) for argument in call.args], ["session", "identity"])
        self.assertLess(access_calls[0].lineno, structure_calls[0].lineno)
        self.assertLess(structure_calls[0].lineno, callback_calls[0].lineno)
        locks = [node for node in ast.walk(transaction) if isinstance(node, ast.Constant)
            and isinstance(node.value, str) and node.value.startswith("LOCK TABLE ONLY ")]
        self.assertEqual([node.value for node in locks], ["LOCK TABLE ONLY {}, ONLY {} IN ACCESS SHARE MODE"])
        self.assertLess(locks[0].lineno, access_calls[0].lineno)
        self.assertLess(callback_calls[0].lineno, transaction.body[-1].lineno)
        self.assertEqual(ast.unparse(guarded.body[-1]), "return result")
        self.assertLess(transaction.end_lineno, guarded.body[-1].lineno)
        self.assertIn("TransactionStatus.IDLE", ast.unparse(guarded.body[1]))
        self.assertEqual(len(guarded.handlers), 1)
        handler = guarded.handlers[0]
        self.assertEqual(ast.unparse(handler.type), "BaseException")
        close_calls = calls(handler, "connection.close")
        unknown = calls(handler, "LocalInitializationOutcomeUnknown")
        self.assertEqual((len(close_calls), len(unknown)), (1, 1))
        self.assertLess(close_calls[0].lineno, unknown[0].lineno)
        self.assertTrue(any(isinstance(node, ast.If) and ast.unparse(node.test) == "committing"
            and calls(node, "LocalInitializationOutcomeUnknown") for node in handler.body))
        self.assertIsInstance(handler.body[-1], ast.Raise)
        self.assertIsNone(handler.body[-1].exc)
        # Native reopen/rollback cases test the successful/ordinary failure
        # paths. This structural check does NOT simulate a physical crash or
        # prove whether a failed COMMIT acknowledgment reached durable media.
        context_queries = [node for node in ast.walk(operation)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            and "current_setting('fsync')" in node.value]
        self.assertEqual(len(context_queries), 1)
        self.assertIn("current_setting('full_page_writes')", context_queries[0].value)
        self.assertIn("current_setting('synchronous_commit')", context_queries[0].value)
        self.assertIn("pg_is_in_recovery()", context_queries[0].value)
        self.assertLess(locks[0].lineno, context_queries[0].lineno)
        self.assertLess(context_queries[0].lineno, access_calls[0].lineno)
        # The deadline-arm helper must not establish a SELECT snapshot before
        # the two relation locks. This is source linkage, not concurrent DDL or
        # GRANT/REVOKE exclusion under privileged administrator changes.
        session_class = next(node for node in parsed.body
            if isinstance(node, ast.ClassDef) and node.name == "_Session")
        arm = next(node for node in session_class.body if isinstance(node, ast.FunctionDef) and node.name == "arm")
        arm_sql = [node.value for node in ast.walk(arm) if isinstance(node, ast.Constant)
            and isinstance(node.value, str) and ("SET " in node.value or "SELECT " in node.value)]
        self.assertTrue(arm_sql)
        self.assertTrue(all(value.startswith("SET LOCAL ") for value in arm_sql))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--postgres-dsn", required=True)
    parser.add_argument("--prepared-result")
    parser.add_argument("--disposable-cluster", action="store_true",
                        help="acknowledge that this externally prepared cluster is disposable")
    arguments, test_arguments = parser.parse_known_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    DISPOSABLE_CLUSTER_ACKNOWLEDGED = arguments.disposable_cluster
    run_native_fixture("scripts/test_authority_audit_initialization_store_postgres.py",
        argv=[sys.argv[0], *test_arguments], result_path=arguments.prepared_result)
