#!/usr/bin/env python3
"""Native local initialization storage, never externally anchored authority.

An explicitly acknowledged disposable PG16/UTF8 harness must provide one owned
mode-0700 Unix socket. No engine starts here. This fixture COMMITS a uniquely
named store schema/enrollment/candidate so reopen checks exercise real database
transactions. Cleanup removes only that exact fixture-created store schema.
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

from serverware import authority_audit_initialization_admission as admission
from serverware import authority_audit_initialization_postgres as reader
from serverware import authority_audit_initialization_store as store
from serverware import authority_contract
from serverware.authority_store.audit_initialization_store_sql import audit_initialization_store_ddl
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
        self.schema = "audit_init_store_" + uuid.uuid4().hex
        self.schema_created = False
        self.metadata = None
        self.addCleanup(self.cleanup_owned_state)
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
        admin = self.connect()
        environment = admin.execute(
            "SELECT pg_catalog.inet_server_addr(), pg_catalog.getdatabaseencoding(), "
            "pg_catalog.current_setting('server_version_num')::integer, current_user=session_user, "
            "pg_catalog.current_setting('fsync'), pg_catalog.current_setting('full_page_writes'), "
            "pg_catalog.pg_is_in_recovery()"
        ).fetchone()
        if (environment is None or environment[0] is not None or environment[1] != "UTF8"
                or not 160000 <= environment[2] < 170000 or environment[3] is not True
                or environment[4:] != ("on", "on", False)):
            raise RuntimeError("requires direct primary Unix-socket PG16/UTF8 with fsync/full_page_writes on")
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(self.schema)))
        self.schema_created = True
        admin.execute(sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(sql.Identifier(self.schema)))
        for statement in audit_initialization_store_ddl(self.schema):
            admin.execute(statement)
        # Deliberate owner provisioning for this isolated component. The tested
        # recorder must never manufacture this row when it is absent.
        admin.execute(sql.SQL(
            "INSERT INTO {} (database_identity_digest,enrollment_digest,enrollment_bytes,head_sequence,head_digest) "
            "VALUES (%s,%s,%s,0,%s)"
        ).format(self.object(ENROLLMENTS)), (expected.database_identity_digest,
            self.enrollment.digest, self.enrollment.canonical_bytes, self.enrollment.digest))
        admin.commit()
        self.connection = self.connect()

    def connect(self, *, autocommit=False):
        connection = psycopg.connect(**CONNECTION_PARAMETERS, autocommit=autocommit)
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
        if self.schema_created:
            # Never derive a DROP target from database contents, an environment
            # variable or a wildcard. Validate the exact random owned name.
            if re.fullmatch(r"audit_init_store_[0-9a-f]{32}", self.schema) is None:
                failures.append(AssertionError("refusing an unowned cleanup namespace"))
            else:
                cleanup = psycopg.connect(**CONNECTION_PARAMETERS, autocommit=True)
                try:
                    cleanup.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE")
                        .format(sql.Identifier(self.schema)))
                except Exception as exc:
                    failures.append(exc)
                finally:
                    cleanup.close()
        if failures:
            raise AssertionError("owned fixture cleanup failed") from failures[0]

    def snapshot(self):
        observer = self.connect()
        try:
            return {table: observer.execute(sql.SQL("SELECT * FROM {} ORDER BY database_identity_digest")
                .format(self.object(table))).fetchall() for table in (ENROLLMENTS, CANDIDATES)}
        finally:
            observer.rollback()
            observer.close()

    def owner_change(self, statement, parameters=()):
        admin = self.connect()
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
            read_limits=metadata_fixture.read_limits(), store_limits=store_limits(),
            namespace=self.schema, metadata_namespace=self.metadata.store.schema)
        arguments.update(changes)
        return store.record_local_initialization_candidate(
            self.connection if connection is None else connection,
            self.metadata.connection if metadata_connection is None else metadata_connection,
            self.signed.checkpoint if checkpoint is None else checkpoint,
            self.signed.authorization if authorization is None else authorization, **arguments)

    def lookup(self, checkpoint=None, authorization=None, *, connection=None, **changes):
        arguments = dict(enrollment=self.enrollment, store_limits=store_limits(), namespace=self.schema)
        arguments.update(changes)
        return store.lookup_exact_local_initialization_candidate(
            self.connection if connection is None else connection,
            self.signed.checkpoint if checkpoint is None else checkpoint,
            self.signed.authorization if authorization is None else authorization, **arguments)

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
            replace(self.enrollment, backend_incarnation_digest=WRONG_DIGEST),
            replace(self.enrollment, source_contract_digest=WRONG_DIGEST),
        ):
            with self.subTest(enrollment=changed.digest), self.assertRaises(store.LocalInitializationStoreError):
                self.lookup(enrollment=changed)
            self.assertEqual(self.snapshot(), before)
            self.renew_failed_store()
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
        # Genuine SQL failure after the candidate write, not a fake successful
        # verifier/commit. This is transaction rollback, not crash durability.
        self.owner_change(sql.SQL(
            "CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ "
            "BEGIN RAISE EXCEPTION 'fixture rejects initialization head advance'; END; $$"
        ).format(self.object("fixture_reject_head_advance")))
        self.owner_change(sql.SQL(
            "CREATE TRIGGER fixture_reject_head_advance BEFORE UPDATE ON {} "
            "FOR EACH ROW EXECUTE FUNCTION {}()"
        ).format(self.object(ENROLLMENTS), self.object("fixture_reject_head_advance")))
        before = self.snapshot()
        with self.assertRaises(psycopg.errors.RaiseException) as raised:
            self.record()
        self.assertEqual(raised.exception.diag.message_primary, "fixture rejects initialization head advance")
        self.assertEqual(self.snapshot(), before)
        self.renew_failed_store()
        self.assertEqual(self.metadata.connection.info.transaction_status, TransactionStatus.INTRANS)
        self.assertIsNone(self.lookup())
        self.owner_change(sql.SQL("DROP TRIGGER fixture_reject_head_advance ON {}")
            .format(self.object(ENROLLMENTS)))
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
                         ["store_connection", "limits", "started", "record"])
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-dsn", required=True)
    parser.add_argument("--disposable-cluster", action="store_true",
                        help="acknowledge that this externally prepared cluster is disposable")
    arguments, test_arguments = parser.parse_known_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    DISPOSABLE_CLUSTER_ACKNOWLEDGED = arguments.disposable_cluster
    unittest.main(argv=[sys.argv[0], *test_arguments])
