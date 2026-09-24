#!/usr/bin/env python3
"""Genuine raw replay and persistence branches over an explicit SQL recorder.

Signatures, complete proofs, effects and retained commitments are real. The
small transaction recorder models returned rows and savepoint rollback only;
it is not PostgreSQL execution, constraint/ACL proof or production admission.
No successful verification result or registry replacement is injected.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract
from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_retention as retention
from serverware.authority_store import planner_connection as admission
from serverware.authority_store import revocation_retention as store
from serverware.authority_store import authorization_records
import test_authority_revocation_plan as oracle
import test_authority_revocation_retention as record_oracle
import test_authority_revocation_wire as wire_oracle


PARENT = "serverware_metadata.policy_authority_planner_transactions"
SIDECAR = "serverware_metadata.policy_authority_revocation_retained_plans"
ASSERTION = "serverware_metadata.policy_authority_webauthn_assertion_evidence"
PROJECTION = "serverware_metadata.policy_authority_authorization_projections"
RESERVED_FIELDS = (
    "planner_transaction_id", "operation", "operation_id", "request_digest", "capability_id",
    "operation_contract_digest", "query_manifest_digest", "selected_business_rows_json",
    "selected_business_rows_digest", "mutation_plan_json", "mutation_plan_digest", "work_units",
    "authority_root_set_before_digest", "planner_session_identity_digest", "planner_measurement_digest",
    "planner_attestation_receipt_digest", "deadline_monotonic_ns", "deadline_epoch_ns", "fence",
    "reserved_at_epoch_ns", "source_revision", "plan_protocol",
)
PLANNED_FIELDS = ("authorization_projection_digest", "authority_snapshot_digest",
    "exact_plan_base64url", "exact_plan_bytes_digest", "exact_plan_byte_count", "retained_record_digest")
RECORD_FIELDS = ("planner_transaction_id", "plan_protocol", "exact_envelope_base64url",
    "exact_envelope_bytes_digest", "exact_envelope_byte_count", "evaluation_context_base64url",
    "evaluation_context_bytes_digest", "evaluation_context_byte_count", "planner_key_digest",
    "verifier_key_digest", "retained_record_digest", "source_revision")
ASSERTION_SCALARS = (
    ("operation", "operation"), ("operation_id", "operationId"), ("request_digest", "requestDigest"),
    ("capability_id", "capabilityId"), ("challenge_id", "challengeId"), ("challenge_digest", "challengeDigest"),
    ("client_challenge_digest", "clientChallengeDigest"), ("credential_record_id", "credentialRecordId"),
    ("credential_id", "credentialId"), ("credential_policy_digest", "credentialPolicyDigest"),
    ("authenticator_data_base64url", "authenticatorDataBase64url"), ("authenticator_data_digest", "authenticatorDataDigest"),
    ("client_data_json_base64url", "clientDataJSONBase64url"), ("client_data_json_digest", "clientDataJSONDigest"),
    ("signature_base64url", "signatureBase64url"), ("signature_digest", "signatureDigest"),
    ("rp_id", "rpId"), ("rp_id_hash_digest", "rpIdHashDigest"), ("origin", "origin"), ("flags", "flags"),
)
ASSERTION_FIELDS = ("assertion_evidence_digest", *(name for name, _ in ASSERTION_SCALARS),
    "user_present", "user_verified", "prior_counter", "counter", "trust_high_water_digest",
    "metadata_publication_sequence", "verifier_session_identity_digest", "verifier_measurement_digest",
    "verifier_attestation_receipt_digest", "verified_assertion_receipt_digest", "evidence_json",
    "verified_at_epoch_ns", "expires_at_epoch_ns", "source_revision")
PROJECTION_FIELDS = ("authorization_projection_digest", "planner_transaction_id", "operation", "operation_id",
    "request_digest", "capability_id", "operation_contract_digest", "authorization_reads_json",
    "authorization_reads_digest", "source_rows_json", "source_rows_digest", "source_high_water_digest",
    "approver_policy_digest", "assertion_evidence_digest", "projection_json", "verifier_session_identity_digest",
    "verifier_measurement_digest", "verifier_attestation_receipt_digest", "created_at_epoch_ns", "expires_at_epoch_ns",
    "source_revision")


def expected_authorization_rows(fixture):
    """Literal legacy SQL projection; no materializer output supplies expected values."""
    evidence, projection = fixture.payload["webauthnEvidence"], fixture.payload["authorizationProjection"]
    assertion = {"assertion_evidence_digest": oracle.framed(
        "serverware.policyAuthorityWebAuthnAssertionEvidence/v1", oracle.wire(evidence)),
        **{column: evidence[field] for column, field in ASSERTION_SCALARS},
        "user_present": 1, "user_verified": 1, "prior_counter": evidence["priorCounter"],
        "counter": evidence["counter"], "trust_high_water_digest": evidence["trustHighWaterDigest"],
        "metadata_publication_sequence": evidence["metadataPublicationSequence"],
        "verifier_session_identity_digest": evidence["verifierSessionIdentityDigest"],
        "verifier_measurement_digest": evidence["verifierMeasurementDigest"],
        "verifier_attestation_receipt_digest": evidence["verifierAttestationReceiptDigest"],
        "verified_assertion_receipt_digest": evidence["verifiedAssertionReceiptDigest"],
        "evidence_json": oracle.wire(evidence).decode("ascii"), "verified_at_epoch_ns": evidence["verifiedAtEpochNs"],
        "expires_at_epoch_ns": evidence["expiresAtEpochNs"], "source_revision": authority_contract.SOURCE_REVISION}
    authorization = {
        "authorization_projection_digest": oracle.framed("serverware.policyAuthorityAuthorizationProjection/v1",
            oracle.wire(projection)),
        "planner_transaction_id": projection["plannerTransactionId"], "operation": projection["operation"],
        "operation_id": projection["operationId"], "request_digest": projection["requestDigest"],
        "capability_id": projection["capabilityId"], "operation_contract_digest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "authorization_reads_json": oracle.wire(projection["authorizationReads"]).decode("ascii"),
        "authorization_reads_digest": oracle.framed("serverware.policyAuthorityAuthorizationReads/v1",
            oracle.wire(projection["authorizationReads"])),
        "source_rows_json": oracle.wire(projection["sourceRows"]).decode("ascii"),
        "source_rows_digest": oracle.framed("serverware.policyAuthorityAuthorizationRows/v1",
            oracle.wire(projection["sourceRows"])),
        "source_high_water_digest": projection["sourceHighWaterDigest"],
        "approver_policy_digest": projection["approverPolicyDigest"],
        "assertion_evidence_digest": projection["assertionEvidenceDigest"],
        "projection_json": oracle.wire(projection).decode("ascii"),
        "verifier_session_identity_digest": projection["verifierSessionIdentityDigest"],
        "verifier_measurement_digest": projection["verifierMeasurementDigest"],
        "verifier_attestation_receipt_digest": projection["verifierAttestationReceiptDigest"],
        "created_at_epoch_ns": projection["createdAtEpochNs"], "expires_at_epoch_ns": projection["expiresAtEpochNs"],
        "source_revision": authority_contract.SOURCE_REVISION}
    return assertion, authorization


def expected_rows(fixture, planned_at):
    """Literal parent/sidecar recipe, never production-returned rows/digests."""
    payload, measured = fixture.payload, fixture.payload["measuredPlan"]
    raw = oracle.wire(fixture.envelope)
    context_raw = oracle.wire(record_oracle.record_context(fixture))
    payload_raw = oracle.wire(payload)
    header = record_oracle.record_header(fixture, raw, context_raw)
    record_digest = oracle.framed("serverware.policyAuthorityRevocationRetainedPlan/v1", oracle.wire(header))
    parent = {
        "planner_transaction_id": fixture.planner_transaction_id, "operation": measured["operation"],
        "operation_id": measured["operationId"], "request_digest": measured["requestDigest"],
        "capability_id": measured["capabilityId"], "operation_contract_digest": measured["operationContractDigest"],
        "query_manifest_digest": measured["queryManifestDigest"],
        "selected_business_rows_json": oracle.wire(payload["selectedBusinessRows"]).decode("ascii"),
        "selected_business_rows_digest": measured["selectedBusinessRowsDigest"],
        "mutation_plan_json": oracle.wire(payload["mutationPlan"]).decode("ascii"),
        "mutation_plan_digest": measured["mutationPlanDigest"], "work_units": measured["workUnits"],
        "authority_root_set_before_digest": measured["authorityRootSetBeforeDigest"],
        "planner_session_identity_digest": fixture.identity["sessionIdentityDigest"],
        "planner_measurement_digest": fixture.identity["measurementDigest"],
        "planner_attestation_receipt_digest": fixture.identity["attestationReceiptDigest"],
        "deadline_monotonic_ns": fixture.deadline_monotonic_ns, "deadline_epoch_ns": fixture.deadline_epoch_ns,
        "fence": fixture.fence, "reserved_at_epoch_ns": fixture.reserved_at_epoch_ns,
        "source_revision": authority_contract.SOURCE_REVISION, "plan_protocol": "revocation-v4",
        "authorization_projection_digest": measured["authorizationProjectionDigest"],
        "authority_snapshot_digest": measured["authoritySnapshotDigest"],
        "exact_plan_base64url": oracle.encoded(payload_raw), "exact_plan_bytes_digest": oracle.sha(payload_raw),
        "exact_plan_byte_count": len(payload_raw), "retained_record_digest": record_digest,
        "status": "planned", "planned_at_epoch_ns": planned_at,
    }
    sidecar = {
        "planner_transaction_id": fixture.planner_transaction_id, "plan_protocol": "revocation-v4",
        "exact_envelope_base64url": oracle.encoded(raw), "exact_envelope_bytes_digest": oracle.sha(raw),
        "exact_envelope_byte_count": len(raw), "evaluation_context_base64url": oracle.encoded(context_raw),
        "evaluation_context_bytes_digest": oracle.sha(context_raw), "evaluation_context_byte_count": len(context_raw),
        "planner_key_digest": header["plannerKeyDigest"], "verifier_key_digest": header["verifierKeyDigest"],
        "retained_record_digest": record_digest, "source_revision": authority_contract.SOURCE_REVISION,
    }
    return parent, sidecar


def codec_encode(raw):
    padded = 4 * ((len(raw) + 2) // 3)
    return (0, len(raw) + 3 * padded + len(oracle.encoded(raw)), 0)


def codec_decode(raw):
    length = len(oracle.encoded(raw))
    padded = length + (-length % 4)
    decoded = 3 * (padded // 4)
    reencoded = 4 * ((decoded + 2) // 3)
    return (0, 2 * length + 4 * padded + 2 * decoded + 5 * reencoded, 0)


def scalar_comparisons(document):
    return oracle.add(*(oracle.graph_cost(value, 4, 4) for value in document.values()))


def independent_authorization_work(fixture, *, insert=False):
    evidence, projection = fixture.payload["webauthnEvidence"], fixture.payload["authorizationProjection"]
    assertion_row, projection_row = expected_authorization_rows(fixture)
    materialized = oracle.add(*(oracle.add(oracle.graph_cost(value, byte_passes, node_passes),
        oracle.frame_cost(domain, (oracle.wire(value),))) for value, domain, byte_passes, node_passes in (
        (evidence, "serverware.policyAuthorityWebAuthnAssertionEvidence/v1", 6, 4),
        (projection, "serverware.policyAuthorityAuthorizationProjection/v1", 6, 4),
        (projection["authorizationReads"], "serverware.policyAuthorityAuthorizationReads/v1", 5, 4),
        (projection["sourceRows"], "serverware.policyAuthorityAuthorizationRows/v1", 3, 2))))
    joined = oracle.add(*(oracle.graph_cost(value, 4, 4) for value in (
        assertion_row["assertion_evidence_digest"], projection_row["authorization_projection_digest"],
        assertion_row["assertion_evidence_digest"], projection_row["planner_transaction_id"])))
    rows = oracle.add(*(oracle.add(oracle.graph_cost(row), scalar_comparisons(row),
        oracle.graph_cost(row) if insert else (0, 0, 0)) for row in (assertion_row, projection_row)))
    live = (0, 0, 0)
    if insert:
        unsigned = {name: value for name, value in evidence.items() if name not in {
            "verifierSignatureBase64url", "verifierSignatureDigest", "verifiedAssertionReceiptDigest"}}
        live = oracle.add((0, 1096, 0), oracle.graph_cost(evidence), oracle.graph_cost(unsigned, 3, 2),
            oracle.frame_cost("serverware.policyAuthorityVerifiedWebAuthnAssertionReceipt/v1", (oracle.wire(unsigned),)),
            (1, 64, 0), oracle.graph_cost(evidence["verifiedAssertionReceiptDigest"], 4, 4),
            oracle.graph_cost(evidence["verifierSignatureDigest"], 4, 4),
            oracle.utf8_cost(evidence["verifiedAssertionReceiptDigest"]))
    return {"materialized": materialized, "joined": joined, "rows": rows, "live": live,
        "total": oracle.add(materialized, joined, rows, live)}


def independent_store_metrics(fixture, planned_at, *, mode="new"):
    parent, sidecar = expected_rows(fixture, planned_at)
    reservation = {name: parent[name] for name in RESERVED_FIELDS}
    planned = {name: parent[name] for name in PLANNED_FIELDS}
    raw, context_raw = oracle.wire(fixture.envelope), oracle.wire(record_oracle.record_context(fixture))
    bindings = oracle.add(oracle.graph_cost(fixture.payload["selectedBusinessRows"], 3, 2),
        oracle.graph_cost(fixture.payload["mutationPlan"], 3, 2), codec_encode(raw),
        codec_encode(context_raw), codec_encode(oracle.wire(fixture.payload)))
    record = record_oracle.independent_record_metrics(fixture)
    prefix = (0, 0, 0)
    if mode == "read":
        external = {name: value for name, value in wire_oracle.expectations(fixture).items()
            if name not in {"planner_public_key", "verifier_public_key", "database_now"}}
        prefix = oracle.add(oracle.graph_cost(external, 1, 1),
            oracle.graph_cost(fixture.planner_transaction_id, 4, 4),
            oracle.graph_cost(parent), oracle.graph_cost(sidecar), codec_decode(raw), codec_decode(context_raw))
        tail = oracle.add(bindings, scalar_comparisons(reservation), scalar_comparisons(planned),
            scalar_comparisons(sidecar))
    else:
        tail = oracle.add(bindings, oracle.graph_cost(reservation), oracle.graph_cost(planned),
            oracle.graph_cost(sidecar), oracle.graph_cost(parent), scalar_comparisons(reservation),
            oracle.graph_cost(sidecar), scalar_comparisons(sidecar), scalar_comparisons(planned))
        if mode == "new":
            reserved = {**parent, **{name: None for name in PLANNED_FIELDS},
                "status": "reserved", "planned_at_epoch_ns": None}
            # Replace the first planned-row copy with the actual reserved row;
            # then add its null fields and genuine post-CAS reread/comparison.
            old = oracle.graph_cost(parent)
            tail = tuple(value - remove for value, remove in zip(tail, old))
            tail = oracle.add(tail, oracle.graph_cost(reserved),
                scalar_comparisons({name: None for name in PLANNED_FIELDS}),
                oracle.graph_cost(parent), scalar_comparisons(reservation))
    authorization = independent_authorization_work(fixture, insert=mode == "new")
    tail = oracle.add(tail, authorization["total"])
    total = oracle.add(prefix, record["total"], tail)
    peak = oracle.add(prefix, record["admission"])
    return {"total": total, "admission": tuple(max(a, b) for a, b in zip(total, peak)),
        "prefix": prefix, "tail": tail, "authorization": authorization}


class StoreError(ValueError):
    pass


class Facade:
    def __init__(self, raw):
        self.raw_connection = raw
        self.in_transaction = True


class Recorder:
    """Statement-level fixture only; deliberately no claims about SQL engine."""
    def __init__(self):
        self.parent = self.sidecar = None
        self.assertions, self.projections = {}, {}
        self.statements = []
        self.rollbacks = self.releases = 0
        self.isolation = "serializable"
        self.role, self.read_only, self.deferrable = "fixture-planner-writer", "off", "off"
        self.callback = None
        self.fail_completion = False
        self.return_aliases = False

    def cursor(self):
        return Cursor(self)

    def snapshot(self):
        return copy.deepcopy((self.parent, self.sidecar, self.assertions, self.projections))

    def seed(self, fixture, planned_at):
        self.parent, self.sidecar = expected_rows(fixture, planned_at)
        evidence, projection = expected_authorization_rows(fixture)
        self.assertions[evidence["assertion_evidence_digest"]] = evidence
        self.projections[projection["authorization_projection_digest"]] = projection

    @contextmanager
    def transaction(self):
        before = self.snapshot()
        try:
            yield self
        except BaseException:
            self.parent, self.sidecar, self.assertions, self.projections = before
            self.rollbacks += 1
            raise
        else:
            self.releases += 1


class Cursor:
    def __init__(self, recorder):
        self.recorder, self.result, self.rowcount = recorder, None, -1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, parameters=()):
        r = self.recorder
        r.statements.append((sql, parameters))
        if r.callback is not None:
            r.callback(sql, parameters)
        self.result, self.rowcount = None, -1
        if sql == "SHOW transaction_isolation":
            self.result = {"transaction_isolation": r.isolation}
        elif sql.startswith("SELECT current_user AS current_role"):
            self.result = {"current_role": r.role, "session_role": r.role,
                "read_only": r.read_only, "deferrable": r.deferrable}
        elif sql.startswith("INSERT INTO " + PARENT):
            if r.parent is None:
                r.parent = dict(zip(RESERVED_FIELDS, parameters))
                r.parent.update({name: None for name in PLANNED_FIELDS})
                r.parent.update(status="reserved", planned_at_epoch_ns=None)
            self.rowcount = 0
        elif sql.startswith("INSERT INTO " + SIDECAR):
            if r.sidecar is None:
                r.sidecar = dict(zip(RECORD_FIELDS, parameters))
            self.rowcount = 0
        elif sql.startswith(("INSERT INTO " + ASSERTION, "INSERT INTO " + PROJECTION)):
            table, fields, rows = ((ASSERTION, ASSERTION_FIELDS, r.assertions)
                if sql.startswith("INSERT INTO " + ASSERTION) else (PROJECTION, PROJECTION_FIELDS, r.projections))
            expected_sql = ("INSERT INTO " + table + " (" + ", ".join(fields) + ") VALUES ("
                + ", ".join(("%s",) * len(fields)) + ") ON CONFLICT (" + fields[0] + ") DO NOTHING")
            if sql != expected_sql or len(parameters) != len(fields):
                raise AssertionError("authorization INSERT escaped its literal column/parameter closure")
            row = dict(zip(fields, parameters))
            # Explicit SQL-recorder collision model, not native constraint evidence.
            for digest, stored in rows.items():
                if digest != row[fields[0]] and (all(stored[name] == row[name]
                        for name in ("operation_id", "request_digest", "capability_id"))
                        or stored["challenge_id" if table == ASSERTION else "planner_transaction_id"]
                        == row["challenge_id" if table == ASSERTION else "planner_transaction_id"]):
                    raise StoreError("synthetic authorization uniqueness conflict")
            rows.setdefault(row[fields[0]], row)
            self.rowcount = 0
        elif sql.startswith("UPDATE " + PARENT):
            if r.fail_completion:
                self.rowcount = 0
            elif r.parent is not None and r.parent["status"] == "reserved":
                if "AND plan_protocol = 'revocation-v4'" not in sql or "retained_record_digest IS NULL" not in sql:
                    raise AssertionError("missing versioned CAS predicate")
                r.parent.update(dict(zip(PLANNED_FIELDS, parameters[:6])))
                r.parent.update(status="planned", planned_at_epoch_ns=parameters[6])
                self.rowcount = 1
        elif sql.startswith("SELECT ") and " FROM " + PARENT in sql:
            if not sql.endswith("FOR UPDATE"):
                raise AssertionError("parent read is not locked")
            self.result = (r.parent if r.return_aliases or r.parent is None else r.parent.copy())
        elif sql.startswith("SELECT ") and " FROM " + SIDECAR in sql:
            self.result = (r.sidecar if r.return_aliases or r.sidecar is None else r.sidecar.copy())
        elif sql.startswith("SELECT ") and any(" FROM " + table in sql for table in (ASSERTION, PROJECTION)):
            table, fields, rows = ((ASSERTION, ASSERTION_FIELDS, r.assertions)
                if " FROM " + ASSERTION in sql else (PROJECTION, PROJECTION_FIELDS, r.projections))
            if sql != "SELECT " + ", ".join(fields) + " FROM " + table + " WHERE " + fields[0] + " = %s":
                raise AssertionError("authorization SELECT requires only existing SELECT privilege")
            row = rows.get(parameters[0])
            self.result = row if r.return_aliases or row is None else row.copy()
        else:
            raise AssertionError("unexpected SQL in fixed persistence recorder: " + sql)
        return self

    def fetchone(self):
        return self.result


class RevocationPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.old_namespace = admission._DB_GLOBALS
        self.current_key_bytes, self.key_loads = None, 0

        def current_key():
            # Deterministic configured raw key bytes, not a signature verdict.
            self.key_loads += 1
            return self.current_key_bytes

        admission.bind_db_globals({"PostgresMetadataConnection": Facade, "MetadataStoreError": StoreError,
            "_METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE": "fixture-planner-writer",
            "_POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_AGE_NS": 300_000_000_000,
            "_POLICY_AUTHORITY_VERIFIER_MAX_CLOCK_SKEW_NS": 1_000_000_000,
            "_policy_authority_verifier_public_key": current_key,
            "Ed25519PublicKey": Ed25519PublicKey, "InvalidSignature": InvalidSignature})

    def tearDown(self):
        admission._DB_GLOBALS = self.old_namespace

    def fixture(self):
        fixture = oracle.PlanFixture(approval=False, include_audit=False)
        self.current_key_bytes = fixture.semantic.receipt.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return fixture

    def work(self, limits=None):
        return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))

    def persist(self, fixture, recorder, work=None, *, planned_at=None,
                clock_epoch_ns=None, clock_monotonic_ns=None, clock_epoch_sequence=None, **changes):
        supplied = {"envelope_bytes": oracle.wire(fixture.envelope),
            "evaluation_context_bytes": oracle.wire(record_oracle.record_context(fixture)),
            "planned_at_epoch_ns": fixture.now_epoch_ns if planned_at is None else planned_at,
            "connection": Facade(recorder), "work": work or self.work(), **wire_oracle.expectations(fixture)}
        supplied.update(changes)
        with patch.object(admission.time, "time_ns", return_value=(fixture.now_epoch_ns
                if clock_epoch_ns is None else clock_epoch_ns), side_effect=clock_epoch_sequence), \
                patch.object(admission.time, "monotonic_ns", return_value=(fixture.now_monotonic_ns
                if clock_monotonic_ns is None else clock_monotonic_ns)):
            return store.persist_revocation_planner_record(**supplied)

    def read(self, fixture, recorder, work=None, **changes):
        supplied = {"planner_transaction_id": fixture.planner_transaction_id,
            "connection": Facade(recorder), "work": work or self.work(), **wire_oracle.expectations(fixture)}
        supplied.update(changes)
        return store.read_revocation_planner_record(**supplied)

    def test_actual_raw_verification_reserves_inserts_and_completes_exact_original_record(self):
        fixture, recorder = self.fixture(), Recorder()
        expected = expected_rows(fixture, fixture.now_epoch_ns)
        metrics = independent_store_metrics(fixture, fixture.now_epoch_ns)
        work = self.work(metrics["admission"])
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as verified, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
            actual = self.persist(fixture, recorder, work)
        self.assertEqual((verified.call_count, proof.call_count), (1, 1))
        self.assertIs(verified.call_args.kwargs["work"], work)
        self.assertEqual((recorder.parent, recorder.sidecar), expected)
        assertion, projection = expected_authorization_rows(fixture)
        self.assertEqual((tuple(assertion), tuple(projection)), (ASSERTION_FIELDS, PROJECTION_FIELDS))
        self.assertEqual((len(assertion), len(projection)), (35, 21))
        self.assertEqual(recorder.assertions, {assertion["assertion_evidence_digest"]: assertion})
        self.assertEqual(recorder.projections, {projection["authorization_projection_digest"]: projection})
        self.assertEqual(self.key_loads, 1)
        self.assertEqual(actual["exactEnvelopeBytes"], oracle.wire(fixture.envelope))
        self.assertEqual(actual["evaluationContextBytes"], oracle.wire(record_oracle.record_context(fixture)))
        self.assertEqual(actual["retainedRecordDigest"], expected[1]["retained_record_digest"])
        self.assertEqual(oracle.units(work.metrics), metrics["total"])
        sql = [statement for statement, _ in recorder.statements]
        self.assertLess(next(i for i, q in enumerate(sql) if q.startswith("INSERT INTO " + SIDECAR)),
                        next(i for i, q in enumerate(sql) if q.startswith("UPDATE " + PARENT)))
        for earlier, later in ((ASSERTION, PROJECTION), (PROJECTION, SIDECAR)):
            self.assertLess(next(i for i, q in enumerate(sql) if q.startswith("INSERT INTO " + earlier)),
                            next(i for i, q in enumerate(sql) if q.startswith("INSERT INTO " + later)))
        self.assertTrue(all("FOR UPDATE" not in q for q in sql if " FROM " + ASSERTION in q or " FROM " + PROJECTION in q))
        self.assertEqual((recorder.rollbacks, recorder.releases), (0, 1))

    def test_identical_retry_reverifies_exact_bytes_and_preserves_original_timestamp(self):
        fixture, recorder = self.fixture(), Recorder()
        recorder.seed(fixture, fixture.now_epoch_ns)
        before = recorder.snapshot()
        expected = independent_store_metrics(fixture, fixture.now_epoch_ns, mode="retry")
        work = self.work(expected["admission"])
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as verified:
            actual = self.persist(fixture, recorder, work, planned_at=fixture.now_epoch_ns + 1)
        self.assertEqual(verified.call_count, 1)
        self.assertEqual(actual["plannedAtEpochNs"], fixture.now_epoch_ns)
        self.assertEqual(recorder.snapshot(), before)
        self.assertFalse(any(sql.startswith(("UPDATE ", "INSERT INTO " + SIDECAR)) for sql, _ in recorder.statements))
        self.assertFalse(any(sql.startswith(("INSERT INTO " + ASSERTION, "INSERT INTO " + PROJECTION))
                             for sql, _ in recorder.statements))
        self.assertEqual(self.key_loads, 0)
        self.assertEqual(oracle.units(work.metrics), expected["total"])

    def test_historical_read_verifies_original_bytes_without_resampling_time(self):
        fixture, recorder = self.fixture(), Recorder()
        recorder.seed(fixture, fixture.now_epoch_ns)
        expected = independent_store_metrics(fixture, fixture.now_epoch_ns, mode="read")
        work = self.work(expected["admission"])
        with patch.object(admission.time, "time_ns", side_effect=AssertionError("historical clock refresh")), \
                patch.object(admission.time, "monotonic_ns", side_effect=AssertionError("historical clock refresh")), \
                patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as verified:
            result = self.read(fixture, recorder, work)
        self.assertEqual(verified.call_count, 1)
        self.assertEqual(self.key_loads, 0)
        self.assertEqual(result["exactEnvelopeBytes"], oracle.wire(fixture.envelope))
        self.assertEqual(oracle.units(work.metrics), expected["total"])
        self.assertFalse(any(sql.startswith(("INSERT ", "UPDATE ", "DELETE ")) for sql, _ in recorder.statements))

    def test_conflicting_parent_and_sidecar_retry_deny_without_overwrite(self):
        fixture = self.fixture()
        for target, field, value in (("parent", "request_digest", oracle.sha(b"foreign request")),
                ("parent", "plan_protocol", "v3"), ("sidecar", "planner_key_digest", oracle.sha(b"foreign key")),
                ("sidecar", "evaluation_context_base64url", oracle.encoded(b"{}")),
                ("sidecar", "exact_envelope_base64url", oracle.encoded(b"{}"))):
            recorder = Recorder()
            recorder.seed(fixture, fixture.now_epoch_ns)
            getattr(recorder, target)[field] = value
            before = recorder.snapshot()
            with self.subTest(target=target, field=field), self.assertRaises(StoreError):
                self.persist(fixture, recorder)
            self.assertEqual(recorder.snapshot(), before)
            self.assertEqual(recorder.rollbacks, 1)

    def test_cas_failure_rolls_back_new_parent_and_sidecar_in_caller_savepoint(self):
        fixture, recorder, work = self.fixture(), Recorder(), self.work()
        recorder.fail_completion = True
        with self.assertRaisesRegex(StoreError, "completion CAS failed"):
            self.persist(fixture, recorder, work)
        self.assertEqual((recorder.parent, recorder.sidecar), (None, None))
        self.assertEqual((recorder.assertions, recorder.projections), ({}, {}))
        self.assertTrue(all(any(sql.startswith("INSERT INTO " + table) for sql, _ in recorder.statements)
                            for table in (ASSERTION, PROJECTION)))
        self.assertEqual((recorder.rollbacks, recorder.releases), (1, 0))
        self.assertGreater(work.hash_work, 0)

    def test_false_signature_and_foreign_historical_context_deny_before_any_sql(self):
        fixture = self.fixture()
        wrong = copy.deepcopy(fixture.envelope)
        wrong["signatureBase64Url"] = oracle.encoded(bytes(64))
        context = record_oracle.record_context(fixture)
        context["databaseCutoffUs"] += 1
        for changes in ({"envelope_bytes": oracle.wire(wrong)},
                        {"evaluation_context_bytes": oracle.wire(context)}):
            recorder = Recorder()
            with self.subTest(changes=tuple(changes)), self.assertRaises(retention.RevocationRetentionError):
                self.persist(fixture, recorder, **changes)
            self.assertEqual(recorder.statements, [])

    def test_exact_preconsumed_write_and_read_peaks_and_each_minus_one_keep_one_work(self):
        fixture, prior = self.fixture(), (3, 31, 5)
        for mode in ("new", "read"):
            expected = independent_store_metrics(fixture, fixture.now_epoch_ns, mode=mode)
            for dimension in (None, 0, 1, 2):
                recorder = Recorder()
                if mode == "read":
                    recorder.seed(fixture, fixture.now_epoch_ns)
                before = recorder.snapshot()
                limits = list(oracle.add(prior, expected["admission"]))
                if dimension is not None:
                    limits[dimension] -= 1
                work = self.work(limits)
                work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                entering = work.limits
                call = self.persist if mode == "new" else self.read
                with self.subTest(mode=mode, dimension=dimension), \
                        patch.object(retention.plan.retained._PackagingLedger, "__init__",
                            side_effect=AssertionError("new outer work allowance")):
                    if dimension is None:
                        call(fixture, recorder, work)
                        self.assertEqual(oracle.units(work.metrics), oracle.add(prior, expected["total"]))
                    else:
                        with self.assertRaises(ValueError):
                            call(fixture, recorder, work)
                        self.assertEqual(recorder.snapshot(), before)
                        self.assertTrue(all(start <= used <= limit for start, used, limit
                            in zip(prior, oracle.units(work.metrics), limits)))
                self.assertIs(work.limits, entering)
                self.assertFalse(hasattr(work, "_revocation_packaging_owner"))

    def test_real_write_then_read_accumulates_without_cached_proof_or_counter_reset(self):
        fixture, recorder, prior = self.fixture(), Recorder(), (2, 17, 3)
        written = independent_store_metrics(fixture, fixture.now_epoch_ns)
        replay = independent_store_metrics(fixture, fixture.now_epoch_ns, mode="read")
        peak = tuple(max(a, b) for a, b in zip(written["admission"],
            oracle.add(written["total"], replay["admission"])))
        work = self.work(oracle.add(prior, peak))
        work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
        entering = work.limits
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as verified, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
            first = self.persist(fixture, recorder, work)
            second = self.read(fixture, recorder, work)
        self.assertEqual(first, second)
        self.assertEqual((verified.call_count, proof.call_count), (2, 2))
        self.assertTrue(all(call.kwargs["work"] is work for call in verified.call_args_list))
        self.assertEqual(oracle.units(work.metrics), oracle.add(prior, written["total"], replay["total"]))
        self.assertIs(work.limits, entering)

    def test_replay_absence_is_distinct_from_wrong_protocol_incomplete_or_missing_record(self):
        fixture = self.fixture()
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as verified:
            self.assertIsNone(self.read(fixture, Recorder()))
        self.assertEqual(verified.call_count, 0)
        for changed in ({"plan_protocol": "v3", "retained_record_digest": None},
                        {"plan_protocol": "unknown"}, {"plan_protocol": None},
                        {"status": "reserved"}, {"status": "failed"},
                        {"retained_record_digest": None}, {"missing_sidecar": True}):
            recorder = Recorder()
            recorder.seed(fixture, fixture.now_epoch_ns)
            if "missing_sidecar" in changed:
                recorder.sidecar = None
            else:
                recorder.parent.update(changed)
            with self.subTest(changed=changed), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as verified:
                with self.assertRaises(StoreError):
                    self.read(fixture, recorder)
            self.assertEqual(verified.call_count, 0)
            self.assertFalse(any(sql.startswith(("INSERT ", "UPDATE ")) for sql, _ in recorder.statements))

    def test_stored_codec_digests_keypins_and_parent_payload_are_rechecked_on_read(self):
        fixture = self.fixture()
        for target, field, value, replay_calls in (
                ("sidecar", "exact_envelope_byte_count", True, 0),
                ("sidecar", "evaluation_context_byte_count", 524289, 0),
                ("sidecar", "exact_envelope_base64url", "=", 0),
                ("sidecar", "exact_envelope_bytes_digest", oracle.sha(b"wrong bytes"), 1),
                ("sidecar", "planner_key_digest", oracle.sha(b"unapproved key"), 1),
                ("sidecar", "verifier_key_digest", oracle.sha(b"unapproved verifier"), 1),
                ("sidecar", "retained_record_digest", oracle.sha(b"wrong record"), 1),
                ("parent", "exact_plan_base64url", oracle.encoded(b"{}"), 1),
                ("parent", "selected_business_rows_json", "[]", 1)):
            recorder = Recorder()
            recorder.seed(fixture, fixture.now_epoch_ns)
            getattr(recorder, target)[field] = value
            with self.subTest(target=target, field=field), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as verified:
                with self.assertRaises(ValueError):
                    self.read(fixture, recorder)
            self.assertEqual(verified.call_count, replay_calls)

    def test_actual_facade_transaction_isolation_and_writer_role_guards_precede_dml(self):
        fixture = self.fixture()
        for variant in ("foreign_facade", "no_transaction", "isolation", "role", "read_only", "deferrable"):
            recorder, facade = Recorder(), None
            facade = Facade(recorder)
            if variant == "foreign_facade":
                facade = object()
            elif variant == "no_transaction":
                facade.in_transaction = False
            else:
                setattr(recorder, variant, {"isolation": "read committed", "role": "foreign-writer",
                    "read_only": "on", "deferrable": "on"}[variant])
            with self.subTest(variant=variant), self.assertRaises(StoreError):
                self.persist(fixture, recorder, connection=facade)
            self.assertIsNone(recorder.parent)
            self.assertFalse(any(sql.startswith(("INSERT ", "UPDATE ")) for sql, _ in recorder.statements))

    def test_live_expiry_denies_new_and_identical_writes_and_late_completion_rolls_back(self):
        fixture = self.fixture()
        for existing in (False, True):
            recorder = Recorder()
            if existing:
                recorder.seed(fixture, fixture.now_epoch_ns)
            before = recorder.snapshot()
            with self.subTest(existing=existing), self.assertRaisesRegex(ValueError, "stale or inconsistent"):
                self.persist(fixture, recorder, clock_epoch_ns=fixture.deadline_epoch_ns,
                    clock_monotonic_ns=fixture.deadline_monotonic_ns)
            self.assertEqual(recorder.snapshot(), before)
            self.assertFalse(any(sql.startswith(("INSERT ", "UPDATE ")) for sql, _ in recorder.statements))
        recorder = Recorder()

        def expire_after_insert(sql, parameters):
            if sql.startswith("SELECT ") and " FROM " + SIDECAR in sql:
                admission.time.time_ns.return_value = fixture.deadline_epoch_ns
                admission.time.monotonic_ns.return_value = fixture.deadline_monotonic_ns

        recorder.callback = expire_after_insert
        with self.assertRaisesRegex(ValueError, "stale or inconsistent"):
            self.persist(fixture, recorder)
        self.assertTrue(any(sql.startswith("INSERT INTO " + SIDECAR) for sql, _ in recorder.statements))
        self.assertFalse(any(sql.startswith("UPDATE ") for sql, _ in recorder.statements))
        self.assertEqual((recorder.parent, recorder.sidecar, recorder.rollbacks), (None, None, 1))
        self.assertEqual((recorder.assertions, recorder.projections), ({}, {}))

    def test_planned_timestamp_is_bound_to_original_interval_on_write_retry_and_read(self):
        fixture = self.fixture()
        for planned_at in (fixture.reserved_at_epoch_ns - 1, fixture.deadline_epoch_ns,
                           fixture.deadline_epoch_ns + 1):
            recorder = Recorder()
            with self.subTest(mode="write", planned_at=planned_at), self.assertRaises(StoreError):
                self.persist(fixture, recorder, planned_at=planned_at)
            self.assertEqual(recorder.statements, [])
            for mode in ("retry", "read"):
                recorder = Recorder()
                recorder.seed(fixture, planned_at)
                call = self.persist if mode == "retry" else self.read
                with self.subTest(mode=mode, planned_at=planned_at), self.assertRaises(StoreError):
                    call(fixture, recorder)

    def test_read_owns_external_graphs_and_returned_rows_before_later_callbacks(self):
        fixture, recorder = self.fixture(), Recorder()
        recorder.seed(fixture, fixture.now_epoch_ns)
        recorder.return_aliases = True
        external = wire_oracle.expectations(fixture)

        def mutate_aliases(sql, parameters):
            if sql == "SHOW transaction_isolation":
                external["expected_request"]["arguments"].clear()
                external["expected_before"]["businessBeforeRoots"].clear()
            elif sql.startswith("SELECT ") and " FROM " + SIDECAR in sql:
                recorder.parent["selected_business_rows_json"] = "[]"
            elif sql.startswith("SELECT ") and " FROM " + PROJECTION in sql:
                # The preceding assertion row has already been owned/matched.
                next(iter(recorder.assertions.values()))["evidence_json"] = "{}"

        recorder.callback = mutate_aliases
        result = self.read(fixture, recorder, **external)
        self.assertEqual(result["exactEnvelopeBytes"], oracle.wire(fixture.envelope))
        self.assertEqual(external["expected_request"]["arguments"], {})
        self.assertEqual(recorder.parent["selected_business_rows_json"], "[]")
        self.assertEqual(next(iter(recorder.assertions.values()))["evidence_json"], "{}")

    def test_driver_spending_or_equal_float_counter_corruption_rolls_back_without_refund(self):
        fixture = self.fixture()
        for corruption in ("spend", "float"):
            recorder, work = Recorder(), self.work()

            def alter_work(sql, parameters):
                if sql.startswith("INSERT INTO " + SIDECAR):
                    if corruption == "spend":
                        work.charge(json_nodes=1)
                    else:
                        work.json_nodes = float(work.json_nodes)

            recorder.callback = alter_work
            with self.subTest(corruption=corruption), self.assertRaises(ValueError):
                self.persist(fixture, recorder, work)
            self.assertEqual((recorder.parent, recorder.sidecar, recorder.rollbacks), (None, None, 1))
            self.assertEqual((recorder.assertions, recorder.projections), ({}, {}))
            self.assertGreater(work.hash_work, 0)
            if corruption == "float":
                self.assertIs(type(work.json_nodes), float)

    def test_context_cleanup_cannot_suppress_failure_or_skip_exit_for_corrupt_work(self):
        class Manager:
            def __init__(self, *, on_enter=None, cleanup_error=False):
                self.on_enter, self.cleanup_error, self.exits = on_enter, cleanup_error, []

            def __enter__(self):
                if self.on_enter is not None:
                    self.on_enter()
                return self

            def __exit__(self, kind, error, traceback):
                self.exits.append((kind, error))
                if self.cleanup_error:
                    raise RuntimeError("cleanup is not the first error")
                return True

        work, manager = self.work(), Manager()
        with self.assertRaises(ValueError):
            with store._context(manager, work):
                work.input_bytes = float(work.input_bytes)
        self.assertEqual(len(manager.exits), 1)
        self.assertTrue(issubclass(manager.exits[0][0], ValueError))
        self.assertIs(type(work.input_bytes), float)
        for cleanup_error in (False, True):
            manager = Manager(cleanup_error=cleanup_error)
            first = ValueError("original body failure")
            with self.subTest(cleanup_error=cleanup_error), self.assertRaises(ValueError) as caught:
                with store._context(manager, self.work()):
                    raise first
            self.assertIs(caught.exception, first)
            self.assertEqual(len(manager.exits), 1)
        work = self.work()
        manager = Manager(on_enter=lambda: work.charge(input_bytes=1))
        with self.assertRaisesRegex(StoreError, "callback changed"):
            with store._context(manager, work):
                self.fail("entry corruption must not enter the body")
        self.assertEqual(len(manager.exits), 1)
        self.assertEqual(work.input_bytes, 1)

    def test_actual_row_materializers_preserve_legacy_values_and_exact_remaining_work(self):
        fixture, prior = self.fixture(), (1, 7, 5)
        expected = expected_authorization_rows(fixture)
        costs = independent_authorization_work(fixture)["materialized"]

        def materialize(work=None):
            return (authorization_records._assertion_storage_row(fixture.payload["webauthnEvidence"], work=work),
                authorization_records._projection_storage_row(fixture.payload["authorizationProjection"], work=work))

        self.assertEqual(materialize(), expected)
        self.assertEqual(costs[0], 4)
        for dimension in (None, 0, 1, 2):
            limits = list(oracle.add(prior, costs))
            if dimension is not None:
                limits[dimension] -= 1
            work = self.work(limits)
            work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            entering = work.limits
            with self.subTest(dimension=dimension), patch.object(accounting._ValidationWork, "__init__",
                    side_effect=AssertionError("materializer allocated another work allowance")):
                if dimension is None:
                    self.assertEqual(materialize(work), expected)
                    self.assertEqual(oracle.units(work.metrics), oracle.add(prior, costs))
                else:
                    with self.assertRaises(ValueError):
                        materialize(work)
                    self.assertTrue(all(start <= used <= limit for start, used, limit
                        in zip(prior, oracle.units(work.metrics), limits)))
            self.assertIs(work.limits, entering)

    def test_retry_and_historical_read_deny_missing_or_changed_custody_without_repair(self):
        fixture = self.fixture()
        changes = (("assertions", None, None), ("projections", None, None),
            ("assertions", "user_present", True), ("assertions", "counter", 1.0),
            ("assertions", "verifier_measurement_digest", oracle.sha(b"foreign verifier")),
            ("assertions", "evidence_json", "{}"),
            ("projections", "assertion_evidence_digest", oracle.sha(b"foreign assertion")),
            ("projections", "source_rows_digest", oracle.sha(b"foreign source rows")),
            ("projections", "expires_at_epoch_ns", float(fixture.deadline_epoch_ns)),
            ("projections", "missing_field", None), ("projections", "extra_field", None),
            ("projections", "projection_json", "oversized"))
        for mode in ("retry", "read"):
            for target, field, value in changes:
                recorder = Recorder()
                recorder.seed(fixture, fixture.now_epoch_ns)
                rows = getattr(recorder, target)
                row = next(iter(rows.values()))
                if field is None:
                    rows.clear()
                elif field == "missing_field":
                    row.pop("source_rows_json")
                elif field == "extra_field":
                    row["foreign"] = None
                elif value == "oversized":
                    row[field] += " "
                else:
                    row[field] = value
                before = recorder.snapshot()
                call = self.persist if mode == "retry" else self.read
                with self.subTest(mode=mode, target=target, field=field), self.assertRaises(StoreError):
                    call(fixture, recorder)
                self.assertEqual(recorder.snapshot(), before)
                self.assertFalse(any(sql.startswith(("INSERT INTO " + ASSERTION, "INSERT INTO " + PROJECTION,
                    "UPDATE ", "DELETE ")) for sql, _ in recorder.statements))
                self.assertEqual(self.key_loads, 0)
        # A terminal consumed parent is still a genuine historical replay, not
        # permission to restore custody which has disappeared.
        recorder = Recorder()
        recorder.seed(fixture, fixture.now_epoch_ns)
        recorder.parent["status"] = "consumed"
        self.assertIsNotNone(self.read(fixture, recorder))
        recorder.projections.clear()
        with self.assertRaises(StoreError):
            self.read(fixture, recorder)

    def test_partial_custody_conflicts_roll_back_new_records_and_preserve_prior_rows(self):
        fixture = self.fixture()
        for conflict in ("projection_readback", "reused_challenge", "reused_projection_transaction"):
            recorder = Recorder()
            assertion, projection = expected_authorization_rows(fixture)
            if conflict == "projection_readback":
                projection["source_rows_digest"] = oracle.sha(b"conflicting rows")
                recorder.projections[projection["authorization_projection_digest"]] = projection
            elif conflict == "reused_challenge":
                assertion["assertion_evidence_digest"] = oracle.sha(b"prior assertion")
                recorder.assertions[assertion["assertion_evidence_digest"]] = assertion
            else:
                projection["authorization_projection_digest"] = oracle.sha(b"prior projection")
                recorder.projections[projection["authorization_projection_digest"]] = projection
            before, receipts = recorder.snapshot(), []
            with self.subTest(conflict=conflict), self.assertRaises(StoreError):
                receipts.append(self.persist(fixture, recorder))
            self.assertEqual(receipts, [])
            self.assertEqual(recorder.snapshot(), before)
            self.assertEqual((recorder.rollbacks, recorder.releases), (1, 0))
            self.assertTrue(any(sql.startswith("INSERT INTO " + ASSERTION) for sql, _ in recorder.statements))
            self.assertFalse(any(sql.startswith(("INSERT INTO " + SIDECAR, "UPDATE " + PARENT))
                for sql, _ in recorder.statements))

    def test_new_custody_requires_current_key_and_both_windows_but_history_does_not_refresh(self):
        fixture = self.fixture()
        wrong_key = Ed25519PrivateKey.from_private_bytes(b"\xf1" * 32).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        original_key = self.current_key_bytes
        expiry = fixture.payload["webauthnEvidence"]["expiresAtEpochNs"]
        self.assertLess(expiry, fixture.deadline_epoch_ns)
        for failure in ("wrong_key", "malformed_key", "evidence_expired", "projection_expired"):
            recorder, self.key_loads = Recorder(), 0
            self.current_key_bytes = wrong_key if failure == "wrong_key" else (
                b"x" * 31 if failure == "malformed_key" else original_key)
            changes = {}
            if failure == "evidence_expired":
                changes = {"clock_epoch_ns": expiry,
                    "clock_monotonic_ns": fixture.now_monotonic_ns + expiry - fixture.now_epoch_ns}
            elif failure == "projection_expired":
                # Original deadline admission and evidence window pass, then
                # the real second authorization clock observes projection expiry.
                changes = {"clock_epoch_sequence": [fixture.now_epoch_ns, fixture.now_epoch_ns,
                    fixture.deadline_epoch_ns]}
            error = ValueError if failure.endswith("key") else StoreError
            with self.subTest(failure=failure), self.assertRaises(error):
                self.persist(fixture, recorder, **changes)
            self.assertEqual(recorder.snapshot(), (None, None, {}, {}))
            self.assertEqual((recorder.rollbacks, recorder.releases), (1, 0))
            self.assertEqual(self.key_loads, int(failure.endswith("key")))
            self.assertFalse(any(sql.startswith(("INSERT INTO " + ASSERTION, "INSERT INTO " + PROJECTION))
                for sql, _ in recorder.statements))
        recorder = Recorder()
        recorder.seed(fixture, fixture.now_epoch_ns)
        self.current_key_bytes, self.key_loads = wrong_key, 0
        with patch.object(admission.time, "time_ns", side_effect=AssertionError("historical clock refresh")), \
                patch.object(admission.time, "monotonic_ns", side_effect=AssertionError("historical clock refresh")):
            historical = self.read(fixture, recorder)
        retried = self.persist(fixture, recorder)
        self.assertEqual(historical, retried)
        self.assertEqual(self.key_loads, 0)

    def test_current_key_loader_cannot_spend_or_corrupt_the_shared_meter(self):
        fixture = self.fixture()
        for corruption in ("spend", "float"):
            recorder, work, observed = Recorder(), self.work(), []

            def current_key():
                if corruption == "spend":
                    work.charge(json_nodes=1)
                else:
                    work.json_nodes = float(work.json_nodes)
                observed.append((work.hash_work, work.input_bytes, work.json_nodes))
                return self.current_key_bytes

            with self.subTest(corruption=corruption), patch.dict(admission._DB_GLOBALS,
                    {"_policy_authority_verifier_public_key": current_key}), self.assertRaises(ValueError):
                self.persist(fixture, recorder, work)
            self.assertEqual(len(observed), 1)
            self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), observed[0])
            self.assertEqual(recorder.snapshot(), (None, None, {}, {}))
            self.assertEqual((recorder.rollbacks, recorder.releases), (1, 0))
            self.assertFalse(any(sql.startswith(("INSERT INTO " + ASSERTION, "INSERT INTO " + PROJECTION))
                for sql, _ in recorder.statements))
            if corruption == "float":
                self.assertIs(type(work.json_nodes), float)


if __name__ == "__main__":
    unittest.main()
