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


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract
from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_retention as retention
from serverware.authority_store import planner_connection as admission
from serverware.authority_store import revocation_retention as store
import test_authority_revocation_plan as oracle
import test_authority_revocation_retention as record_oracle
import test_authority_revocation_wire as wire_oracle


PARENT = "serverware_metadata.policy_authority_planner_transactions"
SIDECAR = "serverware_metadata.policy_authority_revocation_retained_plans"
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
    total = oracle.add(prefix, record["total"], tail)
    peak = oracle.add(prefix, record["admission"])
    return {"total": total, "admission": tuple(max(a, b) for a, b in zip(total, peak)),
        "prefix": prefix, "tail": tail}


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
        self.statements = []
        self.rollbacks = self.releases = 0
        self.isolation = "serializable"
        self.role, self.read_only, self.deferrable = "fixture-planner-writer", "off", "off"
        self.callback = None
        self.fail_completion = False

    def cursor(self):
        return Cursor(self)

    @contextmanager
    def transaction(self):
        before = copy.deepcopy((self.parent, self.sidecar))
        try:
            yield self
        except BaseException:
            self.parent, self.sidecar = before
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
            self.result = None if r.parent is None else r.parent.copy()
        elif sql.startswith("SELECT ") and " FROM " + SIDECAR in sql:
            self.result = None if r.sidecar is None else r.sidecar.copy()
        else:
            raise AssertionError("unexpected SQL in fixed persistence recorder: " + sql)
        return self

    def fetchone(self):
        return self.result


class RevocationPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.old_namespace = admission._DB_GLOBALS
        admission.bind_db_globals({"PostgresMetadataConnection": Facade, "MetadataStoreError": StoreError,
            "_METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE": "fixture-planner-writer",
            "_POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_AGE_NS": 300_000_000_000,
            "_POLICY_AUTHORITY_VERIFIER_MAX_CLOCK_SKEW_NS": 1_000_000_000})

    def tearDown(self):
        admission._DB_GLOBALS = self.old_namespace

    def fixture(self):
        return oracle.PlanFixture(approval=False, include_audit=False)

    def work(self, limits=None):
        return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))

    def persist(self, fixture, recorder, work=None, *, planned_at=None, **changes):
        supplied = {"envelope_bytes": oracle.wire(fixture.envelope),
            "evaluation_context_bytes": oracle.wire(record_oracle.record_context(fixture)),
            "planned_at_epoch_ns": fixture.now_epoch_ns if planned_at is None else planned_at,
            "connection": Facade(recorder), "work": work or self.work(), **wire_oracle.expectations(fixture)}
        supplied.update(changes)
        with patch.object(admission.time, "time_ns", return_value=fixture.now_epoch_ns), \
                patch.object(admission.time, "monotonic_ns", return_value=fixture.now_monotonic_ns):
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
        self.assertEqual(actual["exactEnvelopeBytes"], oracle.wire(fixture.envelope))
        self.assertEqual(actual["evaluationContextBytes"], oracle.wire(record_oracle.record_context(fixture)))
        self.assertEqual(actual["retainedRecordDigest"], expected[1]["retained_record_digest"])
        self.assertEqual(oracle.units(work.metrics), metrics["total"])
        sql = [statement for statement, _ in recorder.statements]
        self.assertLess(next(i for i, q in enumerate(sql) if q.startswith("INSERT INTO " + SIDECAR)),
                        next(i for i, q in enumerate(sql) if q.startswith("UPDATE " + PARENT)))
        self.assertEqual((recorder.rollbacks, recorder.releases), (0, 1))

    def test_identical_retry_reverifies_exact_bytes_and_preserves_original_timestamp(self):
        fixture, recorder = self.fixture(), Recorder()
        recorder.parent, recorder.sidecar = expected_rows(fixture, fixture.now_epoch_ns)
        before = copy.deepcopy((recorder.parent, recorder.sidecar))
        expected = independent_store_metrics(fixture, fixture.now_epoch_ns, mode="retry")
        work = self.work(expected["admission"])
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as verified:
            actual = self.persist(fixture, recorder, work, planned_at=fixture.now_epoch_ns + 1)
        self.assertEqual(verified.call_count, 1)
        self.assertEqual(actual["plannedAtEpochNs"], fixture.now_epoch_ns)
        self.assertEqual((recorder.parent, recorder.sidecar), before)
        self.assertFalse(any(sql.startswith(("UPDATE ", "INSERT INTO " + SIDECAR)) for sql, _ in recorder.statements))
        self.assertEqual(oracle.units(work.metrics), expected["total"])

    def test_historical_read_verifies_original_bytes_without_resampling_time(self):
        fixture, recorder = self.fixture(), Recorder()
        recorder.parent, recorder.sidecar = expected_rows(fixture, fixture.now_epoch_ns)
        expected = independent_store_metrics(fixture, fixture.now_epoch_ns, mode="read")
        work = self.work(expected["admission"])
        with patch.object(admission.time, "time_ns", side_effect=AssertionError("historical clock refresh")), \
                patch.object(admission.time, "monotonic_ns", side_effect=AssertionError("historical clock refresh")), \
                patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as verified:
            result = self.read(fixture, recorder, work)
        self.assertEqual(verified.call_count, 1)
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
            recorder.parent, recorder.sidecar = expected_rows(fixture, fixture.now_epoch_ns)
            getattr(recorder, target)[field] = value
            before = copy.deepcopy((recorder.parent, recorder.sidecar))
            with self.subTest(target=target, field=field), self.assertRaises(StoreError):
                self.persist(fixture, recorder)
            self.assertEqual((recorder.parent, recorder.sidecar), before)
            self.assertEqual(recorder.rollbacks, 1)

    def test_cas_failure_rolls_back_new_parent_and_sidecar_in_caller_savepoint(self):
        fixture, recorder, work = self.fixture(), Recorder(), self.work()
        recorder.fail_completion = True
        with self.assertRaisesRegex(StoreError, "completion CAS failed"):
            self.persist(fixture, recorder, work)
        self.assertEqual((recorder.parent, recorder.sidecar), (None, None))
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


if __name__ == "__main__":
    unittest.main()
