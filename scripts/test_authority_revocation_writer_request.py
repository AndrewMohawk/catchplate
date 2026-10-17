#!/usr/bin/env python3
"""Immutable detached request custody over a six-set SQL recorder.

Literal rows and costs are independent of the request-row producer. The
recorder models fixed SQL, uniqueness and savepoint rollback, not PostgreSQL
constraints, TLS, catalog admission, launch provenance or a durable ACK.
The startup fixture separately keeps the actual db/registry gate and both
genuine retained-proof replays. This source is authored, not executed.
Isolated helper failures temporarily bind only the existing error class and
restore the original namespace; no facade, key or admission verdict is bound.
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

from catchplate import authority_contract as authority
from catchplate import authority_query_read_work as accounting
from catchplate.authority_store import planner_connection as admission
from catchplate.authority_store import revocation_writer_request as request_store
import test_authority_revocation_persistence as persistence_oracle
import test_authority_revocation_plan as oracle
import test_authority_revocation_reservation as reservation_oracle
import test_authority_revocation_writer_composition as composition_oracle


TABLE = "catchplate_metadata.policy_authority_revocation_writer_requests"
FIELDS = (
    "intent_envelope_id", "relay_envelope_id", "execution_envelope_id",
    "planner_transaction_id", "plan_protocol", "retained_record_digest",
    "configuration_digest", "generation_sequence", "generation_digest",
    "exact_intent_base64url", "exact_intent_bytes_digest", "exact_intent_byte_count",
    "exact_relay_base64url", "exact_relay_bytes_digest", "exact_relay_byte_count",
    "historical_expectations_base64url", "historical_expectations_bytes_digest",
    "historical_expectations_byte_count", "planner_key_digest", "verifier_key_digest",
    "planned_at_epoch_ns", "source_revision",
)
SELECT = ("SELECT " + ", ".join(FIELDS) + " FROM " + TABLE
          + " WHERE intent_envelope_id = %s")
INSERT = ("INSERT INTO " + TABLE + " (" + ", ".join(FIELDS) + ") VALUES ("
          + ", ".join(("%s",) * len(FIELDS))
          + ") ON CONFLICT (intent_envelope_id) DO NOTHING")


def expected_row(fixture):
    """All twenty-two stored fields from genuine independent original inputs."""
    arguments = fixture.action.arguments
    _, sidecar = persistence_oracle.expected_rows(fixture.plan, arguments["planned_at_epoch_ns"])
    intent_id = oracle.framed("catchplate.policyAuthorityRevocationWriterIntentEnvelope/v1",
        arguments["envelope_id"].encode("ascii"), arguments["planner_transaction_id"].encode("ascii"))
    relay_id = oracle.framed("catchplate.policyAuthorityRevocationWriterRelayEnvelope/v1",
        intent_id.encode("ascii"))
    return {
        "intent_envelope_id": intent_id, "relay_envelope_id": relay_id,
        "execution_envelope_id": arguments["envelope_id"],
        "planner_transaction_id": arguments["planner_transaction_id"],
        "plan_protocol": "revocation-v4", "retained_record_digest": sidecar["retained_record_digest"],
        "configuration_digest": fixture.configuration_digest,
        "generation_sequence": fixture.generation_sequence, "generation_digest": fixture.generation_digest,
        "exact_intent_base64url": oracle.encoded(fixture.intent_bytes),
        "exact_intent_bytes_digest": oracle.sha(fixture.intent_bytes),
        "exact_intent_byte_count": len(fixture.intent_bytes),
        "exact_relay_base64url": oracle.encoded(fixture.relay_bytes),
        "exact_relay_bytes_digest": oracle.sha(fixture.relay_bytes),
        "exact_relay_byte_count": len(fixture.relay_bytes),
        "historical_expectations_base64url": oracle.encoded(fixture.history_bytes),
        "historical_expectations_bytes_digest": oracle.sha(fixture.history_bytes),
        "historical_expectations_byte_count": len(fixture.history_bytes),
        "planner_key_digest": sidecar["planner_key_digest"],
        "verifier_key_digest": sidecar["verifier_key_digest"],
        "planned_at_epoch_ns": arguments["planned_at_epoch_ns"],
        "source_revision": authority.SOURCE_REVISION,
    }


def prefix_arguments(fixture, work):
    args = fixture.action.arguments
    return {"intent_bytes": fixture.intent_bytes, "relay_bytes": fixture.relay_bytes,
        "historical_expectations_bytes": fixture.history_bytes,
        "configuration_digest": fixture.configuration_digest,
        "generation_sequence": fixture.generation_sequence, "generation_digest": fixture.generation_digest,
        "planned_at_epoch_ns": args["planned_at_epoch_ns"], "envelope_id": args["envelope_id"],
        "planner_transaction_id": args["planner_transaction_id"], "work": work}


def expected_prefix(fixture):
    return {name: value for name, value in expected_row(fixture).items()
            if name not in {"retained_record_digest", "planner_key_digest", "verifier_key_digest"}}


def materializer_links(fixture):
    """Ordinary scalar inputs to the row builder, never proof authority.

    Startup obtains these fields from actual fresh store calls. The component
    only checks the row builder's comparison recipe and explicitly does not
    call these independently reconstructed dictionaries admitted receipts.
    """
    row = expected_row(fixture)
    receipt = {"plannerTransactionId": row["planner_transaction_id"],
        "planProtocol": "revocation-v4", "plannedAtEpochNs": row["planned_at_epoch_ns"],
        "retainedRecordDigest": row["retained_record_digest"],
        "plannerKeyDigest": row["planner_key_digest"], "verifierKeyDigest": row["verifier_key_digest"]}
    reserved = reservation_oracle.expected_envelope(fixture.plan, row["execution_envelope_id"])
    return receipt, reserved


def independent_request_work(fixture, *, existing=False):
    """Literal custody-only costs; add real replay totals/peaks separately."""
    row, prefix = expected_row(fixture), expected_prefix(fixture)
    args, add = fixture.action.arguments, oracle.add
    ids = add((0, 3 * 142, 3 * 2),
        oracle.frame_cost("catchplate.policyAuthorityRevocationWriterIntentEnvelope/v1",
            (args["envelope_id"].encode("ascii"), args["planner_transaction_id"].encode("ascii"))),
        oracle.frame_cost("catchplate.policyAuthorityRevocationWriterRelayEnvelope/v1",
            (row["intent_envelope_id"].encode("ascii"),)))
    originals = (fixture.intent_bytes, fixture.relay_bytes, fixture.history_bytes)
    materialize = add(ids, *(add((1, len(raw), 0), persistence_oracle.codec_encode(raw)) for raw in originals))
    lookup = add(oracle.graph_cost(row), persistence_oracle.scalar_comparisons(prefix)) if existing else (0, 0, 0)
    receipt_links = {"plannerTransactionId": row["planner_transaction_id"],
        "planProtocol": row["plan_protocol"], "plannedAtEpochNs": row["planned_at_epoch_ns"]}
    reservation_links = {"envelope_id": row["execution_envelope_id"],
        "planner_transaction_id": row["planner_transaction_id"], "status": "reserved",
        "source_revision": row["source_revision"]}
    links = add(persistence_oracle.scalar_comparisons(receipt_links),
        persistence_oracle.scalar_comparisons(reservation_links))
    tail = add(links, oracle.graph_cost(row) if not existing else (0, 0, 0),
        oracle.graph_cost(row), persistence_oracle.scalar_comparisons(row))
    return {"materialize": materialize, "lookup": lookup, "links": links,
        "prefix": add(materialize, lookup), "tail": tail,
        "total": add(materialize, lookup, tail)}


class Recorder(reservation_oracle.Recorder):
    """Opt-in sixth record set; existing five-set fixtures stay unchanged."""
    def __init__(self):
        super().__init__()
        self.requests = {}
        self.request_reads = 0
        self.missing_request_readback = False

    def cursor(self):
        return Cursor(self)

    def snapshot(self):
        return copy.deepcopy((self.parent, self.sidecar, self.assertions,
                              self.projections, self.envelopes, self.requests))

    @contextmanager
    def transaction(self):
        before = self.snapshot()
        try:
            self.event("savepoint.enter")
            yield self
        except BaseException:
            (self.parent, self.sidecar, self.assertions,
             self.projections, self.envelopes, self.requests) = before
            self.rollbacks += 1
            self.event("savepoint.rollback")
            raise
        else:
            self.releases += 1
            self.event("savepoint.release")


class Cursor(reservation_oracle.Cursor):
    def execute(self, sql, parameters=()):
        if not (sql.startswith("INSERT INTO " + TABLE) or " FROM " + TABLE in sql):
            return super().execute(sql, parameters)
        recorder = self.recorder
        recorder.statements.append((sql, parameters))
        if recorder.callback is not None:
            recorder.callback(sql, parameters)
        self.result, self.rowcount = None, -1
        if sql == INSERT and len(parameters) == len(FIELDS):
            row = dict(zip(FIELDS, parameters))
            # Constraint observations are synthetic. Native schema fixtures
            # separately exercise the actual unique/composite-FK constraints.
            for identity, old in recorder.requests.items():
                if identity != row["intent_envelope_id"] and any(old[name] == row[name]
                        for name in ("relay_envelope_id", "execution_envelope_id")):
                    raise persistence_oracle.StoreError("synthetic request uniqueness conflict")
            retained = recorder.sidecar
            execution = recorder.envelopes.get(row["execution_envelope_id"])
            if (retained is None or any(retained[name] != row[name] for name in
                    ("planner_transaction_id", "plan_protocol", "retained_record_digest"))
                    or execution is None or execution["planner_transaction_id"] != row["planner_transaction_id"]):
                raise persistence_oracle.StoreError("synthetic request composite-link conflict")
            recorder.requests.setdefault(row["intent_envelope_id"], row)
            self.rowcount = 0
        elif sql == SELECT and len(parameters) == 1:
            recorder.request_reads += 1
            row = recorder.requests.get(parameters[0])
            if recorder.missing_request_readback and recorder.request_reads >= 2:
                row = None
            self.result = row if recorder.return_aliases or row is None else row.copy()
        else:
            raise AssertionError("request custody escaped its exact SQL/parameter closure")
        return self


class RevocationWriterRequestTests(unittest.TestCase):
    def setUp(self):
        self.old_namespace = admission._DB_GLOBALS
        self.addCleanup(setattr, admission, "_DB_GLOBALS", self.old_namespace)
        admission.bind_db_globals({"MetadataStoreError": persistence_oracle.StoreError})

    def work(self, limits=None):
        return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))

    def fixture(self, *, existing=False):
        fixture, recorder = composition_oracle.CompositionFixture(), Recorder()
        recorder.seed(fixture.plan, fixture.action.arguments["planned_at_epoch_ns"])
        identity = fixture.action.arguments["envelope_id"]
        recorder.envelopes[identity] = reservation_oracle.expected_envelope(fixture.plan, identity)
        if existing:
            row = expected_row(fixture)
            recorder.requests[row["intent_envelope_id"]] = row
        return fixture, recorder

    def materialize(self, fixture, recorder, work):
        # This is only the actual row-helper sequence. No store replay or
        # authenticated custody success is claimed by these direct helpers.
        prefix = request_store._prefix_on_work(**prefix_arguments(fixture, work))
        receipt, reservation = materializer_links(fixture)
        with recorder.transaction():
            cursor = recorder.cursor()
            observed = request_store._lookup(cursor, prefix, work)
            return request_store._persist(cursor, prefix, receipt, reservation,
                work, insert=observed is None)

    def test_literal_prefix_keeps_original_three_codecs_and_global_ids_without_authentication_claim(self):
        fixture, _ = self.fixture()
        expected = independent_request_work(fixture)
        work = self.work(expected["materialize"])
        prefix = request_store._prefix_on_work(**prefix_arguments(fixture, work))
        self.assertEqual(prefix, expected_prefix(fixture))
        self.assertEqual((len(prefix), len(expected_row(fixture))), (19, 22))
        self.assertEqual(oracle.units(work.metrics), expected["materialize"])
        self.assertEqual(expected["materialize"][0], 5)
        old_ids = (prefix["intent_envelope_id"], prefix["relay_envelope_id"])
        arguments = prefix_arguments(fixture, self.work())
        arguments.update(configuration_digest=oracle.sha(b"another measured configuration"),
            generation_sequence=fixture.generation_sequence + 1, generation_digest=oracle.sha(b"another generation"))
        changed = request_store._prefix_on_work(**arguments)
        self.assertEqual((changed["intent_envelope_id"], changed["relay_envelope_id"]), old_ids)
        self.assertNotEqual(changed["configuration_digest"], prefix["configuration_digest"])

    def test_real_helpers_insert_once_then_compare_the_entire_existing_row_without_updates(self):
        for existing in (False, True):
            fixture, recorder = self.fixture(existing=existing)
            before = recorder.snapshot()
            expected = independent_request_work(fixture, existing=existing)
            work = self.work(expected["total"])
            row = self.materialize(fixture, recorder, work)
            self.assertEqual(row, expected_row(fixture))
            self.assertEqual(recorder.snapshot()[:5], before[:5])
            self.assertEqual(recorder.requests, {row["intent_envelope_id"]: row})
            self.assertEqual([sql for sql, _ in recorder.statements],
                [SELECT, SELECT] if existing else [SELECT, INSERT, SELECT])
            self.assertEqual((recorder.releases, recorder.rollbacks), (1, 0))
            self.assertEqual(oracle.units(work.metrics), expected["total"])
            self.assertIsNot(row, recorder.requests[row["intent_envelope_id"]])

    def test_fixed_raw_bounds_and_closed_returned_scalars_deny_without_sql_repair(self):
        fixture, _ = self.fixture()
        for name, value in (
                ("intent_bytes", bytearray(fixture.intent_bytes)), ("relay_bytes", b"x"),
                ("historical_expectations_bytes", memoryview(fixture.history_bytes)),
                ("generation_sequence", True), ("planned_at_epoch_ns", 0),
                ("configuration_digest", "not-a-digest"), ("envelope_id", False)):
            work = self.work()
            supplied = prefix_arguments(fixture, work)
            supplied[name] = value
            with self.subTest(input=name), self.assertRaises(ValueError):
                request_store._prefix_on_work(**supplied)
            self.assertEqual(oracle.units(work.metrics), (0, 0, 0))
        for change in (lambda row: row.update(extra=None),
                       lambda row: row.pop("source_revision"),
                       lambda row: row.update(generation_sequence=True),
                       lambda row: row.update(planned_at_epoch_ns=1.0),
                       lambda row: row.update(exact_intent_base64url=row["exact_intent_base64url"] + "A"),
                       lambda row: row.update(planner_key_digest="invalid")):
            fixture, recorder = self.fixture(existing=True)
            identity = expected_row(fixture)["intent_envelope_id"]
            change(recorder.requests[identity])
            before = recorder.snapshot()
            with self.assertRaises(ValueError): self.materialize(fixture, recorder, self.work())
            self.assertEqual(recorder.snapshot(), before)
            self.assertFalse(any(sql == INSERT for sql, _ in recorder.statements))

    def test_every_stored_scalar_conflict_is_rejected_without_overwrite_or_a_missing_signal(self):
        for name in FIELDS:
            fixture, recorder = self.fixture(existing=True)
            identity = expected_row(fixture)["intent_envelope_id"]
            row = recorder.requests[identity]
            value = row[name]
            row[name] = value + 1 if type(value) is int else (
                oracle.sha(b"different valid digest") if value.startswith("sha256:") else
                ("A" if value[:1] != "A" else "B") + value[1:])
            before = recorder.snapshot()
            with self.subTest(field=name), self.assertRaises(ValueError):
                self.materialize(fixture, recorder, self.work())
            self.assertEqual(recorder.snapshot(), before)
            self.assertFalse(any(sql == INSERT for sql, _ in recorder.statements))
            expected_reads = 2 if name in {"retained_record_digest", "planner_key_digest", "verifier_key_digest"} else 1
            self.assertEqual(recorder.request_reads, expected_reads)

    def test_complete_row_requires_exact_original_planned_time_and_both_local_result_links(self):
        fixture, recorder = self.fixture()
        prefix = expected_prefix(fixture)
        for target, name in (("receipt", "plannerTransactionId"), ("receipt", "planProtocol"),
                ("receipt", "plannedAtEpochNs"), ("reservation", "envelope_id"),
                ("reservation", "planner_transaction_id"), ("reservation", "status"),
                ("reservation", "source_revision")):
            receipt, reserved = materializer_links(fixture)
            document = receipt if target == "receipt" else reserved
            value = document[name]
            document[name] = value + 1 if type(value) is int else "different"
            with self.subTest(target=target, field=name), self.assertRaises(ValueError):
                request_store._complete_on_work(prefix, receipt, reserved, self.work())
        receipt, reserved = materializer_links(fixture)
        retimed = {**prefix, "planned_at_epoch_ns": prefix["planned_at_epoch_ns"] + 1}
        with self.assertRaises(ValueError):
            request_store._persist(recorder.cursor(), retimed, receipt, reserved, self.work(), insert=True)
        self.assertEqual(recorder.statements, [])
        self.assertEqual(recorder.requests, {})

    def test_returned_aliases_are_owned_and_post_insert_readback_failure_restores_six_sets(self):
        fixture, recorder = self.fixture(existing=True)
        recorder.return_aliases = True
        prefix, work = expected_prefix(fixture), self.work()
        cursor = recorder.cursor()
        owned = request_store._lookup(cursor, prefix, work)
        expected = expected_row(fixture)
        recorder.requests[expected["intent_envelope_id"]]["verifier_key_digest"] = oracle.sha(b"late change")
        self.assertEqual(owned, expected)
        receipt, reserved = materializer_links(fixture)
        with self.assertRaises(ValueError): request_store._persist(cursor, prefix, receipt, reserved, work, insert=False)
        fixture, recorder = self.fixture()
        before = recorder.snapshot()
        recorder.missing_request_readback = True
        with self.assertRaises(ValueError): self.materialize(fixture, recorder, self.work())
        self.assertEqual([sql for sql, _ in recorder.statements], [SELECT, INSERT, SELECT])
        self.assertEqual(recorder.snapshot(), before)
        self.assertEqual((recorder.rollbacks, recorder.releases), (1, 0))

    def test_driver_exceptions_and_meter_poison_preserve_first_failure_and_original_six_sets(self):
        for mode in ("exception", "counters", "limits"):
            fixture, recorder = self.fixture()
            work, failure, poisoned = self.work(), RuntimeError("native request driver failure"), []
            before = recorder.snapshot()

            def callback(sql, parameters):
                if sql != SELECT: return
                if mode == "exception": raise failure
                if mode == "counters": work.input_bytes -= 1
                else: work.limits = accounting.QueryReadValidationLimits()
                poisoned.append((work.limits, oracle.units(work.metrics)))

            recorder.callback = callback
            with self.subTest(mode=mode), self.assertRaises(RuntimeError if mode == "exception" else ValueError) as raised:
                self.materialize(fixture, recorder, work)
            if mode == "exception": self.assertIs(raised.exception, failure)
            else:
                self.assertIs(work.limits, poisoned[0][0])
                self.assertEqual(oracle.units(work.metrics), poisoned[0][1])
            self.assertEqual(recorder.snapshot(), before)
            self.assertFalse(hasattr(work, "_revocation_packaging_owner"))

    def test_exact_prior_each_short_axis_and_repeated_helpers_spend_only_the_existing_allowance(self):
        for existing in (False, True):
            for prior, axis in (((0, 0, 0), None), ((3, 17, 11), None),
                                ((3, 17, 11), 0), ((3, 17, 11), 1), ((3, 17, 11), 2)):
                fixture, recorder = self.fixture(existing=existing)
                expected = independent_request_work(fixture, existing=existing)["total"]
                limits = list(oracle.add(prior, expected))
                if axis is not None: limits[axis] -= 1
                work = self.work(limits)
                work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                before, entering = recorder.snapshot(), work.limits
                with self.subTest(existing=existing, prior=prior, axis=axis), \
                        patch.object(accounting._ValidationWork, "__init__", side_effect=AssertionError("replacement helper allowance")):
                    if axis is None:
                        self.assertEqual(self.materialize(fixture, recorder, work), expected_row(fixture))
                        self.assertEqual(oracle.units(work.metrics), oracle.add(prior, expected))
                    else:
                        with self.assertRaises(ValueError): self.materialize(fixture, recorder, work)
                        self.assertEqual(recorder.snapshot(), before)
                self.assertIs(work.limits, entering)
        for axis in (None, 0, 1, 2):
            fixture, recorder = self.fixture()
            new = independent_request_work(fixture)["total"]
            retry = independent_request_work(fixture, existing=True)["total"]
            limits = list(oracle.add(new, retry))
            if axis is not None: limits[axis] -= 1
            work = self.work(limits)
            self.materialize(fixture, recorder, work)
            before = recorder.snapshot()
            if axis is None:
                self.materialize(fixture, recorder, work)
                self.assertEqual(oracle.units(work.metrics), oracle.add(new, retry))
            else:
                with self.assertRaises(ValueError): self.materialize(fixture, recorder, work)
            self.assertEqual(recorder.snapshot(), before)
            self.assertFalse(hasattr(work, "_revocation_packaging_owner"))


if __name__ == "__main__":
    unittest.main()
